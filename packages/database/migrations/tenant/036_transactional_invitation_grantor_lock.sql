-- Bind every role grant to the exact acceptance epoch. A legacy tenant may be
-- upgraded only with a transaction-local manifest built from locked,
-- one-to-one control-plane acceptance evidence by the maintenance runner. No
-- email, membership or role similarity is accepted as inference.
DO $$
DECLARE
  configured_tenant_id uuid;
  legacy_binding_count integer;
  legacy_invitation_count integer;
  manifest_count integer;
  manifest_binding_count integer;
  manifest_digest_count integer;
BEGIN
  SELECT tenant_id INTO configured_tenant_id
    FROM public.tenant_settings WHERE singleton=true;
  SELECT count(*)::integer,count(DISTINCT source_invitation_id)::integer
    INTO legacy_binding_count,legacy_invitation_count
    FROM public.role_bindings WHERE source_invitation_id IS NOT NULL;
  IF legacy_binding_count > 0 THEN
    IF to_regclass('pg_temp.legacy_invitation_binding_reconciliation_manifest') IS NULL THEN
      RAISE EXCEPTION 'Legacy invitation bindings require exact control-plane reconciliation before upgrade'
        USING ERRCODE='23514', CONSTRAINT='legacy_invitation_binding_reconciliation_required';
    END IF;
    SELECT count(*)::integer,max(binding_count),count(DISTINCT manifest_sha256)::integer
      INTO manifest_count,manifest_binding_count,manifest_digest_count
      FROM pg_temp.legacy_invitation_binding_reconciliation_manifest;
    IF configured_tenant_id IS NULL
       OR manifest_count IS DISTINCT FROM legacy_invitation_count
       OR manifest_binding_count IS DISTINCT FROM legacy_binding_count
       OR manifest_digest_count IS DISTINCT FROM 1
       OR EXISTS (
         SELECT 1 FROM pg_temp.legacy_invitation_binding_reconciliation_manifest manifest
          WHERE manifest.tenant_id IS DISTINCT FROM configured_tenant_id
             OR manifest.role_codes IS DISTINCT FROM ARRAY(
               SELECT role_code FROM unnest(manifest.role_codes) role(role_code) ORDER BY role_code
             )
             OR cardinality(manifest.role_codes) NOT BETWEEN 1 AND 3
             OR cardinality(manifest.role_codes) IS DISTINCT FROM (
               SELECT count(DISTINCT role_code)::integer FROM unnest(manifest.role_codes) role(role_code)
             )
             OR (manifest.authority_kind='tenant_delegate' AND manifest.authority_epoch<>0)
             OR (manifest.authority_kind='initial_admin' AND (
               manifest.authority_epoch<=0 OR manifest.role_codes<>ARRAY['CHURCH_ADMIN']::text[]
             ))
       )
       OR EXISTS (
         SELECT 1
           FROM public.role_bindings binding
           JOIN public.roles role ON role.id=binding.role_id
           LEFT JOIN pg_temp.legacy_invitation_binding_reconciliation_manifest manifest
             ON manifest.invitation_id=binding.source_invitation_id
          WHERE binding.source_invitation_id IS NOT NULL
            AND (
              manifest.invitation_id IS NULL
              OR binding.identity_id IS DISTINCT FROM manifest.invited_identity_id
              OR binding.granted_by_identity_id IS DISTINCT FROM manifest.granted_by_identity_id
              OR NOT role.system_role
              OR NOT role.code=ANY(manifest.role_codes)
            )
       )
       OR EXISTS (
         SELECT 1
           FROM pg_temp.legacy_invitation_binding_reconciliation_manifest manifest
           LEFT JOIN LATERAL (
             SELECT count(*)::integer AS binding_count,
                    array_agg(role.code ORDER BY role.code) AS role_codes
               FROM public.role_bindings binding
               JOIN public.roles role ON role.id=binding.role_id
              WHERE binding.source_invitation_id=manifest.invitation_id
           ) actual ON true
          WHERE actual.binding_count IS DISTINCT FROM cardinality(manifest.role_codes)
             OR actual.role_codes IS DISTINCT FROM manifest.role_codes
       ) THEN
      RAISE EXCEPTION 'Legacy invitation bindings are ambiguous against the locked control-plane manifest'
        USING ERRCODE='23514', CONSTRAINT='legacy_invitation_binding_reconciliation_ambiguous';
    END IF;
  END IF;
END
$$;

ALTER TABLE role_bindings
  ADD COLUMN source_acceptance_id uuid;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM public.role_bindings WHERE source_invitation_id IS NOT NULL) THEN
    UPDATE public.role_bindings binding
       SET source_acceptance_id=manifest.acceptance_id
      FROM pg_temp.legacy_invitation_binding_reconciliation_manifest manifest
     WHERE binding.source_invitation_id=manifest.invitation_id;
    IF EXISTS (
      SELECT 1 FROM public.role_bindings
       WHERE source_invitation_id IS NOT NULL AND source_acceptance_id IS NULL
    ) THEN
      RAISE EXCEPTION 'Legacy invitation acceptance epoch backfill was incomplete'
        USING ERRCODE='23514', CONSTRAINT='legacy_invitation_binding_reconciliation_ambiguous';
    END IF;
  END IF;
END
$$;

ALTER TABLE role_bindings
  ADD CONSTRAINT role_bindings_invitation_acceptance_complete CHECK (
    (source_invitation_id IS NULL)=(source_acceptance_id IS NULL)
  );

CREATE INDEX role_bindings_invitation_acceptance
  ON role_bindings(source_invitation_id,source_acceptance_id,identity_id)
  WHERE source_invitation_id IS NOT NULL;

-- The preimage is held only by the configured secret provider. The tenant
-- stores its verifier and a monotonic attempt fence. Runtime has no table
-- privileges and may only consume the pre-established verifier through the
-- exact SECURITY DEFINER functions below.
CREATE TABLE initial_admin_activation_capability (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  apply_secret_hash text NOT NULL CHECK (apply_secret_hash ~ '^[0-9a-f]{64}$'),
  cleanup_secret_hash text NOT NULL CHECK (cleanup_secret_hash ~ '^[0-9a-f]{64}$'),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','applied','consumed')),
  authority_epoch bigint NOT NULL DEFAULT 0 CHECK (authority_epoch >= 0),
  last_acceptance_attempt integer NOT NULL DEFAULT 0 CHECK (last_acceptance_attempt >= 0),
  invitation_id uuid,
  acceptance_id uuid,
  invited_identity_id uuid,
  grantor_identity_id uuid,
  applied_at timestamptz,
  consumed_at timestamptz,
  CHECK (
    (state = 'pending' AND applied_at IS NULL AND consumed_at IS NULL
      AND (
        (authority_epoch = 0 AND last_acceptance_attempt = 0
          AND invitation_id IS NULL AND acceptance_id IS NULL
          AND invited_identity_id IS NULL AND grantor_identity_id IS NULL)
        OR
        (authority_epoch > 0 AND last_acceptance_attempt > 0
          AND invitation_id IS NOT NULL AND acceptance_id IS NOT NULL
          AND invited_identity_id IS NOT NULL AND grantor_identity_id IS NOT NULL)
      ))
    OR
    (state = 'applied' AND authority_epoch > 0 AND last_acceptance_attempt > 0
      AND invitation_id IS NOT NULL AND acceptance_id IS NOT NULL
      AND invited_identity_id IS NOT NULL AND grantor_identity_id IS NOT NULL
      AND applied_at IS NOT NULL AND consumed_at IS NULL)
    OR
    (state = 'consumed' AND authority_epoch > 0 AND last_acceptance_attempt > 0
      AND invitation_id IS NOT NULL AND acceptance_id IS NOT NULL
      AND invited_identity_id IS NOT NULL AND grantor_identity_id IS NOT NULL
      AND applied_at IS NOT NULL AND consumed_at IS NOT NULL)
  )
);

REVOKE ALL ON TABLE initial_admin_activation_capability FROM PUBLIC;

-- While bootstrap is applied but not yet consumed, only the exact rollback
-- protocol may release its binding. Ordinary role revocation cannot race the
-- irreversible consume boundary and strand an accepted tenant without its
-- administrator. Rollback first changes capability state in the same
-- transaction, then deletes the binding.
CREATE FUNCTION public.guard_applied_initial_admin_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF OLD.source_invitation_id IS NOT NULL
     AND OLD.source_acceptance_id IS NOT NULL
     AND EXISTS (
       SELECT 1
         FROM public.initial_admin_activation_capability capability
        WHERE capability.singleton = true
          AND capability.state = 'applied'
          AND capability.invitation_id = OLD.source_invitation_id
          AND capability.acceptance_id = OLD.source_acceptance_id
          AND capability.invited_identity_id = OLD.identity_id
     ) THEN
    RAISE EXCEPTION 'Applied initial administrator binding is fenced'
      USING ERRCODE = '55000', CONSTRAINT = 'initial_admin_binding_applied';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;

CREATE TRIGGER role_binding_initial_admin_apply_guard
BEFORE UPDATE OR DELETE ON role_bindings
FOR EACH ROW EXECUTE FUNCTION public.guard_applied_initial_admin_binding();

CREATE TABLE tenant_invitation_acceptance_fences (
  invitation_id uuid PRIMARY KEY,
  state text NOT NULL CHECK (state IN ('applied','rolled_back')),
  acceptance_attempt integer NOT NULL CHECK (acceptance_attempt > 0),
  acceptance_id uuid NOT NULL,
  invited_identity_id uuid NOT NULL,
  granted_by_identity_id uuid NOT NULL,
  role_codes text[] NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

REVOKE ALL ON TABLE tenant_invitation_acceptance_fences FROM PUBLIC;

-- Seed the same exact monotonic fence used by new acceptances. This occurs in
-- the migration transaction, so either the acceptance ids and every fence are
-- durable together or none of the legacy tenant is changed.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM public.role_bindings WHERE source_invitation_id IS NOT NULL) THEN
    INSERT INTO public.tenant_invitation_acceptance_fences(
      invitation_id,state,acceptance_attempt,acceptance_id,invited_identity_id,
      granted_by_identity_id,role_codes,updated_at
    )
    SELECT manifest.invitation_id,'applied',manifest.acceptance_attempt,
           manifest.acceptance_id,manifest.invited_identity_id,
           manifest.granted_by_identity_id,manifest.role_codes,clock_timestamp()
      FROM pg_temp.legacy_invitation_binding_reconciliation_manifest manifest
     ORDER BY manifest.invitation_id;
    IF (SELECT count(*) FROM public.tenant_invitation_acceptance_fences)
       IS DISTINCT FROM (
         SELECT count(*) FROM pg_temp.legacy_invitation_binding_reconciliation_manifest
       ) THEN
      RAISE EXCEPTION 'Legacy invitation acceptance fence backfill was incomplete'
        USING ERRCODE='23514', CONSTRAINT='legacy_invitation_binding_reconciliation_ambiguous';
    END IF;
  END IF;
END
$$;

-- Tenant invitation delegation must be linearizable with local access
-- revocation. Lock every active grantor binding before evaluating authority;
-- the lock is retained by the outer transaction through invited-role insert.
CREATE OR REPLACE FUNCTION public.assert_tenant_invitation_role_delegation_allowed(
  p_actor_identity_id uuid,
  p_requested_role_codes text[]
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  contextual_actor uuid;
  configured_tenant_id uuid;
  bound_tenant_id uuid;
BEGIN
  IF p_actor_identity_id IS NULL OR p_requested_role_codes IS NULL THEN
    RAISE EXCEPTION 'Invitation role assignment parameters are required' USING ERRCODE = '23502';
  END IF;
  SELECT tenant_id INTO configured_tenant_id FROM public.tenant_settings WHERE singleton = true;
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
    contextual_actor := current_setting('app.identity_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Tenant invitation role-assignment context is missing' USING ERRCODE = '42501';
  END;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id THEN
    RAISE EXCEPTION 'Tenant invitation role-assignment context does not match this database' USING ERRCODE = '42501';
  END IF;
  IF contextual_actor IS DISTINCT FROM p_actor_identity_id THEN
    RAISE EXCEPTION 'Invitation grantor does not match the bound session' USING ERRCODE = '42501';
  END IF;
  IF cardinality(p_requested_role_codes) NOT BETWEEN 1 AND 3
     OR cardinality(p_requested_role_codes) <> (
       SELECT count(DISTINCT role_code)::integer FROM unnest(p_requested_role_codes) requested(role_code)
     )
     OR EXISTS (
       SELECT 1 FROM unnest(p_requested_role_codes) requested(role_code)
        WHERE requested.role_code NOT IN (
          'CHURCH_ADMIN','COMMITTEE_CHAIR','COMMITTEE_SECRETARY',
          'COMMITTEE_MEMBER','TALLY_CUSTODIAN','AUDITOR'
        )
     ) THEN
    RAISE EXCEPTION 'Invitation roles are not an exact supported set' USING ERRCODE = '23514';
  END IF;

  PERFORM binding.role_id
    FROM public.role_bindings binding
   WHERE binding.identity_id = p_actor_identity_id
     AND binding.revoked_at IS NULL
   ORDER BY binding.role_id
   FOR SHARE OF binding;

  IF NOT EXISTS (
    SELECT 1
      FROM public.role_bindings binding
      JOIN public.role_permissions role_permission ON role_permission.role_id = binding.role_id
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.revoked_at IS NULL
       AND role_permission.permission_code = 'role.manage'
  ) THEN
    RAISE EXCEPTION 'Tenant role management permission is required' USING ERRCODE = '42501';
  END IF;
  IF (SELECT count(*) FROM public.roles
       WHERE system_role = true AND code = ANY(p_requested_role_codes)) <> cardinality(p_requested_role_codes) THEN
    RAISE EXCEPTION 'Invitation references an unavailable tenant role' USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT requested.role_code FROM unnest(p_requested_role_codes) requested(role_code)
    EXCEPT
    SELECT DISTINCT assignment.assignable_role_code
      FROM public.role_bindings binding
      JOIN public.roles grantor_role ON grantor_role.id = binding.role_id AND grantor_role.system_role = true
      JOIN public.system_role_assignment_matrix assignment ON assignment.grantor_role_code = grantor_role.code
      JOIN public.roles assignable_role ON assignable_role.code = assignment.assignable_role_code
                                      AND assignable_role.system_role = true
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Actor cannot assign one or more invitation roles' USING ERRCODE = '42501';
  END IF;
END
$$;

DROP FUNCTION public.apply_tenant_invitation_roles(uuid,uuid,text[],uuid);

CREATE FUNCTION public.apply_tenant_invitation_roles(
  p_invitation_id uuid,
  p_invited_identity_id uuid,
  p_requested_role_codes text[],
  p_granted_by_identity_id uuid,
  p_acceptance_attempt integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  contextual_acceptance_id uuid;
  fence_record record;
  inserted_count integer;
  active_count integer;
BEGIN
  IF p_invitation_id IS NULL OR p_invited_identity_id IS NULL OR p_granted_by_identity_id IS NULL
     OR p_acceptance_attempt IS NULL OR p_acceptance_attempt <= 0 THEN
    RAISE EXCEPTION 'Invitation role parameters are required' USING ERRCODE = '23502';
  END IF;
  BEGIN
    contextual_acceptance_id := current_setting('app.session_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Invitation acceptance context is missing' USING ERRCODE = '42501';
  END;
  PERFORM public.assert_tenant_invitation_role_delegation_allowed(
    p_granted_by_identity_id,p_requested_role_codes
  );
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('tenant_invitation_fence:' || p_invitation_id::text,0)
  );
  SELECT * INTO fence_record
    FROM public.tenant_invitation_acceptance_fences
   WHERE invitation_id = p_invitation_id
   FOR UPDATE;
  IF FOUND
     AND fence_record.state = 'applied'
     AND fence_record.acceptance_attempt = p_acceptance_attempt
     AND fence_record.acceptance_id = contextual_acceptance_id
     AND fence_record.invited_identity_id = p_invited_identity_id THEN
    IF fence_record.granted_by_identity_id IS DISTINCT FROM p_granted_by_identity_id
       OR fence_record.role_codes IS DISTINCT FROM ARRAY(
         SELECT role_code FROM unnest(p_requested_role_codes) requested(role_code) ORDER BY role_code
       ) THEN
      RAISE EXCEPTION 'Applied invitation binding fence parameters changed' USING ERRCODE = '40001';
    END IF;
    SELECT count(*)::integer INTO active_count
      FROM public.role_bindings binding
      JOIN public.roles role ON role.id = binding.role_id
     WHERE identity_id = p_invited_identity_id
       AND binding.source_invitation_id = p_invitation_id
       AND binding.source_acceptance_id = contextual_acceptance_id
       AND binding.granted_by_identity_id = p_granted_by_identity_id
       AND binding.revoked_at IS NULL
       AND role.code = ANY(p_requested_role_codes);
    IF active_count = cardinality(p_requested_role_codes)
       AND NOT EXISTS (
         SELECT 1 FROM public.role_bindings binding
         JOIN public.roles role ON role.id=binding.role_id
         WHERE binding.identity_id=p_invited_identity_id AND binding.revoked_at IS NULL
           AND role.code <> ALL(p_requested_role_codes)
       ) THEN RETURN active_count; END IF;
    RAISE EXCEPTION 'Applied invitation binding fence is inconsistent' USING ERRCODE = '23514';
  END IF;
  IF FOUND AND p_acceptance_attempt <= fence_record.acceptance_attempt THEN
    RAISE EXCEPTION 'Invitation acceptance epoch is stale' USING ERRCODE = '40001';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.role_bindings binding
     WHERE binding.source_invitation_id = p_invitation_id
       AND binding.source_acceptance_id IS DISTINCT FROM contextual_acceptance_id
  ) THEN
    RAISE EXCEPTION 'A different invitation acceptance epoch already owns these bindings'
      USING ERRCODE = '40001';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.role_bindings binding
     WHERE binding.identity_id = p_invited_identity_id
       AND binding.revoked_at IS NULL
       AND binding.source_invitation_id IS DISTINCT FROM p_invitation_id
  ) THEN
    RAISE EXCEPTION 'Invitation identity already has unrelated active role bindings' USING ERRCODE = '23505';
  END IF;

  DELETE FROM public.role_bindings
   WHERE source_invitation_id = p_invitation_id
     AND source_acceptance_id = contextual_acceptance_id
     AND identity_id = p_invited_identity_id;

  INSERT INTO public.role_bindings(
    identity_id,role_id,granted_by_identity_id,source_invitation_id,source_acceptance_id
  )
  SELECT p_invited_identity_id,role.id,p_granted_by_identity_id,p_invitation_id,contextual_acceptance_id
    FROM public.roles role
   WHERE role.system_role = true AND role.code = ANY(p_requested_role_codes)
   ORDER BY role.code;
  GET DIAGNOSTICS inserted_count = ROW_COUNT;
  SELECT count(*)::integer INTO active_count
    FROM public.role_bindings
   WHERE identity_id = p_invited_identity_id AND revoked_at IS NULL;
  IF inserted_count <> cardinality(p_requested_role_codes)
     OR active_count <> cardinality(p_requested_role_codes) THEN
    RAISE EXCEPTION 'Invitation roles were not bound exactly' USING ERRCODE = '23514';
  END IF;
  INSERT INTO public.tenant_invitation_acceptance_fences(
    invitation_id,state,acceptance_attempt,acceptance_id,invited_identity_id,
    granted_by_identity_id,role_codes,updated_at
  ) VALUES (
    p_invitation_id,'applied',p_acceptance_attempt,contextual_acceptance_id,p_invited_identity_id,
    p_granted_by_identity_id,
    ARRAY(SELECT role_code FROM unnest(p_requested_role_codes) requested(role_code) ORDER BY role_code),
    clock_timestamp()
  )
  ON CONFLICT(invitation_id) DO UPDATE SET
    state=EXCLUDED.state,acceptance_attempt=EXCLUDED.acceptance_attempt,
    acceptance_id=EXCLUDED.acceptance_id,invited_identity_id=EXCLUDED.invited_identity_id,
    granted_by_identity_id=EXCLUDED.granted_by_identity_id,role_codes=EXCLUDED.role_codes,
    updated_at=EXCLUDED.updated_at;
  RETURN inserted_count;
END
$$;

DROP FUNCTION public.cleanup_tenant_invitation_roles(uuid);

CREATE FUNCTION public.cleanup_tenant_invitation_roles(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_invited_identity_id uuid,
  p_acceptance_attempt integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  configured_tenant_id uuid;
  bound_tenant_id uuid;
  contextual_identity_id uuid;
  contextual_acceptance_id uuid;
  fence_record record;
  removed_count integer;
BEGIN
  SELECT tenant_id INTO configured_tenant_id FROM public.tenant_settings WHERE singleton = true;
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
    contextual_identity_id := current_setting('app.identity_id', true)::uuid;
    contextual_acceptance_id := current_setting('app.session_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Tenant invitation cleanup context is missing' USING ERRCODE = '42501';
  END;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id
     OR contextual_identity_id IS DISTINCT FROM p_invited_identity_id
     OR contextual_acceptance_id IS DISTINCT FROM p_acceptance_id
     OR p_acceptance_attempt IS NULL OR p_acceptance_attempt <= 0 THEN
    RAISE EXCEPTION 'Tenant invitation cleanup context is invalid' USING ERRCODE = '42501';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('tenant_invitation_fence:' || p_invitation_id::text,0)
  );
  SELECT * INTO fence_record
    FROM public.tenant_invitation_acceptance_fences
   WHERE invitation_id = p_invitation_id
   FOR UPDATE;
  IF FOUND AND fence_record.acceptance_attempt > p_acceptance_attempt THEN
    RAISE EXCEPTION 'Invitation cleanup epoch is stale' USING ERRCODE = '40001';
  END IF;
  IF FOUND AND fence_record.acceptance_attempt = p_acceptance_attempt
     AND (fence_record.acceptance_id IS DISTINCT FROM p_acceptance_id
          OR fence_record.invited_identity_id IS DISTINCT FROM p_invited_identity_id) THEN
    RAISE EXCEPTION 'Invitation cleanup tuple is inconsistent' USING ERRCODE = '40001';
  END IF;
  DELETE FROM public.role_bindings
   WHERE source_invitation_id = p_invitation_id
     AND source_acceptance_id = p_acceptance_id
     AND identity_id = p_invited_identity_id;
  GET DIAGNOSTICS removed_count = ROW_COUNT;
  INSERT INTO public.tenant_invitation_acceptance_fences(
    invitation_id,state,acceptance_attempt,acceptance_id,invited_identity_id,
    granted_by_identity_id,role_codes,updated_at
  ) VALUES (
    p_invitation_id,'rolled_back',p_acceptance_attempt,p_acceptance_id,p_invited_identity_id,
    COALESCE(fence_record.granted_by_identity_id,contextual_identity_id),
    COALESCE(fence_record.role_codes,ARRAY[]::text[]),clock_timestamp()
  )
  ON CONFLICT(invitation_id) DO UPDATE SET
    state='rolled_back',acceptance_attempt=EXCLUDED.acceptance_attempt,
    acceptance_id=EXCLUDED.acceptance_id,invited_identity_id=EXCLUDED.invited_identity_id,
    granted_by_identity_id=EXCLUDED.granted_by_identity_id,role_codes=EXCLUDED.role_codes,
    updated_at=EXCLUDED.updated_at;
  RETURN removed_count;
END
$$;

-- Initial-admin activation is a separate one-time bootstrap boundary. It has
-- no caller-selectable role: exactly one built-in CHURCH_ADMIN is installed,
-- only in a pristine real tenant, against a pre-established secret verifier.
CREATE FUNCTION public.apply_tenant_initial_admin_role(
  p_invitation_id uuid,
  p_invited_identity_id uuid,
  p_granted_by_identity_id uuid,
  p_authority_epoch bigint,
  p_acceptance_attempt integer,
  p_capability_secret text
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  configured_tenant_id uuid;
  bound_tenant_id uuid;
  contextual_grantor_id uuid;
  contextual_acceptance_id uuid;
  settings_record record;
  capability_record record;
  church_admin_role_id uuid;
BEGIN
  IF p_invitation_id IS NULL OR p_invited_identity_id IS NULL OR p_granted_by_identity_id IS NULL
     OR p_authority_epoch IS NULL OR p_authority_epoch <= 0
     OR p_acceptance_attempt IS NULL OR p_acceptance_attempt <= 0
     OR p_capability_secret IS NULL OR p_capability_secret !~ '^[A-Za-z0-9_-]{43}$' THEN
    RAISE EXCEPTION 'Initial administrator activation parameters are invalid' USING ERRCODE = '23514';
  END IF;
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
    contextual_grantor_id := current_setting('app.identity_id', true)::uuid;
    contextual_acceptance_id := current_setting('app.session_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Initial administrator activation context is missing' USING ERRCODE = '42501';
  END;
  SELECT tenant_id,kind,setup_state INTO settings_record
    FROM public.tenant_settings WHERE singleton = true FOR SHARE;
  configured_tenant_id := settings_record.tenant_id;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id
     OR contextual_grantor_id IS DISTINCT FROM p_granted_by_identity_id
     OR settings_record.kind IS DISTINCT FROM 'real'
     OR settings_record.setup_state IS DISTINCT FROM 'not_started' THEN
    RAISE EXCEPTION 'Tenant is not eligible for initial administrator activation' USING ERRCODE = '42501';
  END IF;

  LOCK TABLE public.role_bindings IN SHARE ROW EXCLUSIVE MODE;
  SELECT * INTO capability_record
    FROM public.initial_admin_activation_capability
   WHERE singleton = true
   FOR UPDATE;
  IF NOT FOUND
     OR capability_record.apply_secret_hash IS DISTINCT FROM encode(sha256(convert_to(p_capability_secret,'UTF8')),'hex') THEN
    RAISE EXCEPTION 'Initial administrator activation capability is unavailable' USING ERRCODE = '42501';
  END IF;
  IF capability_record.state = 'applied'
     AND capability_record.invitation_id = p_invitation_id
     AND capability_record.acceptance_id = contextual_acceptance_id
     AND capability_record.invited_identity_id = p_invited_identity_id
     AND capability_record.grantor_identity_id = p_granted_by_identity_id
     AND capability_record.authority_epoch = p_authority_epoch
     AND capability_record.last_acceptance_attempt = p_acceptance_attempt THEN
    IF (SELECT count(*) FROM public.role_bindings binding
         JOIN public.roles role ON role.id = binding.role_id
        WHERE binding.identity_id = p_invited_identity_id
          AND binding.source_invitation_id = p_invitation_id
          AND binding.source_acceptance_id = contextual_acceptance_id
          AND binding.revoked_at IS NULL
          AND role.system_role = true AND role.code = 'CHURCH_ADMIN') = 1 THEN
      RETURN 1;
    END IF;
    RAISE EXCEPTION 'Applied initial administrator binding is inconsistent' USING ERRCODE = '23514';
  END IF;
  IF capability_record.state <> 'pending'
     OR (p_authority_epoch,p_acceptance_attempt)
          <= (capability_record.authority_epoch,capability_record.last_acceptance_attempt)
     OR EXISTS (SELECT 1 FROM public.role_bindings) THEN
    RAISE EXCEPTION 'Initial administrator activation capability cannot be reused' USING ERRCODE = '42501';
  END IF;
  SELECT role.id INTO church_admin_role_id
    FROM public.roles role
   WHERE role.system_role = true AND role.code = 'CHURCH_ADMIN';
  IF NOT FOUND OR (SELECT count(*) FROM public.roles WHERE system_role = true AND code = 'CHURCH_ADMIN') <> 1 THEN
    RAISE EXCEPTION 'Canonical initial administrator role is unavailable' USING ERRCODE = '23514';
  END IF;

  INSERT INTO public.role_bindings(
    identity_id,role_id,granted_by_identity_id,source_invitation_id,source_acceptance_id
  ) VALUES (
    p_invited_identity_id,church_admin_role_id,p_granted_by_identity_id,
    p_invitation_id,contextual_acceptance_id
  );
  UPDATE public.initial_admin_activation_capability
     SET state = 'applied',
         authority_epoch = p_authority_epoch,
         last_acceptance_attempt = p_acceptance_attempt,
         invitation_id = p_invitation_id,
         acceptance_id = contextual_acceptance_id,
         invited_identity_id = p_invited_identity_id,
         grantor_identity_id = p_granted_by_identity_id,
         applied_at = clock_timestamp(),
         consumed_at = NULL
   WHERE singleton = true;
  RETURN 1;
END
$$;

-- This operation is both compensation and an epoch fence. Even when the old
-- attempt never reached tenant apply, advancing last_acceptance_attempt makes
-- a late process carrying that old claim unable to apply later.
CREATE FUNCTION public.rollback_tenant_initial_admin_role(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_invited_identity_id uuid,
  p_grantor_identity_id uuid,
  p_authority_epoch bigint,
  p_acceptance_attempt integer,
  p_capability_secret text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  configured_tenant_id uuid;
  bound_tenant_id uuid;
  contextual_identity_id uuid;
  contextual_acceptance_id uuid;
  capability_record record;
  remove_binding boolean := false;
BEGIN
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
    contextual_identity_id := current_setting('app.identity_id', true)::uuid;
    contextual_acceptance_id := current_setting('app.session_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Initial administrator rollback context is missing' USING ERRCODE = '42501';
  END;
  SELECT tenant_id INTO configured_tenant_id FROM public.tenant_settings WHERE singleton = true FOR SHARE;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id
     OR contextual_identity_id IS DISTINCT FROM p_invited_identity_id
     OR contextual_acceptance_id IS DISTINCT FROM p_acceptance_id
     OR p_grantor_identity_id IS NULL
     OR p_authority_epoch IS NULL OR p_authority_epoch <= 0
     OR p_acceptance_attempt IS NULL OR p_acceptance_attempt <= 0
     OR p_capability_secret IS NULL OR p_capability_secret !~ '^[A-Za-z0-9_-]{43}$' THEN
    RAISE EXCEPTION 'Initial administrator rollback context is invalid' USING ERRCODE = '42501';
  END IF;
  LOCK TABLE public.role_bindings IN SHARE ROW EXCLUSIVE MODE;
  SELECT * INTO capability_record FROM public.initial_admin_activation_capability
   WHERE singleton = true FOR UPDATE;
  IF NOT FOUND
     OR capability_record.cleanup_secret_hash IS DISTINCT FROM encode(sha256(convert_to(p_capability_secret,'UTF8')),'hex')
     OR capability_record.state = 'consumed' THEN
    RETURN false;
  END IF;
  IF capability_record.state = 'applied' THEN
    IF capability_record.invitation_id IS DISTINCT FROM p_invitation_id
       OR capability_record.acceptance_id IS DISTINCT FROM p_acceptance_id
       OR capability_record.invited_identity_id IS DISTINCT FROM p_invited_identity_id
       OR capability_record.grantor_identity_id IS DISTINCT FROM p_grantor_identity_id
       OR capability_record.authority_epoch IS DISTINCT FROM p_authority_epoch
       OR capability_record.last_acceptance_attempt IS DISTINCT FROM p_acceptance_attempt THEN
      RETURN false;
    END IF;
    remove_binding := true;
  ELSIF (p_authority_epoch,p_acceptance_attempt)
        = (capability_record.authority_epoch,capability_record.last_acceptance_attempt)
        AND capability_record.invitation_id = p_invitation_id
        AND capability_record.acceptance_id = p_acceptance_id
        AND capability_record.invited_identity_id = p_invited_identity_id
        AND capability_record.grantor_identity_id = p_grantor_identity_id THEN
    RETURN NOT EXISTS (
      SELECT 1 FROM public.role_bindings binding
       WHERE binding.source_invitation_id = p_invitation_id
         AND binding.source_acceptance_id = p_acceptance_id
         AND binding.identity_id = p_invited_identity_id
    );
  ELSIF (p_authority_epoch,p_acceptance_attempt)
        <= (capability_record.authority_epoch,capability_record.last_acceptance_attempt) THEN
    RETURN false;
  END IF;
  UPDATE public.initial_admin_activation_capability
     SET state = 'pending',
         authority_epoch = p_authority_epoch,
         last_acceptance_attempt = p_acceptance_attempt,
         invitation_id = p_invitation_id, acceptance_id = p_acceptance_id,
         invited_identity_id = p_invited_identity_id,
         grantor_identity_id = p_grantor_identity_id,
         applied_at = NULL, consumed_at = NULL
   WHERE singleton = true;
  IF remove_binding THEN
    DELETE FROM public.role_bindings
     WHERE source_invitation_id = p_invitation_id
       AND source_acceptance_id = p_acceptance_id
       AND identity_id = p_invited_identity_id;
  END IF;
  RETURN true;
END
$$;

CREATE FUNCTION public.consume_tenant_initial_admin_role(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_invited_identity_id uuid,
  p_authority_epoch bigint,
  p_acceptance_attempt integer,
  p_capability_secret text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  configured_tenant_id uuid;
  bound_tenant_id uuid;
  contextual_identity_id uuid;
  contextual_acceptance_id uuid;
  capability_record record;
BEGIN
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
    contextual_identity_id := current_setting('app.identity_id', true)::uuid;
    contextual_acceptance_id := current_setting('app.session_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Initial administrator consumption context is missing' USING ERRCODE = '42501';
  END;
  SELECT tenant_id INTO configured_tenant_id FROM public.tenant_settings WHERE singleton = true FOR SHARE;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id
     OR contextual_identity_id IS DISTINCT FROM p_invited_identity_id
     OR contextual_acceptance_id IS DISTINCT FROM p_acceptance_id
     OR p_authority_epoch IS NULL OR p_authority_epoch <= 0
     OR p_acceptance_attempt IS NULL OR p_acceptance_attempt <= 0
     OR p_capability_secret IS NULL OR p_capability_secret !~ '^[A-Za-z0-9_-]{43}$' THEN
    RAISE EXCEPTION 'Initial administrator consumption context is invalid' USING ERRCODE = '42501';
  END IF;
  -- Serialize the irreversible capability transition with every role-binding
  -- grant/revocation. Once this lock is held, the exact CHURCH_ADMIN binding
  -- cannot disappear between validation and state='consumed'.
  LOCK TABLE public.role_bindings IN SHARE ROW EXCLUSIVE MODE;
  SELECT * INTO capability_record FROM public.initial_admin_activation_capability
   WHERE singleton = true FOR UPDATE;
  IF NOT FOUND
     OR capability_record.apply_secret_hash IS DISTINCT FROM encode(sha256(convert_to(p_capability_secret,'UTF8')),'hex')
     OR capability_record.invitation_id IS DISTINCT FROM p_invitation_id
     OR capability_record.acceptance_id IS DISTINCT FROM p_acceptance_id
     OR capability_record.invited_identity_id IS DISTINCT FROM p_invited_identity_id
     OR capability_record.authority_epoch IS DISTINCT FROM p_authority_epoch
     OR capability_record.last_acceptance_attempt IS DISTINCT FROM p_acceptance_attempt THEN
    RETURN false;
  END IF;
  IF capability_record.state NOT IN ('applied','consumed')
     OR (SELECT count(*) FROM public.role_bindings binding
          JOIN public.roles role ON role.id = binding.role_id
         WHERE binding.source_invitation_id = p_invitation_id
           AND binding.source_acceptance_id = p_acceptance_id
           AND binding.identity_id = p_invited_identity_id
           AND binding.granted_by_identity_id = capability_record.grantor_identity_id
           AND binding.revoked_at IS NULL
           AND role.system_role = true AND role.code = 'CHURCH_ADMIN') <> 1
     OR EXISTS (
       SELECT 1 FROM public.role_bindings binding
        JOIN public.roles role ON role.id = binding.role_id
       WHERE binding.identity_id = p_invited_identity_id
         AND binding.revoked_at IS NULL
         AND NOT (
           binding.source_invitation_id = p_invitation_id
           AND binding.source_acceptance_id = p_acceptance_id
           AND binding.granted_by_identity_id = capability_record.grantor_identity_id
           AND role.system_role = true AND role.code = 'CHURCH_ADMIN'
         )
     ) THEN
    RETURN false;
  END IF;
  IF capability_record.state = 'consumed' THEN RETURN true; END IF;
  UPDATE public.initial_admin_activation_capability
     SET state = 'consumed',consumed_at = clock_timestamp()
   WHERE singleton = true;
  RETURN true;
END
$$;

-- The same active-binding lock protects local role definition and binding
-- decisions reached by create/update/grant/revoke access operations.
CREATE OR REPLACE FUNCTION public.assert_local_role_definition_allowed(
  p_actor_identity_id uuid,
  p_permission_codes text[],
  p_delegable_permission_codes text[]
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  contextual_actor uuid;
BEGIN
  IF p_permission_codes IS NULL OR p_delegable_permission_codes IS NULL THEN
    RAISE EXCEPTION 'Local role permission arrays are required' USING ERRCODE = '23502';
  END IF;
  BEGIN
    contextual_actor := current_setting('app.identity_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Tenant access-control context is missing' USING ERRCODE = '42501';
  END;
  IF contextual_actor IS DISTINCT FROM p_actor_identity_id THEN
    RAISE EXCEPTION 'Tenant access-control actor does not match the bound session' USING ERRCODE = '42501';
  END IF;
  PERFORM binding.role_id
    FROM public.role_bindings binding
   WHERE binding.identity_id = p_actor_identity_id AND binding.revoked_at IS NULL
   ORDER BY binding.role_id FOR SHARE OF binding;
  IF NOT EXISTS (
    SELECT 1 FROM public.role_bindings binding
    JOIN public.role_permissions role_permission ON role_permission.role_id = binding.role_id
    WHERE binding.identity_id = p_actor_identity_id AND binding.revoked_at IS NULL
      AND role_permission.permission_code = 'role.manage'
  ) THEN
    RAISE EXCEPTION 'Tenant role management permission is required' USING ERRCODE = '42501';
  END IF;
  IF cardinality(p_permission_codes) NOT BETWEEN 1 AND 40
     OR cardinality(p_permission_codes) <> (SELECT count(DISTINCT permission_code)::integer FROM unnest(p_permission_codes) requested(permission_code))
     OR EXISTS (SELECT 1 FROM unnest(p_permission_codes) requested(permission_code) WHERE permission_code IS NULL)
     OR cardinality(p_delegable_permission_codes) <> (SELECT count(DISTINCT permission_code)::integer FROM unnest(p_delegable_permission_codes) requested(permission_code))
     OR EXISTS (SELECT 1 FROM unnest(p_delegable_permission_codes) requested(permission_code) WHERE permission_code IS NULL)
     OR EXISTS (SELECT 1 FROM unnest(p_delegable_permission_codes) delegated(permission_code)
                 WHERE NOT delegated.permission_code = ANY(p_permission_codes)) THEN
    RAISE EXCEPTION 'Local role permission set is invalid' USING ERRCODE = '23514';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(p_permission_codes) requested(permission_code) WHERE permission_code LIKE 'platform.%')
     OR (SELECT count(*) FROM public.permissions WHERE code = ANY(p_permission_codes)) <> cardinality(p_permission_codes) THEN
    RAISE EXCEPTION 'Local roles cannot contain unknown or platform permissions' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (
    SELECT requested.permission_code FROM unnest(p_permission_codes) requested(permission_code)
    EXCEPT
    SELECT DISTINCT role_permission.permission_code FROM public.role_bindings binding
    JOIN public.role_permissions role_permission ON role_permission.role_id = binding.role_id
    WHERE binding.identity_id = p_actor_identity_id AND binding.revoked_at IS NULL AND role_permission.delegable
  ) THEN
    RAISE EXCEPTION 'Actor cannot delegate one or more requested permissions' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (
    SELECT requested.permission_code FROM unnest(p_delegable_permission_codes) requested(permission_code)
    EXCEPT
    SELECT DISTINCT role_permission.permission_code FROM public.role_bindings binding
    JOIN public.role_permissions role_permission ON role_permission.role_id = binding.role_id
    WHERE binding.identity_id = p_actor_identity_id AND binding.revoked_at IS NULL AND role_permission.delegable
  ) THEN
    RAISE EXCEPTION 'Actor cannot pass delegation authority it does not possess' USING ERRCODE = '42501';
  END IF;
END
$$;

REVOKE ALL ON FUNCTION public.assert_tenant_invitation_role_delegation_allowed(uuid,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.apply_tenant_invitation_roles(uuid,uuid,text[],uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.cleanup_tenant_invitation_roles(uuid,uuid,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.apply_tenant_initial_admin_role(uuid,uuid,uuid,bigint,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rollback_tenant_initial_admin_role(uuid,uuid,uuid,uuid,bigint,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.consume_tenant_initial_admin_role(uuid,uuid,uuid,bigint,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_applied_initial_admin_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assert_local_role_definition_allowed(uuid,text[],text[]) FROM PUBLIC;
