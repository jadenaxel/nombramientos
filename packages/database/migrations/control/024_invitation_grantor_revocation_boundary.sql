-- Invitation authority is not homogeneous. Ordinary invitations are delegated
-- by an active tenant member, while the one-time initial-administrator
-- invitation is delegated by a platform administrator before the tenant has
-- any member. Persist the distinction and prove every historical row before
-- making it mandatory; an ambiguous upgrade must stop rather than guess.
ALTER TABLE tenants
  ADD COLUMN initial_admin_authority_epoch bigint NOT NULL DEFAULT 0
    CHECK (initial_admin_authority_epoch >= 0);

ALTER TABLE tenant_invitations
  ADD COLUMN authority_kind text,
  -- The cross-field authority constraint below also proves this nonnegative;
  -- do not create PostgreSQL's implicit *_authority_epoch_check name here,
  -- because the stronger semantic constraint deliberately owns that name.
  ADD COLUMN authority_epoch bigint NOT NULL DEFAULT 0,
  ADD COLUMN acceptance_attempt integer NOT NULL DEFAULT 0 CHECK (acceptance_attempt >= 0),
  ADD COLUMN acceptance_recovery_hash text
    CHECK (acceptance_recovery_hash IS NULL OR acceptance_recovery_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN authority_finalized_at timestamptz,
  ADD COLUMN tenant_cleanup_completed_at timestamptz,
  ADD COLUMN reconciliation_attempt_count integer NOT NULL DEFAULT 0
    CHECK (reconciliation_attempt_count >= 0),
  ADD COLUMN reconciliation_next_attempt_at timestamptz,
  ADD COLUMN reconciliation_claimed_at timestamptz,
  ADD COLUMN reconciliation_lease_expires_at timestamptz,
  ADD COLUMN reconciliation_lease_token uuid,
  ADD COLUMN reconciliation_last_error_code text
    CHECK (
      reconciliation_last_error_code IS NULL
      OR reconciliation_last_error_code ~ '^[A-Z][A-Z0-9_]{0,95}$'
    ),
  ADD CONSTRAINT tenant_invitations_authority_kind_check
    CHECK (authority_kind IN ('tenant_delegate','initial_admin'));

-- Provenance is authoritative; a current membership is only mutable context
-- and does not make a historical platform bootstrap ambiguous. Two conflicting
-- immutable audit/provisioning provenances, or a partial historical acceptance
-- tuple, do make the upgrade ambiguous and must abort before any backfill.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM public.tenant_invitations invitation
     WHERE (
       EXISTS (
         SELECT 1 FROM public.provisioning_jobs job
          WHERE job.tenant_id = invitation.tenant_id
            AND job.idempotency_key = invitation.idempotency_key
            AND job.request_payload->'initialAdmin'->>'mode' = 'invitation'
            AND job.request_payload->'initialAdmin'->>'normalizedEmail' = invitation.normalized_email
            AND job.request_payload->'initialAdmin'->>'tokenHash' = invitation.token_hash
            AND job.request_payload->'initialAdmin'->>'createdByIdentityId' = invitation.created_by_identity_id::text
       )
       OR EXISTS (
         SELECT 1 FROM public.platform_audit_events event
          WHERE event.action = 'platform.initial_admin_invited'
            AND event.result = 'success'
            AND event.entity_type = 'tenant_invitation'
            AND event.entity_id = invitation.id::text
            AND event.tenant_id = invitation.tenant_id
            AND event.actor_identity_id = invitation.created_by_identity_id
       )
     )
       AND EXISTS (
         SELECT 1 FROM public.platform_audit_events event
          WHERE event.action = 'invitation.created'
            AND event.result = 'success'
            AND event.entity_type = 'tenant_invitation'
            AND event.entity_id = invitation.id::text
            AND event.tenant_id = invitation.tenant_id
            AND event.actor_identity_id = invitation.created_by_identity_id
       )
  ) THEN
    RAISE EXCEPTION 'Historical invitation has conflicting immutable authority provenance'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_authority_ambiguous';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_invitations invitation
     WHERE (invitation.acceptance_id IS NULL) <> (invitation.acceptance_identity_id IS NULL)
        OR (invitation.acceptance_id IS NULL) <> (invitation.acceptance_started_at IS NULL)
        OR (invitation.status IN ('accepting','accepted') AND invitation.acceptance_id IS NULL)
  ) THEN
    RAISE EXCEPTION 'Historical invitation acceptance tuple is partial'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_acceptance_ambiguous';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_invitations invitation
     WHERE invitation.status = 'accepting'
  ) THEN
    RAISE EXCEPTION 'Historical in-flight invitation requires operator reconciliation before upgrade'
      USING ERRCODE = '23514', CONSTRAINT = 'legacy_invitation_acceptance_reconciliation_required';
  END IF;
END
$$;

UPDATE tenant_invitations invitation
   SET authority_kind = 'initial_admin'
 WHERE invitation.role_codes = ARRAY['CHURCH_ADMIN']::text[]
   AND (
     EXISTS (
       SELECT 1
         FROM provisioning_jobs job
        WHERE job.tenant_id = invitation.tenant_id
          AND job.idempotency_key = invitation.idempotency_key
          AND job.request_payload->'initialAdmin'->>'mode' = 'invitation'
          AND job.request_payload->'initialAdmin'->>'normalizedEmail' = invitation.normalized_email
          AND job.request_payload->'initialAdmin'->>'tokenHash' = invitation.token_hash
          AND job.request_payload->'initialAdmin'->>'createdByIdentityId' = invitation.created_by_identity_id::text
     )
     OR EXISTS (
       SELECT 1
         FROM platform_audit_events event
        WHERE event.action = 'platform.initial_admin_invited'
          AND event.result = 'success'
          AND event.entity_type = 'tenant_invitation'
          AND event.entity_id = invitation.id::text
          AND event.tenant_id = invitation.tenant_id
          AND event.actor_identity_id = invitation.created_by_identity_id
          AND event.metadata->'roles' = '["CHURCH_ADMIN"]'::jsonb
     )
   );

UPDATE tenant_invitations invitation
   SET authority_kind = 'tenant_delegate'
 WHERE invitation.authority_kind IS NULL
   AND (
     EXISTS (
       SELECT 1
         FROM tenant_memberships membership
        WHERE membership.tenant_id = invitation.tenant_id
          AND membership.identity_id = invitation.created_by_identity_id
     )
     OR EXISTS (
       SELECT 1
         FROM platform_audit_events event
        WHERE event.action = 'invitation.created'
          AND event.result = 'success'
          AND event.entity_type = 'tenant_invitation'
          AND event.entity_id = invitation.id::text
          AND event.tenant_id = invitation.tenant_id
          AND event.actor_identity_id = invitation.created_by_identity_id
          AND event.metadata->'roles' = to_jsonb(invitation.role_codes)
     )
   );

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM tenant_invitations WHERE authority_kind IS NULL) THEN
    RAISE EXCEPTION 'Historical invitation authority cannot be proven'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_authority_ambiguous';
  END IF;
END
$$;

WITH ranked AS (
  SELECT invitation.id,
         row_number() OVER (
           PARTITION BY invitation.tenant_id
           ORDER BY invitation.created_at,invitation.id
         )::bigint AS authority_epoch
    FROM tenant_invitations invitation
   WHERE invitation.authority_kind = 'initial_admin'
)
UPDATE tenant_invitations invitation
   SET authority_epoch = ranked.authority_epoch
  FROM ranked
 WHERE invitation.id = ranked.id;

UPDATE tenants tenant
   SET initial_admin_authority_epoch = evidence.maximum_epoch
  FROM (
    SELECT tenant_id,max(authority_epoch) AS maximum_epoch
      FROM tenant_invitations
     WHERE authority_kind = 'initial_admin'
     GROUP BY tenant_id
  ) evidence
 WHERE tenant.id = evidence.tenant_id;

UPDATE tenant_invitations
   SET acceptance_attempt = 1
 WHERE acceptance_id IS NOT NULL
   AND acceptance_attempt = 0;

ALTER TABLE tenant_invitations
  ALTER COLUMN authority_kind SET DEFAULT 'tenant_delegate',
  ALTER COLUMN authority_kind SET NOT NULL;

ALTER TABLE tenant_invitations
  DROP CONSTRAINT tenant_invitations_status_check,
  ADD CONSTRAINT tenant_invitations_status_check CHECK (status IN (
    'pending','accepting','compensating','accepted','revoked','expired','failed'
  )),
  ADD CONSTRAINT tenant_invitations_compensation_claim_check CHECK (
    status NOT IN ('accepting','compensating','accepted')
    OR (acceptance_id IS NOT NULL AND acceptance_identity_id IS NOT NULL
        AND acceptance_started_at IS NOT NULL AND acceptance_attempt > 0)
  ),
  ADD CONSTRAINT tenant_invitations_authority_epoch_check CHECK (
    (authority_kind = 'tenant_delegate' AND authority_epoch = 0)
    OR (authority_kind = 'initial_admin' AND authority_epoch > 0
        AND role_codes = ARRAY['CHURCH_ADMIN']::text[])
  ),
  ADD CONSTRAINT tenant_invitations_authority_finalization_check CHECK (
    authority_finalized_at IS NULL
    OR (authority_kind = 'initial_admin' AND status = 'accepted')
  ),
  ADD CONSTRAINT tenant_invitations_cleanup_completion_check CHECK (
    tenant_cleanup_completed_at IS NULL
    OR status IN ('revoked','expired','failed')
  ),
  ADD CONSTRAINT tenant_invitations_reconciliation_lease_check CHECK (
    (
      reconciliation_claimed_at IS NULL
      AND reconciliation_lease_expires_at IS NULL
      AND reconciliation_lease_token IS NULL
    )
    OR (
      reconciliation_claimed_at IS NOT NULL
      AND reconciliation_lease_expires_at > reconciliation_claimed_at
      AND reconciliation_lease_token IS NOT NULL
    )
  );

CREATE INDEX tenant_invitations_reconciliation_queue
  ON tenant_invitations(
    reconciliation_next_attempt_at,
    reconciliation_lease_expires_at,
    acceptance_started_at,
    id
  )
  WHERE acceptance_id IS NOT NULL AND acceptance_identity_id IS NOT NULL;

CREATE INDEX tenant_invitations_open_grantor
  ON tenant_invitations(created_by_identity_id,tenant_id,authority_kind,id)
  WHERE status IN ('pending','accepting','compensating');

DROP INDEX tenant_invitations_one_open_email;
CREATE UNIQUE INDEX tenant_invitations_one_open_email
  ON tenant_invitations(normalized_email)
  WHERE status IN ('pending','accepting','compensating');

CREATE UNIQUE INDEX tenant_invitations_acceptance_id_unique
  ON tenant_invitations(acceptance_id)
  WHERE acceptance_id IS NOT NULL;

CREATE UNIQUE INDEX tenant_invitations_acceptance_identity_unique
  ON tenant_invitations(acceptance_identity_id)
  WHERE acceptance_identity_id IS NOT NULL;

-- Keep the sanitized lifecycle summary tied to explicit bootstrap authority.
-- A delegated CHURCH_ADMIN invitation must never make the platform report the
-- one-time initial administrator as active.
CREATE OR REPLACE VIEW public.platform_tenant_summaries
WITH (security_barrier = true)
AS
SELECT COALESCE(tenant.id, job.tenant_id) AS id,
       COALESCE(tenant.slug, job.request_payload->>'slug', job.requested_slug) AS slug,
       COALESCE(tenant.display_name, job.request_payload->>'displayName') AS display_name,
       COALESCE(tenant.kind, job.request_payload->>'kind') AS kind,
       CASE
         WHEN job.state = 'pending_activation' THEN 'provisioning'
         WHEN job.request_payload->'initialAdmin'->>'mode' = 'invitation'
          AND COALESCE(initial_admin.status, 'missing') NOT IN ('pending','accepting','accepted')
           THEN 'provisioning'
         ELSE COALESCE(tenant.status, 'provisioning')
       END AS status,
       COALESCE(tenant.timezone, job.request_payload->>'timezone') AS timezone,
       COALESCE(tenant.locale, job.request_payload->>'locale') AS locale,
       COALESCE(tenant.version, 0) AS version,
       job.state AS provisioning_state,
       COALESCE(job.attempt_count, 0) AS attempt_count,
       job.last_error_code,
       CASE
         WHEN initial_admin.status = 'accepted'
          AND initial_admin.authority_finalized_at IS NOT NULL
          AND initial_admin.strong_factor_enrolled THEN 'admin_active'
         WHEN initial_admin.status IN ('pending','accepting','accepted') THEN 'invitation_pending'
         WHEN job.state = 'pending_activation'
           OR job.request_payload->'initialAdmin'->>'mode' = 'pending'
           OR job.request_payload->'initialAdmin'->>'mode' = 'invitation' THEN 'pending_activation'
         ELSE 'active'
       END AS activation_state,
       latest_export.id AS export_id,
       latest_export.tenant_version AS export_tenant_version,
       latest_export.state AS export_state,
       latest_export.attempt_count AS export_attempt_count,
       latest_export.revision AS export_revision,
       latest_export.public_manifest AS export_public_manifest,
       latest_export.encrypted_bytes AS export_encrypted_bytes,
       latest_export.ciphertext_sha256 AS export_ciphertext_sha256,
       latest_export.recovery_point_at AS export_recovery_point_at,
       latest_export.last_error_code AS export_last_error_code,
       latest_export.created_at AS export_created_at,
       latest_export.updated_at AS export_updated_at,
       latest_export.ready_at AS export_ready_at,
       latest_export.failed_at AS export_failed_at,
       decommission.id AS decommission_id,
       decommission.state AS decommission_state,
       decommission.source_export_job_id AS decommission_export_job_id,
       decommission.reason_code AS decommission_reason_code,
       decommission.retention_until AS decommission_retention_until,
       decommission.version AS decommission_version,
       decommission.scheduled_at AS decommission_scheduled_at,
       decommission.cancelled_at AS decommission_cancelled_at,
       COALESCE(tenant.created_at, job.created_at) AS created_at,
       COALESCE(tenant.updated_at, job.updated_at) AS updated_at
  FROM public.tenants tenant
  FULL JOIN public.provisioning_jobs job ON job.tenant_id = tenant.id
  LEFT JOIN LATERAL (
    SELECT invitation.status,
           invitation.authority_finalized_at,
           (
             (
               identity.mfa_enabled
               AND identity.totp_secret_ciphertext IS NOT NULL
             )
             OR (
               identity.passkey_enabled
               AND identity.passkey_enrolled_at IS NOT NULL
               AND EXISTS (
                 SELECT 1
                   FROM public.webauthn_credentials credential
                  WHERE credential.identity_id = identity.id
                    AND credential.revoked_at IS NULL
                    AND credential.user_verified
               )
             )
           ) AS strong_factor_enrolled
      FROM public.tenant_invitations invitation
      LEFT JOIN public.platform_identities identity
        ON identity.id = invitation.acceptance_identity_id
       AND identity.status = 'active'
     WHERE invitation.tenant_id = COALESCE(tenant.id, job.tenant_id)
       AND invitation.authority_kind = 'initial_admin'
       AND invitation.role_codes = ARRAY['CHURCH_ADMIN']::text[]
     ORDER BY invitation.authority_epoch DESC, invitation.created_at DESC, invitation.id DESC
     LIMIT 1
  ) initial_admin ON true
  LEFT JOIN LATERAL (
    SELECT export.id, export.tenant_version, export.state, export.attempt_count, export.revision,
           export.public_manifest, export.encrypted_bytes, export.ciphertext_sha256,
           export.recovery_point_at, export.last_error_code, export.created_at, export.updated_at,
           export.ready_at, export.failed_at
      FROM public.tenant_export_jobs export
     WHERE export.tenant_id = COALESCE(tenant.id, job.tenant_id)
     ORDER BY export.created_at DESC, export.id DESC
     LIMIT 1
  ) latest_export ON true
  LEFT JOIN public.tenant_decommission_requests decommission
    ON decommission.id = tenant.decommission_request_id
 WHERE tenant.id IS NOT NULL OR job.request_payload IS NOT NULL;

-- The runtime cannot lock control authority tables directly. This narrow
-- definer is the single authority->invitation ordering boundary used by claim
-- and completion. It first verifies the immutable invitation tuple without a
-- row lock, then locks only the authority rows appropriate to its explicit
-- kind. The caller locks/revalidates the invitation afterwards.
CREATE FUNCTION lock_active_invitation_grantor(
  p_invitation_id uuid,
  p_grantor_identity_id uuid,
  p_tenant_id uuid,
  p_authority_kind text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  invitation_roles text[];
BEGIN
  IF p_invitation_id IS NULL OR p_grantor_identity_id IS NULL OR p_tenant_id IS NULL
     OR p_authority_kind NOT IN ('tenant_delegate','initial_admin') THEN
    RETURN false;
  END IF;

  SELECT invitation.role_codes
    INTO invitation_roles
    FROM public.tenant_invitations invitation
   WHERE invitation.id = p_invitation_id
     AND invitation.created_by_identity_id = p_grantor_identity_id
     AND invitation.tenant_id = p_tenant_id
     AND invitation.authority_kind = p_authority_kind;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('tenant_identity_policy:' || p_tenant_id::text, 0)
  );

  IF p_authority_kind = 'tenant_delegate' THEN
    PERFORM 1
      FROM public.platform_identities identity
      JOIN public.tenant_memberships membership
        ON membership.identity_id = identity.id
       AND membership.tenant_id = p_tenant_id
      JOIN public.tenants tenant ON tenant.id = membership.tenant_id
     WHERE identity.id = p_grantor_identity_id
       AND identity.status = 'active'
       AND membership.status = 'active'
       AND tenant.status = 'active'
     FOR SHARE OF identity,membership,tenant;
    RETURN FOUND;
  END IF;

  IF invitation_roles IS DISTINCT FROM ARRAY['CHURCH_ADMIN']::text[] THEN
    RETURN false;
  END IF;
  PERFORM 1
    FROM public.platform_identities identity
    JOIN public.platform_role_bindings binding
      ON binding.identity_id = identity.id
     AND binding.role_code = 'platform_admin'
    JOIN public.tenants tenant ON tenant.id = p_tenant_id
    JOIN public.provisioning_jobs job ON job.tenant_id = tenant.id
   WHERE identity.id = p_grantor_identity_id
     AND identity.status = 'active'
     AND tenant.status = 'active'
     AND tenant.kind = 'real'
     AND job.state = 'active'
     AND NOT EXISTS (
       SELECT 1 FROM public.tenant_memberships membership
        WHERE membership.tenant_id = p_tenant_id
     )
   FOR SHARE OF identity,binding,tenant,job;
  RETURN FOUND;
END
$$;

-- The stored verifier is deliberately not readable by the runtime role and is
-- never accepted as a bearer.  Only the canonical 256-bit token preimage may
-- cross this boundary; PostgreSQL hashes it internally before returning
-- non-secret invitation metadata.  This lookup intentionally takes no row
-- lock: claim ordering remains authority -> invitation and cannot deadlock
-- with offboarding. Expiry is terminalized only by begin after authority is
-- locked.
CREATE FUNCTION find_tenant_invitation_idempotency(
  p_tenant_id uuid,
  p_actor_identity_id uuid,
  p_idempotency_key uuid
)
RETURNS TABLE(
  id uuid,tenant_id uuid,email text,normalized_email text,role_codes text[],status text,
  request_hash text,created_by_identity_id uuid,created_at timestamptz,expires_at timestamptz,
  acceptance_started_at timestamptz,accepted_at timestamptz,revoked_at timestamptz,version integer
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT invitation.id,invitation.tenant_id,invitation.email,invitation.normalized_email,
         invitation.role_codes,invitation.status,invitation.request_hash,
         invitation.created_by_identity_id,invitation.created_at,invitation.expires_at,
         invitation.acceptance_started_at,invitation.accepted_at,invitation.revoked_at,
         invitation.version
    FROM public.tenant_invitations invitation
   WHERE invitation.tenant_id = p_tenant_id
     AND invitation.created_by_identity_id = p_actor_identity_id
     AND invitation.idempotency_key = p_idempotency_key
   FOR UPDATE OF invitation
$$;

CREATE FUNCTION inspect_tenant_invitation_bearer(
  p_token text,
  p_normalized_email text,
  p_recovery_proof text
)
RETURNS TABLE(
  id uuid,
  tenant_id uuid,
  email text,
  normalized_email text,
  role_codes text[],
  status text,
  request_hash text,
  created_by_identity_id uuid,
  authority_kind text,
  authority_epoch bigint,
  acceptance_attempt integer,
  acceptance_id uuid,
  acceptance_identity_id uuid,
  created_at timestamptz,
  expires_at timestamptz,
  acceptance_started_at timestamptz,
  accepted_at timestamptz,
  revoked_at timestamptz,
  version integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  bearer_hash text;
  recovery_hash text;
BEGIN
  IF p_token IS NULL OR p_token !~ '^[A-Za-z0-9_-]{43}$'
     OR p_recovery_proof IS NULL OR p_recovery_proof !~ '^[A-Za-z0-9_-]{43}$'
     OR p_normalized_email IS NULL
     OR p_normalized_email IS DISTINCT FROM lower(btrim(p_normalized_email)) THEN
    RETURN;
  END IF;
  bearer_hash := encode(sha256(convert_to(p_token,'UTF8')),'hex');
  recovery_hash := encode(sha256(convert_to(p_recovery_proof,'UTF8')),'hex');
  RETURN QUERY
  SELECT invitation.id,invitation.tenant_id,invitation.email,invitation.normalized_email,
         invitation.role_codes,invitation.status,invitation.request_hash,
         invitation.created_by_identity_id,invitation.authority_kind,
         invitation.authority_epoch,invitation.acceptance_attempt,
         invitation.acceptance_id,invitation.acceptance_identity_id,
         invitation.created_at,invitation.expires_at,invitation.acceptance_started_at,
         invitation.accepted_at,invitation.revoked_at,invitation.version
    FROM public.tenant_invitations invitation
   WHERE invitation.token_hash = bearer_hash
     AND invitation.normalized_email = p_normalized_email
     AND (
       invitation.status = 'pending'
       OR invitation.acceptance_recovery_hash = recovery_hash
     );
END
$$;

-- acceptance_attempt is authority metadata and is intentionally not directly
-- writable by the runtime role. This definer performs the post-authority-lock
-- row CAS and increments the monotonic attempt in one statement. The raw
-- bearer is hashed internally so disclosure of token_hash is never sufficient.
CREATE FUNCTION begin_tenant_invitation_acceptance(
  p_invitation_id uuid,
  p_token text,
  p_normalized_email text,
  p_recovery_proof text,
  p_grantor_identity_id uuid,
  p_tenant_id uuid,
  p_authority_kind text,
  p_acceptance_id uuid,
  p_identity_id uuid
)
RETURNS TABLE(
  id uuid,
  tenant_id uuid,
  email text,
  normalized_email text,
  role_codes text[],
  expires_at timestamptz,
  created_by_identity_id uuid,
  authority_kind text,
  authority_epoch bigint,
  acceptance_attempt integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_token IS NULL OR p_token !~ '^[A-Za-z0-9_-]{43}$'
     OR p_recovery_proof IS NULL OR p_recovery_proof !~ '^[A-Za-z0-9_-]{43}$'
     OR p_acceptance_id IS NULL OR p_identity_id IS NULL THEN
    RETURN;
  END IF;
  UPDATE public.tenant_invitations invitation
     SET status = 'expired',updated_at = clock_timestamp(),version = invitation.version + 1
   WHERE invitation.id = p_invitation_id
     AND invitation.token_hash = encode(sha256(convert_to(p_token,'UTF8')),'hex')
     AND invitation.normalized_email = p_normalized_email
     AND invitation.created_by_identity_id = p_grantor_identity_id
     AND invitation.tenant_id = p_tenant_id
     AND invitation.authority_kind = p_authority_kind
     AND invitation.status = 'pending'
     AND invitation.expires_at <= clock_timestamp();

  RETURN QUERY
  UPDATE public.tenant_invitations invitation
     SET status = 'accepting',
         acceptance_id = p_acceptance_id,
         acceptance_identity_id = p_identity_id,
         acceptance_started_at = clock_timestamp(),
         acceptance_attempt = invitation.acceptance_attempt + 1,
         acceptance_recovery_hash = encode(sha256(convert_to(p_recovery_proof,'UTF8')),'hex'),
         last_error_code = NULL,
         updated_at = clock_timestamp(),
         version = invitation.version + 1
   WHERE invitation.id = p_invitation_id
     AND p_token ~ '^[A-Za-z0-9_-]{43}$'
     AND invitation.token_hash = encode(sha256(convert_to(p_token,'UTF8')),'hex')
     AND invitation.normalized_email = p_normalized_email
     AND invitation.created_by_identity_id = p_grantor_identity_id
     AND invitation.tenant_id = p_tenant_id
     AND invitation.authority_kind = p_authority_kind
     AND (
       (invitation.authority_kind = 'tenant_delegate' AND invitation.authority_epoch = 0)
       OR (invitation.authority_kind = 'initial_admin' AND invitation.authority_epoch > 0)
     )
     AND invitation.status = 'pending'
     AND invitation.expires_at > clock_timestamp()
  RETURNING invitation.id,invitation.tenant_id,invitation.email,
            invitation.normalized_email,invitation.role_codes,invitation.expires_at,
            invitation.created_by_identity_id,invitation.authority_kind,
            invitation.authority_epoch,invitation.acceptance_attempt;
END
$$;

-- Compensation must win a control-plane CAS before any tenant binding can be
-- removed. It therefore linearizes against the 021 accepting->accepted CAS.
CREATE FUNCTION begin_tenant_invitation_compensation(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_identity_id uuid,
  p_acceptance_attempt integer
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  WITH changed AS (
    UPDATE public.tenant_invitations invitation
       SET status = 'compensating',updated_at = clock_timestamp(),version = invitation.version + 1
     WHERE invitation.id = p_invitation_id
       AND invitation.acceptance_id = p_acceptance_id
       AND invitation.acceptance_identity_id = p_identity_id
       AND invitation.acceptance_attempt = p_acceptance_attempt
       AND invitation.status = 'accepting'
    RETURNING 1
  )
  SELECT EXISTS (SELECT 1 FROM changed)
$$;

-- Migration 021 predates the monotonic acceptance fence. Preserve its audited
-- implementation behind an owner-only private name, strip every inherited
-- EXECUTE ACL, and expose only an attempt-aware wrapper. The wrapper locks the
-- exact attempt before entering the 021 atomic identity/membership/session
-- transaction, eliminating acceptance-id ABA even if a tuple is reused.
ALTER FUNCTION public.complete_tenant_invitation_acceptance(
  uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text
) RENAME TO complete_tenant_invitation_acceptance_021_private;

REVOKE ALL ON FUNCTION public.complete_tenant_invitation_acceptance_021_private(
  uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text
) FROM PUBLIC;

DO $$
DECLARE
  grantee_name text;
BEGIN
  FOR grantee_name IN
    SELECT DISTINCT role.rolname
      FROM pg_catalog.pg_proc procedure
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(procedure.proacl,pg_catalog.acldefault('f',procedure.proowner))
      ) privilege
      JOIN pg_catalog.pg_roles role ON role.oid = privilege.grantee
     WHERE namespace.nspname = 'public'
       AND procedure.proname = 'complete_tenant_invitation_acceptance_021_private'
       AND pg_catalog.pg_get_function_identity_arguments(procedure.oid) =
           'uuid, uuid, uuid, uuid, text, text, text, uuid, text, text, timestamp with time zone, text, text, text'
       AND privilege.privilege_type = 'EXECUTE'
       AND privilege.grantee <> procedure.proowner
  LOOP
    EXECUTE pg_catalog.format(
      'REVOKE ALL ON FUNCTION public.complete_tenant_invitation_acceptance_021_private(uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text) FROM %I',
      grantee_name
    );
  END LOOP;
END
$$;

CREATE FUNCTION public.complete_tenant_invitation_acceptance(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_identity_id uuid,
  p_acceptance_attempt integer,
  p_tenant_id uuid,
  p_normalized_email text,
  p_display_name text,
  p_password_hash text,
  p_session_id uuid,
  p_session_token_hash text,
  p_csrf_hash text,
  p_session_expires_at timestamptz,
  p_user_agent_hash text,
  p_ip_prefix_hash text,
  p_disabled_password_hash text
)
RETURNS TABLE(completed boolean,session_expires_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_acceptance_attempt IS NULL OR p_acceptance_attempt <= 0 THEN
    RETURN QUERY SELECT false,NULL::timestamptz;
    RETURN;
  END IF;
  PERFORM 1
    FROM public.tenant_invitations invitation
   WHERE invitation.id = p_invitation_id
     AND invitation.acceptance_id = p_acceptance_id
     AND invitation.acceptance_identity_id = p_identity_id
     AND invitation.acceptance_attempt = p_acceptance_attempt
     AND invitation.tenant_id = p_tenant_id
     AND invitation.normalized_email = p_normalized_email
     AND invitation.status = 'accepting'
   FOR UPDATE OF invitation;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,NULL::timestamptz;
    RETURN;
  END IF;
  RETURN QUERY
  SELECT result.completed,result.session_expires_at
    FROM public.complete_tenant_invitation_acceptance_021_private(
      p_invitation_id,p_acceptance_id,p_identity_id,p_tenant_id,
      p_normalized_email,p_display_name,p_password_hash,p_session_id,
      p_session_token_hash,p_csrf_hash,p_session_expires_at,p_user_agent_hash,
      p_ip_prefix_hash,p_disabled_password_hash
    ) result;
END
$$;

-- If the control commit succeeded but the HTTP response/cookie was lost, the
-- invitation bearer may rotate the short-lived enrollment-only session. The
-- recovery bearer is bounded to 24 hours, while every issued session remains
-- bounded to ten minutes, and recovery stops immediately after any strong
-- authenticator is enrolled. The old enrollment session is revoked in the
-- same transaction.
CREATE FUNCTION recover_tenant_invitation_enrollment_session(
  p_invitation_id uuid,
  p_token text,
  p_recovery_proof text,
  p_normalized_email text,
  p_session_id uuid,
  p_session_token_hash text,
  p_csrf_hash text,
  p_session_expires_at timestamptz,
  p_user_agent_hash text,
  p_ip_prefix_hash text
)
RETURNS TABLE(recovered boolean,identity_id uuid,tenant_id uuid,session_expires_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  invitation_record record;
  issued_expires_at timestamptz;
BEGIN
  IF p_invitation_id IS NULL OR p_token !~ '^[A-Za-z0-9_-]{43}$'
     OR p_recovery_proof !~ '^[A-Za-z0-9_-]{43}$'
     OR p_session_id IS NULL OR p_session_token_hash !~ '^[0-9a-f]{64}$'
     OR p_csrf_hash !~ '^[0-9a-f]{64}$' OR p_session_expires_at <= clock_timestamp()
     OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^[0-9a-f]{64}$')
     OR (p_ip_prefix_hash IS NOT NULL AND p_ip_prefix_hash !~ '^[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'Invitation enrollment recovery input is invalid' USING ERRCODE = '23514';
  END IF;
  SELECT invitation.acceptance_identity_id AS identity_id,
         invitation.tenant_id,invitation.accepted_at
    INTO invitation_record
    FROM public.tenant_invitations invitation
    JOIN public.platform_identities identity ON identity.id=invitation.acceptance_identity_id
    JOIN public.tenant_memberships membership
      ON membership.identity_id=identity.id AND membership.tenant_id=invitation.tenant_id
    JOIN public.tenants tenant ON tenant.id=membership.tenant_id
   WHERE invitation.id=p_invitation_id
     AND invitation.token_hash=encode(sha256(convert_to(p_token,'UTF8')),'hex')
     AND invitation.acceptance_recovery_hash=
         encode(sha256(convert_to(p_recovery_proof,'UTF8')),'hex')
     AND invitation.normalized_email=p_normalized_email
     AND invitation.status='accepted'
     AND invitation.accepted_at>clock_timestamp()-interval '24 hours'
     AND identity.status='active'
     AND identity.mfa_enabled=false
     AND identity.passkey_enabled=false
     AND membership.status='active'
     AND tenant.status='active'
     AND NOT EXISTS (
       SELECT 1 FROM public.webauthn_credentials credential
        WHERE credential.identity_id=identity.id AND credential.revoked_at IS NULL
     )
   FOR UPDATE OF invitation,identity,membership,tenant;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::timestamptz;
    RETURN;
  END IF;
  issued_expires_at := LEAST(
    p_session_expires_at,
    invitation_record.accepted_at + interval '24 hours',
    clock_timestamp() + interval '10 minutes'
  );
  IF issued_expires_at <= clock_timestamp() THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::timestamptz;
    RETURN;
  END IF;
  UPDATE public.auth_sessions
     SET revoked_at=clock_timestamp(),revoke_reason='invitation_enrollment_rotated'
   WHERE invitation_id=p_invitation_id
     AND identity_id=invitation_record.identity_id
     AND enrollment_source='invitation'
     AND revoked_at IS NULL;
  INSERT INTO public.auth_sessions(
    id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
    user_agent_hash,ip_prefix_hash,assurance_level,mfa_verified_at,
    auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,
    idle_timeout_minutes,idle_expires_at,last_user_agent_hash,last_ip_prefix_hash,
    enrollment_source,invitation_id
  ) VALUES (
    p_session_id,p_session_token_hash,p_csrf_hash,invitation_record.identity_id,
    invitation_record.tenant_id,issued_expires_at,p_user_agent_hash,p_ip_prefix_hash,
    'enrollment_only',NULL,'bootstrap',1,false,NULL,false,10,issued_expires_at,
    p_user_agent_hash,p_ip_prefix_hash,'invitation',p_invitation_id
  );
  RETURN QUERY SELECT true,invitation_record.identity_id,invitation_record.tenant_id,issued_expires_at;
END
$$;

CREATE FUNCTION mark_tenant_invitation_authority_finalized(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_identity_id uuid,
  p_acceptance_attempt integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  finalized_at timestamptz;
BEGIN
  SELECT invitation.authority_finalized_at
    INTO finalized_at
    FROM public.tenant_invitations invitation
   WHERE invitation.id = p_invitation_id
     AND invitation.acceptance_id = p_acceptance_id
     AND invitation.acceptance_identity_id = p_identity_id
     AND invitation.acceptance_attempt = p_acceptance_attempt
     AND invitation.authority_kind = 'initial_admin'
     AND invitation.status = 'accepted'
   FOR UPDATE OF invitation;
  IF NOT FOUND THEN RETURN false; END IF;
  IF finalized_at IS NOT NULL THEN RETURN true; END IF;
  UPDATE public.tenant_invitations invitation
     SET authority_finalized_at = clock_timestamp(),
         updated_at = clock_timestamp(),
         version = invitation.version + 1
   WHERE invitation.id = p_invitation_id;
  RETURN true;
END
$$;

CREATE FUNCTION mark_tenant_invitation_cleanup_completed(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_identity_id uuid,
  p_acceptance_attempt integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  cleanup_completed_at timestamptz;
BEGIN
  SELECT invitation.tenant_cleanup_completed_at
    INTO cleanup_completed_at
    FROM public.tenant_invitations invitation
   WHERE invitation.id = p_invitation_id
     AND invitation.acceptance_id = p_acceptance_id
     AND invitation.acceptance_identity_id = p_identity_id
     AND invitation.acceptance_attempt = p_acceptance_attempt
     AND invitation.status IN ('revoked','expired','failed')
   FOR UPDATE OF invitation;
  IF NOT FOUND THEN RETURN false; END IF;
  IF cleanup_completed_at IS NOT NULL THEN RETURN true; END IF;
  UPDATE public.tenant_invitations invitation
     SET tenant_cleanup_completed_at = clock_timestamp(),
         updated_at = clock_timestamp(),
         version = invitation.version + 1
   WHERE invitation.id = p_invitation_id;
  RETURN true;
END
$$;

-- Background saga repair is claimed per invitation.  The durable lease is
-- deliberately stored on the row, not in worker memory: SKIP LOCKED permits
-- independent candidates to progress, a poison row backs off by itself, and
-- a crashed worker can be reclaimed after the bounded lease expires.
CREATE FUNCTION claim_tenant_invitation_reconciliation(p_lease_token uuid)
RETURNS TABLE(
  id uuid,
  tenant_id uuid,
  email text,
  normalized_email text,
  role_codes text[],
  status text,
  created_by_identity_id uuid,
  created_at timestamptz,
  expires_at timestamptz,
  acceptance_started_at timestamptz,
  acceptance_id uuid,
  acceptance_identity_id uuid,
  accepted_at timestamptz,
  revoked_at timestamptz,
  version integer,
  authority_kind text,
  authority_epoch bigint,
  acceptance_attempt integer,
  reconciliation_attempt_count integer,
  reconciliation_lease_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_lease_token IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY
  WITH candidate AS (
    SELECT invitation.id
      FROM public.tenant_invitations invitation
     WHERE invitation.acceptance_id IS NOT NULL
       AND invitation.acceptance_identity_id IS NOT NULL
       AND invitation.acceptance_attempt > 0
       AND (
         invitation.reconciliation_next_attempt_at IS NULL
         OR invitation.reconciliation_next_attempt_at <= clock_timestamp()
       )
       AND (
         invitation.reconciliation_lease_token IS NULL
         OR invitation.reconciliation_lease_expires_at <= clock_timestamp()
       )
       AND (
         (
           invitation.status = 'accepted'
           AND invitation.authority_kind = 'initial_admin'
           AND invitation.authority_finalized_at IS NULL
         )
         OR (
           invitation.status = 'accepting'
           AND invitation.acceptance_started_at <= clock_timestamp() - interval '10 minutes'
         )
         OR invitation.status = 'compensating'
         OR (
           invitation.status IN ('revoked','expired','failed')
           AND invitation.tenant_cleanup_completed_at IS NULL
         )
       )
     ORDER BY
       CASE
         WHEN invitation.status = 'accepted' THEN 0
         WHEN invitation.status = 'compensating' THEN 1
         WHEN invitation.status IN ('revoked','expired','failed') THEN 2
         ELSE 3
       END,
       invitation.reconciliation_next_attempt_at NULLS FIRST,
       invitation.acceptance_started_at,
       invitation.id
     FOR UPDATE OF invitation SKIP LOCKED
     LIMIT 1
  ), leased AS (
    UPDATE public.tenant_invitations invitation
       SET reconciliation_attempt_count = invitation.reconciliation_attempt_count + 1,
           reconciliation_next_attempt_at = NULL,
           reconciliation_claimed_at = clock_timestamp(),
           reconciliation_lease_expires_at = clock_timestamp() + interval '5 minutes',
           reconciliation_lease_token = p_lease_token,
           updated_at = clock_timestamp(),
           version = invitation.version + 1
      FROM candidate
     WHERE invitation.id = candidate.id
     RETURNING invitation.*
  )
  SELECT invitation.id,
         invitation.tenant_id,
         invitation.email,
         invitation.normalized_email,
         invitation.role_codes,
         invitation.status,
         invitation.created_by_identity_id,
         invitation.created_at,
         invitation.expires_at,
         invitation.acceptance_started_at,
         invitation.acceptance_id,
         invitation.acceptance_identity_id,
         invitation.accepted_at,
         invitation.revoked_at,
         invitation.version,
         invitation.authority_kind,
         invitation.authority_epoch,
         invitation.acceptance_attempt,
         invitation.reconciliation_attempt_count,
         invitation.reconciliation_lease_expires_at
    FROM leased invitation;
END
$$;

CREATE FUNCTION finish_tenant_invitation_reconciliation(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_identity_id uuid,
  p_acceptance_attempt integer,
  p_lease_token uuid,
  p_succeeded boolean,
  p_error_code text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_invitation_id IS NULL OR p_acceptance_id IS NULL OR p_identity_id IS NULL
     OR p_acceptance_attempt <= 0 OR p_lease_token IS NULL OR p_succeeded IS NULL
     OR (p_succeeded AND p_error_code IS NOT NULL)
     OR (
       NOT p_succeeded
       AND (p_error_code IS NULL OR p_error_code !~ '^[A-Z][A-Z0-9_]{0,95}$')
     ) THEN
    RETURN false;
  END IF;
  UPDATE public.tenant_invitations invitation
     SET reconciliation_next_attempt_at = CASE
           WHEN p_succeeded THEN NULL
           ELSE clock_timestamp() + pg_catalog.make_interval(
             secs => LEAST(
               300,
               pg_catalog.power(2,LEAST(invitation.reconciliation_attempt_count,8))::integer
             )
           )
         END,
         reconciliation_claimed_at = NULL,
         reconciliation_lease_expires_at = NULL,
         reconciliation_lease_token = NULL,
         reconciliation_last_error_code = CASE WHEN p_succeeded THEN NULL ELSE p_error_code END,
         updated_at = clock_timestamp(),
         version = invitation.version + 1
   WHERE invitation.id = p_invitation_id
     AND invitation.acceptance_id = p_acceptance_id
     AND invitation.acceptance_identity_id = p_identity_id
     AND invitation.acceptance_attempt = p_acceptance_attempt
     AND invitation.reconciliation_lease_token = p_lease_token
     AND invitation.reconciliation_lease_expires_at > clock_timestamp();
  RETURN FOUND;
END
$$;

-- Keep the original platform operation signature, but make every future
-- initial-administrator row explicit and lock the active platform authority.
CREATE OR REPLACE FUNCTION activate_platform_tenant_initial_admin(
  p_tenant_id uuid,
  p_expected_version integer,
  p_email text,
  p_normalized_email text,
  p_token_hash text,
  p_expires_at timestamptz,
  p_idempotency_key uuid,
  p_request_hash text,
  p_actor_identity_id uuid
)
RETURNS TABLE(invitation_id uuid, tenant_version integer, reused boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  existing_invitation record;
  created_invitation_id uuid;
  changed_version integer;
  next_authority_epoch bigint;
BEGIN
  PERFORM 1
    FROM public.platform_identities identity
    JOIN public.platform_role_bindings binding
      ON binding.identity_id = identity.id
     AND binding.role_code = 'platform_admin'
   WHERE identity.id = p_actor_identity_id
     AND identity.status = 'active'
   FOR SHARE OF identity,binding;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Platform security administration permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_email IS NULL OR p_normalized_email IS NULL OR p_token_hash IS NULL
     OR p_expires_at IS NULL OR p_request_hash IS NULL
     OR length(p_email) NOT BETWEEN 3 AND 320
     OR p_normalized_email IS DISTINCT FROM lower(btrim(p_email))
     OR p_token_hash !~ '^[0-9a-f]{64}$'
     OR p_request_hash !~ '^[0-9a-f]{64}$'
     OR p_expires_at <= clock_timestamp() + interval '59 minutes'
     OR p_expires_at > clock_timestamp() + interval '169 hours' THEN
    RAISE EXCEPTION 'Initial administrator invitation is invalid' USING ERRCODE = '23514';
  END IF;

  SELECT invitation.id, invitation.request_hash, invitation.authority_kind,
         invitation.normalized_email, tenant.version
    INTO existing_invitation
    FROM public.tenant_invitations invitation
    JOIN public.tenants tenant ON tenant.id = invitation.tenant_id
   WHERE invitation.tenant_id = p_tenant_id
     AND invitation.created_by_identity_id = p_actor_identity_id
     AND invitation.idempotency_key = p_idempotency_key
   FOR UPDATE OF invitation,tenant;
  IF FOUND THEN
    IF existing_invitation.request_hash IS DISTINCT FROM p_request_hash
       OR existing_invitation.authority_kind IS DISTINCT FROM 'initial_admin'
       OR existing_invitation.normalized_email IS DISTINCT FROM p_normalized_email THEN
      RAISE EXCEPTION 'Initial administrator idempotency key was reused with different input'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_invitation.id, existing_invitation.version, true;
    RETURN;
  END IF;

  PERFORM 1
    FROM public.tenants tenant
    JOIN public.provisioning_jobs job ON job.tenant_id = tenant.id
   WHERE tenant.id = p_tenant_id
     AND tenant.kind = 'real'
     AND tenant.version = p_expected_version
     AND (
       (tenant.status = 'provisioning' AND job.state IN ('seeded','pending_activation'))
       OR (tenant.status = 'active' AND job.state = 'active')
     )
     AND NOT EXISTS (
       SELECT 1 FROM public.tenant_memberships membership
        WHERE membership.tenant_id = tenant.id
     )
     AND NOT EXISTS (
       SELECT 1 FROM public.tenant_invitations invitation
        WHERE invitation.tenant_id = tenant.id
          AND invitation.authority_kind = 'initial_admin'
          AND (
            invitation.status IN ('accepting','compensating','accepted')
            OR (invitation.status = 'pending' AND invitation.acceptance_id IS NOT NULL)
          )
     )
   FOR UPDATE OF tenant,job;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tenant is not awaiting an initial administrator'
      USING ERRCODE = '40001';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.platform_identities identity WHERE identity.normalized_email = p_normalized_email
    UNION ALL
    SELECT 1 FROM public.tenant_invitations invitation
     WHERE invitation.normalized_email = p_normalized_email
       AND invitation.status IN ('pending','accepting','compensating')
       AND NOT (
         invitation.tenant_id = p_tenant_id
         AND invitation.authority_kind = 'initial_admin'
         AND invitation.status = 'pending'
         AND invitation.acceptance_id IS NULL
       )
  ) THEN
    RAISE EXCEPTION 'Initial administrator recipient is unavailable' USING ERRCODE = '23505';
  END IF;

  UPDATE public.tenant_invitations invitation
     SET status = 'revoked',revoked_at = clock_timestamp(),
         revocation_reason = 'INVITATION_REPLACED',last_error_code = 'INVITATION_REPLACED',
         updated_at = clock_timestamp(),version = invitation.version + 1
   WHERE invitation.tenant_id = p_tenant_id
     AND invitation.authority_kind = 'initial_admin'
     AND invitation.status = 'pending'
     AND invitation.acceptance_id IS NULL;

  UPDATE public.tenants
     SET status = 'active',
         activated_at = COALESCE(activated_at,clock_timestamp()),
         initial_admin_authority_epoch = initial_admin_authority_epoch + 1,
         version = version + 1,
         updated_at = clock_timestamp()
   WHERE id = p_tenant_id
  RETURNING version,initial_admin_authority_epoch
       INTO changed_version,next_authority_epoch;

  INSERT INTO public.tenant_invitations(
    tenant_id,email,normalized_email,role_codes,token_hash,status,idempotency_key,
    request_hash,created_by_identity_id,expires_at,authority_kind,authority_epoch
  ) VALUES (
    p_tenant_id,btrim(p_email),p_normalized_email,ARRAY['CHURCH_ADMIN']::text[],p_token_hash,
    'pending',p_idempotency_key,p_request_hash,p_actor_identity_id,p_expires_at,
    'initial_admin',next_authority_epoch
  ) RETURNING id INTO created_invitation_id;

  UPDATE public.provisioning_jobs
     SET state='active',completed_at=clock_timestamp(),last_error_code=NULL,updated_at=clock_timestamp()
   WHERE tenant_id=p_tenant_id;

  RETURN QUERY SELECT created_invitation_id, changed_version, false;
END
$$;

-- Final database gate inside the unchanged 021 completion function. It
-- validates the authority kind associated with the exact accepting identity.
CREATE FUNCTION enforce_active_invitation_grantor()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  invitation_record record;
BEGIN
  IF NEW.status <> 'active' THEN
    RETURN NEW;
  END IF;

  SELECT invitation.id, invitation.created_by_identity_id,
         invitation.authority_kind, invitation.role_codes
    INTO invitation_record
    FROM public.tenant_invitations invitation
   WHERE invitation.tenant_id = NEW.tenant_id
     AND invitation.acceptance_identity_id = NEW.identity_id
     AND invitation.status = 'accepting'
   FOR SHARE OF invitation;
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;

  IF invitation_record.authority_kind = 'tenant_delegate' THEN
    PERFORM 1
      FROM public.platform_identities identity
      JOIN public.tenant_memberships membership
        ON membership.identity_id = identity.id
       AND membership.tenant_id = NEW.tenant_id
      JOIN public.tenants tenant ON tenant.id = membership.tenant_id
     WHERE identity.id = invitation_record.created_by_identity_id
       AND identity.status = 'active'
       AND membership.status = 'active'
       AND tenant.status = 'active'
     FOR SHARE OF identity,membership,tenant;
  ELSIF invitation_record.authority_kind = 'initial_admin'
        AND TG_OP = 'INSERT'
        AND invitation_record.role_codes = ARRAY['CHURCH_ADMIN']::text[] THEN
    PERFORM 1
      FROM public.platform_identities identity
      JOIN public.platform_role_bindings binding
        ON binding.identity_id = identity.id
       AND binding.role_code = 'platform_admin'
      JOIN public.tenants tenant ON tenant.id = NEW.tenant_id
      JOIN public.provisioning_jobs job ON job.tenant_id = tenant.id
     WHERE identity.id = invitation_record.created_by_identity_id
       AND identity.status = 'active'
       AND tenant.status = 'active'
       AND tenant.kind = 'real'
       AND job.state = 'active'
       AND NOT EXISTS (
         SELECT 1 FROM public.tenant_memberships membership
          WHERE membership.tenant_id = NEW.tenant_id
       )
     FOR SHARE OF identity,binding,tenant,job;
  ELSE
    RAISE EXCEPTION 'Invitation authority is invalid'
      USING ERRCODE = '42501', CONSTRAINT = 'tenant_invitation_grantor_inactive';
  END IF;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Invitation grantor is no longer active'
      USING ERRCODE = '42501', CONSTRAINT = 'tenant_invitation_grantor_inactive';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER tenant_membership_invitation_grantor_guard
BEFORE INSERT OR UPDATE OF status,tenant_id,identity_id ON tenant_memberships
FOR EACH ROW EXECUTE FUNCTION enforce_active_invitation_grantor();

-- Offboarding is enforced at the data boundary. Each trigger already holds
-- the authority row that changed and then locks invitations, matching the
-- authority->invitation ordering used by runtime claim/completion.
CREATE FUNCTION revoke_outstanding_invitations_on_authority_loss()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  authority_scope text := TG_ARGV[0];
  target_identity_id uuid;
  target_tenant_id uuid;
  target_authority_kind text;
  authority_was_lost boolean := false;
BEGIN
  IF authority_scope = 'identity' THEN
    authority_was_lost := TG_OP = 'DELETE' OR (OLD.status = 'active' AND NEW.status <> 'active');
    target_identity_id := OLD.id;
  ELSIF authority_scope = 'membership' THEN
    authority_was_lost := TG_OP = 'DELETE' OR (OLD.status = 'active' AND NEW.status <> 'active');
    target_identity_id := OLD.identity_id;
    target_tenant_id := OLD.tenant_id;
    target_authority_kind := 'tenant_delegate';
  ELSIF authority_scope = 'platform_role' THEN
    authority_was_lost := OLD.role_code = 'platform_admin'
      AND (TG_OP = 'DELETE' OR NEW.role_code IS DISTINCT FROM OLD.role_code
           OR NEW.identity_id IS DISTINCT FROM OLD.identity_id);
    target_identity_id := OLD.identity_id;
    target_authority_kind := 'initial_admin';
  ELSIF authority_scope = 'tenant' THEN
    authority_was_lost := TG_OP = 'DELETE' OR (OLD.status = 'active' AND NEW.status <> 'active');
    target_tenant_id := OLD.id;
  ELSE
    RAISE EXCEPTION 'Invitation authority-loss trigger scope is invalid' USING ERRCODE = '23514';
  END IF;

  IF authority_was_lost THEN
    UPDATE public.tenant_invitations invitation
       SET status = 'revoked',
           revoked_at = COALESCE(invitation.revoked_at,clock_timestamp()),
           revoked_by_identity_id = NULL,
           revocation_reason = 'ADMIN_ACCESS_REVOCATION',
           last_error_code = 'GRANTOR_ACCESS_REVOKED',
           updated_at = clock_timestamp(),
           version = invitation.version + 1
     WHERE invitation.status IN ('pending','accepting','compensating')
       AND (target_identity_id IS NULL OR invitation.created_by_identity_id = target_identity_id)
       AND (target_tenant_id IS NULL OR invitation.tenant_id = target_tenant_id)
       AND (target_authority_kind IS NULL OR invitation.authority_kind = target_authority_kind);
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END
$$;

CREATE TRIGGER platform_identity_invitation_authority_loss
AFTER UPDATE OF status OR DELETE ON platform_identities
FOR EACH ROW EXECUTE FUNCTION revoke_outstanding_invitations_on_authority_loss('identity');

CREATE TRIGGER tenant_membership_invitation_authority_loss
AFTER UPDATE OF status OR DELETE ON tenant_memberships
FOR EACH ROW EXECUTE FUNCTION revoke_outstanding_invitations_on_authority_loss('membership');

CREATE TRIGGER platform_role_invitation_authority_loss
AFTER UPDATE OF identity_id,role_code OR DELETE ON platform_role_bindings
FOR EACH ROW EXECUTE FUNCTION revoke_outstanding_invitations_on_authority_loss('platform_role');

CREATE TRIGGER tenant_invitation_authority_loss
AFTER UPDATE OF status OR DELETE ON tenants
FOR EACH ROW EXECUTE FUNCTION revoke_outstanding_invitations_on_authority_loss('tenant');

-- Repair only rows whose explicit authority is already unavailable. Initial
-- administrators deliberately have no tenant membership at this stage.
UPDATE tenant_invitations invitation
   SET status = 'revoked',
       revoked_at = COALESCE(invitation.revoked_at,clock_timestamp()),
       revoked_by_identity_id = NULL,
       revocation_reason = 'ADMIN_ACCESS_REVOCATION',
       last_error_code = 'GRANTOR_ACCESS_REVOKED',
       updated_at = clock_timestamp(),
       version = invitation.version + 1
 WHERE invitation.status IN ('pending','accepting','compensating')
   AND (
     (invitation.authority_kind = 'tenant_delegate' AND NOT EXISTS (
       SELECT 1
         FROM platform_identities identity
         JOIN tenant_memberships membership
           ON membership.identity_id = identity.id
          AND membership.tenant_id = invitation.tenant_id
         JOIN tenants tenant ON tenant.id = membership.tenant_id
        WHERE identity.id = invitation.created_by_identity_id
          AND identity.status = 'active'
          AND membership.status = 'active'
          AND tenant.status = 'active'
     ))
     OR (invitation.authority_kind = 'initial_admin' AND (
       invitation.role_codes IS DISTINCT FROM ARRAY['CHURCH_ADMIN']::text[]
       OR EXISTS (SELECT 1 FROM tenant_memberships membership WHERE membership.tenant_id = invitation.tenant_id)
       OR NOT EXISTS (
         SELECT 1
           FROM platform_identities identity
           JOIN platform_role_bindings binding
             ON binding.identity_id = identity.id AND binding.role_code = 'platform_admin'
           JOIN tenants tenant ON tenant.id = invitation.tenant_id
           JOIN provisioning_jobs job ON job.tenant_id = tenant.id
          WHERE identity.id = invitation.created_by_identity_id
            AND identity.status = 'active'
            AND tenant.status = 'active'
            AND tenant.kind = 'real'
            AND job.state = 'active'
       )
     ))
   );

-- A compromised runtime credential must not be able to fabricate an
-- accepting/accepted tuple with an old attempt. This trigger is deliberately
-- role-independent: SECURITY DEFINER functions must obey the same monotonic
-- state machine as direct callers.
CREATE FUNCTION enforce_tenant_invitation_state_machine()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  transition_allowed boolean := false;
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.email IS DISTINCT FROM OLD.email
     OR NEW.normalized_email IS DISTINCT FROM OLD.normalized_email
     OR NEW.role_codes IS DISTINCT FROM OLD.role_codes
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
     OR NEW.created_by_identity_id IS DISTINCT FROM OLD.created_by_identity_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.authority_kind IS DISTINCT FROM OLD.authority_kind
     OR NEW.authority_epoch IS DISTINCT FROM OLD.authority_epoch THEN
    RAISE EXCEPTION 'Invitation immutable authority fields cannot change'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_authority_immutable';
  END IF;

  transition_allowed := CASE OLD.status
    WHEN 'pending' THEN NEW.status IN ('pending','accepting','revoked','expired')
    WHEN 'accepting' THEN NEW.status IN ('accepting','compensating','accepted','revoked','expired','failed')
    WHEN 'compensating' THEN NEW.status IN ('compensating','pending','revoked','expired','failed')
    WHEN 'failed' THEN NEW.status IN ('failed','revoked')
    WHEN 'expired' THEN NEW.status IN ('expired','revoked')
    WHEN 'revoked' THEN NEW.status = 'revoked'
    WHEN 'accepted' THEN NEW.status = 'accepted'
    ELSE false
  END;
  IF NOT transition_allowed THEN
    RAISE EXCEPTION 'Invitation state transition is invalid'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_state_transition';
  END IF;

  IF OLD.status = 'pending' AND NEW.status = 'accepting' THEN
    IF NEW.acceptance_attempt <> OLD.acceptance_attempt + 1
       OR NEW.acceptance_id IS NULL OR NEW.acceptance_identity_id IS NULL
       OR NEW.acceptance_started_at IS NULL
       OR NEW.acceptance_recovery_hash !~ '^[0-9a-f]{64}$' THEN
      RAISE EXCEPTION 'Invitation acceptance attempt is not monotonic'
        USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_acceptance_attempt';
    END IF;
  ELSIF OLD.status = 'compensating' AND NEW.status IN ('pending','expired') THEN
    IF NEW.acceptance_attempt <> OLD.acceptance_attempt
     OR NEW.acceptance_id IS NOT NULL OR NEW.acceptance_identity_id IS NOT NULL
       OR NEW.acceptance_started_at IS NOT NULL
       OR NEW.acceptance_recovery_hash IS NOT NULL THEN
      RAISE EXCEPTION 'Invitation compensation reset is invalid'
        USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_compensation_reset';
    END IF;
  ELSIF NEW.acceptance_attempt IS DISTINCT FROM OLD.acceptance_attempt
        OR NEW.acceptance_id IS DISTINCT FROM OLD.acceptance_id
        OR NEW.acceptance_identity_id IS DISTINCT FROM OLD.acceptance_identity_id
        OR NEW.acceptance_started_at IS DISTINCT FROM OLD.acceptance_started_at
        OR NEW.acceptance_recovery_hash IS DISTINCT FROM OLD.acceptance_recovery_hash THEN
    RAISE EXCEPTION 'Invitation acceptance tuple is immutable in this state'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_acceptance_tuple';
  END IF;

  IF NEW.reconciliation_attempt_count = OLD.reconciliation_attempt_count + 1 THEN
    IF NOT (
      (OLD.reconciliation_lease_token IS NULL
       OR OLD.reconciliation_lease_expires_at <= clock_timestamp())
      AND NEW.reconciliation_next_attempt_at IS NULL
      AND NEW.reconciliation_claimed_at IS NOT NULL
      AND NEW.reconciliation_lease_expires_at > NEW.reconciliation_claimed_at
      AND NEW.reconciliation_lease_token IS NOT NULL
      AND NEW.reconciliation_last_error_code IS NOT DISTINCT FROM OLD.reconciliation_last_error_code
    ) THEN
      RAISE EXCEPTION 'Invitation reconciliation lease claim is invalid'
        USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_reconciliation_claim';
    END IF;
  ELSIF NEW.reconciliation_attempt_count = OLD.reconciliation_attempt_count THEN
    IF (
      NEW.reconciliation_claimed_at IS DISTINCT FROM OLD.reconciliation_claimed_at
      OR NEW.reconciliation_lease_expires_at IS DISTINCT FROM OLD.reconciliation_lease_expires_at
      OR NEW.reconciliation_lease_token IS DISTINCT FROM OLD.reconciliation_lease_token
      OR NEW.reconciliation_next_attempt_at IS DISTINCT FROM OLD.reconciliation_next_attempt_at
      OR NEW.reconciliation_last_error_code IS DISTINCT FROM OLD.reconciliation_last_error_code
    ) AND NOT (
      OLD.reconciliation_lease_token IS NOT NULL
      AND NEW.reconciliation_claimed_at IS NULL
      AND NEW.reconciliation_lease_expires_at IS NULL
      AND NEW.reconciliation_lease_token IS NULL
      AND (
        (NEW.reconciliation_next_attempt_at IS NULL AND NEW.reconciliation_last_error_code IS NULL)
        OR (
          NEW.reconciliation_next_attempt_at > clock_timestamp()
          AND NEW.reconciliation_last_error_code ~ '^[A-Z][A-Z0-9_]{0,95}$'
        )
      )
    ) THEN
      RAISE EXCEPTION 'Invitation reconciliation lease completion is invalid'
        USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_reconciliation_finish';
    END IF;
  ELSE
    RAISE EXCEPTION 'Invitation reconciliation attempt must be monotonic'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_reconciliation_attempt';
  END IF;

  IF NEW.status = 'accepted'
     AND (OLD.status <> 'accepted')
     AND (NEW.accepted_at IS NULL OR NEW.consumed_at IS NULL) THEN
    RAISE EXCEPTION 'Accepted invitation must be durably consumed'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_accepted_state';
  END IF;
  IF NEW.authority_finalized_at IS DISTINCT FROM OLD.authority_finalized_at
     AND NOT (
       OLD.status = 'accepted' AND NEW.status = 'accepted'
       AND OLD.authority_kind = 'initial_admin'
       AND OLD.authority_finalized_at IS NULL
       AND NEW.authority_finalized_at IS NOT NULL
     ) THEN
    RAISE EXCEPTION 'Invitation authority finalization marker is invalid'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_authority_finalization';
  END IF;
  IF NEW.tenant_cleanup_completed_at IS DISTINCT FROM OLD.tenant_cleanup_completed_at
     AND NOT (
       OLD.status IN ('revoked','expired','failed')
       AND NEW.status = OLD.status
       AND OLD.tenant_cleanup_completed_at IS NULL
       AND NEW.tenant_cleanup_completed_at IS NOT NULL
     ) THEN
    RAISE EXCEPTION 'Invitation cleanup completion marker is invalid'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_cleanup_completion';
  END IF;
  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'Invitation version must advance exactly once'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_version_advance';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER tenant_invitation_state_machine_guard
BEFORE UPDATE ON tenant_invitations
FOR EACH ROW EXECUTE FUNCTION enforce_tenant_invitation_state_machine();

REVOKE ALL ON FUNCTION lock_active_invitation_grantor(uuid,uuid,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION find_tenant_invitation_idempotency(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION inspect_tenant_invitation_bearer(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION begin_tenant_invitation_acceptance(uuid,text,text,text,uuid,uuid,text,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION begin_tenant_invitation_compensation(uuid,uuid,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION recover_tenant_invitation_enrollment_session(uuid,text,text,text,uuid,text,text,timestamptz,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_tenant_invitation_authority_finalized(uuid,uuid,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_tenant_invitation_cleanup_completed(uuid,uuid,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION claim_tenant_invitation_reconciliation(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION finish_tenant_invitation_reconciliation(uuid,uuid,uuid,integer,uuid,boolean,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION complete_tenant_invitation_acceptance(
  uuid,uuid,uuid,integer,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_active_invitation_grantor() FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_outstanding_invitations_on_authority_loss() FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_tenant_invitation_state_machine() FROM PUBLIC;
REVOKE ALL ON FUNCTION activate_platform_tenant_initial_admin(uuid,integer,text,text,text,timestamptz,uuid,text,uuid) FROM PUBLIC;
