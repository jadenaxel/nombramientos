-- Harden privileged tenant entrypoints against SQL callers that bypass the
-- application validators. Future functions created by the tenant owner are
-- private by default and must be granted deliberately.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE OR REPLACE FUNCTION apply_tenant_invitation_roles(
  p_invitation_id uuid,
  p_invited_identity_id uuid,
  p_requested_role_codes text[],
  p_granted_by_identity_id uuid
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  configured_tenant_id uuid;
  bound_tenant_id uuid;
  inserted_count integer;
  active_count integer;
BEGIN
  IF p_invitation_id IS NULL
     OR p_invited_identity_id IS NULL
     OR p_requested_role_codes IS NULL
     OR p_granted_by_identity_id IS NULL THEN
    RAISE EXCEPTION 'Invitation role parameters are required'
      USING ERRCODE = '23502';
  END IF;
  SELECT tenant_id INTO configured_tenant_id
    FROM public.tenant_settings
   WHERE singleton = true;
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Tenant invitation context is missing'
      USING ERRCODE = '42501';
  END;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id THEN
    RAISE EXCEPTION 'Tenant invitation context does not match this database'
      USING ERRCODE = '42501';
  END IF;
  IF cardinality(p_requested_role_codes) NOT BETWEEN 1 AND 3
     OR cardinality(p_requested_role_codes) <> (
       SELECT count(DISTINCT role_code)::integer FROM unnest(p_requested_role_codes) AS requested(role_code)
     )
     OR EXISTS (
       SELECT 1 FROM unnest(p_requested_role_codes) AS requested(role_code)
        WHERE requested.role_code NOT IN (
          'CHURCH_ADMIN', 'COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY',
          'COMMITTEE_MEMBER', 'TALLY_CUSTODIAN', 'AUDITOR'
        )
     ) THEN
    RAISE EXCEPTION 'Invitation roles are not an exact supported set'
      USING ERRCODE = '23514';
  END IF;
  IF (SELECT count(*) FROM public.roles
       WHERE system_role = true AND code = ANY(p_requested_role_codes)) <> cardinality(p_requested_role_codes) THEN
    RAISE EXCEPTION 'Invitation references an unavailable tenant role'
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM public.role_bindings binding
     WHERE binding.identity_id = p_invited_identity_id
       AND binding.revoked_at IS NULL
       AND binding.source_invitation_id IS DISTINCT FROM p_invitation_id
  ) THEN
    RAISE EXCEPTION 'Invitation identity already has unrelated active role bindings'
      USING ERRCODE = '23505';
  END IF;

  DELETE FROM public.role_bindings
   WHERE source_invitation_id = p_invitation_id;

  INSERT INTO public.role_bindings(
    identity_id, role_id, granted_by_identity_id, source_invitation_id
  )
  SELECT p_invited_identity_id, role.id, p_granted_by_identity_id, p_invitation_id
    FROM public.roles role
   WHERE role.system_role = true
     AND role.code = ANY(p_requested_role_codes)
   ORDER BY role.code;
  GET DIAGNOSTICS inserted_count = ROW_COUNT;
  SELECT count(*)::integer INTO active_count
    FROM public.role_bindings
   WHERE identity_id = p_invited_identity_id
     AND revoked_at IS NULL;
  IF inserted_count <> cardinality(p_requested_role_codes)
     OR active_count <> cardinality(p_requested_role_codes) THEN
    RAISE EXCEPTION 'Invitation roles were not bound exactly'
      USING ERRCODE = '23514';
  END IF;
  RETURN inserted_count;
END
$$;

CREATE OR REPLACE FUNCTION cleanup_tenant_invitation_roles(p_invitation_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  configured_tenant_id uuid;
  bound_tenant_id uuid;
  removed_count integer;
BEGIN
  IF p_invitation_id IS NULL THEN
    RAISE EXCEPTION 'Invitation identifier is required' USING ERRCODE = '23502';
  END IF;
  SELECT tenant_id INTO configured_tenant_id
    FROM public.tenant_settings
   WHERE singleton = true;
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Tenant invitation cleanup context is missing'
      USING ERRCODE = '42501';
  END;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id THEN
    RAISE EXCEPTION 'Tenant invitation cleanup context does not match this database'
      USING ERRCODE = '42501';
  END IF;
  DELETE FROM public.role_bindings
   WHERE source_invitation_id = p_invitation_id;
  GET DIAGNOSTICS removed_count = ROW_COUNT;
  RETURN removed_count;
END
$$;

CREATE OR REPLACE FUNCTION assert_local_role_definition_allowed(
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
    RAISE EXCEPTION 'Tenant access-control actor does not match the bound session'
      USING ERRCODE = '42501';
  END IF;
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
  IF cardinality(p_permission_codes) NOT BETWEEN 1 AND 40
     OR cardinality(p_permission_codes) <> (
       SELECT count(DISTINCT permission_code)::integer
         FROM unnest(p_permission_codes) requested(permission_code)
     )
     OR EXISTS (SELECT 1 FROM unnest(p_permission_codes) requested(permission_code) WHERE permission_code IS NULL)
     OR cardinality(p_delegable_permission_codes) <> (
       SELECT count(DISTINCT permission_code)::integer
         FROM unnest(p_delegable_permission_codes) requested(permission_code)
     )
     OR EXISTS (SELECT 1 FROM unnest(p_delegable_permission_codes) requested(permission_code) WHERE permission_code IS NULL)
     OR EXISTS (
       SELECT 1 FROM unnest(p_delegable_permission_codes) delegated(permission_code)
        WHERE NOT delegated.permission_code = ANY(p_permission_codes)
     ) THEN
    RAISE EXCEPTION 'Local role permission set is invalid' USING ERRCODE = '23514';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(p_permission_codes) requested(permission_code) WHERE permission_code LIKE 'platform.%')
     OR (SELECT count(*) FROM public.permissions WHERE code = ANY(p_permission_codes)) <> cardinality(p_permission_codes) THEN
    RAISE EXCEPTION 'Local roles cannot contain unknown or platform permissions' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (
    SELECT requested.permission_code
      FROM unnest(p_permission_codes) requested(permission_code)
    EXCEPT
    SELECT DISTINCT role_permission.permission_code
      FROM public.role_bindings binding
      JOIN public.role_permissions role_permission ON role_permission.role_id = binding.role_id
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.revoked_at IS NULL
       AND role_permission.delegable
  ) THEN
    RAISE EXCEPTION 'Actor cannot delegate one or more requested permissions' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (
    SELECT requested.permission_code
      FROM unnest(p_delegable_permission_codes) requested(permission_code)
    EXCEPT
    SELECT DISTINCT role_permission.permission_code
      FROM public.role_bindings binding
      JOIN public.role_permissions role_permission ON role_permission.role_id = binding.role_id
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.revoked_at IS NULL
       AND role_permission.delegable
  ) THEN
    RAISE EXCEPTION 'Actor cannot pass delegation authority it does not possess' USING ERRCODE = '42501';
  END IF;
END
$$;

REVOKE ALL ON FUNCTION public.apply_tenant_invitation_roles(uuid,uuid,text[],uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.cleanup_tenant_invitation_roles(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assert_local_role_definition_allowed(uuid,text[],text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.create_local_role(uuid,uuid,text,jsonb,text[],text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.update_local_role(uuid,uuid,integer,jsonb,text[],text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assert_role_binding_allowed(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.grant_tenant_role_binding(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.revoke_tenant_role_binding(uuid,uuid,uuid,integer) FROM PUBLIC;
