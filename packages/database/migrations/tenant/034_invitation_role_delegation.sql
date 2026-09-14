-- Invitation role grants are delegated authority, not merely invitation
-- management.  Keep this check in the tenant database so callers cannot
-- bypass the API's permission middleware.
CREATE OR REPLACE FUNCTION assert_tenant_invitation_role_delegation_allowed(
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
    RAISE EXCEPTION 'Invitation role delegation parameters are required'
      USING ERRCODE = '23502';
  END IF;
  SELECT tenant_id INTO configured_tenant_id
    FROM public.tenant_settings
   WHERE singleton = true;
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
    contextual_actor := current_setting('app.identity_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Tenant invitation delegation context is missing'
      USING ERRCODE = '42501';
  END;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id THEN
    RAISE EXCEPTION 'Tenant invitation delegation context does not match this database'
      USING ERRCODE = '42501';
  END IF;
  IF contextual_actor IS DISTINCT FROM p_actor_identity_id THEN
    RAISE EXCEPTION 'Invitation grantor does not match the bound session'
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
  IF NOT EXISTS (
    SELECT 1
      FROM public.role_bindings binding
      JOIN public.role_permissions role_permission ON role_permission.role_id = binding.role_id
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.revoked_at IS NULL
       AND role_permission.permission_code = 'role.manage'
  ) THEN
    RAISE EXCEPTION 'Tenant role management permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF (SELECT count(*) FROM public.roles
       WHERE system_role = true AND code = ANY(p_requested_role_codes)) <> cardinality(p_requested_role_codes) THEN
    RAISE EXCEPTION 'Invitation references an unavailable tenant role'
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT role_permission.permission_code
      FROM public.roles role
      JOIN public.role_permissions role_permission ON role_permission.role_id = role.id
     WHERE role.system_role = true
       AND role.code = ANY(p_requested_role_codes)
    EXCEPT
    SELECT DISTINCT role_permission.permission_code
      FROM public.role_bindings binding
      JOIN public.role_permissions role_permission ON role_permission.role_id = binding.role_id
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.revoked_at IS NULL
       AND role_permission.delegable
  ) THEN
    RAISE EXCEPTION 'Actor cannot delegate one or more invitation role permissions'
      USING ERRCODE = '42501';
  END IF;
END
$$;

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
  inserted_count integer;
  active_count integer;
BEGIN
  IF p_invitation_id IS NULL OR p_invited_identity_id IS NULL OR p_granted_by_identity_id IS NULL THEN
    RAISE EXCEPTION 'Invitation role parameters are required'
      USING ERRCODE = '23502';
  END IF;
  PERFORM public.assert_tenant_invitation_role_delegation_allowed(
    p_granted_by_identity_id, p_requested_role_codes
  );
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

REVOKE ALL ON FUNCTION public.assert_tenant_invitation_role_delegation_allowed(uuid,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.apply_tenant_invitation_roles(uuid,uuid,text[],uuid) FROM PUBLIC;
