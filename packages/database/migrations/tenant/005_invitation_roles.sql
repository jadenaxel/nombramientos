ALTER TABLE role_bindings
ADD COLUMN source_invitation_id uuid;

CREATE UNIQUE INDEX role_bindings_source_invitation_role
ON role_bindings(source_invitation_id, role_id)
WHERE source_invitation_id IS NOT NULL;

CREATE FUNCTION apply_tenant_invitation_roles(
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
BEGIN
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
      JOIN public.roles role ON role.id = binding.role_id
     WHERE binding.identity_id = p_invited_identity_id
       AND binding.revoked_at IS NULL
       AND role.code = ANY(p_requested_role_codes)
       AND binding.source_invitation_id IS DISTINCT FROM p_invitation_id
  ) THEN
    RAISE EXCEPTION 'Invitation identity already has an unrelated active role binding'
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
  IF inserted_count <> cardinality(p_requested_role_codes) THEN
    RAISE EXCEPTION 'Invitation roles were not bound exactly'
      USING ERRCODE = '23514';
  END IF;
  RETURN inserted_count;
END
$$;

CREATE FUNCTION cleanup_tenant_invitation_roles(p_invitation_id uuid)
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

REVOKE ALL ON FUNCTION apply_tenant_invitation_roles(uuid, uuid, text[], uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION cleanup_tenant_invitation_roles(uuid) FROM PUBLIC;
