CREATE OR REPLACE FUNCTION sync_gestionchurch_federated_roles(
  p_identity_id uuid,
  p_role_codes text[]
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  contextual_identity uuid;
  contextual_tenant uuid;
  configured_tenant uuid;
  inserted_count integer;
BEGIN
  BEGIN
    contextual_identity := current_setting('app.identity_id',true)::uuid;
    contextual_tenant := current_setting('app.tenant_id',true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'GestionChurch federation context is missing' USING ERRCODE = '42501';
  END;
  SELECT tenant_id INTO configured_tenant FROM public.tenant_settings WHERE singleton=true;
  IF p_identity_id IS NULL OR contextual_identity IS DISTINCT FROM p_identity_id
     OR contextual_tenant IS DISTINCT FROM configured_tenant THEN
    RAISE EXCEPTION 'GestionChurch federation context does not match this tenant'
      USING ERRCODE = '42501';
  END IF;
  IF cardinality(p_role_codes) NOT BETWEEN 1 AND 3
     OR cardinality(p_role_codes) <> (
       SELECT count(DISTINCT role_code)::integer FROM unnest(p_role_codes) requested(role_code)
     )
     OR EXISTS (
       SELECT 1 FROM unnest(p_role_codes) requested(role_code)
        WHERE role_code NOT IN ('CHURCH_ADMIN','COMMITTEE_SECRETARY','COMMITTEE_MEMBER','AUDITOR')
     )
     OR (SELECT count(*) FROM public.roles WHERE system_role=true AND code=ANY(p_role_codes)) <> cardinality(p_role_codes) THEN
    RAISE EXCEPTION 'GestionChurch federation roles are invalid' USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.role_bindings
     WHERE identity_id=p_identity_id AND source_invitation_id IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Federated identities cannot reuse invitation-bound roles' USING ERRCODE = '23505';
  END IF;

  DELETE FROM public.role_bindings WHERE identity_id=p_identity_id;
  INSERT INTO public.role_bindings(identity_id,role_id,granted_by_identity_id)
  SELECT p_identity_id,role.id,p_identity_id
    FROM public.roles role
   WHERE role.system_role=true AND role.code=ANY(p_role_codes)
   ORDER BY role.code;
  GET DIAGNOSTICS inserted_count = ROW_COUNT;
  IF inserted_count <> cardinality(p_role_codes) THEN
    RAISE EXCEPTION 'GestionChurch roles were not bound exactly' USING ERRCODE = '23514';
  END IF;
  RETURN inserted_count;
END
$$;

REVOKE ALL ON FUNCTION sync_gestionchurch_federated_roles(uuid,text[]) FROM PUBLIC;

