-- Assigning a built-in role is a governance capability distinct from the
-- operational permissions carried by that role. Keep the allowlist relational
-- and migration-owned so it can be reviewed without granting those permissions
-- (notably proposal.submit or ballot.submit) to the assigning administrator.
CREATE TABLE system_role_assignment_matrix (
  grantor_role_code text NOT NULL
    REFERENCES public.roles(code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  assignable_role_code text NOT NULL
    REFERENCES public.roles(code) ON UPDATE RESTRICT ON DELETE RESTRICT,
  PRIMARY KEY (grantor_role_code, assignable_role_code),
  CHECK (grantor_role_code IN (
    'CHURCH_ADMIN', 'COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY',
    'COMMITTEE_MEMBER', 'TALLY_CUSTODIAN', 'AUDITOR'
  )),
  CHECK (assignable_role_code IN (
    'CHURCH_ADMIN', 'COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY',
    'COMMITTEE_MEMBER', 'TALLY_CUSTODIAN', 'AUDITOR'
  ))
);

INSERT INTO public.system_role_assignment_matrix(
  grantor_role_code, assignable_role_code
) VALUES
  ('CHURCH_ADMIN', 'AUDITOR'),
  ('CHURCH_ADMIN', 'CHURCH_ADMIN'),
  ('CHURCH_ADMIN', 'COMMITTEE_CHAIR'),
  ('CHURCH_ADMIN', 'COMMITTEE_MEMBER'),
  ('CHURCH_ADMIN', 'COMMITTEE_SECRETARY'),
  ('CHURCH_ADMIN', 'TALLY_CUSTODIAN');

REVOKE ALL ON TABLE public.system_role_assignment_matrix FROM PUBLIC;

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
    RAISE EXCEPTION 'Invitation role assignment parameters are required'
      USING ERRCODE = '23502';
  END IF;
  SELECT tenant_id INTO configured_tenant_id
    FROM public.tenant_settings
   WHERE singleton = true;
  BEGIN
    bound_tenant_id := current_setting('app.tenant_id', true)::uuid;
    contextual_actor := current_setting('app.identity_id', true)::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Tenant invitation role-assignment context is missing'
      USING ERRCODE = '42501';
  END;
  IF configured_tenant_id IS NULL OR bound_tenant_id IS DISTINCT FROM configured_tenant_id THEN
    RAISE EXCEPTION 'Tenant invitation role-assignment context does not match this database'
      USING ERRCODE = '42501';
  END IF;
  IF contextual_actor IS DISTINCT FROM p_actor_identity_id THEN
    RAISE EXCEPTION 'Invitation grantor does not match the bound session'
      USING ERRCODE = '42501';
  END IF;
  IF cardinality(p_requested_role_codes) NOT BETWEEN 1 AND 3
     OR cardinality(p_requested_role_codes) <> (
       SELECT count(DISTINCT role_code)::integer
         FROM unnest(p_requested_role_codes) AS requested(role_code)
     )
     OR EXISTS (
       SELECT 1
         FROM unnest(p_requested_role_codes) AS requested(role_code)
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
    SELECT requested.role_code
      FROM unnest(p_requested_role_codes) AS requested(role_code)
    EXCEPT
    SELECT DISTINCT assignment.assignable_role_code
      FROM public.role_bindings binding
      JOIN public.roles grantor_role
        ON grantor_role.id = binding.role_id
       AND grantor_role.system_role = true
      JOIN public.system_role_assignment_matrix assignment
        ON assignment.grantor_role_code = grantor_role.code
      JOIN public.roles assignable_role
        ON assignable_role.code = assignment.assignable_role_code
       AND assignable_role.system_role = true
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Actor cannot assign one or more invitation roles'
      USING ERRCODE = '42501';
  END IF;
END
$$;

REVOKE ALL ON FUNCTION public.assert_tenant_invitation_role_delegation_allowed(uuid,text[]) FROM PUBLIC;
