ALTER TABLE roles
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();

ALTER TABLE role_permissions
  ADD COLUMN delegable boolean NOT NULL DEFAULT false;

ALTER TABLE role_bindings
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();

-- Only the built-in church administrator is a delegation source. Security
-- administration and recovery remain non-delegable so a local role can never
-- manufacture another administrator or a recovery authority.
UPDATE role_permissions permission
   SET delegable = true
  FROM roles role
 WHERE role.id = permission.role_id
   AND role.code = 'CHURCH_ADMIN'
   AND permission.permission_code NOT IN ('role.manage', 'recovery.activate');

CREATE FUNCTION assert_local_role_definition_allowed(
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

CREATE FUNCTION create_local_role(
  p_actor_identity_id uuid,
  p_role_id uuid,
  p_code text,
  p_name_i18n jsonb,
  p_permission_codes text[],
  p_delegable_permission_codes text[]
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM public.assert_local_role_definition_allowed(
    p_actor_identity_id, p_permission_codes, p_delegable_permission_codes
  );
  IF p_code !~ '^LOCAL_[A-Z0-9_]{3,54}$'
     OR jsonb_typeof(p_name_i18n) <> 'object'
     OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(p_name_i18n) key) <> ARRAY['en','es','fr']::text[]
     OR EXISTS (
       SELECT 1 FROM jsonb_each_text(p_name_i18n) localized(locale, value)
        WHERE length(btrim(localized.value)) NOT BETWEEN 2 AND 120
     ) THEN
    RAISE EXCEPTION 'Local role code or localized name is invalid' USING ERRCODE = '23514';
  END IF;
  INSERT INTO public.roles(id, code, name_i18n, system_role)
  VALUES (p_role_id, p_code, p_name_i18n, false);
  INSERT INTO public.role_permissions(role_id, permission_code, delegable)
  SELECT p_role_id, requested.permission_code,
         requested.permission_code = ANY(p_delegable_permission_codes)
    FROM unnest(p_permission_codes) requested(permission_code)
   ORDER BY requested.permission_code;
  RETURN 1;
END
$$;

CREATE FUNCTION update_local_role(
  p_actor_identity_id uuid,
  p_role_id uuid,
  p_expected_version integer,
  p_name_i18n jsonb,
  p_permission_codes text[],
  p_delegable_permission_codes text[]
)
RETURNS TABLE(next_version integer, affected_identity_ids uuid[])
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  changed_version integer;
  affected uuid[];
BEGIN
  PERFORM public.assert_local_role_definition_allowed(
    p_actor_identity_id, p_permission_codes, p_delegable_permission_codes
  );
  IF jsonb_typeof(p_name_i18n) <> 'object'
     OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(p_name_i18n) key) <> ARRAY['en','es','fr']::text[]
     OR EXISTS (
       SELECT 1 FROM jsonb_each_text(p_name_i18n) localized(locale, value)
        WHERE length(btrim(localized.value)) NOT BETWEEN 2 AND 120
     ) THEN
    RAISE EXCEPTION 'Localized role name is invalid' USING ERRCODE = '23514';
  END IF;
  SELECT COALESCE(array_agg(identity_id ORDER BY identity_id), ARRAY[]::uuid[])
    INTO affected
    FROM public.role_bindings
   WHERE role_id = p_role_id AND revoked_at IS NULL;
  UPDATE public.roles
     SET name_i18n = p_name_i18n, version = version + 1, updated_at = clock_timestamp()
   WHERE id = p_role_id AND NOT system_role AND version = p_expected_version
  RETURNING version INTO changed_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Local role version changed or system role is immutable' USING ERRCODE = '40001';
  END IF;
  DELETE FROM public.role_permissions WHERE role_id = p_role_id;
  INSERT INTO public.role_permissions(role_id, permission_code, delegable)
  SELECT p_role_id, requested.permission_code,
         requested.permission_code = ANY(p_delegable_permission_codes)
    FROM unnest(p_permission_codes) requested(permission_code)
   ORDER BY requested.permission_code;
  RETURN QUERY SELECT changed_version, affected;
END
$$;

CREATE FUNCTION assert_role_binding_allowed(
  p_actor_identity_id uuid,
  p_target_identity_id uuid,
  p_role_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_actor_identity_id = p_target_identity_id THEN
    RAISE EXCEPTION 'Self-assignment and self-revocation are not permitted' USING ERRCODE = '42501';
  END IF;
  PERFORM public.assert_local_role_definition_allowed(
    p_actor_identity_id,
    ARRAY(SELECT permission_code FROM public.role_permissions WHERE role_id = p_role_id ORDER BY permission_code),
    ARRAY[]::text[]
  );
  IF NOT EXISTS (SELECT 1 FROM public.roles WHERE id = p_role_id) THEN
    RAISE EXCEPTION 'Tenant role is unavailable' USING ERRCODE = '23503';
  END IF;
END
$$;

CREATE FUNCTION grant_tenant_role_binding(
  p_actor_identity_id uuid,
  p_target_identity_id uuid,
  p_role_id uuid
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  next_version integer;
BEGIN
  PERFORM public.assert_role_binding_allowed(p_actor_identity_id, p_target_identity_id, p_role_id);
  INSERT INTO public.role_bindings(identity_id, role_id, granted_by_identity_id)
  VALUES (p_target_identity_id, p_role_id, p_actor_identity_id)
  ON CONFLICT(identity_id, role_id) DO UPDATE SET
    granted_at = clock_timestamp(),
    granted_by_identity_id = EXCLUDED.granted_by_identity_id,
    revoked_at = NULL,
    version = public.role_bindings.version + 1,
    updated_at = clock_timestamp()
  WHERE public.role_bindings.revoked_at IS NOT NULL
  RETURNING version INTO next_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Role binding is already active' USING ERRCODE = '23505';
  END IF;
  RETURN next_version;
END
$$;

CREATE FUNCTION revoke_tenant_role_binding(
  p_actor_identity_id uuid,
  p_target_identity_id uuid,
  p_role_id uuid,
  p_expected_version integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  next_version integer;
BEGIN
  PERFORM public.assert_role_binding_allowed(p_actor_identity_id, p_target_identity_id, p_role_id);
  UPDATE public.role_bindings
     SET revoked_at = clock_timestamp(), version = version + 1, updated_at = clock_timestamp()
   WHERE identity_id = p_target_identity_id
     AND role_id = p_role_id
     AND revoked_at IS NULL
     AND version = p_expected_version
  RETURNING version INTO next_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Role binding version changed or binding is inactive' USING ERRCODE = '40001';
  END IF;
  RETURN next_version;
END
$$;

REVOKE ALL ON FUNCTION assert_local_role_definition_allowed(uuid,text[],text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION create_local_role(uuid,uuid,text,jsonb,text[],text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION update_local_role(uuid,uuid,integer,jsonb,text[],text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION assert_role_binding_allowed(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_tenant_role_binding(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_tenant_role_binding(uuid,uuid,uuid,integer) FROM PUBLIC;
