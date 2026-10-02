ALTER TABLE tenants
  ADD COLUMN gestionchurch_tenant_id uuid;

CREATE UNIQUE INDEX tenants_gestionchurch_tenant_id_unique
  ON tenants(gestionchurch_tenant_id)
  WHERE gestionchurch_tenant_id IS NOT NULL;

ALTER TABLE platform_identities
  ADD COLUMN gestionchurch_subject text,
  ADD COLUMN gestionchurch_roles text[],
  ADD COLUMN gestionchurch_role_fingerprint text;

CREATE UNIQUE INDEX platform_identities_gestionchurch_subject_unique
  ON platform_identities(gestionchurch_subject)
  WHERE gestionchurch_subject IS NOT NULL;

ALTER TABLE platform_identities
  ADD CONSTRAINT platform_identities_gestionchurch_federation_complete CHECK (
    (gestionchurch_subject IS NULL AND gestionchurch_roles IS NULL AND gestionchurch_role_fingerprint IS NULL)
    OR
    (gestionchurch_subject IS NOT NULL
      AND cardinality(gestionchurch_roles) BETWEEN 1 AND 12
      AND gestionchurch_role_fingerprint ~ '^[0-9a-f]{64}$')
  );

CREATE OR REPLACE FUNCTION sync_gestionchurch_federated_identity(
  p_gestionchurch_tenant_id uuid,
  p_gestionchurch_tenant_slug text,
  p_tenant_name text,
  p_gestionchurch_subject text,
  p_email text,
  p_display_name text,
  p_gestionchurch_roles text[],
  p_role_fingerprint text,
  p_disabled_password_hash text
)
RETURNS TABLE(identity_id uuid, tenant_id uuid, tenant_slug text, tenant_status text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  selected_tenant public.tenants%ROWTYPE;
  selected_identity_id uuid;
  synthetic_normalized_email text;
BEGIN
  IF p_gestionchurch_tenant_id IS NULL
     OR p_gestionchurch_tenant_slug !~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'
     OR length(trim(p_tenant_name)) NOT BETWEEN 2 AND 160
     OR p_gestionchurch_subject !~ '^(global|tenant):[0-9a-f-]{36}:[0-9a-f-]{36}$'
     OR length(trim(p_email)) NOT BETWEEN 3 AND 320
     OR length(trim(p_display_name)) NOT BETWEEN 2 AND 160
     OR cardinality(p_gestionchurch_roles) NOT BETWEEN 1 AND 12
     OR p_role_fingerprint !~ '^[0-9a-f]{64}$'
     OR length(p_disabled_password_hash) < 20 THEN
    RAISE EXCEPTION 'GestionChurch federation input is invalid' USING ERRCODE = '23514';
  END IF;
  IF cardinality(p_gestionchurch_roles) <> (
    SELECT count(DISTINCT role_code)::integer FROM unnest(p_gestionchurch_roles) requested(role_code)
  ) OR EXISTS (
    SELECT 1 FROM unnest(p_gestionchurch_roles) requested(role_code)
     WHERE role_code NOT IN (
       'GLOBAL_ADMIN','TENANT_ADMIN','PASTOR','BOARD_SECRETARY','FIRST_ELDER','ELDER',
       'REVIEWER','DEPARTMENT_LEADER','DEPARTMENT_PLANNER','NOMINATIONS_USER','VIEWER','AUDITOR'
     )
  ) THEN
    RAISE EXCEPTION 'GestionChurch roles are not an exact supported set' USING ERRCODE = '23514';
  END IF;

  SELECT tenant.* INTO selected_tenant
    FROM public.tenants tenant
   WHERE tenant.gestionchurch_tenant_id = p_gestionchurch_tenant_id
      OR (
        tenant.gestionchurch_tenant_id IS NULL
        AND (tenant.slug = p_gestionchurch_tenant_slug OR lower(tenant.display_name) = lower(trim(p_tenant_name)))
      )
   ORDER BY (tenant.gestionchurch_tenant_id = p_gestionchurch_tenant_id) DESC,
            (tenant.slug = p_gestionchurch_tenant_slug) DESC
   LIMIT 1
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'GestionChurch tenant has not been provisioned in Nombramientos'
      USING ERRCODE = 'P0001', CONSTRAINT = 'gestionchurch_tenant_not_provisioned';
  END IF;
  IF selected_tenant.status NOT IN ('active','provisioning') THEN
    RAISE EXCEPTION 'GestionChurch tenant is not available in Nombramientos'
      USING ERRCODE = '55000', CONSTRAINT = 'gestionchurch_tenant_unavailable';
  END IF;

  UPDATE public.tenants
     SET gestionchurch_tenant_id=p_gestionchurch_tenant_id,
         display_name=trim(p_tenant_name),
         status='active',
         activated_at=COALESCE(activated_at,clock_timestamp()),
         suspended_at=NULL,
         version=version+1,
         updated_at=clock_timestamp()
   WHERE id=selected_tenant.id;
  UPDATE public.provisioning_jobs
     SET state='active',last_error_code=NULL,updated_at=clock_timestamp(),completed_at=COALESCE(completed_at,clock_timestamp())
   WHERE tenant_id=selected_tenant.id AND state<>'active';

  synthetic_normalized_email := 'gc+' || encode(sha256(convert_to(p_gestionchurch_subject,'UTF8')),'hex') || '@federated.gestionchurch.local';
  INSERT INTO public.platform_identities(
    email,normalized_email,display_name,password_hash,status,mfa_enabled,mfa_required,
    passkey_enabled,strong_auth_enabled,password_provisioned,gestionchurch_subject,
    gestionchurch_roles,gestionchurch_role_fingerprint
  ) VALUES (
    lower(trim(p_email)),synthetic_normalized_email,trim(p_display_name),p_disabled_password_hash,
    'active',false,false,false,false,false,p_gestionchurch_subject,p_gestionchurch_roles,p_role_fingerprint
  )
  ON CONFLICT(gestionchurch_subject) WHERE gestionchurch_subject IS NOT NULL DO UPDATE
    SET email=EXCLUDED.email,
        display_name=EXCLUDED.display_name,
        status='active',
        failed_login_count=0,
        locked_until=NULL,
        mfa_enabled=false,
        mfa_required=false,
        totp_secret_ciphertext=NULL,
        mfa_enrollment_id=NULL,
        mfa_enrollment_secret_ciphertext=NULL,
        mfa_enrollment_started_at=NULL,
        mfa_enrolled_at=NULL,
        passkey_enabled=false,
        passkey_enrolled_at=NULL,
        strong_auth_enabled=false,
        password_provisioned=false,
        gestionchurch_roles=EXCLUDED.gestionchurch_roles,
        gestionchurch_role_fingerprint=EXCLUDED.gestionchurch_role_fingerprint,
        updated_at=clock_timestamp()
  RETURNING id INTO selected_identity_id;

  INSERT INTO public.tenant_memberships(tenant_id,identity_id,status,is_default)
  VALUES(selected_tenant.id,selected_identity_id,'active',true)
  ON CONFLICT(tenant_id,identity_id) DO UPDATE
    SET status='active',is_default=true,revoked_at=NULL;

  UPDATE public.auth_sessions
     SET revoked_at=clock_timestamp(),revoke_reason='gestionchurch_session_rotated'
   WHERE identity_id=selected_identity_id AND revoked_at IS NULL;

  RETURN QUERY
    SELECT selected_identity_id,selected_tenant.id,selected_tenant.slug,'active'::text;
END
$$;

REVOKE ALL ON FUNCTION sync_gestionchurch_federated_identity(
  uuid,text,text,text,text,text,text[],text,text
) FROM PUBLIC;

