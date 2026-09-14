ALTER TABLE provisioning_jobs
  ADD COLUMN request_payload jsonb,
  ADD COLUMN requested_by_identity_id uuid REFERENCES platform_identities(id) ON DELETE RESTRICT,
  ADD COLUMN request_id uuid,
  ADD COLUMN next_attempt_at timestamptz;

ALTER TABLE provisioning_jobs
  DROP CONSTRAINT provisioning_jobs_state_check,
  ADD CONSTRAINT provisioning_jobs_state_check CHECK (state IN (
    'requested', 'roles_created', 'database_created', 'migrated', 'seeded',
    'pending_activation', 'active', 'failed'
  ));

ALTER TABLE tenants
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ADD COLUMN suspension_reason text;

CREATE TABLE platform_worker_status (
  worker_code text PRIMARY KEY CHECK (worker_code = 'tenant-provisioner'),
  instance_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('starting', 'running', 'stopping', 'stopped', 'failed')),
  started_at timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL,
  processed_count bigint NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
  last_error_code text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON platform_worker_status FROM PUBLIC;

CREATE FUNCTION queue_platform_tenant_provisioning(
  p_idempotency_key uuid,
  p_tenant_id uuid,
  p_slug text,
  p_display_name text,
  p_kind text,
  p_timezone text,
  p_locale text,
  p_initial_admin_mode text,
  p_initial_admin_email text,
  p_initial_admin_normalized_email text,
  p_initial_admin_token_hash text,
  p_initial_admin_expires_at timestamptz,
  p_initial_admin_expires_in_hours integer,
  p_request_hash text,
  p_actor_identity_id uuid,
  p_request_id uuid
)
RETURNS TABLE(job_id uuid, job_state text, reused boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  existing_job record;
  created_job_id uuid;
  initial_admin_payload jsonb;
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM public.platform_role_bindings binding
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.role_code IN ('platform_admin', 'platform_operator')
  ) THEN
    RAISE EXCEPTION 'Platform tenant provisioning permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_initial_admin_mode = 'invitation' AND NOT EXISTS (
    SELECT 1 FROM public.platform_role_bindings binding
     WHERE binding.identity_id = p_actor_identity_id AND binding.role_code = 'platform_admin'
  ) THEN
    RAISE EXCEPTION 'Platform security administration permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_slug !~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'
     OR length(btrim(p_display_name)) NOT BETWEEN 2 AND 160
     OR p_kind NOT IN ('demo', 'real')
     OR length(p_timezone) NOT BETWEEN 1 AND 80
     OR p_locale NOT IN ('es', 'en', 'fr')
     OR p_initial_admin_mode IS NULL
     OR p_initial_admin_mode NOT IN ('invitation', 'pending', 'demo_seed')
     OR (p_initial_admin_mode = 'demo_seed' AND p_kind <> 'demo')
     OR p_request_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Provisioning request is invalid' USING ERRCODE = '23514';
  END IF;

  IF p_initial_admin_mode = 'invitation' THEN
    IF p_initial_admin_email IS NULL
       OR p_initial_admin_normalized_email IS NULL
       OR p_initial_admin_token_hash IS NULL
       OR p_initial_admin_expires_at IS NULL
       OR p_initial_admin_expires_in_hours IS NULL
       OR length(p_initial_admin_email) NOT BETWEEN 3 AND 320
       OR p_initial_admin_normalized_email IS DISTINCT FROM lower(btrim(p_initial_admin_email))
       OR p_initial_admin_token_hash !~ '^[0-9a-f]{64}$'
       OR p_initial_admin_expires_in_hours NOT BETWEEN 1 AND 168
       OR p_initial_admin_expires_at <= clock_timestamp() + interval '59 minutes'
       OR p_initial_admin_expires_at > clock_timestamp() + interval '169 hours' THEN
      RAISE EXCEPTION 'Initial administrator invitation is invalid' USING ERRCODE = '23514';
    END IF;
    initial_admin_payload := jsonb_build_object(
      'mode', 'invitation',
      'email', btrim(p_initial_admin_email),
      'normalizedEmail', p_initial_admin_normalized_email,
      'tokenHash', p_initial_admin_token_hash,
      'expiresAt', p_initial_admin_expires_at,
      'expiresInHours', p_initial_admin_expires_in_hours,
      'createdByIdentityId', p_actor_identity_id
    );
  ELSE
    IF p_initial_admin_email IS NOT NULL
       OR p_initial_admin_normalized_email IS NOT NULL
       OR p_initial_admin_token_hash IS NOT NULL
       OR p_initial_admin_expires_at IS NOT NULL
       OR p_initial_admin_expires_in_hours IS NOT NULL THEN
      RAISE EXCEPTION 'Pending activation cannot contain invitation material' USING ERRCODE = '23514';
    END IF;
    initial_admin_payload := jsonb_build_object('mode', p_initial_admin_mode);
  END IF;

  SELECT id, idempotency_key, tenant_id, request_hash, state
    INTO existing_job
    FROM public.provisioning_jobs
   WHERE idempotency_key = p_idempotency_key OR tenant_id = p_tenant_id
   ORDER BY (idempotency_key = p_idempotency_key) DESC
   LIMIT 1
   FOR UPDATE;
  IF FOUND THEN
    IF existing_job.idempotency_key IS DISTINCT FROM p_idempotency_key
       OR existing_job.tenant_id IS DISTINCT FROM p_tenant_id
       OR existing_job.request_hash IS DISTINCT FROM p_request_hash THEN
      RAISE EXCEPTION 'Provisioning idempotency key or tenant id was reused with different input'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_job.id, existing_job.state, true;
    RETURN;
  END IF;

  IF p_initial_admin_mode = 'invitation' AND EXISTS (
    SELECT 1 FROM public.platform_identities identity
     WHERE identity.normalized_email = p_initial_admin_normalized_email
    UNION ALL
    SELECT 1 FROM public.tenant_invitations invitation
     WHERE invitation.normalized_email = p_initial_admin_normalized_email
       AND invitation.status IN ('pending','accepting')
  ) THEN
    RAISE EXCEPTION 'Initial administrator recipient is unavailable' USING ERRCODE = '23505';
  END IF;

  IF EXISTS (SELECT 1 FROM public.tenants WHERE slug = p_slug AND id <> p_tenant_id) THEN
    RAISE EXCEPTION 'Tenant slug already exists' USING ERRCODE = '23505';
  END IF;

  INSERT INTO public.provisioning_jobs(
    idempotency_key, tenant_id, requested_slug, request_hash, state,
    request_payload, requested_by_identity_id, request_id
  ) VALUES (
    p_idempotency_key, p_tenant_id, p_slug, p_request_hash, 'requested',
    jsonb_build_object(
      'idempotencyKey', p_idempotency_key,
      'tenantId', p_tenant_id,
      'slug', p_slug,
      'displayName', btrim(p_display_name),
      'kind', p_kind,
      'timezone', p_timezone,
      'locale', p_locale,
      'initialAdmin', initial_admin_payload
    ),
    p_actor_identity_id,
    p_request_id
  )
  RETURNING id INTO created_job_id;
  RETURN QUERY SELECT created_job_id, 'requested'::text, false;
END
$$;

CREATE FUNCTION activate_platform_tenant_initial_admin(
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
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.platform_role_bindings binding
     WHERE binding.identity_id = p_actor_identity_id AND binding.role_code = 'platform_admin'
  ) THEN
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

  SELECT invitation.id, invitation.request_hash, tenant.version
    INTO existing_invitation
    FROM public.tenant_invitations invitation
    JOIN public.tenants tenant ON tenant.id = invitation.tenant_id
   WHERE invitation.tenant_id = p_tenant_id
     AND invitation.created_by_identity_id = p_actor_identity_id
     AND invitation.idempotency_key = p_idempotency_key
   FOR UPDATE OF invitation, tenant;
  IF FOUND THEN
    IF existing_invitation.request_hash IS DISTINCT FROM p_request_hash THEN
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
     AND tenant.status = 'provisioning'
     AND tenant.version = p_expected_version
     AND job.state IN ('seeded','pending_activation')
   FOR UPDATE OF tenant, job;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tenant is not awaiting an initial administrator'
      USING ERRCODE = '40001';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.platform_identities identity WHERE identity.normalized_email = p_normalized_email
    UNION ALL
    SELECT 1 FROM public.tenant_invitations invitation
     WHERE invitation.normalized_email = p_normalized_email
       AND invitation.status IN ('pending','accepting')
  ) THEN
    RAISE EXCEPTION 'Initial administrator recipient is unavailable' USING ERRCODE = '23505';
  END IF;

  INSERT INTO public.tenant_invitations(
    tenant_id,email,normalized_email,role_codes,token_hash,status,idempotency_key,
    request_hash,created_by_identity_id,expires_at
  ) VALUES (
    p_tenant_id,btrim(p_email),p_normalized_email,ARRAY['CHURCH_ADMIN']::text[],p_token_hash,
    'pending',p_idempotency_key,p_request_hash,p_actor_identity_id,p_expires_at
  ) RETURNING id INTO created_invitation_id;

  UPDATE public.tenants
     SET status='active',activated_at=clock_timestamp(),version=version+1,updated_at=clock_timestamp()
   WHERE id=p_tenant_id
  RETURNING version INTO changed_version;
  UPDATE public.provisioning_jobs
     SET state='active',completed_at=clock_timestamp(),last_error_code=NULL,updated_at=clock_timestamp()
   WHERE tenant_id=p_tenant_id;

  RETURN QUERY SELECT created_invitation_id, changed_version, false;
END
$$;

CREATE FUNCTION suspend_platform_tenant(
  p_tenant_id uuid,
  p_expected_version integer,
  p_reason text,
  p_actor_identity_id uuid
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  next_version integer;
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM public.platform_role_bindings binding
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.role_code IN ('platform_admin', 'platform_operator')
  ) THEN
    RAISE EXCEPTION 'Platform tenant suspension permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF length(btrim(p_reason)) NOT BETWEEN 4 AND 500 THEN
    RAISE EXCEPTION 'A bounded suspension reason is required' USING ERRCODE = '23514';
  END IF;

  UPDATE public.tenants
     SET status = 'suspended',
         suspended_at = clock_timestamp(),
         suspension_reason = btrim(p_reason),
         version = version + 1,
         updated_at = clock_timestamp()
   WHERE id = p_tenant_id
     AND status = 'active'
     AND version = p_expected_version
  RETURNING version INTO next_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tenant state or version changed' USING ERRCODE = '40001';
  END IF;

  UPDATE public.auth_sessions
     SET revoked_at = clock_timestamp(), revoke_reason = 'tenant_suspended'
   WHERE active_tenant_id = p_tenant_id AND revoked_at IS NULL;
  RETURN next_version;
END
$$;

REVOKE ALL ON FUNCTION queue_platform_tenant_provisioning(uuid,uuid,text,text,text,text,text,text,text,text,text,timestamptz,integer,text,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION activate_platform_tenant_initial_admin(uuid,integer,text,text,text,timestamptz,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION suspend_platform_tenant(uuid,integer,text,uuid) FROM PUBLIC;
