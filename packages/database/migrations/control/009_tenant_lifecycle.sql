ALTER TABLE tenants
  DROP CONSTRAINT tenants_status_check,
  ADD CONSTRAINT tenants_status_check CHECK (
    status IN ('provisioning', 'active', 'suspended', 'failed', 'decommission_pending')
  ),
  ADD COLUMN decommission_request_id uuid,
  ADD COLUMN retention_until timestamptz,
  ADD COLUMN decommission_requested_at timestamptz,
  ADD CONSTRAINT tenant_decommission_state_tuple CHECK (
    (status = 'decommission_pending'
      AND decommission_request_id IS NOT NULL
      AND retention_until IS NOT NULL
      AND decommission_requested_at IS NOT NULL)
    OR
    (status <> 'decommission_pending'
      AND decommission_request_id IS NULL
      AND retention_until IS NULL
      AND decommission_requested_at IS NULL)
  );

UPDATE tenants
   SET suspension_reason='operational_hold'
 WHERE suspension_reason IS NOT NULL;

ALTER TABLE tenants
  ADD CONSTRAINT tenants_suspension_reason_code CHECK (
    suspension_reason IS NULL
    OR suspension_reason IN ('security_review','operational_hold','institution_request','compliance_review')
  );

CREATE OR REPLACE FUNCTION suspend_platform_tenant(
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
  IF p_reason NOT IN ('security_review','operational_hold','institution_request','compliance_review') THEN
    RAISE EXCEPTION 'A normalized suspension reason code is required' USING ERRCODE = '23514';
  END IF;

  UPDATE public.tenants
     SET status='suspended',suspended_at=clock_timestamp(),suspension_reason=p_reason,
         version=version+1,updated_at=clock_timestamp()
   WHERE id=p_tenant_id AND status='active' AND version=p_expected_version
  RETURNING version INTO next_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tenant state or version changed' USING ERRCODE = '40001';
  END IF;
  UPDATE public.auth_sessions
     SET revoked_at=clock_timestamp(),revoke_reason='tenant_suspended'
   WHERE active_tenant_id=p_tenant_id AND revoked_at IS NULL;
  RETURN next_version;
END
$$;

CREATE TABLE tenant_export_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  idempotency_key uuid NOT NULL UNIQUE,
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  tenant_version integer NOT NULL CHECK (tenant_version > 0),
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'ready', 'failed')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 8),
  next_attempt_at timestamptz,
  claimed_at timestamptz,
  requested_by_identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL,
  backup_id uuid,
  artifact_relative_path text CHECK (
    artifact_relative_path IS NULL
    OR artifact_relative_path ~ '^[0-9a-f-]{36}/[0-9TZ]+-[0-9a-f-]{36}$'
  ),
  public_manifest jsonb,
  encrypted_bytes bigint CHECK (encrypted_bytes IS NULL OR encrypted_bytes > 0),
  ciphertext_sha256 text CHECK (ciphertext_sha256 IS NULL OR ciphertext_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  recovery_point_at timestamptz,
  last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,80}$'),
  revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ready_at timestamptz,
  failed_at timestamptz,
  CHECK (
    (state = 'ready'
      AND backup_id IS NOT NULL
      AND artifact_relative_path IS NOT NULL
      AND public_manifest IS NOT NULL
      AND encrypted_bytes IS NOT NULL
      AND ciphertext_sha256 IS NOT NULL
      AND recovery_point_at IS NOT NULL
      AND ready_at IS NOT NULL
      AND last_error_code IS NULL)
    OR
    (state <> 'ready'
      AND backup_id IS NULL
      AND artifact_relative_path IS NULL
      AND public_manifest IS NULL
      AND encrypted_bytes IS NULL
      AND ciphertext_sha256 IS NULL
      AND recovery_point_at IS NULL
      AND ready_at IS NULL)
  )
);

CREATE UNIQUE INDEX tenant_export_one_in_flight
ON tenant_export_jobs(tenant_id)
WHERE state IN ('queued', 'running');

CREATE INDEX tenant_export_jobs_tenant_created
ON tenant_export_jobs(tenant_id, created_at DESC, id DESC);

CREATE TABLE tenant_export_download_authorizations (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  export_job_id uuid NOT NULL REFERENCES tenant_export_jobs(id) ON DELETE RESTRICT,
  idempotency_key uuid NOT NULL UNIQUE,
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  requested_by_identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'consumed', 'revoked', 'expired')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  consumed_at timestamptz,
  revoked_at timestamptz,
  revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
  CHECK (expires_at > created_at),
  CHECK ((status = 'consumed') = (consumed_at IS NOT NULL)),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX tenant_export_download_active
ON tenant_export_download_authorizations(requested_by_identity_id, expires_at)
WHERE status = 'active';

CREATE TABLE tenant_decommission_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  source_export_job_id uuid NOT NULL REFERENCES tenant_export_jobs(id) ON DELETE RESTRICT,
  schedule_idempotency_key uuid NOT NULL UNIQUE,
  schedule_request_hash text NOT NULL CHECK (schedule_request_hash ~ '^[0-9a-f]{64}$'),
  state text NOT NULL DEFAULT 'scheduled' CHECK (state IN ('scheduled', 'cancelled')),
  reason_code text NOT NULL CHECK (reason_code IN (
    'institution_request', 'duplicate_tenant', 'service_ended', 'legal_retention'
  )),
  previous_tenant_status text NOT NULL CHECK (previous_tenant_status IN ('active', 'suspended')),
  retention_until timestamptz NOT NULL,
  scheduled_by_identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE RESTRICT,
  scheduled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  cancel_idempotency_key uuid UNIQUE,
  cancel_request_hash text CHECK (cancel_request_hash IS NULL OR cancel_request_hash ~ '^[0-9a-f]{64}$'),
  cancelled_by_identity_id uuid REFERENCES platform_identities(id) ON DELETE RESTRICT,
  cancelled_at timestamptz,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK (
    (state = 'scheduled'
      AND cancel_idempotency_key IS NULL
      AND cancel_request_hash IS NULL
      AND cancelled_by_identity_id IS NULL
      AND cancelled_at IS NULL)
    OR
    (state = 'cancelled'
      AND cancel_idempotency_key IS NOT NULL
      AND cancel_request_hash IS NOT NULL
      AND cancelled_by_identity_id IS NOT NULL
      AND cancelled_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX tenant_decommission_one_scheduled
ON tenant_decommission_requests(tenant_id)
WHERE state = 'scheduled';

ALTER TABLE tenants
  ADD CONSTRAINT tenants_decommission_request_fkey
  FOREIGN KEY (decommission_request_id) REFERENCES tenant_decommission_requests(id) ON DELETE RESTRICT;

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON tenant_export_jobs FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON tenant_export_download_authorizations FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON tenant_decommission_requests FROM PUBLIC;

CREATE FUNCTION queue_platform_tenant_export(
  p_tenant_id uuid,
  p_expected_version integer,
  p_idempotency_key uuid,
  p_request_hash text,
  p_actor_identity_id uuid,
  p_request_id uuid
)
RETURNS TABLE(job_id uuid, job_state text, job_revision integer, reused boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  existing_job record;
  created_job record;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.platform_role_bindings binding
     WHERE binding.identity_id = p_actor_identity_id
       AND binding.role_code IN ('platform_admin', 'platform_operator')
  ) THEN
    RAISE EXCEPTION 'Platform tenant export permission is required' USING ERRCODE = '42501';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version < 1
     OR p_request_hash IS NULL OR p_request_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Tenant export request is invalid' USING ERRCODE = '23514';
  END IF;

  SELECT job.id,job.state,job.revision,job.request_hash,job.tenant_id,job.tenant_version
    INTO existing_job
    FROM public.tenant_export_jobs job
   WHERE job.idempotency_key = p_idempotency_key
   FOR UPDATE;
  IF FOUND THEN
    IF existing_job.request_hash IS DISTINCT FROM p_request_hash
       OR existing_job.tenant_id IS DISTINCT FROM p_tenant_id
       OR existing_job.tenant_version IS DISTINCT FROM p_expected_version THEN
      RAISE EXCEPTION 'Tenant export idempotency key was reused with different input'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_job.id,existing_job.state,existing_job.revision,true;
    RETURN;
  END IF;

  PERFORM 1 FROM public.tenants tenant
   WHERE tenant.id=p_tenant_id
     AND tenant.status IN ('active','suspended')
     AND tenant.version=p_expected_version
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tenant state or version changed' USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.tenant_export_jobs(
    tenant_id,idempotency_key,request_hash,tenant_version,requested_by_identity_id,request_id
  ) VALUES (
    p_tenant_id,p_idempotency_key,p_request_hash,p_expected_version,p_actor_identity_id,p_request_id
  ) RETURNING id,state,revision INTO created_job;
  RETURN QUERY SELECT created_job.id,created_job.state,created_job.revision,false;
END
$$;

CREATE FUNCTION authorize_platform_tenant_export_download(
  p_authorization_id uuid,
  p_tenant_id uuid,
  p_export_job_id uuid,
  p_expires_at timestamptz,
  p_idempotency_key uuid,
  p_request_hash text,
  p_actor_identity_id uuid
)
RETURNS TABLE(authorization_id uuid, authorization_status text, authorization_revision integer, expires_at timestamptz, reused boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  existing_authorization record;
  created_authorization record;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.platform_role_bindings binding
     WHERE binding.identity_id=p_actor_identity_id AND binding.role_code='platform_admin'
  ) THEN
    RAISE EXCEPTION 'Platform tenant export download permission is required' USING ERRCODE = '42501';
  END IF;
  IF p_expires_at IS NULL
     OR p_expires_at <= clock_timestamp()
     OR p_expires_at > clock_timestamp() + interval '10 minutes'
     OR p_request_hash IS NULL OR p_request_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Tenant export download authorization is invalid' USING ERRCODE = '23514';
  END IF;

  SELECT authz.id,authz.status,authz.revision,authz.expires_at,
         authz.request_hash,authz.tenant_id,authz.export_job_id
    INTO existing_authorization
    FROM public.tenant_export_download_authorizations authz
   WHERE authz.idempotency_key=p_idempotency_key
   FOR UPDATE;
  IF FOUND THEN
    IF existing_authorization.request_hash IS DISTINCT FROM p_request_hash
       OR existing_authorization.tenant_id IS DISTINCT FROM p_tenant_id
       OR existing_authorization.export_job_id IS DISTINCT FROM p_export_job_id THEN
      RAISE EXCEPTION 'Download authorization idempotency key was reused with different input'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_authorization.id,existing_authorization.status,
      existing_authorization.revision,existing_authorization.expires_at,true;
    RETURN;
  END IF;

  PERFORM 1 FROM public.tenant_export_jobs job
   WHERE job.id=p_export_job_id AND job.tenant_id=p_tenant_id AND job.state='ready'
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'A ready tenant export is required' USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.tenant_export_download_authorizations(
    id,tenant_id,export_job_id,idempotency_key,request_hash,requested_by_identity_id,expires_at
  ) VALUES (
    p_authorization_id,p_tenant_id,p_export_job_id,p_idempotency_key,p_request_hash,
    p_actor_identity_id,p_expires_at
  ) RETURNING id,status,revision,tenant_export_download_authorizations.expires_at
    INTO created_authorization;
  RETURN QUERY SELECT created_authorization.id,created_authorization.status,
    created_authorization.revision,created_authorization.expires_at,false;
END
$$;

CREATE FUNCTION consume_platform_tenant_export_download(
  p_authorization_id uuid,
  p_tenant_id uuid,
  p_export_job_id uuid,
  p_actor_identity_id uuid
)
RETURNS TABLE(
  artifact_relative_path text,
  public_manifest jsonb,
  encrypted_bytes bigint,
  ciphertext_sha256 text,
  backup_id uuid,
  tenant_slug text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.platform_role_bindings binding
     WHERE binding.identity_id=p_actor_identity_id AND binding.role_code='platform_admin'
  ) THEN
    RAISE EXCEPTION 'Platform tenant export download permission is required' USING ERRCODE = '42501';
  END IF;

  UPDATE public.tenant_export_download_authorizations authz
     SET status='expired',revision=revision+1
   WHERE authz.id=p_authorization_id
     AND authz.tenant_id=p_tenant_id
     AND authz.export_job_id=p_export_job_id
     AND authz.requested_by_identity_id=p_actor_identity_id
     AND authz.status='active'
     AND authz.expires_at <= clock_timestamp();

  RETURN QUERY
  WITH consumed AS (
    UPDATE public.tenant_export_download_authorizations authz
       SET status='consumed',consumed_at=clock_timestamp(),revision=revision+1
     WHERE authz.id=p_authorization_id
       AND authz.tenant_id=p_tenant_id
       AND authz.export_job_id=p_export_job_id
       AND authz.requested_by_identity_id=p_actor_identity_id
       AND authz.status='active'
       AND authz.expires_at > clock_timestamp()
     RETURNING authz.export_job_id
  )
  SELECT job.artifact_relative_path,job.public_manifest,job.encrypted_bytes,
         job.ciphertext_sha256,job.backup_id,tenant.slug
    FROM consumed
    JOIN public.tenant_export_jobs job ON job.id=consumed.export_job_id AND job.state='ready'
    JOIN public.tenants tenant ON tenant.id=job.tenant_id;
END
$$;

CREATE FUNCTION revoke_platform_tenant_export_download(
  p_authorization_id uuid,
  p_expected_revision integer,
  p_actor_identity_id uuid
)
RETURNS TABLE(authorization_status text, authorization_revision integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  authz_record record;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.platform_role_bindings binding
     WHERE binding.identity_id=p_actor_identity_id AND binding.role_code='platform_admin'
  ) THEN
    RAISE EXCEPTION 'Platform tenant export download permission is required' USING ERRCODE = '42501';
  END IF;
  SELECT status,revision INTO authz_record
    FROM public.tenant_export_download_authorizations
   WHERE id=p_authorization_id AND requested_by_identity_id=p_actor_identity_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Download authorization is unavailable' USING ERRCODE = '40001';
  END IF;
  IF authz_record.status='revoked' AND authz_record.revision=p_expected_revision+1 THEN
    RETURN QUERY SELECT 'revoked'::text,authz_record.revision;
    RETURN;
  END IF;
  IF authz_record.status<>'active' OR authz_record.revision<>p_expected_revision THEN
    RAISE EXCEPTION 'Download authorization state or revision changed' USING ERRCODE = '40001';
  END IF;
  UPDATE public.tenant_export_download_authorizations
     SET status='revoked',revoked_at=clock_timestamp(),revision=revision+1
   WHERE id=p_authorization_id
   RETURNING status,revision INTO authz_record;
  RETURN QUERY SELECT authz_record.status,authz_record.revision;
END
$$;

CREATE FUNCTION schedule_platform_tenant_decommission(
  p_tenant_id uuid,
  p_expected_version integer,
  p_export_job_id uuid,
  p_retention_days integer,
  p_reason_code text,
  p_idempotency_key uuid,
  p_request_hash text,
  p_actor_identity_id uuid
)
RETURNS TABLE(
  decommission_id uuid,
  decommission_state text,
  tenant_version integer,
  retention_until timestamptz,
  sessions_revoked integer,
  reused boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  existing_request record;
  tenant_record record;
  created_request record;
  revoked_count integer;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.platform_role_bindings binding
     WHERE binding.identity_id=p_actor_identity_id AND binding.role_code='platform_admin'
  ) THEN
    RAISE EXCEPTION 'Platform tenant decommission permission is required' USING ERRCODE = '42501';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version < 1
     OR p_retention_days IS NULL OR p_retention_days NOT BETWEEN 7 AND 3650
     OR p_reason_code NOT IN ('institution_request','duplicate_tenant','service_ended','legal_retention')
     OR p_request_hash IS NULL OR p_request_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Tenant decommission request is invalid' USING ERRCODE = '23514';
  END IF;

  SELECT request.id,request.state,tenant.version,request.retention_until,
         request.schedule_request_hash,request.tenant_id,request.source_export_job_id
    INTO existing_request
    FROM public.tenant_decommission_requests request
    JOIN public.tenants tenant ON tenant.id=request.tenant_id
   WHERE request.schedule_idempotency_key=p_idempotency_key
   FOR UPDATE OF request,tenant;
  IF FOUND THEN
    IF existing_request.schedule_request_hash IS DISTINCT FROM p_request_hash
       OR existing_request.tenant_id IS DISTINCT FROM p_tenant_id
       OR existing_request.source_export_job_id IS DISTINCT FROM p_export_job_id THEN
      RAISE EXCEPTION 'Decommission idempotency key was reused with different input'
        USING ERRCODE = '23505';
    END IF;
    IF existing_request.state <> 'scheduled' THEN
      RAISE EXCEPTION 'Decommission schedule is no longer current'
        USING ERRCODE = '40001';
    END IF;
    RETURN QUERY SELECT existing_request.id,existing_request.state,existing_request.version,
      existing_request.retention_until,0,true;
    RETURN;
  END IF;

  SELECT tenant.status,tenant.version INTO tenant_record
    FROM public.tenants tenant
   WHERE tenant.id=p_tenant_id
     AND tenant.status IN ('active','suspended')
     AND tenant.version=p_expected_version
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tenant state or version changed' USING ERRCODE = '40001';
  END IF;
  PERFORM 1 FROM public.tenant_export_jobs job
   WHERE job.id=p_export_job_id
     AND job.tenant_id=p_tenant_id
     AND job.state='ready'
     AND job.tenant_version=p_expected_version
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'A ready export for the current tenant version is required' USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.tenant_decommission_requests(
    tenant_id,source_export_job_id,schedule_idempotency_key,schedule_request_hash,
    reason_code,previous_tenant_status,retention_until,scheduled_by_identity_id
  ) VALUES (
    p_tenant_id,p_export_job_id,p_idempotency_key,p_request_hash,p_reason_code,
    tenant_record.status,clock_timestamp()+(p_retention_days*interval '1 day'),p_actor_identity_id
  ) RETURNING id,state,tenant_decommission_requests.retention_until INTO created_request;

  UPDATE public.tenants
     SET status='decommission_pending',decommission_request_id=created_request.id,
         retention_until=created_request.retention_until,decommission_requested_at=clock_timestamp(),
         version=version+1,updated_at=clock_timestamp()
   WHERE id=p_tenant_id
   RETURNING version INTO tenant_record.version;
  UPDATE public.auth_sessions
     SET revoked_at=clock_timestamp(),revoke_reason='tenant_decommission_pending'
   WHERE active_tenant_id=p_tenant_id AND revoked_at IS NULL;
  GET DIAGNOSTICS revoked_count = ROW_COUNT;
  RETURN QUERY SELECT created_request.id,created_request.state,tenant_record.version,
    created_request.retention_until,revoked_count,false;
END
$$;

CREATE FUNCTION cancel_platform_tenant_decommission(
  p_tenant_id uuid,
  p_decommission_id uuid,
  p_expected_version integer,
  p_idempotency_key uuid,
  p_request_hash text,
  p_actor_identity_id uuid
)
RETURNS TABLE(
  decommission_id uuid,
  decommission_state text,
  tenant_status text,
  tenant_version integer,
  reused boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  request_record record;
  next_tenant_version integer;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.platform_role_bindings binding
     WHERE binding.identity_id=p_actor_identity_id AND binding.role_code='platform_admin'
  ) THEN
    RAISE EXCEPTION 'Platform tenant decommission cancellation permission is required' USING ERRCODE = '42501';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version < 1
     OR p_request_hash IS NULL OR p_request_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Tenant decommission cancellation is invalid' USING ERRCODE = '23514';
  END IF;

  SELECT request.id,request.tenant_id,request.state,request.previous_tenant_status,
         request.cancel_request_hash,request.cancel_idempotency_key,tenant.version
    INTO request_record
    FROM public.tenant_decommission_requests request
    JOIN public.tenants tenant ON tenant.id=request.tenant_id
   WHERE request.cancel_idempotency_key=p_idempotency_key
   FOR UPDATE OF request,tenant;
  IF FOUND THEN
    IF request_record.cancel_request_hash IS DISTINCT FROM p_request_hash
       OR request_record.id IS DISTINCT FROM p_decommission_id
       OR request_record.tenant_id IS DISTINCT FROM p_tenant_id THEN
      RAISE EXCEPTION 'Cancellation idempotency key was reused with different input'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT request_record.id,request_record.state,request_record.previous_tenant_status,
      request_record.version,true;
    RETURN;
  END IF;

  SELECT request.id,request.tenant_id,request.state,request.previous_tenant_status,
         request.retention_until,tenant.version
    INTO request_record
    FROM public.tenant_decommission_requests request
    JOIN public.tenants tenant ON tenant.id=request.tenant_id
   WHERE request.id=p_decommission_id
     AND request.tenant_id=p_tenant_id
     AND request.state='scheduled'
     AND request.retention_until>clock_timestamp()
     AND tenant.status='decommission_pending'
     AND tenant.decommission_request_id=request.id
     AND tenant.version=p_expected_version
   FOR UPDATE OF request,tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Decommission state, retention window, or tenant version changed'
      USING ERRCODE = '40001';
  END IF;

  UPDATE public.tenant_decommission_requests
     SET state='cancelled',cancel_idempotency_key=p_idempotency_key,
         cancel_request_hash=p_request_hash,cancelled_by_identity_id=p_actor_identity_id,
         cancelled_at=clock_timestamp(),version=version+1
   WHERE id=p_decommission_id;
  UPDATE public.tenants
     SET status=request_record.previous_tenant_status,decommission_request_id=NULL,
         retention_until=NULL,decommission_requested_at=NULL,version=version+1,
         updated_at=clock_timestamp()
   WHERE id=p_tenant_id
   RETURNING version INTO next_tenant_version;
  RETURN QUERY SELECT p_decommission_id,'cancelled'::text,request_record.previous_tenant_status,
    next_tenant_version,false;
END
$$;

REVOKE ALL ON FUNCTION queue_platform_tenant_export(uuid,integer,uuid,text,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION authorize_platform_tenant_export_download(uuid,uuid,uuid,timestamptz,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION consume_platform_tenant_export_download(uuid,uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_platform_tenant_export_download(uuid,integer,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION schedule_platform_tenant_decommission(uuid,integer,uuid,integer,text,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION cancel_platform_tenant_decommission(uuid,uuid,integer,uuid,text,uuid) FROM PUBLIC;
