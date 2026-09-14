CREATE TABLE tenant_reactivation_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  idempotency_key uuid NOT NULL UNIQUE,
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  expected_tenant_version integer NOT NULL CHECK (expected_tenant_version > 0),
  reason_code text NOT NULL CHECK (reason_code IN (
    'security_review_completed',
    'operational_hold_resolved',
    'institution_request_resumed',
    'compliance_review_completed'
  )),
  requested_by_identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL,
  resulting_tenant_version integer NOT NULL CHECK (resulting_tenant_version > expected_tenant_version),
  sessions_revoked integer NOT NULL CHECK (sessions_revoked >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON tenant_reactivation_requests FROM PUBLIC;

CREATE FUNCTION reactivate_platform_tenant(
  p_tenant_id uuid,
  p_expected_version integer,
  p_reason_code text,
  p_idempotency_key uuid,
  p_request_hash text,
  p_actor_identity_id uuid,
  p_request_id uuid
)
RETURNS TABLE(tenant_version integer, sessions_revoked integer, reused boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  existing_request record;
  next_version integer;
  revoked_count integer;
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM public.platform_role_bindings binding
     WHERE binding.identity_id=p_actor_identity_id
       AND binding.role_code IN ('platform_admin','platform_operator')
  ) THEN
    RAISE EXCEPTION 'Platform tenant reactivation permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_tenant_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
     OR p_reason_code IS NULL OR p_reason_code NOT IN (
       'security_review_completed',
       'operational_hold_resolved',
       'institution_request_resumed',
       'compliance_review_completed'
     )
     OR p_idempotency_key IS NULL
     OR p_request_hash IS NULL OR p_request_hash !~ '^[0-9a-f]{64}$'
     OR p_actor_identity_id IS NULL OR p_request_id IS NULL THEN
    RAISE EXCEPTION 'Tenant reactivation request is invalid' USING ERRCODE = '23514';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform-tenant-reactivation:' || p_idempotency_key::text,
    0
  ));
  SELECT request.tenant_id,request.expected_tenant_version,request.reason_code,
         request.request_hash,request.resulting_tenant_version,request.sessions_revoked
    INTO existing_request
    FROM public.tenant_reactivation_requests request
   WHERE request.idempotency_key=p_idempotency_key
   FOR UPDATE;
  IF FOUND THEN
    IF existing_request.request_hash IS DISTINCT FROM p_request_hash
       OR existing_request.tenant_id IS DISTINCT FROM p_tenant_id
       OR existing_request.expected_tenant_version IS DISTINCT FROM p_expected_version
       OR existing_request.reason_code IS DISTINCT FROM p_reason_code THEN
      RAISE EXCEPTION 'Tenant reactivation idempotency key was reused with different input'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_request.resulting_tenant_version,
      existing_request.sessions_revoked,true;
    RETURN;
  END IF;

  PERFORM 1
    FROM public.tenants tenant
   WHERE tenant.id=p_tenant_id
     AND tenant.status='suspended'
     AND tenant.version=p_expected_version
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tenant state or version changed' USING ERRCODE = '40001';
  END IF;

  UPDATE public.auth_sessions
     SET revoked_at=clock_timestamp(),revoke_reason='tenant_reactivated_login_required'
   WHERE active_tenant_id=p_tenant_id AND revoked_at IS NULL;
  GET DIAGNOSTICS revoked_count = ROW_COUNT;

  UPDATE public.tenants
     SET status='active',suspended_at=NULL,suspension_reason=NULL,
         version=version+1,updated_at=clock_timestamp()
   WHERE id=p_tenant_id
   RETURNING version INTO next_version;

  INSERT INTO public.tenant_reactivation_requests(
    tenant_id,idempotency_key,request_hash,expected_tenant_version,reason_code,
    requested_by_identity_id,request_id,resulting_tenant_version,sessions_revoked
  ) VALUES (
    p_tenant_id,p_idempotency_key,p_request_hash,p_expected_version,p_reason_code,
    p_actor_identity_id,p_request_id,next_version,revoked_count
  );
  RETURN QUERY SELECT next_version,revoked_count,false;
END
$$;

REVOKE ALL ON FUNCTION reactivate_platform_tenant(uuid,integer,text,uuid,text,uuid,uuid) FROM PUBLIC;

COMMENT ON TABLE tenant_reactivation_requests IS
  'Idempotent, non-sensitive evidence for reversible suspended-to-active transitions.';
COMMENT ON COLUMN tenant_reactivation_requests.reason_code IS
  'Closed administrative code only; human narrative and PII are forbidden.';
