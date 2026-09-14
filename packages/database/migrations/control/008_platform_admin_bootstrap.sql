CREATE TABLE platform_admin_bootstrap_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  purpose text NOT NULL DEFAULT 'bootstrap' CHECK (purpose IN ('bootstrap', 'recovery')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'consumed', 'expired', 'revoked')),
  anchor_tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  recovery_reason text CHECK (
    (purpose = 'bootstrap' AND recovery_reason IS NULL)
    OR (purpose = 'recovery' AND length(btrim(recovery_reason)) BETWEEN 8 AND 240)
  ),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_by_identity_id uuid REFERENCES platform_identities(id) ON DELETE RESTRICT,
  consumed_session_id uuid REFERENCES auth_sessions(id) ON DELETE SET NULL,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK (expires_at > created_at),
  CHECK (
    status <> 'consumed'
    OR (consumed_at IS NOT NULL AND consumed_by_identity_id IS NOT NULL AND consumed_session_id IS NOT NULL)
  )
);

CREATE UNIQUE INDEX platform_admin_bootstrap_one_pending
ON platform_admin_bootstrap_tokens ((true))
WHERE status = 'pending';

CREATE INDEX platform_admin_bootstrap_expiry
ON platform_admin_bootstrap_tokens (expires_at)
WHERE status = 'pending';

REVOKE ALL ON platform_admin_bootstrap_tokens FROM PUBLIC;

CREATE FUNCTION consume_platform_admin_bootstrap(
  p_token_hash text,
  p_email text,
  p_normalized_email text,
  p_display_name text,
  p_password_hash text,
  p_identity_id uuid,
  p_session_id uuid,
  p_session_token_hash text,
  p_csrf_hash text,
  p_session_expires_at timestamptz,
  p_user_agent_hash text,
  p_ip_prefix_hash text
)
RETURNS TABLE(created_identity_id uuid, created_session_id uuid, anchor_tenant_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  bootstrap_record record;
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$'
     OR p_email IS NULL OR length(btrim(p_email)) NOT BETWEEN 3 AND 320
     OR p_normalized_email IS NULL
     OR p_normalized_email IS DISTINCT FROM lower(btrim(p_email))
     OR p_display_name IS NULL OR length(btrim(p_display_name)) NOT BETWEEN 2 AND 120
     OR p_password_hash IS NULL OR NOT starts_with(p_password_hash, '$argon2id$')
     OR p_session_token_hash IS NULL OR p_session_token_hash !~ '^[0-9a-f]{64}$'
     OR p_csrf_hash IS NULL OR p_csrf_hash !~ '^[0-9a-f]{64}$'
     OR p_session_expires_at IS NULL OR p_session_expires_at <= clock_timestamp()
     OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^[0-9a-f]{64}$')
     OR (p_ip_prefix_hash IS NOT NULL AND p_ip_prefix_hash !~ '^[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'Platform administrator bootstrap input is invalid'
      USING ERRCODE = '23514';
  END IF;

  SELECT bootstrap.id, bootstrap.purpose, bootstrap.anchor_tenant_id, bootstrap.expires_at
    INTO bootstrap_record
    FROM public.platform_admin_bootstrap_tokens bootstrap
   WHERE bootstrap.token_hash = p_token_hash
     AND bootstrap.status = 'pending'
   FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF bootstrap_record.expires_at <= clock_timestamp() THEN
    UPDATE public.platform_admin_bootstrap_tokens
       SET status='expired',version=version+1
     WHERE id=bootstrap_record.id;
    RETURN;
  END IF;

  IF bootstrap_record.purpose = 'bootstrap' AND EXISTS (
    SELECT 1
      FROM public.platform_role_bindings binding
      JOIN public.platform_identities identity ON identity.id=binding.identity_id
     WHERE binding.role_code='platform_admin' AND identity.status='active'
  ) THEN
    UPDATE public.platform_admin_bootstrap_tokens
       SET status='revoked',version=version+1
     WHERE id=bootstrap_record.id;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.platform_identities identity
     WHERE identity.normalized_email=p_normalized_email
  ) THEN
    RETURN;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenants tenant
     WHERE tenant.id=bootstrap_record.anchor_tenant_id AND tenant.status='active'
  ) THEN
    RETURN;
  END IF;

  INSERT INTO public.platform_identities(
    id,email,normalized_email,display_name,password_hash,mfa_enabled,mfa_required,status
  ) VALUES (
    p_identity_id,btrim(p_email),p_normalized_email,btrim(p_display_name),p_password_hash,false,true,'active'
  );
  -- The active demo tenant is an authentication anchor only. This bootstrap
  -- creates no tenant role binding and no device-key grant, so the global
  -- identity receives neither tenant permissions nor decryptable content.
  INSERT INTO public.tenant_memberships(tenant_id,identity_id,status,is_default)
  VALUES (bootstrap_record.anchor_tenant_id,p_identity_id,'active',true);
  INSERT INTO public.platform_role_bindings(identity_id,role_code)
  VALUES (p_identity_id,'platform_admin');
  INSERT INTO public.auth_sessions(
    id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
    user_agent_hash,ip_prefix_hash,assurance_level,mfa_verified_at
  ) VALUES (
    p_session_id,p_session_token_hash,p_csrf_hash,p_identity_id,bootstrap_record.anchor_tenant_id,
    p_session_expires_at,p_user_agent_hash,p_ip_prefix_hash,'enrollment_only',NULL
  );
  UPDATE public.platform_admin_bootstrap_tokens
     SET status='consumed',consumed_at=clock_timestamp(),consumed_by_identity_id=p_identity_id,
         consumed_session_id=p_session_id,version=version+1
   WHERE id=bootstrap_record.id;

  RETURN QUERY SELECT p_identity_id,p_session_id,bootstrap_record.anchor_tenant_id;
END
$$;

REVOKE ALL ON FUNCTION consume_platform_admin_bootstrap(text,text,text,text,text,uuid,uuid,text,text,timestamptz,text,text) FROM PUBLIC;
