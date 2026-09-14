-- PostgreSQL treats RETURNS TABLE column names as PL/pgSQL variables.  The
-- 024 implementation used an unqualified identity_id inside the auth_sessions
-- UPDATE, so the recovery function failed closed with SQLSTATE 42702 when an
-- accepted invitation attempted to rotate its enrollment-only session.  Keep
-- the security boundary and every predicate unchanged while making the target
-- relation explicit.
CREATE OR REPLACE FUNCTION recover_tenant_invitation_enrollment_session(
  p_invitation_id uuid,
  p_token text,
  p_recovery_proof text,
  p_normalized_email text,
  p_session_id uuid,
  p_session_token_hash text,
  p_csrf_hash text,
  p_session_expires_at timestamptz,
  p_user_agent_hash text,
  p_ip_prefix_hash text
)
RETURNS TABLE(recovered boolean,identity_id uuid,tenant_id uuid,session_expires_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  invitation_record record;
  issued_expires_at timestamptz;
BEGIN
  IF p_invitation_id IS NULL OR p_token !~ '^[A-Za-z0-9_-]{43}$'
     OR p_recovery_proof !~ '^[A-Za-z0-9_-]{43}$'
     OR p_session_id IS NULL OR p_session_token_hash !~ '^[0-9a-f]{64}$'
     OR p_csrf_hash !~ '^[0-9a-f]{64}$' OR p_session_expires_at <= clock_timestamp()
     OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^[0-9a-f]{64}$')
     OR (p_ip_prefix_hash IS NOT NULL AND p_ip_prefix_hash !~ '^[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'Invitation enrollment recovery input is invalid' USING ERRCODE = '23514';
  END IF;
  SELECT invitation.acceptance_identity_id AS identity_id,
         invitation.tenant_id,invitation.accepted_at
    INTO invitation_record
    FROM public.tenant_invitations invitation
    JOIN public.platform_identities identity ON identity.id=invitation.acceptance_identity_id
    JOIN public.tenant_memberships membership
      ON membership.identity_id=identity.id AND membership.tenant_id=invitation.tenant_id
    JOIN public.tenants tenant ON tenant.id=membership.tenant_id
   WHERE invitation.id=p_invitation_id
     AND invitation.token_hash=encode(sha256(convert_to(p_token,'UTF8')),'hex')
     AND invitation.acceptance_recovery_hash=
         encode(sha256(convert_to(p_recovery_proof,'UTF8')),'hex')
     AND invitation.normalized_email=p_normalized_email
     AND invitation.status='accepted'
     AND invitation.accepted_at>clock_timestamp()-interval '24 hours'
     AND identity.status='active'
     AND identity.mfa_enabled=false
     AND identity.passkey_enabled=false
     AND membership.status='active'
     AND tenant.status='active'
     AND NOT EXISTS (
       SELECT 1 FROM public.webauthn_credentials credential
        WHERE credential.identity_id=identity.id AND credential.revoked_at IS NULL
     )
   FOR UPDATE OF invitation,identity,membership,tenant;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::timestamptz;
    RETURN;
  END IF;
  issued_expires_at := LEAST(
    p_session_expires_at,
    invitation_record.accepted_at + interval '24 hours',
    clock_timestamp() + interval '10 minutes'
  );
  IF issued_expires_at <= clock_timestamp() THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::timestamptz;
    RETURN;
  END IF;
  UPDATE public.auth_sessions session
     SET revoked_at=clock_timestamp(),revoke_reason='invitation_enrollment_rotated'
   WHERE session.invitation_id=p_invitation_id
     AND session.identity_id=invitation_record.identity_id
     AND session.enrollment_source='invitation'
     AND session.revoked_at IS NULL;
  INSERT INTO public.auth_sessions(
    id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
    user_agent_hash,ip_prefix_hash,assurance_level,mfa_verified_at,
    auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,
    idle_timeout_minutes,idle_expires_at,last_user_agent_hash,last_ip_prefix_hash,
    enrollment_source,invitation_id
  ) VALUES (
    p_session_id,p_session_token_hash,p_csrf_hash,invitation_record.identity_id,
    invitation_record.tenant_id,issued_expires_at,p_user_agent_hash,p_ip_prefix_hash,
    'enrollment_only',NULL,'bootstrap',1,false,NULL,false,10,issued_expires_at,
    p_user_agent_hash,p_ip_prefix_hash,'invitation',p_invitation_id
  );
  RETURN QUERY SELECT true,invitation_record.identity_id,invitation_record.tenant_id,issued_expires_at;
END
$$;

-- CREATE OR REPLACE retains the existing owner and runtime EXECUTE ACL.  Keep
-- the public surface closed explicitly for both upgraded and fresh databases.
REVOKE ALL ON FUNCTION recover_tenant_invitation_enrollment_session(
  uuid,text,text,text,uuid,text,text,timestamptz,text,text
) FROM PUBLIC;
