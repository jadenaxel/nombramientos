-- A passwordless invitation is authenticated by its one-time invitation
-- bearer, not by the password hash persisted for compatibility.  Bind the
-- resulting short enrollment session to the consumed invitation so policy
-- reconciliation can preserve only this narrow passkey-onboarding escape.

ALTER TABLE auth_sessions
  ADD COLUMN enrollment_source text,
  ADD COLUMN invitation_id uuid REFERENCES tenant_invitations(id) ON DELETE RESTRICT,
  ADD CONSTRAINT auth_session_enrollment_source_consistent CHECK (
    (enrollment_source IS NULL AND invitation_id IS NULL)
    OR (
      enrollment_source = 'invitation'
      AND invitation_id IS NOT NULL
      AND assurance_level = 'enrollment_only'
      AND auth_method = 'bootstrap'
      AND aal = 1
      AND NOT phishing_resistant
      AND NOT recovery_limited
      AND authenticated_credential_id IS NULL
      AND mfa_verified_at IS NULL
      AND idle_timeout_minutes <= 10
      AND idle_expires_at <= expires_at
      AND expires_at <= created_at + interval '10 minutes'
    )
  );

-- The runtime role receives INSERT only on the ordinary session columns in
-- migrate-control.ts, deliberately excluding enrollment_source and
-- invitation_id.  Only this SECURITY DEFINER function can mint the exception.
CREATE FUNCTION guard_invitation_enrollment_session_source()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.enrollment_source = 'invitation' AND NOT EXISTS (
    SELECT 1
      FROM public.tenant_invitations invitation
     WHERE invitation.id=NEW.invitation_id
       AND invitation.tenant_id=NEW.active_tenant_id
       AND invitation.acceptance_identity_id=NEW.identity_id
       AND invitation.status='accepted'
       AND invitation.consumed_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Invitation enrollment session must bind to its accepted invitation'
      USING ERRCODE = '23514', CONSTRAINT = 'auth_sessions_invitation_enrollment_source_guard';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER auth_sessions_invitation_enrollment_source_guard
BEFORE INSERT OR UPDATE OF enrollment_source,invitation_id,identity_id,active_tenant_id ON auth_sessions
FOR EACH ROW EXECUTE FUNCTION guard_invitation_enrollment_session_source();

CREATE OR REPLACE FUNCTION complete_tenant_invitation_acceptance(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_identity_id uuid,
  p_tenant_id uuid,
  p_normalized_email text,
  p_display_name text,
  p_password_hash text,
  p_session_id uuid,
  p_session_token_hash text,
  p_csrf_hash text,
  p_session_expires_at timestamptz,
  p_user_agent_hash text,
  p_ip_prefix_hash text
)
RETURNS TABLE(completed boolean, session_expires_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  invitation_record record;
  policy_record record;
  invitation_requires_mfa boolean;
  issued_session_expires_at timestamptz;
BEGIN
  IF p_session_id IS NULL
     OR p_session_token_hash IS NULL OR p_session_token_hash !~ '^[0-9a-f]{64}$'
     OR p_csrf_hash IS NULL OR p_csrf_hash !~ '^[0-9a-f]{64}$'
     OR p_session_expires_at IS NULL OR p_session_expires_at <= clock_timestamp()
     OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^[0-9a-f]{64}$')
     OR (p_ip_prefix_hash IS NOT NULL AND p_ip_prefix_hash !~ '^[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'Invitation enrollment session input is invalid'
      USING ERRCODE = '23514';
  END IF;

  -- Lock before the invitation row so direct callers share the same lock
  -- order as InvitationStore.complete and policy activation.
  PERFORM pg_advisory_xact_lock(
    hashtextextended('tenant_identity_policy:' || p_tenant_id::text,0)
  );
  SELECT invitation.id,
         invitation.email,
         invitation.normalized_email,
         invitation.expires_at,
         invitation.role_codes
    INTO invitation_record
    FROM public.tenant_invitations invitation
    JOIN public.tenants tenant
      ON tenant.id=invitation.tenant_id
     AND tenant.status='active'
   WHERE invitation.id=p_invitation_id
     AND invitation.acceptance_id=p_acceptance_id
     AND invitation.acceptance_identity_id=p_identity_id
     AND invitation.tenant_id=p_tenant_id
     AND invitation.normalized_email=p_normalized_email
     AND invitation.status='accepting'
   FOR UPDATE OF invitation;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,NULL::timestamptz;
    RETURN;
  END IF;
  IF invitation_record.expires_at <= clock_timestamp() THEN
    UPDATE public.tenant_invitations
       SET status='expired',updated_at=clock_timestamp(),version=version+1
     WHERE id=p_invitation_id;
    RETURN QUERY SELECT false,NULL::timestamptz;
    RETURN;
  END IF;
  IF NOT starts_with(p_password_hash, '$argon2id$')
     OR length(p_display_name) NOT BETWEEN 2 AND 120 THEN
    RAISE EXCEPTION 'Invitation identity attributes are invalid'
      USING ERRCODE = '23514';
  END IF;

  SELECT COALESCE(policy.enforcement_mode,baseline.enforcement_mode) AS enforcement_mode,
         COALESCE(policy.absolute_session_minutes,baseline.absolute_session_minutes) AS absolute_session_minutes
    INTO policy_record
    FROM public.tenants tenant
    CROSS JOIN public.identity_policy_baseline baseline
    LEFT JOIN public.tenant_identity_policies policy ON policy.tenant_id=tenant.id
   WHERE tenant.id=p_tenant_id
     AND tenant.status='active'
     AND baseline.policy_key='global';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Invitation identity policy is unavailable'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_identity_policy_readiness';
  END IF;

  -- The function, not the caller, caps the invitation-bound session. It is
  -- sufficient only to enroll a first passkey and never normal authorization.
  issued_session_expires_at := LEAST(
    p_session_expires_at,
    clock_timestamp() + interval '10 minutes',
    clock_timestamp() + make_interval(mins => policy_record.absolute_session_minutes)
  );
  IF issued_session_expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'Invitation enrollment session expiry is invalid'
      USING ERRCODE = '23514';
  END IF;

  invitation_requires_mfa := invitation_record.role_codes && ARRAY[
    'CHURCH_ADMIN', 'COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY', 'TALLY_CUSTODIAN'
  ]::text[];
  INSERT INTO public.platform_identities(
    id,email,normalized_email,display_name,password_hash,mfa_enabled,mfa_required,status
  ) VALUES (
    p_identity_id,invitation_record.email,invitation_record.normalized_email,
    p_display_name,p_password_hash,false,invitation_requires_mfa,'active'
  );
  INSERT INTO public.tenant_memberships(tenant_id,identity_id,status,is_default)
  VALUES (p_tenant_id,p_identity_id,'active',true);
  UPDATE public.tenant_invitations
     SET status='accepted',accepted_at=clock_timestamp(),consumed_at=clock_timestamp(),
         updated_at=clock_timestamp(),version=version+1
   WHERE id=p_invitation_id;
  INSERT INTO public.auth_sessions(
    id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
    user_agent_hash,ip_prefix_hash,assurance_level,mfa_verified_at,
    auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,
    idle_timeout_minutes,idle_expires_at,last_user_agent_hash,last_ip_prefix_hash,
    enrollment_source,invitation_id
  ) VALUES (
    p_session_id,p_session_token_hash,p_csrf_hash,p_identity_id,p_tenant_id,issued_session_expires_at,
    p_user_agent_hash,p_ip_prefix_hash,'enrollment_only',NULL,
    'bootstrap',1,false,NULL,false,
    10,LEAST(issued_session_expires_at,clock_timestamp()+interval '10 minutes'),p_user_agent_hash,p_ip_prefix_hash,
    'invitation',p_invitation_id
  );
  RETURN QUERY SELECT true,issued_session_expires_at;
END
$$;

REVOKE ALL ON FUNCTION guard_invitation_enrollment_session_source() FROM PUBLIC;
REVOKE ALL ON FUNCTION complete_tenant_invitation_acceptance(
  uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text
) FROM PUBLIC;
