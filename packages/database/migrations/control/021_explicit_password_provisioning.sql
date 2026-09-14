-- Passwordless invitation onboarding must never turn an arbitrary compatibility
-- hash into a usable password when a tenant later enables password login.
-- Existing identities predate the explicit marker and therefore retain their
-- current, intentionally provisioned password semantics.
ALTER TABLE platform_identities
  ADD COLUMN password_provisioned boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN platform_identities.password_provisioned IS
  'True only when password_hash was deliberately provisioned as an authentication credential.';

-- Migration 019 exposed this overload before password provisioning was an
-- explicit database invariant. Remove it so no previously granted runtime role
-- can bypass the policy decision and the password_provisioned marker.
DROP FUNCTION complete_tenant_invitation_acceptance(
  uuid,uuid,uuid,uuid,text,text,text
);

DROP FUNCTION complete_tenant_invitation_acceptance(
  uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text
);

CREATE FUNCTION complete_tenant_invitation_acceptance(
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
  p_ip_prefix_hash text,
  p_disabled_password_hash text
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
  selected_password_hash text;
  selected_password_provisioned boolean;
BEGIN
  IF p_session_id IS NULL
     OR p_session_token_hash IS NULL OR p_session_token_hash !~ '^[0-9a-f]{64}$'
     OR p_csrf_hash IS NULL OR p_csrf_hash !~ '^[0-9a-f]{64}$'
     OR p_session_expires_at IS NULL OR p_session_expires_at <= clock_timestamp()
     OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^[0-9a-f]{64}$')
     OR (p_ip_prefix_hash IS NOT NULL AND p_ip_prefix_hash !~ '^[0-9a-f]{64}$')
     OR p_disabled_password_hash IS NULL
     OR NOT starts_with(p_disabled_password_hash, '$argon2id$') THEN
    RAISE EXCEPTION 'Invitation enrollment session input is invalid'
      USING ERRCODE = '23514';
  END IF;

  -- Keep policy activation and membership creation in the same serialization
  -- order. The policy is read only after this lock, so the password decision
  -- cannot race an allow_password transition.
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
  IF length(p_display_name) NOT BETWEEN 2 AND 120
     OR (p_password_hash IS NOT NULL AND NOT starts_with(p_password_hash, '$argon2id$')) THEN
    RAISE EXCEPTION 'Invitation identity attributes are invalid'
      USING ERRCODE = '23514';
  END IF;

  SELECT COALESCE(policy.enforcement_mode,baseline.enforcement_mode) AS enforcement_mode,
         COALESCE(policy.allow_password,baseline.allow_password) AS allow_password,
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

  -- The database owns this decision. A missing required password is retryable:
  -- raise before identity, membership, invitation or session mutation.
  IF policy_record.allow_password AND p_password_hash IS NULL THEN
    RAISE EXCEPTION 'A password is required by the current invitation policy'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_password_required';
  END IF;
  selected_password_provisioned := policy_record.allow_password;
  selected_password_hash := CASE
    WHEN selected_password_provisioned THEN p_password_hash
    ELSE p_disabled_password_hash
  END;

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
    id,email,normalized_email,display_name,password_hash,password_provisioned,
    mfa_enabled,mfa_required,status
  ) VALUES (
    p_identity_id,invitation_record.email,invitation_record.normalized_email,
    p_display_name,selected_password_hash,selected_password_provisioned,
    false,invitation_requires_mfa,'active'
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

REVOKE ALL ON FUNCTION complete_tenant_invitation_acceptance(
  uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text
) FROM PUBLIC;
