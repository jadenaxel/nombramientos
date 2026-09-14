-- Invitation acceptance creates an active password identity.  It must share
-- the tenant policy activation serialization so it cannot invalidate an
-- enforce-mode readiness decision after that decision has locked its members.

CREATE OR REPLACE FUNCTION complete_tenant_invitation_acceptance(
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_identity_id uuid,
  p_tenant_id uuid,
  p_normalized_email text,
  p_display_name text,
  p_password_hash text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  invitation_record record;
  policy_record record;
  invitation_requires_mfa boolean;
BEGIN
  -- Take the tenant policy key before the invitation row. This ordering is
  -- shared by InvitationStore.complete and avoids a direct-function caller
  -- deadlocking against a policy-serialized completion.
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
    RETURN false;
  END IF;
  IF invitation_record.expires_at <= clock_timestamp() THEN
    UPDATE public.tenant_invitations
       SET status='expired',updated_at=clock_timestamp(),version=version+1
     WHERE id=p_invitation_id;
    RETURN false;
  END IF;
  IF NOT starts_with(p_password_hash, '$argon2id$')
     OR length(p_display_name) NOT BETWEEN 2 AND 120 THEN
    RAISE EXCEPTION 'Invitation identity attributes are invalid'
      USING ERRCODE = '23514';
  END IF;

  SELECT COALESCE(policy.enforcement_mode,baseline.enforcement_mode) AS enforcement_mode,
         COALESCE(policy.allow_password,baseline.allow_password) AS allow_password,
         COALESCE(policy.minimum_passkey_count,baseline.minimum_passkey_count) AS minimum_passkey_count
    INTO policy_record
    FROM public.tenants tenant
    CROSS JOIN public.identity_policy_baseline baseline
    LEFT JOIN public.tenant_identity_policies policy ON policy.tenant_id=tenant.id
   WHERE tenant.id=p_tenant_id
     AND tenant.status='active'
     AND baseline.policy_key='global';
  IF NOT FOUND
     OR NOT policy_record.allow_password
     OR (policy_record.enforcement_mode='enforce' AND policy_record.minimum_passkey_count > 0) THEN
    RAISE EXCEPTION 'Invitation acceptance would create an active identity without a usable authentication path'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_invitation_identity_policy_readiness';
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
  RETURN true;
END
$$;

REVOKE ALL ON FUNCTION complete_tenant_invitation_acceptance(uuid, uuid, uuid, uuid, text, text, text) FROM PUBLIC;
