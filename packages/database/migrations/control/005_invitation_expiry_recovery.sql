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
BEGIN
  SELECT invitation.id,
         invitation.email,
         invitation.normalized_email,
         invitation.expires_at
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
    -- Keep the claim identifiers until tenant-side compensation succeeds. If
    -- cleanup fails, the control row can move to failed and a manager can
    -- revoke it to retry cleanup without granting active access.
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

  INSERT INTO public.platform_identities(
    id,email,normalized_email,display_name,password_hash,mfa_enabled,status
  ) VALUES (
    p_identity_id,invitation_record.email,invitation_record.normalized_email,
    p_display_name,p_password_hash,false,'active'
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
