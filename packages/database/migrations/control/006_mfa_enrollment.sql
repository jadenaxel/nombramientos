ALTER TABLE platform_identities
  ADD COLUMN mfa_required boolean NOT NULL DEFAULT false,
  ADD COLUMN mfa_enrollment_id uuid,
  ADD COLUMN mfa_enrollment_secret_ciphertext text,
  ADD COLUMN mfa_enrollment_started_at timestamptz,
  ADD COLUMN mfa_enrolled_at timestamptz,
  ADD COLUMN mfa_recovery_generation integer NOT NULL DEFAULT 0 CHECK (mfa_recovery_generation >= 0),
  ADD COLUMN mfa_last_used_step bigint;

ALTER TABLE platform_identities
  ADD CONSTRAINT platform_identity_mfa_enrollment_complete_tuple CHECK (
    (mfa_enrollment_id IS NULL
      AND mfa_enrollment_secret_ciphertext IS NULL
      AND mfa_enrollment_started_at IS NULL)
    OR
    (mfa_enrollment_id IS NOT NULL
      AND mfa_enrollment_secret_ciphertext IS NOT NULL
      AND mfa_enrollment_started_at IS NOT NULL)
  );

UPDATE platform_identities
   SET mfa_enrolled_at = COALESCE(mfa_enrolled_at, updated_at, created_at)
 WHERE mfa_enabled;

ALTER TABLE platform_identities
  ADD CONSTRAINT platform_identity_mfa_enrolled_at_consistent CHECK (
    NOT mfa_enabled OR mfa_enrolled_at IS NOT NULL
  );

UPDATE platform_identities identity
   SET mfa_required = true,
       updated_at = clock_timestamp()
 WHERE EXISTS (
   SELECT 1
     FROM platform_role_bindings binding
    WHERE binding.identity_id = identity.id
      AND binding.role_code = 'platform_admin'
 );

UPDATE platform_identities identity
   SET mfa_required = true,
       updated_at = clock_timestamp()
 WHERE EXISTS (
   SELECT 1
     FROM tenant_invitations invitation
    WHERE invitation.acceptance_identity_id = identity.id
      AND invitation.status = 'accepted'
      AND invitation.role_codes && ARRAY[
        'CHURCH_ADMIN', 'COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY', 'TALLY_CUSTODIAN'
      ]::text[]
 );

ALTER TABLE auth_sessions
  ADD COLUMN assurance_level text NOT NULL DEFAULT 'password'
    CHECK (assurance_level IN ('enrollment_only', 'password', 'mfa')),
  ADD COLUMN authenticated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ADD COLUMN mfa_verified_at timestamptz;

ALTER TABLE auth_sessions
  ADD CONSTRAINT auth_session_mfa_assurance_consistent CHECK (
    (assurance_level = 'mfa' AND mfa_verified_at IS NOT NULL)
    OR (assurance_level <> 'mfa' AND mfa_verified_at IS NULL)
  );

-- Pre-migration sessions cannot prove their assurance. Revoke every session
-- belonging to an MFA-enabled or MFA-required identity instead of upgrading it.
UPDATE auth_sessions session
   SET revoked_at = clock_timestamp(),
       revoke_reason = 'mfa_assurance_migration'
  FROM platform_identities identity
 WHERE session.identity_id = identity.id
   AND session.revoked_at IS NULL
   AND (identity.mfa_enabled OR identity.mfa_required);

CREATE TABLE mfa_recovery_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE CASCADE,
  generation integer NOT NULL CHECK (generation > 0),
  code_hash text NOT NULL CHECK (starts_with(code_hash, '$argon2id$')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  consumed_at timestamptz,
  revoked_at timestamptz,
  CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX mfa_recovery_codes_active_identity
ON mfa_recovery_codes(identity_id, generation)
WHERE consumed_at IS NULL AND revoked_at IS NULL;

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
  invitation_requires_mfa boolean;
BEGIN
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
