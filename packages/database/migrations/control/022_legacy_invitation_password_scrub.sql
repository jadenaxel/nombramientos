-- Migration 019 could persist a user-selected password while the effective
-- tenant policy disabled password authentication. Migration 021 made future
-- provisioning explicit, but its conservative DEFAULT true retained the
-- credential semantics of every existing identity. Scrub only the historical
-- rows whose policy can be reconstructed without ambiguity.

ALTER TABLE platform_identities
  ADD COLUMN legacy_invitation_password_scrubbed_at timestamptz;

COMMENT ON COLUMN platform_identities.legacy_invitation_password_scrubbed_at IS
  'Set only when migration 022 destroyed a password captured by invitation migration 019 while password authentication was disabled.';

DO $$
DECLARE
  migration_019_applied_at timestamptz;
  migration_021_applied_at timestamptz;
  ambiguous_identity_count bigint;
  scrubbed_identity_count bigint;
  -- Argon2id hash generated once from 32 random bytes whose preimage was
  -- discarded before this migration was authored. The hash is a non-secret,
  -- deterministic disabled-credential sentinel; no plaintext exists to use.
  disabled_password_hash constant text :=
    '$argon2id$v=19$m=65536,t=3,p=1$BlX3TtC3KRRD8kjGx9PwxQ$BRboo0FP4y3RHcgkaHeHuBjXcmcJayVDIp/Qp4qMCIY';
BEGIN
  SELECT applied_at INTO migration_019_applied_at
    FROM schema_migrations
   WHERE name = '019_invitation_passwordless_enrollment.sql';
  SELECT applied_at INTO migration_021_applied_at
    FROM schema_migrations
   WHERE name = '021_explicit_password_provisioning.sql';

  IF migration_019_applied_at IS NULL
     OR migration_021_applied_at IS NULL
     OR migration_021_applied_at <= migration_019_applied_at THEN
    RAISE EXCEPTION 'Invitation password remediation migration boundaries are unavailable'
      USING ERRCODE = '23514', CONSTRAINT = 'legacy_invitation_password_migration_window';
  END IF;

  -- The policy table is current-state, not temporal history. A current
  -- override whose last update is at/before acceptance proves its value at
  -- acceptance. A missing override or a later update cannot prove the old
  -- value, so stop the entire migration instead of guessing or disabling a
  -- legitimate credential.
  SELECT count(*) INTO ambiguous_identity_count
    FROM tenant_invitations invitation
    JOIN platform_identities identity
      ON identity.id = invitation.acceptance_identity_id
    LEFT JOIN tenant_identity_policies policy
      ON policy.tenant_id = invitation.tenant_id
   WHERE invitation.status = 'accepted'
     AND invitation.accepted_at >= migration_019_applied_at
     AND invitation.accepted_at < migration_021_applied_at
     AND identity.password_provisioned
     AND (
       policy.tenant_id IS NULL
       OR policy.updated_at > invitation.accepted_at
     );
  IF ambiguous_identity_count <> 0 THEN
    RAISE EXCEPTION 'Cannot prove historical password policy for % invitation identity/identities',
      ambiguous_identity_count
      USING ERRCODE = '23514', CONSTRAINT = 'legacy_invitation_password_policy_ambiguous';
  END IF;

  UPDATE platform_identities identity
     SET password_hash = disabled_password_hash,
         password_provisioned = false,
         legacy_invitation_password_scrubbed_at = clock_timestamp(),
         updated_at = clock_timestamp()
    FROM tenant_invitations invitation
    JOIN tenant_identity_policies policy
      ON policy.tenant_id = invitation.tenant_id
   WHERE invitation.acceptance_identity_id = identity.id
     AND invitation.status = 'accepted'
     AND invitation.accepted_at >= migration_019_applied_at
     AND invitation.accepted_at < migration_021_applied_at
     AND policy.updated_at <= invitation.accepted_at
     AND NOT policy.allow_password
     AND identity.password_provisioned;
  GET DIAGNOSTICS scrubbed_identity_count = ROW_COUNT;

  -- Password, TOTP and recovery-code sessions all originate in a password
  -- challenge. Invitation bootstrap sessions are restricted but are revoked as
  -- well so no pre-remediation browser credential remains. Independent passkey
  -- and federated sessions remain valid.
  UPDATE auth_sessions session
     SET revoked_at = COALESCE(session.revoked_at, clock_timestamp()),
         revoke_reason = COALESCE(session.revoke_reason, 'legacy_invitation_password_scrubbed')
    FROM platform_identities identity
   WHERE identity.id = session.identity_id
     AND identity.legacy_invitation_password_scrubbed_at IS NOT NULL
     AND identity.password_hash = disabled_password_hash
     AND session.revoked_at IS NULL
     AND session.auth_method IN ('password', 'totp', 'recovery_code', 'bootstrap');

  UPDATE mfa_challenges challenge
     SET consumed_at = COALESCE(challenge.consumed_at, clock_timestamp())
    FROM platform_identities identity
   WHERE identity.id = challenge.identity_id
     AND identity.legacy_invitation_password_scrubbed_at IS NOT NULL
     AND identity.password_hash = disabled_password_hash
     AND challenge.consumed_at IS NULL;

  UPDATE authentication_step_up_grants step_up_grant
     SET revoked_at = COALESCE(step_up_grant.revoked_at, clock_timestamp())
    FROM auth_sessions session
    JOIN platform_identities identity
      ON identity.id = session.identity_id
   WHERE step_up_grant.session_id = session.id
     AND identity.legacy_invitation_password_scrubbed_at IS NOT NULL
     AND identity.password_hash = disabled_password_hash
     AND session.auth_method IN ('password', 'totp', 'recovery_code', 'bootstrap')
     AND step_up_grant.consumed_at IS NULL
     AND step_up_grant.revoked_at IS NULL;

  RAISE NOTICE 'Scrubbed % legacy invitation password credential(s)', scrubbed_identity_count;
END
$$;

REVOKE UPDATE(legacy_invitation_password_scrubbed_at) ON platform_identities FROM PUBLIC;
