-- A registration ceremony may replace one active passkey without creating a
-- destructive gap. The selected credential is bound to the server-side
-- ceremony; completion revalidates ownership and performs revoke+insert in one
-- transaction. A failed registration therefore leaves the old credential
-- active and usable.

ALTER TABLE webauthn_ceremonies
  ADD COLUMN replacement_credential_id uuid
    REFERENCES webauthn_credentials(id) ON DELETE SET NULL,
  ADD CONSTRAINT webauthn_ceremony_replacement_registration_only CHECK (
    replacement_credential_id IS NULL OR ceremony_type = 'registration'
  );

CREATE INDEX webauthn_ceremonies_active_replacement
ON webauthn_ceremonies(replacement_credential_id, expires_at)
WHERE replacement_credential_id IS NOT NULL
  AND consumed_at IS NULL
  AND failed_at IS NULL;

-- WebAuthn credential backup eligibility is an immutable authenticator
-- property. Multi-device credentials are backup eligible; single-device
-- credentials are not. Validate all existing rows before accepting the floor.
ALTER TABLE webauthn_credentials
  ADD CONSTRAINT webauthn_credential_device_backup_consistent CHECK (
    (device_type = 'multiDevice') = backup_eligible
  );

REVOKE ALL ON TABLE webauthn_ceremonies FROM PUBLIC;
REVOKE ALL ON TABLE webauthn_credentials FROM PUBLIC;
