ALTER TABLE report_versions
  DROP CONSTRAINT IF EXISTS report_versions_state_check;

ALTER TABLE report_versions
  ADD CONSTRAINT report_versions_state_check
    CHECK (state IN ('queued', 'pending', 'ready', 'failed', 'expired')),
  ADD COLUMN artifact_manifest jsonb,
  ADD COLUMN plaintext_bytes bigint CHECK (plaintext_bytes IS NULL OR plaintext_bytes BETWEEN 1 AND 20971520),
  ADD COLUMN ciphertext_sha256 text CHECK (ciphertext_sha256 IS NULL OR ciphertext_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN failed_at timestamptz,
  ADD COLUMN error_code text CHECK (error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0);

UPDATE report_versions
   SET state='failed',ready_at=NULL,failed_at=clock_timestamp(),error_code='LEGACY_ARTIFACT_MISSING'
 WHERE state='ready'
   AND (artifact_envelope IS NULL OR artifact_bytes IS NOT NULL OR artifact_sha256 IS NULL OR ciphertext_sha256 IS NULL
     OR artifact_manifest IS NULL OR plaintext_bytes IS NULL);

ALTER TABLE report_versions
  ADD CONSTRAINT report_versions_lifecycle_check CHECK (
    (state = 'ready' AND artifact_envelope IS NOT NULL AND artifact_bytes IS NULL AND artifact_sha256 IS NOT NULL
      AND ciphertext_sha256 IS NOT NULL
      AND artifact_manifest IS NOT NULL AND plaintext_bytes IS NOT NULL AND ready_at IS NOT NULL
      AND failed_at IS NULL AND error_code IS NULL)
    OR (state = 'failed' AND artifact_envelope IS NULL AND artifact_bytes IS NULL AND artifact_sha256 IS NULL
      AND ciphertext_sha256 IS NULL
      AND artifact_manifest IS NULL AND plaintext_bytes IS NULL AND ready_at IS NULL
      AND failed_at IS NOT NULL AND error_code IS NOT NULL)
    OR (state IN ('queued','pending','expired'))
  );

COMMENT ON COLUMN report_versions.artifact_manifest IS
  'Immutable issuance evidence including snapshot digest, encrypted-envelope digest, plaintext size metadata, row count, generation time and report identity.';
COMMENT ON COLUMN report_versions.artifact_envelope IS
  'Opaque client-encrypted report container. The server never receives or persists plaintext report bytes.';
