CREATE OR REPLACE FUNCTION is_valid_tally_decision_rule(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT candidate = '{"kind":"PLURALITY"}'::jsonb
    OR (
      jsonb_typeof(candidate) = 'object'
      AND candidate ?& ARRAY['kind','threshold','denominator']
      AND candidate - 'kind' - 'threshold' - 'denominator' = '{}'::jsonb
      AND candidate->>'kind' = 'STRICT_MAJORITY'
      AND CASE WHEN jsonb_typeof(candidate->'threshold') = 'number'
        THEN (candidate->>'threshold')::numeric >= 0 AND (candidate->>'threshold')::numeric < 1
        ELSE false
      END
      AND candidate->>'denominator' IN ('NON_ABSTAINING_BALLOTS','ALL_RECEIVED_BALLOTS')
    )
$$;

ALTER TABLE rounds
  ADD COLUMN decision_rule jsonb NOT NULL DEFAULT '{"kind":"PLURALITY"}'::jsonb
  CHECK (is_valid_tally_decision_rule(decision_rule));

CREATE TABLE custodian_device_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  custodian_identity_id uuid NOT NULL,
  device_id uuid NOT NULL,
  recipient_id text NOT NULL CHECK (
    length(recipient_id) BETWEEN 1 AND 128
    AND recipient_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$'
  ),
  key_version integer NOT NULL CHECK (key_version > 0),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'superseded', 'revoked')),
  hpke_kem text NOT NULL CHECK (hpke_kem = 'DHKEM(P-256, HKDF-SHA256)'),
  hpke_kdf text NOT NULL CHECK (hpke_kdf = 'HKDF-SHA256'),
  hpke_aead text NOT NULL CHECK (hpke_aead = 'AES-256-GCM'),
  hpke_public_key text NOT NULL CHECK (hpke_public_key ~ '^[A-Za-z0-9_-]+$'),
  hpke_fingerprint text NOT NULL UNIQUE CHECK (hpke_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  signing_algorithm text NOT NULL CHECK (signing_algorithm = 'Ed25519'),
  signing_public_key_spki text NOT NULL CHECK (signing_public_key_spki ~ '^[A-Za-z0-9_-]+$'),
  signing_fingerprint text NOT NULL UNIQUE CHECK (signing_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  registered_by_identity_id uuid NOT NULL,
  registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_by_identity_id uuid,
  revoked_at timestamptz,
  revocation_reason text CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 3 AND 240),
  UNIQUE (custodian_identity_id, device_id, key_version),
  CHECK (
    (status = 'revoked' AND revoked_by_identity_id IS NOT NULL AND revoked_at IS NOT NULL)
    OR (status <> 'revoked' AND revoked_by_identity_id IS NULL AND revoked_at IS NULL AND revocation_reason IS NULL)
  )
);

CREATE UNIQUE INDEX custodian_device_keys_one_active_per_device
  ON custodian_device_keys(custodian_identity_id, device_id)
  WHERE status = 'active';

CREATE UNIQUE INDEX custodian_device_keys_one_active_recipient
  ON custodian_device_keys(recipient_id)
  WHERE status = 'active';

CREATE INDEX custodian_device_keys_active_identity
  ON custodian_device_keys(custodian_identity_id, device_id)
  WHERE status = 'active';

CREATE TABLE round_custody_sets (
  round_id uuid PRIMARY KEY REFERENCES rounds(id) ON DELETE RESTRICT,
  round_version integer NOT NULL CHECK (round_version > 0),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  decision_rule jsonb NOT NULL CHECK (is_valid_tally_decision_rule(decision_rule)),
  frozen_by_identity_id uuid NOT NULL,
  frozen_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE round_custodian_key_snapshots (
  round_id uuid NOT NULL REFERENCES round_custody_sets(round_id) ON DELETE RESTRICT,
  custodian_identity_id uuid NOT NULL,
  device_id uuid NOT NULL,
  source_key_id uuid NOT NULL REFERENCES custodian_device_keys(id) ON DELETE RESTRICT,
  recipient_id text NOT NULL,
  key_version integer NOT NULL CHECK (key_version > 0),
  hpke_kem text NOT NULL CHECK (hpke_kem = 'DHKEM(P-256, HKDF-SHA256)'),
  hpke_kdf text NOT NULL CHECK (hpke_kdf = 'HKDF-SHA256'),
  hpke_aead text NOT NULL CHECK (hpke_aead = 'AES-256-GCM'),
  hpke_public_key text NOT NULL,
  hpke_fingerprint text NOT NULL CHECK (hpke_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  signing_algorithm text NOT NULL CHECK (signing_algorithm = 'Ed25519'),
  signing_public_key_spki text NOT NULL,
  signing_fingerprint text NOT NULL CHECK (signing_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  frozen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (round_id, custodian_identity_id),
  UNIQUE (round_id, source_key_id),
  UNIQUE (round_id, recipient_id),
  UNIQUE (round_id, hpke_fingerprint),
  UNIQUE (round_id, signing_fingerprint)
);

CREATE TABLE tally_manifests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  round_id uuid NOT NULL UNIQUE REFERENCES round_custody_sets(round_id) ON DELETE RESTRICT,
  custody_version integer NOT NULL CHECK (custody_version > 0),
  round_version integer NOT NULL CHECK (round_version > 0),
  decision_rule jsonb NOT NULL CHECK (is_valid_tally_decision_rule(decision_rule)),
  manifest_hash text NOT NULL UNIQUE CHECK (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  entry_count integer NOT NULL CHECK (entry_count > 0),
  state text NOT NULL DEFAULT 'awaiting_attestations' CHECK (
    state IN ('awaiting_attestations', 'publishable', 'disputed', 'published')
  ),
  agreed_aggregate_hash text CHECK (agreed_aggregate_hash IS NULL OR agreed_aggregate_hash ~ '^sha256:[0-9a-f]{64}$'),
  agreed_aggregate jsonb CHECK (agreed_aggregate IS NULL OR jsonb_typeof(agreed_aggregate) = 'object'),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_by_identity_id uuid,
  published_at timestamptz,
  CHECK (
    (state = 'published' AND agreed_aggregate_hash IS NOT NULL AND published_by_identity_id IS NOT NULL AND published_at IS NOT NULL)
    OR (state <> 'published' AND published_by_identity_id IS NULL AND published_at IS NULL)
  ),
  CHECK (
    (state IN ('publishable', 'published') AND agreed_aggregate_hash IS NOT NULL AND agreed_aggregate IS NOT NULL)
    OR (state IN ('awaiting_attestations', 'disputed') AND agreed_aggregate_hash IS NULL AND agreed_aggregate IS NULL)
  )
);

CREATE TABLE tally_manifest_entries (
  manifest_id uuid NOT NULL REFERENCES tally_manifests(id) ON DELETE RESTRICT,
  position integer NOT NULL CHECK (position > 0),
  receipt_id uuid NOT NULL UNIQUE REFERENCES participation_receipts(id) ON DELETE RESTRICT,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  envelope_hash text NOT NULL CHECK (envelope_hash ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (manifest_id, position),
  UNIQUE (manifest_id, receipt_id)
);

CREATE TABLE custodian_attestations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  manifest_id uuid NOT NULL REFERENCES tally_manifests(id) ON DELETE RESTRICT,
  round_id uuid NOT NULL REFERENCES round_custody_sets(round_id) ON DELETE RESTRICT,
  custodian_identity_id uuid NOT NULL,
  source_key_id uuid NOT NULL REFERENCES custodian_device_keys(id) ON DELETE RESTRICT,
  manifest_hash text NOT NULL CHECK (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  aggregate_hash text NOT NULL CHECK (aggregate_hash ~ '^sha256:[0-9a-f]{64}$'),
  signing_fingerprint text NOT NULL CHECK (signing_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  signature text NOT NULL CHECK (signature ~ '^[A-Za-z0-9_-]+$'),
  context_hash text NOT NULL CHECK (context_hash ~ '^sha256:[0-9a-f]{64}$'),
  attested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (manifest_id, custodian_identity_id)
);

CREATE INDEX custodian_attestations_manifest_aggregate
  ON custodian_attestations(manifest_id, aggregate_hash);

CREATE OR REPLACE FUNCTION reject_immutable_custody_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'custody evidence is immutable' USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER round_custodian_snapshots_immutable
BEFORE UPDATE OR DELETE ON round_custodian_key_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_immutable_custody_row();

CREATE TRIGGER tally_manifest_entries_immutable
BEFORE UPDATE OR DELETE ON tally_manifest_entries
FOR EACH ROW EXECUTE FUNCTION reject_immutable_custody_row();

CREATE TRIGGER custodian_attestations_immutable
BEFORE UPDATE OR DELETE ON custodian_attestations
FOR EACH ROW EXECUTE FUNCTION reject_immutable_custody_row();

REVOKE UPDATE, DELETE, TRUNCATE ON round_custodian_key_snapshots FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON tally_manifest_entries FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON custodian_attestations FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_immutable_custody_row() FROM PUBLIC;
