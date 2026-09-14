-- AC-32: tenant content keys are created, wrapped and recovered only by clients.
-- This schema persists public keys, ciphertext envelopes and secret-free metadata.

CREATE TABLE e2ee_key_devices (
  device_id uuid PRIMARY KEY,
  identity_id uuid NOT NULL,
  label text NOT NULL CHECK (length(btrim(label)) BETWEEN 1 AND 80),
  wrapping_public_key jsonb NOT NULL CHECK (jsonb_typeof(wrapping_public_key) = 'object'),
  wrapping_key_fingerprint text NOT NULL UNIQUE
    CHECK (wrapping_key_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'active', 'revoked')),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz,
  revoked_at timestamptz,
  revoked_by_identity_id uuid,
  revoke_reason text CHECK (revoke_reason IS NULL OR length(btrim(revoke_reason)) BETWEEN 4 AND 240),
  UNIQUE (device_id, identity_id),
  CHECK ((status = 'active') = (activated_at IS NOT NULL AND revoked_at IS NULL)),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX e2ee_key_devices_identity_status
ON e2ee_key_devices(identity_id, status, registered_at DESC);

CREATE TABLE e2ee_key_generations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_key_id uuid NOT NULL UNIQUE,
  generation integer NOT NULL UNIQUE CHECK (generation > 0),
  status text NOT NULL CHECK (status IN ('active', 'retired', 'lost')),
  recovery_public_key jsonb NOT NULL CHECK (jsonb_typeof(recovery_public_key) = 'object'),
  recovery_key_fingerprint text NOT NULL
    CHECK (recovery_key_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  lost_at timestamptz,
  rotated_from_generation_id uuid REFERENCES e2ee_key_generations(id) ON DELETE RESTRICT,
  rotation_reason text CHECK (rotation_reason IS NULL OR length(btrim(rotation_reason)) BETWEEN 4 AND 240),
  CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
  CHECK ((status = 'lost') = (lost_at IS NOT NULL))
);

CREATE UNIQUE INDEX e2ee_key_generations_one_active
ON e2ee_key_generations((true)) WHERE status = 'active';

CREATE TABLE e2ee_key_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  generation_id uuid NOT NULL REFERENCES e2ee_key_generations(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL,
  device_id uuid NOT NULL,
  envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
  envelope_hash text NOT NULL CHECK (envelope_hash ~ '^sha256:[0-9a-f]{64}$'),
  grant_kind text NOT NULL CHECK (grant_kind IN ('initial', 'admin_approved', 'rotation', 'recovery')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'revoked')),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  granted_by_identity_id uuid NOT NULL,
  recovery_nonce uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  revoked_at timestamptz,
  revoked_by_identity_id uuid,
  revoke_reason text CHECK (revoke_reason IS NULL OR length(btrim(revoke_reason)) BETWEEN 4 AND 240),
  FOREIGN KEY (device_id, identity_id)
    REFERENCES e2ee_key_devices(device_id, identity_id) ON DELETE RESTRICT,
  UNIQUE (generation_id, device_id),
  UNIQUE (recovery_nonce),
  CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX e2ee_key_grants_identity_status
ON e2ee_key_grants(identity_id, status, created_at DESC);

CREATE INDEX e2ee_key_grants_generation_status
ON e2ee_key_grants(generation_id, status, created_at);

CREATE TABLE e2ee_key_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_identity_id uuid NOT NULL,
  session_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN (
    'device.register', 'grant.initialize', 'grant.approve', 'grant.revoke',
    'key.rotate', 'key.recover', 'key.declare_lost'
  )),
  request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  idempotency_key uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'consumed')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  request_id uuid,
  UNIQUE (actor_identity_id, idempotency_key),
  CHECK (expires_at > created_at),
  CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);

CREATE INDEX e2ee_key_challenges_pending_expiry
ON e2ee_key_challenges(expires_at)
WHERE status = 'pending';

-- The application role receives only SELECT/INSERT/UPDATE through
-- applyRuntimeGrants; no lifecycle table can be deleted or truncated by it.
REVOKE DELETE, TRUNCATE ON e2ee_key_devices, e2ee_key_generations,
  e2ee_key_grants, e2ee_key_challenges FROM PUBLIC;
