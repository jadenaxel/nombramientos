-- Additive device session proof metadata. No key/grant/ciphertext/role conversion.
CREATE TABLE e2ee_http_devices (
  device_id uuid PRIMARY KEY,
  identity_id uuid NOT NULL,
  signing_fingerprint text NOT NULL CHECK(signing_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  public_jwk jsonb NOT NULL CHECK(public_jwk->>'kty'='EC' AND public_jwk->>'crv'='P-256' AND NOT public_jwk ? 'd'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(device_id,identity_id),
  FOREIGN KEY(device_id,identity_id) REFERENCES e2ee_key_devices(device_id,identity_id)
);
CREATE TABLE e2ee_http_session_bindings (
  session_id uuid PRIMARY KEY,
  identity_id uuid NOT NULL,
  device_id uuid NOT NULL,
  source_session_id uuid,
  bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  revoke_reason text,
  FOREIGN KEY(device_id,identity_id) REFERENCES e2ee_http_devices(device_id,identity_id)
);
CREATE INDEX e2ee_http_session_bindings_device ON e2ee_http_session_bindings(device_id) WHERE revoked_at IS NULL;
CREATE TABLE e2ee_http_challenges (
  id uuid PRIMARY KEY,
  identity_id uuid NOT NULL,
  session_id uuid NOT NULL,
  device_id uuid NOT NULL REFERENCES e2ee_key_devices(device_id),
  purpose text NOT NULL CHECK(purpose IN ('enrollment','request')),
  secret_hash text,
  public_jwk jsonb,
  context jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX e2ee_http_challenges_session ON e2ee_http_challenges(session_id,expires_at) WHERE consumed_at IS NULL;
CREATE INDEX e2ee_http_challenges_expiration ON e2ee_http_challenges(expires_at);
REVOKE ALL ON e2ee_http_devices,e2ee_http_session_bindings,e2ee_http_challenges FROM PUBLIC;

-- Trigger runs in the same tenant transaction as key-device revocation. The
-- control-plane session cleanup is supplementary, not the security boundary.
CREATE FUNCTION revoke_e2ee_http_device_sessions() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
  IF NEW.status='revoked' AND OLD.status IS DISTINCT FROM NEW.status THEN
    UPDATE e2ee_http_session_bindings SET revoked_at=clock_timestamp(),revoke_reason='e2ee_device_revoked'
      WHERE device_id=NEW.device_id AND revoked_at IS NULL;
    UPDATE e2ee_http_challenges SET consumed_at=clock_timestamp()
      WHERE device_id=NEW.device_id AND consumed_at IS NULL;
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION revoke_e2ee_http_device_sessions() FROM PUBLIC;
CREATE TRIGGER e2ee_http_device_revocation AFTER UPDATE OF status ON e2ee_key_devices
  FOR EACH ROW EXECUTE FUNCTION revoke_e2ee_http_device_sessions();

-- Nonces are transient security metadata, never business/audit history. The
-- owner is the tenant's NOLOGIN role; runtime receives neither DELETE nor
-- EXECUTE. Bounded expiration cleanup never touches a still-valid challenge.
CREATE FUNCTION prune_expired_e2ee_http_challenges() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  DELETE FROM public.e2ee_http_challenges
    WHERE id IN (
      SELECT id FROM public.e2ee_http_challenges
      WHERE expires_at<=statement_timestamp()
      ORDER BY expires_at,id LIMIT 500 FOR UPDATE SKIP LOCKED
    );
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION prune_expired_e2ee_http_challenges() FROM PUBLIC;
CREATE TRIGGER e2ee_http_challenge_expiration AFTER INSERT ON e2ee_http_challenges
  FOR EACH STATEMENT EXECUTE FUNCTION prune_expired_e2ee_http_challenges();
