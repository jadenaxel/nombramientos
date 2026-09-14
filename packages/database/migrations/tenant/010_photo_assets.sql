CREATE TABLE member_photo_assets (
  id uuid PRIMARY KEY,
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
  version integer NOT NULL CHECK (version > 0),
  media_type text NOT NULL CHECK (media_type = 'image/jpeg'),
  width integer NOT NULL CHECK (width BETWEEN 128 AND 1024),
  height integer NOT NULL CHECK (height BETWEEN 128 AND 1024),
  plaintext_bytes integer NOT NULL CHECK (plaintext_bytes BETWEEN 128 AND 786432),
  cipher_bytes integer NOT NULL CHECK (cipher_bytes = plaintext_bytes + 16),
  envelope jsonb NOT NULL CHECK (
    jsonb_typeof(envelope) = 'object'
    AND envelope ->> 'algorithm' = 'AES-256-GCM'
    AND jsonb_typeof(envelope -> 'keyId') = 'string'
    AND jsonb_typeof(envelope -> 'nonce') = 'string'
    AND jsonb_typeof(envelope -> 'ciphertext') = 'string'
    AND jsonb_typeof(envelope -> 'aad') = 'string'
    AND envelope = jsonb_build_object(
      'algorithm', envelope -> 'algorithm',
      'keyId', envelope -> 'keyId',
      'nonce', envelope -> 'nonce',
      'ciphertext', envelope -> 'ciphertext',
      'aad', envelope -> 'aad'
    )
  ),
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  archived_by_identity_id uuid,
  archived_at timestamptz,
  UNIQUE (member_id, version),
  CHECK (width = height),
  CHECK (
    (archived_at IS NULL AND archived_by_identity_id IS NULL)
    OR (archived_at IS NOT NULL AND archived_by_identity_id IS NOT NULL)
  )
);

CREATE UNIQUE INDEX member_photo_assets_one_active_per_member
  ON member_photo_assets(member_id)
  WHERE archived_at IS NULL;

CREATE INDEX member_photo_assets_member_history
  ON member_photo_assets(member_id, version DESC);

CREATE OR REPLACE FUNCTION enforce_member_photo_asset_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.archived_at IS NOT NULL
     OR NEW.archived_at IS NULL
     OR NEW.archived_by_identity_id IS NULL
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.member_id IS DISTINCT FROM OLD.member_id
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.media_type IS DISTINCT FROM OLD.media_type
     OR NEW.width IS DISTINCT FROM OLD.width
     OR NEW.height IS DISTINCT FROM OLD.height
     OR NEW.plaintext_bytes IS DISTINCT FROM OLD.plaintext_bytes
     OR NEW.cipher_bytes IS DISTINCT FROM OLD.cipher_bytes
     OR NEW.envelope IS DISTINCT FROM OLD.envelope
     OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
     OR NEW.created_by_identity_id IS DISTINCT FROM OLD.created_by_identity_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'photo asset history is immutable except for one-way archival'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER member_photo_assets_history_guard
BEFORE UPDATE ON member_photo_assets
FOR EACH ROW EXECUTE FUNCTION enforce_member_photo_asset_history();

CREATE TRIGGER member_photo_assets_delete_guard
BEFORE DELETE ON member_photo_assets
FOR EACH ROW EXECUTE FUNCTION reject_immutable_workflow_evidence();

REVOKE DELETE, TRUNCATE ON member_photo_assets FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_member_photo_asset_history() FROM PUBLIC;

COMMENT ON TABLE member_photo_assets IS
  'Tenant-local, browser-encrypted normalized photographs. Original bytes, names, EXIF and location metadata must never be stored.';
COMMENT ON COLUMN member_photo_assets.envelope IS
  'Opaque AES-256-GCM ciphertext and authentication material; the tenant runtime has no content key.';
COMMENT ON COLUMN member_photo_assets.plaintext_bytes IS
  'Authenticated normalized-image length disclosed as explicit operational metadata; it is not an original-file size.';
