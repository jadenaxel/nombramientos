-- Forward-only hardening for qualification detail envelopes. Migration 032 is
-- already immutable in deployed tenant histories, so this constraint is added
-- incrementally rather than rewriting that migration.
ALTER TABLE member_qualification_versions
ADD CONSTRAINT member_qualification_details_envelope_shape CHECK (
  details_envelope IS NULL
  OR (
    jsonb_typeof(details_envelope) = 'object'
    AND details_envelope = jsonb_build_object(
      'algorithm', details_envelope -> 'algorithm',
      'keyId', details_envelope -> 'keyId',
      'nonce', details_envelope -> 'nonce',
      'ciphertext', details_envelope -> 'ciphertext',
      'aad', details_envelope -> 'aad'
    )
    AND jsonb_typeof(details_envelope -> 'algorithm') = 'string'
    AND details_envelope ->> 'algorithm' = 'AES-256-GCM'
    AND jsonb_typeof(details_envelope -> 'keyId') = 'string'
    AND char_length(details_envelope ->> 'keyId') BETWEEN 8 AND 160
    AND jsonb_typeof(details_envelope -> 'nonce') = 'string'
    AND details_envelope ->> 'nonce' ~ '^[A-Za-z0-9_-]{16}$'
    AND jsonb_typeof(details_envelope -> 'ciphertext') = 'string'
    AND details_envelope ->> 'ciphertext' ~ '^[A-Za-z0-9_-]+$'
    AND char_length(details_envelope ->> 'ciphertext') BETWEEN 22 AND 2731
    AND jsonb_typeof(details_envelope -> 'aad') = 'string'
    AND details_envelope ->> 'aad' ~ '^[A-Za-z0-9_-]+$'
    AND char_length(details_envelope ->> 'aad') BETWEEN 2 AND 2048
  )
);
