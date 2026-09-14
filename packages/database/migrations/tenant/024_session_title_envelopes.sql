-- Session and agenda titles are part of the internal minutes. Keep only
-- authenticated ciphertext for new content. Historic plaintext cannot be
-- encrypted during a server-side migration because the server deliberately
-- has no tenant content key, so redact it while preserving the immutable
-- session/agenda identity, ordering, state and timestamps.
ALTER TABLE cycle_sessions
  ADD COLUMN title_envelope jsonb,
  ADD COLUMN title_envelope_version integer NOT NULL DEFAULT 0 CHECK (title_envelope_version >= 0);

ALTER TABLE session_agenda_items
  ADD COLUMN title_envelope jsonb,
  ADD COLUMN title_envelope_version integer NOT NULL DEFAULT 0 CHECK (title_envelope_version >= 0);

UPDATE cycle_sessions
   SET title = 'LEGACY_TITLE_REDACTED',
       title_envelope = NULL,
       title_envelope_version = 0;

UPDATE session_agenda_items
   SET title = 'LEGACY_TITLE_REDACTED',
       title_envelope = NULL,
       title_envelope_version = 0;

ALTER TABLE cycle_sessions
  DROP CONSTRAINT cycle_sessions_title_check,
  ALTER COLUMN title DROP NOT NULL,
  ADD CONSTRAINT cycle_sessions_title_legacy_marker
    CHECK (title IS NULL OR title = 'LEGACY_TITLE_REDACTED'),
  ADD CONSTRAINT cycle_sessions_title_envelope_shape
    CHECK (
      title_envelope IS NULL
      OR (
        jsonb_typeof(title_envelope) = 'object'
        AND title_envelope ->> 'algorithm' IN ('AES-256-GCM','XCHACHA20-POLY1305')
        AND jsonb_typeof(title_envelope -> 'keyId') = 'string'
        AND jsonb_typeof(title_envelope -> 'nonce') = 'string'
        AND jsonb_typeof(title_envelope -> 'ciphertext') = 'string'
        AND jsonb_typeof(title_envelope -> 'aad') = 'string'
        AND title_envelope = jsonb_build_object(
          'algorithm', title_envelope -> 'algorithm',
          'keyId', title_envelope -> 'keyId',
          'nonce', title_envelope -> 'nonce',
          'ciphertext', title_envelope -> 'ciphertext',
          'aad', title_envelope -> 'aad'
        )
      )
    ),
  ADD CONSTRAINT cycle_sessions_title_envelope_state
    CHECK (
      (title IS NULL AND title_envelope IS NOT NULL AND title_envelope_version > 0)
      OR
      (title = 'LEGACY_TITLE_REDACTED' AND title_envelope IS NULL AND title_envelope_version = 0)
    );

ALTER TABLE session_agenda_items
  DROP CONSTRAINT session_agenda_items_title_check,
  ALTER COLUMN title DROP NOT NULL,
  ADD CONSTRAINT session_agenda_items_title_legacy_marker
    CHECK (title IS NULL OR title = 'LEGACY_TITLE_REDACTED'),
  ADD CONSTRAINT session_agenda_items_title_envelope_shape
    CHECK (
      title_envelope IS NULL
      OR (
        jsonb_typeof(title_envelope) = 'object'
        AND title_envelope ->> 'algorithm' IN ('AES-256-GCM','XCHACHA20-POLY1305')
        AND jsonb_typeof(title_envelope -> 'keyId') = 'string'
        AND jsonb_typeof(title_envelope -> 'nonce') = 'string'
        AND jsonb_typeof(title_envelope -> 'ciphertext') = 'string'
        AND jsonb_typeof(title_envelope -> 'aad') = 'string'
        AND title_envelope = jsonb_build_object(
          'algorithm', title_envelope -> 'algorithm',
          'keyId', title_envelope -> 'keyId',
          'nonce', title_envelope -> 'nonce',
          'ciphertext', title_envelope -> 'ciphertext',
          'aad', title_envelope -> 'aad'
        )
      )
    ),
  ADD CONSTRAINT session_agenda_items_title_envelope_state
    CHECK (
      (title IS NULL AND title_envelope IS NOT NULL AND title_envelope_version > 0)
      OR
      (title = 'LEGACY_TITLE_REDACTED' AND title_envelope IS NULL AND title_envelope_version = 0)
    );

COMMENT ON COLUMN cycle_sessions.title IS
  'Legacy-only redaction marker. New session titles must exist solely in title_envelope.';
COMMENT ON COLUMN cycle_sessions.title_envelope IS
  'E2EE session-title ciphertext; authenticated context binds tenant, cycle, session, purpose, schema and title version.';
COMMENT ON COLUMN cycle_sessions.title_envelope_version IS
  'Independent title revision used in authenticated context; unrelated session mutations do not change it.';
COMMENT ON COLUMN session_agenda_items.title IS
  'Legacy-only redaction marker. New agenda titles must exist solely in title_envelope.';
COMMENT ON COLUMN session_agenda_items.title_envelope IS
  'E2EE agenda-title ciphertext; authenticated context binds tenant, session, agenda item, purpose, schema and title version.';
COMMENT ON COLUMN session_agenda_items.title_envelope_version IS
  'Independent title revision used in authenticated context; agenda ordering/status mutations do not change it.';
