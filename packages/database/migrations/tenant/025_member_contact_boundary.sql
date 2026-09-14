-- Separate the roster identity used throughout nomination workflows from
-- optional contact data. Existing profile envelopes cannot be split by the
-- server because it never possesses the tenant content key. They therefore
-- remain quarantined in profile_envelope until an authorized client replaces
-- them; application projections never select that legacy column.

ALTER TABLE members
  ALTER COLUMN profile_envelope DROP NOT NULL,
  ADD COLUMN display_envelope jsonb,
  ADD COLUMN display_content_hash text,
  ADD COLUMN contact_envelope jsonb,
  ADD COLUMN contact_content_hash text,
  ADD COLUMN profile_migration_required boolean NOT NULL DEFAULT true;

ALTER TABLE members
  ADD CONSTRAINT members_display_envelope_hash_pair CHECK (
    (display_envelope IS NULL) = (display_content_hash IS NULL)
    AND (display_content_hash IS NULL OR display_content_hash ~ '^sha256:[0-9a-f]{64}$')
  ),
  ADD CONSTRAINT members_contact_envelope_hash_pair CHECK (
    (contact_envelope IS NULL) = (contact_content_hash IS NULL)
    AND (contact_content_hash IS NULL OR contact_content_hash ~ '^sha256:[0-9a-f]{64}$')
  ),
  ADD CONSTRAINT members_legacy_profile_resolution CHECK (
    (
      profile_migration_required
      AND profile_envelope IS NOT NULL
      AND display_envelope IS NULL
      AND display_content_hash IS NULL
      AND contact_envelope IS NULL
      AND contact_content_hash IS NULL
    )
    OR (
      NOT profile_migration_required
      AND profile_envelope IS NULL
      AND display_envelope IS NOT NULL
      AND display_content_hash IS NOT NULL
    )
  );

-- Rows created before this boundary deliberately remain migration-required.
-- Future inserts are split records and must opt into the legacy state.
ALTER TABLE members ALTER COLUMN profile_migration_required SET DEFAULT false;

-- Frozen cycle snapshots receive only the display envelope going forward.
-- Historical combined envelopes have no operational recovery purpose: unlike
-- the live member profile, a snapshot cannot be interactively re-encrypted.
-- Neutralize that ciphertext without decrypting it and retain an explicit
-- provenance marker instead.
ALTER TABLE cycle_member_snapshots
  ALTER COLUMN profile_envelope DROP NOT NULL,
  ADD COLUMN display_envelope jsonb,
  ADD COLUMN legacy_profile_redacted boolean NOT NULL DEFAULT true;

UPDATE cycle_member_snapshots SET profile_envelope = NULL;

ALTER TABLE cycle_member_snapshots
  ALTER COLUMN legacy_profile_redacted SET DEFAULT false;

ALTER TABLE cycle_member_snapshots
  ADD CONSTRAINT cycle_member_snapshot_envelope_generation CHECK (
    profile_envelope IS NULL
    AND (
      (legacy_profile_redacted AND display_envelope IS NULL)
      OR (NOT legacy_profile_redacted AND display_envelope IS NOT NULL)
    )
  );

-- Historical workflow copies used the combined member-profile envelope. They
-- have no safe server-side split path, so remove only that opaque envelope and
-- preserve the remaining provenance. New snapshots are populated exclusively
-- from members.display_envelope by the runtime.
ALTER TABLE candidate_snapshots ALTER COLUMN display_envelope DROP NOT NULL;
UPDATE candidate_snapshots SET display_envelope = NULL WHERE display_envelope IS NOT NULL;

ALTER TABLE candidacies ALTER COLUMN display_envelope_snapshot DROP NOT NULL;
ALTER TABLE candidacies DISABLE TRIGGER candidacies_preserve_evidence;
UPDATE candidacies SET display_envelope_snapshot = NULL WHERE display_envelope_snapshot IS NOT NULL;
ALTER TABLE candidacies ENABLE TRIGGER candidacies_preserve_evidence;

ALTER TABLE candidate_list_entries ALTER COLUMN display_envelope_snapshot DROP NOT NULL;
ALTER TABLE candidate_list_entries DISABLE TRIGGER candidate_list_entries_immutable;
UPDATE candidate_list_entries SET display_envelope_snapshot = NULL WHERE display_envelope_snapshot IS NOT NULL;
ALTER TABLE candidate_list_entries ENABLE TRIGGER candidate_list_entries_immutable;

ALTER TABLE session_attendance DISABLE TRIGGER session_attendance_preserve_snapshots;
UPDATE session_attendance
   SET display_envelope_snapshot = NULL
 WHERE member_id IS NOT NULL AND display_envelope_snapshot IS NOT NULL;
ALTER TABLE session_attendance ENABLE TRIGGER session_attendance_preserve_snapshots;

ALTER TABLE assignments DISABLE TRIGGER assignments_preserve_provenance;
UPDATE assignments
   SET member_snapshot = (member_snapshot - 'displayEnvelope' - 'profileEnvelope' - 'contactEnvelope')
                         || jsonb_build_object('displayEnvelopeRedacted', true)
 WHERE member_snapshot IS NOT NULL
   AND jsonb_typeof(member_snapshot) = 'object'
   AND member_snapshot ?| ARRAY['displayEnvelope','profileEnvelope','contactEnvelope'];
ALTER TABLE assignments ENABLE TRIGGER assignments_preserve_provenance;

-- A previously issued encrypted artifact may itself contain a legacy combined
-- profile. Expire it and neutralize all stored artifact content without
-- pretending to inspect or decrypt it. It can be regenerated from split
-- display data after migration while request metadata remains auditable.
UPDATE report_versions
   SET state = 'expired',
       artifact_envelope = NULL,
       artifact_bytes = NULL,
       artifact_sha256 = NULL,
       ciphertext_sha256 = NULL,
       artifact_manifest = NULL,
       plaintext_bytes = NULL,
       filename = NULL,
       media_type = NULL,
       ready_at = NULL,
       version = version + 1
 WHERE state IN ('queued', 'pending', 'ready');

-- Staged import envelopes from the prior contract must never be committed or
-- replayed after the boundary change. Summaries remain available for audit.
UPDATE member_import_jobs
   SET preview_envelopes = '[]'::jsonb,
       state = CASE WHEN state IN ('previewed','committing') THEN 'failed' ELSE state END,
       error_report = CASE WHEN state IN ('previewed','committing')
                           THEN '[{"sourceRow":0,"action":"skip","codes":["LEGACY_PROFILE_CONTRACT_RETIRED"]}]'::jsonb
                           ELSE error_report END,
       revision = revision + 1
 WHERE jsonb_array_length(preview_envelopes) > 0;

INSERT INTO permissions(code, description) VALUES
  ('member.contact.read', 'Read separately encrypted member contact envelopes'),
  ('member.contact.manage', 'Create, replace, or remove member contact envelopes')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code, delegable)
SELECT role.id, permission.code, true
  FROM roles role
  JOIN permissions permission
    ON permission.code IN ('member.contact.read', 'member.contact.manage')
 WHERE role.code = 'CHURCH_ADMIN'
ON CONFLICT (role_id, permission_code) DO UPDATE SET delegable = EXCLUDED.delegable;

COMMENT ON COLUMN members.profile_envelope IS
  'Quarantined legacy member-profile/v1 envelope. Never selected by runtime projections; cleared only by an authorized split-profile migration.';
COMMENT ON COLUMN members.display_envelope IS
  'E2EE identity envelope with exact AAD purpose member-display and no contact fields.';
COMMENT ON COLUMN members.contact_envelope IS
  'Optional E2EE contact envelope with exact AAD purpose member-contact; permission-gated independently from member.read.';
COMMENT ON COLUMN members.profile_migration_required IS
  'True while an inaccessible legacy combined profile remains pending authorized client-side replacement or discard.';
COMMENT ON COLUMN cycle_member_snapshots.profile_envelope IS
  'Retired legacy combined profile slot. Migration 025 neutralizes every value and the generation constraint keeps it null.';
COMMENT ON COLUMN cycle_member_snapshots.display_envelope IS
  'Frozen display-only identity envelope with exact AAD purpose member-display.';
COMMENT ON COLUMN cycle_member_snapshots.legacy_profile_redacted IS
  'True only for a historical snapshot whose combined ciphertext was irreversibly neutralized without server-side decryption.';
