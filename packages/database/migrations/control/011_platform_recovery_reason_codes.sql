-- A platform recovery is a privileged operational event.  Store only a
-- closed, non-sensitive code plus a one-way reference to the separately
-- controlled incident record; never persist the operator's narrative.
ALTER TABLE platform_admin_bootstrap_tokens
  -- PostgreSQL names this table-level expression `..._check` because the
  -- original inline CHECK references both `purpose` and `recovery_reason`.
  -- Keep the explicit-column variant for forward compatibility with a
  -- freshly named 008 migration, but require the replacement constraint
  -- below on every installation.
  DROP CONSTRAINT IF EXISTS platform_admin_bootstrap_tokens_recovery_reason_check,
  DROP CONSTRAINT IF EXISTS platform_admin_bootstrap_tokens_check;

UPDATE platform_admin_bootstrap_tokens
   SET recovery_reason = 'LEGACY_RECOVERY'
 WHERE purpose = 'recovery';

ALTER TABLE platform_admin_bootstrap_tokens
  RENAME COLUMN recovery_reason TO recovery_reason_code;

ALTER TABLE platform_admin_bootstrap_tokens
  ADD COLUMN external_incident_ref_hash text;

ALTER TABLE platform_admin_bootstrap_tokens
  ADD CONSTRAINT platform_admin_bootstrap_recovery_code_check CHECK (
    (purpose = 'bootstrap'
      AND recovery_reason_code IS NULL
      AND external_incident_ref_hash IS NULL)
    OR
    (purpose = 'recovery'
      AND recovery_reason_code IN (
        'SECURITY_RESPONSE',
        'ADMIN_ACCESS_LOSS',
        'AUTHORIZED_RECOVERY',
        'LEGACY_RECOVERY'
      )
      AND (
        (recovery_reason_code = 'LEGACY_RECOVERY' AND external_incident_ref_hash IS NULL)
        OR
        (recovery_reason_code <> 'LEGACY_RECOVERY'
          AND external_incident_ref_hash ~ '^[0-9a-f]{64}$')
      ))
  );

COMMENT ON COLUMN platform_admin_bootstrap_tokens.recovery_reason_code IS
  'Closed non-sensitive code. Human incident narrative belongs in an external controlled record.';

COMMENT ON COLUMN platform_admin_bootstrap_tokens.external_incident_ref_hash IS
  'SHA-256 of the external incident reference; the reference itself is never stored in the control database.';
