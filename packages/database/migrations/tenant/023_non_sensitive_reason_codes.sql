-- Operational reasons are deliberately non-sensitive machine codes. Any
-- historic prose is redacted in mutable lifecycle columns; immutable audit
-- history is not rewritten because doing so would invalidate its hash chain.
UPDATE custodian_device_keys
   SET revocation_reason = 'SECURITY_RESPONSE'
 WHERE revocation_reason IS NOT NULL
   AND revocation_reason NOT IN ('DEVICE_RETIRED','DEVICE_REPLACED','SECURITY_RESPONSE','VERIFIED_KEY_LOSS');

UPDATE e2ee_key_devices
   SET revoke_reason = 'SECURITY_RESPONSE'
 WHERE revoke_reason IS NOT NULL
   AND revoke_reason NOT IN ('DEVICE_RETIRED','DEVICE_REPLACED','ACCESS_REMOVED','SECURITY_RESPONSE');

UPDATE e2ee_key_generations
   SET rotation_reason = CASE
     WHEN status = 'lost' THEN 'VERIFIED_RECOVERY_FAILURE'
     ELSE 'SECURITY_RESPONSE'
   END
 WHERE rotation_reason IS NOT NULL
   AND NOT (
     (status = 'lost' AND rotation_reason IN (
       'RECOVERY_MATERIAL_UNAVAILABLE','AUTHORIZED_DEVICES_UNAVAILABLE','VERIFIED_RECOVERY_FAILURE'
     ))
     OR
     (status <> 'lost' AND rotation_reason IN (
       'SCHEDULED_ROTATION','DEVICE_ROSTER_CHANGED','SECURITY_RESPONSE','RECOVERY_REKEY'
     ))
   );

UPDATE e2ee_key_grants
   SET revoke_reason = 'SECURITY_RESPONSE'
 WHERE revoke_reason IS NOT NULL
   AND revoke_reason NOT IN ('DEVICE_RETIRED','DEVICE_REPLACED','ACCESS_REMOVED','SECURITY_RESPONSE');

-- Session decisions are mutable only to the migration owner. Replace any
-- historic free vocabulary with the least-specific code implied by outcome.
UPDATE session_decisions
   SET decision_code = CASE outcome
     WHEN 'APPROVED' THEN 'RESOLUTION'
     WHEN 'REJECTED' THEN 'ITEM_REJECTED'
     WHEN 'DEFERRED' THEN 'ITEM_DEFERRED'
     ELSE 'INFORMATION_NOTED'
   END
 WHERE NOT (
   (outcome = 'APPROVED' AND decision_code IN ('RESOLUTION','AGREEMENT'))
   OR (outcome = 'REJECTED' AND decision_code = 'ITEM_REJECTED')
   OR (outcome = 'DEFERRED' AND decision_code = 'ITEM_DEFERRED')
   OR (outcome = 'RECORDED' AND decision_code = 'INFORMATION_NOTED')
 );

ALTER TABLE custodian_device_keys
  DROP CONSTRAINT custodian_device_keys_revocation_reason_check;
ALTER TABLE e2ee_key_devices
  DROP CONSTRAINT e2ee_key_devices_revoke_reason_check;
ALTER TABLE e2ee_key_generations
  DROP CONSTRAINT e2ee_key_generations_rotation_reason_check;
ALTER TABLE e2ee_key_grants
  DROP CONSTRAINT e2ee_key_grants_revoke_reason_check;

ALTER TABLE custodian_device_keys
  ADD CONSTRAINT custodian_device_keys_reason_code_format
  CHECK (revocation_reason IS NULL OR revocation_reason ~ '^[A-Z][A-Z0-9_]{2,63}$');

ALTER TABLE e2ee_key_devices
  ADD CONSTRAINT e2ee_key_devices_reason_code_format
  CHECK (revoke_reason IS NULL OR revoke_reason ~ '^[A-Z][A-Z0-9_]{2,63}$');

ALTER TABLE e2ee_key_generations
  ADD CONSTRAINT e2ee_key_generations_reason_code_format
  CHECK (rotation_reason IS NULL OR rotation_reason ~ '^[A-Z][A-Z0-9_]{2,63}$');

ALTER TABLE e2ee_key_grants
  ADD CONSTRAINT e2ee_key_grants_reason_code_format
  CHECK (revoke_reason IS NULL OR revoke_reason ~ '^[A-Z][A-Z0-9_]{2,63}$');

ALTER TABLE custodian_device_keys
  ADD CONSTRAINT custodian_device_keys_reason_code_allowed
  CHECK (revocation_reason IS NULL OR revocation_reason IN (
    'DEVICE_RETIRED','DEVICE_REPLACED','SECURITY_RESPONSE','VERIFIED_KEY_LOSS'
  ));

ALTER TABLE e2ee_key_devices
  ADD CONSTRAINT e2ee_key_devices_reason_code_allowed
  CHECK (revoke_reason IS NULL OR revoke_reason IN (
    'DEVICE_RETIRED','DEVICE_REPLACED','ACCESS_REMOVED','SECURITY_RESPONSE'
  ));

ALTER TABLE e2ee_key_generations
  ADD CONSTRAINT e2ee_key_generations_reason_code_allowed
  CHECK (
    rotation_reason IS NULL
    OR (status = 'lost' AND rotation_reason IN (
      'RECOVERY_MATERIAL_UNAVAILABLE','AUTHORIZED_DEVICES_UNAVAILABLE','VERIFIED_RECOVERY_FAILURE'
    ))
    OR (status <> 'lost' AND rotation_reason IN (
      'SCHEDULED_ROTATION','DEVICE_ROSTER_CHANGED','SECURITY_RESPONSE','RECOVERY_REKEY'
    ))
  );

ALTER TABLE e2ee_key_grants
  ADD CONSTRAINT e2ee_key_grants_reason_code_allowed
  CHECK (revoke_reason IS NULL OR revoke_reason IN (
    'DEVICE_RETIRED','DEVICE_REPLACED','ACCESS_REMOVED','SECURITY_RESPONSE'
  ));

ALTER TABLE session_decisions
  ADD CONSTRAINT session_decisions_decision_code_allowed
  CHECK (
    (outcome = 'APPROVED' AND decision_code IN ('RESOLUTION','AGREEMENT'))
    OR (outcome = 'REJECTED' AND decision_code = 'ITEM_REJECTED')
    OR (outcome = 'DEFERRED' AND decision_code = 'ITEM_DEFERRED')
    OR (outcome = 'RECORDED' AND decision_code = 'INFORMATION_NOTED')
  );

-- These evidence tables are immutable. NOT VALID preserves historic records
-- without rewriting them, while PostgreSQL enforces the closed vocabulary for
-- every new insert after this migration.
ALTER TABLE candidacy_reviews
  ADD CONSTRAINT candidacy_reviews_reason_code_allowed
  CHECK (
    (to_state = 'UNDER_REVIEW' AND reason_code = 'REVIEW_STARTED')
    OR (to_state = 'PRELIMINARY_ACCEPTED' AND reason_code = 'REVIEW_ACCEPTED')
    OR (to_state = 'WITHDRAWN' AND reason_code = 'CANDIDATE_WITHDREW')
    OR (to_state = 'EXCLUDED' AND reason_code = 'COMMITTEE_EXCLUDED')
    OR (to_state = 'INELIGIBLE' AND reason_code = 'ELIGIBILITY_FAILED')
  ) NOT VALID;

ALTER TABLE member_eligibility_workflow_pauses
  ADD CONSTRAINT member_eligibility_pause_resolution_reason_allowed
  CHECK (
    resolution_reason_code IS NULL
    OR (resolution_code = 'ANNUL_AND_RESTART' AND resolution_reason_code = 'ELIGIBILITY_ROUND_RESTARTED')
    OR (resolution_code = 'RESUME_UNCHANGED' AND resolution_reason_code = 'ELIGIBILITY_PROCESS_RESUMED')
    OR (resolution_code = 'EXCLUDE_AND_REVIEW' AND resolution_reason_code = 'ELIGIBILITY_CANDIDACIES_EXCLUDED')
    OR (resolution_code = 'CLOSE_AFTER_REPLACEMENT' AND resolution_reason_code = 'ELIGIBILITY_REPLACEMENT_COMPLETED')
  ) NOT VALID;

ALTER TABLE assignment_transitions
  ADD CONSTRAINT assignment_transitions_reason_code_allowed
  CHECK (
    (action = 'PROVISIONAL_CREATED' AND reason_code = 'PUBLISHED_AGGREGATE_SELECTED')
    OR (action = 'LINKED_DESIGNATION_CREATED' AND reason_code = 'LINKED_BASE_DESIGNATION')
    OR (action = 'CONSENT_RECORDED' AND reason_code IN (
      'CONSENT_PENDING','CONSENT_CONTACTED','CONSENT_ACCEPTED','CONSENT_DECLINED','CONSENT_WITHDRAWN'
    ))
    OR (action = 'PRESENTED_TO_CHURCH' AND reason_code = 'PRESENTATION_RECORDED')
    OR (action = 'CONGREGATIONAL_DECISION_RECORDED' AND reason_code IN (
      'CONGREGATIONAL_ELECTED','CONGREGATIONAL_RETURNED_TO_COMMITTEE','CONGREGATIONAL_NOT_ELECTED','CONGREGATIONAL_DEFERRED'
    ))
    OR (action = 'TERM_ACTIVATED' AND reason_code = 'TERM_STARTED')
    OR (action = 'ASSIGNMENT_FINALIZED' AND reason_code IN (
      'TERM_COMPLETED_NO_VACANCY','TERM_COMPLETED_OPEN_VACANCY'
    ))
    OR (action = 'ASSIGNMENT_SUBSTITUTED' AND reason_code = 'ASSIGNMENT_REPLACED')
    OR (action = 'VACANCY_OPENED' AND reason_code IN (
      'TERM_COMPLETED_OPEN_VACANCY','ASSIGNMENT_REPLACED'
    ))
  ) NOT VALID;

COMMENT ON COLUMN custodian_device_keys.revocation_reason IS
  'Non-sensitive machine reason code; human justification must be encrypted elsewhere.';
COMMENT ON COLUMN e2ee_key_devices.revoke_reason IS
  'Non-sensitive machine reason code; human justification must be encrypted elsewhere.';
COMMENT ON COLUMN e2ee_key_generations.rotation_reason IS
  'Non-sensitive machine reason code; human justification must be encrypted elsewhere.';
COMMENT ON COLUMN e2ee_key_grants.revoke_reason IS
  'Non-sensitive machine reason code; human justification must be encrypted elsewhere.';
COMMENT ON COLUMN session_decisions.decision_code IS
  'Closed non-sensitive decision vocabulary; narrative evidence belongs only in evidence_envelope.';
COMMENT ON CONSTRAINT assignment_transitions_reason_code_allowed ON assignment_transitions IS
  'Closed vocabulary for the shared transition channel. NOT VALID preserves immutable legacy rows; all new rows are checked.';
