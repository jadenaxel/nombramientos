ALTER TABLE member_eligibility_workflow_pauses
  ADD COLUMN resolution_id uuid,
  ADD COLUMN resolution_code text CHECK (resolution_code IN (
    'ANNUL_AND_RESTART', 'RESUME_UNCHANGED', 'EXCLUDE_AND_REVIEW',
    'CLOSE_AFTER_REPLACEMENT'
  )),
  ADD COLUMN resolution_reason_code text CHECK (
    resolution_reason_code IS NULL OR resolution_reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
  ),
  ADD COLUMN resolution_evidence_envelope jsonb,
  ADD COLUMN resolved_by_identity_id uuid,
  ADD COLUMN replacement_round_id uuid REFERENCES rounds(id) ON DELETE RESTRICT,
  ADD COLUMN replacement_process_id uuid REFERENCES office_processes(id) ON DELETE RESTRICT,
  ADD COLUMN resolution_process_phase text,
  ADD CONSTRAINT member_eligibility_pause_resolution_lifecycle CHECK (
    (
      resolved_at IS NULL
      AND resolution_id IS NULL
      AND resolution_code IS NULL
      AND resolution_reason_code IS NULL
      AND resolution_evidence_envelope IS NULL
      AND resolved_by_identity_id IS NULL
      AND replacement_round_id IS NULL
      AND replacement_process_id IS NULL
      AND resolution_process_phase IS NULL
    )
    OR
    (
      resolved_at IS NOT NULL
      AND resolution_id IS NOT NULL
      AND resolution_code IS NOT NULL
      AND resolution_reason_code IS NOT NULL
      AND resolution_evidence_envelope IS NOT NULL
      AND resolved_by_identity_id IS NOT NULL
      AND resolution_process_phase IS NOT NULL
      AND (
        (resolution_code = 'ANNUL_AND_RESTART' AND replacement_round_id IS NOT NULL AND replacement_process_id IS NULL)
        OR (resolution_code = 'CLOSE_AFTER_REPLACEMENT' AND replacement_round_id IS NULL AND replacement_process_id IS NOT NULL)
        OR (resolution_code NOT IN ('ANNUL_AND_RESTART','CLOSE_AFTER_REPLACEMENT') AND replacement_round_id IS NULL AND replacement_process_id IS NULL)
      )
    )
  );

CREATE FUNCTION protect_member_eligibility_pause_resolution()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.resolved_at IS NOT NULL THEN
    RAISE EXCEPTION 'Resolved eligibility pauses are immutable' USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.cycle_id IS DISTINCT FROM OLD.cycle_id
     OR NEW.process_id IS DISTINCT FROM OLD.process_id
     OR NEW.round_id IS DISTINCT FROM OLD.round_id
     OR NEW.member_id IS DISTINCT FROM OLD.member_id
     OR NEW.member_version IS DISTINCT FROM OLD.member_version
     OR NEW.previous_process_phase IS DISTINCT FROM OLD.previous_process_phase
     OR NEW.previous_round_phase IS DISTINCT FROM OLD.previous_round_phase
     OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
     OR NEW.actor_identity_id IS DISTINCT FROM OLD.actor_identity_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'Eligibility pause incident fields are immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER member_eligibility_pause_resolution_once
BEFORE UPDATE OR DELETE ON member_eligibility_workflow_pauses
FOR EACH ROW EXECUTE FUNCTION protect_member_eligibility_pause_resolution();

INSERT INTO permissions(code, description)
VALUES ('workflow.eligibility.resolve', 'Resolve an eligibility-triggered workflow pause')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code)
SELECT role.id, permission.code
  FROM roles role
  JOIN permissions permission ON permission.code = 'workflow.eligibility.resolve'
 WHERE role.code IN ('CHURCH_ADMIN', 'COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY')
ON CONFLICT DO NOTHING;

UPDATE role_permissions binding
   SET delegable = true
  FROM roles role
 WHERE binding.role_id = role.id
   AND role.code = 'CHURCH_ADMIN'
   AND binding.permission_code = 'workflow.eligibility.resolve';

COMMENT ON TABLE member_eligibility_workflow_pauses IS
  'One-time, auditable eligibility incidents. Resolution preserves frozen rounds; an open round can only be annulled, never resumed or rewritten.';
COMMENT ON COLUMN member_eligibility_workflow_pauses.resolution_evidence_envelope IS
  'Opaque client-encrypted rationale bound by exact AAD to process, pause ids, resolution and reason code.';
