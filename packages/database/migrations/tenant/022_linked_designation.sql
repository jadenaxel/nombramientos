ALTER TABLE assignment_transitions
  DROP CONSTRAINT IF EXISTS assignment_transitions_action_check;

ALTER TABLE assignment_transitions
  ADD CONSTRAINT assignment_transitions_action_check CHECK (action IN (
    'PROVISIONAL_CREATED', 'LINKED_DESIGNATION_CREATED', 'CONSENT_RECORDED',
    'PRESENTED_TO_CHURCH', 'CONGREGATIONAL_DECISION_RECORDED', 'TERM_ACTIVATED',
    'ASSIGNMENT_FINALIZED', 'ASSIGNMENT_SUBSTITUTED', 'VACANCY_OPENED'
  ));

INSERT INTO permissions(code, description)
VALUES ('linked-designation.record', 'Record a linked responsibility from its base assignment')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code)
SELECT role.id, permission.code
  FROM roles role
  JOIN permissions permission ON permission.code = 'linked-designation.record'
 WHERE role.code IN ('CHURCH_ADMIN', 'COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY')
ON CONFLICT DO NOTHING;

UPDATE role_permissions binding
   SET delegable = true
  FROM roles role
 WHERE binding.role_id = role.id
   AND role.code = 'CHURCH_ADMIN'
   AND binding.permission_code = 'linked-designation.record';

COMMENT ON COLUMN assignments.linked_to_assignment_id IS
  'Explicit base assignment for a derived responsibility. A linked designation is independently traceable but does not add independent workload.';
