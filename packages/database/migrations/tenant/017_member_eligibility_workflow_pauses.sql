CREATE TABLE member_eligibility_workflow_pauses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cycle_id uuid NOT NULL REFERENCES election_cycles(id) ON DELETE RESTRICT,
  process_id uuid NOT NULL REFERENCES office_processes(id) ON DELETE RESTRICT,
  round_id uuid REFERENCES rounds(id) ON DELETE RESTRICT,
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
  member_version integer NOT NULL CHECK (member_version > 0),
  previous_process_phase text NOT NULL,
  previous_round_phase text,
  reason_code text NOT NULL CHECK (reason_code IN ('MEMBER_ELIGIBILITY_CHANGED','MEMBER_ARCHIVED')),
  actor_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  resolved_at timestamptz,
  CHECK ((round_id IS NULL) = (previous_round_phase IS NULL))
);

CREATE UNIQUE INDEX member_eligibility_one_active_pause_per_process
  ON member_eligibility_workflow_pauses(process_id)
  WHERE resolved_at IS NULL;

COMMENT ON TABLE member_eligibility_workflow_pauses IS
  'Documents automatic workflow pauses caused by eligibility/availability changes without rewriting frozen candidate or electorate snapshots.';
