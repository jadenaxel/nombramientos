-- Incremental hardening after the immutable 030 eligibility-scope contract.
-- A single process can be affected by several members in one atomic import.
-- Resolution already accepts a set of incidents; retain one unresolved record
-- per process/member so no changed candidate disappears behind the first pause.
DROP INDEX IF EXISTS member_eligibility_one_active_pause_per_process;
CREATE UNIQUE INDEX IF NOT EXISTS member_eligibility_one_active_pause_per_process_member
  ON member_eligibility_workflow_pauses(process_id, member_id)
  WHERE resolved_at IS NULL;

-- Snapshot writers must always supply the tenant civil date and their explicit
-- eligibility decision. Host-session CURRENT_DATE and implicit false values
-- are not valid operational evidence.
ALTER TABLE cycle_member_snapshots
  ALTER COLUMN eligibility_evaluated_on DROP DEFAULT,
  ALTER COLUMN eligibility_effective DROP DEFAULT;

ALTER TABLE candidate_snapshots
  ALTER COLUMN eligibility_evaluated_on DROP DEFAULT,
  ALTER COLUMN eligibility_effective DROP DEFAULT;

ALTER TABLE candidacies
  ALTER COLUMN eligibility_evaluated_on DROP DEFAULT,
  ALTER COLUMN eligibility_effective_snapshot DROP DEFAULT;

ALTER TABLE candidate_list_entries
  ALTER COLUMN eligibility_evaluated_on DROP DEFAULT,
  ALTER COLUMN eligibility_effective_snapshot DROP DEFAULT;

COMMENT ON INDEX member_eligibility_one_active_pause_per_process_member IS
  'At most one unresolved eligibility incident per process/member; several affected members share one recoverable paused workflow state.';
