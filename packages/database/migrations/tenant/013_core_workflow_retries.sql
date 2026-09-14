ALTER TABLE election_cycles
  ADD COLUMN closed_at timestamptz,
  ADD COLUMN archived_at timestamptz;

ALTER TABLE rounds
  ADD COLUMN workflow_attempt integer NOT NULL DEFAULT 1 CHECK (workflow_attempt > 0);

ALTER TABLE assignment_transitions
  ADD COLUMN session_id uuid REFERENCES cycle_sessions(id) ON DELETE RESTRICT;

CREATE INDEX assignment_transitions_session
  ON assignment_transitions(session_id, occurred_at, id)
  WHERE session_id IS NOT NULL;

DROP INDEX IF EXISTS rounds_one_submission_stage_per_process;

CREATE UNIQUE INDEX rounds_process_stage_attempt_unique
  ON rounds(process_id, workflow_stage, workflow_attempt)
  WHERE process_id IS NOT NULL AND workflow_stage IS NOT NULL;

CREATE UNIQUE INDEX rounds_one_pending_workflow_attempt_per_process
  ON rounds(process_id)
  WHERE process_id IS NOT NULL
    AND workflow_stage IS NOT NULL
    AND phase IN (
      'CONFIGURADO', 'PROPUESTAS_ABIERTAS', 'PROPUESTAS_CERRADAS', 'DEPURACION',
      'LISTA_CONFIRMADA', 'VOTACION_ABIERTA', 'VOTACION_CERRADA', 'ESCRUTINIO',
      'RECOMENDACION_CONFIRMADA', 'PAUSADO'
    );

ALTER TABLE proposal_aggregates
  DROP CONSTRAINT IF EXISTS proposal_aggregates_process_id_key;

CREATE INDEX proposal_aggregates_process_created
  ON proposal_aggregates(process_id, created_at DESC, id DESC);

ALTER TABLE candidacies
  DROP CONSTRAINT IF EXISTS candidacies_process_id_member_id_key;

ALTER TABLE candidacies
  ADD CONSTRAINT candidacies_aggregate_member_unique UNIQUE (source_aggregate_id, member_id);

CREATE INDEX candidacies_process_aggregate
  ON candidacies(process_id, source_aggregate_id, created_at, id);

ALTER TABLE candidate_list_versions
  DROP CONSTRAINT IF EXISTS candidate_list_versions_process_id_candidate_set_hash_rules_hash_key;

COMMENT ON COLUMN rounds.workflow_attempt IS
  'Monotonic attempt within process/workflow_stage. Historical attempts remain immutable and discoverable.';

COMMENT ON COLUMN election_cycles.closed_at IS
  'Institutional close timestamp. Closing preserves all workflow evidence and frees the single active-cycle slot.';

COMMENT ON COLUMN election_cycles.archived_at IS
  'Administrative archive timestamp applied only after institutional close.';

COMMENT ON COLUMN assignment_transitions.session_id IS
  'Optional explicit institutional session that witnessed the transition; validated against the assignment cycle before insertion.';
