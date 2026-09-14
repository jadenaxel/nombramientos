ALTER TABLE election_cycles
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN jurisdiction text NOT NULL DEFAULT 'pending_local_validation',
  ADD COLUMN configuration jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(configuration) = 'object'),
  ADD COLUMN cloned_from_cycle_id uuid REFERENCES election_cycles(id) ON DELETE RESTRICT,
  ADD COLUMN created_by_identity_id uuid,
  ADD COLUMN activated_at timestamptz,
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();

CREATE TABLE cycle_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cycle_id uuid NOT NULL REFERENCES election_cycles(id) ON DELETE RESTRICT,
  sequence integer NOT NULL CHECK (sequence > 0),
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'in_progress', 'closed', 'cancelled')),
  location_envelope jsonb,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (cycle_id, sequence),
  CHECK (ends_at > starts_at)
);

CREATE TABLE cycle_elector_roster (
  cycle_id uuid NOT NULL REFERENCES election_cycles(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL,
  can_propose boolean NOT NULL DEFAULT true,
  can_vote boolean NOT NULL DEFAULT true,
  recused boolean NOT NULL DEFAULT false,
  active boolean NOT NULL DEFAULT true,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  configured_by_identity_id uuid NOT NULL,
  configured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (cycle_id, identity_id),
  CHECK (NOT active OR can_propose OR can_vote OR recused)
);

CREATE UNIQUE INDEX committee_one_active_seat_per_member_cycle
  ON committee_memberships(cycle_id, member_id)
  WHERE status = 'active' AND member_id IS NOT NULL;

CREATE TABLE office_processes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cycle_id uuid NOT NULL REFERENCES election_cycles(id) ON DELETE RESTRICT,
  office_id uuid NOT NULL REFERENCES offices(id) ON DELETE RESTRICT,
  phase text NOT NULL CHECK (phase IN (
    'PENDIENTE', 'CONFIGURADO', 'PROPUESTAS_ABIERTAS', 'PROPUESTAS_CERRADAS',
    'DEPURACION', 'LISTA_CONFIRMADA', 'VOTACION_ABIERTA', 'VOTACION_CERRADA',
    'ESCRUTINIO', 'RESULTADO_INTERNO', 'RECOMENDACION_CONFIRMADA', 'CERRADO',
    'PAUSADO', 'SIN_CANDIDATOS', 'DESEMPATE_PENDIENTE', 'ANULADO',
    'VACANTE_PENDIENTE'
  )),
  vacancy_count integer NOT NULL CHECK (vacancy_count > 0),
  max_proposal_selections integer NOT NULL CHECK (max_proposal_selections > 0),
  max_ballot_selections integer NOT NULL CHECK (max_ballot_selections > 0),
  decision_rule jsonb NOT NULL CHECK (is_valid_tally_decision_rule(decision_rule)),
  abstention_rule text NOT NULL CHECK (abstention_rule IN ('EXCLUDED_FROM_CANDIDATE_TOTALS', 'INCLUDED_IN_ALL_RECEIVED_DENOMINATOR')),
  tiebreak_policy text NOT NULL CHECK (tiebreak_policy IN ('NEW_BALLOT_ROUND', 'DOCUMENTED_HUMAN_RESOLUTION')),
  quorum_rule jsonb NOT NULL CHECK (jsonb_typeof(quorum_rule) = 'object'),
  aggregate_audience text NOT NULL CHECK (aggregate_audience IN ('committee', 'auditor', 'church_after_publication')),
  agenda_order integer NOT NULL CHECK (agenda_order > 0),
  procedure_sequence integer NOT NULL DEFAULT 1 CHECK (procedure_sequence > 0),
  enabled boolean NOT NULL DEFAULT true,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  source_process_id uuid REFERENCES office_processes(id) ON DELETE RESTRICT,
  replacement_for_assignment_id uuid REFERENCES assignments(id) ON DELETE RESTRICT,
  reused_vacancy_id uuid REFERENCES vacancies(id) ON DELETE RESTRICT,
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (cycle_id, office_id, procedure_sequence),
  UNIQUE (cycle_id, agenda_order),
  CHECK (max_ballot_selections <= vacancy_count)
);

ALTER TABLE vacancies
  ADD COLUMN process_id uuid REFERENCES office_processes(id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX vacancies_process_ordinal_unique
  ON vacancies(process_id, ordinal)
  WHERE process_id IS NOT NULL;

ALTER TABLE rounds
  ADD COLUMN process_id uuid REFERENCES office_processes(id) ON DELETE RESTRICT,
  ADD COLUMN workflow_stage text CHECK (workflow_stage IN ('proposal', 'ballot', 'tiebreak')),
  ADD COLUMN configuration_hash text CHECK (configuration_hash IS NULL OR configuration_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN electorate_hash text CHECK (electorate_hash IS NULL OR electorate_hash ~ '^sha256:[0-9a-f]{64}$');

CREATE UNIQUE INDEX rounds_one_submission_stage_per_process
  ON rounds(process_id, workflow_stage)
  WHERE process_id IS NOT NULL AND workflow_stage IN ('proposal', 'ballot');

CREATE TABLE proposal_manifests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  round_id uuid NOT NULL UNIQUE REFERENCES rounds(id) ON DELETE RESTRICT,
  round_version integer NOT NULL CHECK (round_version > 0),
  manifest_hash text NOT NULL UNIQUE CHECK (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  entry_count integer NOT NULL CHECK (entry_count > 0),
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE proposal_manifest_entries (
  manifest_id uuid NOT NULL REFERENCES proposal_manifests(id) ON DELETE RESTRICT,
  position integer NOT NULL CHECK (position > 0),
  receipt_id uuid NOT NULL UNIQUE REFERENCES participation_receipts(id) ON DELETE RESTRICT,
  content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
  submission_round_version integer NOT NULL CHECK (submission_round_version > 0),
  PRIMARY KEY (manifest_id, position),
  UNIQUE (manifest_id, receipt_id)
);

CREATE TABLE proposal_aggregates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  process_id uuid NOT NULL UNIQUE REFERENCES office_processes(id) ON DELETE RESTRICT,
  source_round_id uuid NOT NULL UNIQUE REFERENCES rounds(id) ON DELETE RESTRICT,
  source_manifest_id uuid NOT NULL UNIQUE REFERENCES proposal_manifests(id) ON DELETE RESTRICT,
  aggregate_hash text NOT NULL UNIQUE CHECK (aggregate_hash ~ '^sha256:[0-9a-f]{64}$'),
  completed_responses integer NOT NULL CHECK (completed_responses >= 0),
  electorate_denominator integer NOT NULL CHECK (electorate_denominator > 0),
  effective_response_denominator integer NOT NULL CHECK (effective_response_denominator >= 0),
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (completed_responses <= electorate_denominator),
  CHECK (effective_response_denominator <= completed_responses)
);

CREATE TABLE candidacies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  process_id uuid NOT NULL REFERENCES office_processes(id) ON DELETE RESTRICT,
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
  source_aggregate_id uuid NOT NULL REFERENCES proposal_aggregates(id) ON DELETE RESTRICT,
  member_version integer NOT NULL CHECK (member_version > 0),
  display_envelope_snapshot jsonb NOT NULL,
  state text NOT NULL CHECK (state IN (
    'PROPOSED', 'UNDER_REVIEW', 'PRELIMINARY_ACCEPTED', 'CONFIRMED_FOR_BALLOT',
    'WITHDRAWN', 'EXCLUDED', 'INELIGIBLE'
  )),
  distinct_proponent_count integer NOT NULL CHECK (distinct_proponent_count > 0),
  electorate_denominator integer NOT NULL CHECK (electorate_denominator > 0),
  support_denominator integer NOT NULL CHECK (support_denominator > 0),
  available_snapshot boolean NOT NULL,
  already_assigned_count integer NOT NULL CHECK (already_assigned_count >= 0),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (process_id, member_id),
  CHECK (distinct_proponent_count <= electorate_denominator),
  CHECK (distinct_proponent_count <= support_denominator)
);

CREATE TABLE candidacy_reviews (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  candidacy_id uuid NOT NULL REFERENCES candidacies(id) ON DELETE RESTRICT,
  from_state text NOT NULL,
  to_state text NOT NULL,
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  rationale_envelope jsonb,
  restricted_note_envelope jsonb,
  actor_identity_id uuid NOT NULL,
  candidacy_version integer NOT NULL CHECK (candidacy_version > 1),
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (from_state <> to_state)
);

CREATE INDEX candidacy_reviews_candidacy_time
  ON candidacy_reviews(candidacy_id, decided_at, id);

CREATE TABLE candidate_list_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  process_id uuid NOT NULL REFERENCES office_processes(id) ON DELETE RESTRICT,
  version integer NOT NULL CHECK (version > 0),
  candidate_set_hash text NOT NULL CHECK (candidate_set_hash ~ '^sha256:[0-9a-f]{64}$'),
  rules_hash text NOT NULL CHECK (rules_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (process_id, version),
  UNIQUE (process_id, candidate_set_hash, rules_hash)
);

CREATE TABLE candidate_list_entries (
  list_id uuid NOT NULL REFERENCES candidate_list_versions(id) ON DELETE RESTRICT,
  candidacy_id uuid NOT NULL REFERENCES candidacies(id) ON DELETE RESTRICT,
  candidate_id uuid NOT NULL,
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
  display_envelope_snapshot jsonb NOT NULL,
  visible_order integer NOT NULL CHECK (visible_order > 0),
  PRIMARY KEY (list_id, candidate_id),
  UNIQUE (list_id, candidacy_id),
  UNIQUE (list_id, member_id),
  UNIQUE (list_id, visible_order)
);

ALTER TABLE assignments
  ADD COLUMN cycle_id uuid REFERENCES election_cycles(id) ON DELETE RESTRICT,
  ADD COLUMN office_id uuid REFERENCES offices(id) ON DELETE RESTRICT,
  ADD COLUMN process_id uuid REFERENCES office_processes(id) ON DELETE RESTRICT,
  ADD COLUMN source_round_id uuid REFERENCES rounds(id) ON DELETE RESTRICT,
  ADD COLUMN source_manifest_id uuid REFERENCES tally_manifests(id) ON DELETE RESTRICT,
  ADD COLUMN source_aggregate_hash text CHECK (source_aggregate_hash IS NULL OR source_aggregate_hash ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN source_candidate_id uuid REFERENCES candidacies(id) ON DELETE RESTRICT,
  ADD COLUMN member_snapshot jsonb,
  ADD COLUMN office_snapshot jsonb,
  ADD COLUMN presented_at timestamptz,
  ADD COLUMN started_at timestamptz,
  ADD COLUMN ended_at timestamptz;

UPDATE assignments assignment
   SET cycle_id = vacancy.cycle_id,
       office_id = vacancy.office_id
  FROM vacancies vacancy
 WHERE vacancy.id = assignment.vacancy_id;

ALTER TABLE assignments
  ALTER COLUMN cycle_id SET NOT NULL,
  ALTER COLUMN office_id SET NOT NULL;

CREATE UNIQUE INDEX assignments_one_effective_member_per_office_term
  ON assignments(cycle_id, office_id, member_id)
  WHERE effective;

CREATE TABLE assignment_transitions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assignment_id uuid NOT NULL REFERENCES assignments(id) ON DELETE RESTRICT,
  from_state text,
  to_state text NOT NULL,
  action text NOT NULL CHECK (action IN (
    'PROVISIONAL_CREATED', 'CONSENT_RECORDED', 'PRESENTED_TO_CHURCH',
    'CONGREGATIONAL_DECISION_RECORDED', 'TERM_ACTIVATED', 'ASSIGNMENT_FINALIZED',
    'ASSIGNMENT_SUBSTITUTED', 'VACANCY_OPENED'
  )),
  reason_code text CHECK (reason_code IS NULL OR reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  evidence_envelope jsonb,
  actor_identity_id uuid NOT NULL,
  assignment_version integer NOT NULL CHECK (assignment_version > 0),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX assignment_transitions_assignment_time
  ON assignment_transitions(assignment_id, occurred_at, id);

CREATE UNIQUE INDEX office_processes_one_replacement_per_assignment
  ON office_processes(replacement_for_assignment_id)
  WHERE replacement_for_assignment_id IS NOT NULL;

CREATE OR REPLACE FUNCTION reject_immutable_workflow_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'workflow evidence is immutable' USING ERRCODE = '55000';
END
$$;

CREATE OR REPLACE FUNCTION preserve_assignment_provenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF ROW(
    NEW.vacancy_id,NEW.member_id,NEW.independent,NEW.linked_to_assignment_id,
    NEW.cycle_id,NEW.office_id,NEW.process_id,NEW.source_round_id,NEW.source_manifest_id,
    NEW.source_aggregate_hash,NEW.source_candidate_id,NEW.member_snapshot,NEW.office_snapshot
  ) IS DISTINCT FROM ROW(
    OLD.vacancy_id,OLD.member_id,OLD.independent,OLD.linked_to_assignment_id,
    OLD.cycle_id,OLD.office_id,OLD.process_id,OLD.source_round_id,OLD.source_manifest_id,
    OLD.source_aggregate_hash,OLD.source_candidate_id,OLD.member_snapshot,OLD.office_snapshot
  ) THEN
    RAISE EXCEPTION 'assignment provenance is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION preserve_candidacy_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF ROW(
    NEW.process_id,NEW.member_id,NEW.source_aggregate_id,NEW.member_version,
    NEW.display_envelope_snapshot,NEW.distinct_proponent_count,NEW.electorate_denominator,NEW.support_denominator,
    NEW.available_snapshot,NEW.already_assigned_count,NEW.created_at
  ) IS DISTINCT FROM ROW(
    OLD.process_id,OLD.member_id,OLD.source_aggregate_id,OLD.member_version,
    OLD.display_envelope_snapshot,OLD.distinct_proponent_count,OLD.electorate_denominator,OLD.support_denominator,
    OLD.available_snapshot,OLD.already_assigned_count,OLD.created_at
  ) THEN
    RAISE EXCEPTION 'candidacy evidence is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER assignments_preserve_provenance
BEFORE UPDATE ON assignments
FOR EACH ROW EXECUTE FUNCTION preserve_assignment_provenance();

CREATE TRIGGER candidacies_preserve_evidence
BEFORE UPDATE ON candidacies
FOR EACH ROW EXECUTE FUNCTION preserve_candidacy_evidence();

CREATE TRIGGER proposal_aggregates_immutable
BEFORE UPDATE OR DELETE ON proposal_aggregates
FOR EACH ROW EXECUTE FUNCTION reject_immutable_workflow_evidence();

CREATE TRIGGER proposal_manifests_immutable
BEFORE UPDATE OR DELETE ON proposal_manifests
FOR EACH ROW EXECUTE FUNCTION reject_immutable_workflow_evidence();

CREATE TRIGGER proposal_manifest_entries_immutable
BEFORE UPDATE OR DELETE ON proposal_manifest_entries
FOR EACH ROW EXECUTE FUNCTION reject_immutable_workflow_evidence();

CREATE TRIGGER candidacy_reviews_immutable
BEFORE UPDATE OR DELETE ON candidacy_reviews
FOR EACH ROW EXECUTE FUNCTION reject_immutable_workflow_evidence();

CREATE TRIGGER assignment_transitions_immutable
BEFORE UPDATE OR DELETE ON assignment_transitions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_workflow_evidence();

CREATE TRIGGER candidate_list_versions_immutable
BEFORE UPDATE OR DELETE ON candidate_list_versions
FOR EACH ROW EXECUTE FUNCTION reject_immutable_workflow_evidence();

CREATE TRIGGER candidate_list_entries_immutable
BEFORE UPDATE OR DELETE ON candidate_list_entries
FOR EACH ROW EXECUTE FUNCTION reject_immutable_workflow_evidence();

REVOKE UPDATE, DELETE, TRUNCATE ON proposal_aggregates FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON proposal_manifests FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON proposal_manifest_entries FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON candidacy_reviews FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON assignment_transitions FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON candidate_list_versions FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON candidate_list_entries FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_immutable_workflow_evidence() FROM PUBLIC;
REVOKE ALL ON FUNCTION preserve_assignment_provenance() FROM PUBLIC;
REVOKE ALL ON FUNCTION preserve_candidacy_evidence() FROM PUBLIC;

COMMENT ON TABLE proposal_aggregates IS
  'Contains only aggregate support by candidate. It must never contain an elector-to-preference relation.';
COMMENT ON COLUMN assignments.source_aggregate_hash IS
  'Immutable provenance of a published two-custodian tally aggregate for workflow-created provisional assignments.';
