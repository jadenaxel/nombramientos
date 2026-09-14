-- Operational member eligibility scope. These fields are deliberately
-- structured and non-sensitive: private rationale remains exclusively in the
-- independently encrypted eligibility envelope.
ALTER TABLE members
  ADD COLUMN eligibility_department_id uuid REFERENCES departments(id) ON DELETE RESTRICT,
  ADD COLUMN eligibility_valid_until date;

CREATE INDEX members_operational_eligibility_scope
  ON members(eligibility_department_id, eligibility_valid_until)
  WHERE archived_at IS NULL AND eligibility_status = 'eligible' AND available;

COMMENT ON COLUMN members.eligibility_department_id IS
  'Null means unrestricted. A value permits nomination only for offices whose department_id is exactly this active department id.';
COMMENT ON COLUMN members.eligibility_valid_until IS
  'Inclusive tenant civil date. Null means no automatic expiry. Runtime evaluation uses tenant_settings.timezone.';
COMMENT ON COLUMN members.eligibility_envelope IS
  'Optional E2EE private review rationale. Operational department scope and validity must never be encoded only in this envelope.';

-- Cycle snapshots retain the operational values and the tenant civil date at
-- activation. Existing snapshots predate structured scope and are faithfully
-- represented as unrestricted under their then-current contract.
ALTER TABLE cycle_member_snapshots
  ADD COLUMN eligibility_department_id_snapshot uuid REFERENCES departments(id) ON DELETE RESTRICT,
  ADD COLUMN eligibility_valid_until_snapshot date,
  ADD COLUMN eligibility_evaluated_on date,
  ADD COLUMN eligibility_effective boolean;

UPDATE cycle_member_snapshots snapshot
   SET eligibility_evaluated_on = (snapshot.frozen_at AT TIME ZONE settings.timezone)::date,
       eligibility_effective = (
         snapshot.eligibility_status = 'eligible'
         AND snapshot.available
       )
  FROM tenant_settings settings
 WHERE settings.singleton = true;

ALTER TABLE cycle_member_snapshots
  ALTER COLUMN eligibility_evaluated_on SET NOT NULL,
  ALTER COLUMN eligibility_evaluated_on SET DEFAULT CURRENT_DATE,
  ALTER COLUMN eligibility_effective SET NOT NULL,
  ALTER COLUMN eligibility_effective SET DEFAULT false,
  ADD CONSTRAINT cycle_member_snapshot_effective_base CHECK (
    NOT eligibility_effective OR (eligibility_status = 'eligible' AND available)
  );

-- Every office-specific freeze records the exact scope used to admit the
-- member. The same evidence is copied through candidacy and final-list
-- snapshots so historical review never depends on mutable member rows.
ALTER TABLE candidate_snapshots
  ADD COLUMN member_version_snapshot integer CHECK (member_version_snapshot IS NULL OR member_version_snapshot > 0),
  ADD COLUMN eligibility_department_id_snapshot uuid REFERENCES departments(id) ON DELETE RESTRICT,
  ADD COLUMN eligibility_valid_until_snapshot date,
  ADD COLUMN eligibility_evaluated_on date,
  ADD COLUMN eligibility_effective boolean;

UPDATE candidate_snapshots snapshot
   SET eligibility_evaluated_on = (round_state.created_at AT TIME ZONE settings.timezone)::date,
       eligibility_effective = snapshot.eligible
  FROM rounds round_state
  CROSS JOIN tenant_settings settings
 WHERE round_state.id = snapshot.round_id
   AND settings.singleton = true;

ALTER TABLE candidate_snapshots
  ALTER COLUMN eligibility_evaluated_on SET NOT NULL,
  ALTER COLUMN eligibility_evaluated_on SET DEFAULT CURRENT_DATE,
  ALTER COLUMN eligibility_effective SET NOT NULL,
  ALTER COLUMN eligibility_effective SET DEFAULT false,
  ADD CONSTRAINT candidate_snapshot_effective_base CHECK (
    NOT eligibility_effective OR eligible
  );

ALTER TABLE candidacies
  ADD COLUMN eligibility_department_id_snapshot uuid REFERENCES departments(id) ON DELETE RESTRICT,
  ADD COLUMN eligibility_valid_until_snapshot date,
  ADD COLUMN eligibility_evaluated_on date,
  ADD COLUMN eligibility_effective_snapshot boolean;

UPDATE candidacies candidacy
   SET eligibility_evaluated_on = (candidacy.created_at AT TIME ZONE settings.timezone)::date,
       eligibility_effective_snapshot = candidacy.available_snapshot
  FROM tenant_settings settings
 WHERE settings.singleton = true;

ALTER TABLE candidacies
  ALTER COLUMN eligibility_evaluated_on SET NOT NULL,
  ALTER COLUMN eligibility_evaluated_on SET DEFAULT CURRENT_DATE,
  ALTER COLUMN eligibility_effective_snapshot SET NOT NULL,
  ALTER COLUMN eligibility_effective_snapshot SET DEFAULT false,
  ADD CONSTRAINT candidacy_effective_snapshot_base CHECK (
    NOT eligibility_effective_snapshot OR available_snapshot
  );

ALTER TABLE candidate_list_entries
  ADD COLUMN eligibility_department_id_snapshot uuid REFERENCES departments(id) ON DELETE RESTRICT,
  ADD COLUMN eligibility_valid_until_snapshot date,
  ADD COLUMN eligibility_evaluated_on date,
  ADD COLUMN eligibility_effective_snapshot boolean;

-- Backfill is the sole authorized rewrite of this immutable historical table.
-- The surrounding migration transaction guarantees that the guard is restored
-- if any statement fails.
ALTER TABLE candidate_list_entries DISABLE TRIGGER candidate_list_entries_immutable;

UPDATE candidate_list_entries entry
   SET eligibility_department_id_snapshot = candidacy.eligibility_department_id_snapshot,
       eligibility_valid_until_snapshot = candidacy.eligibility_valid_until_snapshot,
       eligibility_evaluated_on = (list.created_at AT TIME ZONE settings.timezone)::date,
       eligibility_effective_snapshot = candidacy.eligibility_effective_snapshot
  FROM candidate_list_versions list
  JOIN candidacies candidacy ON true
  CROSS JOIN tenant_settings settings
 WHERE list.id = entry.list_id
   AND candidacy.id = entry.candidacy_id
   AND settings.singleton = true;

ALTER TABLE candidate_list_entries ENABLE TRIGGER candidate_list_entries_immutable;

ALTER TABLE candidate_list_entries
  ALTER COLUMN eligibility_evaluated_on SET NOT NULL,
  ALTER COLUMN eligibility_evaluated_on SET DEFAULT CURRENT_DATE,
  ALTER COLUMN eligibility_effective_snapshot SET NOT NULL,
  ALTER COLUMN eligibility_effective_snapshot SET DEFAULT false;

CREATE OR REPLACE FUNCTION preserve_candidacy_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF ROW(
    NEW.process_id,NEW.member_id,NEW.source_aggregate_id,NEW.member_version,
    NEW.display_envelope_snapshot,NEW.photo_snapshot,NEW.distinct_proponent_count,NEW.electorate_denominator,NEW.support_denominator,
    NEW.available_snapshot,NEW.already_assigned_count,NEW.created_at,
    NEW.eligibility_department_id_snapshot,NEW.eligibility_valid_until_snapshot,
    NEW.eligibility_evaluated_on,NEW.eligibility_effective_snapshot
  ) IS DISTINCT FROM ROW(
    OLD.process_id,OLD.member_id,OLD.source_aggregate_id,OLD.member_version,
    OLD.display_envelope_snapshot,OLD.photo_snapshot,OLD.distinct_proponent_count,OLD.electorate_denominator,OLD.support_denominator,
    OLD.available_snapshot,OLD.already_assigned_count,OLD.created_at,
    OLD.eligibility_department_id_snapshot,OLD.eligibility_valid_until_snapshot,
    OLD.eligibility_evaluated_on,OLD.eligibility_effective_snapshot
  ) THEN
    RAISE EXCEPTION 'candidacy evidence is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

COMMENT ON COLUMN cycle_member_snapshots.eligibility_effective IS
  'General eligibility at cycle activation; department compatibility is evaluated separately for each office.';
COMMENT ON COLUMN candidate_snapshots.eligibility_effective IS
  'True only when base, validity, and exact department rules admitted the member to this office-specific round.';
COMMENT ON COLUMN candidacies.eligibility_effective_snapshot IS
  'Immutable structured eligibility decision copied when the opaque proposal aggregate became a candidacy.';
COMMENT ON COLUMN candidate_list_entries.eligibility_effective_snapshot IS
  'Immutable structured eligibility decision copied when the final ballot list was confirmed.';
