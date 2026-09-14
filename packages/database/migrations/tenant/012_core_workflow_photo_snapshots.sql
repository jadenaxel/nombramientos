ALTER TABLE candidacies
  ADD COLUMN photo_snapshot jsonb;

CREATE OR REPLACE FUNCTION preserve_candidacy_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF ROW(
    NEW.process_id,NEW.member_id,NEW.source_aggregate_id,NEW.member_version,
    NEW.display_envelope_snapshot,NEW.photo_snapshot,NEW.distinct_proponent_count,
    NEW.electorate_denominator,NEW.support_denominator,NEW.available_snapshot,
    NEW.already_assigned_count,NEW.created_at
  ) IS DISTINCT FROM ROW(
    OLD.process_id,OLD.member_id,OLD.source_aggregate_id,OLD.member_version,
    OLD.display_envelope_snapshot,OLD.photo_snapshot,OLD.distinct_proponent_count,
    OLD.electorate_denominator,OLD.support_denominator,OLD.available_snapshot,
    OLD.already_assigned_count,OLD.created_at
  ) THEN
    RAISE EXCEPTION 'candidacy evidence is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

COMMENT ON COLUMN candidacies.photo_snapshot IS
  'Optional immutable encrypted photo asset captured at proposal consolidation; preserves historical identity without plaintext.';
