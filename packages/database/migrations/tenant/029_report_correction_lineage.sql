ALTER TABLE report_versions
  ADD COLUMN supersedes_report_id uuid,
  ADD COLUMN correction_reason_code text,
  ADD COLUMN lineage_root_id uuid,
  ADD COLUMN lineage_revision integer;

UPDATE report_versions
   SET lineage_root_id=id,
       lineage_revision=1;

ALTER TABLE report_versions
  ALTER COLUMN lineage_root_id SET NOT NULL,
  ALTER COLUMN lineage_revision SET NOT NULL,
  ADD CONSTRAINT report_versions_supersedes_fk
    FOREIGN KEY (supersedes_report_id) REFERENCES report_versions(id) ON DELETE RESTRICT,
  ADD CONSTRAINT report_versions_lineage_root_fk
    FOREIGN KEY (lineage_root_id) REFERENCES report_versions(id) ON DELETE RESTRICT,
  ADD CONSTRAINT report_versions_correction_reason_check
    CHECK (correction_reason_code IS NULL OR correction_reason_code IN (
      'SOURCE_DATA_CORRECTED',
      'TRANSLATION_CORRECTED',
      'STRUCTURE_CORRECTED',
      'LAYOUT_CORRECTED',
      'AUTHORIZED_CORRECTION'
    )),
  ADD CONSTRAINT report_versions_lineage_shape_check
    CHECK (
      (lineage_revision=1 AND lineage_root_id=id AND supersedes_report_id IS NULL AND correction_reason_code IS NULL)
      OR
      (lineage_revision>1 AND lineage_root_id<>id AND supersedes_report_id IS NOT NULL AND correction_reason_code IS NOT NULL)
    );

CREATE UNIQUE INDEX report_versions_one_successor_idx
  ON report_versions(supersedes_report_id)
  WHERE supersedes_report_id IS NOT NULL;

CREATE UNIQUE INDEX report_versions_lineage_revision_idx
  ON report_versions(lineage_root_id,lineage_revision);

CREATE INDEX report_versions_lineage_history_idx
  ON report_versions(lineage_root_id,created_at,id);

CREATE OR REPLACE FUNCTION guard_report_version_lineage()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public
AS $$
DECLARE
  previous_report report_versions%ROWTYPE;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.supersedes_report_id IS DISTINCT FROM OLD.supersedes_report_id
      OR NEW.correction_reason_code IS DISTINCT FROM OLD.correction_reason_code
      OR NEW.lineage_root_id IS DISTINCT FROM OLD.lineage_root_id
      OR NEW.lineage_revision IS DISTINCT FROM OLD.lineage_revision THEN
      RAISE EXCEPTION 'report lineage is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.lineage_root_id IS NULL THEN
    NEW.lineage_root_id := NEW.id;
  END IF;
  IF NEW.lineage_revision IS NULL THEN
    NEW.lineage_revision := 1;
  END IF;

  IF NEW.supersedes_report_id IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT * INTO previous_report
    FROM public.report_versions
   WHERE id=NEW.supersedes_report_id
   FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'superseded report does not exist' USING ERRCODE='23503';
  END IF;
  IF previous_report.state<>'ready'
    AND NOT (previous_report.state='failed' AND previous_report.supersedes_report_id IS NOT NULL) THEN
    RAISE EXCEPTION 'only a ready issuance or failed correction may be superseded' USING ERRCODE='23514';
  END IF;
  IF NEW.report_type<>previous_report.report_type
    OR NEW.audience<>previous_report.audience
    OR NEW.locale<>previous_report.locale
    OR NEW.format<>previous_report.format THEN
    RAISE EXCEPTION 'a correction must preserve report type, audience, locale and format' USING ERRCODE='23514';
  END IF;
  IF (NEW.filters - ARRAY['snapshotSha256','snapshotAt'])
    IS DISTINCT FROM (previous_report.filters - ARRAY['snapshotSha256','snapshotAt']) THEN
    RAISE EXCEPTION 'a correction must preserve the report filter scope' USING ERRCODE='23514';
  END IF;
  IF NEW.lineage_root_id<>previous_report.lineage_root_id
    OR NEW.lineage_revision<>previous_report.lineage_revision+1 THEN
    RAISE EXCEPTION 'invalid report lineage root or revision' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION guard_report_version_lineage() FROM PUBLIC;

CREATE TRIGGER report_versions_lineage_guard
BEFORE INSERT OR UPDATE ON report_versions
FOR EACH ROW EXECUTE FUNCTION guard_report_version_lineage();

COMMENT ON COLUMN report_versions.supersedes_report_id IS
  'Immediate prior immutable issuance corrected by this report; one successor keeps the lineage linear.';
COMMENT ON COLUMN report_versions.correction_reason_code IS
  'Closed non-sensitive reason code for a correction; free text and report contents never enter audit metadata.';
COMMENT ON COLUMN report_versions.lineage_root_id IS
  'First issuance in the immutable report lineage.';
COMMENT ON COLUMN report_versions.lineage_revision IS
  'Monotonic document revision inside the report lineage; distinct from row lifecycle version.';
