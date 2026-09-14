ALTER TABLE member_import_jobs
  ADD COLUMN IF NOT EXISTS source_file_name text,
  ADD COLUMN IF NOT EXISTS source_sheet_name text NOT NULL DEFAULT 'legacy',
  ADD COLUMN IF NOT EXISTS column_mapping jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS error_report jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1;

ALTER TABLE member_import_jobs
  DROP CONSTRAINT IF EXISTS member_import_jobs_identity_id_source_fingerprint_key;

CREATE UNIQUE INDEX IF NOT EXISTS member_import_jobs_source_selection
  ON member_import_jobs(identity_id, source_fingerprint, source_sheet_name);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'member_import_jobs'::regclass
       AND conname = 'member_import_jobs_source_metadata_check'
  ) THEN
    ALTER TABLE member_import_jobs
      ADD CONSTRAINT member_import_jobs_source_metadata_check CHECK (
        (source_file_name IS NULL OR (length(source_file_name) BETWEEN 1 AND 255 AND source_file_name !~ '[\\/\x00-\x1f]'))
        AND length(source_sheet_name) BETWEEN 1 AND 120
        AND source_sheet_name !~ '[\x00-\x1f]'
        AND jsonb_typeof(column_mapping) = 'object'
        AND jsonb_typeof(error_report) = 'array'
        AND row_count BETWEEN 0 AND 10000
        AND revision > 0
      );
  END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS members_stable_code_casefolded
  ON members(lower(stable_code));
