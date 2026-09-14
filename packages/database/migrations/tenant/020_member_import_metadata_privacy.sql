ALTER TABLE member_import_jobs
  DROP CONSTRAINT IF EXISTS member_import_jobs_source_metadata_check;

ALTER TABLE member_import_jobs
  ADD CONSTRAINT member_import_jobs_source_metadata_check CHECK (
    (source_file_name IS NULL OR source_file_name IN ('roster.csv','roster.xlsx'))
    AND (source_sheet_name = 'legacy' OR source_sheet_name ~ '^sheet-sha256:[0-9a-f]{64}$')
    AND jsonb_typeof(column_mapping) = 'object'
    AND jsonb_typeof(error_report) = 'array'
    AND row_count BETWEEN 0 AND 10000
    AND revision > 0
  );
