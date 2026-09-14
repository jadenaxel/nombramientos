DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM schema_migrations
     WHERE name = '018_report_artifact_lifecycle.sql'
  ) THEN
    UPDATE report_versions
       SET state = 'expired'
     WHERE state = 'ready';
  END IF;
END
$$;

COMMENT ON TABLE report_versions IS
  'Legacy encrypted artifacts predating authenticated report manifests are retained as historical evidence but expired before the new lifecycle migration.';
