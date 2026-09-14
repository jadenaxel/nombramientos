ALTER TABLE audit_events
  ADD COLUMN hash_version smallint NOT NULL DEFAULT 1
    CHECK (hash_version IN (1, 2));

COMMENT ON COLUMN audit_events.hash_version IS
  'Version 1 is the legacy content hash. Version 2 also binds id, sequence and occurred_at so ordering and timestamps are tamper-evident.';
