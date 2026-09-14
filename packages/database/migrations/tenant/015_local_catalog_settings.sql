ALTER TABLE tenant_settings
  ADD COLUMN jurisdiction text NOT NULL DEFAULT 'pending_local_validation',
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0);

ALTER TABLE departments
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();

ALTER TABLE offices
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();

COMMENT ON COLUMN tenant_settings.jurisdiction IS
  'Tenant-local jurisdiction label; it does not change the immutable normative catalog version.';

COMMENT ON COLUMN tenant_settings.version IS
  'Optimistic concurrency token for tenant-admin settings changes.';

COMMENT ON COLUMN departments.local_extension IS
  'False identifies provisioned canonical catalog material. Tenant-admin APIs may mutate only true rows.';

COMMENT ON COLUMN offices.local_extension IS
  'False identifies provisioned canonical catalog material. Tenant-admin APIs may mutate only true rows.';
