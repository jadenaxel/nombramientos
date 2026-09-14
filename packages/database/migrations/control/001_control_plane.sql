CREATE TABLE tenants (
  id uuid PRIMARY KEY,
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
  display_name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('demo', 'real')),
  status text NOT NULL CHECK (status IN ('provisioning', 'active', 'suspended', 'failed')),
  timezone text NOT NULL,
  locale text NOT NULL CHECK (locale IN ('es', 'en', 'fr')),
  database_host text NOT NULL DEFAULT '127.0.0.1',
  database_port integer NOT NULL CHECK (database_port BETWEEN 1 AND 65535),
  database_name name NOT NULL UNIQUE,
  runtime_role name NOT NULL UNIQUE,
  runtime_secret_ref text NOT NULL UNIQUE,
  credential_version integer NOT NULL DEFAULT 1 CHECK (credential_version > 0),
  ssl_mode text NOT NULL DEFAULT 'disable' CHECK (ssl_mode IN ('disable', 'require', 'verify-full')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz,
  suspended_at timestamptz,
  CHECK ((status = 'active') = (activated_at IS NOT NULL) OR status <> 'active')
);

CREATE TABLE provisioning_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key uuid NOT NULL UNIQUE,
  tenant_id uuid NOT NULL UNIQUE,
  requested_slug text NOT NULL,
  request_hash text NOT NULL,
  state text NOT NULL CHECK (state IN (
    'requested', 'roles_created', 'database_created', 'migrated', 'seeded', 'active', 'failed'
  )),
  attempt_count integer NOT NULL DEFAULT 0,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz
);

CREATE TABLE platform_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  normalized_email text NOT NULL UNIQUE,
  display_name text NOT NULL,
  password_hash text NOT NULL,
  mfa_enabled boolean NOT NULL DEFAULT false,
  totp_secret_ciphertext text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('invited', 'active', 'locked', 'disabled')),
  failed_login_count integer NOT NULL DEFAULT 0,
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (NOT mfa_enabled OR totp_secret_ciphertext IS NOT NULL)
);

CREATE TABLE tenant_memberships (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('invited', 'active', 'suspended', 'revoked')),
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, identity_id)
);

CREATE UNIQUE INDEX tenant_membership_one_default
ON tenant_memberships(identity_id)
WHERE is_default AND status = 'active';

CREATE TABLE platform_role_bindings (
  identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE CASCADE,
  role_code text NOT NULL CHECK (role_code IN ('platform_admin', 'platform_auditor', 'platform_operator')),
  granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  granted_by uuid REFERENCES platform_identities(id) ON DELETE SET NULL,
  PRIMARY KEY (identity_id, role_code)
);

CREATE TABLE auth_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE CHECK (length(token_hash) = 64),
  csrf_hash text NOT NULL CHECK (length(csrf_hash) = 64),
  identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE CASCADE,
  active_tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_agent_hash text,
  ip_prefix_hash text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revoke_reason text
);

CREATE INDEX auth_sessions_active_lookup ON auth_sessions(token_hash, expires_at)
WHERE revoked_at IS NULL;

CREATE TABLE mfa_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE CHECK (length(token_hash) = 64),
  identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  origin_hash text NOT NULL CHECK (length(origin_hash) = 64),
  user_agent_hash text,
  ip_prefix_hash text,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 10),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE platform_audit_events (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_identity_id uuid REFERENCES platform_identities(id) ON DELETE SET NULL,
  tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
  action text NOT NULL,
  entity_type text,
  entity_id text,
  result text NOT NULL CHECK (result IN ('success', 'denied', 'failure')),
  request_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  previous_hash text,
  event_hash text NOT NULL
);

REVOKE UPDATE, DELETE, TRUNCATE ON platform_audit_events FROM PUBLIC;

CREATE INDEX platform_audit_occurred_at ON platform_audit_events(occurred_at DESC);
CREATE INDEX platform_audit_tenant ON platform_audit_events(tenant_id, occurred_at DESC);
