CREATE FUNCTION tenant_invitation_roles_are_valid(candidate text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT cardinality(candidate) BETWEEN 1 AND 3
     AND candidate <@ ARRAY[
       'CHURCH_ADMIN', 'COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY',
       'COMMITTEE_MEMBER', 'TALLY_CUSTODIAN', 'AUDITOR'
     ]::text[]
     AND cardinality(candidate) = (
       SELECT count(DISTINCT role_code)::integer FROM unnest(candidate) AS requested(role_code)
     )
$$;

REVOKE ALL ON FUNCTION tenant_invitation_roles_are_valid(text[]) FROM PUBLIC;

CREATE TABLE tenant_invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  email text NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
  normalized_email text NOT NULL CHECK (
    length(normalized_email) BETWEEN 3 AND 320
    AND normalized_email = lower(btrim(normalized_email))
  ),
  role_codes text[] NOT NULL CHECK (tenant_invitation_roles_are_valid(role_codes)),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending', 'accepting', 'accepted', 'revoked', 'expired', 'failed'
  )),
  idempotency_key uuid NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  created_by_identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  acceptance_id uuid,
  acceptance_identity_id uuid,
  acceptance_started_at timestamptz,
  accepted_at timestamptz,
  consumed_at timestamptz,
  revoked_at timestamptz,
  revoked_by_identity_id uuid REFERENCES platform_identities(id) ON DELETE SET NULL,
  revocation_reason text CHECK (revocation_reason IS NULL OR length(revocation_reason) <= 240),
  last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{2,80}$'),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  UNIQUE (tenant_id, created_by_identity_id, idempotency_key),
  CHECK (expires_at > created_at),
  CHECK (
    status <> 'accepting'
    OR (acceptance_id IS NOT NULL AND acceptance_identity_id IS NOT NULL AND acceptance_started_at IS NOT NULL)
  ),
  CHECK (
    status <> 'accepted'
    OR (acceptance_identity_id IS NOT NULL AND accepted_at IS NOT NULL AND consumed_at IS NOT NULL)
  ),
  CHECK (status <> 'revoked' OR revoked_at IS NOT NULL)
);

CREATE UNIQUE INDEX tenant_invitations_one_open_email
ON tenant_invitations(normalized_email)
WHERE status IN ('pending', 'accepting');

CREATE INDEX tenant_invitations_tenant_created
ON tenant_invitations(tenant_id, created_at DESC, id DESC);

CREATE INDEX tenant_invitations_expiry
ON tenant_invitations(expires_at)
WHERE status IN ('pending', 'accepting');
