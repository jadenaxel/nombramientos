-- Enterprise authentication control plane: passkeys, one-time ceremonies,
-- operation-bound step-up, policy floors, and explicit session assurance.

CREATE OR REPLACE FUNCTION identity_action_requirements_are_valid(p_requirements jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
  action_name text;
  requirement jsonb;
BEGIN
  IF p_requirements IS NULL OR jsonb_typeof(p_requirements) <> 'object' THEN
    RETURN false;
  END IF;

  FOR action_name, requirement IN
    SELECT entry.key, entry.value FROM jsonb_each(p_requirements) AS entry
  LOOP
    IF action_name !~ '^[a-z][a-z0-9._:-]{1,127}$'
       OR jsonb_typeof(requirement) <> 'object'
       OR (requirement - ARRAY['minAal','phishingResistant','stepUpRequired']::text[]) <> '{}'::jsonb
       OR NOT (requirement ? 'minAal')
       OR jsonb_typeof(requirement->'minAal') <> 'number'
       OR (requirement->>'minAal') !~ '^[123]$'
       OR (requirement ? 'phishingResistant'
           AND jsonb_typeof(requirement->'phishingResistant') <> 'boolean')
       OR (requirement ? 'stepUpRequired'
           AND jsonb_typeof(requirement->'stepUpRequired') <> 'boolean') THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END
$$;

CREATE OR REPLACE FUNCTION identity_action_requirements_tighten(
  p_candidate jsonb,
  p_baseline jsonb
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
  action_name text;
  baseline_requirement jsonb;
  candidate_requirement jsonb;
BEGIN
  IF NOT public.identity_action_requirements_are_valid(p_candidate)
     OR NOT public.identity_action_requirements_are_valid(p_baseline) THEN
    RETURN false;
  END IF;

  FOR action_name, baseline_requirement IN
    SELECT entry.key, entry.value FROM jsonb_each(p_baseline) AS entry
  LOOP
    candidate_requirement := p_candidate->action_name;
    IF candidate_requirement IS NULL
       OR (candidate_requirement->>'minAal')::integer < (baseline_requirement->>'minAal')::integer
       OR (COALESCE((baseline_requirement->>'phishingResistant')::boolean, false)
           AND NOT COALESCE((candidate_requirement->>'phishingResistant')::boolean, false))
       OR (COALESCE((baseline_requirement->>'stepUpRequired')::boolean, false)
           AND NOT COALESCE((candidate_requirement->>'stepUpRequired')::boolean, false)) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END
$$;

CREATE OR REPLACE FUNCTION webauthn_rp_id_is_valid(p_rp_id text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
  label text;
BEGIN
  IF p_rp_id IS NULL
     OR p_rp_id <> lower(p_rp_id)
     OR length(p_rp_id) NOT BETWEEN 1 AND 253
     OR p_rp_id ~ '[[:space:]/:]'
     OR p_rp_id ~ '^[0-9]+(\.[0-9]+){3}$' THEN
    RETURN false;
  END IF;
  IF p_rp_id = 'localhost' THEN
    RETURN true;
  END IF;
  IF p_rp_id !~ '\.[a-z]([a-z0-9-]*[a-z0-9])?$' THEN
    RETURN false;
  END IF;
  IF position('.' IN p_rp_id) = 0 THEN
    RETURN false;
  END IF;
  FOREACH label IN ARRAY string_to_array(p_rp_id, '.')
  LOOP
    IF length(label) NOT BETWEEN 1 AND 63
       OR label !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END
$$;

CREATE TABLE identity_policy_baseline (
  policy_key text PRIMARY KEY CHECK (policy_key = 'global'),
  version bigint NOT NULL CHECK (version > 0),
  enforcement_mode text NOT NULL CHECK (enforcement_mode IN ('monitor','enforce')),
  minimum_aal smallint NOT NULL CHECK (minimum_aal BETWEEN 1 AND 3),
  privileged_minimum_aal smallint NOT NULL CHECK (privileged_minimum_aal BETWEEN 2 AND 3),
  require_user_verification boolean NOT NULL,
  require_phishing_resistant_for_privileged boolean NOT NULL,
  require_device_bound_for_privileged boolean NOT NULL,
  require_attestation_for_privileged boolean NOT NULL,
  allow_password boolean NOT NULL,
  allow_totp_fallback boolean NOT NULL,
  allow_recovery_codes boolean NOT NULL,
  allow_synced_passkeys boolean NOT NULL,
  minimum_passkey_count smallint NOT NULL CHECK (minimum_passkey_count BETWEEN 0 AND 10),
  privileged_minimum_passkey_count smallint NOT NULL CHECK (privileged_minimum_passkey_count BETWEEN 1 AND 10),
  maximum_passkeys smallint NOT NULL CHECK (maximum_passkeys BETWEEN 1 AND 20),
  maximum_active_sessions smallint NOT NULL CHECK (maximum_active_sessions BETWEEN 1 AND 100),
  idle_timeout_minutes integer NOT NULL CHECK (idle_timeout_minutes BETWEEN 5 AND 1440),
  absolute_session_minutes integer NOT NULL CHECK (absolute_session_minutes BETWEEN 5 AND 10080),
  step_up_ttl_seconds integer NOT NULL CHECK (step_up_ttl_seconds BETWEEN 60 AND 900),
  action_requirements jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (identity_action_requirements_are_valid(action_requirements)),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (privileged_minimum_aal >= minimum_aal),
  CHECK (privileged_minimum_passkey_count >= minimum_passkey_count),
  CHECK (minimum_passkey_count <= maximum_passkeys),
  CHECK (privileged_minimum_passkey_count <= maximum_passkeys),
  CHECK (idle_timeout_minutes <= absolute_session_minutes)
);

INSERT INTO identity_policy_baseline(
  policy_key,version,enforcement_mode,minimum_aal,privileged_minimum_aal,
  require_user_verification,require_phishing_resistant_for_privileged,
  require_device_bound_for_privileged,require_attestation_for_privileged,
  allow_password,allow_totp_fallback,allow_recovery_codes,allow_synced_passkeys,
  minimum_passkey_count,privileged_minimum_passkey_count,maximum_passkeys,
  maximum_active_sessions,idle_timeout_minutes,absolute_session_minutes,
  step_up_ttl_seconds,action_requirements
) VALUES (
  'global',1,'monitor',2,2,true,true,false,false,
  true,true,true,true,
  1,2,10,10,30,720,300,
  '{
    "platform.tenant.provision":{"minAal":2,"phishingResistant":true,"stepUpRequired":true},
    "platform.tenant.suspend":{"minAal":2,"phishingResistant":true,"stepUpRequired":true},
    "platform.tenant.decommission.schedule":{"minAal":2,"phishingResistant":true,"stepUpRequired":true},
    "platform.tenant.export.download":{"minAal":2,"phishingResistant":true,"stepUpRequired":true},
    "auth.passkey.revoke":{"minAal":2,"phishingResistant":true,"stepUpRequired":true},
    "auth.session.revoke_others":{"minAal":2,"phishingResistant":true,"stepUpRequired":true}
  }'::jsonb
);

CREATE TABLE tenant_identity_policies (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  enforcement_mode text NOT NULL CHECK (enforcement_mode IN ('monitor','enforce')),
  minimum_aal smallint NOT NULL CHECK (minimum_aal BETWEEN 1 AND 3),
  privileged_minimum_aal smallint NOT NULL CHECK (privileged_minimum_aal BETWEEN 2 AND 3),
  require_user_verification boolean NOT NULL,
  require_phishing_resistant_for_privileged boolean NOT NULL,
  require_device_bound_for_privileged boolean NOT NULL,
  require_attestation_for_privileged boolean NOT NULL,
  allow_password boolean NOT NULL,
  allow_totp_fallback boolean NOT NULL,
  allow_recovery_codes boolean NOT NULL,
  allow_synced_passkeys boolean NOT NULL,
  minimum_passkey_count smallint NOT NULL CHECK (minimum_passkey_count BETWEEN 0 AND 10),
  privileged_minimum_passkey_count smallint NOT NULL CHECK (privileged_minimum_passkey_count BETWEEN 1 AND 10),
  maximum_passkeys smallint NOT NULL CHECK (maximum_passkeys BETWEEN 1 AND 20),
  maximum_active_sessions smallint NOT NULL CHECK (maximum_active_sessions BETWEEN 1 AND 100),
  idle_timeout_minutes integer NOT NULL CHECK (idle_timeout_minutes BETWEEN 5 AND 1440),
  absolute_session_minutes integer NOT NULL CHECK (absolute_session_minutes BETWEEN 5 AND 10080),
  step_up_ttl_seconds integer NOT NULL CHECK (step_up_ttl_seconds BETWEEN 60 AND 900),
  action_requirements jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (identity_action_requirements_are_valid(action_requirements)),
  changed_by_identity_id uuid REFERENCES platform_identities(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (privileged_minimum_aal >= minimum_aal),
  CHECK (privileged_minimum_passkey_count >= minimum_passkey_count),
  CHECK (minimum_passkey_count <= maximum_passkeys),
  CHECK (privileged_minimum_passkey_count <= maximum_passkeys),
  CHECK (idle_timeout_minutes <= absolute_session_minutes)
);

CREATE OR REPLACE FUNCTION enforce_tenant_identity_policy_floor()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  baseline public.identity_policy_baseline%ROWTYPE;
BEGIN
  SELECT * INTO STRICT baseline
    FROM public.identity_policy_baseline
   WHERE policy_key = 'global';

  IF (baseline.enforcement_mode = 'enforce' AND NEW.enforcement_mode <> 'enforce')
     OR NEW.minimum_aal < baseline.minimum_aal
     OR NEW.privileged_minimum_aal < baseline.privileged_minimum_aal
     OR (baseline.require_user_verification AND NOT NEW.require_user_verification)
     OR (baseline.require_phishing_resistant_for_privileged
         AND NOT NEW.require_phishing_resistant_for_privileged)
     OR (baseline.require_device_bound_for_privileged
         AND NOT NEW.require_device_bound_for_privileged)
     OR (baseline.require_attestation_for_privileged
         AND NOT NEW.require_attestation_for_privileged)
     OR (NEW.allow_password AND NOT baseline.allow_password)
     OR (NEW.allow_totp_fallback AND NOT baseline.allow_totp_fallback)
     OR (NEW.allow_recovery_codes AND NOT baseline.allow_recovery_codes)
     OR (NEW.allow_synced_passkeys AND NOT baseline.allow_synced_passkeys)
     OR NEW.minimum_passkey_count < baseline.minimum_passkey_count
     OR NEW.privileged_minimum_passkey_count < baseline.privileged_minimum_passkey_count
     OR NEW.maximum_passkeys > baseline.maximum_passkeys
     OR NEW.maximum_active_sessions > baseline.maximum_active_sessions
     OR NEW.idle_timeout_minutes > baseline.idle_timeout_minutes
     OR NEW.absolute_session_minutes > baseline.absolute_session_minutes
     OR NEW.step_up_ttl_seconds > baseline.step_up_ttl_seconds
     OR NOT public.identity_action_requirements_tighten(
       NEW.action_requirements,
       baseline.action_requirements
     ) THEN
    RAISE EXCEPTION 'Tenant identity policy cannot weaken the global security floor'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_identity_policy_security_floor';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER tenant_identity_policy_floor_guard
BEFORE INSERT OR UPDATE ON tenant_identity_policies
FOR EACH ROW EXECUTE FUNCTION enforce_tenant_identity_policy_floor();

CREATE TABLE webauthn_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE CASCADE,
  credential_id text NOT NULL UNIQUE
    CHECK (length(credential_id) BETWEEN 1 AND 2048 AND credential_id ~ '^[A-Za-z0-9_-]+$'),
  public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 16 AND 4096),
  user_handle text NOT NULL
    CHECK (length(user_handle) BETWEEN 1 AND 128 AND user_handle ~ '^[A-Za-z0-9_-]+$'),
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports text[] NOT NULL DEFAULT ARRAY[]::text[]
    CHECK (transports <@ ARRAY['ble','cable','hybrid','internal','nfc','smart-card','usb']::text[]),
  aaguid uuid,
  attachment text CHECK (attachment IN ('platform','cross-platform')),
  device_type text NOT NULL CHECK (device_type IN ('singleDevice','multiDevice')),
  backup_eligible boolean NOT NULL,
  backup_state boolean NOT NULL,
  discoverable boolean NOT NULL DEFAULT true,
  user_verified boolean NOT NULL DEFAULT true,
  attestation_format text CHECK (
    attestation_format IS NULL OR
    (length(attestation_format) BETWEEN 1 AND 32 AND attestation_format ~ '^[A-Za-z0-9._-]+$')
  ),
  trust_level text NOT NULL DEFAULT 'unverified'
    CHECK (trust_level IN ('unverified','self','attested','enterprise_attested')),
  attestation_object_hash text
    CHECK (attestation_object_hash IS NULL OR attestation_object_hash ~ '^[0-9a-f]{64}$'),
  rp_id text NOT NULL CHECK (webauthn_rp_id_is_valid(rp_id)),
  display_name text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 120),
  created_by_session_id uuid REFERENCES auth_sessions(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_used_at timestamptz,
  last_used_session_id uuid REFERENCES auth_sessions(id) ON DELETE SET NULL,
  revoked_at timestamptz,
  revoked_by_identity_id uuid REFERENCES platform_identities(id) ON DELETE SET NULL,
  revocation_reason text CHECK (
    revocation_reason IS NULL OR revocation_reason IN (
      'user_revoked','admin_revoked','compromised','replaced','policy_change'
    )
  ),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK (NOT backup_state OR backup_eligible),
  CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
  CHECK (last_used_at IS NULL OR last_used_at >= created_at)
);

CREATE UNIQUE INDEX webauthn_credentials_active_name
ON webauthn_credentials(identity_id, lower(btrim(display_name)))
WHERE revoked_at IS NULL;

CREATE INDEX webauthn_credentials_active_identity
ON webauthn_credentials(identity_id, created_at, id)
WHERE revoked_at IS NULL;

ALTER TABLE platform_identities
  ADD COLUMN passkey_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN passkey_enrolled_at timestamptz,
  ADD COLUMN strong_auth_enabled boolean
    GENERATED ALWAYS AS (mfa_enabled OR passkey_enabled) STORED;

ALTER TABLE platform_identities
  ADD CONSTRAINT platform_identity_passkey_state_consistent CHECK (
    (passkey_enabled AND passkey_enrolled_at IS NOT NULL)
    OR (NOT passkey_enabled AND passkey_enrolled_at IS NULL)
  );

CREATE TABLE webauthn_ceremonies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  challenge_hash text NOT NULL UNIQUE CHECK (challenge_hash ~ '^[0-9a-f]{64}$'),
  ceremony_type text NOT NULL CHECK (ceremony_type IN ('registration','authentication','step_up')),
  identity_id uuid REFERENCES platform_identities(id) ON DELETE CASCADE,
  tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
  session_id uuid REFERENCES auth_sessions(id) ON DELETE CASCADE,
  purpose text CHECK (
    purpose IS NULL OR (length(purpose) BETWEEN 2 AND 128 AND purpose ~ '^[a-z][a-z0-9._:-]+$')
  ),
  operation_hash text CHECK (operation_hash IS NULL OR operation_hash ~ '^[0-9a-f]{64}$'),
  rp_id text NOT NULL CHECK (webauthn_rp_id_is_valid(rp_id)),
  expected_origin text NOT NULL CHECK (
    length(expected_origin) BETWEEN 8 AND 512
    AND (
      expected_origin ~ '^https://[^[:space:]/]+$'
      OR expected_origin ~ '^http://localhost(:[0-9]{1,5})?$'
    )
  ),
  require_user_verification boolean NOT NULL DEFAULT true,
  policy_version bigint NOT NULL CHECK (policy_version > 0),
  user_agent_hash text CHECK (user_agent_hash IS NULL OR user_agent_hash ~ '^[0-9a-f]{64}$'),
  ip_prefix_hash text CHECK (ip_prefix_hash IS NULL OR ip_prefix_hash ~ '^[0-9a-f]{64}$'),
  attempt_count smallint NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 6),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  failed_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
  CHECK (consumed_at IS NULL OR failed_at IS NULL),
  CHECK (
    (ceremony_type = 'registration'
      AND identity_id IS NOT NULL AND tenant_id IS NOT NULL AND session_id IS NOT NULL
      AND purpose IS NULL AND operation_hash IS NULL)
    OR
    (ceremony_type = 'authentication'
      AND session_id IS NULL AND purpose IS NULL AND operation_hash IS NULL)
    OR
    (ceremony_type = 'step_up'
      AND identity_id IS NOT NULL AND tenant_id IS NOT NULL AND session_id IS NOT NULL
      AND purpose IS NOT NULL AND operation_hash IS NOT NULL)
  )
);

CREATE INDEX webauthn_ceremonies_active_identity
ON webauthn_ceremonies(identity_id, ceremony_type, expires_at)
WHERE consumed_at IS NULL AND failed_at IS NULL;

ALTER TABLE auth_sessions
  DROP CONSTRAINT auth_sessions_assurance_level_check,
  DROP CONSTRAINT auth_session_mfa_assurance_consistent;

ALTER TABLE auth_sessions
  ADD CONSTRAINT auth_sessions_assurance_level_check CHECK (
    assurance_level IN ('enrollment_only','password','mfa','recovery_limited')
  ),
  ADD COLUMN auth_method text NOT NULL DEFAULT 'password'
    CHECK (auth_method IN ('password','totp','recovery_code','passkey','federated','bootstrap')),
  ADD COLUMN aal smallint NOT NULL DEFAULT 1 CHECK (aal BETWEEN 1 AND 3),
  ADD COLUMN phishing_resistant boolean NOT NULL DEFAULT false,
  ADD COLUMN authenticated_credential_id uuid REFERENCES webauthn_credentials(id) ON DELETE SET NULL,
  ADD COLUMN recovery_limited boolean NOT NULL DEFAULT false,
  ADD COLUMN idle_timeout_minutes integer NOT NULL DEFAULT 30
    CHECK (idle_timeout_minutes BETWEEN 5 AND 1440),
  ADD COLUMN idle_expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '30 minutes'),
  ADD COLUMN last_user_agent_hash text
    CHECK (last_user_agent_hash IS NULL OR last_user_agent_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN user_agent_change_count integer NOT NULL DEFAULT 0 CHECK (user_agent_change_count >= 0),
  ADD COLUMN user_agent_context_changed_at timestamptz,
  ADD COLUMN last_ip_prefix_hash text
    CHECK (last_ip_prefix_hash IS NULL OR last_ip_prefix_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN ip_change_count integer NOT NULL DEFAULT 0 CHECK (ip_change_count >= 0),
  ADD COLUMN ip_context_changed_at timestamptz,
  ADD COLUMN device_label text CHECK (
    device_label IS NULL OR length(btrim(device_label)) BETWEEN 1 AND 120
  ),
  ADD COLUMN step_up_verified_at timestamptz,
  ADD COLUMN step_up_method text CHECK (
    step_up_method IS NULL OR step_up_method IN ('passkey','federated')
  ),
  ADD COLUMN step_up_credential_id uuid REFERENCES webauthn_credentials(id) ON DELETE SET NULL,
  ADD COLUMN step_up_purpose text CHECK (
    step_up_purpose IS NULL OR
    (length(step_up_purpose) BETWEEN 2 AND 128 AND step_up_purpose ~ '^[a-z][a-z0-9._:-]+$')
  ),
  ADD COLUMN step_up_operation_hash text CHECK (
    step_up_operation_hash IS NULL OR step_up_operation_hash ~ '^[0-9a-f]{64}$'
  ),
  ADD COLUMN step_up_expires_at timestamptz;

UPDATE auth_sessions
   SET auth_method = CASE assurance_level
     WHEN 'enrollment_only' THEN 'bootstrap'
     WHEN 'mfa' THEN 'totp'
     ELSE 'password'
   END,
       aal = CASE WHEN assurance_level = 'mfa' THEN 2 ELSE 1 END,
       phishing_resistant = false,
       recovery_limited = false,
       idle_expires_at = LEAST(expires_at, clock_timestamp() + interval '30 minutes'),
       last_user_agent_hash = user_agent_hash,
       last_ip_prefix_hash = ip_prefix_hash;

ALTER TABLE auth_sessions
  ADD CONSTRAINT auth_session_mfa_assurance_consistent CHECK (
    (assurance_level = 'mfa' AND mfa_verified_at IS NOT NULL)
    OR (assurance_level <> 'mfa' AND mfa_verified_at IS NULL)
  ),
  ADD CONSTRAINT auth_session_recovery_consistent CHECK (
    (assurance_level = 'recovery_limited'
      AND recovery_limited
      AND auth_method = 'recovery_code'
      AND aal = 1
      AND NOT phishing_resistant
      AND authenticated_credential_id IS NULL)
    OR
    (assurance_level <> 'recovery_limited' AND NOT recovery_limited)
  ),
  ADD CONSTRAINT auth_session_method_assurance_consistent CHECK (
    (auth_method = 'passkey'
      AND assurance_level = 'mfa'
      AND aal >= 2
      AND phishing_resistant
      AND authenticated_credential_id IS NOT NULL)
    OR
    (auth_method = 'totp'
      AND assurance_level = 'mfa'
      AND aal = 2
      AND NOT phishing_resistant
      AND authenticated_credential_id IS NULL)
    OR
    (auth_method = 'recovery_code' AND assurance_level = 'recovery_limited')
    OR
    (auth_method IN ('password','bootstrap')
      AND assurance_level IN ('password','enrollment_only')
      AND aal = 1
      AND NOT phishing_resistant
      AND authenticated_credential_id IS NULL)
    OR
    (auth_method = 'federated'
      AND assurance_level IN ('password','mfa')
      AND authenticated_credential_id IS NULL)
  ),
  ADD CONSTRAINT auth_session_phishing_resistant_aal CHECK (
    NOT phishing_resistant OR aal >= 2
  ),
  ADD CONSTRAINT auth_session_step_up_tuple_complete CHECK (
    (step_up_verified_at IS NULL
      AND step_up_method IS NULL
      AND step_up_credential_id IS NULL
      AND step_up_purpose IS NULL
      AND step_up_operation_hash IS NULL
      AND step_up_expires_at IS NULL)
    OR
    (step_up_verified_at IS NOT NULL
      AND step_up_method IS NOT NULL
      AND step_up_purpose IS NOT NULL
      AND step_up_operation_hash IS NOT NULL
      AND step_up_expires_at IS NOT NULL
      AND step_up_expires_at > step_up_verified_at)
  );

CREATE OR REPLACE FUNCTION normalize_legacy_auth_session_assurance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  -- Pre-015 callers supplied assurance_level but had no method/AAL columns.
  -- Preserve that narrow compatibility without permitting passkey claims:
  -- an omitted legacy MFA tuple can only be normalized to non-phishing TOTP.
  IF NEW.assurance_level = 'mfa'
     AND NEW.auth_method = 'password'
     AND NEW.aal = 1
     AND NOT NEW.phishing_resistant
     AND NEW.authenticated_credential_id IS NULL THEN
    NEW.auth_method := 'totp';
    NEW.aal := 2;
  ELSIF NEW.assurance_level = 'enrollment_only'
        AND NEW.auth_method = 'password' THEN
    NEW.auth_method := 'bootstrap';
  END IF;
  NEW.idle_expires_at := LEAST(NEW.expires_at, NEW.idle_expires_at);
  NEW.last_user_agent_hash := COALESCE(NEW.last_user_agent_hash, NEW.user_agent_hash);
  NEW.last_ip_prefix_hash := COALESCE(NEW.last_ip_prefix_hash, NEW.ip_prefix_hash);
  RETURN NEW;
END
$$;

CREATE TRIGGER auth_session_legacy_assurance_normalizer
BEFORE INSERT ON auth_sessions
FOR EACH ROW EXECUTE FUNCTION normalize_legacy_auth_session_assurance();

CREATE INDEX auth_sessions_active_identity
ON auth_sessions(identity_id, last_seen_at DESC, id)
WHERE revoked_at IS NULL;

CREATE INDEX auth_sessions_active_credential
ON auth_sessions(authenticated_credential_id, expires_at)
WHERE revoked_at IS NULL AND authenticated_credential_id IS NOT NULL;

CREATE TABLE authentication_step_up_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
  credential_id uuid NOT NULL REFERENCES webauthn_credentials(id) ON DELETE CASCADE,
  purpose text NOT NULL
    CHECK (length(purpose) BETWEEN 2 AND 128 AND purpose ~ '^[a-z][a-z0-9._:-]+$'),
  operation_hash text NOT NULL CHECK (operation_hash ~ '^[0-9a-f]{64}$'),
  aal smallint NOT NULL DEFAULT 2 CHECK (aal BETWEEN 2 AND 3),
  phishing_resistant boolean NOT NULL DEFAULT true CHECK (phishing_resistant),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
  CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX authentication_step_up_grants_active_session
ON authentication_step_up_grants(session_id, purpose, operation_hash, expires_at)
WHERE consumed_at IS NULL AND revoked_at IS NULL;

REVOKE ALL ON FUNCTION identity_action_requirements_are_valid(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_action_requirements_tighten(jsonb,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION webauthn_rp_id_is_valid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION enforce_tenant_identity_policy_floor() FROM PUBLIC;
REVOKE ALL ON FUNCTION normalize_legacy_auth_session_assurance() FROM PUBLIC;
REVOKE ALL ON TABLE identity_policy_baseline FROM PUBLIC;
REVOKE ALL ON TABLE tenant_identity_policies FROM PUBLIC;
REVOKE ALL ON TABLE webauthn_credentials FROM PUBLIC;
REVOKE ALL ON TABLE webauthn_ceremonies FROM PUBLIC;
REVOKE ALL ON TABLE authentication_step_up_grants FROM PUBLIC;
