-- Governed recovery for an accepted initial administrator who lost every
-- invitation enrollment cookie before registering a strong authenticator.
--
-- This is deliberately a separate aggregate.  It never reopens or rewrites an
-- accepted invitation, never grants a role, and can mint only a ten-minute
-- enrollment-only session.  Two different active platform administrators must
-- each consume a WebAuthn operation grant bound to the exact HTTP operation.

CREATE FUNCTION initial_admin_recovery_context_hashes_are_valid(candidate text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  -- Browser preflights and tabs are independent of the much smaller session
  -- rotation budget.  Keep enough roots for realistic concurrent desktop and
  -- mobile hand-offs while retaining a strict, header-safe upper bound.
  SELECT cardinality(candidate) BETWEEN 1 AND 12
     AND cardinality(candidate) = (
       SELECT count(DISTINCT item)::integer FROM unnest(candidate) item
     )
     AND NOT EXISTS (
       SELECT 1 FROM unnest(candidate) item WHERE item !~ '^[0-9a-f]{64}$'
     )
$$;

REVOKE ALL ON FUNCTION initial_admin_recovery_context_hashes_are_valid(text[]) FROM PUBLIC;

CREATE TABLE initial_admin_onboarding_recoveries (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  invitation_id uuid NOT NULL REFERENCES tenant_invitations(id) ON DELETE RESTRICT,
  acceptance_id uuid NOT NULL,
  acceptance_identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE RESTRICT,
  acceptance_attempt integer NOT NULL CHECK (acceptance_attempt > 0),
  authority_epoch bigint NOT NULL CHECK (authority_epoch > 0),
  -- Evidence captured under the requester's signed operation.  A later
  -- authority-finalization marker may advance the invitation version once;
  -- every effective fence below therefore uses the immutable tuple/epoch and
  -- requires authority_finalized_at rather than requiring version equality.
  source_invitation_version integer NOT NULL CHECK (source_invitation_version > 0),

  requester_identity_id uuid NOT NULL REFERENCES platform_identities(id) ON DELETE RESTRICT,
  requester_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
  requester_step_up_grant_id uuid NOT NULL UNIQUE
    REFERENCES authentication_step_up_grants(id) ON DELETE RESTRICT,
  requester_operation_hash text NOT NULL CHECK (requester_operation_hash ~ '^[0-9a-f]{64}$'),
  idempotency_key uuid NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  reason_code text NOT NULL CHECK (reason_code IN (
    'browser_context_lost','browser_profile_reset','device_lost','session_delivery_failure'
  )),
  case_reference_hash text NOT NULL CHECK (case_reference_hash ~ '^[0-9a-f]{64}$'),

  approver_identity_id uuid REFERENCES platform_identities(id) ON DELETE RESTRICT,
  approver_session_id uuid REFERENCES auth_sessions(id) ON DELETE RESTRICT,
  approver_step_up_grant_id uuid UNIQUE
    REFERENCES authentication_step_up_grants(id) ON DELETE RESTRICT,
  approver_operation_hash text CHECK (
    approver_operation_hash IS NULL OR approver_operation_hash ~ '^[0-9a-f]{64}$'
  ),

  status text NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending','finalization_pending','enrollment_pending','admin_active',
    'revoked','expired','failed'
  )),
  delivery_channel text CHECK (
    delivery_channel IS NULL OR delivery_channel IN (
      'local_console','verified_email','verified_sms','service_desk'
    )
  ),
  delivery_state text NOT NULL DEFAULT 'not_started' CHECK (delivery_state IN (
    'not_started','pending','delivered','failed'
  )),
  delivery_reference_hash text CHECK (
    delivery_reference_hash IS NULL OR delivery_reference_hash ~ '^[0-9a-f]{64}$'
  ),
  delivery_receipt_hash text CHECK (
    delivery_receipt_hash IS NULL OR delivery_receipt_hash ~ '^[0-9a-f]{64}$'
  ),
  -- Both possession values are verifier-only.  Raw recovery/context/session
  -- material is never persisted in PostgreSQL.
  token_hash text UNIQUE CHECK (token_hash IS NULL OR token_hash ~ '^[0-9a-f]{64}$'),
  browser_context_hashes text[] CHECK (
    browser_context_hashes IS NULL
    OR initial_admin_recovery_context_hashes_are_valid(browser_context_hashes)
  ),
  precommit_user_agent_hash text CHECK (
    precommit_user_agent_hash IS NULL OR precommit_user_agent_hash ~ '^[0-9a-f]{64}$'
  ),
  precommit_ip_prefix_hash text CHECK (
    precommit_ip_prefix_hash IS NULL OR precommit_ip_prefix_hash ~ '^[0-9a-f]{64}$'
  ),

  requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  request_expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  delivery_confirmed_at timestamptz,
  token_expires_at timestamptz,
  token_consumed_at timestamptz,
  browser_context_expires_at timestamptz,
  first_redeemed_at timestamptz,
  last_redeemed_at timestamptz,
  redemption_count smallint NOT NULL DEFAULT 0 CHECK (redemption_count BETWEEN 0 AND 4),
  redeemed_session_id uuid REFERENCES auth_sessions(id) ON DELETE SET NULL,
  revoked_session_count integer NOT NULL DEFAULT 0 CHECK (revoked_session_count >= 0),
  revoked_mfa_challenge_count integer NOT NULL DEFAULT 0 CHECK (revoked_mfa_challenge_count >= 0),
  revoked_step_up_grant_count integer NOT NULL DEFAULT 0 CHECK (revoked_step_up_grant_count >= 0),
  revoked_webauthn_ceremony_count integer NOT NULL DEFAULT 0 CHECK (revoked_webauthn_ceremony_count >= 0),
  strong_factor_finalized_at timestamptz,
  revoked_at timestamptz,
  revoked_by_identity_id uuid REFERENCES platform_identities(id) ON DELETE RESTRICT,
  revocation_reason_code text CHECK (
    revocation_reason_code IS NULL OR revocation_reason_code IN (
      'security_response','requester_cancelled','delivery_reissue','governance_invalidated'
    )
  ),
  failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[A-Z0-9_]{2,80}$'),

  last_transition_action text NOT NULL CHECK (last_transition_action IN (
    'requested','approved','delivery_confirmed','delivery_failed','redeemed',
    'session_rotated','revoked','expired','strong_factor_finalized'
  )),
  last_transition_actor_identity_id uuid REFERENCES platform_identities(id) ON DELETE SET NULL,
  last_transition_request_id uuid,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),

  UNIQUE (requester_identity_id,idempotency_key),
  CHECK (request_expires_at > requested_at AND request_expires_at <= requested_at + interval '24 hours'),
  CHECK (requester_identity_id <> acceptance_identity_id),
  CHECK (approver_identity_id IS NULL OR approver_identity_id <> requester_identity_id),
  CHECK (approver_identity_id IS NULL OR approver_identity_id <> acceptance_identity_id),
  CHECK (approver_step_up_grant_id IS NULL OR approver_step_up_grant_id <> requester_step_up_grant_id),
  CHECK (
    (approver_identity_id IS NULL AND approver_session_id IS NULL
      AND approver_step_up_grant_id IS NULL AND approver_operation_hash IS NULL
      AND approved_at IS NULL AND token_hash IS NULL AND token_expires_at IS NULL
      AND delivery_channel IS NULL AND delivery_reference_hash IS NULL)
    OR
    (approver_identity_id IS NOT NULL AND approver_session_id IS NOT NULL
      AND approver_step_up_grant_id IS NOT NULL AND approver_operation_hash IS NOT NULL
      AND approved_at IS NOT NULL AND token_hash IS NOT NULL AND token_expires_at IS NOT NULL
      AND delivery_channel IS NOT NULL AND delivery_reference_hash IS NOT NULL)
  ),
  CHECK (
    (delivery_state = 'not_started'
      AND delivery_confirmed_at IS NULL AND delivery_receipt_hash IS NULL)
    OR (delivery_state = 'pending'
      AND delivery_confirmed_at IS NULL AND delivery_receipt_hash IS NULL)
    OR (delivery_state = 'delivered'
      AND delivery_confirmed_at IS NOT NULL AND delivery_receipt_hash IS NOT NULL)
    OR (delivery_state = 'failed'
      AND delivery_confirmed_at IS NULL)
  ),
  CHECK (
    token_expires_at IS NULL
    OR (approved_at IS NOT NULL AND token_expires_at > approved_at
      AND token_expires_at <= approved_at + interval '30 minutes'
      AND token_expires_at <= request_expires_at)
  ),
  CHECK (
    (browser_context_hashes IS NULL AND browser_context_expires_at IS NULL
      AND token_consumed_at IS NULL)
    OR (browser_context_hashes IS NOT NULL AND browser_context_expires_at IS NOT NULL
      AND token_consumed_at IS NOT NULL AND token_expires_at IS NOT NULL
      AND browser_context_expires_at <= token_expires_at)
  ),
  CHECK (
    (redemption_count = 0 AND first_redeemed_at IS NULL AND last_redeemed_at IS NULL
      AND redeemed_session_id IS NULL)
    OR (redemption_count > 0 AND first_redeemed_at IS NOT NULL AND last_redeemed_at IS NOT NULL
      AND redeemed_session_id IS NOT NULL AND last_redeemed_at >= first_redeemed_at)
  ),
  CHECK (
    status <> 'pending'
    OR (delivery_state = 'not_started' AND approver_identity_id IS NULL
      AND browser_context_hashes IS NULL AND redemption_count = 0)
  ),
  CHECK (
    status <> 'finalization_pending'
    OR (approver_identity_id IS NOT NULL AND delivery_state IN ('pending','delivered')
      AND browser_context_hashes IS NULL AND redemption_count = 0)
  ),
  CHECK (
    status <> 'enrollment_pending'
    OR (delivery_state = 'delivered' AND browser_context_hashes IS NOT NULL
      AND token_consumed_at IS NOT NULL AND redemption_count > 0)
  ),
  CHECK (
    status <> 'admin_active'
    OR (delivery_state = 'delivered' AND redemption_count > 0
      AND strong_factor_finalized_at IS NOT NULL)
  ),
  CHECK (status <> 'revoked' OR (
    revoked_at IS NOT NULL AND revocation_reason_code IS NOT NULL
    AND (
      (revocation_reason_code='governance_invalidated' AND revoked_by_identity_id IS NULL)
      OR (revocation_reason_code<>'governance_invalidated' AND revoked_by_identity_id IS NOT NULL)
    )
  )),
  CHECK (status <> 'failed' OR failure_code IS NOT NULL),
  CHECK (strong_factor_finalized_at IS NULL OR status = 'admin_active')
);

CREATE UNIQUE INDEX initial_admin_onboarding_recovery_one_open_source
  ON initial_admin_onboarding_recoveries(tenant_id,acceptance_identity_id)
  WHERE status IN ('pending','finalization_pending','enrollment_pending');

CREATE INDEX initial_admin_onboarding_recovery_expiry
  ON initial_admin_onboarding_recoveries(request_expires_at,token_expires_at,browser_context_expires_at)
  WHERE status IN ('pending','finalization_pending','enrollment_pending');

CREATE INDEX initial_admin_onboarding_recovery_source
  ON initial_admin_onboarding_recoveries(
    invitation_id,acceptance_id,acceptance_identity_id,acceptance_attempt,authority_epoch
  );

REVOKE ALL ON TABLE initial_admin_onboarding_recoveries FROM PUBLIC;

-- Mark the exact provenance of sessions minted by this recovery aggregate.
-- The ordinary runtime INSERT grant intentionally excludes all three source
-- columns; only the SECURITY DEFINER redemption function below may populate
-- them.
ALTER TABLE auth_sessions
  ADD COLUMN initial_admin_onboarding_recovery_id uuid
    REFERENCES initial_admin_onboarding_recoveries(id) ON DELETE RESTRICT;

ALTER TABLE auth_sessions
  DROP CONSTRAINT auth_session_enrollment_source_consistent,
  ADD CONSTRAINT auth_session_enrollment_source_consistent CHECK (
    (enrollment_source IS NULL AND invitation_id IS NULL
      AND initial_admin_onboarding_recovery_id IS NULL)
    OR (
      enrollment_source = 'invitation'
      AND invitation_id IS NOT NULL
      AND initial_admin_onboarding_recovery_id IS NULL
      AND assurance_level = 'enrollment_only'
      AND auth_method = 'bootstrap'
      AND aal = 1
      AND NOT phishing_resistant
      AND NOT recovery_limited
      AND authenticated_credential_id IS NULL
      AND mfa_verified_at IS NULL
      AND idle_timeout_minutes <= 10
      AND idle_expires_at <= expires_at
      AND expires_at <= created_at + interval '10 minutes'
    )
    OR (
      enrollment_source = 'initial_admin_recovery'
      AND invitation_id IS NOT NULL
      AND initial_admin_onboarding_recovery_id IS NOT NULL
      AND assurance_level = 'enrollment_only'
      AND auth_method = 'bootstrap'
      AND aal = 1
      AND NOT phishing_resistant
      AND NOT recovery_limited
      AND authenticated_credential_id IS NULL
      AND mfa_verified_at IS NULL
      AND idle_timeout_minutes <= 10
      AND idle_expires_at <= expires_at
      AND expires_at <= created_at + interval '10 minutes'
    )
  );

CREATE UNIQUE INDEX auth_sessions_one_initial_admin_recovery_active
  ON auth_sessions(initial_admin_onboarding_recovery_id)
  WHERE initial_admin_onboarding_recovery_id IS NOT NULL AND revoked_at IS NULL;

-- Replace the 019 guard so both enrollment provenance variants are checked.
CREATE OR REPLACE FUNCTION guard_invitation_enrollment_session_source()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.enrollment_source = 'invitation' AND NOT EXISTS (
    SELECT 1
      FROM public.tenant_invitations invitation
     WHERE invitation.id=NEW.invitation_id
       AND invitation.tenant_id=NEW.active_tenant_id
       AND invitation.acceptance_identity_id=NEW.identity_id
       AND invitation.status='accepted'
       AND invitation.consumed_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Invitation enrollment session must bind to its accepted invitation'
      USING ERRCODE = '23514', CONSTRAINT = 'auth_sessions_invitation_enrollment_source_guard';
  END IF;
  IF NEW.enrollment_source = 'initial_admin_recovery' AND NOT EXISTS (
    SELECT 1
      FROM public.initial_admin_onboarding_recoveries recovery
      JOIN public.tenant_invitations invitation
        ON invitation.id=recovery.invitation_id
       AND invitation.tenant_id=recovery.tenant_id
       AND invitation.acceptance_id=recovery.acceptance_id
       AND invitation.acceptance_identity_id=recovery.acceptance_identity_id
       AND invitation.acceptance_attempt=recovery.acceptance_attempt
       AND invitation.authority_epoch=recovery.authority_epoch
     WHERE recovery.id=NEW.initial_admin_onboarding_recovery_id
       AND recovery.invitation_id=NEW.invitation_id
       AND recovery.tenant_id=NEW.active_tenant_id
       AND recovery.acceptance_identity_id=NEW.identity_id
       AND recovery.status IN ('finalization_pending','enrollment_pending')
       AND invitation.status='accepted'
       AND invitation.authority_kind='initial_admin'
       AND invitation.authority_finalized_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Initial-admin recovery session has invalid provenance'
      USING ERRCODE = '23514', CONSTRAINT = 'auth_sessions_initial_admin_recovery_source_guard';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER auth_sessions_invitation_enrollment_source_guard ON auth_sessions;
CREATE TRIGGER auth_sessions_invitation_enrollment_source_guard
BEFORE INSERT OR UPDATE OF
  enrollment_source,invitation_id,initial_admin_onboarding_recovery_id,identity_id,active_tenant_id
ON auth_sessions
FOR EACH ROW EXECUTE FUNCTION guard_invitation_enrollment_session_source();

-- Lock and revalidate an administrator's complete authority tuple.  Recovery
-- transitions retain these locks until commit, so disabling the identity,
-- revoking the role/membership, suspending the tenant, or revoking the session
-- cannot race a governed mutation.
CREATE FUNCTION lock_initial_admin_recovery_platform_admin(
  p_actor_identity_id uuid,
  p_actor_session_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE locked_identity_id uuid; locked_session_id uuid;
BEGIN
  IF p_actor_identity_id IS NULL OR p_actor_session_id IS NULL THEN
    RETURN false;
  END IF;
  SELECT actor.id INTO locked_identity_id
    FROM public.platform_identities actor
    JOIN public.platform_role_bindings role_binding
      ON role_binding.identity_id=actor.id AND role_binding.role_code='platform_admin'
   WHERE actor.id=p_actor_identity_id AND actor.status='active'
   FOR UPDATE OF actor,role_binding;
  IF locked_identity_id IS NULL THEN
    RETURN false;
  END IF;
  SELECT session.id INTO locked_session_id
    FROM public.auth_sessions session
    JOIN public.tenants session_tenant
      ON session_tenant.id=session.active_tenant_id AND session_tenant.status='active'
    JOIN public.tenant_memberships session_membership
      ON session_membership.tenant_id=session_tenant.id
     AND session_membership.identity_id=p_actor_identity_id
     AND session_membership.status='active'
   WHERE session.id=p_actor_session_id
     AND session.identity_id=p_actor_identity_id
     AND session.revoked_at IS NULL
     AND session.expires_at>clock_timestamp()
     AND session.idle_expires_at>clock_timestamp()
     AND session.assurance_level NOT IN ('enrollment_only','recovery_limited')
     AND NOT session.recovery_limited
   FOR UPDATE OF session,session_tenant,session_membership;
  RETURN locked_session_id IS NOT NULL;
END
$$;

REVOKE ALL ON FUNCTION lock_initial_admin_recovery_platform_admin(uuid,uuid) FROM PUBLIC;

-- Every governed mutation consumes an already-issued WebAuthn grant inside
-- the same transaction.  The actor authority tuple is locked first, followed
-- by the exact grant and active credential, preventing credential/role/session
-- revocation from racing either half of dual control.
CREATE FUNCTION consume_initial_admin_recovery_step_up(
  p_actor_identity_id uuid,
  p_actor_session_id uuid,
  p_grant_token_hash text,
  p_operation_hash text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  consumed_grant_id uuid;
  locked_grant_id uuid;
BEGIN
  IF p_actor_identity_id IS NULL OR p_actor_session_id IS NULL
     OR p_grant_token_hash IS NULL OR p_grant_token_hash !~ '^[0-9a-f]{64}$'
     OR p_operation_hash IS NULL OR p_operation_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Initial-admin recovery step-up input is invalid'
      USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_step_up_input';
  END IF;

  IF NOT public.lock_initial_admin_recovery_platform_admin(
    p_actor_identity_id,p_actor_session_id
  ) THEN
    RAISE EXCEPTION 'A fresh WebAuthn operation grant is required'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_step_up_invalid';
  END IF;

  SELECT grant_record.id INTO locked_grant_id
    FROM public.authentication_step_up_grants grant_record
    JOIN public.auth_sessions session
      ON session.id=grant_record.session_id
     AND session.identity_id=grant_record.identity_id
     AND session.active_tenant_id=grant_record.tenant_id
    JOIN public.webauthn_credentials credential
      ON credential.id=grant_record.credential_id
     AND credential.identity_id=grant_record.identity_id
   WHERE grant_record.token_hash=p_grant_token_hash
     AND grant_record.identity_id=p_actor_identity_id
     AND grant_record.session_id=p_actor_session_id
     AND grant_record.purpose='platform_administration'
     AND grant_record.operation_hash=p_operation_hash
     AND grant_record.aal>=2
     AND grant_record.phishing_resistant
     AND grant_record.consumed_at IS NULL
     AND grant_record.revoked_at IS NULL
     AND grant_record.expires_at>clock_timestamp()
     AND credential.revoked_at IS NULL
     AND credential.user_verified
     AND NOT EXISTS (
       SELECT 1 FROM public.tenant_identity_policies current_policy
        WHERE current_policy.tenant_id=grant_record.tenant_id
          AND current_policy.updated_at>grant_record.created_at
     )
     AND NOT EXISTS (
       SELECT 1 FROM public.identity_policy_baseline baseline
        WHERE baseline.policy_key='global' AND baseline.updated_at>grant_record.created_at
     )
   FOR UPDATE OF grant_record,session,credential;

  IF locked_grant_id IS NULL THEN
    RAISE EXCEPTION 'A fresh WebAuthn operation grant is required'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_step_up_invalid';
  END IF;

  UPDATE public.authentication_step_up_grants grant_record
     SET consumed_at=clock_timestamp()
   WHERE grant_record.id=locked_grant_id
     AND grant_record.consumed_at IS NULL AND grant_record.revoked_at IS NULL
  RETURNING grant_record.id INTO consumed_grant_id;

  IF consumed_grant_id IS NULL THEN
    RAISE EXCEPTION 'A fresh WebAuthn operation grant is required'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_step_up_invalid';
  END IF;
  RETURN consumed_grant_id;
END
$$;

REVOKE ALL ON FUNCTION consume_initial_admin_recovery_step_up(uuid,uuid,text,text) FROM PUBLIC;

-- A low-volume emergency workflow is intentionally serialized globally.  It
-- provides one deterministic lock order across requester, approver, bearer
-- redemption, revocation, identity factor enrollment, and lazy expiry.
CREATE FUNCTION lock_initial_admin_recovery_workflow()
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT pg_advisory_xact_lock(hashtextextended('initial_admin_onboarding_recovery',0))
$$;

REVOKE ALL ON FUNCTION lock_initial_admin_recovery_workflow() FROM PUBLIC;

-- Terminal containment used when dual-control authority disappears or an
-- authorized administrator explicitly revokes the workflow.  All target
-- authentication artifacts are invalidated; requester/approver state is not
-- touched.  A NULL actor is reserved for autonomous governance invalidation.
CREATE FUNCTION terminate_initial_admin_onboarding_recovery(
  p_recovery_id uuid,
  p_actor_identity_id uuid,
  p_reason_code text,
  p_request_id uuid
)
RETURNS TABLE(
  recovery_version integer,sessions_revoked integer,mfa_challenges_revoked integer,
  step_up_grants_revoked integer,webauthn_ceremonies_revoked integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  recovery_record record;
  revoked_sessions integer := 0;
  revoked_mfa_challenges integer := 0;
  revoked_step_up_grants integer := 0;
  revoked_webauthn_ceremonies integer := 0;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_recovery_id IS NULL OR p_request_id IS NULL
     OR p_reason_code IS NULL OR p_reason_code NOT IN (
       'security_response','requester_cancelled','delivery_reissue','governance_invalidated'
     )
     OR (p_reason_code='governance_invalidated' AND p_actor_identity_id IS NOT NULL)
     OR (p_reason_code<>'governance_invalidated' AND p_actor_identity_id IS NULL) THEN
    RAISE EXCEPTION 'Initial-admin recovery termination input is invalid'
      USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_termination_input';
  END IF;
  SELECT recovery.* INTO recovery_record
    FROM public.initial_admin_onboarding_recoveries recovery
   WHERE recovery.id=p_recovery_id
   FOR UPDATE;
  IF NOT FOUND OR recovery_record.status NOT IN (
    'pending','finalization_pending','enrollment_pending'
  ) THEN
    RETURN;
  END IF;
  PERFORM identity.id
    FROM public.platform_identities identity
   WHERE identity.id=recovery_record.acceptance_identity_id
   FOR UPDATE;
  UPDATE public.authentication_step_up_grants grant_record
     SET revoked_at=COALESCE(grant_record.revoked_at,clock_timestamp())
   WHERE grant_record.identity_id=recovery_record.acceptance_identity_id
     AND grant_record.consumed_at IS NULL AND grant_record.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_step_up_grants=ROW_COUNT;
  UPDATE public.mfa_challenges challenge
     SET consumed_at=COALESCE(challenge.consumed_at,clock_timestamp())
   WHERE challenge.identity_id=recovery_record.acceptance_identity_id
     AND challenge.consumed_at IS NULL;
  GET DIAGNOSTICS revoked_mfa_challenges=ROW_COUNT;
  UPDATE public.webauthn_ceremonies ceremony
     SET failed_at=COALESCE(ceremony.failed_at,clock_timestamp())
   WHERE ceremony.identity_id=recovery_record.acceptance_identity_id
     AND ceremony.consumed_at IS NULL AND ceremony.failed_at IS NULL;
  GET DIAGNOSTICS revoked_webauthn_ceremonies=ROW_COUNT;
  UPDATE public.auth_sessions session
     SET revoked_at=clock_timestamp(),revoke_reason='initial_admin_recovery_revoked'
   WHERE session.identity_id=recovery_record.acceptance_identity_id
     AND session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_sessions=ROW_COUNT;
  UPDATE public.initial_admin_onboarding_recoveries recovery
     SET status='revoked',revoked_at=clock_timestamp(),
         revoked_by_identity_id=p_actor_identity_id,revocation_reason_code=p_reason_code,
         revoked_session_count=recovery.revoked_session_count+revoked_sessions,
         revoked_mfa_challenge_count=recovery.revoked_mfa_challenge_count+revoked_mfa_challenges,
         revoked_step_up_grant_count=recovery.revoked_step_up_grant_count+revoked_step_up_grants,
         revoked_webauthn_ceremony_count=
           recovery.revoked_webauthn_ceremony_count+revoked_webauthn_ceremonies,
         version=recovery.version+1,last_transition_action='revoked',
         last_transition_actor_identity_id=p_actor_identity_id,
         last_transition_request_id=p_request_id
   WHERE recovery.id=p_recovery_id;
  RETURN QUERY SELECT recovery_record.version+1,revoked_sessions,revoked_mfa_challenges,
    revoked_step_up_grants,revoked_webauthn_ceremonies;
END
$$;

REVOKE ALL ON FUNCTION terminate_initial_admin_onboarding_recovery(uuid,uuid,text,uuid) FROM PUBLIC;

-- First statement of every TOTP/passkey enrollment transaction.  It always
-- acquires the global recovery advisory lock, including for original
-- invitation sessions, so approval cannot race factor persistence.  For a
-- recovery session it then locks recovery/source before identities and keeps
-- both administrators' authority locked through the caller's transaction.
CREATE FUNCTION authorize_initial_admin_recovery_factor_transaction(
  p_source_enrollment_session_id uuid,
  p_request_id uuid
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE recovery_record record; termination_record record;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_source_enrollment_session_id IS NULL OR p_request_id IS NULL THEN
    RAISE EXCEPTION 'Strong-factor transaction context is invalid'
      USING ERRCODE='23514';
  END IF;
  SELECT recovery.* INTO recovery_record
    FROM public.auth_sessions source_session
    JOIN public.initial_admin_onboarding_recoveries recovery
      ON recovery.id=source_session.initial_admin_onboarding_recovery_id
     AND recovery.redeemed_session_id=source_session.id
     AND recovery.invitation_id=source_session.invitation_id
     AND recovery.acceptance_identity_id=source_session.identity_id
     AND recovery.tenant_id=source_session.active_tenant_id
   WHERE source_session.id=p_source_enrollment_session_id
     AND source_session.enrollment_source='initial_admin_recovery'
   FOR UPDATE OF recovery,source_session;
  IF NOT FOUND THEN
    RETURN 'not_recovery';
  END IF;
  IF recovery_record.status<>'enrollment_pending'
     OR recovery_record.browser_context_expires_at<=clock_timestamp()
     OR NOT EXISTS (
       SELECT 1 FROM public.auth_sessions source_session
        WHERE source_session.id=p_source_enrollment_session_id
          AND source_session.revoked_at IS NULL
          AND source_session.expires_at>clock_timestamp()
          AND source_session.idle_expires_at>clock_timestamp()
          AND source_session.assurance_level='enrollment_only'
     ) THEN
    RETURN 'unavailable';
  END IF;
  IF NOT public.lock_initial_admin_recovery_platform_admin(
       recovery_record.requester_identity_id,recovery_record.requester_session_id
     ) OR NOT public.lock_initial_admin_recovery_platform_admin(
       recovery_record.approver_identity_id,recovery_record.approver_session_id
     ) THEN
    SELECT * INTO termination_record
      FROM public.terminate_initial_admin_onboarding_recovery(
        recovery_record.id,NULL,'governance_invalidated',p_request_id
      );
    RETURN 'governance_invalidated';
  END IF;
  RETURN 'authorized';
END
$$;

REVOKE ALL ON FUNCTION authorize_initial_admin_recovery_factor_transaction(uuid,uuid) FROM PUBLIC;

-- The table itself is immutable to the runtime.  This trigger is defense in
-- depth for migration owners and future SECURITY DEFINER routines.
CREATE FUNCTION enforce_initial_admin_onboarding_recovery_state()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.invitation_id IS DISTINCT FROM OLD.invitation_id
       OR NEW.acceptance_id IS DISTINCT FROM OLD.acceptance_id
       OR NEW.acceptance_identity_id IS DISTINCT FROM OLD.acceptance_identity_id
       OR NEW.acceptance_attempt IS DISTINCT FROM OLD.acceptance_attempt
       OR NEW.authority_epoch IS DISTINCT FROM OLD.authority_epoch
       OR NEW.source_invitation_version IS DISTINCT FROM OLD.source_invitation_version
       OR NEW.requester_identity_id IS DISTINCT FROM OLD.requester_identity_id
       OR NEW.requester_session_id IS DISTINCT FROM OLD.requester_session_id
       OR NEW.requester_step_up_grant_id IS DISTINCT FROM OLD.requester_step_up_grant_id
       OR NEW.requester_operation_hash IS DISTINCT FROM OLD.requester_operation_hash
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
       OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
       OR NEW.case_reference_hash IS DISTINCT FROM OLD.case_reference_hash
       OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
       OR NEW.request_expires_at IS DISTINCT FROM OLD.request_expires_at THEN
      RAISE EXCEPTION 'Initial-admin recovery source and requester evidence are immutable'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_source_immutable';
    END IF;
    IF NEW.version <> OLD.version+1 THEN
      RAISE EXCEPTION 'Initial-admin recovery version must advance exactly once'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_version';
    END IF;
    IF NEW.last_transition_request_id IS NULL THEN
      RAISE EXCEPTION 'Initial-admin recovery transition evidence is incomplete'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_transition_evidence';
    END IF;

    -- Approval evidence and bearer verifier may be written once only.
    IF NEW.last_transition_action<>'approved' AND (
      NEW.approver_identity_id IS DISTINCT FROM OLD.approver_identity_id
      OR NEW.approver_session_id IS DISTINCT FROM OLD.approver_session_id
      OR NEW.approver_step_up_grant_id IS DISTINCT FROM OLD.approver_step_up_grant_id
      OR NEW.approver_operation_hash IS DISTINCT FROM OLD.approver_operation_hash
      OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
      OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
      OR NEW.token_expires_at IS DISTINCT FROM OLD.token_expires_at
      OR NEW.delivery_channel IS DISTINCT FROM OLD.delivery_channel
      OR NEW.delivery_reference_hash IS DISTINCT FROM OLD.delivery_reference_hash
    ) THEN
      RAISE EXCEPTION 'Initial-admin recovery approval evidence is immutable'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_approval_immutable';
    END IF;
    IF NEW.last_transition_action NOT IN ('approved','delivery_confirmed','delivery_failed')
       AND (
         NEW.delivery_state IS DISTINCT FROM OLD.delivery_state
         OR NEW.delivery_confirmed_at IS DISTINCT FROM OLD.delivery_confirmed_at
         OR NEW.delivery_receipt_hash IS DISTINCT FROM OLD.delivery_receipt_hash
       ) THEN
      RAISE EXCEPTION 'Initial-admin recovery delivery evidence is immutable'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_delivery_immutable';
    END IF;
    IF NEW.last_transition_action<>'redeemed' AND (
      NEW.token_consumed_at IS DISTINCT FROM OLD.token_consumed_at
      OR NEW.browser_context_hashes IS DISTINCT FROM OLD.browser_context_hashes
      OR NEW.browser_context_expires_at IS DISTINCT FROM OLD.browser_context_expires_at
      OR NEW.precommit_user_agent_hash IS DISTINCT FROM OLD.precommit_user_agent_hash
      OR NEW.precommit_ip_prefix_hash IS DISTINCT FROM OLD.precommit_ip_prefix_hash
    ) THEN
      RAISE EXCEPTION 'Initial-admin recovery browser context is immutable'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_context_immutable';
    END IF;
    IF NEW.last_transition_action NOT IN (
      'approved','redeemed','session_rotated','strong_factor_finalized','revoked'
    ) AND (
      NEW.first_redeemed_at IS DISTINCT FROM OLD.first_redeemed_at
      OR NEW.last_redeemed_at IS DISTINCT FROM OLD.last_redeemed_at
      OR NEW.redemption_count IS DISTINCT FROM OLD.redemption_count
      OR NEW.redeemed_session_id IS DISTINCT FROM OLD.redeemed_session_id
      OR NEW.revoked_session_count IS DISTINCT FROM OLD.revoked_session_count
      OR NEW.revoked_mfa_challenge_count IS DISTINCT FROM OLD.revoked_mfa_challenge_count
      OR NEW.revoked_step_up_grant_count IS DISTINCT FROM OLD.revoked_step_up_grant_count
      OR NEW.revoked_webauthn_ceremony_count IS DISTINCT FROM OLD.revoked_webauthn_ceremony_count
    ) THEN
      RAISE EXCEPTION 'Initial-admin recovery redemption evidence is immutable'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_redemption_immutable';
    END IF;
    IF NEW.last_transition_action<>'revoked' AND (
      NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
      OR NEW.revoked_by_identity_id IS DISTINCT FROM OLD.revoked_by_identity_id
      OR NEW.revocation_reason_code IS DISTINCT FROM OLD.revocation_reason_code
    ) THEN
      RAISE EXCEPTION 'Initial-admin recovery revocation evidence is immutable'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_revocation_immutable';
    END IF;
    IF NEW.last_transition_action<>'delivery_failed'
       AND NEW.failure_code IS DISTINCT FROM OLD.failure_code THEN
      RAISE EXCEPTION 'Initial-admin recovery failure evidence is immutable'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_failure_immutable';
    END IF;
    IF NEW.last_transition_action<>'strong_factor_finalized'
       AND NEW.strong_factor_finalized_at IS DISTINCT FROM OLD.strong_factor_finalized_at THEN
      RAISE EXCEPTION 'Initial-admin recovery factor evidence is immutable'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_factor_immutable';
    END IF;

    -- Validate the complete OLD/NEW tuple for every permitted action.  In
    -- particular, session_rotated may repeat up to the bounded fourth
    -- redemption without weakening any context or authority evidence.
    IF NEW.last_transition_action='approved' THEN
      IF OLD.status<>'pending' OR NEW.status<>'finalization_pending'
         OR OLD.approver_identity_id IS NOT NULL OR NEW.approver_identity_id IS NULL
         OR NEW.approver_identity_id=NEW.requester_identity_id
         OR NEW.approver_identity_id=NEW.acceptance_identity_id
         OR NEW.approver_session_id IS NULL OR NEW.approver_step_up_grant_id IS NULL
         OR NEW.approver_operation_hash IS NULL OR NEW.approved_at IS NULL
         OR NEW.token_hash IS NULL OR NEW.token_expires_at IS NULL
         OR NEW.delivery_channel IS NULL OR NEW.delivery_reference_hash IS NULL
         OR OLD.delivery_state<>'not_started'
         OR NOT (
           (NEW.delivery_channel='local_console'
             AND NEW.delivery_state='delivered'
             AND NEW.delivery_confirmed_at IS NOT NULL
             AND NEW.delivery_receipt_hash IS NOT NULL)
           OR
           (NEW.delivery_channel<>'local_console'
             AND NEW.delivery_state='pending'
             AND NEW.delivery_confirmed_at IS NULL
             AND NEW.delivery_receipt_hash IS NULL)
         )
         OR NEW.last_transition_actor_identity_id IS DISTINCT FROM NEW.approver_identity_id
         OR NEW.redemption_count<>0 THEN
        RAISE EXCEPTION 'Initial-admin recovery approval transition is invalid'
          USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_approval_transition';
      END IF;
    ELSIF NEW.last_transition_action='delivery_confirmed' THEN
      IF OLD.status<>'finalization_pending' OR NEW.status<>OLD.status
         OR OLD.delivery_state<>'pending' OR NEW.delivery_state<>'delivered'
         OR OLD.delivery_confirmed_at IS NOT NULL OR NEW.delivery_confirmed_at IS NULL
         OR OLD.delivery_receipt_hash IS NOT NULL OR NEW.delivery_receipt_hash IS NULL
         OR NEW.last_transition_actor_identity_id IS DISTINCT FROM NEW.approver_identity_id THEN
        RAISE EXCEPTION 'Initial-admin recovery delivery transition is invalid'
          USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_delivery_transition';
      END IF;
    ELSIF NEW.last_transition_action='delivery_failed' THEN
      IF OLD.status<>'finalization_pending' OR NEW.status<>'failed'
         OR OLD.delivery_state<>'pending' OR NEW.delivery_state<>'failed'
         OR OLD.failure_code IS NOT NULL OR NEW.failure_code IS NULL
         OR NEW.last_transition_actor_identity_id IS DISTINCT FROM NEW.approver_identity_id THEN
        RAISE EXCEPTION 'Initial-admin recovery delivery failure transition is invalid'
          USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_delivery_failure_transition';
      END IF;
    ELSIF NEW.last_transition_action='redeemed' THEN
      IF OLD.status<>'finalization_pending' OR NEW.status<>'enrollment_pending'
         OR OLD.delivery_state<>'delivered' OR NEW.delivery_state<>OLD.delivery_state
         OR OLD.browser_context_hashes IS NOT NULL OR NEW.browser_context_hashes IS NULL
         OR OLD.token_consumed_at IS NOT NULL OR NEW.token_consumed_at IS NULL
         OR OLD.redemption_count<>0 OR NEW.redemption_count<>1
         OR OLD.first_redeemed_at IS NOT NULL OR NEW.first_redeemed_at IS NULL
         OR NEW.last_redeemed_at<NEW.first_redeemed_at
         OR NEW.redeemed_session_id IS NULL
         OR NEW.last_transition_actor_identity_id IS DISTINCT FROM NEW.acceptance_identity_id THEN
        RAISE EXCEPTION 'Initial-admin recovery redemption transition is invalid'
          USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_redemption_transition';
      END IF;
    ELSIF NEW.last_transition_action='session_rotated' THEN
      IF OLD.status<>'enrollment_pending' OR NEW.status<>OLD.status
         OR NEW.redemption_count<>OLD.redemption_count+1 OR NEW.redemption_count>4
         OR NEW.first_redeemed_at IS DISTINCT FROM OLD.first_redeemed_at
         OR NEW.last_redeemed_at<=OLD.last_redeemed_at
         OR NEW.redeemed_session_id IS NULL
         OR NEW.redeemed_session_id IS NOT DISTINCT FROM OLD.redeemed_session_id
         OR NEW.last_transition_actor_identity_id IS DISTINCT FROM NEW.acceptance_identity_id THEN
        RAISE EXCEPTION 'Initial-admin recovery session rotation is invalid'
          USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_rotation_transition';
      END IF;
    ELSIF NEW.last_transition_action='revoked' THEN
      IF OLD.status NOT IN ('pending','finalization_pending','enrollment_pending')
         OR NEW.status<>'revoked' OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
         OR NEW.revocation_reason_code IS NULL
         OR (
           NEW.revocation_reason_code='governance_invalidated'
           AND (NEW.revoked_by_identity_id IS NOT NULL
             OR NEW.last_transition_actor_identity_id IS NOT NULL)
         )
         OR (
           NEW.revocation_reason_code<>'governance_invalidated'
           AND (NEW.revoked_by_identity_id IS NULL
             OR NEW.last_transition_actor_identity_id IS DISTINCT FROM NEW.revoked_by_identity_id)
         )
         OR NEW.revoked_session_count<OLD.revoked_session_count
         OR NEW.revoked_mfa_challenge_count<OLD.revoked_mfa_challenge_count
         OR NEW.revoked_step_up_grant_count<OLD.revoked_step_up_grant_count
         OR NEW.revoked_webauthn_ceremony_count<OLD.revoked_webauthn_ceremony_count THEN
        RAISE EXCEPTION 'Initial-admin recovery revocation transition is invalid'
          USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_revocation_transition';
      END IF;
    ELSIF NEW.last_transition_action='expired' THEN
      IF OLD.status NOT IN ('pending','finalization_pending','enrollment_pending')
         OR NEW.status<>'expired'
         OR NEW.last_transition_actor_identity_id IS NOT NULL THEN
        RAISE EXCEPTION 'Initial-admin recovery expiry transition is invalid'
          USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_expiry_transition';
      END IF;
    ELSIF NEW.last_transition_action='strong_factor_finalized' THEN
      IF OLD.status<>'enrollment_pending' OR NEW.status<>'admin_active'
         OR OLD.strong_factor_finalized_at IS NOT NULL OR NEW.strong_factor_finalized_at IS NULL
         OR NEW.last_transition_actor_identity_id IS DISTINCT FROM NEW.acceptance_identity_id THEN
        RAISE EXCEPTION 'Initial-admin recovery factor finalization transition is invalid'
          USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_factor_transition';
      END IF;
    ELSE
      RAISE EXCEPTION 'Initial-admin recovery transition action is invalid'
        USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_transition';
    END IF;
  ELSIF NEW.version<>1 OR NEW.status<>'pending'
        OR NEW.last_transition_action<>'requested'
        OR NEW.last_transition_actor_identity_id IS DISTINCT FROM NEW.requester_identity_id
        OR NEW.last_transition_request_id IS NULL THEN
    RAISE EXCEPTION 'Initial-admin recovery request evidence is invalid'
      USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_request_evidence';
  END IF;

  IF NEW.status='admin_active' AND NOT EXISTS (
    SELECT 1
      FROM public.platform_identities identity
      JOIN public.tenant_invitations invitation
        ON invitation.id=NEW.invitation_id
       AND invitation.acceptance_identity_id=identity.id
       AND invitation.acceptance_id=NEW.acceptance_id
       AND invitation.acceptance_attempt=NEW.acceptance_attempt
       AND invitation.authority_epoch=NEW.authority_epoch
     WHERE identity.id=NEW.acceptance_identity_id
       AND identity.status='active'
       AND invitation.status='accepted'
       AND invitation.authority_kind='initial_admin'
       AND invitation.authority_finalized_at IS NOT NULL
       AND (
         (identity.mfa_enabled AND identity.totp_secret_ciphertext IS NOT NULL)
         OR EXISTS (
           SELECT 1 FROM public.webauthn_credentials credential
            WHERE credential.identity_id=identity.id AND credential.revoked_at IS NULL
         )
       )
  ) THEN
    RAISE EXCEPTION 'Initial administrator cannot become active without finalized strong authentication'
      USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_strong_factor_required';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER initial_admin_onboarding_recovery_state_guard
BEFORE INSERT OR UPDATE ON initial_admin_onboarding_recoveries
FOR EACH ROW EXECUTE FUNCTION enforce_initial_admin_onboarding_recovery_state();

REVOKE ALL ON FUNCTION enforce_initial_admin_onboarding_recovery_state() FROM PUBLIC;

-- Mutations append an audit-chain event even if a future caller bypasses the
-- TypeScript store.  Empty metadata is intentional: the complete evidence is
-- the separately protected recovery row, and `{}` lets this function use the
-- exact canonical JSON layout used by ControlPlaneStore.
CREATE FUNCTION audit_initial_admin_onboarding_recovery_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  previous_hash text;
  canonical text;
  action_name text;
  event_result text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('platform_audit_chain',0));
  SELECT event_hash INTO previous_hash
    FROM public.platform_audit_events ORDER BY sequence DESC LIMIT 1;
  action_name := 'platform.initial_admin_onboarding_recovery_' || NEW.last_transition_action;
  event_result := CASE NEW.last_transition_action WHEN 'delivery_failed' THEN 'failure' ELSE 'success' END;
  canonical := '{"previousHash":' || COALESCE(to_json(previous_hash)::text,'null')
    || ',"action":' || to_json(action_name)::text
    || ',"actorIdentityId":' || COALESCE(to_json(NEW.last_transition_actor_identity_id::text)::text,'null')
    || ',"tenantId":' || to_json(NEW.tenant_id::text)::text
    || ',"entityType":"initial_admin_onboarding_recovery"'
    || ',"entityId":' || to_json(NEW.id::text)::text
    || ',"result":' || to_json(event_result)::text
    || ',"requestId":' || COALESCE(to_json(NEW.last_transition_request_id::text)::text,'null')
    || ',"metadata":{}}';
  INSERT INTO public.platform_audit_events(
    actor_identity_id,tenant_id,action,entity_type,entity_id,result,request_id,
    metadata,previous_hash,event_hash
  ) VALUES (
    NEW.last_transition_actor_identity_id,NEW.tenant_id,action_name,
    'initial_admin_onboarding_recovery',NEW.id::text,event_result,
    NEW.last_transition_request_id,'{}'::jsonb,previous_hash,
    encode(sha256(convert_to(canonical,'UTF8')),'hex')
  );
  RETURN NEW;
END
$$;

CREATE TRIGGER initial_admin_onboarding_recovery_audit
AFTER INSERT OR UPDATE ON initial_admin_onboarding_recoveries
FOR EACH ROW EXECUTE FUNCTION audit_initial_admin_onboarding_recovery_transition();

REVOKE ALL ON FUNCTION audit_initial_admin_onboarding_recovery_transition() FROM PUBLIC;

CREATE FUNCTION request_initial_admin_onboarding_recovery(
  p_recovery_id uuid,
  p_tenant_id uuid,
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_acceptance_identity_id uuid,
  p_acceptance_attempt integer,
  p_authority_epoch bigint,
  p_source_invitation_version integer,
  p_requester_identity_id uuid,
  p_requester_session_id uuid,
  p_step_up_token_hash text,
  p_operation_hash text,
  p_idempotency_key uuid,
  p_request_hash text,
  p_reason_code text,
  p_case_reference_hash text,
  p_request_expires_at timestamptz,
  p_request_id uuid
)
RETURNS TABLE(recovery_id uuid,recovery_version integer,recovery_status text,created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  source_record record;
  existing_record record;
  consumed_grant_id uuid;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_recovery_id IS NULL OR p_tenant_id IS NULL OR p_invitation_id IS NULL
     OR p_acceptance_id IS NULL OR p_acceptance_identity_id IS NULL
     OR p_acceptance_attempt IS NULL OR p_acceptance_attempt<=0
     OR p_authority_epoch IS NULL OR p_authority_epoch<=0
     OR p_source_invitation_version IS NULL OR p_source_invitation_version<=0
     OR p_requester_identity_id IS NULL OR p_requester_session_id IS NULL
     OR p_requester_identity_id=p_acceptance_identity_id
     OR p_idempotency_key IS NULL
     OR p_request_hash IS NULL OR p_request_hash !~ '^[0-9a-f]{64}$'
     OR p_case_reference_hash IS NULL OR p_case_reference_hash !~ '^[0-9a-f]{64}$'
     OR p_reason_code IS NULL OR p_reason_code NOT IN (
       'browser_context_lost','browser_profile_reset','device_lost','session_delivery_failure'
     )
     OR p_request_expires_at IS NULL OR p_request_expires_at<=clock_timestamp()
     OR p_request_expires_at>clock_timestamp()+interval '24 hours'
     OR p_request_id IS NULL THEN
    RAISE EXCEPTION 'Initial-admin recovery request is invalid'
      USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_request_input';
  END IF;

  SELECT recovery.id,recovery.version,recovery.status,recovery.request_hash
    INTO existing_record
    FROM public.initial_admin_onboarding_recoveries recovery
   WHERE recovery.id=p_recovery_id
     AND recovery.requester_identity_id=p_requester_identity_id
     AND recovery.idempotency_key=p_idempotency_key
   FOR UPDATE;
  IF FOUND THEN
    IF existing_record.request_hash IS DISTINCT FROM p_request_hash THEN
      RAISE EXCEPTION 'Initial-admin recovery idempotency conflict'
        USING ERRCODE='23505', CONSTRAINT='initial_admin_recovery_idempotency_conflict';
    END IF;
    RETURN QUERY SELECT existing_record.id,existing_record.version,existing_record.status,false;
    RETURN;
  END IF;

  -- A recovery id and a requester-scoped idempotency key form one inseparable
  -- replay identity.  Never let a valid id take precedence over a different
  -- key (or vice versa), even when a caller reuses the original request hash.
  PERFORM 1
    FROM public.initial_admin_onboarding_recoveries recovery
   WHERE recovery.id=p_recovery_id
      OR (recovery.requester_identity_id=p_requester_identity_id
          AND recovery.idempotency_key=p_idempotency_key)
   FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'Initial-admin recovery idempotency conflict'
      USING ERRCODE='23505', CONSTRAINT='initial_admin_recovery_idempotency_conflict';
  END IF;

  -- Lazy expiry makes a bounded retry possible without a privileged cleanup
  -- worker and releases the one-open-source uniqueness fence.
  UPDATE public.initial_admin_onboarding_recoveries recovery
     SET status='expired',failure_code=NULL,version=recovery.version+1,
         last_transition_action='expired',last_transition_actor_identity_id=NULL,
         last_transition_request_id=p_request_id
   WHERE recovery.tenant_id=p_tenant_id
     AND recovery.acceptance_identity_id=p_acceptance_identity_id
     AND recovery.status IN ('pending','finalization_pending','enrollment_pending')
     AND COALESCE(recovery.browser_context_expires_at,recovery.token_expires_at,recovery.request_expires_at)
         <=clock_timestamp();

  SELECT invitation.version,invitation.authority_finalized_at
    INTO source_record
    FROM public.tenant_invitations invitation
    JOIN public.tenants tenant
      ON tenant.id=invitation.tenant_id AND tenant.status='active'
    JOIN public.platform_identities identity
      ON identity.id=invitation.acceptance_identity_id AND identity.status='active'
    JOIN public.tenant_memberships membership
      ON membership.tenant_id=invitation.tenant_id
     AND membership.identity_id=invitation.acceptance_identity_id
     AND membership.status='active'
   WHERE invitation.id=p_invitation_id
     AND invitation.tenant_id=p_tenant_id
     AND invitation.acceptance_id=p_acceptance_id
     AND invitation.acceptance_identity_id=p_acceptance_identity_id
     AND invitation.acceptance_attempt=p_acceptance_attempt
     AND invitation.authority_epoch=p_authority_epoch
     AND invitation.authority_kind='initial_admin'
     AND invitation.role_codes=ARRAY['CHURCH_ADMIN']::text[]
     AND invitation.status='accepted'
     AND invitation.authority_finalized_at IS NOT NULL
     AND tenant.initial_admin_authority_epoch=p_authority_epoch
     -- The requester signs the exact locked version. If authority
     -- finalization won the race, the caller must refetch and obtain a new
     -- operation-bound WebAuthn grant; this tuple is never rebound silently.
     AND invitation.version=p_source_invitation_version
     AND NOT identity.mfa_enabled
     AND identity.totp_secret_ciphertext IS NULL
     AND NOT identity.passkey_enabled
     AND NOT EXISTS (
       SELECT 1 FROM public.webauthn_credentials credential
        WHERE credential.identity_id=identity.id AND credential.revoked_at IS NULL
     )
   FOR UPDATE OF invitation,tenant,identity,membership;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Initial-admin recovery source is not eligible'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_source_ineligible';
  END IF;

  consumed_grant_id := public.consume_initial_admin_recovery_step_up(
    p_requester_identity_id,p_requester_session_id,p_step_up_token_hash,p_operation_hash
  );
  INSERT INTO public.initial_admin_onboarding_recoveries(
    id,tenant_id,invitation_id,acceptance_id,acceptance_identity_id,
    acceptance_attempt,authority_epoch,source_invitation_version,
    requester_identity_id,requester_session_id,requester_step_up_grant_id,
    requester_operation_hash,idempotency_key,request_hash,reason_code,
    case_reference_hash,request_expires_at,last_transition_action,
    last_transition_actor_identity_id,last_transition_request_id
  ) VALUES (
    p_recovery_id,p_tenant_id,p_invitation_id,p_acceptance_id,p_acceptance_identity_id,
    p_acceptance_attempt,p_authority_epoch,source_record.version,
    p_requester_identity_id,p_requester_session_id,consumed_grant_id,
    p_operation_hash,p_idempotency_key,p_request_hash,p_reason_code,
    p_case_reference_hash,p_request_expires_at,'requested',
    p_requester_identity_id,p_request_id
  );
  RETURN QUERY SELECT p_recovery_id,1,'pending'::text,true;
END
$$;

CREATE FUNCTION approve_initial_admin_onboarding_recovery(
  p_recovery_id uuid,
  p_expected_version integer,
  p_tenant_id uuid,
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_acceptance_identity_id uuid,
  p_acceptance_attempt integer,
  p_authority_epoch bigint,
  p_source_invitation_version integer,
  p_approver_identity_id uuid,
  p_approver_session_id uuid,
  p_step_up_token_hash text,
  p_operation_hash text,
  p_token_hash text,
  p_token_expires_at timestamptz,
  p_delivery_channel text,
  p_delivery_reference_hash text,
  p_request_id uuid
)
RETURNS TABLE(
  recovery_id uuid,recovery_version integer,recovery_status text,
  delivery_state text,recipient_email text,token_expires_at timestamptz,reused boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  recovery_record record;
  source_record record;
  termination_record record;
  consumed_grant_id uuid;
  revoked_sessions integer := 0;
  revoked_mfa_challenges integer := 0;
  revoked_step_up_grants integer := 0;
  revoked_webauthn_ceremonies integer := 0;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_recovery_id IS NULL OR p_expected_version IS NULL OR p_expected_version<=0
     OR p_tenant_id IS NULL OR p_invitation_id IS NULL OR p_acceptance_id IS NULL
     OR p_acceptance_identity_id IS NULL OR p_acceptance_attempt IS NULL OR p_acceptance_attempt<=0
     OR p_authority_epoch IS NULL OR p_authority_epoch<=0
     OR p_source_invitation_version IS NULL OR p_source_invitation_version<=0
     OR p_approver_identity_id IS NULL OR p_approver_session_id IS NULL
     OR p_step_up_token_hash IS NULL OR p_step_up_token_hash !~ '^[0-9a-f]{64}$'
     OR p_operation_hash IS NULL OR p_operation_hash !~ '^[0-9a-f]{64}$'
     OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$'
     OR p_token_expires_at IS NULL OR p_token_expires_at<=clock_timestamp()
     OR p_token_expires_at>clock_timestamp()+interval '30 minutes'
     OR p_delivery_channel IS NULL OR p_delivery_channel NOT IN (
       'local_console','verified_email','verified_sms','service_desk'
     )
     OR p_delivery_reference_hash IS NULL OR p_delivery_reference_hash !~ '^[0-9a-f]{64}$'
     OR p_request_id IS NULL THEN
    RAISE EXCEPTION 'Initial-admin recovery approval is invalid'
      USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_approval_input';
  END IF;

  SELECT recovery.*,invitation.email AS recipient_email
    INTO recovery_record
    FROM public.initial_admin_onboarding_recoveries recovery
    JOIN public.tenant_invitations invitation ON invitation.id=recovery.invitation_id
   WHERE recovery.id=p_recovery_id
   FOR UPDATE OF recovery;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Initial-admin recovery request is unavailable'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_unavailable';
  END IF;
  IF recovery_record.tenant_id IS DISTINCT FROM p_tenant_id
     OR recovery_record.invitation_id IS DISTINCT FROM p_invitation_id
     OR recovery_record.acceptance_id IS DISTINCT FROM p_acceptance_id
     OR recovery_record.acceptance_identity_id IS DISTINCT FROM p_acceptance_identity_id
     OR recovery_record.acceptance_attempt IS DISTINCT FROM p_acceptance_attempt
     OR recovery_record.authority_epoch IS DISTINCT FROM p_authority_epoch
     OR recovery_record.source_invitation_version IS DISTINCT FROM p_source_invitation_version THEN
    RAISE EXCEPTION 'Initial-admin recovery source tuple changed'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_source_mismatch';
  END IF;
  IF recovery_record.status='finalization_pending'
     AND recovery_record.approver_identity_id=p_approver_identity_id
     AND recovery_record.approver_session_id=p_approver_session_id
     AND recovery_record.approver_operation_hash=p_operation_hash
     AND recovery_record.delivery_channel=p_delivery_channel
     AND recovery_record.delivery_reference_hash=p_delivery_reference_hash THEN
    IF NOT public.lock_initial_admin_recovery_platform_admin(
         recovery_record.requester_identity_id,recovery_record.requester_session_id
       ) OR NOT public.lock_initial_admin_recovery_platform_admin(
         recovery_record.approver_identity_id,recovery_record.approver_session_id
       ) THEN
      SELECT * INTO termination_record
        FROM public.terminate_initial_admin_onboarding_recovery(
          recovery_record.id,NULL,'governance_invalidated',p_request_id
        );
      RETURN QUERY SELECT recovery_record.id,termination_record.recovery_version,
        'revoked'::text,recovery_record.delivery_state,recovery_record.recipient_email,
        recovery_record.token_expires_at,true;
      RETURN;
    END IF;
    RETURN QUERY SELECT recovery_record.id,recovery_record.version,recovery_record.status,
      recovery_record.delivery_state,recovery_record.recipient_email,
      recovery_record.token_expires_at,true;
    RETURN;
  END IF;
  IF recovery_record.status IS DISTINCT FROM 'pending'
     OR recovery_record.version IS DISTINCT FROM p_expected_version
     OR recovery_record.request_expires_at<=clock_timestamp()
     OR recovery_record.requester_identity_id IS NOT DISTINCT FROM p_approver_identity_id
     OR recovery_record.acceptance_identity_id IS NOT DISTINCT FROM p_approver_identity_id
     OR p_token_expires_at>recovery_record.request_expires_at THEN
    RAISE EXCEPTION 'Initial-admin recovery approval is unavailable'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_approval_unavailable';
  END IF;
  IF NOT public.lock_initial_admin_recovery_platform_admin(
    recovery_record.requester_identity_id,recovery_record.requester_session_id
  ) THEN
    SELECT * INTO termination_record
      FROM public.terminate_initial_admin_onboarding_recovery(
        recovery_record.id,NULL,'governance_invalidated',p_request_id
      );
    RETURN QUERY SELECT recovery_record.id,termination_record.recovery_version,
      'revoked'::text,recovery_record.delivery_state,recovery_record.recipient_email,
      recovery_record.token_expires_at,true;
    RETURN;
  END IF;

  -- Target identity is the serialization lock shared with TOTP and passkey
  -- registration.  Lock the source tuple first, then the complete active
  -- credential set before deciding that no strong factor exists.
  SELECT invitation.id AS locked_invitation_id
    INTO source_record
    FROM public.tenant_invitations invitation
    JOIN public.tenants tenant ON tenant.id=invitation.tenant_id AND tenant.status='active'
    JOIN public.platform_identities identity
      ON identity.id=invitation.acceptance_identity_id AND identity.status='active'
    JOIN public.tenant_memberships membership
      ON membership.tenant_id=invitation.tenant_id
     AND membership.identity_id=identity.id AND membership.status='active'
   WHERE invitation.id=recovery_record.invitation_id
     AND invitation.tenant_id=recovery_record.tenant_id
     AND invitation.acceptance_id=recovery_record.acceptance_id
     AND invitation.acceptance_identity_id=recovery_record.acceptance_identity_id
     AND invitation.acceptance_attempt=recovery_record.acceptance_attempt
     AND invitation.authority_epoch=recovery_record.authority_epoch
     AND invitation.authority_kind='initial_admin'
     AND invitation.status='accepted'
     AND invitation.authority_finalized_at IS NOT NULL
     AND tenant.initial_admin_authority_epoch=recovery_record.authority_epoch
     AND NOT identity.mfa_enabled
     AND identity.totp_secret_ciphertext IS NULL
     AND NOT identity.passkey_enabled
   FOR UPDATE OF invitation,tenant,identity,membership;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Initial-admin recovery source is no longer eligible'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_source_ineligible';
  END IF;
  PERFORM credential.id
    FROM public.webauthn_credentials credential
   WHERE credential.identity_id=recovery_record.acceptance_identity_id
     AND credential.revoked_at IS NULL
   ORDER BY credential.id
   FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'Initial-admin recovery source already has a strong factor'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_source_ineligible';
  END IF;

  consumed_grant_id := public.consume_initial_admin_recovery_step_up(
    p_approver_identity_id,p_approver_session_id,p_step_up_token_hash,p_operation_hash
  );

  -- Approval is the governed incident-containment boundary.  Quarantine every
  -- active session and pending authentication artifact of the beneficiary,
  -- never those of the two platform administrators.
  UPDATE public.authentication_step_up_grants grant_record
     SET revoked_at=COALESCE(grant_record.revoked_at,clock_timestamp())
   WHERE grant_record.identity_id=recovery_record.acceptance_identity_id
     AND grant_record.consumed_at IS NULL AND grant_record.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_step_up_grants=ROW_COUNT;
  UPDATE public.mfa_challenges challenge
     SET consumed_at=COALESCE(challenge.consumed_at,clock_timestamp())
   WHERE challenge.identity_id=recovery_record.acceptance_identity_id
     AND challenge.consumed_at IS NULL;
  GET DIAGNOSTICS revoked_mfa_challenges=ROW_COUNT;
  UPDATE public.webauthn_ceremonies ceremony
     SET failed_at=COALESCE(ceremony.failed_at,clock_timestamp())
   WHERE ceremony.identity_id=recovery_record.acceptance_identity_id
     AND ceremony.consumed_at IS NULL AND ceremony.failed_at IS NULL;
  GET DIAGNOSTICS revoked_webauthn_ceremonies=ROW_COUNT;
  UPDATE public.auth_sessions session
     SET revoked_at=clock_timestamp(),revoke_reason='initial_admin_recovery_approved'
   WHERE session.identity_id=recovery_record.acceptance_identity_id
     AND session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_sessions=ROW_COUNT;

  UPDATE public.initial_admin_onboarding_recoveries recovery
     SET approver_identity_id=p_approver_identity_id,
         approver_session_id=p_approver_session_id,
         approver_step_up_grant_id=consumed_grant_id,
         approver_operation_hash=p_operation_hash,
         status='finalization_pending',approved_at=clock_timestamp(),
         token_hash=p_token_hash,token_expires_at=p_token_expires_at,
         delivery_channel=p_delivery_channel,
         delivery_state=CASE WHEN p_delivery_channel='local_console'
           THEN 'delivered' ELSE 'pending' END,
         delivery_reference_hash=p_delivery_reference_hash,
         delivery_receipt_hash=CASE WHEN p_delivery_channel='local_console'
           THEN p_delivery_reference_hash ELSE NULL END,
         delivery_confirmed_at=CASE WHEN p_delivery_channel='local_console'
           THEN clock_timestamp() ELSE NULL END,
         revoked_session_count=recovery.revoked_session_count+revoked_sessions,
         revoked_mfa_challenge_count=recovery.revoked_mfa_challenge_count+revoked_mfa_challenges,
         revoked_step_up_grant_count=recovery.revoked_step_up_grant_count+revoked_step_up_grants,
         revoked_webauthn_ceremony_count=
           recovery.revoked_webauthn_ceremony_count+revoked_webauthn_ceremonies,
         version=recovery.version+1,last_transition_action='approved',
         last_transition_actor_identity_id=p_approver_identity_id,
         last_transition_request_id=p_request_id
   WHERE recovery.id=p_recovery_id;
  RETURN QUERY
  SELECT recovery.id,recovery.version,recovery.status,recovery.delivery_state,
         recovery_record.recipient_email,recovery.token_expires_at,false
    FROM public.initial_admin_onboarding_recoveries recovery
   WHERE recovery.id=p_recovery_id;
END
$$;

-- This function is a delivery-worker boundary, not an HTTP authority boundary.
-- Migration grants must expose it only to the dedicated owner-controlled OOB
-- worker role.  It revalidates the already-approved dual-control principals.
CREATE FUNCTION confirm_initial_admin_onboarding_recovery_delivery(
  p_recovery_id uuid,
  p_expected_version integer,
  p_approver_identity_id uuid,
  p_delivery_receipt_hash text,
  p_request_id uuid
)
RETURNS TABLE(recovery_version integer,recovery_status text,delivery_state text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE recovery_record record; termination_record record;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_recovery_id IS NULL OR p_expected_version IS NULL OR p_expected_version<=0
     OR p_approver_identity_id IS NULL OR p_delivery_receipt_hash IS NULL
     OR p_delivery_receipt_hash !~ '^[0-9a-f]{64}$' OR p_request_id IS NULL THEN
    RAISE EXCEPTION 'Initial-admin recovery delivery receipt is invalid'
      USING ERRCODE='23514';
  END IF;
  SELECT * INTO recovery_record
    FROM public.initial_admin_onboarding_recoveries recovery
   WHERE recovery.id=p_recovery_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Initial-admin recovery delivery is unavailable' USING ERRCODE='42501';
  END IF;
  IF recovery_record.status='finalization_pending' AND (
       NOT public.lock_initial_admin_recovery_platform_admin(
         recovery_record.requester_identity_id,recovery_record.requester_session_id
       )
       OR NOT public.lock_initial_admin_recovery_platform_admin(
         recovery_record.approver_identity_id,recovery_record.approver_session_id
       )
     ) THEN
    SELECT * INTO termination_record
      FROM public.terminate_initial_admin_onboarding_recovery(
        recovery_record.id,NULL,'governance_invalidated',p_request_id
      );
    RETURN QUERY SELECT termination_record.recovery_version,'revoked'::text,
      recovery_record.delivery_state;
    RETURN;
  END IF;
  IF recovery_record.delivery_state='delivered'
     AND recovery_record.delivery_receipt_hash=p_delivery_receipt_hash THEN
    RETURN QUERY SELECT recovery_record.version,recovery_record.status,recovery_record.delivery_state;
    RETURN;
  END IF;
  IF recovery_record.status<>'finalization_pending'
     OR recovery_record.delivery_state<>'pending'
     OR recovery_record.version IS DISTINCT FROM p_expected_version
     OR recovery_record.approver_identity_id IS DISTINCT FROM p_approver_identity_id
     OR recovery_record.token_expires_at<=clock_timestamp()
     OR recovery_record.request_expires_at<=clock_timestamp() THEN
    RAISE EXCEPTION 'Initial-admin recovery delivery is unavailable'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_delivery_unavailable';
  END IF;
  UPDATE public.initial_admin_onboarding_recoveries recovery
     SET delivery_state='delivered',delivery_receipt_hash=p_delivery_receipt_hash,
         delivery_confirmed_at=clock_timestamp(),version=recovery.version+1,
         last_transition_action='delivery_confirmed',
         last_transition_actor_identity_id=p_approver_identity_id,
         last_transition_request_id=p_request_id
   WHERE recovery.id=p_recovery_id;
  RETURN QUERY SELECT recovery.version,recovery.status,recovery.delivery_state
    FROM public.initial_admin_onboarding_recoveries recovery WHERE recovery.id=p_recovery_id;
END
$$;

-- Same dedicated delivery-worker boundary as confirmation; never grant this
-- function to the public HTTP runtime role.
CREATE FUNCTION fail_initial_admin_onboarding_recovery_delivery(
  p_recovery_id uuid,
  p_expected_version integer,
  p_approver_identity_id uuid,
  p_failure_code text,
  p_request_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE recovery_record record; termination_record record;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_recovery_id IS NULL OR p_expected_version IS NULL OR p_expected_version<=0
     OR p_approver_identity_id IS NULL OR p_failure_code IS NULL
     OR p_failure_code !~ '^[A-Z0-9_]{2,80}$' OR p_request_id IS NULL THEN
    RAISE EXCEPTION 'Initial-admin recovery delivery failure is invalid' USING ERRCODE='23514';
  END IF;
  SELECT * INTO recovery_record
    FROM public.initial_admin_onboarding_recoveries recovery
   WHERE recovery.id=p_recovery_id
   FOR UPDATE;
  IF NOT FOUND OR recovery_record.version IS DISTINCT FROM p_expected_version
     OR recovery_record.status IS DISTINCT FROM 'finalization_pending'
     OR recovery_record.delivery_state IS DISTINCT FROM 'pending'
     OR recovery_record.approver_identity_id IS DISTINCT FROM p_approver_identity_id THEN
    RETURN false;
  END IF;
  IF NOT public.lock_initial_admin_recovery_platform_admin(
       recovery_record.requester_identity_id,recovery_record.requester_session_id
     ) OR NOT public.lock_initial_admin_recovery_platform_admin(
       recovery_record.approver_identity_id,recovery_record.approver_session_id
     ) THEN
    SELECT * INTO termination_record
      FROM public.terminate_initial_admin_onboarding_recovery(
        recovery_record.id,NULL,'governance_invalidated',p_request_id
      );
    RETURN termination_record.recovery_version IS NOT NULL;
  END IF;
  UPDATE public.initial_admin_onboarding_recoveries recovery
     SET status='failed',delivery_state='failed',failure_code=p_failure_code,
         version=recovery.version+1,last_transition_action='delivery_failed',
         last_transition_actor_identity_id=p_approver_identity_id,
         last_transition_request_id=p_request_id
   WHERE recovery.id=p_recovery_id;
  RETURN FOUND;
END
$$;

CREATE FUNCTION redeem_initial_admin_onboarding_recovery(
  p_recovery_id uuid,
  p_token text,
  p_context_proofs text[],
  p_session_id uuid,
  p_session_token_hash text,
  p_csrf_hash text,
  p_session_expires_at timestamptz,
  p_user_agent_hash text,
  p_ip_prefix_hash text,
  p_request_id uuid
)
RETURNS TABLE(
  recovered boolean,identity_id uuid,tenant_id uuid,session_id uuid,
  session_expires_at timestamptz,rotated boolean,recovery_version integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  recovery_record record;
  termination_record record;
  source_record record;
  context_hashes text[];
  issued_expires_at timestamptz;
  is_rotation boolean;
  revoked_sessions integer := 0;
  revoked_mfa_challenges integer := 0;
  revoked_step_up_grants integer := 0;
  revoked_webauthn_ceremonies integer := 0;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_recovery_id IS NULL OR p_session_id IS NULL
     OR p_session_token_hash IS NULL OR p_session_token_hash !~ '^[0-9a-f]{64}$'
     OR p_csrf_hash IS NULL OR p_csrf_hash !~ '^[0-9a-f]{64}$'
     OR p_session_expires_at IS NULL OR p_session_expires_at<=clock_timestamp()
     OR p_request_id IS NULL OR p_context_proofs IS NULL
     OR (p_token IS NOT NULL AND p_token !~ '^[A-Za-z0-9_-]{43}$')
     OR cardinality(p_context_proofs) NOT BETWEEN 1 AND 12
     OR cardinality(p_context_proofs)<>(SELECT count(DISTINCT proof) FROM unnest(p_context_proofs) proof)
     OR EXISTS (SELECT 1 FROM unnest(p_context_proofs) proof WHERE proof !~ '^[A-Za-z0-9_-]{43}$')
     OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^[0-9a-f]{64}$')
     OR (p_ip_prefix_hash IS NOT NULL AND p_ip_prefix_hash !~ '^[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'Initial-admin recovery redemption input is invalid'
      USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_redemption_input';
  END IF;
  SELECT array_agg(encode(sha256(convert_to(proof,'UTF8')),'hex') ORDER BY proof)
    INTO context_hashes FROM unnest(p_context_proofs) proof;

  SELECT recovery.* INTO recovery_record
    FROM public.initial_admin_onboarding_recoveries recovery
   WHERE recovery.id=p_recovery_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz,false,0;
    RETURN;
  END IF;
  IF recovery_record.status IN ('pending','finalization_pending','enrollment_pending')
     AND COALESCE(
       recovery_record.browser_context_expires_at,
       recovery_record.token_expires_at,
       recovery_record.request_expires_at
     )<=clock_timestamp() THEN
    UPDATE public.initial_admin_onboarding_recoveries recovery
       SET status='expired',version=recovery.version+1,last_transition_action='expired',
           last_transition_actor_identity_id=NULL,
           last_transition_request_id=p_request_id
     WHERE recovery.id=p_recovery_id;
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz,false,
      recovery_record.version+1;
    RETURN;
  END IF;
  is_rotation := recovery_record.status='enrollment_pending';
  IF NOT (
    (recovery_record.status='finalization_pending'
      AND recovery_record.delivery_state='delivered'
      AND recovery_record.token_expires_at>clock_timestamp()
      AND p_token IS NOT NULL
      AND recovery_record.token_hash=encode(sha256(convert_to(p_token,'UTF8')),'hex'))
    OR
    (recovery_record.status='enrollment_pending'
      AND recovery_record.browser_context_expires_at>clock_timestamp()
      AND recovery_record.redemption_count<4
      AND recovery_record.browser_context_hashes && context_hashes
      AND (p_token IS NULL
        OR recovery_record.token_hash=encode(sha256(convert_to(p_token,'UTF8')),'hex'))
      AND (recovery_record.precommit_user_agent_hash IS NULL
        OR recovery_record.precommit_user_agent_hash IS NOT DISTINCT FROM p_user_agent_hash)
      AND (recovery_record.precommit_ip_prefix_hash IS NULL OR p_ip_prefix_hash IS NULL
        OR recovery_record.precommit_ip_prefix_hash=p_ip_prefix_hash))
  ) THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz,false,
      recovery_record.version;
    RETURN;
  END IF;

  -- Possession of the recovery bearer never outlives the dual-control
  -- authority that approved it.  This check occurs only after bearer/context
  -- authentication, preventing an unauthenticated UUID probe from revoking a
  -- still-valid workflow.
  IF NOT public.lock_initial_admin_recovery_platform_admin(
       recovery_record.requester_identity_id,recovery_record.requester_session_id
     ) OR NOT public.lock_initial_admin_recovery_platform_admin(
       recovery_record.approver_identity_id,recovery_record.approver_session_id
     ) THEN
    SELECT * INTO termination_record
      FROM public.terminate_initial_admin_onboarding_recovery(
        recovery_record.id,NULL,'governance_invalidated',p_request_id
      );
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz,false,
      termination_record.recovery_version;
    RETURN;
  END IF;

  SELECT invitation.id AS locked_invitation_id
    INTO source_record
    FROM public.tenant_invitations invitation
    JOIN public.tenants tenant ON tenant.id=invitation.tenant_id AND tenant.status='active'
    JOIN public.platform_identities identity
      ON identity.id=invitation.acceptance_identity_id AND identity.status='active'
    JOIN public.tenant_memberships membership
      ON membership.tenant_id=invitation.tenant_id
     AND membership.identity_id=identity.id AND membership.status='active'
   WHERE invitation.id=recovery_record.invitation_id
     AND invitation.tenant_id=recovery_record.tenant_id
     AND invitation.acceptance_id=recovery_record.acceptance_id
     AND invitation.acceptance_identity_id=recovery_record.acceptance_identity_id
     AND invitation.acceptance_attempt=recovery_record.acceptance_attempt
     AND invitation.authority_epoch=recovery_record.authority_epoch
     AND invitation.authority_kind='initial_admin'
     AND invitation.status='accepted'
     AND invitation.authority_finalized_at IS NOT NULL
     AND tenant.initial_admin_authority_epoch=recovery_record.authority_epoch
     AND NOT identity.mfa_enabled
     AND identity.totp_secret_ciphertext IS NULL
     AND NOT identity.passkey_enabled
   FOR UPDATE OF invitation,tenant,identity,membership;
  IF NOT FOUND THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz,false,
      recovery_record.version;
    RETURN;
  END IF;
  PERFORM credential.id
    FROM public.webauthn_credentials credential
   WHERE credential.identity_id=recovery_record.acceptance_identity_id
     AND credential.revoked_at IS NULL
   ORDER BY credential.id
   FOR UPDATE;
  IF FOUND THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz,false,
      recovery_record.version;
    RETURN;
  END IF;

  issued_expires_at := LEAST(
    p_session_expires_at,clock_timestamp()+interval '10 minutes',
    COALESCE(recovery_record.browser_context_expires_at,recovery_record.token_expires_at),
    recovery_record.request_expires_at
  );
  IF issued_expires_at<=clock_timestamp() THEN
    RETURN QUERY SELECT false,NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz,false,
      recovery_record.version;
    RETURN;
  END IF;

  -- Re-check and quarantine all target authentication state in the same
  -- transaction that mints the restricted session. This closes the race
  -- between approval containment and bearer redemption.
  UPDATE public.authentication_step_up_grants grant_record
     SET revoked_at=COALESCE(grant_record.revoked_at,clock_timestamp())
   WHERE grant_record.identity_id=recovery_record.acceptance_identity_id
     AND grant_record.consumed_at IS NULL AND grant_record.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_step_up_grants=ROW_COUNT;
  UPDATE public.mfa_challenges challenge
     SET consumed_at=COALESCE(challenge.consumed_at,clock_timestamp())
   WHERE challenge.identity_id=recovery_record.acceptance_identity_id
     AND challenge.consumed_at IS NULL;
  GET DIAGNOSTICS revoked_mfa_challenges=ROW_COUNT;
  UPDATE public.webauthn_ceremonies ceremony
     SET failed_at=COALESCE(ceremony.failed_at,clock_timestamp())
   WHERE ceremony.identity_id=recovery_record.acceptance_identity_id
     AND ceremony.consumed_at IS NULL AND ceremony.failed_at IS NULL;
  GET DIAGNOSTICS revoked_webauthn_ceremonies=ROW_COUNT;
  UPDATE public.auth_sessions session
     SET revoked_at=clock_timestamp(),revoke_reason='initial_admin_recovery_rotated'
   WHERE session.identity_id=recovery_record.acceptance_identity_id
     AND session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_sessions=ROW_COUNT;

  INSERT INTO public.auth_sessions(
    id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
    user_agent_hash,ip_prefix_hash,assurance_level,mfa_verified_at,
    auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,
    idle_timeout_minutes,idle_expires_at,last_user_agent_hash,last_ip_prefix_hash,
    enrollment_source,invitation_id,initial_admin_onboarding_recovery_id
  ) VALUES (
    p_session_id,p_session_token_hash,p_csrf_hash,recovery_record.acceptance_identity_id,
    recovery_record.tenant_id,issued_expires_at,p_user_agent_hash,p_ip_prefix_hash,
    'enrollment_only',NULL,'bootstrap',1,false,NULL,false,10,issued_expires_at,
    p_user_agent_hash,p_ip_prefix_hash,'initial_admin_recovery',
    recovery_record.invitation_id,recovery_record.id
  );

  UPDATE public.initial_admin_onboarding_recoveries recovery
     SET status='enrollment_pending',
         token_consumed_at=COALESCE(recovery.token_consumed_at,clock_timestamp()),
         browser_context_hashes=COALESCE(recovery.browser_context_hashes,context_hashes),
         browser_context_expires_at=COALESCE(
           recovery.browser_context_expires_at,
           LEAST(recovery.token_expires_at,clock_timestamp()+interval '30 minutes')
         ),
         precommit_user_agent_hash=COALESCE(recovery.precommit_user_agent_hash,p_user_agent_hash),
         precommit_ip_prefix_hash=COALESCE(recovery.precommit_ip_prefix_hash,p_ip_prefix_hash),
         first_redeemed_at=COALESCE(recovery.first_redeemed_at,clock_timestamp()),
         last_redeemed_at=clock_timestamp(),redemption_count=recovery.redemption_count+1,
         redeemed_session_id=p_session_id,version=recovery.version+1,
         revoked_session_count=recovery.revoked_session_count+revoked_sessions,
         revoked_mfa_challenge_count=recovery.revoked_mfa_challenge_count+revoked_mfa_challenges,
         revoked_step_up_grant_count=recovery.revoked_step_up_grant_count+revoked_step_up_grants,
         revoked_webauthn_ceremony_count=
           recovery.revoked_webauthn_ceremony_count+revoked_webauthn_ceremonies,
         last_transition_action=CASE WHEN is_rotation THEN 'session_rotated' ELSE 'redeemed' END,
         last_transition_actor_identity_id=recovery.acceptance_identity_id,
         last_transition_request_id=p_request_id
   WHERE recovery.id=p_recovery_id;

  RETURN QUERY SELECT true,recovery_record.acceptance_identity_id,recovery_record.tenant_id,
    p_session_id,issued_expires_at,is_rotation,recovery_record.version+1;
END
$$;

CREATE FUNCTION revoke_initial_admin_onboarding_recovery(
  p_recovery_id uuid,
  p_expected_version integer,
  p_tenant_id uuid,
  p_invitation_id uuid,
  p_acceptance_id uuid,
  p_acceptance_identity_id uuid,
  p_acceptance_attempt integer,
  p_authority_epoch bigint,
  p_source_invitation_version integer,
  p_actor_identity_id uuid,
  p_actor_session_id uuid,
  p_step_up_token_hash text,
  p_operation_hash text,
  p_reason_code text,
  p_request_id uuid
)
RETURNS TABLE(recovery_version integer,recovery_status text,sessions_revoked integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE recovery_record record; termination_record record;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_recovery_id IS NULL OR p_expected_version IS NULL OR p_expected_version<=0
     OR p_tenant_id IS NULL OR p_invitation_id IS NULL OR p_acceptance_id IS NULL
     OR p_acceptance_identity_id IS NULL OR p_acceptance_attempt IS NULL OR p_acceptance_attempt<=0
     OR p_authority_epoch IS NULL OR p_authority_epoch<=0
     OR p_source_invitation_version IS NULL OR p_source_invitation_version<=0
     OR p_actor_identity_id IS NULL OR p_actor_session_id IS NULL
     OR p_step_up_token_hash IS NULL OR p_step_up_token_hash !~ '^[0-9a-f]{64}$'
     OR p_operation_hash IS NULL OR p_operation_hash !~ '^[0-9a-f]{64}$'
     OR p_reason_code IS NULL OR p_reason_code NOT IN (
       'security_response','requester_cancelled','delivery_reissue'
     )
     OR p_request_id IS NULL THEN
    RAISE EXCEPTION 'Initial-admin recovery revocation input is invalid'
      USING ERRCODE='23514', CONSTRAINT='initial_admin_recovery_revocation_input';
  END IF;
  SELECT * INTO recovery_record
    FROM public.initial_admin_onboarding_recoveries recovery
   WHERE recovery.id=p_recovery_id FOR UPDATE;
  IF NOT FOUND OR recovery_record.version IS DISTINCT FROM p_expected_version
     OR recovery_record.status NOT IN ('pending','finalization_pending','enrollment_pending')
     OR recovery_record.tenant_id IS DISTINCT FROM p_tenant_id
     OR recovery_record.invitation_id IS DISTINCT FROM p_invitation_id
     OR recovery_record.acceptance_id IS DISTINCT FROM p_acceptance_id
     OR recovery_record.acceptance_identity_id IS DISTINCT FROM p_acceptance_identity_id
     OR recovery_record.acceptance_attempt IS DISTINCT FROM p_acceptance_attempt
     OR recovery_record.authority_epoch IS DISTINCT FROM p_authority_epoch
     OR recovery_record.source_invitation_version IS DISTINCT FROM p_source_invitation_version THEN
    RAISE EXCEPTION 'Initial-admin recovery revocation is unavailable'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_revocation_unavailable';
  END IF;
  PERFORM public.consume_initial_admin_recovery_step_up(
    p_actor_identity_id,p_actor_session_id,p_step_up_token_hash,p_operation_hash
  );
  SELECT * INTO termination_record
    FROM public.terminate_initial_admin_onboarding_recovery(
      p_recovery_id,p_actor_identity_id,p_reason_code,p_request_id
    );
  IF termination_record.recovery_version IS NULL THEN
    RAISE EXCEPTION 'Initial-admin recovery revocation changed concurrently'
      USING ERRCODE='40001', CONSTRAINT='initial_admin_recovery_revocation_race';
  END IF;
  RETURN QUERY SELECT termination_record.recovery_version,'revoked'::text,
    termination_record.sessions_revoked;
END
$$;

-- Called from the same control-database transaction that commits a successful
-- TOTP enrollment or first passkey registration.  The new unrestricted
-- session is explicit evidence; a password hash can never satisfy this gate.
CREATE FUNCTION finalize_initial_admin_onboarding_recovery(
  p_source_enrollment_session_id uuid,
  p_new_session_id uuid,
  p_request_id uuid
)
RETURNS TABLE(
  recovery_id uuid,recovery_version integer,factor_method text,
  enrollment_sessions_revoked integer,reused boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  recovery_record record;
  session_record record;
  revoked_count integer := 0;
  resolved_factor_method text;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_source_enrollment_session_id IS NULL OR p_new_session_id IS NULL OR p_request_id IS NULL
     OR p_source_enrollment_session_id=p_new_session_id THEN
    RAISE EXCEPTION 'Initial-admin recovery factor finalization input is invalid'
      USING ERRCODE='23514';
  END IF;
  SELECT recovery.*,source_session.identity_id AS source_identity_id,
         source_session.active_tenant_id AS source_tenant_id
    INTO recovery_record
    FROM public.auth_sessions source_session
    JOIN public.initial_admin_onboarding_recoveries recovery
      ON recovery.id=source_session.initial_admin_onboarding_recovery_id
     AND recovery.invitation_id=source_session.invitation_id
     AND recovery.acceptance_identity_id=source_session.identity_id
     AND recovery.tenant_id=source_session.active_tenant_id
   WHERE source_session.id=p_source_enrollment_session_id
     AND source_session.enrollment_source='initial_admin_recovery'
     AND source_session.assurance_level='enrollment_only'
     AND recovery.redeemed_session_id=source_session.id
     AND recovery.status IN ('enrollment_pending','admin_active')
   FOR UPDATE OF source_session,recovery;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF recovery_record.status='admin_active' THEN
    RETURN QUERY SELECT recovery_record.id,recovery_record.version,
      CASE
        WHEN EXISTS (
          SELECT 1 FROM public.webauthn_credentials credential
           WHERE credential.identity_id=recovery_record.acceptance_identity_id
             AND credential.revoked_at IS NULL
        ) THEN 'passkey'::text
        ELSE 'totp'::text
      END,0,true;
    RETURN;
  END IF;

  -- Official factor flows acquired these locks in the authorization function
  -- before changing any factor state.  Repeat the check here as defense in
  -- depth for every direct SECURITY DEFINER caller.
  IF NOT public.lock_initial_admin_recovery_platform_admin(
       recovery_record.requester_identity_id,recovery_record.requester_session_id
     ) OR NOT public.lock_initial_admin_recovery_platform_admin(
       recovery_record.approver_identity_id,recovery_record.approver_session_id
     ) THEN
    RAISE EXCEPTION 'Initial-admin recovery dual-control authority was withdrawn'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_governance_invalidated';
  END IF;

  SELECT session.auth_method,session.authenticated_credential_id
    INTO session_record
    FROM public.auth_sessions session
    JOIN public.platform_identities identity
      ON identity.id=session.identity_id AND identity.status='active'
   WHERE session.id=p_new_session_id
     AND session.identity_id=recovery_record.acceptance_identity_id
     AND session.active_tenant_id=recovery_record.tenant_id
     AND session.revoked_at IS NULL
     AND session.expires_at>clock_timestamp()
     AND session.idle_expires_at>clock_timestamp()
     AND session.assurance_level='mfa'
     AND session.aal>=2
     AND NOT session.recovery_limited
     AND session.enrollment_source IS NULL
     AND (
       (session.auth_method='passkey'
         AND session.phishing_resistant
         AND session.authenticated_credential_id IS NOT NULL
         AND EXISTS (
           SELECT 1 FROM public.webauthn_credentials credential
            WHERE credential.id=session.authenticated_credential_id
              AND credential.identity_id=identity.id
              AND credential.revoked_at IS NULL
              AND credential.user_verified
         ))
       OR
       (session.auth_method='totp'
         AND session.mfa_verified_at IS NOT NULL
         AND identity.mfa_enabled
         AND identity.totp_secret_ciphertext IS NOT NULL)
     )
   FOR UPDATE OF session,identity;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Initial-admin recovery requires a newly finalized strong factor session'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_factor_session_invalid';
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM public.tenant_invitations invitation
      JOIN public.tenants tenant ON tenant.id=invitation.tenant_id AND tenant.status='active'
      JOIN public.tenant_memberships membership
        ON membership.tenant_id=invitation.tenant_id
       AND membership.identity_id=invitation.acceptance_identity_id
       AND membership.status='active'
     WHERE invitation.id=recovery_record.invitation_id
       AND invitation.tenant_id=recovery_record.tenant_id
       AND invitation.acceptance_id=recovery_record.acceptance_id
       AND invitation.acceptance_identity_id=recovery_record.acceptance_identity_id
       AND invitation.acceptance_attempt=recovery_record.acceptance_attempt
       AND invitation.authority_epoch=recovery_record.authority_epoch
       AND invitation.authority_kind='initial_admin'
       AND invitation.status='accepted'
       AND invitation.authority_finalized_at IS NOT NULL
       AND tenant.initial_admin_authority_epoch=recovery_record.authority_epoch
  ) THEN
    RAISE EXCEPTION 'Initial-admin recovery source is no longer finalized'
      USING ERRCODE='42501', CONSTRAINT='initial_admin_recovery_source_ineligible';
  END IF;

  resolved_factor_method := session_record.auth_method;
  UPDATE public.auth_sessions session
     SET revoked_at=clock_timestamp(),revoke_reason='initial_admin_recovery_completed'
   WHERE session.identity_id=recovery_record.acceptance_identity_id
     AND session.id<>p_new_session_id
     AND session.assurance_level='enrollment_only'
     AND session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_count=ROW_COUNT;
  UPDATE public.initial_admin_onboarding_recoveries recovery
     SET status='admin_active',strong_factor_finalized_at=clock_timestamp(),
         revoked_session_count=recovery.revoked_session_count+revoked_count,
         version=recovery.version+1,last_transition_action='strong_factor_finalized',
         last_transition_actor_identity_id=recovery_record.acceptance_identity_id,
         last_transition_request_id=p_request_id
   WHERE recovery.id=recovery_record.id;
  RETURN QUERY SELECT recovery_record.id,recovery_record.version+1,
    resolved_factor_method,revoked_count,false;
END
$$;

REVOKE ALL ON FUNCTION finalize_initial_admin_onboarding_recovery(uuid,uuid,uuid) FROM PUBLIC;

-- Platform administrators discover the exact immutable source tuple through a
-- parameterized SECURITY DEFINER boundary.  The runtime receives no base-table
-- SELECT and no verifier; the tuple returned here is the tuple that must be
-- embedded in the requester's operation-bound WebAuthn ceremony.
CREATE FUNCTION list_initial_admin_onboarding_recovery_candidates(
  p_actor_identity_id uuid,
  p_actor_session_id uuid,
  p_tenant_id uuid,
  p_limit integer
)
RETURNS TABLE(
  tenant_id uuid,tenant_display_name text,invitation_id uuid,acceptance_id uuid,
  acceptance_identity_id uuid,acceptance_attempt integer,authority_epoch bigint,
  invitation_version integer,recipient_email text,recipient_display_name text,
  authority_finalized_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_actor_identity_id IS NULL OR p_actor_session_id IS NULL
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 OR NOT EXISTS (
    SELECT 1
      FROM public.auth_sessions session
      JOIN public.platform_identities actor
        ON actor.id=session.identity_id AND actor.status='active'
      JOIN public.platform_role_bindings role_binding
        ON role_binding.identity_id=actor.id AND role_binding.role_code='platform_admin'
      JOIN public.tenants session_tenant
        ON session_tenant.id=session.active_tenant_id AND session_tenant.status='active'
      JOIN public.tenant_memberships membership
        ON membership.tenant_id=session_tenant.id
       AND membership.identity_id=actor.id AND membership.status='active'
     WHERE session.id=p_actor_session_id
       AND session.identity_id=p_actor_identity_id
       AND session.revoked_at IS NULL
       AND session.expires_at>clock_timestamp()
       AND session.idle_expires_at>clock_timestamp()
       AND session.assurance_level NOT IN ('enrollment_only','recovery_limited')
       AND NOT session.recovery_limited
  ) THEN
    RAISE EXCEPTION 'Initial-admin recovery candidates are unavailable'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT invitation.tenant_id,tenant.display_name,invitation.id,
         invitation.acceptance_id,invitation.acceptance_identity_id,
         invitation.acceptance_attempt,invitation.authority_epoch,
         invitation.version,identity.email,identity.display_name,
         invitation.authority_finalized_at
    FROM public.tenant_invitations invitation
    JOIN public.tenants tenant
      ON tenant.id=invitation.tenant_id AND tenant.status='active'
    JOIN public.platform_identities identity
      ON identity.id=invitation.acceptance_identity_id AND identity.status='active'
    JOIN public.tenant_memberships membership
      ON membership.tenant_id=invitation.tenant_id
     AND membership.identity_id=identity.id AND membership.status='active'
   WHERE (p_tenant_id IS NULL OR invitation.tenant_id=p_tenant_id)
     AND invitation.authority_kind='initial_admin'
     AND invitation.status='accepted'
     AND invitation.authority_finalized_at IS NOT NULL
     AND invitation.authority_epoch=tenant.initial_admin_authority_epoch
     AND NOT identity.mfa_enabled
     AND identity.totp_secret_ciphertext IS NULL
     AND NOT identity.passkey_enabled
     AND NOT EXISTS (
       SELECT 1 FROM public.webauthn_credentials credential
        WHERE credential.identity_id=identity.id AND credential.revoked_at IS NULL
     )
     AND NOT EXISTS (
       SELECT 1 FROM public.initial_admin_onboarding_recoveries recovery
        WHERE recovery.tenant_id=invitation.tenant_id
          AND recovery.acceptance_identity_id=identity.id
          AND recovery.status IN ('pending','finalization_pending','enrollment_pending')
          AND COALESCE(
            recovery.browser_context_expires_at,
            recovery.token_expires_at,
            recovery.request_expires_at
          )>clock_timestamp()
     )
   ORDER BY invitation.accepted_at,invitation.id
   LIMIT p_limit;
END
$$;

REVOKE ALL ON FUNCTION list_initial_admin_onboarding_recovery_candidates(uuid,uuid,uuid,integer) FROM PUBLIC;

-- Explicit, authorized cleanup releases stale unique-index fences. Automatic
-- expiry is system-attributed (NULL actor); the request id is correlation only.
CREATE FUNCTION expire_stale_initial_admin_onboarding_recoveries(
  p_actor_identity_id uuid,
  p_actor_session_id uuid,
  p_tenant_id uuid,
  p_request_id uuid
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE expired_count integer;
BEGIN
  PERFORM public.lock_initial_admin_recovery_workflow();
  IF p_actor_identity_id IS NULL OR p_actor_session_id IS NULL OR p_request_id IS NULL
     OR NOT public.lock_initial_admin_recovery_platform_admin(
       p_actor_identity_id,p_actor_session_id
     ) THEN
    RAISE EXCEPTION 'Initial-admin recovery expiry authority is unavailable'
      USING ERRCODE='42501';
  END IF;
  UPDATE public.initial_admin_onboarding_recoveries recovery
     SET status='expired',version=recovery.version+1,
         last_transition_action='expired',last_transition_actor_identity_id=NULL,
         last_transition_request_id=p_request_id
   WHERE (p_tenant_id IS NULL OR recovery.tenant_id=p_tenant_id)
     AND recovery.status IN ('pending','finalization_pending','enrollment_pending')
     AND COALESCE(
       recovery.browser_context_expires_at,
       recovery.token_expires_at,
       recovery.request_expires_at
     )<=clock_timestamp();
  GET DIAGNOSTICS expired_count=ROW_COUNT;
  RETURN expired_count;
END
$$;

REVOKE ALL ON FUNCTION expire_stale_initial_admin_onboarding_recoveries(uuid,uuid,uuid,uuid) FROM PUBLIC;

-- Stable cursor queue for the second administrator.  It intentionally omits
-- token, delivery, case-reference, operation, grant, and browser verifiers.
CREATE FUNCTION list_initial_admin_onboarding_recoveries(
  p_actor_identity_id uuid,
  p_actor_session_id uuid,
  p_tenant_id uuid,
  p_status text,
  p_before_requested_at timestamptz,
  p_before_recovery_id uuid,
  p_limit integer
)
RETURNS TABLE(
  recovery_id uuid,recovery_version integer,recovery_status text,
  tenant_id uuid,tenant_display_name text,invitation_id uuid,acceptance_id uuid,
  acceptance_identity_id uuid,acceptance_attempt integer,authority_epoch bigint,
  source_invitation_version integer,recipient_email text,recipient_display_name text,
  requester_identity_id uuid,requester_email text,requester_display_name text,
  approver_identity_id uuid,approver_email text,approver_display_name text,
  reason_code text,delivery_channel text,delivery_state text,
  requested_at timestamptz,request_expires_at timestamptz,approved_at timestamptz,
  token_expires_at timestamptz,redemption_count smallint,strong_factor_finalized_at timestamptz,
  revoked_at timestamptz,revocation_reason_code text,failure_code text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_actor_identity_id IS NULL OR p_actor_session_id IS NULL
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
     OR (p_status IS NOT NULL AND p_status NOT IN (
       'pending','finalization_pending','enrollment_pending','admin_active',
       'revoked','expired','failed'
     ))
     OR ((p_before_requested_at IS NULL)<>(p_before_recovery_id IS NULL))
     OR NOT EXISTS (
       SELECT 1
         FROM public.auth_sessions session
         JOIN public.platform_identities actor
           ON actor.id=session.identity_id AND actor.status='active'
         JOIN public.platform_role_bindings role_binding
           ON role_binding.identity_id=actor.id AND role_binding.role_code='platform_admin'
         JOIN public.tenants session_tenant
           ON session_tenant.id=session.active_tenant_id AND session_tenant.status='active'
         JOIN public.tenant_memberships membership
           ON membership.tenant_id=session_tenant.id
          AND membership.identity_id=actor.id AND membership.status='active'
        WHERE session.id=p_actor_session_id
          AND session.identity_id=p_actor_identity_id
          AND session.revoked_at IS NULL
          AND session.expires_at>clock_timestamp()
          AND session.idle_expires_at>clock_timestamp()
          AND session.assurance_level NOT IN ('enrollment_only','recovery_limited')
          AND NOT session.recovery_limited
     ) THEN
    RAISE EXCEPTION 'Initial-admin recovery queue is unavailable'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT recovery.id,recovery.version,recovery.status,
         recovery.tenant_id,tenant.display_name,recovery.invitation_id,recovery.acceptance_id,
         recovery.acceptance_identity_id,recovery.acceptance_attempt,recovery.authority_epoch,
         recovery.source_invitation_version,target.email,target.display_name,
         recovery.requester_identity_id,requester.email,requester.display_name,
         recovery.approver_identity_id,approver.email,approver.display_name,
         recovery.reason_code,recovery.delivery_channel,recovery.delivery_state,
         recovery.requested_at,recovery.request_expires_at,recovery.approved_at,
         recovery.token_expires_at,recovery.redemption_count,
         recovery.strong_factor_finalized_at,recovery.revoked_at,
         recovery.revocation_reason_code,recovery.failure_code
    FROM public.initial_admin_onboarding_recoveries recovery
    JOIN public.tenants tenant ON tenant.id=recovery.tenant_id
    JOIN public.platform_identities target ON target.id=recovery.acceptance_identity_id
    JOIN public.platform_identities requester ON requester.id=recovery.requester_identity_id
    LEFT JOIN public.platform_identities approver ON approver.id=recovery.approver_identity_id
   WHERE (p_tenant_id IS NULL OR recovery.tenant_id=p_tenant_id)
     AND (p_status IS NULL OR recovery.status=p_status)
     AND (
       p_before_requested_at IS NULL
       OR (recovery.requested_at,recovery.id)<(p_before_requested_at,p_before_recovery_id)
     )
   ORDER BY recovery.requested_at DESC,recovery.id DESC
   LIMIT p_limit;
END
$$;

REVOKE ALL ON FUNCTION list_initial_admin_onboarding_recoveries(
  uuid,uuid,uuid,text,timestamptz,uuid,integer
) FROM PUBLIC;

CREATE FUNCTION get_initial_admin_onboarding_recovery_approval_context(
  p_actor_identity_id uuid,
  p_actor_session_id uuid,
  p_recovery_id uuid
)
RETURNS TABLE(
  recovery_id uuid,recovery_version integer,recovery_status text,delivery_state text,
  tenant_id uuid,invitation_id uuid,acceptance_id uuid,acceptance_identity_id uuid,
  acceptance_attempt integer,authority_epoch bigint,source_invitation_version integer,
  recipient_email text,recipient_display_name text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_actor_identity_id IS NULL OR p_actor_session_id IS NULL OR p_recovery_id IS NULL
     OR NOT EXISTS (
       SELECT 1
         FROM public.auth_sessions session
         JOIN public.platform_identities actor
           ON actor.id=session.identity_id AND actor.status='active'
         JOIN public.platform_role_bindings role_binding
           ON role_binding.identity_id=actor.id AND role_binding.role_code='platform_admin'
         JOIN public.tenants session_tenant
           ON session_tenant.id=session.active_tenant_id AND session_tenant.status='active'
         JOIN public.tenant_memberships membership
           ON membership.tenant_id=session_tenant.id
          AND membership.identity_id=actor.id AND membership.status='active'
        WHERE session.id=p_actor_session_id
          AND session.identity_id=p_actor_identity_id
          AND session.revoked_at IS NULL
          AND session.expires_at>clock_timestamp()
          AND session.idle_expires_at>clock_timestamp()
          AND session.assurance_level NOT IN ('enrollment_only','recovery_limited')
          AND NOT session.recovery_limited
     ) THEN
    RAISE EXCEPTION 'Initial-admin recovery approval context is unavailable'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT recovery.id,recovery.version,recovery.status,recovery.delivery_state,
         recovery.tenant_id,recovery.invitation_id,recovery.acceptance_id,
         recovery.acceptance_identity_id,recovery.acceptance_attempt,recovery.authority_epoch,
         recovery.source_invitation_version,identity.email,identity.display_name
    FROM public.initial_admin_onboarding_recoveries recovery
    JOIN public.platform_identities identity ON identity.id=recovery.acceptance_identity_id
   WHERE recovery.id=p_recovery_id;
END
$$;

REVOKE ALL ON FUNCTION get_initial_admin_onboarding_recovery_approval_context(uuid,uuid,uuid) FROM PUBLIC;

-- Sanitized owner/runtime view: possession verifiers and browser-binding
-- hashes are never selectable through the application role.
CREATE VIEW initial_admin_onboarding_recovery_summaries
WITH (security_barrier=true)
AS
SELECT recovery.id,recovery.tenant_id,recovery.invitation_id,recovery.acceptance_id,
       recovery.acceptance_identity_id,recovery.acceptance_attempt,recovery.authority_epoch,
       recovery.source_invitation_version,recovery.requester_identity_id,
       recovery.approver_identity_id,recovery.status,recovery.reason_code,
       recovery.delivery_channel,recovery.delivery_state,recovery.requested_at,
       recovery.request_expires_at,recovery.approved_at,recovery.delivery_confirmed_at,
       recovery.token_expires_at,recovery.token_consumed_at,
       recovery.browser_context_expires_at,recovery.first_redeemed_at,
       recovery.last_redeemed_at,recovery.redemption_count,recovery.redeemed_session_id,
       recovery.revoked_session_count,recovery.revoked_mfa_challenge_count,
       recovery.revoked_step_up_grant_count,recovery.revoked_webauthn_ceremony_count,
       recovery.strong_factor_finalized_at,recovery.revoked_at,
       recovery.revoked_by_identity_id,recovery.revocation_reason_code,
       recovery.failure_code,recovery.version
  FROM initial_admin_onboarding_recoveries recovery;

REVOKE ALL ON TABLE initial_admin_onboarding_recovery_summaries FROM PUBLIC;

CREATE FUNCTION get_initial_admin_onboarding_recovery_summary(
  p_actor_identity_id uuid,
  p_actor_session_id uuid,
  p_recovery_id uuid
)
RETURNS SETOF initial_admin_onboarding_recovery_summaries
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_actor_identity_id IS NULL OR p_actor_session_id IS NULL OR p_recovery_id IS NULL
     OR NOT EXISTS (
       SELECT 1
         FROM public.auth_sessions session
         JOIN public.platform_identities actor
           ON actor.id=session.identity_id AND actor.status='active'
         JOIN public.platform_role_bindings role_binding
           ON role_binding.identity_id=actor.id AND role_binding.role_code='platform_admin'
         JOIN public.tenants session_tenant
           ON session_tenant.id=session.active_tenant_id AND session_tenant.status='active'
         JOIN public.tenant_memberships membership
           ON membership.tenant_id=session_tenant.id
          AND membership.identity_id=actor.id AND membership.status='active'
        WHERE session.id=p_actor_session_id
          AND session.identity_id=p_actor_identity_id
          AND session.revoked_at IS NULL
          AND session.expires_at>clock_timestamp()
          AND session.idle_expires_at>clock_timestamp()
          AND session.assurance_level NOT IN ('enrollment_only','recovery_limited')
          AND NOT session.recovery_limited
     ) THEN
    RAISE EXCEPTION 'Initial-admin recovery summary is unavailable'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT summary.*
    FROM public.initial_admin_onboarding_recovery_summaries summary
   WHERE summary.id=p_recovery_id;
END
$$;

REVOKE ALL ON FUNCTION get_initial_admin_onboarding_recovery_summary(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION request_initial_admin_onboarding_recovery(
  uuid,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,uuid,text,text,text,timestamptz,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION approve_initial_admin_onboarding_recovery(
  uuid,integer,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,text,timestamptz,text,text,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION confirm_initial_admin_onboarding_recovery_delivery(uuid,integer,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION fail_initial_admin_onboarding_recovery_delivery(uuid,integer,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION redeem_initial_admin_onboarding_recovery(
  uuid,text,text[],uuid,text,text,timestamptz,text,text,uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_initial_admin_onboarding_recovery(
  uuid,integer,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,text,uuid
) FROM PUBLIC;
