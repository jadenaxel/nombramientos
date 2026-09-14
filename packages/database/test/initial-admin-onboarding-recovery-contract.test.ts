import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";
import {
  initialAdminRecoveryRequestHash,
  InitialAdminOnboardingRecoveryStore,
} from "../src/initial-admin-onboarding-recovery-store.js";

const enterpriseAuthStore = readFileSync(path.resolve(
  process.cwd(),
  "src/enterprise-auth-store.ts",
), "utf8");

const recoveryStore = readFileSync(path.resolve(
  process.cwd(),
  "src/initial-admin-onboarding-recovery-store.ts",
), "utf8");

const migrateControl = readFileSync(path.resolve(
  process.cwd(),
  "scripts/migrate-control.ts",
), "utf8");

const migration = readFileSync(path.resolve(
  process.cwd(),
  "migrations/control/025_initial_admin_onboarding_recovery.sql",
), "utf8");

describe("governed initial-admin onboarding recovery contract", () => {
  test("uses a separate, versioned aggregate fenced to exact accepted initial-admin provenance", () => {
    expect(migration).toContain("CREATE TABLE initial_admin_onboarding_recoveries");
    for (const column of [
      "tenant_id", "invitation_id", "acceptance_id", "acceptance_identity_id",
      "acceptance_attempt", "authority_epoch", "source_invitation_version",
    ]) expect(migration).toContain(column);
    expect(migration).toMatch(/invitation\.acceptance_id=p_acceptance_id/u);
    expect(migration).toMatch(/invitation\.acceptance_attempt=p_acceptance_attempt/u);
    expect(migration).toMatch(/invitation\.authority_epoch=p_authority_epoch/u);
    expect(migration).toMatch(/invitation\.authority_kind='initial_admin'/u);
    expect(migration).toMatch(/invitation\.authority_finalized_at IS NOT NULL/u);
    expect(migration).toMatch(/invitation\.version=p_source_invitation_version/u);
    expect(migration).not.toMatch(/invitation\.version BETWEEN p_source_invitation_version/u);
    // Later transitions fence the immutable tuple/finalization rather than a
    // mutable marker version, so finalization cannot invalidate valid work.
    expect(migration.match(/source_invitation_version/g)?.length).toBeGreaterThanOrEqual(8);
    expect(migration).not.toMatch(/invitation\.version=recovery_record\.source_invitation_version/u);
  });

  test("requires two different platform admins and consumes two exact WebAuthn grants", () => {
    expect(migration).toContain("approver_identity_id IS NULL OR approver_identity_id <> requester_identity_id");
    expect(migration).toContain("approver_identity_id IS NULL OR approver_identity_id <> acceptance_identity_id");
    expect(migration).toContain("approver_step_up_grant_id IS NULL OR approver_step_up_grant_id <> requester_step_up_grant_id");
    expect(migration).toMatch(/role_binding\.role_code='platform_admin'/u);
    expect(migration).toMatch(/credential\.id=grant_record\.credential_id/u);
    expect(migration).toMatch(/credential\.revoked_at IS NULL/u);
    expect(migration).toMatch(/credential\.user_verified/u);
    expect(migration).toMatch(/grant_record\.operation_hash=p_operation_hash/u);
    expect(migration).toMatch(/grant_record\.purpose='platform_administration'/u);
    expect(migration.match(/consume_initial_admin_recovery_step_up\(/g)?.length).toBeGreaterThanOrEqual(4);
    expect(migration).toContain("recovery_record.acceptance_identity_id IS NOT DISTINCT FROM p_approver_identity_id");
  });

  test("persists only 256-bit verifiers and hides them from its sanitized view", () => {
    expect(migration).toMatch(/token_hash text UNIQUE CHECK \(token_hash IS NULL OR token_hash ~ '\^\[0-9a-f\]\{64\}\$'\)/u);
    expect(migration).toContain("browser_context_hashes text[]");
    expect(migration).toContain("cardinality(candidate) BETWEEN 1 AND 12");
    expect(migration).toContain("cardinality(p_context_proofs) NOT BETWEEN 1 AND 12");
    const view = migration.slice(migration.indexOf("CREATE VIEW initial_admin_onboarding_recovery_summaries"));
    expect(view).not.toContain("recovery.token_hash");
    expect(view).not.toContain("recovery.browser_context_hashes");
    expect(view).not.toContain("requester_operation_hash");
    expect(view).not.toContain("approver_operation_hash");
    expect(migration).not.toMatch(/session_token\s+text/u);
    expect(migration).not.toMatch(/csrf_token\s+text/u);
  });

  test("allows at least twelve precommit roots but only four session rotations", () => {
    expect(migration).toContain("redemption_count BETWEEN 0 AND 4");
    expect(migration).toContain("recovery_record.redemption_count<4");
    expect(migration).toContain("NEW.redemption_count<>OLD.redemption_count+1 OR NEW.redemption_count>4");
    expect(migration).toContain("NEW.last_transition_action='session_rotated'");
    expect(migration).not.toContain("NEW.last_transition_action = OLD.last_transition_action");
    expect(migration).toContain("revoke_reason='initial_admin_recovery_rotated'");
    expect(migration).toContain("auth_sessions_one_initial_admin_recovery_active");
  });

  test("quarantines every target session and pending authentication artifact", () => {
    expect(migration.match(/session\.identity_id=recovery_record\.acceptance_identity_id/g)?.length)
      .toBeGreaterThanOrEqual(2);
    expect(migration.match(/grant_record\.identity_id=recovery_record\.acceptance_identity_id/g)?.length)
      .toBeGreaterThanOrEqual(2);
    expect(migration.match(/challenge\.identity_id=recovery_record\.acceptance_identity_id/g)?.length)
      .toBeGreaterThanOrEqual(2);
    expect(migration.match(/ceremony\.identity_id=recovery_record\.acceptance_identity_id/g)?.length)
      .toBeGreaterThanOrEqual(2);
    expect(migration).not.toMatch(/WHERE session\.identity_id=recovery_record\.acceptance_identity_id\s+AND session\.invitation_id/u);
    for (const count of [
      "revoked_session_count", "revoked_mfa_challenge_count",
      "revoked_step_up_grant_count", "revoked_webauthn_ceremony_count",
    ]) expect(migration).toContain(count);
  });

  test("mints only a bounded enrollment-only bootstrap session with explicit provenance", () => {
    expect(migration).toContain("enrollment_source = 'initial_admin_recovery'");
    expect(migration).toContain("initial_admin_onboarding_recovery_id IS NOT NULL");
    expect(migration).toContain("clock_timestamp()+interval '10 minutes'");
    expect(migration).toMatch(/'enrollment_only',NULL,'bootstrap',1,false,NULL,false,10/u);
    expect(migration).toContain("auth_sessions_initial_admin_recovery_source_guard");
    expect(migration).toContain("The ordinary runtime INSERT grant intentionally excludes all three source");
  });

  test("defines strong factor from persisted TOTP/passkey state and never from a password hash", () => {
    expect(migration).toMatch(/identity\.mfa_enabled AND identity\.totp_secret_ciphertext IS NOT NULL/u);
    expect(migration).toMatch(/FROM public\.webauthn_credentials credential/u);
    expect(migration).toMatch(/credential\.revoked_at IS NULL/u);
    const factorGuard = migration.slice(
      migration.indexOf("IF NEW.status='admin_active'"),
      migration.indexOf("RETURN NEW;", migration.indexOf("IF NEW.status='admin_active'")),
    );
    expect(factorGuard).not.toContain("password_hash");
  });

  test("audits every successful transition even for direct SECURITY DEFINER callers", () => {
    expect(migration).toContain("CREATE TRIGGER initial_admin_onboarding_recovery_audit");
    expect(migration).toContain("AFTER INSERT OR UPDATE ON initial_admin_onboarding_recoveries");
    expect(migration).toContain("pg_advisory_xact_lock(hashtextextended('platform_audit_chain',0))");
    expect(migration).toContain("platform.initial_admin_onboarding_recovery_");
    expect(migration).toContain("REVOKE ALL ON TABLE initial_admin_onboarding_recoveries FROM PUBLIC");
  });

  test("approval replay never claims that a newly generated token was persisted", () => {
    const replay = migration.slice(
      migration.indexOf("IF recovery_record.status='finalization_pending'"),
      migration.indexOf("IF recovery_record.status<>'pending'"),
    );
    expect(replay).toMatch(/recipient_email,[\s\S]*token_expires_at,true;/u);
    const fresh = migration.slice(
      migration.indexOf("UPDATE public.initial_admin_onboarding_recoveries recovery", migration.indexOf("CREATE FUNCTION approve_initial")),
      migration.indexOf("CREATE FUNCTION confirm_initial", migration.indexOf("CREATE FUNCTION approve_initial")),
    );
    expect(fresh).toMatch(/recipient_email,recovery\.token_expires_at,false/u);
  });

  test("binds the recovery id and requester idempotency key as one replay identity", () => {
    const request = migration.slice(
      migration.indexOf("CREATE FUNCTION request_initial_admin_onboarding_recovery"),
      migration.indexOf("CREATE FUNCTION approve_initial_admin_onboarding_recovery"),
    );
    expect(request).toMatch(
      /recovery\.id=p_recovery_id\s+AND recovery\.requester_identity_id=p_requester_identity_id\s+AND recovery\.idempotency_key=p_idempotency_key/u,
    );
    expect(request).toContain("A recovery id and a requester-scoped idempotency key form one inseparable");
    expect(request).not.toContain("ORDER BY (recovery.id=p_recovery_id) DESC");
  });
});

test("request evidence hash is deterministic, ordered, and does not require secret material", () => {
  const left = initialAdminRecoveryRequestHash({
    source: { acceptanceId: "a", authorityEpoch: 2 },
    recoveryId: "r",
  });
  const right = initialAdminRecoveryRequestHash({
    recoveryId: "r",
    source: { authorityEpoch: 2, acceptanceId: "a" },
  });
  expect(left).toBe(right);
  expect(left).toMatch(/^[0-9a-f]{64}$/u);
  expect(typeof InitialAdminOnboardingRecoveryStore).toBe("function");
});

test("passkey recovery authorization is bound only to the ceremony's canonical source session", () => {
  expect(enterpriseAuthStore).toContain("SELECT ceremony.session_id AS source_session_id");
  expect(enterpriseAuthStore).toContain("AND ($1::uuid IS NULL OR ceremony.session_id=$1)");
  expect(enterpriseAuthStore).not.toContain("COALESCE($1::uuid,ceremony.session_id)");
});

test("runtime and delivery-worker ACLs expose only their exact recovery boundaries", () => {
  const runtime = migrateControl.slice(
    migrateControl.indexOf("async function applyControlRuntimeGrants"),
    migrateControl.indexOf("async function applyRecoveryDeliveryWorkerGrants"),
  );
  const worker = migrateControl.slice(
    migrateControl.indexOf("async function applyRecoveryDeliveryWorkerGrants"),
    migrateControl.indexOf("async function grantControlTablePrivileges"),
  );
  const runtimeRecoverySignatures = [...runtime.matchAll(
    /"((?:list|expire|get|request|approve|redeem|revoke|authorize|finalize)_[a-z_]*initial_admin[a-z_]*\([^"\r\n]+\))"/gu,
  )].map((match) => match[1]);
  expect(runtimeRecoverySignatures).toEqual([
    "list_initial_admin_onboarding_recovery_candidates(uuid,uuid,uuid,integer)",
    "expire_stale_initial_admin_onboarding_recoveries(uuid,uuid,uuid,uuid)",
    "list_initial_admin_onboarding_recoveries(uuid,uuid,uuid,text,timestamptz,uuid,integer)",
    "get_initial_admin_onboarding_recovery_approval_context(uuid,uuid,uuid)",
    "get_initial_admin_onboarding_recovery_summary(uuid,uuid,uuid)",
    "request_initial_admin_onboarding_recovery(uuid,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,uuid,text,text,text,timestamptz,uuid)",
    "approve_initial_admin_onboarding_recovery(uuid,integer,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,text,timestamptz,text,text,uuid)",
    "redeem_initial_admin_onboarding_recovery(uuid,text,text[],uuid,text,text,timestamptz,text,text,uuid)",
    "revoke_initial_admin_onboarding_recovery(uuid,integer,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,text,uuid)",
    "authorize_initial_admin_recovery_factor_transaction(uuid,uuid)",
    "finalize_initial_admin_onboarding_recovery(uuid,uuid,uuid)",
  ]);
  expect(runtime).not.toContain("confirm_initial_admin_onboarding_recovery_delivery");
  expect(runtime).not.toContain("fail_initial_admin_onboarding_recovery_delivery");
  expect(runtime).not.toMatch(/GRANT (?:SELECT|INSERT|UPDATE|DELETE)[^\n]*initial_admin_onboarding_recover/iu);
  expect(worker).toContain("confirm_initial_admin_onboarding_recovery_delivery(uuid,integer,uuid,text,uuid)");
  expect(worker).toContain("fail_initial_admin_onboarding_recovery_delivery(uuid,integer,uuid,text,uuid)");
  expect(worker).toContain("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public");
  expect(migrateControl).toContain("CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION");
  expect(recoveryStore).not.toContain("confirm_initial_admin_onboarding_recovery_delivery");
  expect(recoveryStore).not.toContain("fail_initial_admin_onboarding_recovery_delivery");
});
