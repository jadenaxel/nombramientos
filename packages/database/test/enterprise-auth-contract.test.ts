import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migration = readFileSync(
  path.join(packageRoot, "migrations", "control", "015_enterprise_authentication.sql"),
  "utf8",
);
const baselineGuardMigration = readFileSync(
  path.join(packageRoot, "migrations", "control", "016_immutable_identity_policy_baseline.sql"),
  "utf8",
);
const atomicReplacementMigration = readFileSync(
  path.join(packageRoot, "migrations", "control", "017_atomic_passkey_replacement.sql"),
  "utf8",
);
const mfaChallengeAttemptCeilingMigration = readFileSync(
  path.join(packageRoot, "migrations", "control", "020_mfa_challenge_attempt_ceiling.sql"),
  "utf8",
);
const grants = readFileSync(path.join(packageRoot, "scripts", "migrate-control.ts"), "utf8");
const controlStore = readFileSync(path.join(packageRoot, "src", "control-store.ts"), "utf8");
const enterpriseAuthStore = readFileSync(path.join(packageRoot, "src", "enterprise-auth-store.ts"), "utf8");

describe("enterprise authentication persistence contract", () => {
  it("persists no raw ceremony challenge or step-up bearer and enforces one-time state", () => {
    expect(migration).toContain("challenge_hash text NOT NULL UNIQUE");
    expect(migration).toContain("token_hash text NOT NULL UNIQUE");
    expect(migration).not.toMatch(/\bchallenge\s+text\b/iu);
    expect(migration).toContain("authentication_step_up_grants");
    expect(migration).toContain("consumed_at timestamptz");
    expect(migration).toContain("operation_hash text NOT NULL");
  });

  it("rejects IP RP identifiers, supports only secure origins outside localhost, and records device-context mobility as risk", () => {
    expect(migration).toContain("CREATE OR REPLACE FUNCTION webauthn_rp_id_is_valid");
    expect(migration).toContain("p_rp_id ~ '^[0-9]+(\\.[0-9]+){3}$'");
    expect(migration).toContain("p_rp_id !~ '\\.[a-z]([a-z0-9-]*[a-z0-9])?$'");
    expect(migration).toContain("expected_origin ~ '^https://");
    expect(migration).toContain("expected_origin ~ '^http://localhost");
    expect(controlStore).not.toContain("s.ip_prefix_hash IS NOT DISTINCT FROM $3");
    expect(controlStore).toContain("ip_change_count=s.ip_change_count+CASE");
    expect(controlStore).not.toContain("s.user_agent_hash IS NOT DISTINCT FROM $2");
    expect(controlStore).toContain("user_agent_change_count=s.user_agent_change_count+CASE");
  });

  it("applies least-privilege runtime grants for every enterprise auth relation", () => {
    for (const table of [
      "identity_policy_baseline",
      "tenant_identity_policies",
      "webauthn_credentials",
      "webauthn_ceremonies",
      "authentication_step_up_grants",
    ]) {
      expect(grants).toContain(`\"${table}\"`);
      expect(migration).toContain(`REVOKE ALL ON TABLE ${table} FROM PUBLIC`);
    }
    expect(grants).toContain("GRANT UPDATE(display_name,sign_count,backup_state,last_used_at,last_used_session_id");
    expect(grants).toContain("GRANT UPDATE(attempt_count,consumed_at,failed_at) ON TABLE webauthn_ceremonies");
    expect(grants).toContain("GRANT UPDATE(consumed_at,revoked_at) ON TABLE authentication_step_up_grants");
    expect(grants).toContain("last_user_agent_hash,user_agent_change_count,user_agent_context_changed_at");
    expect(grants).toContain("passkey_enabled,passkey_enrolled_at");
    expect(grants).not.toContain("GRANT UPDATE(strong_auth_enabled");
  });

  it("keeps the tenant policy beneath an immutable global floor", () => {
    expect(migration).toContain("tenant_identity_policy_floor_guard");
    expect(migration).toContain("Tenant identity policy cannot weaken the global security floor");
    expect(migration).toContain("enforcement_mode text NOT NULL CHECK (enforcement_mode IN ('monitor','enforce'))");
    expect(migration).toContain("'global',1,'monitor'");
    expect(migration).toContain("baseline.enforcement_mode = 'enforce'");
    expect(migration).toContain("require_phishing_resistant_for_privileged");
    expect(migration).toContain("identity_action_requirements_tighten");
    expect(baselineGuardMigration).toContain("BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE");
    expect(baselineGuardMigration).toContain("identity_policy_baseline is immutable");
    expect(baselineGuardMigration).toContain("atomically revalidates every tenant policy and active authorization");
  });

  it("serializes registration and treats PostgreSQL bigint policy versions numerically", () => {
    expect(enterpriseAuthStore).toMatch(
      /lockRegistrationIdentity\(client, input\.ceremonyId\);[\s\S]*lockCeremony\(client, input, "registration"\)/u,
    );
    expect(enterpriseAuthStore.match(/Number\(ceremony\.policy_version\)/gu)).toHaveLength(2);
    expect(enterpriseAuthStore).toContain("assertTenantPolicyActivationReady(client, input.changedByIdentityId, policy)");
    expect(enterpriseAuthStore).toContain("invalidateTenantPolicyAuthorizations(client, input.tenantId)");
    expect(enterpriseAuthStore).toContain("reconcileTenantSessionsForPolicy(");
  });

  it("binds passkey replacement to registration and preserves authenticator invariants atomically", () => {
    expect(atomicReplacementMigration).toContain("replacement_credential_id uuid");
    expect(atomicReplacementMigration).toContain("ceremony_type = 'registration'");
    expect(atomicReplacementMigration).toContain("(device_type = 'multiDevice') = backup_eligible");
    expect(enterpriseAuthStore).toContain("assertCredentialSetPreservesIdentityPolicies(");
    expect(enterpriseAuthStore).toContain("revocation_reason='replaced'");
    expect(enterpriseAuthStore).toContain("replacedCredentialId: replacement.id");
  });

  it("persists the same six-attempt ceiling enforced by atomic MFA reservation", () => {
    expect(mfaChallengeAttemptCeilingMigration).toContain("SET attempt_count = 6");
    expect(mfaChallengeAttemptCeilingMigration).toContain("CHECK (attempt_count BETWEEN 0 AND 6) NOT VALID");
    expect(mfaChallengeAttemptCeilingMigration).toContain("VALIDATE CONSTRAINT mfa_challenges_attempt_count_check");
    expect(controlStore).toContain("challenge.attempt_count<6");
  });
});
