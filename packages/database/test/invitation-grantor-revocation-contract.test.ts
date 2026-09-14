import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const control024 = readFileSync(
  path.join(packageRoot, "migrations", "control", "024_invitation_grantor_revocation_boundary.sql"),
  "utf8",
);
const tenant034 = readFileSync(
  path.join(packageRoot, "migrations", "tenant", "034_invitation_role_delegation.sql"),
  "utf8",
);
const tenant027 = readFileSync(
  path.join(packageRoot, "migrations", "tenant", "027_security_definer_boundaries.sql"),
  "utf8",
);
const tenant036 = readFileSync(
  path.join(packageRoot, "migrations", "tenant", "036_transactional_invitation_grantor_lock.sql"),
  "utf8",
);
const invitationStore = readFileSync(path.join(packageRoot, "src", "invitation-store.ts"), "utf8");
const controlGrants = readFileSync(path.join(packageRoot, "scripts", "migrate-control.ts"), "utf8");
const reconciler = readFileSync(path.join(packageRoot, "src", "invitation-reconciler.ts"), "utf8");
const worker = readFileSync(path.join(packageRoot, "scripts", "process-provisioning-jobs.ts"), "utf8");

describe("invitation grantor revocation boundary", () => {
  it("repairs historical open invitations and wires every control offboarding boundary", () => {
    expect(control024).toContain("WHERE invitation.status IN ('pending','accepting','compensating')");
    expect(control024).toContain("last_error_code = 'GRANTOR_ACCESS_REVOKED'");
    expect(control024).toContain("platform_identity_invitation_authority_loss");
    expect(control024).toContain("tenant_membership_invitation_authority_loss");
    expect(control024).toContain("tenant_invitation_authority_loss");
    expect(control024).toContain("revocation_reason = 'ADMIN_ACCESS_REVOCATION'");
  });

  it("revalidates the grantor in the atomic membership insert and keeps trigger routines private", () => {
    expect(control024).toContain("CREATE TRIGGER tenant_membership_invitation_grantor_guard");
    expect(control024).toContain("FOR SHARE OF identity,membership,tenant");
    expect(control024).toContain("CONSTRAINT = 'tenant_invitation_grantor_inactive'");
    expect(control024).toContain("REVOKE ALL ON FUNCTION enforce_active_invitation_grantor() FROM PUBLIC");
    expect(control024).toContain(
      "REVOKE ALL ON FUNCTION revoke_outstanding_invitations_on_authority_loss() FROM PUBLIC",
    );
  });

  it("validates the raw bearer read-only, then locks authority before the invitation CAS", () => {
    const claim = invitationStore.slice(
      invitationStore.indexOf("public async claim"),
      invitationStore.indexOf("public async complete"),
    );
    expect(claim).toContain("inspect_tenant_invitation_bearer($1,$2,$3)");
    expect(claim).toContain("SELECT lock_active_invitation_grantor($1,$2,$3,$4) AS active");
    expect(claim).not.toContain("token_hash=$1");
    expect(claim.indexOf("lock_active_invitation_grantor")).toBeLessThan(
      claim.indexOf("begin_tenant_invitation_acceptance"),
    );
    expect(control024.slice(
      control024.indexOf("CREATE FUNCTION inspect_tenant_invitation_bearer"),
      control024.indexOf("CREATE FUNCTION begin_tenant_invitation_acceptance"),
    )).not.toContain("FOR UPDATE");
  });

  it("takes the grantor context lock before invitation rows in create and completion", () => {
    const create = invitationStore.slice(
      invitationStore.indexOf("public async create"),
      invitationStore.indexOf("public async list"),
    );
    const complete = invitationStore.slice(
      invitationStore.indexOf("public async complete"),
      invitationStore.indexOf("public async abortAcceptance"),
    );
    expect(create.indexOf("lock_active_authentication_context")).toBeLessThan(
      create.indexOf("FROM tenant_invitations"),
    );
    expect(complete.indexOf("lock_active_invitation_grantor")).toBeLessThan(
      complete.indexOf("complete_tenant_invitation_acceptance"),
    );
  });

  it("retains active tenant bindings through role activation and access mutations", () => {
    expect(tenant036).toContain("FOR SHARE OF binding");
    expect(tenant034).toContain("PERFORM public.assert_tenant_invitation_role_delegation_allowed(");
    expect(tenant036).toContain("PERFORM binding.role_id");
    expect(tenant036).toContain("REVOKE ALL ON FUNCTION public.assert_tenant_invitation_role_delegation_allowed");
    expect(tenant036).toContain("REVOKE ALL ON FUNCTION public.assert_local_role_definition_allowed");
  });

  it("requires an exact transaction-local legacy manifest before binding acceptance epochs", () => {
    expect(tenant036).toContain("pg_temp.legacy_invitation_binding_reconciliation_manifest");
    expect(tenant036).toContain("legacy_invitation_binding_reconciliation_required");
    expect(tenant036).toContain("legacy_invitation_binding_reconciliation_ambiguous");
    expect(tenant036).toContain("binding.identity_id IS DISTINCT FROM manifest.invited_identity_id");
    expect(tenant036).toContain("binding.granted_by_identity_id IS DISTINCT FROM manifest.granted_by_identity_id");
    expect(tenant036).toContain("actual.role_codes IS DISTINCT FROM manifest.role_codes");
    expect(tenant036).toContain("SET source_acceptance_id=manifest.acceptance_id");
    expect(tenant036).toContain("role_bindings_invitation_acceptance_complete");
  });

  it("reconciles control routine ACLs as a closed-world allowlist", () => {
    expect(controlGrants).toContain("REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC");
    expect(controlGrants).toContain(
      "REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM %I",
    );
    expect(controlGrants).toContain(
      "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC",
    );
    expect(controlGrants).toContain(
      "GRANT EXECUTE ON FUNCTION lock_active_authentication_context(uuid,uuid)",
    );
    expect(controlGrants).toContain('"claim_tenant_invitation_reconciliation(uuid)"');
    expect(controlGrants).toContain(
      '"finish_tenant_invitation_reconciliation(uuid,uuid,uuid,integer,uuid,boolean,text)"',
    );
  });

  it("leases background repair per exact invitation without poison-row starvation", () => {
    expect(control024).toContain("CREATE FUNCTION claim_tenant_invitation_reconciliation(p_lease_token uuid)");
    expect(control024).toContain("FOR UPDATE OF invitation SKIP LOCKED");
    expect(control024).toContain("reconciliation_next_attempt_at <= clock_timestamp()");
    expect(control024).toContain("reconciliation_lease_expires_at <= clock_timestamp()");
    expect(control024).toContain("clock_timestamp() + interval '5 minutes'");
    expect(control024).toContain("CREATE FUNCTION finish_tenant_invitation_reconciliation(");
    expect(control024).toContain("AND invitation.acceptance_id = p_acceptance_id");
    expect(control024).toContain("AND invitation.acceptance_attempt = p_acceptance_attempt");
    expect(control024).toContain("AND invitation.reconciliation_lease_token = p_lease_token");
    expect(control024).toContain("pg_catalog.power(2,LEAST(invitation.reconciliation_attempt_count,8))");
    expect(reconciler).toContain("failReconciliation");
    expect(invitationStore).toContain("invitation.reconciliation_failed");
    expect(invitationStore).toContain("acceptanceAttempt: claim.acceptanceAttempt");
    expect(worker).toContain("environment.DATABASE_CONTROL_URL");
    expect(worker).not.toContain("reconciliationFailureCount");
    const runtime = worker.slice(
      worker.indexOf("const invitationRuntime"),
      worker.indexOf("const invitationReconciler"),
    );
    expect(runtime).not.toContain("DATABASE_ADMIN_URL");
  });

  it("reports an initial administrator active only after durable capability finalization and a real strong factor", () => {
    expect(control024).toContain("initial_admin.authority_finalized_at IS NOT NULL");
    expect(control024).toContain("initial_admin.strong_factor_enrolled");
    expect(control024).toContain("identity.mfa_enabled");
    expect(control024).toContain("identity.totp_secret_ciphertext IS NOT NULL");
    expect(control024).toContain("identity.passkey_enabled");
    expect(control024).toContain("credential.revoked_at IS NULL");
    expect(control024).toContain("credential.user_verified");
  });
});
