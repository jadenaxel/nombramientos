import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = readFileSync(path.join(packageRoot, "scripts", "migrate-tenants.ts"), "utf8");

describe("tenant upgrade executable contract", () => {
  it("has an explicit read-only preflight/apply split and exact tenant lifecycle guard", () => {
    expect(source).toContain('z.enum(["preflight", "apply"])');
    expect(source).toContain('requiredEnvironment("NOMBRAMIENTOS_TENANT_UPGRADE_MODE")');
    expect(source).toContain("resolveTenantMaintenanceRoute(control, selectedTenantId)");
    expect(source).toContain("assertTenantMaintenanceDatabase(tenantPool, tenant)");
    expect(source).toContain('if (upgradeMode === "preflight")');
    expect(source).toContain("expectedPendingMigrations: plan.pending");
    expect(source).toContain("tenantLifecycle: tenant.status");
    expect(source).toContain("maintenanceClass: tenant.maintenanceClass");
    expect(source).toContain("tenantCatalogTarget(catalogPackage2025)");
    expect(source).toContain("tenantSecurityTargetSha256(selectedTenantId)");
    expect(source).toContain("catalogReconciliationRequired");
    expect(source).toContain("schemaVersion: TENANT_UPGRADE_REPORT_SCHEMA_VERSION");
    expect(source).toContain('status: "no_changes"');
    expect(source).toContain('status: "approval_required"');
    expect(source).toContain('status: "applied"');
    expect(source.match(/securityTargetSha256,/gu)).toHaveLength(4);
  });

  it("authenticates the complete backup artifact before accepting an approval", () => {
    expect(source).toContain('readFile(path.join(backupDirectory, "manifest.sha256"), "utf8")');
    expect(source).toContain("expectedManifestChecksum.trim() !== sha256(manifestBytes)");
    expect(source).toContain("await decryptBackupPayload(");
    expect(source).toContain("dump.bytes !== manifest.core.dump.bytes");
    expect(source).toContain("dump.sha256 !== manifest.core.dump.sha256");
    expect(source).toContain("compareTenantInvariants(manifest.core.invariant, currentInvariant)");
    expect(source).toContain("key.fill(0)");
    expect(source).toContain("await removeTemporaryUpgradeDirectory(workDirectory, temporaryRoot)");
  });

  it("requires a quiet maintenance boundary immediately before apply", () => {
    const sessionGuard = source.indexOf("await assertNoOtherTenantSessions(tenantPool)");
    const backupRecheck = source.indexOf("await assertTenantMatchesBackupInvariant(tenantPool", sessionGuard);
    const catalogRecheck = source.indexOf("assertTenantCatalogReconciliationSafe(catalogAtApply)", sessionGuard);
    const migrationApply = source.indexOf("const applied = await runMigrations(tenantPool");
    expect(sessionGuard).toBeGreaterThan(0);
    expect(backupRecheck).toBeGreaterThan(sessionGuard);
    expect(catalogRecheck).toBeGreaterThan(backupRecheck);
    expect(migrationApply).toBeGreaterThan(sessionGuard);
    expect(migrationApply).toBeGreaterThan(catalogRecheck);
  });

  it("blocks known non-reconcilable catalog state before backup or committed migrations", () => {
    const initialCatalogCheck = source.indexOf("assertTenantCatalogReconciliationSafe(catalogBefore)");
    const backupVerification = source.indexOf("await verifyCurrentLocalBackup(");
    const migrationApply = source.indexOf("const applied = await runMigrations(tenantPool");
    expect(initialCatalogCheck).toBeGreaterThan(0);
    expect(backupVerification).toBeGreaterThan(initialCatalogCheck);
    expect(migrationApply).toBeGreaterThan(backupVerification);
  });

  it("binds the computed security target into approval before reconciliation", () => {
    const target = source.indexOf("const securityTargetSha256 = tenantSecurityTargetSha256(selectedTenantId)");
    const approvalContext = source.indexOf("const approvalContext = {");
    const approvalDigest = source.indexOf("tenantUpgradeApprovalDigest(approvalContext)");
    const reconciliation = source.indexOf("await reconcileTenantOwnershipAndRuntimeGrants(");
    expect(target).toBeGreaterThan(0);
    expect(approvalContext).toBeGreaterThan(target);
    expect(source.slice(approvalContext, approvalDigest)).toContain("securityTargetSha256");
    expect(approvalDigest).toBeGreaterThan(approvalContext);
    expect(reconciliation).toBeGreaterThan(approvalDigest);
  });

  it("binds exact legacy invitation evidence into preflight and finalizes it after tenant migration", () => {
    const inspect = source.indexOf("const legacyInvitationBefore = await inspectLegacyInvitationReconciliation(");
    const approvalContext = source.indexOf("const approvalContext = {");
    const lockedInspect = source.indexOf("const lockedLegacyInvitation = await inspectLegacyInvitationReconciliation(");
    const migrationApply = source.indexOf("const applied = await runMigrations(tenantPool");
    const manifestInstall = source.indexOf("await installLegacyInvitationReconciliationManifest(", migrationApply);
    const appliedCheck = source.indexOf("assertLegacyInvitationReconciliationApplied(", migrationApply);
    const evidenceFinalize = source.indexOf("await finalizeLegacyInvitationReconciliationEvidence(", appliedCheck);
    const controlCommit = source.indexOf('await controlClient.query("COMMIT")', evidenceFinalize);
    expect(inspect).toBeGreaterThan(0);
    expect(approvalContext).toBeGreaterThan(inspect);
    expect(source.slice(approvalContext, source.indexOf("tenantUpgradeApprovalDigest", approvalContext)))
      .toContain("legacyInvitationReconciliation");
    expect(lockedInspect).toBeGreaterThan(approvalContext);
    expect(migrationApply).toBeGreaterThan(lockedInspect);
    expect(manifestInstall).toBeGreaterThan(migrationApply);
    expect(appliedCheck).toBeGreaterThan(manifestInstall);
    expect(evidenceFinalize).toBeGreaterThan(appliedCheck);
    expect(controlCommit).toBeGreaterThan(evidenceFinalize);
  });

  it("locks the control route and atomically revalidates ownership plus grants after migrations", () => {
    const controlBegin = source.indexOf('await controlClient.query("BEGIN")');
    const identityPolicyLock = source.indexOf(
      "await lockLegacyInvitationReconciliationBoundary(controlClient, tenant.id)",
    );
    const routeLock = source.indexOf("await lockTenantMaintenanceRoute(controlClient, tenant.id)");
    const migrationApply = source.indexOf("const applied = await runMigrations(tenantPool");
    const catalogReconciliation = source.indexOf("await reconcileTenantCatalog(tenantPool", migrationApply);
    const ownership = source.indexOf("await reconcileTenantObjectOwnership(tenantPool");
    const atomicReconciliation = source.indexOf("await reconcileTenantOwnershipAndRuntimeGrants(");
    const canonicalInventory = source.indexOf(
      "await assertCanonicalTenantTableInventory(tenantClient, lockedTenant.id)",
    );
    const routeRecheck = source.indexOf(
      "await resolveTenantMaintenanceRoute(controlClient, tenant.id)",
      routeLock,
    );
    const controlCommit = source.indexOf('await controlClient.query("COMMIT")', routeLock);

    expect(controlBegin).toBeGreaterThan(0);
    expect(identityPolicyLock).toBeGreaterThan(controlBegin);
    expect(routeLock).toBeGreaterThan(identityPolicyLock);
    expect(ownership).toBeGreaterThan(routeLock);
    expect(migrationApply).toBeGreaterThan(ownership);
    expect(catalogReconciliation).toBeGreaterThan(migrationApply);
    expect(atomicReconciliation).toBeGreaterThan(catalogReconciliation);
    expect(canonicalInventory).toBeGreaterThan(atomicReconciliation);
    expect(routeRecheck).toBeGreaterThan(atomicReconciliation);
    expect(controlCommit).toBeGreaterThan(routeRecheck);
    expect(source).toContain("assertRouteUnchanged(tenant, lockedTenant)");
    expect(source).toContain("assertRouteUnchanged(lockedTenant, confirmedRoute)");
    expect(source).not.toContain("applyRuntimeGrants(tenantPool");
  });
});
