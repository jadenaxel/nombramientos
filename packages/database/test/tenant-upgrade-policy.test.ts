import { describe, expect, it } from "vitest";
import {
  assertTenantUpgradeAuthorized,
  irreversiblePendingMigrations,
  tenantUpgradeApprovalDigest,
  type TenantUpgradeApprovalContext,
} from "../src/tenant-upgrade-policy.js";
import { tenantSecurityTargetSha256 } from "../src/tenant-security-target.js";

const context = {
  tenantId: "50000000-0000-4000-8000-000000000001",
  backupId: "50000000-0000-4000-8000-000000000002",
  backupPayloadSha256: `sha256:${"a".repeat(64)}`,
  pendingMigrations: [
    { name: "024_session_title_envelopes.sql", checksum: "1".repeat(64) },
    { name: "025_member_contact_boundary.sql", checksum: "2".repeat(64) },
    { name: "026_candidacy_review_internal_reason_code.sql", checksum: "3".repeat(64) },
  ],
  catalogTarget: {
    version: "2025.1.0",
    departmentCount: 29,
    officeCount: 67,
    catalogSha256: `sha256:${"c".repeat(64)}`,
  },
  securityTargetSha256: tenantSecurityTargetSha256("50000000-0000-4000-8000-000000000001"),
  legacyInvitationReconciliation: {
    required: true,
    sourceSchema: "legacy_035",
    invitationCount: 1,
    bindingCount: 1,
    manifestSha256: `sha256:${"d".repeat(64)}`,
    controlSnapshotSha256: `sha256:${"e".repeat(64)}`,
  },
  reentryPlanReference: "change/tenant-5000/contact-reentry-v1",
} as const satisfies TenantUpgradeApprovalContext;

describe("tenant upgrade policy", () => {
  it("identifies exactly the irreversible historical-content boundaries", () => {
    expect(irreversiblePendingMigrations(context.pendingMigrations)).toEqual([
      "024_session_title_envelopes.sql",
      "025_member_contact_boundary.sql",
    ]);
  });

  it("binds approval to the exact tenant, backup, migration, catalog, security, and re-entry targets", () => {
    const expected = tenantUpgradeApprovalDigest(context);
    expect(() => assertTenantUpgradeAuthorized({ ...context, suppliedApproval: expected })).not.toThrow();
    expect(() => assertTenantUpgradeAuthorized({
      ...context,
      pendingMigrations: context.pendingMigrations.slice(0, 2),
      suppliedApproval: expected,
    })).toThrow(/exact preflight approval/u);
    expect(() => assertTenantUpgradeAuthorized({
      ...context,
      catalogTarget: { ...context.catalogTarget, catalogSha256: `sha256:${"d".repeat(64)}` },
      suppliedApproval: expected,
    })).toThrow(/exact preflight approval/u);
    expect(() => assertTenantUpgradeAuthorized({
      ...context,
      securityTargetSha256: `sha256:${"e".repeat(64)}`,
      suppliedApproval: expected,
    })).toThrow(/exact preflight approval/u);
    expect(() => assertTenantUpgradeAuthorized({
      ...context,
      legacyInvitationReconciliation: {
        ...context.legacyInvitationReconciliation,
        manifestSha256: `sha256:${"f".repeat(64)}`,
      },
      suppliedApproval: expected,
    })).toThrow(/exact preflight approval/u);
    expect(() => assertTenantUpgradeAuthorized({
      ...context,
      backupPayloadSha256: `sha256:${"b".repeat(64)}`,
      suppliedApproval: expected,
    })).toThrow(/exact preflight approval/u);
    expect(() => assertTenantUpgradeAuthorized({
      ...context,
      pendingMigrations: context.pendingMigrations.map((migration, index) => index === 0
        ? { ...migration, checksum: "f".repeat(64) }
        : migration),
      suppliedApproval: expected,
    })).toThrow(/exact preflight approval/u);
  });

  it("requires a preflight-bound approval even for a forward-only non-destructive plan", () => {
    const forward = {
      tenantId: "not-consulted",
      backupId: "not-consulted",
      backupPayloadSha256: "not-consulted",
      pendingMigrations: [{ name: "026_candidacy_review_internal_reason_code.sql", checksum: "3".repeat(64) }],
      catalogTarget: context.catalogTarget,
      securityTargetSha256: context.securityTargetSha256,
      legacyInvitationReconciliation: context.legacyInvitationReconciliation,
      reentryPlanReference: "not-consulted",
      suppliedApproval: "not-consulted",
    };
    expect(() => assertTenantUpgradeAuthorized(forward)).toThrow(/canonical tenant and backup UUIDs/u);
  });

  it("rejects an unusable re-entry reference before emitting a preflight digest", () => {
    expect(() => tenantUpgradeApprovalDigest({
      ...context,
      reentryPlanReference: "docs/operations.md#unsupported-fragment",
    })).toThrow(/bounded client re-entry plan reference/u);
    expect(() => tenantUpgradeApprovalDigest({
      ...context,
      securityTargetSha256: "not-a-checksum",
    })).toThrow(/security target checksum/u);
  });

  it("accepts a non-destructive plan only with its exact generated digest", () => {
    const forward = {
      ...context,
      pendingMigrations: [{ name: "026_candidacy_review_internal_reason_code.sql", checksum: "3".repeat(64) }],
    };
    expect(() => assertTenantUpgradeAuthorized({
      ...forward,
      suppliedApproval: tenantUpgradeApprovalDigest(forward),
    })).not.toThrow();
  });
});
