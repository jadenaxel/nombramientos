import { createHash } from "node:crypto";

export const IRREVERSIBLE_TENANT_MIGRATIONS = [
  "024_session_title_envelopes.sql",
  "025_member_contact_boundary.sql",
] as const;

export interface TenantUpgradeApprovalContext {
  readonly tenantId: string;
  readonly backupId: string;
  readonly backupPayloadSha256: string;
  readonly pendingMigrations: readonly {
    readonly name: string;
    readonly checksum: string;
  }[];
  readonly catalogTarget: {
    readonly version: string;
    readonly departmentCount: number;
    readonly officeCount: number;
    readonly catalogSha256: string;
  };
  readonly securityTargetSha256: string;
  readonly legacyInvitationReconciliation: {
    readonly required: boolean;
    readonly sourceSchema: "legacy_035" | "transactional_036";
    readonly invitationCount: number;
    readonly bindingCount: number;
    readonly manifestSha256: string;
    readonly controlSnapshotSha256: string;
  };
  readonly reentryPlanReference: string;
}

export interface TenantUpgradeAuthorization extends TenantUpgradeApprovalContext {
  readonly suppliedApproval: string;
}

export function irreversiblePendingMigrations(
  pendingMigrations: readonly { readonly name: string }[],
): readonly string[] {
  const irreversible = new Set<string>(IRREVERSIBLE_TENANT_MIGRATIONS);
  return pendingMigrations.map(({ name }) => name).filter((migration) => irreversible.has(migration));
}

export function tenantUpgradeApprovalDigest(context: TenantUpgradeApprovalContext): string {
  assertTenantUpgradeApprovalContext(context);
  const payload = JSON.stringify({
    tenantId: context.tenantId,
    backupId: context.backupId,
    backupPayloadSha256: context.backupPayloadSha256,
    pendingMigrations: context.pendingMigrations.map(({ name, checksum }) => ({ name, checksum })),
    catalogTarget: {
      version: context.catalogTarget.version,
      departmentCount: context.catalogTarget.departmentCount,
      officeCount: context.catalogTarget.officeCount,
      catalogSha256: context.catalogTarget.catalogSha256,
    },
    securityTargetSha256: context.securityTargetSha256,
    legacyInvitationReconciliation: {
      required: context.legacyInvitationReconciliation.required,
      sourceSchema: context.legacyInvitationReconciliation.sourceSchema,
      invitationCount: context.legacyInvitationReconciliation.invitationCount,
      bindingCount: context.legacyInvitationReconciliation.bindingCount,
      manifestSha256: context.legacyInvitationReconciliation.manifestSha256,
      controlSnapshotSha256: context.legacyInvitationReconciliation.controlSnapshotSha256,
    },
    reentryPlanReference: context.reentryPlanReference,
  });
  return `sha256:${createHash("sha256").update(payload).digest("hex")}`;
}

export function assertTenantUpgradeApprovalContext(input: TenantUpgradeApprovalContext): void {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  if (!uuid.test(input.tenantId) || !uuid.test(input.backupId)) {
    throw new Error("Tenant migration approval requires canonical tenant and backup UUIDs");
  }
  if (!/^sha256:[0-9a-f]{64}$/u.test(input.backupPayloadSha256)) {
    throw new Error("Tenant migration approval requires a verified backup payload checksum");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(input.catalogTarget.version)
    || !Number.isInteger(input.catalogTarget.departmentCount)
    || input.catalogTarget.departmentCount < 1
    || !Number.isInteger(input.catalogTarget.officeCount)
    || input.catalogTarget.officeCount < 1
    || !/^sha256:[0-9a-f]{64}$/u.test(input.catalogTarget.catalogSha256)) {
    throw new Error("Tenant migration approval requires an exact versioned catalog target");
  }
  if (!/^sha256:[0-9a-f]{64}$/u.test(input.securityTargetSha256)) {
    throw new Error("Tenant migration approval requires an exact security target checksum");
  }
  const legacy = input.legacyInvitationReconciliation;
  if (
    !legacy
    || !["legacy_035", "transactional_036"].includes(legacy.sourceSchema)
    || !Number.isInteger(legacy.invitationCount)
    || legacy.invitationCount < 0
    || !Number.isInteger(legacy.bindingCount)
    || legacy.bindingCount < legacy.invitationCount
    || !/^sha256:[0-9a-f]{64}$/u.test(legacy.manifestSha256)
    || !/^sha256:[0-9a-f]{64}$/u.test(legacy.controlSnapshotSha256)
    || (legacy.invitationCount === 0 && (legacy.bindingCount !== 0 || legacy.required))
    || (legacy.sourceSchema === "legacy_035" && legacy.invitationCount > 0 && !legacy.required)
  ) {
    throw new Error("Tenant migration approval requires exact legacy invitation reconciliation evidence");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}$/u.test(input.reentryPlanReference)) {
    throw new Error("Tenant migration approval requires a bounded client re-entry plan reference");
  }
}

export function assertTenantUpgradeAuthorized(input: TenantUpgradeAuthorization): void {
  const irreversible = irreversiblePendingMigrations(input.pendingMigrations);
  assertTenantUpgradeApprovalContext(input);
  const expected = tenantUpgradeApprovalDigest(input);
  if (input.suppliedApproval !== expected) {
    throw new Error(
      `Tenant migration plan${irreversible.length > 0 ? ` (irreversible: ${irreversible.join(", ")})` : ""} requires its exact preflight approval digest`,
    );
  }
}
