export interface TenantSeedTarget {
  readonly databaseName: string;
  readonly tenantId: string;
  readonly kind: string;
}

/**
 * Fail-closed guard for a privileged synthetic seed. Both the control-plane
 * mapping and the settings row inside the connected database must identify the
 * one deterministic demo target before any fixture write is attempted.
 */
export function assertSyntheticSeedTarget(
  expected: TenantSeedTarget,
  actual: TenantSeedTarget,
): void {
  if (
    actual.databaseName !== expected.databaseName
    || actual.tenantId !== expected.tenantId
    || actual.kind !== expected.kind
  ) {
    throw new Error("Synthetic seed target verification failed; refusing all writes");
  }
}

