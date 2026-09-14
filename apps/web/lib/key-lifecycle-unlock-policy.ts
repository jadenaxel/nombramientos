export type TenantGrantUnlockMode = "current-write" | "historical-read-only";

export type TenantGrantUnlockContext = {
  readonly grantStatus: string;
  readonly grantTenantKeyId: string;
  readonly currentTenantKeyId: string | undefined;
  readonly tenantId: string;
  readonly vaultTenantId: string | undefined;
  readonly vaultKeyId: string | undefined;
};

export function tenantGrantUnlockMode(
  context: TenantGrantUnlockContext,
): TenantGrantUnlockMode | undefined {
  if (
    context.grantStatus === "active"
    && context.grantTenantKeyId === context.currentTenantKeyId
  ) return "current-write";

  if (
    context.grantStatus === "retired"
    && context.currentTenantKeyId !== undefined
    && context.vaultTenantId === context.tenantId
    && context.vaultKeyId === context.currentTenantKeyId
  ) return "historical-read-only";

  return undefined;
}

export function canUnlockTenantGrant(context: TenantGrantUnlockContext): boolean {
  return tenantGrantUnlockMode(context) !== undefined;
}

export async function unlockTenantGrantForVault(input: TenantGrantUnlockContext & {
  readonly keyBytes: Uint8Array<ArrayBuffer>;
  readonly unlockCurrent: (
    keyBytes: Uint8Array<ArrayBuffer>,
    keyId: string,
    tenantId: string,
  ) => Promise<void>;
  readonly rememberHistorical: (
    keyBytes: Uint8Array<ArrayBuffer>,
    keyId: string,
    tenantId: string,
  ) => Promise<void>;
}): Promise<TenantGrantUnlockMode> {
  const mode = tenantGrantUnlockMode(input);
  if (mode === "current-write") {
    await input.unlockCurrent(input.keyBytes, input.grantTenantKeyId, input.tenantId);
    return mode;
  }
  if (mode === "historical-read-only") {
    await input.rememberHistorical(input.keyBytes, input.grantTenantKeyId, input.tenantId);
    return mode;
  }
  throw new Error("CLIENT_CRYPTO_ERROR");
}
