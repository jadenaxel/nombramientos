/**
 * Session-memory keyring for tenant content-key generations. CryptoKeys remain
 * non-extractable; raw bytes are never retained here. A tenant switch clears
 * every remembered generation before accepting the new current key.
 */
export class TenantCryptoKeyring {
  #tenantId: string | undefined;
  readonly #keys = new Map<string, CryptoKey>();

  public get tenantId(): string | undefined {
    return this.#tenantId;
  }

  public rememberCurrent(tenantId: string, keyId: string, key: CryptoKey): void {
    if (this.#tenantId !== tenantId) {
      this.clear();
      this.#tenantId = tenantId;
    }
    this.#keys.set(keyId, key);
  }

  public rememberHistorical(tenantId: string, keyId: string, key: CryptoKey): void {
    if (this.#tenantId !== tenantId) throw new Error("TENANT_KEY_CONTEXT_MISMATCH");
    this.#keys.set(keyId, key);
  }

  public keyFor(tenantId: string, keyId: string): CryptoKey | undefined {
    return this.#tenantId === tenantId ? this.#keys.get(keyId) : undefined;
  }

  public keyIds(tenantId: string): readonly string[] {
    return this.#tenantId === tenantId ? [...this.#keys.keys()].sort() : [];
  }

  public clear(): void {
    this.#keys.clear();
    this.#tenantId = undefined;
  }
}
