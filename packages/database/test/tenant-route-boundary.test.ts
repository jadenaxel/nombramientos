import { describe, expect, it, vi } from "vitest";

import { assertLocalTenantCredentialRoute, TenantPoolResolver } from "../src/pools.js";
import type { TenantCredentialRecord } from "../src/types.js";

const tenantId = "d0000000-0000-4000-8000-000000000001";
const suffix = tenantId.replaceAll("-", "");
const valid: TenantCredentialRecord = {
  tenantId,
  host: "127.0.0.1",
  port: 55_432,
  database: `nom_t_${suffix}`,
  user: `nom_r_${suffix}`,
  secretReference: `tenant-db/${tenantId}/runtime/v1`,
  credentialVersion: 1,
  sslMode: "disable",
};

describe("local tenant credential route boundary", () => {
  it("accepts the exact deterministic local route", () => {
    expect(() => assertLocalTenantCredentialRoute(valid)).not.toThrow();
  });

  it("rejects every routing or identity mismatch", () => {
    for (const changed of [
      { host: "localhost" },
      { host: "db.example.invalid" },
      { port: 5432 },
      { database: "nom_t_other" },
      { user: "nom_r_other" },
      { secretReference: "tenant-db/other/runtime/v1" },
      { credentialVersion: 0 },
      { sslMode: "require" as const },
    ]) expect(() => assertLocalTenantCredentialRoute({ ...valid, ...changed })).toThrow(/deterministic contract/u);
  });

  it("rejects a hostile route before decrypting its runtime password", async () => {
    const getSecret = vi.fn(async () => "must-not-be-read");
    const resolver = new TenantPoolResolver(
      async () => ({ ...valid, host: "db.example.invalid" }),
      { getSecret },
      1,
      1_000,
    );
    await expect(resolver.getPool(tenantId)).rejects.toThrow(/deterministic contract/u);
    expect(getSecret).not.toHaveBeenCalled();
    await resolver.close();
  });
});
