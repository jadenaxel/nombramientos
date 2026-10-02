import type { PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import {
  assertWritableTenantContentKey,
  ContentKeyWriteGuardError,
} from "../src/content-key-write-guard.js";

const identityId = "11111111-1111-4111-8111-111111111111";

describe("transactional tenant content-key write guard", () => {
  it("does not acquire lifecycle locks when no encrypted field is being written", async () => {
    const query = vi.fn();
    const result = await assertWritableTenantContentKey(client(query), {
      identityId,
      envelopes: [null, undefined],
    });
    expect(result).toBeNull();
    expect(query).not.toHaveBeenCalled();
  });

  it("uses the legacy read-only Demo grant without requesting table write privilege", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("tenant_settings")) return rows([{ kind: "demo" }]);
      if (sql.includes("device_key_grants")) return rows([{ tenant_key_id: "demo-key" }]);
      throw new Error(`Unexpected query: ${sql}`);
    });
    await expect(assertWritableTenantContentKey(client(query), {
      identityId,
      envelopes: [{ keyId: "demo-key" }, { keyId: "demo-key" }],
    })).resolves.toEqual({ tenantKind: "demo", tenantKeyId: "demo-key" });
    expect(query).toHaveBeenCalledTimes(2);
    expect(String(query.mock.calls[0]?.[0])).toMatch(/tenant_settings[\s\S]*FOR SHARE/u);
    const demoGrantSql = String(query.mock.calls[1]?.[0]);
    expect(demoGrantSql).toMatch(/device_key_grants[\s\S]*status='active'/u);
    expect(demoGrantSql).not.toMatch(/\bFOR\s+(?:NO\s+KEY\s+UPDATE|UPDATE|SHARE|KEY\s+SHARE)\b/u);
  });

  it("uses the real lifecycle without requiring a legacy grant and locks generation, grant and device", async () => {
    const currentKeyId = "22222222-2222-4222-8222-222222222222";
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("tenant_settings")) return rows([{ kind: "real" }]);
      if (sql.includes("app.proven_device_id") && !sql.includes("e2ee_key_generations")) return rows([{device_id:identityId}]);
      if (sql.includes("e2ee_key_generations")) return rows([{ tenant_key_id: currentKeyId }]);
      throw new Error(`Unexpected query: ${sql}`);
    });
    await expect(assertWritableTenantContentKey(client(query), {
      identityId,
      envelopes: [{ keyId: currentKeyId }],
    })).resolves.toEqual({ tenantKind: "real", tenantKeyId: currentKeyId });
    const lifecycleSql = String(query.mock.calls[2]?.[0]);
    expect(lifecycleSql).toMatch(/generation\.status='active'/u);
    expect(lifecycleSql).toMatch(/key_grant\.status='active'/u);
    expect(lifecycleSql).toMatch(/device\.status='active'/u);
    expect(lifecycleSql).toMatch(/FOR SHARE OF generation,key_grant,device/u);
    expect(lifecycleSql).not.toContain("device_key_grants");
  });

  it("requires the exact proven session/device even when another active identity grant remains", async () => {
    const currentKeyId = "77777777-7777-4777-8777-777777777777";
    const query = vi.fn(async (sql: string, parameters?: readonly unknown[]) => {
      if (sql.includes("tenant_settings")) return rows([{ kind: "real" }]);
      if (sql.includes("app.proven_device_id") && !sql.includes("e2ee_key_generations")) return rows([{device_id:identityId}]);
      expect(parameters).toEqual([identityId]);
      return rows([{ tenant_key_id: currentKeyId }]);
    });
    await expect(assertWritableTenantContentKey(client(query), {
      identityId,
      envelopes: [{ keyId: currentKeyId }],
    })).resolves.toEqual({ tenantKind: "real", tenantKeyId: currentKeyId });
    expect(String(query.mock.calls[2]?.[0])).toMatch(/device\.device_id=NULLIF\(current_setting\('app\.proven_device_id'/u);
    expect(String(query.mock.calls[2]?.[0])).toContain("binding.session_id=NULLIF(current_setting('app.session_id'");
    expect(String(query.mock.calls[2]?.[0])).toContain("binding.revoked_at IS NULL");
  });

  it("rejects absent, stale, revoked and arbitrary keys with stable public codes", async () => {
    const noGrant = vi.fn(async (sql: string) => sql.includes("tenant_settings") ? rows([{ kind: "real" }])
      : sql.includes("e2ee_key_generations") ? rows([]) : rows([{device_id:identityId}]));
    await expect(assertWritableTenantContentKey(client(noGrant), {
      identityId,
      envelopes: [{ keyId: "33333333-3333-4333-8333-333333333333" }],
    })).rejects.toEqual(expect.objectContaining({
      statusCode: 409,
      code: "KEY_GRANT_REQUIRED",
    }));

    const activeKey = "44444444-4444-4444-8444-444444444444";
    const activeGrant = vi.fn(async (sql: string) => sql.includes("tenant_settings") ? rows([{ kind: "real" }])
      : sql.includes("e2ee_key_generations") ? rows([{ tenant_key_id: activeKey }]) : rows([{device_id:identityId}]));
    for (const rejected of [
      [{ keyId: "55555555-5555-4555-8555-555555555555" }],
      [{ keyId: activeKey }, { keyId: "66666666-6666-4666-8666-666666666666" }],
    ]) {
      await expect(assertWritableTenantContentKey(client(activeGrant), {
        identityId,
        envelopes: rejected,
      })).rejects.toBeInstanceOf(ContentKeyWriteGuardError);
      await expect(assertWritableTenantContentKey(client(activeGrant), {
        identityId,
        envelopes: rejected,
      })).rejects.toEqual(expect.objectContaining({
        statusCode: 409,
        code: "ENVELOPE_KEY_MISMATCH",
      }));
    }
  });
  it("rejects a real write before looking up any grant without a verified device context",async() => {
    const query=vi.fn(async(sql:string) => sql.includes("tenant_settings") ? rows([{kind:"real"}]) : rows([{device_id:null}]));
    await expect(assertWritableTenantContentKey(client(query),{identityId,envelopes:[{keyId:identityId}]})).rejects.toMatchObject({code:"DEVICE_PROOF_REQUIRED"});
    expect(query).toHaveBeenCalledTimes(2);
  });
});

function client(query: ReturnType<typeof vi.fn>): PoolClient {
  return { query } as unknown as PoolClient;
}

function rows<T>(values: readonly T[]) {
  return { rows: values, rowCount: values.length };
}
