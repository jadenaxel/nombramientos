import { describe, expect, it } from "vitest";
import { TENANT_RUNTIME_GRANT_CONTRACT } from "../src/runtime-grant-contract.js";
import { TENANT_CANONICAL_TABLES } from "../src/tenant-maintenance-policy.js";
import {
  buildTenantSecurityTarget,
  securityTargetSha256,
  tenantSecurityTargetSha256,
  TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT,
  TENANT_OWNER_ROLE_SECURITY_CONTRACT,
  TENANT_RUNTIME_ROLE_SECURITY_CONTRACT,
  type TenantSecurityTarget,
} from "../src/tenant-security-target.js";

const TENANT_ID = "50000000-0000-4000-8000-000000000001";

describe("tenant maintenance security target", () => {
  it("deterministically binds exact role, ownership, grant, default-privilege, and inventory contracts", () => {
    const target = buildTenantSecurityTarget(TENANT_ID);
    expect(target.identities).toEqual({
      database: "nom_t_50000000000040008000000000000001",
      ownerRole: "nom_o_50000000000040008000000000000001",
      runtimeRole: "nom_r_50000000000040008000000000000001",
    });
    expect(target.roles).toEqual({
      owner: TENANT_OWNER_ROLE_SECURITY_CONTRACT,
      runtime: TENANT_RUNTIME_ROLE_SECURITY_CONTRACT,
    });
    expect(target.ownership).toMatchObject({
      databaseOwner: target.identities.ownerRole,
      publicSchemaOwner: "pg_database_owner",
      nonExtensionPublicObjectOwner: target.identities.ownerRole,
    });
    expect(target.inventory.exactTables).toEqual(TENANT_CANONICAL_TABLES);
    expect(target.inventory.runtimeGrantedFunctions).toEqual(
      [...TENANT_RUNTIME_GRANT_CONTRACT.functions].sort(),
    );
    expect(target.defaultPrivileges).toEqual([{
      grantorRole: target.identities.ownerRole,
      ...TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT,
    }]);
    expect(tenantSecurityTargetSha256(TENANT_ID)).toBe(securityTargetSha256(target));
    expect(tenantSecurityTargetSha256(TENANT_ID)).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(tenantSecurityTargetSha256(TENANT_ID)).toBe(tenantSecurityTargetSha256(TENANT_ID));
  });

  it("changes the checksum for every protected contract dimension", () => {
    const target = buildTenantSecurityTarget(TENANT_ID);
    const original = securityTargetSha256(target);
    const variants = [
      changedTarget(target, (copy) => {
        nestedRecord(nestedRecord(copy, "roles"), "runtime")["canLogin"] = false;
      }),
      changedTarget(target, (copy) => {
        nestedRecord(copy, "ownership")["publicSchemaOwner"] = "unexpected_owner";
      }),
      changedTarget(target, (copy) => {
        nestedArray(nestedRecord(nestedRecord(copy, "grants"), "tables"), "members")[0] = "DELETE";
      }),
      changedTarget(target, (copy) => {
        const defaults = copy["defaultPrivileges"];
        if (!Array.isArray(defaults)) throw new Error("Default privilege target is not an array");
        nestedArray(defaults[0], "privileges").push("EXECUTE");
      }),
      changedTarget(target, (copy) => {
        const inventory = nestedRecord(copy, "inventory");
        const tables = inventory["exactTables"];
        if (!Array.isArray(tables)) throw new Error("Security target table inventory is not an array");
        tables.pop();
      }),
    ];
    for (const variant of variants) expect(securityTargetSha256(variant)).not.toBe(original);
    expect(new Set(variants.map(securityTargetSha256)).size).toBe(variants.length);
  });

  it("is tenant-specific and rejects a non-canonical tenant identity", () => {
    expect(tenantSecurityTargetSha256("50000000-0000-4000-8000-000000000002"))
      .not.toBe(tenantSecurityTargetSha256(TENANT_ID));
    expect(() => tenantSecurityTargetSha256("not-a-tenant")).toThrow(/canonical tenant UUID/u);
  });
});

function changedTarget(
  source: TenantSecurityTarget,
  mutate: (copy: Record<string, unknown>) => void,
): TenantSecurityTarget {
  const copy = structuredClone(source) as unknown as Record<string, unknown>;
  mutate(copy);
  return copy as unknown as TenantSecurityTarget;
}

function nestedRecord(source: unknown, key: string): Record<string, unknown> {
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    throw new Error(`Security target ${key} container is invalid`);
  }
  const value = (source as Record<string, unknown>)[key];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Security target ${key} is invalid`);
  }
  return value as Record<string, unknown>;
}

function nestedArray(source: unknown, key: string): unknown[] {
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    throw new Error(`Security target ${key} container is invalid`);
  }
  const value = (source as Record<string, unknown>)[key];
  if (!Array.isArray(value)) throw new Error(`Security target ${key} is not an array`);
  return value;
}
