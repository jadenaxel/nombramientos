import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migration = readFileSync(
  path.join(packageRoot, "migrations", "control", "023_atomic_authentication_context_lock.sql"),
  "utf8",
);
const controlStore = readFileSync(path.join(packageRoot, "src", "control-store.ts"), "utf8");
const enterpriseAuthStore = readFileSync(path.join(packageRoot, "src", "enterprise-auth-store.ts"), "utf8");
const grants = readFileSync(path.join(packageRoot, "scripts", "migrate-control.ts"), "utf8");

describe("atomic authentication-context lock contract", () => {
  it("serializes policy and active identity, membership, and tenant state behind a narrow definer", () => {
    expect(migration).toContain("CREATE FUNCTION lock_active_authentication_context");
    expect(migration).toContain("SECURITY DEFINER");
    expect(migration).toContain("SET search_path = pg_catalog");
    expect(migration).toContain("pg_catalog.pg_advisory_xact_lock");
    expect(migration).toContain("tenant_identity_policy:");
    expect(migration).toContain("identity.status = 'active'");
    expect(migration).toContain("membership.status = 'active'");
    expect(migration).toContain("tenant.status = 'active'");
    expect(migration).toContain("FOR SHARE OF identity, membership, tenant");
    expect(migration).toContain(
      "REVOKE ALL ON FUNCTION lock_active_authentication_context(uuid,uuid) FROM PUBLIC",
    );
  });

  it("uses the same boundary for password/TOTP sessions, passkey sessions, and tenant switching", () => {
    expect(controlStore.match(/lock_active_authentication_context\(\$1,\$2\)/gu)).toHaveLength(2);
    expect(enterpriseAuthStore).toContain("lock_active_authentication_context($1,$2)");
    expect(controlStore).not.toContain("FOR SHARE OF membership,tenant");
    expect(controlStore).not.toContain("FOR SHARE OF membership, tenant");
    expect(enterpriseAuthStore).not.toContain("FOR SHARE OF membership,identity,tenant");
  });

  it("grants only function execution to the runtime role", () => {
    expect(grants).toContain(
      "GRANT EXECUTE ON FUNCTION lock_active_authentication_context(uuid,uuid) TO %I",
    );
    expect(grants).not.toContain("GRANT UPDATE ON TABLE tenant_memberships");
    expect(grants).not.toContain("GRANT UPDATE ON TABLE tenants");
  });
});
