import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { assertExactWorkspaceAdminUrl } from "./local-test-database-boundary.js";

const exact = "postgresql://nom_admin:fixture@127.0.0.1:55432/postgres";

describe("live API test database boundary", () => {
  it("accepts only the canonical isolated administrator URL", () => {
    expect(assertExactWorkspaceAdminUrl(exact)).toBe(exact);
  });

  it("rejects aliases, alternate identities, routes and pg connection-string overrides", () => {
    for (const value of [
      exact.replace("127.0.0.1", "localhost"),
      exact.replace("127.0.0.1", "127.0.0.1."),
      exact.replace("127.0.0.1", "127.1"),
      exact.replace("127.0.0.1", "2130706433"),
      exact.replace("127.0.0.1", "[::1]"),
      exact.replace("55432", "5432"),
      exact.replace("nom_admin", "postgres"),
      exact.replace("nom_admin", "nom%5Fadmin"),
      exact.replace("nom_admin:fixture", "ignored@nom_admin:fixture"),
      exact.replace("/postgres", "/nombramientos_control"),
      exact.replace("/postgres", "/%70ostgres"),
      `${exact}?host=database.example.test`,
      `${exact}?port=5432`,
      `${exact}#ignored`,
      ` ${exact}`,
      `${exact} `,
    ]) {
      expect(() => assertExactWorkspaceAdminUrl(value), value).toThrow(/exact protected/u);
    }
  });

  it("reattests the exact administrator before provisioning and immediately before cleanup DDL", () => {
    const source = readFileSync(new URL("./temporary-active-tenant.ts", import.meta.url), "utf8");
    const provisionStart = source.indexOf("export async function provisionTemporaryActiveTenant");
    const provisioner = source.indexOf("new TenantProvisioner", provisionStart);
    const provisionAttestation = source.indexOf("exactWorkspaceAdminConnection(databaseAdminUrl)", provisionStart);
    expect(provisionStart).toBeGreaterThanOrEqual(0);
    expect(provisionAttestation).toBeGreaterThan(provisionStart);
    expect(provisionAttestation).toBeLessThan(provisioner);

    const destroyStart = source.indexOf("export async function destroyTemporaryActiveTenant");
    const controlConnect = source.indexOf("control.connect()", destroyStart);
    const entryAttestation = source.indexOf("assertExactWorkspaceAdminUrl(databaseAdminUrl)", destroyStart);
    const cleanupPool = source.indexOf("const cluster = new Pool", destroyStart);
    const cleanupAttestation = source.indexOf("exactWorkspaceAdminConnection(databaseAdminUrl)", cleanupPool);
    expect(entryAttestation).toBeGreaterThan(destroyStart);
    expect(entryAttestation).toBeLessThan(controlConnect);
    expect(cleanupAttestation).toBeGreaterThan(cleanupPool);
    expect(source).not.toContain("connectionString: databaseAdminUrl");
  });
});
