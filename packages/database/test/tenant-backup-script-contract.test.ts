import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = readFileSync(path.join(packageRoot, "scripts", "tenant-backup.ts"), "utf8");

describe("tenant backup and restore drill executable contract", () => {
  it("uses the shared lifecycle/readiness/empty-operational policy", () => {
    expect(source).toContain("resolveTenantMaintenanceRoute(control, tenantId)");
    expect(source).toContain("listTenantMaintenanceRoutes(context.controlPool)");
    expect(source).toContain("await assertTenantMaintenanceDatabase(client, tenant)");
  });

  it("guards scratch collisions against every registered database", () => {
    expect(source).toContain('"SELECT database_name::text FROM tenants ORDER BY id"');
    expect(source).not.toMatch(/database_name::text FROM tenants WHERE status=/u);
    expect(source).toContain("assertScratchDatabaseName(scratch, registeredNames)");
    expect(source).toContain("dropScratchDatabase(context.controlPool, scratch, registeredNames)");
  });

  it("requires exact neighbor coverage and reports its ids and count", () => {
    expect(source).toContain("assertExpectedTenantComparisons(otherTenants.map(({ id }) => id), comparedTenantIds)");
    expect(source).toContain("comparedTenantIds: result.comparedTenantIds");
    expect(source).toContain("comparedTenantCount: result.comparedTenantIds.length");
  });

  it("reports only sanitized lifecycle evidence for the selected tenant", () => {
    expect(source).toContain("tenantLifecycle: tenant.status");
    expect(source).toContain("maintenanceClass: tenant.maintenanceClass");
  });

  it("zeroes decoded backup key material on encryption and restore paths", () => {
    expect(source).toContain("activeKeyMaterial.fill(0)");
    expect(source).toContain("backupKeyMaterial.fill(0)");
    expect(source).not.toContain('decryptBackupPayload(\n      payloadPath,\n      plaintextDump,\n      Buffer.from(backupKey.keyB64');
  });

  it("uses portable PostgreSQL executable names on Windows and Linux", () => {
    expect(source).toContain('process.platform === "win32" ? `${tool}.exe` : tool');
    expect(source).toContain('pgToolPath(context.pgBin, "pg_dump")');
    expect(source).toContain('pgToolPath(context.pgBin, "pg_restore")');
    expect(source).not.toContain('path.join(context.pgBin, "pg_dump.exe")');
    expect(source).not.toContain('path.join(context.pgBin, "pg_restore.exe")');
  });
});
