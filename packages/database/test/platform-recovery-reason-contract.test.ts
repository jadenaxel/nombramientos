import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = path.resolve(packageRoot, "..", "..");
const issuerSource = readFileSync(path.join(packageRoot, "scripts", "issue-platform-admin-bootstrap.ts"), "utf8");
const migrationSource = readFileSync(
  path.join(packageRoot, "migrations", "control", "011_platform_recovery_reason_codes.sql"),
  "utf8",
);
const operationsSource = readFileSync(path.join(workspaceRoot, "docs", "operations.md"), "utf8");

describe("platform administrator recovery metadata boundary", () => {
  it("accepts only closed non-sensitive codes and stores a one-way incident reference", () => {
    for (const code of ["SECURITY_RESPONSE", "ADMIN_ACCESS_LOSS", "AUTHORIZED_RECOVERY"]) {
      expect(issuerSource).toContain(`"${code}"`);
      expect(migrationSource).toContain(`'${code}'`);
    }
    expect(issuerSource).toContain("NOMBRAMIENTOS_PLATFORM_RECOVERY_REASON_CODE");
    expect(issuerSource).toContain("NOMBRAMIENTOS_PLATFORM_RECOVERY_INCIDENT_REF");
    expect(issuerSource).toContain("z.string().uuid().safeParse");
    expect(issuerSource).toContain("sha256(externalIncidentReference.data)");
    expect(migrationSource).toContain("DROP CONSTRAINT IF EXISTS platform_admin_bootstrap_tokens_check");
    expect(migrationSource).toContain("external_incident_ref_hash ~ '^[0-9a-f]{64}$'");
  });

  it("does not preserve the former free-text recovery channel in code or operator guidance", () => {
    expect(issuerSource).not.toContain('process.env["NOMBRAMIENTOS_PLATFORM_RECOVERY_REASON"]');
    expect(issuerSource).not.toContain("recovery_reason,expires_at");
    expect(operationsSource).not.toContain("NOMBRAMIENTOS_PLATFORM_RECOVERY_REASON =");
    expect(operationsSource).toContain("ni ella ni la narrativa del incidente se guardan");
  });
});
