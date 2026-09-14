import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migration = readFileSync(
  path.join(packageRoot, "migrations", "control", "013_tenant_activation_summary.sql"),
  "utf8",
);
const compatibilityMigration = readFileSync(
  path.join(packageRoot, "migrations", "control", "014_tenant_summary_export_bytes.sql"),
  "utf8",
);
const controlStore = readFileSync(path.join(packageRoot, "src", "control-store.ts"), "utf8");
const migrateControl = readFileSync(path.join(packageRoot, "scripts", "migrate-control.ts"), "utf8");

describe("sanitized platform tenant summaries", () => {
  it("reconciles only untouched legacy real tenants without activation evidence", () => {
    expect(migration).toContain("tenant.kind = 'real'");
    expect(migration).toContain("tenant.status = 'active'");
    expect(migration).toContain("tenant.version = 1");
    expect(migration).toContain("tenant.decommission_request_id IS NULL");
    expect(migration).toContain("job.state = 'active'");
    expect(migration).toContain("NOT EXISTS (\n       SELECT 1 FROM public.tenant_invitations");
    expect(migration).toContain("NOT EXISTS (\n       SELECT 1 FROM public.tenant_memberships");
    expect(migration).toContain("state = 'pending_activation'");
    expect(migration).toContain("status = 'provisioning'");
  });

  it("uses a security-barrier projection while keeping provisioning payloads unreadable", () => {
    expect(migration).toContain("CREATE VIEW public.platform_tenant_summaries");
    expect(migration).toContain("WITH (security_barrier = true)");
    expect(migration).toContain("REVOKE ALL ON TABLE public.platform_tenant_summaries FROM PUBLIC");
    expect(compatibilityMigration).toContain(
      "RENAME COLUMN encrypted_bytes TO export_encrypted_bytes",
    );
    expect(migrateControl).toContain(
      'grantControlTablePrivileges(client, role, "platform_tenant_summaries", "SELECT")',
    );
    expect(migrateControl).not.toMatch(/grantControlTablePrivileges\(client, role, "provisioning_jobs"/u);
    expect(controlStore).toContain("FROM platform_tenant_summaries");
    expect(controlStore).not.toContain("FULL JOIN provisioning_jobs");
  });
});
