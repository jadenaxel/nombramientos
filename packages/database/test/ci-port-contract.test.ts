import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const workspaceRoot = path.resolve(import.meta.dirname, "../../..");
const workflow = readFileSync(path.join(workspaceRoot, ".github/workflows/ci.yml"), "utf8");
const installer = readFileSync(path.join(workspaceRoot, "scripts/create-ci-install.mjs"), "utf8");
const exposureTest = readFileSync(
  path.join(workspaceRoot, "packages/database/test/ac31-data-exposure.live.test.ts"),
  "utf8",
);

describe("isolated PostgreSQL CI contract", () => {
  it("binds both sides of the service and the real server to 55432", () => {
    expect(workflow).toContain("- 55432:55432");
    expect(workflow).toContain("ALTER SYSTEM SET port = 55432");
    expect(workflow).toContain("pg_isready -U postgres -p 55432");
    expect(workflow).not.toContain("- 5432:5432");
    expect(workflow).not.toContain("- 55432:5432");
  });

  it("generates only loopback administrator and control URLs on 55432", () => {
    expect(installer).toContain("127.0.0.1:55432/postgres");
    expect(installer).toContain("127.0.0.1:55432/nombramientos_control");
    expect(installer).not.toContain("127.0.0.1:5432/");
  });

  it("extracts and validates a portable PostgreSQL 18 client before configuration", () => {
    expect(workflow).toContain("apt-get download postgresql-client-18 libpq5");
    expect(workflow).toContain('dpkg-deb --extract "$package" "$client_root/root"');
    expect(workflow).toContain('pg_bin="$client_root/root/usr/lib/postgresql/18/bin"');
    expect(workflow).toContain("for tool in pg_dump pg_restore");
    expect(workflow).toContain('echo "POSTGRES_BIN=$pg_bin" >> "$GITHUB_ENV"');
    expect(workflow.indexOf("Install and validate portable PostgreSQL 18 client"))
      .toBeLessThan(workflow.indexOf("Generate ephemeral local-only credentials"));
  });

  it("creates a protected backup-key inventory and exports every live-test boundary", () => {
    expect(installer).toContain('const backupKeyFile = path.join(localRoot, "backup-keys.json")');
    expect(installer).toContain("activeKeyId: activeBackupKeyId");
    expect(installer).toContain('status: "active"');
    expect(installer).toContain("keyB64: secret(32)");
    expect(installer).toContain("DATABASE_BACKUP_KEY_FILE: backupKeyFile");
    expect(installer).toContain("POSTGRES_BIN: postgresBin");
    expect(installer).toContain('"NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true"');
    expect(installer).toContain('"NOMBRAMIENTOS_PRIVILEGE_LIVE=true"');
    expect(installer).toContain("await chmod(backupKeyFile, 0o600)");
  });

  it("runs a real health-gated worker and always captures and stops it", () => {
    expect(workflow).toContain("nohup node packages/database/dist/scripts/process-provisioning-jobs.js > .ci-worker.log 2>&1 &");
    expect(workflow).toContain('health.worker?.healthy !== true');
    expect(workflow).toContain("AbortSignal.timeout(2000)");
    expect(workflow).toContain("curl --fail --silent --connect-timeout 1 --max-time 2");
    expect(workflow).toMatch(/- name: Stop local services\n\s+if: always\(\)[\s\S]*stop_service \.ci-worker\.pid/u);
    expect(workflow).toContain(".ci-worker.log");
  });

  it("selects extensionless PostgreSQL tools on Linux and .exe tools on Windows", () => {
    expect(exposureTest).toContain('process.platform === "win32" ? `${tool}.exe` : tool');
    expect(exposureTest).toContain('pgToolPath(installation.postgresBin, "pg_dump")');
    expect(exposureTest).toContain('pgToolPath(installation.postgresBin, "pg_restore")');
    expect(exposureTest).not.toContain('path.join(installation.postgresBin, "pg_dump.exe")');
    expect(exposureTest).not.toContain('path.join(installation.postgresBin, "pg_restore.exe")');
  });
});
