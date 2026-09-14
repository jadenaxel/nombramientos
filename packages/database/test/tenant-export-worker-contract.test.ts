import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runWorkerProcess } from "../scripts/process-provisioning-jobs.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = path.resolve(packageRoot, "..", "..");
const workerSource = readFileSync(path.join(packageRoot, "scripts", "process-provisioning-jobs.ts"), "utf8");
const migrateSource = readFileSync(path.join(packageRoot, "scripts", "migrate-control.ts"), "utf8");
const startSource = readFileSync(path.join(workspaceRoot, "scripts", "start-local.ps1"), "utf8");
const stopSource = readFileSync(path.join(workspaceRoot, "scripts", "stop-local.ps1"), "utf8");

describe("privileged tenant export worker contract", () => {
  it("is safely importable and executes the backup child without a shell", async () => {
    const result = await runWorkerProcess(process.execPath, [
      "-e",
      "process.stdout.write(JSON.stringify({action:'backup',status:'completed'}))",
    ]);
    expect(result).toEqual({ code: 0, stdout: '{"action":"backup","status":"completed"}' });
    expect(workerSource).toMatch(/spawn\(executable, args, \{[\s\S]*windowsHide: true,[\s\S]*shell: false,/u);
    expect(workerSource).toMatch(/if \(invokedFile === import\.meta\.url\)[\s\S]*runProvisioningWorker/u);
  });

  it("one-shot processing invokes the real backup tool and authenticates every published boundary", () => {
    expect(workerSource).toMatch(/export async function processTenantExportJob/u);
    expect(workerSource).toMatch(/"dist", "scripts", "tenant-backup\.js"/u);
    expect(workerSource).toMatch(/"--action", "backup",[\s\S]*"--tenant-id", job\.tenant_id/u);
    expect(workerSource).toMatch(/realpath\(path\.join\(packageRoot, "\.local", "backups"\)\)/u);
    expect(workerSource).toMatch(/backupDirectory\.startsWith\(`\$\{backupRoot\}\$\{path\.sep\}`\)/u);
    expect(workerSource).toMatch(/relative\.startsWith\(`\$\{job\.tenant_id\}\//u);
    expect(workerSource).toMatch(/readBackupManifest\(path\.join\(backupDirectory, "manifest\.json"\)\)/u);
    expect(workerSource).toMatch(/manifest\.core\.tenantId !== job\.tenant_id/u);
    expect(workerSource).toMatch(/manifest\.core\.backupId !== output\.backupId/u);
    expect(workerSource).toMatch(/ciphertext\.bytes !== manifest\.payload\.bytes/u);
    expect(workerSource).toMatch(/ciphertext\.sha256 !== manifest\.payload\.sha256/u);
    expect(workerSource).toMatch(/authenticatedCoreSha256: manifest\.encryption\.aadSha256/u);
    expect(workerSource).toMatch(/keyCustody: "platform-managed-not-exported"/u);
    expect(workerSource).toMatch(/WHERE id=\$1 AND state='running'/u);
    expect(workerSource).toMatch(/contentAccess: false,[\s\S]*keyAccess: false/u);
    assertRuntimeCannotSelectProtectedStorageReferences();
  });

  it("the same privileged worker is started, health-gated and stopped by the local lifecycle", () => {
    expect(startSource).toMatch(/dist\\scripts\\process-provisioning-jobs\.js/u);
    expect(startSource).toMatch(/Start-Process[\s\S]*\$NomWorkerEntry[\s\S]*-WindowStyle Hidden/u);
    expect(startSource).toMatch(/\$NomHealth\.worker\.healthy -eq \$true/u);
    expect(stopSource).toMatch(/Name = 'provisioning worker'[\s\S]*Graceful = \$true/u);
    expect(stopSource).toMatch(/WriteAllText\(\$NomWorkerStopFile/u);
  });
});

function assertRuntimeCannotSelectProtectedStorageReferences(): void {
  expect(migrateSource).toMatch(/GRANT SELECT\(id,tenant_id,tenant_version,state,attempt_count,revision,public_manifest/u);
  expect(migrateSource).not.toMatch(/GRANT SELECT\([^)]*artifact_relative_path/u);
  expect(migrateSource).not.toMatch(/GRANT SELECT\([^)]*request_hash/u);
}
