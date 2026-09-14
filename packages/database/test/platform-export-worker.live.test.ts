import { randomUUID } from "node:crypto";
import { open, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { hashFile, readBackupManifest } from "../src/backup.js";
import { ControlPlaneStore, type PlatformTenantExportManifest } from "../src/control-store.js";
import { loadLocalScriptEnvironment, withoutDatabase } from "../scripts/script-config.js";

const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const live = requireLive ? describe.sequential : describe.skip;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const demoTenantId = "d0000000-0000-4000-8000-000000000001";
// Reserved, disabled control-plane principal for this live proof. Keeping one stable
// principal preserves immutable export/audit lineage without requiring a real admin.
const liveExportActorId = "e0000000-0000-4000-8000-0000000000e1";
const liveExportActorEmail = "live-export-verification@invalid.example";
const liveExportActorDisplayName = "Live export verification actor";

let control: Pool | undefined;
let store: ControlPlaneStore | undefined;
let liveExportActorPrepared = false;

live("real encrypted Demo export through the lifecycle worker", () => {
  beforeAll(async () => {
    const environment = loadLocalScriptEnvironment();
    const administrator = new URL(environment.DATABASE_ADMIN_URL);
    if (Number(administrator.port || "5432") !== 55_432) {
      throw new Error("Live export verification refuses PostgreSQL outside workspace port 55432");
    }
    control = new Pool({
      connectionString: withoutDatabase(environment.DATABASE_ADMIN_URL, "nombramientos_control"),
      application_name: "nombramientos-real-export-live-test",
      max: 2,
    });
    store = new ControlPlaneStore(control);
    const worker = await store.getProvisioningWorkerStatus();
    if (!worker.healthy || worker.status !== "running") {
      throw new Error("Real export verification requires the lifecycle worker to be healthy and running");
    }
    await prepareLiveExportActor(control);
    liveExportActorPrepared = true;
  }, 15_000);

  afterAll(async () => {
    if (!control) return;
    try {
      if (liveExportActorPrepared) await revokeLiveExportActorRole(control);
    } finally {
      await control.end();
    }
  });

  it("produces ciphertext plus an authenticated manifest and consumes authorization once", async () => {
    const database = requireControl();
    const lifecycle = requireStore();
    await waitForNoInFlightExport(database, demoTenantId, 120_000);

    const tenantResult = await database.query<{
      id: string;
      status: "active" | "suspended";
      version: number;
    }>(
      `SELECT id,status,version
         FROM tenants
        WHERE id=$1 AND status IN ('active','suspended')`,
      [demoTenantId],
    );
    const tenant = tenantResult.rows[0];
    if (!tenant) throw new Error("Demo tenant must be active or suspended for real export verification");
    const actorScope = (await database.query<{ memberships: number; sessions: number }>(
      `SELECT
         (SELECT count(*)::int FROM tenant_memberships WHERE identity_id=$1) AS memberships,
         (SELECT count(*)::int FROM auth_sessions WHERE identity_id=$1) AS sessions`,
      [liveExportActorId],
    )).rows[0];
    expect(actorScope).toEqual({ memberships: 0, sessions: 0 });

    const queued = await lifecycle.queueTenantExport({
      tenantId: tenant.id,
      expectedVersion: tenant.version,
      idempotencyKey: randomUUID(),
      actorIdentityId: liveExportActorId,
      requestId: randomUUID(),
    });
    expect(queued).toMatchObject({ state: "queued", revision: 1, reused: false });

    const job = await waitForReadyExport(database, queued.jobId, 180_000);
    expect(job.tenant_id).toBe(tenant.id);
    expect(job.tenant_version).toBe(tenant.version);
    expect(job.attempt_count).toBeGreaterThanOrEqual(1);
    expect(job.backup_id).toMatch(/^[0-9a-f-]{36}$/iu);
    expect(job.artifact_relative_path).toMatch(new RegExp(`^${tenant.id}/[0-9TZ]+-${job.backup_id}$`, "u"));

    const backupRoot = await realpath(path.join(packageRoot, ".local", "backups"));
    const backupDirectory = await realpath(path.join(backupRoot, ...job.artifact_relative_path.split("/")));
    expect(backupDirectory.startsWith(`${backupRoot}${path.sep}`)).toBe(true);
    const manifest = await readBackupManifest(path.join(backupDirectory, "manifest.json"));
    const payloadPath = path.join(backupDirectory, manifest.payload.file);
    const ciphertext = await hashFile(payloadPath);
    expect(manifest.core).toMatchObject({ tenantId: tenant.id, backupId: job.backup_id });
    expect(ciphertext).toEqual({ bytes: Number(job.encrypted_bytes), sha256: job.ciphertext_sha256 });
    expect(manifest.payload).toMatchObject(ciphertext);
    expect(job.public_manifest).toEqual<PlatformTenantExportManifest>({
      format: "nombramientos-tenant-export",
      version: 1,
      backupId: manifest.core.backupId,
      tenantId: manifest.core.tenantId,
      recoveryPointAt: manifest.core.recoveryPointAt,
      completedAt: manifest.core.backupCompletedAt,
      encryption: {
        algorithm: "AES-256-GCM",
        authenticatedCoreSha256: manifest.encryption.aadSha256,
        keyCustody: "platform-managed-not-exported",
      },
      payload: { file: "database.dump.aesgcm", ...ciphertext },
    });
    expect(JSON.stringify(job.public_manifest)).not.toMatch(/nonce|tag|keyB64|artifact_relative_path|database_name/iu);
    const audit = (await database.query<{ result: string; metadata: unknown }>(
      `SELECT result,metadata
         FROM platform_audit_events
        WHERE action='platform.tenant_export_ready'
          AND entity_type='tenant_export_job'
          AND entity_id=$1
        ORDER BY sequence DESC
        LIMIT 1`,
      [queued.jobId],
    )).rows[0];
    expect(audit).toMatchObject({
      result: "success",
      metadata: expect.objectContaining({
        backupId: manifest.core.backupId,
        encryptedBytes: ciphertext.bytes,
        ciphertextSha256: ciphertext.sha256,
        contentAccess: false,
        keyAccess: false,
      }),
    });
    expect(JSON.stringify(audit)).not.toMatch(/artifact_relative_path|database_name|runtime_secret|nonce|tag|keyB64/iu);

    const handle = await open(payloadPath, "r");
    try {
      const prefix = Buffer.alloc(5);
      await handle.read(prefix, 0, prefix.byteLength, 0);
      expect(prefix.toString("ascii")).not.toBe("PGDMP");
    } finally {
      await handle.close();
    }

    const authorization = await lifecycle.authorizeTenantExportDownload({
      authorizationId: randomUUID(),
      tenantId: tenant.id,
      exportJobId: queued.jobId,
      expiresAt: new Date(Date.now() + 5 * 60_000),
      idempotencyKey: randomUUID(),
      actorIdentityId: liveExportActorId,
    });
    expect(authorization).toMatchObject({ status: "active", revision: 1, reused: false });
    await expect(lifecycle.consumeTenantExportDownload({
      authorizationId: authorization.authorizationId,
      tenantId: tenant.id,
      exportJobId: queued.jobId,
      actorIdentityId: liveExportActorId,
    })).resolves.toMatchObject({
      artifactRelativePath: job.artifact_relative_path,
      encryptedBytes: ciphertext.bytes,
      ciphertextSha256: ciphertext.sha256,
      backupId: manifest.core.backupId,
    });
    await expect(lifecycle.consumeTenantExportDownload({
      authorizationId: authorization.authorizationId,
      tenantId: tenant.id,
      exportJobId: queued.jobId,
      actorIdentityId: liveExportActorId,
    })).resolves.toBeNull();
  }, 210_000);
});

async function prepareLiveExportActor(database: Pool): Promise<void> {
  const client = await database.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO platform_identities(
         id,email,normalized_email,display_name,password_hash,mfa_enabled,mfa_required,status
       ) VALUES ($1,$2,$2,$3,'!disabled-live-test-identity!',false,true,'disabled')
       ON CONFLICT (id) DO NOTHING`,
      [liveExportActorId, liveExportActorEmail, liveExportActorDisplayName],
    );
    const identity = (await client.query<{
      email: string;
      normalized_email: string;
      display_name: string;
      status: string;
    }>(
      `SELECT email,normalized_email,display_name,status
         FROM platform_identities
        WHERE id=$1
        FOR UPDATE`,
      [liveExportActorId],
    )).rows[0];
    if (!identity
      || identity.email !== liveExportActorEmail
      || identity.normalized_email !== liveExportActorEmail
      || identity.display_name !== liveExportActorDisplayName
      || identity.status !== "disabled") {
      throw new Error("Reserved live export verification identity is unavailable or unsafe");
    }
    const scope = (await client.query<{ memberships: number; sessions: number }>(
      `SELECT
         (SELECT count(*)::int FROM tenant_memberships WHERE identity_id=$1) AS memberships,
         (SELECT count(*)::int FROM auth_sessions WHERE identity_id=$1) AS sessions`,
      [liveExportActorId],
    )).rows[0];
    if (!scope || scope.memberships !== 0 || scope.sessions !== 0) {
      throw new Error("Reserved live export verification identity acquired an interactive scope");
    }
    await client.query(
      `INSERT INTO platform_role_bindings(identity_id,role_code)
       VALUES ($1,'platform_admin')
       ON CONFLICT DO NOTHING`,
      [liveExportActorId],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function revokeLiveExportActorRole(database: Pool): Promise<void> {
  await database.query(
    "DELETE FROM platform_role_bindings WHERE identity_id=$1 AND role_code='platform_admin'",
    [liveExportActorId],
  );
  const retained = (await database.query<{ status: string; bindings: number }>(
    `SELECT identity.status,
            (SELECT count(*)::int FROM platform_role_bindings binding WHERE binding.identity_id=identity.id) AS bindings
       FROM platform_identities identity
      WHERE identity.id=$1`,
    [liveExportActorId],
  )).rows[0];
  if (!retained || retained.status !== "disabled" || retained.bindings !== 0) {
    throw new Error("Live export verification principal cleanup is incomplete");
  }
}

interface ReadyExportRow {
  readonly tenant_id: string;
  readonly tenant_version: number;
  readonly attempt_count: number;
  readonly backup_id: string;
  readonly artifact_relative_path: string;
  readonly public_manifest: PlatformTenantExportManifest;
  readonly encrypted_bytes: string;
  readonly ciphertext_sha256: string;
}

async function waitForNoInFlightExport(database: Pool, tenantId: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await database.query(
      "SELECT 1 FROM tenant_export_jobs WHERE tenant_id=$1 AND state IN ('queued','running')",
      [tenantId],
    );
    if (result.rowCount === 0) return;
    await pause(500);
  }
  throw new Error("Timed out waiting for the Demo tenant export queue to become idle");
}

async function waitForReadyExport(database: Pool, jobId: string, timeoutMs: number): Promise<ReadyExportRow> {
  const deadline = Date.now() + timeoutMs;
  let lastState = "queued";
  let lastErrorCode: string | null = null;
  while (Date.now() < deadline) {
    const result = await database.query<ReadyExportRow & { state: string; last_error_code: string | null }>(
      `SELECT tenant_id,tenant_version,attempt_count,backup_id,artifact_relative_path,
              public_manifest,encrypted_bytes::text,ciphertext_sha256,state,last_error_code
         FROM tenant_export_jobs
        WHERE id=$1`,
      [jobId],
    );
    const job = result.rows[0];
    if (!job) throw new Error("Queued Demo export disappeared");
    lastState = job.state;
    lastErrorCode = job.last_error_code;
    if (job.state === "ready") return job;
    await pause(500);
  }
  throw new Error(`Timed out waiting for real Demo export: ${lastState}/${lastErrorCode ?? "NO_ERROR_CODE"}`);
}

function pause(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function requireControl(): Pool {
  if (!control) throw new Error("Live control connection is unavailable");
  return control;
}

function requireStore(): ControlPlaneStore {
  if (!store) throw new Error("Live control store is unavailable");
  return store;
}
