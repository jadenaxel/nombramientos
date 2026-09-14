import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { access, realpath } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { catalogPackage2025, validateCatalogPackage } from "@nombramientos/catalog";
import { Pool } from "pg";
import { z } from "zod";
import { EncryptedFileSecretProvider } from "../src/secrets.js";
import { ControlPlaneStore } from "../src/control-store.js";
import { InvitationSagaReconciler } from "../src/invitation-reconciler.js";
import { DatabaseRuntime } from "../src/runtime.js";
import { hashFile, readBackupManifest } from "../src/backup.js";
import { TenantProvisioner } from "../src/provisioner.js";
import type { TenantProvisionRequest } from "../src/types.js";
import {
  loadLocalScriptEnvironment,
  requireMasterKey,
  resolveDatabasePackageRoot,
  withoutDatabase,
} from "./script-config.js";

const queuedRequestSchema = z.object({
  idempotencyKey: z.string().uuid(),
  tenantId: z.string().uuid(),
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),
  displayName: z.string().trim().min(2).max(160),
  kind: z.enum(["demo", "real"]),
  timezone: z.string().min(1).max(80),
  locale: z.enum(["es", "en", "fr"]),
  initialAdmin: z.discriminatedUnion("mode", [
    z.object({ mode: z.literal("pending") }).strict(),
    z.object({ mode: z.literal("demo_seed") }).strict(),
    z.object({
      mode: z.literal("invitation"),
      email: z.string().email().max(320),
      normalizedEmail: z.string().email().max(320),
      expiresInHours: z.number().int().min(1).max(168),
      expiresAt: z.string().datetime({ offset: true }),
      tokenHash: z.string().regex(/^[0-9a-f]{64}$/),
      createdByIdentityId: z.string().uuid(),
    }).strict(),
  ]).optional(),
}).strict();

const pollIntervalMilliseconds = 1_500;
const maximumAttempts = 8;

let running = true;

export async function runProvisioningWorker(): Promise<void> {
  running = true;
  process.once("SIGINT", () => { running = false; });
  process.once("SIGTERM", () => { running = false; });
  const environment = loadLocalScriptEnvironment();
  if (!environment.DATABASE_CONTROL_URL) {
    throw new Error("DATABASE_CONTROL_URL is required for least-privilege invitation reconciliation");
  }
  const packageRoot = resolveDatabasePackageRoot(import.meta.url);
  const workspaceRoot = path.resolve(packageRoot, "..", "..");
  const stopFile = path.join(workspaceRoot, ".local", "provisioning-worker.stop");
  const administrator = new URL(environment.DATABASE_ADMIN_URL);
  if (Number(administrator.port || "5432") !== 55_432) {
    throw new Error("The local provisioning worker refuses PostgreSQL outside workspace port 55432");
  }
  const control = new Pool({
    connectionString: withoutDatabase(environment.DATABASE_ADMIN_URL, "nombramientos_control"),
    application_name: "nombramientos-provisioning-worker",
    max: 2,
  });
  const secretProvider = new EncryptedFileSecretProvider(
    process.env["DATABASE_SECRET_FILE"] ?? path.join(packageRoot, ".local", "secrets.enc.json"),
    requireMasterKey(environment.DATABASE_SECRET_MASTER_KEY_B64),
  );
  const catalogErrors = validateCatalogPackage(catalogPackage2025);
  if (catalogErrors.length > 0) throw new Error(`Catalog package is invalid: ${catalogErrors.join("; ")}`);
  const provisioner = new TenantProvisioner({
    admin: {
      host: administrator.hostname,
      port: Number(administrator.port || "5432"),
      user: decodeURIComponent(administrator.username),
      password: decodeURIComponent(administrator.password),
      database: administrator.pathname.slice(1) || "postgres",
      ssl: false,
    },
    catalog: catalogPackage2025,
    control,
    secrets: secretProvider,
    migrationsRoot: path.join(packageRoot, "migrations"),
  });
  const invitationRuntime = new DatabaseRuntime({
    control: {
      connectionString: environment.DATABASE_CONTROL_URL,
      application_name: "nombramientos-invitation-reconciler",
      max: 2,
    },
    secretProvider,
    tenantPoolMax: 2,
    tenantPoolIdleMs: 30_000,
  });
  const invitationReconciler = new InvitationSagaReconciler(invitationRuntime);
  const instanceId = randomUUID();
  const lease = await control.connect();
  let ownsLease = false;
  let heartbeatTimer: NodeJS.Timeout | undefined;
  let heartbeatInFlight: Promise<void> | undefined;
  let heartbeatFailure: unknown;
  let finalStatus: "stopped" | "failed" = "stopped";
  let finalErrorCode: string | null = null;
  try {
    const lock = await lease.query<{ acquired: boolean }>(
      "SELECT pg_try_advisory_lock(hashtextextended('tenant-provisioning-worker', 0)) AS acquired",
    );
    ownsLease = lock.rows[0]?.acquired === true;
    if (!ownsLease) throw new Error("PROVISIONING_WORKER_ALREADY_RUNNING");

    await lease.query(
      `INSERT INTO platform_worker_status(
         worker_code,instance_id,status,started_at,heartbeat_at,processed_count,last_error_code,updated_at
       ) VALUES ('tenant-provisioner',$1,'starting',clock_timestamp(),clock_timestamp(),0,NULL,clock_timestamp())
       ON CONFLICT(worker_code) DO UPDATE SET
         instance_id=EXCLUDED.instance_id,
         status=EXCLUDED.status,
         started_at=EXCLUDED.started_at,
         heartbeat_at=EXCLUDED.heartbeat_at,
         processed_count=0,
         last_error_code=NULL,
         updated_at=clock_timestamp()`,
      [instanceId],
    );
    await setWorkerStatus(lease, instanceId, "running", null);
    heartbeatTimer = setInterval(() => {
      if (heartbeatInFlight) return;
      heartbeatInFlight = heartbeat(lease, instanceId)
        .catch((error: unknown) => {
          heartbeatFailure = error;
          running = false;
        })
        .finally(() => { heartbeatInFlight = undefined; });
    }, 5_000);

    while (running && !await fileExists(stopFile)) {
      if (heartbeatFailure) throw heartbeatFailure;
      await heartbeat(lease, instanceId);
      try {
        const reconciliation = await invitationReconciler.reconcileOne(randomUUID());
        if (reconciliation.processed) {
          await recordProcessedJob(lease, instanceId, null);
          continue;
        }
      } catch (error) {
        // The reconciler has already persisted an exact per-invitation lease
        // failure and backoff. Continue to other saga/provisioning/export rows
        // instead of imposing a global poison-candidate delay.
        await recordProcessedJob(lease, instanceId, safeWorkerErrorCode(error));
      }
      const jobs = await control.query<{
        id: string;
        request_payload: unknown;
        attempt_count: number;
      }>(
        `SELECT id, request_payload, attempt_count
           FROM provisioning_jobs
          WHERE state NOT IN ('active','pending_activation')
            AND request_payload IS NOT NULL
            AND attempt_count < $1
            AND (next_attempt_at IS NULL OR next_attempt_at <= clock_timestamp())
          ORDER BY created_at, id
          LIMIT 1`,
        [maximumAttempts],
      );
      const job = jobs.rows[0];
      if (!job) {
        const exportResult = await processTenantExportJob(control, packageRoot);
        if (!exportResult.processed) {
          await pause(pollIntervalMilliseconds);
          continue;
        }
        await recordProcessedJob(lease, instanceId, exportResult.errorCode);
        continue;
      }

      let errorCode: string | null = null;
      try {
        const parsedRequest = queuedRequestSchema.parse(job.request_payload);
        const { initialAdmin, ...baseRequest } = parsedRequest;
        const request: TenantProvisionRequest = initialAdmin === undefined
          ? baseRequest
          : { ...baseRequest, initialAdmin };
        await provisioner.provision(request);
        await control.query("UPDATE provisioning_jobs SET next_attempt_at=NULL WHERE id=$1", [job.id]);
      } catch (error) {
        errorCode = safeWorkerErrorCode(error);
        const retrySeconds = Math.min(300, 2 ** Math.min(job.attempt_count + 1, 8));
        await control.query(
          `UPDATE provisioning_jobs
              SET state='failed',
                  attempt_count=CASE WHEN attempt_count=$2 THEN attempt_count+1 ELSE attempt_count END,
                  next_attempt_at=clock_timestamp() + ($3::int * interval '1 second'),
                  last_error_code=$4,
                  updated_at=clock_timestamp()
            WHERE id=$1`,
          [job.id, job.attempt_count, retrySeconds, errorCode],
        );
      }
      await recordProcessedJob(lease, instanceId, errorCode);
    }
    if (heartbeatFailure) throw heartbeatFailure;
    await setWorkerStatus(lease, instanceId, "stopping", null);
  } catch (error) {
    finalStatus = "failed";
    finalErrorCode = safeWorkerErrorCode(error);
    if (ownsLease) await setWorkerStatus(lease, instanceId, "failed", finalErrorCode).catch(() => undefined);
    throw error;
  } finally {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    if (heartbeatInFlight) await heartbeatInFlight.catch(() => undefined);
    if (ownsLease) {
      if (finalStatus === "stopped") await setWorkerStatus(lease, instanceId, "stopped", null).catch(() => undefined);
      await lease.query("SELECT pg_advisory_unlock(hashtextextended('tenant-provisioning-worker', 0))").catch(() => undefined);
    }
    lease.release();
    await invitationRuntime.close();
    await provisioner.close();
    await control.end();
  }
}

export async function processTenantExportJob(
  control: Pool,
  packageRoot: string,
): Promise<{ readonly processed: boolean; readonly errorCode: string | null }> {
  const claimed = await control.query<{
    id: string;
    tenant_id: string;
    requested_by_identity_id: string;
    attempt_count: number;
  }>(
    `WITH candidate AS (
       SELECT id
         FROM tenant_export_jobs
        WHERE attempt_count < $1
          AND (
            (state IN ('queued','failed') AND (next_attempt_at IS NULL OR next_attempt_at<=clock_timestamp()))
            OR (state='running' AND updated_at<clock_timestamp()-interval '5 minutes')
          )
        ORDER BY created_at,id
        LIMIT 1
        FOR UPDATE SKIP LOCKED
     )
     UPDATE tenant_export_jobs job
        SET state='running',attempt_count=job.attempt_count+1,claimed_at=clock_timestamp(),
            next_attempt_at=NULL,last_error_code=NULL,failed_at=NULL,revision=job.revision+1,
            updated_at=clock_timestamp()
       FROM candidate
      WHERE job.id=candidate.id
      RETURNING job.id,job.tenant_id,job.requested_by_identity_id,job.attempt_count`,
    [maximumAttempts],
  );
  const job = claimed.rows[0];
  if (!job) return { processed: false, errorCode: null };

  const store = new ControlPlaneStore(control);
  let errorCode: string | null = null;
  try {
    const executable = path.join(packageRoot, "dist", "scripts", "tenant-backup.js");
    const result = await runWorkerProcess(process.execPath, [
      executable,
      "--action", "backup",
      "--tenant-id", job.tenant_id,
    ]);
    if (result.code !== 0) throw new Error("TENANT_EXPORT_BACKUP_FAILED");
    const line = result.stdout.split(/\r?\n/u).map((value) => value.trim()).filter(Boolean).at(-1);
    if (!line) throw new Error("TENANT_EXPORT_RESULT_MISSING");
    const output = z.object({
      action: z.literal("backup"),
      status: z.literal("completed"),
      tenantId: z.string().uuid(),
      backupId: z.string().uuid(),
      backupDirectory: z.string().min(1),
      encryptedBytes: z.number().int().positive(),
    }).parse(JSON.parse(line) as unknown);
    if (output.tenantId !== job.tenant_id) throw new Error("TENANT_EXPORT_BOUNDARY_MISMATCH");

    const backupRoot = await realpath(path.join(packageRoot, ".local", "backups"));
    const backupDirectory = await realpath(output.backupDirectory);
    if (!backupDirectory.startsWith(`${backupRoot}${path.sep}`)) throw new Error("TENANT_EXPORT_PATH_OUTSIDE_BOUNDARY");
    const relative = path.relative(backupRoot, backupDirectory).split(path.sep).join("/");
    if (!relative.startsWith(`${job.tenant_id}/`) || relative.includes("..")) {
      throw new Error("TENANT_EXPORT_PATH_OUTSIDE_TENANT");
    }
    const manifest = await readBackupManifest(path.join(backupDirectory, "manifest.json"));
    if (manifest.core.tenantId !== job.tenant_id || manifest.core.backupId !== output.backupId) {
      throw new Error("TENANT_EXPORT_MANIFEST_BOUNDARY_MISMATCH");
    }
    const ciphertext = await hashFile(path.join(backupDirectory, manifest.payload.file));
    if (ciphertext.bytes !== output.encryptedBytes
      || ciphertext.bytes !== manifest.payload.bytes
      || ciphertext.sha256 !== manifest.payload.sha256) {
      throw new Error("TENANT_EXPORT_CIPHERTEXT_MISMATCH");
    }
    const publicManifest = {
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
      payload: {
        file: "database.dump.aesgcm",
        bytes: ciphertext.bytes,
        sha256: ciphertext.sha256,
      },
    } as const;
    const completed = await control.query(
      `UPDATE tenant_export_jobs
          SET state='ready',backup_id=$2,artifact_relative_path=$3,public_manifest=$4,
              encrypted_bytes=$5,ciphertext_sha256=$6,recovery_point_at=$7,
              ready_at=clock_timestamp(),failed_at=NULL,last_error_code=NULL,next_attempt_at=NULL,
              revision=revision+1,updated_at=clock_timestamp()
        WHERE id=$1 AND state='running'`,
      [job.id, output.backupId, relative, publicManifest, ciphertext.bytes, ciphertext.sha256, manifest.core.recoveryPointAt],
    );
    if (completed.rowCount !== 1) throw new Error("TENANT_EXPORT_LEASE_LOST");
    await store.appendAudit({
      actorIdentityId: job.requested_by_identity_id,
      tenantId: job.tenant_id,
      action: "platform.tenant_export_ready",
      entityType: "tenant_export_job",
      entityId: job.id,
      result: "success",
      metadata: {
        backupId: output.backupId,
        encryptedBytes: ciphertext.bytes,
        ciphertextSha256: ciphertext.sha256,
        contentAccess: false,
        keyAccess: false,
      },
    });
  } catch (error) {
    errorCode = safeWorkerErrorCode(error);
    const retrySeconds = Math.min(300, 2 ** Math.min(job.attempt_count, 8));
    await control.query(
      `UPDATE tenant_export_jobs
          SET state='failed',next_attempt_at=clock_timestamp()+($2::int*interval '1 second'),
              last_error_code=$3,failed_at=clock_timestamp(),revision=revision+1,
              updated_at=clock_timestamp()
        WHERE id=$1 AND state='running'`,
      [job.id, retrySeconds, errorCode],
    );
    await store.appendAudit({
      actorIdentityId: job.requested_by_identity_id,
      tenantId: job.tenant_id,
      action: "platform.tenant_export_failed",
      entityType: "tenant_export_job",
      entityId: job.id,
      result: "failure",
      metadata: { errorCode, attempt: job.attempt_count, contentAccess: false, keyAccess: false },
    }).catch(() => undefined);
  }
  return { processed: true, errorCode };
}

async function recordProcessedJob(
  lease: import("pg").PoolClient,
  instanceId: string,
  errorCode: string | null,
): Promise<void> {
  await lease.query(
    `UPDATE platform_worker_status
        SET heartbeat_at=clock_timestamp(),processed_count=processed_count+1,
            last_error_code=$2,updated_at=clock_timestamp()
      WHERE worker_code='tenant-provisioner' AND instance_id=$1`,
    [instanceId, errorCode],
  );
}

export async function runWorkerProcess(executable: string, args: readonly string[]): Promise<{
  readonly code: number;
  readonly stdout: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      windowsHide: true,
      shell: false,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.resume();
    child.once("error", reject);
    child.once("close", (code) => resolve({ code: code ?? -1, stdout }));
  });
}

async function heartbeat(
  lease: import("pg").PoolClient,
  instanceId: string,
): Promise<void> {
  const result = await lease.query(
    `UPDATE platform_worker_status
        SET heartbeat_at=clock_timestamp(), updated_at=clock_timestamp()
      WHERE worker_code='tenant-provisioner' AND instance_id=$1 AND status='running'`,
    [instanceId],
  );
  if (result.rowCount !== 1) throw new Error("PROVISIONING_WORKER_LEASE_LOST");
}

async function setWorkerStatus(
  lease: import("pg").PoolClient,
  instanceId: string,
  status: "running" | "stopping" | "stopped" | "failed",
  errorCode: string | null,
): Promise<void> {
  const result = await lease.query(
    `UPDATE platform_worker_status
        SET status=$2, heartbeat_at=clock_timestamp(), last_error_code=$3, updated_at=clock_timestamp()
      WHERE worker_code='tenant-provisioner' AND instance_id=$1`,
    [instanceId, status, errorCode],
  );
  if (result.rowCount !== 1) throw new Error("PROVISIONING_WORKER_LEASE_LOST");
}

async function fileExists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

function pause(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeWorkerErrorCode(error: unknown): string {
  if (error instanceof z.ZodError) return "INVALID_JOB_PAYLOAD";
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = String(error.code).toUpperCase();
    if (/^[A-Z0-9_]{1,80}$/.test(code)) return code;
  }
  if (error instanceof Error && /^[A-Z0-9_]{1,80}$/.test(error.message)) return error.message;
  return "PROVISIONING_WORKER_FAILURE";
}

const invokedFile = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : undefined;
if (invokedFile === import.meta.url) {
  await runProvisioningWorker().catch((error: unknown) => {
    process.stderr.write(`${safeWorkerErrorCode(error)}\n`);
    process.exitCode = 1;
  });
}
