import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { z } from "zod";
import {
  assertScratchDatabaseName,
  backupKeyInventorySchema,
  backupManifestSchema,
  canonicalJson,
  captureTenantInvariant,
  compareTenantInvariants,
  decryptBackupPayload,
  encryptBackupPayload,
  hashFile,
  readBackupManifest,
  scratchDatabaseName,
  sha256,
  type BackupCore,
  type BackupManifest,
  type TenantInvariant,
} from "../src/backup.js";
import { EncryptedFileSecretProvider } from "../src/secrets.js";
import {
  assertExpectedTenantComparisons,
  assertTenantMaintenanceDatabase,
  listTenantMaintenanceRoutes,
  resolveTenantMaintenanceRoute,
  type TenantMaintenanceRoute,
} from "../src/tenant-maintenance-policy.js";
import { assertWorkspacePostgresUrl, resolveDatabasePackageRoot } from "./script-config.js";

const tenantIdSchema = z.string().uuid();
const installSchema = z.object({
  version: z.literal(1),
  DATABASE_ADMIN_URL: z.string().url(),
  DATABASE_SECRET_MASTER_KEY_B64: z.string().min(1),
  DATABASE_SECRET_FILE: z.string().min(1),
  DATABASE_BACKUP_KEY_FILE: z.string().min(1),
  POSTGRES_BIN: z.string().min(1),
});

interface BackupResult {
  readonly directory: string;
  readonly manifest: BackupManifest;
  readonly durationMs: number;
}

interface LocalContext {
  readonly localRoot: string;
  readonly backupRoot: string;
  readonly workRoot: string;
  readonly pgBin: string;
  readonly adminUrl: URL;
  readonly controlPool: Pool;
  readonly secretProvider: EncryptedFileSecretProvider;
  readonly keyInventory: z.infer<typeof backupKeyInventorySchema>;
}

async function main(): Promise<void> {
  const operationStartedAt = performance.now();
  const options = parseArguments(process.argv.slice(2));
  const context = await loadContext();
  try {
    if (options.action === "backup") {
      if (!options.tenantId) throw new Error("--tenant-id is required for a tenant backup");
      const tenant = await resolveTenant(context.controlPool, options.tenantId);
      const result = await createTenantBackup(context, tenant);
      const recoveryPointAgeMs = Math.max(0, Date.now() - Date.parse(result.manifest.core.recoveryPointAt));
      process.stdout.write(`${JSON.stringify({
        action: "backup",
        status: "completed",
        tenantId: tenant.id,
        tenantLifecycle: tenant.status,
        maintenanceClass: tenant.maintenanceClass,
        backupId: result.manifest.core.backupId,
        backupDirectory: result.directory,
        encryptedBytes: result.manifest.payload.bytes,
        durationMs: result.durationMs,
        recoveryPointAgeMs,
      })}\n`);
      return;
    }

    if (!options.tenantId) throw new Error("--tenant-id is required for a restore drill");
    const tenant = await resolveTenant(context.controlPool, options.tenantId);
    let backupDirectory: string;
    let backupDurationMs: number | null = null;
    if (options.backupDirectory) {
      backupDirectory = await resolveBackupDirectory(context, options.backupDirectory);
    } else {
      const backup = await createTenantBackup(context, tenant);
      backupDirectory = backup.directory;
      backupDurationMs = backup.durationMs;
    }
    const result = await runRestoreDrill(context, tenant, backupDirectory);
    process.stdout.write(`${JSON.stringify({
      action: "restore-drill",
      status: "passed",
      tenantId: tenant.id,
      tenantLifecycle: tenant.status,
      maintenanceClass: tenant.maintenanceClass,
      backupId: result.backupId,
      backupDirectory,
      scratchDatabase: result.scratchDatabase,
      scratchRemoved: true,
      restoredInvariantMatches: true,
      otherTenantUnchanged: true,
      comparedTenantIds: result.comparedTenantIds,
      comparedTenantCount: result.comparedTenantIds.length,
      recoveryPointAgeMs: result.recoveryPointAgeMs,
      backupDurationMs,
      restoreTimeMs: result.restoreTimeMs,
      totalDrillTimeMs: result.totalDrillTimeMs,
      totalOperationTimeMs: Math.round(performance.now() - operationStartedAt),
      rpoTargetMet: result.recoveryPointAgeMs <= 15 * 60_000,
      rtoTargetMet: result.totalDrillTimeMs <= 4 * 60 * 60_000,
    })}\n`);
  } finally {
    await context.controlPool.end();
  }
}

function parseArguments(values: readonly string[]): {
  action: "backup" | "drill";
  tenantId?: string;
  backupDirectory?: string;
} {
  let action: "backup" | "drill" | undefined;
  let tenantId: string | undefined;
  let backupDirectory: string | undefined;
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    const value = values[index + 1];
    if (key === "--action" && (value === "backup" || value === "drill")) {
      action = value;
      index += 1;
    } else if (key === "--tenant-id" && value) {
      tenantId = tenantIdSchema.parse(value);
      index += 1;
    } else if (key === "--backup-dir" && value) {
      backupDirectory = value;
      index += 1;
    } else {
      throw new Error(`Unsupported backup argument: ${key ?? "missing"}`);
    }
  }
  if (!action) throw new Error("--action must be backup or drill");
  return {
    action,
    ...(tenantId ? { tenantId } : {}),
    ...(backupDirectory ? { backupDirectory } : {}),
  };
}

async function loadContext(): Promise<LocalContext> {
  const packageRoot = resolveDatabasePackageRoot(import.meta.url);
  const localRoot = path.resolve(packageRoot, ".local");
  const install = installSchema.parse(
    JSON.parse(await readFile(path.join(localRoot, "install.json"), "utf8")) as unknown,
  );
  const adminUrl = assertWorkspacePostgresUrl(install.DATABASE_ADMIN_URL, "nom_admin", "postgres");
  const pgBin = await realpath(path.resolve(install.POSTGRES_BIN));
  const backupKeyFile = await resolveExistingWithin(localRoot, install.DATABASE_BACKUP_KEY_FILE, "backup key file");
  const secretFile = await resolveExistingWithin(localRoot, install.DATABASE_SECRET_FILE, "tenant secret file");
  const masterKey = Buffer.from(install.DATABASE_SECRET_MASTER_KEY_B64, "base64url");
  if (masterKey.byteLength !== 32) throw new Error("Database secret master key must encode 32 bytes");
  const keyInventory = backupKeyInventorySchema.parse(
    JSON.parse(await readFile(backupKeyFile, "utf8")) as unknown,
  );
  await ensurePg18(pgToolPath(pgBin, "pg_dump"), "pg_dump");
  await ensurePg18(pgToolPath(pgBin, "pg_restore"), "pg_restore");
  const controlUrl = new URL(adminUrl);
  controlUrl.pathname = "/nombramientos_control";
  const backupRoot = path.join(localRoot, "backups");
  const workRoot = path.join(localRoot, "backup-work");
  await Promise.all([mkdir(backupRoot, { recursive: true }), mkdir(workRoot, { recursive: true })]);
  return {
    localRoot,
    backupRoot,
    workRoot,
    pgBin,
    adminUrl,
    controlPool: new Pool({
      host: controlUrl.hostname,
      port: Number(controlUrl.port),
      database: "nombramientos_control",
      user: decodeURIComponent(controlUrl.username),
      password: decodeURIComponent(controlUrl.password),
      ssl: false,
      application_name: "nombramientos-backup-control",
      max: 1,
      connectionTimeoutMillis: 5_000,
    }),
    secretProvider: new EncryptedFileSecretProvider(secretFile, masterKey),
    keyInventory,
  };
}

async function resolveTenant(control: Pool, tenantId: string): Promise<TenantMaintenanceRoute> {
  const tenant = await resolveTenantMaintenanceRoute(control, tenantId);
  assertLocalTenantRoute(tenant);
  return tenant;
}

function assertLocalTenantRoute(tenant: TenantMaintenanceRoute): void {
  const suffix = tenant.id.replaceAll("-", "");
  if (tenant.databaseName !== `nom_t_${suffix}` || tenant.runtimeRole !== `nom_r_${suffix}`) {
    throw new Error("Tenant backup route does not match its deterministic isolation boundary");
  }
  if (tenant.runtimeSecretReference !== `tenant-db/${tenant.id}/runtime/v${tenant.credentialVersion}`) {
    throw new Error("Tenant backup secret reference does not match its credential version");
  }
  if (tenant.databaseHost !== "127.0.0.1" || tenant.databasePort !== 55432) {
    throw new Error("Tenant backup route is outside the isolated loopback PostgreSQL cluster");
  }
}

async function createTenantBackup(context: LocalContext, tenant: TenantMaintenanceRoute): Promise<BackupResult> {
  const startedAt = performance.now();
  const backupId = randomUUID();
  const timestamp = new Date().toISOString().replaceAll(/[-:.]/g, "").replace("Z", "Z");
  const tenantRoot = path.join(context.backupRoot, tenant.id);
  const partialDirectory = path.join(tenantRoot, `.partial-${backupId}`);
  const finalDirectory = path.join(tenantRoot, `${timestamp}-${backupId}`);
  const workDirectory = await mkdtemp(path.join(context.workRoot, "backup-"));
  const dumpPath = path.join(workDirectory, "database.dump");
  let finalized = false;
  try {
    await mkdir(tenantRoot, { recursive: true });
    await resolveExistingWithin(context.backupRoot, tenantRoot, "tenant backup directory");
    await mkdir(partialDirectory, { recursive: false });
    if (!(await context.secretProvider.hasSecret(tenant.runtimeSecretReference))) {
      throw new Error("Tenant runtime secret reference is unavailable for backup coherence");
    }
    const sourcePool = createAdminPool(context.adminUrl, tenant.databaseName, "nombramientos-backup-source");
    let invariant: TenantInvariant;
    let recoveryPointAt: string;
    let postgresServerVersion: string;
    try {
      const client = await sourcePool.connect();
      try {
        await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
        const snapshot = await client.query<{ snapshot_id: string; captured_at: Date; server_version: string }>(
          "SELECT pg_export_snapshot() AS snapshot_id,clock_timestamp() AS captured_at,current_setting('server_version') AS server_version",
        );
        const state = snapshot.rows[0];
        if (!state) throw new Error("PostgreSQL did not export a backup snapshot");
        recoveryPointAt = state.captured_at.toISOString();
        postgresServerVersion = state.server_version;
        if (!postgresServerVersion.startsWith("18.")) throw new Error("Backup source must be PostgreSQL 18");
        await assertTenantMaintenanceDatabase(client, tenant);
        invariant = await captureTenantInvariant(client);
        if (invariant.tenantId !== tenant.id || invariant.tenantKind !== tenant.kind) {
          throw new Error("Backup source tenant settings do not match the control-plane route");
        }
        await runPgTool(
          pgToolPath(context.pgBin, "pg_dump"),
          [
            "--host", context.adminUrl.hostname,
            "--port", String(Number(context.adminUrl.port)),
            "--username", decodeURIComponent(context.adminUrl.username),
            "--dbname", tenant.databaseName,
            "--format=custom",
            "--compress=zstd:level=6",
            "--no-owner",
            "--no-privileges",
            "--lock-wait-timeout=5000",
            "--snapshot", state.snapshot_id,
            "--file", dumpPath,
          ],
          decodeURIComponent(context.adminUrl.password),
          "pg_dump",
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    } finally {
      await sourcePool.end();
    }

    const dump = await hashFile(dumpPath);
    const activeKey = context.keyInventory.keys.find(({ id }) => id === context.keyInventory.activeKeyId);
    if (!activeKey) throw new Error("Active backup encryption key is unavailable");
    const core: BackupCore = {
      backupId,
      tenantId: tenant.id,
      tenantKind: tenant.kind,
      sourceDatabase: tenant.databaseName,
      credentialVersion: tenant.credentialVersion,
      runtimeSecretReference: tenant.runtimeSecretReference,
      recoveryPointAt,
      backupCompletedAt: new Date().toISOString(),
      postgresServerVersion,
      pgDumpVersion: await pgToolVersion(pgToolPath(context.pgBin, "pg_dump"), "pg_dump"),
      encryptionKeyId: activeKey.id,
      invariant,
      invariantSha256: sha256(canonicalJson(invariant)),
      dump: { format: "pg_dump-custom", bytes: dump.bytes, sha256: dump.sha256 },
    };
    const payloadPath = path.join(partialDirectory, "database.dump.aesgcm");
    const activeKeyMaterial = Buffer.from(activeKey.keyB64, "base64url");
    let encryption: Awaited<ReturnType<typeof encryptBackupPayload>>;
    try {
      encryption = await encryptBackupPayload(dumpPath, payloadPath, activeKeyMaterial, core);
    } finally {
      activeKeyMaterial.fill(0);
    }
    const payload = await hashFile(payloadPath);
    const manifest = backupManifestSchema.parse({
      format: "nombramientos-tenant-backup",
      version: 1,
      core,
      encryption: { algorithm: "AES-256-GCM", ...encryption },
      payload: { file: "database.dump.aesgcm", ...payload },
    });
    const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
    await writeFile(path.join(partialDirectory, "manifest.json"), manifestText, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await writeFile(path.join(partialDirectory, "manifest.sha256"), `${sha256(manifestText)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await rename(partialDirectory, finalDirectory);
    finalized = true;
    return { directory: finalDirectory, manifest, durationMs: Math.round(performance.now() - startedAt) };
  } finally {
    await safeRemoveDirectory(workDirectory, context.workRoot);
    if (!finalized) await safeRemoveDirectory(partialDirectory, tenantRoot);
  }
}

async function runRestoreDrill(context: LocalContext, tenant: TenantMaintenanceRoute, backupDirectory: string): Promise<{
  backupId: string;
  scratchDatabase: string;
  comparedTenantIds: readonly string[];
  recoveryPointAgeMs: number;
  restoreTimeMs: number;
  totalDrillTimeMs: number;
}> {
  const drillStarted = performance.now();
  const directory = await resolveBackupDirectory(context, backupDirectory);
  await verifyManifestChecksum(directory);
  const manifest = await readBackupManifest(path.join(directory, "manifest.json"));
  if (manifest.core.tenantId !== tenant.id || manifest.core.sourceDatabase !== tenant.databaseName) {
    throw new Error("Backup manifest does not belong to the requested tenant route");
  }
  const payloadPath = await resolveExistingWithin(directory, path.join(directory, manifest.payload.file), "backup payload");
  const encrypted = await hashFile(payloadPath);
  if (encrypted.bytes !== manifest.payload.bytes || encrypted.sha256 !== manifest.payload.sha256) {
    throw new Error("Encrypted backup payload checksum does not match the manifest");
  }
  const backupKey = context.keyInventory.keys.find(({ id }) => id === manifest.core.encryptionKeyId);
  if (!backupKey) throw new Error("Backup encryption key id is not present in the local inventory");

  await assertMaintenanceDatabaseFromDatabase(
    context.adminUrl,
    tenant,
    `nombramientos-restore-target-${tenant.id.slice(0, 8)}`,
  );
  const eligibleTenants = await listTenantMaintenanceRoutes(context.controlPool);
  for (const eligible of eligibleTenants) assertLocalTenantRoute(eligible);
  if (!eligibleTenants.some(({ id }) => id === tenant.id)) {
    throw new Error("Requested tenant left its eligible maintenance lifecycle during restore preparation");
  }
  const otherTenants = eligibleTenants.filter(({ id }) => id !== tenant.id);
  const registered = await context.controlPool.query<{ database_name: string }>(
    "SELECT database_name::text FROM tenants ORDER BY id",
  );
  const scratch = scratchDatabaseName(tenant.id, manifest.core.backupId);
  const registeredNames = registered.rows.map(({ database_name }) => database_name);
  assertScratchDatabaseName(scratch, registeredNames);
  const exists = await databaseExists(context.controlPool, scratch);
  if (exists) throw new Error("Guarded scratch database already exists; refusing to overwrite or drop it");

  const workDirectory = await mkdtemp(path.join(context.workRoot, "restore-"));
  const plaintextDump = path.join(workDirectory, "database.dump");
  const backupKeyMaterial = Buffer.from(backupKey.keyB64, "base64url");
  let scratchCreated = false;
  const restoreStartedAt = performance.now();
  let verified = false;
  try {
    const otherBefore = new Map<string, TenantInvariant>();
    for (const other of otherTenants) {
      otherBefore.set(
        other.id,
        await captureMaintenanceInvariantFromDatabase(
          context.adminUrl,
          other,
          `nombramientos-restore-neighbor-before-${other.id.slice(0, 8)}`,
        ),
      );
    }
    await decryptBackupPayload(
      payloadPath,
      plaintextDump,
      backupKeyMaterial,
      manifest,
    );
    const dump = await hashFile(plaintextDump);
    if (dump.bytes !== manifest.core.dump.bytes || dump.sha256 !== manifest.core.dump.sha256) {
      throw new Error("Decrypted pg_dump checksum does not match the authenticated manifest");
    }

    await createScratchDatabase(context.controlPool, scratch, decodeURIComponent(context.adminUrl.username));
    scratchCreated = true;
    await runPgTool(
      pgToolPath(context.pgBin, "pg_restore"),
      [
        "--host", context.adminUrl.hostname,
        "--port", String(Number(context.adminUrl.port)),
        "--username", decodeURIComponent(context.adminUrl.username),
        "--dbname", scratch,
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--exit-on-error",
        plaintextDump,
      ],
      decodeURIComponent(context.adminUrl.password),
      "pg_restore",
    );
    const restored = await captureInvariantFromDatabase(context.adminUrl, scratch, "nombramientos-restore-scratch-verify");
    const restoredDifferences = compareTenantInvariants(manifest.core.invariant, restored);
    if (restoredDifferences.length > 0) {
      throw new Error(`Restored tenant invariant differs: ${restoredDifferences.join(",")}`);
    }
    const comparedTenantIds: string[] = [];
    for (const other of otherTenants) {
      const before = otherBefore.get(other.id);
      if (!before) throw new Error(`Missing pre-restore invariant for neighboring tenant ${other.id}`);
      const after = await captureMaintenanceInvariantFromDatabase(
        context.adminUrl,
        other,
        `nombramientos-restore-neighbor-after-${other.id.slice(0, 8)}`,
      );
      const otherDifferences = compareTenantInvariants(before, after);
      if (otherDifferences.length > 0) {
        throw new Error(`Other tenant ${other.id} changed during restore drill: ${otherDifferences.join(",")}`);
      }
      comparedTenantIds.push(other.id);
    }
    assertExpectedTenantComparisons(otherTenants.map(({ id }) => id), comparedTenantIds);
    verified = true;
  } finally {
    backupKeyMaterial.fill(0);
    try {
      if (scratchCreated) await dropScratchDatabase(context.controlPool, scratch, registeredNames);
    } finally {
      await safeRemoveDirectory(workDirectory, context.workRoot);
    }
  }
  if (!verified) throw new Error("Restore drill did not reach verified state");
  const completedAt = performance.now();
  const comparedTenantIds = otherTenants.map(({ id }) => id);
  return {
    backupId: manifest.core.backupId,
    scratchDatabase: scratch,
    comparedTenantIds,
    recoveryPointAgeMs: Math.max(0, Date.now() - Date.parse(manifest.core.recoveryPointAt)),
    restoreTimeMs: Math.round(completedAt - restoreStartedAt),
    totalDrillTimeMs: Math.round(completedAt - drillStarted),
  };
}

async function assertMaintenanceDatabaseFromDatabase(
  adminUrl: URL,
  tenant: TenantMaintenanceRoute,
  applicationName: string,
): Promise<void> {
  const pool = createAdminPool(adminUrl, tenant.databaseName, applicationName);
  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await assertTenantMaintenanceDatabase(client, tenant);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

async function captureMaintenanceInvariantFromDatabase(
  adminUrl: URL,
  tenant: TenantMaintenanceRoute,
  applicationName: string,
): Promise<TenantInvariant> {
  const pool = createAdminPool(adminUrl, tenant.databaseName, applicationName);
  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await assertTenantMaintenanceDatabase(client, tenant);
      const invariant = await captureTenantInvariant(client);
      await client.query("COMMIT");
      return invariant;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

async function captureInvariantFromDatabase(adminUrl: URL, database: string, applicationName: string): Promise<TenantInvariant> {
  const pool = createAdminPool(adminUrl, database, applicationName);
  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const invariant = await captureTenantInvariant(client);
      await client.query("COMMIT");
      return invariant;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

function createAdminPool(adminUrl: URL, database: string, applicationName: string): Pool {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(database)) throw new Error("Backup database target is invalid");
  return new Pool({
    host: adminUrl.hostname,
    port: Number(adminUrl.port),
    database,
    user: decodeURIComponent(adminUrl.username),
    password: decodeURIComponent(adminUrl.password),
    ssl: false,
    application_name: applicationName,
    max: 1,
    connectionTimeoutMillis: 5_000,
  });
}

async function createScratchDatabase(client: Pool, scratch: string, owner: string): Promise<void> {
  assertScratchDatabaseName(scratch, []);
  const statement = await client.query<{ sql: string }>(
    "SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L',$1::text,$2::text,'UTF8') AS sql",
    [scratch, owner],
  );
  const sql = statement.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the scratch CREATE DATABASE statement");
  await client.query(sql);
}

async function dropScratchDatabase(client: Pool, scratch: string, registeredDatabases: readonly string[]): Promise<void> {
  assertScratchDatabaseName(scratch, registeredDatabases);
  await client.query(
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()",
    [scratch],
  );
  const statement = await client.query<{ sql: string }>(
    "SELECT format('DROP DATABASE %I',$1::text) AS sql",
    [scratch],
  );
  const sql = statement.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the scratch DROP DATABASE statement");
  await client.query(sql);
}

async function databaseExists(client: Pool, database: string): Promise<boolean> {
  const result = await client.query("SELECT 1 FROM pg_database WHERE datname=$1", [database]);
  return result.rowCount === 1;
}

async function verifyManifestChecksum(directory: string): Promise<void> {
  const manifestPath = path.join(directory, "manifest.json");
  const [manifest, expected] = await Promise.all([
    readFile(manifestPath),
    readFile(path.join(directory, "manifest.sha256"), "utf8"),
  ]);
  if (expected.trim() !== sha256(manifest)) throw new Error("Backup manifest file checksum is invalid");
}

async function resolveBackupDirectory(context: LocalContext, value: string): Promise<string> {
  return resolveExistingWithin(context.backupRoot, value, "backup directory");
}

async function resolveExistingWithin(root: string, value: string, label: string): Promise<string> {
  const [resolvedRoot, resolvedValue] = await Promise.all([
    realpath(root),
    realpath(path.resolve(value)),
  ]);
  const boundary = `${resolvedRoot}${path.sep}`;
  if (!resolvedValue.startsWith(boundary)) throw new Error(`${label} must stay inside the protected local directory`);
  return resolvedValue;
}

async function safeRemoveDirectory(directory: string, root: string): Promise<void> {
  let resolvedDirectory: string;
  try {
    resolvedDirectory = await realpath(directory);
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  const resolvedRoot = await realpath(root);
  if (!resolvedDirectory.startsWith(`${resolvedRoot}${path.sep}`) || resolvedDirectory === resolvedRoot) {
    throw new Error("Refusing to remove a path outside the guarded backup work directory");
  }
  await rm(resolvedDirectory, { recursive: true, force: true });
}

async function ensurePg18(executable: string, label: string): Promise<void> {
  const info = await stat(executable);
  if (!info.isFile()) throw new Error(`${label} executable is unavailable`);
  const version = await pgToolVersion(executable, label);
  if (!/\b18\.\d+\b/.test(version)) throw new Error(`${label} must be from PostgreSQL 18`);
}

function pgToolPath(pgBin: string, tool: "pg_dump" | "pg_restore"): string {
  return path.join(pgBin, process.platform === "win32" ? `${tool}.exe` : tool);
}

async function pgToolVersion(executable: string, label: string): Promise<string> {
  const result = await runProcess(executable, ["--version"], undefined);
  if (result.code !== 0) throw new Error(`${label} --version failed safely`);
  return result.stdout.trim();
}

async function runPgTool(executable: string, args: readonly string[], password: string, label: string): Promise<void> {
  const result = await runProcess(executable, args, password);
  if (result.code !== 0) throw new Error(`${label} failed safely with exit code ${result.code}`);
}

async function runProcess(executable: string, args: readonly string[], password: string | undefined): Promise<{
  code: number;
  stdout: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      windowsHide: true,
      shell: false,
      env: {
        ...process.env,
        PGCONNECT_TIMEOUT: "5",
        ...(password ? { PGPASSWORD: password } : {}),
      },
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

function safeErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) return "unknown safe failure";
  return error.message
    .replace(/postgres(?:ql)?:\/\/[^@\s]+@/gi, "postgresql://[redacted]@")
    .replace(/PGPASSWORD=[^\s]+/gi, "PGPASSWORD=[redacted]");
}

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

void main().catch((error: unknown) => {
  process.stderr.write(`Tenant backup operation failed: ${safeErrorMessage(error)}\n`);
  process.exitCode = 1;
});
