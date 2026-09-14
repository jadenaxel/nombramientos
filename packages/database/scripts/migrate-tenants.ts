import { mkdtemp, readdir, readFile, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { catalogPackage2025, validateCatalogPackage } from "@nombramientos/catalog";
import { Pool } from "pg";
import { z } from "zod";
import {
  backupKeyInventorySchema,
  captureTenantInvariant,
  compareTenantInvariants,
  decryptBackupPayload,
  hashFile,
  sha256,
  verifyBackupManifest,
  type TenantInvariant,
} from "../src/backup.js";
import { inspectMigrationPlan, runMigrations } from "../src/migrations.js";
import {
  assertLegacyInvitationReconciliationApplied,
  assertLegacyInvitationReconciliationFinalized,
  assertLegacyInvitationReconciliationUnchanged,
  finalizeLegacyInvitationReconciliationEvidence,
  inspectLegacyInvitationReconciliation,
  installLegacyInvitationReconciliationManifest,
  LEGACY_INVITATION_RECONCILIATION_MIGRATION,
  lockLegacyInvitationReconciliationBoundary,
} from "../src/legacy-invitation-reconciliation.js";
import {
  ensureInitialAdminActivationCapability,
  initialAdminActivationCapabilityIsReady,
} from "../src/initial-admin-capability.js";
import { EncryptedFileSecretProvider } from "../src/secrets.js";
import {
  readTenantCatalogEvidence,
  reconcileTenantCatalog,
  assertTenantCatalogReconciliationSafe,
  tenantCatalogTarget,
  type CatalogReadQueryClient,
} from "../src/catalog-reconciliation.js";
import {
  reconcileTenantObjectOwnership,
  reconcileTenantOwnershipAndRuntimeGrants,
} from "../src/provisioner.js";
import {
  assertTenantUpgradeAuthorized,
  tenantUpgradeApprovalDigest,
} from "../src/tenant-upgrade-policy.js";
import {
  assertCanonicalTenantTableInventory,
  assertTenantMaintenanceDatabase,
  lockTenantMaintenanceRoute,
  resolveTenantMaintenanceRoute,
  type TenantMaintenanceRoute,
} from "../src/tenant-maintenance-policy.js";
import { tenantSecurityTargetSha256 } from "../src/tenant-security-target.js";
import {
  loadLocalScriptValues,
  localScriptEnvironment,
  requireMasterKey,
  resolveDatabasePackageRoot,
  withoutDatabase,
} from "./script-config.js";

const CONTROL_DATABASE = "nombramientos_control";
const WORKSPACE_PORT = 55_432;
const TENANT_UPGRADE_REPORT_SCHEMA_VERSION = 2;
const uuidSchema = z.string().uuid();
const upgradeModeSchema = z.enum(["preflight", "apply"]);

const localValues = loadLocalScriptValues();
const environment = localScriptEnvironment.parse(localValues);
const administrator = new URL(environment.DATABASE_ADMIN_URL);
assertWorkspaceCluster(administrator);
const selectedTenantId = requiredUuidEnvironment("NOMBRAMIENTOS_TENANT_UPGRADE_ID");
const upgradeMode = upgradeModeSchema.parse(requiredEnvironment("NOMBRAMIENTOS_TENANT_UPGRADE_MODE"));
const catalogErrors = validateCatalogPackage(catalogPackage2025);
if (catalogErrors.length !== 0) {
  throw new Error("The production catalog package failed validation");
}
const catalogTarget = tenantCatalogTarget(catalogPackage2025);
const securityTargetSha256 = tenantSecurityTargetSha256(selectedTenantId);

const control = new Pool({
  connectionString: withoutDatabase(environment.DATABASE_ADMIN_URL, CONTROL_DATABASE),
  application_name: "nombramientos-tenant-migration-discovery",
  connectionTimeoutMillis: 5_000,
  max: 1,
});

try {
  const server = await control.query<{ version: number; port: number }>(
    "SELECT current_setting('server_version_num')::int AS version, current_setting('port')::int AS port",
  );
  const serverRecord = server.rows[0];
  if (!serverRecord || serverRecord.version < 180_000 || serverRecord.port !== WORKSPACE_PORT) {
    throw new Error("Tenant migrations require the configured workspace PostgreSQL 18 cluster on port 55432");
  }

  const tenant = await resolveTenantMaintenanceRoute(control, selectedTenantId);
  assertTenantRoute(tenant);

  const packageRoot = resolveDatabasePackageRoot(import.meta.url);
  const secretProvider = new EncryptedFileSecretProvider(
    process.env["DATABASE_SECRET_FILE"] ?? path.join(packageRoot, ".local", "secrets.enc.json"),
    requireMasterKey(environment.DATABASE_SECRET_MASTER_KEY_B64),
  );
  const migrationDirectory = path.join(packageRoot, "migrations", "tenant");
  const tenantPool = new Pool({
    connectionString: withoutDatabase(environment.DATABASE_ADMIN_URL, tenant.databaseName),
    application_name: `nombramientos-tenant-migrate-${tenant.id.slice(0, 8)}`,
    connectionTimeoutMillis: 5_000,
    max: 1,
  });
  try {
    await assertTenantMaintenanceDatabase(tenantPool, tenant);

    const plan = await inspectMigrationPlan(tenantPool, {
      scope: "tenant",
      directory: migrationDirectory,
    });
    const legacyInvitationBefore = await inspectLegacyInvitationReconciliation(
      tenantPool,
      control,
      tenant.id,
    );
    const catalogBefore = await readTenantCatalogEvidence(catalogReader(tenantPool), catalogPackage2025);
    assertTenantCatalogReconciliationSafe(catalogBefore);
    const catalogReconciliationRequired = catalogBefore.mismatchCount !== 0;
    const capabilityReconciliationRequired = !(await initialAdminActivationCapabilityIsReady(
      tenantPool,
      secretProvider,
      tenant.id,
      tenant.kind,
    ));
    if (
      plan.pending.length === 0
      && !catalogReconciliationRequired
      && !capabilityReconciliationRequired
      && !legacyInvitationBefore.evidence.required
    ) {
      process.stdout.write(`${JSON.stringify({
        schemaVersion: TENANT_UPGRADE_REPORT_SCHEMA_VERSION,
        mode: upgradeMode,
        status: "no_changes",
        tenantId: tenant.id,
        tenantLifecycle: tenant.status,
        maintenanceClass: tenant.maintenanceClass,
        pendingMigrations: [],
        backupId: null,
        backupPayloadSha256: null,
        approvalDigest: null,
        catalogTarget,
        securityTargetSha256,
        legacyInvitationReconciliation: legacyInvitationBefore.evidence,
        catalogMismatchCount: 0,
        catalogReconciliationRequired: false,
        ...(upgradeMode === "apply" ? { appliedMigrations: [] } : {}),
      })}\n`);
    } else {
      const backupId = requiredUuidEnvironment("NOMBRAMIENTOS_TENANT_UPGRADE_BACKUP_ID");
      const reentryPlanReference = requiredEnvironment("NOMBRAMIENTOS_TENANT_UPGRADE_REENTRY_PLAN_REFERENCE");
      const backupKeyFile = requiredInstalledValue(localValues, "DATABASE_BACKUP_KEY_FILE");
      const verifiedBackup = await verifyCurrentLocalBackup(
        packageRoot,
        tenantPool,
        tenant,
        backupId,
        backupKeyFile,
      );
      const backupPayloadSha256 = verifiedBackup.payloadSha256;
      const approvalContext = {
        tenantId: tenant.id,
        backupId,
        backupPayloadSha256,
        pendingMigrations: plan.pending,
        catalogTarget,
        securityTargetSha256,
        legacyInvitationReconciliation: legacyInvitationBefore.evidence,
        reentryPlanReference,
      } as const;
      const approvalDigest = tenantUpgradeApprovalDigest(approvalContext);
      if (upgradeMode === "preflight") {
        process.stdout.write(`${JSON.stringify({
          schemaVersion: TENANT_UPGRADE_REPORT_SCHEMA_VERSION,
          mode: "preflight",
          status: "approval_required",
          tenantId: tenant.id,
          tenantLifecycle: tenant.status,
          maintenanceClass: tenant.maintenanceClass,
          pendingMigrations: plan.pending.map(({ name, checksum }) => ({ name, checksum })),
          backupId,
          backupPayloadSha256,
          approvalDigest,
          catalogTarget,
          securityTargetSha256,
          legacyInvitationReconciliation: legacyInvitationBefore.evidence,
          catalogMismatchCount: catalogBefore.mismatchCount,
          catalogReconciliationRequired,
        })}\n`);
      } else {
        assertTenantUpgradeAuthorized({
          ...approvalContext,
          suppliedApproval: requiredEnvironment("NOMBRAMIENTOS_TENANT_UPGRADE_APPROVAL"),
        });
        const controlClient = await control.connect();
        try {
          await controlClient.query("BEGIN");
          await lockLegacyInvitationReconciliationBoundary(controlClient, tenant.id);
          const lockedTenant = await lockTenantMaintenanceRoute(controlClient, tenant.id);
          assertRouteUnchanged(tenant, lockedTenant);
          assertTenantRoute(lockedTenant);
          await assertTenantMaintenanceDatabase(tenantPool, lockedTenant);
          await assertNoOtherTenantSessions(tenantPool);
          await assertTenantMatchesBackupInvariant(tenantPool, verifiedBackup.invariant);
          const lockedLegacyInvitation = await inspectLegacyInvitationReconciliation(
            tenantPool,
            controlClient,
            lockedTenant.id,
            { lockControlRows: true },
          );
          assertLegacyInvitationReconciliationUnchanged(
            legacyInvitationBefore,
            lockedLegacyInvitation,
          );
          const catalogAtApply = await readTenantCatalogEvidence(catalogReader(tenantPool), catalogPackage2025);
          assertTenantCatalogReconciliationSafe(catalogAtApply);
          const ownerRole = `nom_o_${tenant.id.replaceAll("-", "")}`;
          // Existing ownership drift can prevent SET ROLE from applying a migration.
          // The final helper repeats ownership and grants in one locked transaction.
          await reconcileTenantObjectOwnership(tenantPool, ownerRole);
          const applied = await runMigrations(tenantPool, {
            scope: "tenant",
            directory: migrationDirectory,
            expectedPendingMigrations: plan.pending,
            executionRole: ownerRole,
            beforeMigration: async (migrationClient, migration) => {
              if (migration.name === LEGACY_INVITATION_RECONCILIATION_MIGRATION) {
                await installLegacyInvitationReconciliationManifest(
                  migrationClient,
                  lockedLegacyInvitation,
                );
              }
            },
          });
          const appliedLegacyInvitation = await inspectLegacyInvitationReconciliation(
            tenantPool,
            controlClient,
            lockedTenant.id,
            { lockControlRows: true },
          );
          assertLegacyInvitationReconciliationApplied(
            lockedLegacyInvitation,
            appliedLegacyInvitation,
          );
          await finalizeLegacyInvitationReconciliationEvidence(
            controlClient,
            appliedLegacyInvitation,
            backupId,
          );
          const finalizedLegacyInvitation = await inspectLegacyInvitationReconciliation(
            tenantPool,
            controlClient,
            lockedTenant.id,
            { lockControlRows: true },
          );
          assertLegacyInvitationReconciliationFinalized(
            appliedLegacyInvitation,
            finalizedLegacyInvitation,
          );
          await ensureInitialAdminActivationCapability(
            tenantPool,
            secretProvider,
            lockedTenant.id,
            lockedTenant.kind,
          );
          const catalogResult = await reconcileTenantCatalog(tenantPool, catalogPackage2025);
          await reconcileTenantOwnershipAndRuntimeGrants(
            tenantPool,
            ownerRole,
            lockedTenant.runtimeRole,
            async (tenantClient) => {
              await assertTenantMaintenanceDatabase(tenantClient, lockedTenant);
              await assertCanonicalTenantTableInventory(tenantClient, lockedTenant.id);
            },
            async () => {
              const confirmedRoute = await resolveTenantMaintenanceRoute(controlClient, tenant.id);
              assertRouteUnchanged(lockedTenant, confirmedRoute);
            },
          );
          await controlClient.query("COMMIT");
          process.stdout.write(`${JSON.stringify({
            schemaVersion: TENANT_UPGRADE_REPORT_SCHEMA_VERSION,
            mode: "apply",
            status: "applied",
            tenantId: tenant.id,
            tenantLifecycle: tenant.status,
            maintenanceClass: tenant.maintenanceClass,
            appliedMigrations: applied,
            backupId,
            approvalDigest,
            catalogTarget,
            securityTargetSha256,
            legacyInvitationReconciliation: finalizedLegacyInvitation.evidence,
            catalogReconciled: catalogResult.changed,
            catalogMutationCount: catalogResult.mutationCount,
            catalogMismatchCount: catalogResult.mismatchCount,
            runtimeGrantsReconciled: true,
          })}\n`);
        } catch (error) {
          await controlClient.query("ROLLBACK").catch(() => undefined);
          throw error;
        } finally {
          controlClient.release();
        }
      }
    }
  } finally {
    await tenantPool.end();
  }
} finally {
  await control.end();
}

async function verifyCurrentLocalBackup(
  packageRoot: string,
  tenantPool: Pool,
  tenant: TenantMaintenanceRoute,
  backupId: string,
  backupKeyFile: string,
): Promise<{ readonly payloadSha256: string; readonly invariant: TenantInvariant }> {
  const backupRoot = await realpath(path.join(packageRoot, ".local", "backups")).catch(() => {
    throw new Error("The local backup root does not exist");
  });
  const tenantRoot = await realpath(path.join(backupRoot, tenant.id)).catch(() => {
    throw new Error(`No local backup directory exists for selected tenant ${tenant.id}`);
  });
  if (!tenantRoot.startsWith(`${backupRoot}${path.sep}`)) {
    throw new Error("Tenant upgrade backup root resolved outside the local backup boundary");
  }
  const matches = (await readdir(tenantRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && entry.name.endsWith(`-${backupId}`));
  if (matches.length !== 1) {
    throw new Error(`Exactly one completed local backup ${backupId} is required for tenant ${tenant.id}`);
  }
  const backupDirectory = await realpath(path.join(tenantRoot, matches[0]!.name));
  if (!backupDirectory.startsWith(`${tenantRoot}${path.sep}`)) {
    throw new Error("Tenant upgrade backup resolved outside its tenant backup boundary");
  }
  const manifestPath = path.join(backupDirectory, "manifest.json");
  const [manifestBytes, expectedManifestChecksum] = await Promise.all([
    readFile(manifestPath),
    readFile(path.join(backupDirectory, "manifest.sha256"), "utf8"),
  ]);
  if (expectedManifestChecksum.trim() !== sha256(manifestBytes)) {
    throw new Error("Tenant upgrade backup manifest file checksum is invalid");
  }
  const manifest = verifyBackupManifest(JSON.parse(manifestBytes.toString("utf8")) as unknown);
  if (
    manifest.core.backupId !== backupId
    || manifest.core.tenantId !== tenant.id
    || manifest.core.tenantKind !== tenant.kind
    || manifest.core.sourceDatabase !== tenant.databaseName
    || manifest.core.runtimeSecretReference !== tenant.runtimeSecretReference
    || manifest.core.credentialVersion !== tenant.credentialVersion
  ) {
    throw new Error("Tenant upgrade backup identity does not match the selected control-plane route");
  }
  const payload = await hashFile(path.join(backupDirectory, manifest.payload.file));
  if (payload.bytes !== manifest.payload.bytes || payload.sha256 !== manifest.payload.sha256) {
    throw new Error("Tenant upgrade backup payload checksum does not match its authenticated manifest");
  }
  await authenticateBackupPayload(packageRoot, backupDirectory, backupKeyFile, manifest);

  const client = await tenantPool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const currentInvariant = await captureTenantInvariant(client);
    const differences = compareTenantInvariants(manifest.core.invariant, currentInvariant);
    if (differences.length > 0) {
      throw new Error(`Tenant changed after the selected backup (${differences.join(", ")}); create and verify a new backup`);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return { payloadSha256: payload.sha256, invariant: manifest.core.invariant };
}

async function assertTenantMatchesBackupInvariant(
  tenantPool: Pool,
  expectedInvariant: TenantInvariant,
): Promise<void> {
  const client = await tenantPool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const currentInvariant = await captureTenantInvariant(client);
    const differences = compareTenantInvariants(expectedInvariant, currentInvariant);
    if (differences.length > 0) {
      throw new Error(`Tenant changed inside the maintenance boundary (${differences.join(", ")}); restart preflight with a new backup`);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function authenticateBackupPayload(
  packageRoot: string,
  backupDirectory: string,
  backupKeyFile: string,
  manifest: ReturnType<typeof verifyBackupManifest>,
): Promise<void> {
  const localRoot = await realpath(path.join(packageRoot, ".local"));
  const resolvedKeyFile = await realpath(path.resolve(backupKeyFile)).catch(() => {
    throw new Error("Configured backup key inventory is unavailable");
  });
  if (!resolvedKeyFile.startsWith(`${localRoot}${path.sep}`)) {
    throw new Error("Configured backup key inventory resolved outside protected local state");
  }
  const inventory = backupKeyInventorySchema.parse(
    JSON.parse(await readFile(resolvedKeyFile, "utf8")) as unknown,
  );
  const keyRecord = inventory.keys.find(({ id }) => id === manifest.core.encryptionKeyId);
  if (!keyRecord) throw new Error("Backup encryption key referenced by the manifest is unavailable");

  const temporaryRoot = await realpath(os.tmpdir());
  const workDirectory = await mkdtemp(path.join(temporaryRoot, "nom-tenant-upgrade-"));
  const plaintextDump = path.join(workDirectory, "database.dump");
  const key = Buffer.from(keyRecord.keyB64, "base64url");
  try {
    await decryptBackupPayload(
      path.join(backupDirectory, manifest.payload.file),
      plaintextDump,
      key,
      manifest,
    );
    const dump = await hashFile(plaintextDump);
    if (dump.bytes !== manifest.core.dump.bytes || dump.sha256 !== manifest.core.dump.sha256) {
      throw new Error("Decrypted tenant backup dump does not match its authenticated manifest");
    }
  } finally {
    key.fill(0);
    await removeTemporaryUpgradeDirectory(workDirectory, temporaryRoot);
  }
}

async function removeTemporaryUpgradeDirectory(directory: string, temporaryRoot: string): Promise<void> {
  const resolved = await realpath(directory).catch((error: unknown) => {
    if (isMissingFile(error)) return null;
    throw error;
  });
  if (resolved === null) return;
  if (
    !resolved.startsWith(`${temporaryRoot}${path.sep}`)
    || !path.basename(resolved).startsWith("nom-tenant-upgrade-")
  ) {
    throw new Error("Refusing to remove a temporary upgrade path outside its guarded boundary");
  }
  await rm(resolved, { recursive: true, force: true });
}

async function assertNoOtherTenantSessions(tenantPool: Pool): Promise<void> {
  const sessions = await tenantPool.query<{ count: number }>(
    `SELECT count(*)::int AS count
       FROM pg_catalog.pg_stat_activity
      WHERE datname=current_database() AND pid<>pg_backend_pid()`,
  );
  if ((sessions.rows[0]?.count ?? 0) !== 0) {
    throw new Error("Tenant upgrade requires the application and every other tenant session to be stopped");
  }
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required for an explicit tenant upgrade`);
  return value;
}

function requiredUuidEnvironment(name: string): string {
  return uuidSchema.parse(requiredEnvironment(name));
}

function requiredInstalledValue(values: Record<string, string | undefined>, name: string): string {
  const value = values[name]?.trim();
  if (!value) throw new Error(`${name} must be configured before a tenant upgrade preflight`);
  return value;
}

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function assertWorkspaceCluster(value: URL): void {
  if (!["postgres:", "postgresql:"].includes(value.protocol)) {
    throw new Error("Tenant migrations require a PostgreSQL administrator URL");
  }
  if (!["127.0.0.1", "localhost", "[::1]"].includes(value.hostname)) {
    throw new Error("Tenant migrations refuse a non-loopback PostgreSQL host");
  }
  if (Number(value.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Tenant migrations refuse PostgreSQL outside workspace port 55432");
  }
}

function assertTenantRoute(tenant: TenantMaintenanceRoute): void {
  const suffix = tenant.id.replaceAll("-", "");
  if (
    tenant.databaseHost !== administrator.hostname
    || tenant.databasePort !== WORKSPACE_PORT
    || tenant.databaseName !== `nom_t_${suffix}`
    || tenant.runtimeRole !== `nom_r_${suffix}`
    || tenant.runtimeSecretReference !== `tenant-db/${tenant.id}/runtime/v${tenant.credentialVersion}`
  ) {
    throw new Error(`Tenant ${tenant.id} has a non-deterministic or out-of-cluster database route`);
  }
}

function assertRouteUnchanged(before: TenantMaintenanceRoute, after: TenantMaintenanceRoute): void {
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error(`Tenant ${before.id} maintenance route changed during tenant upgrade`);
  }
}

function catalogReader(pool: Pool): CatalogReadQueryClient {
  return {
    query: async (text, values) => values === undefined
      ? await pool.query(text)
      : await pool.query(text, [...values]),
  };
}
