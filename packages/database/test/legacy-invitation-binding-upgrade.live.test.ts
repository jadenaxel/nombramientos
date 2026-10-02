import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import {
  assertLegacyInvitationReconciliationApplied,
  assertLegacyInvitationReconciliationFinalized,
  assertLegacyInvitationReconciliationUnchanged,
  finalizeLegacyInvitationReconciliationEvidence,
  inspectLegacyInvitationReconciliation,
  installLegacyInvitationReconciliationManifest,
  LEGACY_INVITATION_RECONCILIATION_MIGRATION,
} from "../src/legacy-invitation-reconciliation.js";
import { inspectMigrationPlan, runMigrations } from "../src/migrations.js";
import {
  ensureInitialAdminActivationCapability,
  initialAdminActivationCapabilityIsReady,
} from "../src/initial-admin-capability.js";
import type { WritableSecretProvider } from "../src/types.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tenantMigrations = path.join(packageRoot, "migrations", "tenant");
const controlMigrations = path.join(packageRoot, "migrations", "control");
const GESTIONCHURCH_FEDERATION_MIGRATION = "037_gestionchurch_federation.sql";
const EXPLICIT_CUSTODIAN_MIGRATION = "038_gestionchurch_explicit_custodian_role.sql";
const DEVICE_SESSION_MIGRATION = "039_device_bound_http_sessions.sql";
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Legacy invitation upgrade tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

live("legacy invitation binding 035 to 036 reconciliation", () => {
  it("upgrades only an exact accepted control-plane tuple and commits durable evidence", async () => {
    await withTemporaryPair(async ({ control, tenant }) => {
      const fixture = await seedAcceptedLegacyBinding(control, tenant);
      const plan = await inspectMigrationPlan(tenant, { scope: "tenant", directory: tenantMigrations });
      expect(plan.pending.map(({ name }) => name)).toEqual([
        LEGACY_INVITATION_RECONCILIATION_MIGRATION,
        GESTIONCHURCH_FEDERATION_MIGRATION,
        EXPLICIT_CUSTODIAN_MIGRATION,
        DEVICE_SESSION_MIGRATION,
      ]);
      const before = await inspectLegacyInvitationReconciliation(tenant, control, fixture.tenantId);
      expect(before.evidence).toMatchObject({
        required: true,
        sourceSchema: "legacy_035",
        invitationCount: 1,
        bindingCount: 1,
      });

      const controlClient = await control.connect();
      try {
        await controlClient.query("BEGIN");
        const locked = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationUnchanged(before, locked);
        await runMigrations(tenant, {
          scope: "tenant",
          directory: tenantMigrations,
          expectedPendingMigrations: plan.pending,
          beforeMigration: async (client, migration) => {
            if (migration.name === LEGACY_INVITATION_RECONCILIATION_MIGRATION) {
              await installLegacyInvitationReconciliationManifest(client, locked);
            }
          },
        });
        const applied = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationApplied(locked, applied);
        await finalizeLegacyInvitationReconciliationEvidence(controlClient, applied, randomUUID());
        const finalized = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationFinalized(applied, finalized);
        expect(finalized.evidence.required).toBe(false);
        await controlClient.query("COMMIT");
      } catch (error) {
        await controlClient.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        controlClient.release();
      }

      const tenantEvidence = await tenant.query<{
        source_acceptance_id: string;
        state: string;
        acceptance_attempt: number;
        acceptance_id: string;
        invited_identity_id: string;
        granted_by_identity_id: string;
        role_codes: string[];
      }>(
        `SELECT binding.source_acceptance_id::text,fence.state,fence.acceptance_attempt,
                fence.acceptance_id::text,fence.invited_identity_id::text,
                fence.granted_by_identity_id::text,fence.role_codes
           FROM role_bindings binding
           JOIN tenant_invitation_acceptance_fences fence
             ON fence.invitation_id=binding.source_invitation_id
          WHERE binding.source_invitation_id=$1`,
        [fixture.invitationId],
      );
      expect(tenantEvidence.rows).toEqual([{
        source_acceptance_id: fixture.acceptanceId,
        state: "applied",
        acceptance_attempt: 1,
        acceptance_id: fixture.acceptanceId,
        invited_identity_id: fixture.recipientId,
        granted_by_identity_id: fixture.grantorId,
        role_codes: ["AUDITOR"],
      }]);
      const audit = await control.query<{ count: number; exact_metadata: boolean }>(
        `SELECT count(*)::int AS count,
                bool_and(metadata->>'manifestSha256'=$2
                  AND metadata->>'controlSnapshotSha256'=$3
                  AND metadata->>'migration'=$4
                  AND metadata->>'invitationCount'='1'
                  AND metadata->>'bindingCount'='1') AS exact_metadata
           FROM platform_audit_events
          WHERE tenant_id=$1 AND action='tenant.legacy_invitation_bindings_reconciled'
            AND result='success'`,
        [
          fixture.tenantId,
          before.evidence.manifestSha256,
          before.evidence.controlSnapshotSha256,
          LEGACY_INVITATION_RECONCILIATION_MIGRATION,
        ],
      );
      expect(audit.rows).toEqual([{ count: 1, exact_metadata: true }]);
    });
  }, 180_000);

  it("rolls migration 036 back when tenant bindings diverge from the preflight manifest", async () => {
    await withTemporaryPair(async ({ control, tenant }) => {
      const fixture = await seedAcceptedLegacyBinding(control, tenant);
      const before = await inspectLegacyInvitationReconciliation(tenant, control, fixture.tenantId);
      await tenant.query(
        "UPDATE role_bindings SET granted_by_identity_id=$1 WHERE source_invitation_id=$2",
        [randomUUID(), fixture.invitationId],
      );
      await expect(runMigrations(tenant, {
        scope: "tenant",
        directory: tenantMigrations,
        beforeMigration: async (client, migration) => {
          if (migration.name === LEGACY_INVITATION_RECONCILIATION_MIGRATION) {
            await installLegacyInvitationReconciliationManifest(client, before);
          }
        },
      })).rejects.toMatchObject({
        code: "23514",
        constraint: "legacy_invitation_binding_reconciliation_ambiguous",
      });
      const unchanged = await tenant.query<{ acceptance_column: number; migration_row: number }>(
        `SELECT
           (SELECT count(*)::int FROM information_schema.columns
             WHERE table_schema='public' AND table_name='role_bindings'
               AND column_name='source_acceptance_id') AS acceptance_column,
           (SELECT count(*)::int FROM schema_migrations WHERE name=$1) AS migration_row`,
        [LEGACY_INVITATION_RECONCILIATION_MIGRATION],
      );
      expect(unchanged.rows).toEqual([{ acceptance_column: 0, migration_row: 0 }]);
    });
  }, 180_000);

  it("finalizes an exact historical initial administrator and treats its consumed capability as not applicable", async () => {
    await withTemporaryPair(async ({ control, tenant }) => {
      const fixture = await seedAcceptedLegacyBinding(control, tenant, { authorityKind: "initial_admin" });
      const plan = await inspectMigrationPlan(tenant, { scope: "tenant", directory: tenantMigrations });
      const before = await inspectLegacyInvitationReconciliation(tenant, control, fixture.tenantId);
      expect(before.entries[0]).toMatchObject({
        authorityKind: "initial_admin",
        authorityEpoch: 1,
        roleCodes: ["CHURCH_ADMIN"],
        authorityFinalized: false,
      });
      const controlClient = await control.connect();
      try {
        await controlClient.query("BEGIN");
        const locked = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationUnchanged(before, locked);
        await runMigrations(tenant, {
          scope: "tenant",
          directory: tenantMigrations,
          expectedPendingMigrations: plan.pending,
          beforeMigration: async (client, migration) => {
            if (migration.name === LEGACY_INVITATION_RECONCILIATION_MIGRATION) {
              await installLegacyInvitationReconciliationManifest(client, locked);
            }
          },
        });
        const applied = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationApplied(locked, applied);
        await finalizeLegacyInvitationReconciliationEvidence(controlClient, applied, randomUUID());
        const finalized = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationFinalized(applied, finalized);
        expect(finalized.entries[0]?.authorityFinalized).toBe(true);
        await controlClient.query("COMMIT");
      } catch (error) {
        await controlClient.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        controlClient.release();
      }

      const unusedProvider = {} as WritableSecretProvider;
      await expect(ensureInitialAdminActivationCapability(
        tenant,
        unusedProvider,
        fixture.tenantId,
        "real",
      )).resolves.toBe("not_applicable");
      await expect(initialAdminActivationCapabilityIsReady(
        tenant,
        unusedProvider,
        fixture.tenantId,
        "real",
      )).resolves.toBe(true);
      const durable = await control.query<{
        authority_finalized: boolean;
        version: number;
      }>(
        `SELECT authority_finalized_at IS NOT NULL AS authority_finalized,version
           FROM tenant_invitations WHERE id=$1`,
        [fixture.invitationId],
      );
      expect(durable.rows).toEqual([{ authority_finalized: true, version: 2 }]);
      const capability = await tenant.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM initial_admin_activation_capability",
      );
      expect(capability.rows[0]?.count).toBe(0);
    });
  }, 180_000);

  it("upgrades an exact accepted binding from tenant head 034 through device session head 039", async () => {
    await withTemporaryPair(async ({ control, tenant }) => {
      const fixture = await seedAcceptedLegacyBinding(control, tenant);
      const plan = await inspectMigrationPlan(tenant, { scope: "tenant", directory: tenantMigrations });
      expect(plan.pending.map(({ name }) => name)).toEqual([
        "035_system_role_assignment_matrix.sql",
        LEGACY_INVITATION_RECONCILIATION_MIGRATION,
        GESTIONCHURCH_FEDERATION_MIGRATION,
        EXPLICIT_CUSTODIAN_MIGRATION,
        DEVICE_SESSION_MIGRATION,
      ]);
      const before = await inspectLegacyInvitationReconciliation(tenant, control, fixture.tenantId);
      const controlClient = await control.connect();
      try {
        await controlClient.query("BEGIN");
        const locked = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationUnchanged(before, locked);
        await runMigrations(tenant, {
          scope: "tenant",
          directory: tenantMigrations,
          expectedPendingMigrations: plan.pending,
          beforeMigration: async (client, migration) => {
            if (migration.name === LEGACY_INVITATION_RECONCILIATION_MIGRATION) {
              await installLegacyInvitationReconciliationManifest(client, locked);
            }
          },
        });
        const applied = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationApplied(locked, applied);
        await finalizeLegacyInvitationReconciliationEvidence(controlClient, applied, randomUUID());
        const finalized = await inspectLegacyInvitationReconciliation(
          tenant,
          controlClient,
          fixture.tenantId,
          { lockControlRows: true },
        );
        assertLegacyInvitationReconciliationFinalized(applied, finalized);
        await controlClient.query("COMMIT");
      } catch (error) {
        await controlClient.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        controlClient.release();
      }
      const migrated = await tenant.query<{ source_acceptance_id: string; fence_count: number }>(
        `SELECT binding.source_acceptance_id::text,
                (SELECT count(*)::int FROM tenant_invitation_acceptance_fences) AS fence_count
           FROM role_bindings binding WHERE binding.source_invitation_id=$1`,
        [fixture.invitationId],
      );
      expect(migrated.rows).toEqual([{ source_acceptance_id: fixture.acceptanceId, fence_count: 1 }]);
    }, { tenantMaximumMigration: 34 });
  }, 180_000);
});

async function seedAcceptedLegacyBinding(
  control: Pool,
  tenant: Pool,
  options: { readonly authorityKind?: "tenant_delegate" | "initial_admin" } = {},
): Promise<{
  readonly tenantId: string;
  readonly invitationId: string;
  readonly acceptanceId: string;
  readonly recipientId: string;
  readonly grantorId: string;
}> {
  const tenantId = randomUUID();
  const invitationId = randomUUID();
  const acceptanceId = randomUUID();
  const recipientId = randomUUID();
  const grantorId = randomUUID();
  const authorityKind = options.authorityKind ?? "tenant_delegate";
  const roleCode = authorityKind === "initial_admin" ? "CHURCH_ADMIN" : "AUDITOR";
  const authorityEpoch = authorityKind === "initial_admin" ? 1 : 0;
  await control.query(
    `INSERT INTO tenants(
       id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,
       runtime_secret_ref,database_port,activated_at,initial_admin_authority_epoch
     ) VALUES ($1,$2,'Legacy binding fixture','real','active','America/La_Paz','es',
               $3,$4,$5,55432,clock_timestamp(),$6)`,
    [
      tenantId,
      `legacy-${randomBytes(4).toString("hex")}`,
      `nom_t_${tenantId.replaceAll("-", "")}`,
      `nom_r_${tenantId.replaceAll("-", "")}`,
      `tenant-db/${tenantId}/runtime/v1`,
      authorityEpoch,
    ],
  );
  await control.query(
    `INSERT INTO platform_identities(id,email,normalized_email,display_name,password_hash,status)
     VALUES
       ($1,'grantor@invalid.example','grantor@invalid.example','Grantor','disabled','active'),
       ($2,'recipient@invalid.example','recipient@invalid.example','Recipient','disabled','active')`,
    [grantorId, recipientId],
  );
  await control.query(
    `INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default)
     VALUES ($1,$2,'active',true),($1,$3,'active',true)`,
    [tenantId, grantorId, recipientId],
  );
  await control.query(
    `INSERT INTO tenant_invitations(
       id,tenant_id,email,normalized_email,role_codes,token_hash,status,
       idempotency_key,request_hash,created_by_identity_id,expires_at,
       acceptance_id,acceptance_identity_id,acceptance_started_at,accepted_at,consumed_at,
       authority_kind,authority_epoch,acceptance_attempt,acceptance_recovery_hash
     ) VALUES (
       $1,$2,'recipient@invalid.example','recipient@invalid.example',ARRAY[$10]::text[],
       $3,'accepted',$4,$5,$6,clock_timestamp()+interval '1 hour',$7,$8,
       clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute',clock_timestamp()-interval '1 minute',
       $11,$12,1,$9
     )`,
    [
      invitationId,
      tenantId,
      randomBytes(32).toString("hex"),
      randomUUID(),
      randomBytes(32).toString("hex"),
      grantorId,
      acceptanceId,
      recipientId,
      randomBytes(32).toString("hex"),
      roleCode,
      authorityKind,
      authorityEpoch,
    ],
  );
  await tenant.query(
    `INSERT INTO tenant_settings(
       tenant_id,display_name,kind,timezone,locale,setup_state,catalog_version
     ) VALUES ($1,'Legacy binding fixture','real','America/La_Paz','es','ready','working-2026-09')`,
    [tenantId],
  );
  await tenant.query(
    `INSERT INTO role_bindings(identity_id,role_id,granted_by_identity_id,source_invitation_id)
     SELECT $1,role.id,$2,$3 FROM roles role WHERE role.code=$4`,
    [recipientId, grantorId, invitationId, roleCode],
  );
  return { tenantId, invitationId, acceptanceId, recipientId, grantorId };
}

async function withTemporaryPair(
  run: (databases: { readonly control: Pool; readonly tenant: Pool }) => Promise<void>,
  options: { readonly tenantMaximumMigration?: number } = {},
): Promise<void> {
  if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
  const suffix = randomBytes(9).toString("hex");
  const controlName = `nom_legacy_control_${suffix}`;
  const tenantName = `nom_legacy_tenant_${suffix}`;
  const cluster = new Pool({
    connectionString: databaseUrl(adminUrl, "postgres"),
    application_name: "nombramientos-legacy-upgrade-cluster",
    max: 1,
  });
  const control = new Pool({ connectionString: databaseUrl(adminUrl, controlName), max: 2 });
  const tenant = new Pool({ connectionString: databaseUrl(adminUrl, tenantName), max: 2 });
  await runWithCleanup(async () => {
    await createDatabase(cluster, controlName);
    await createDatabase(cluster, tenantName);
    await createMigrationTable(control);
    await createMigrationTable(tenant);
    await applyMigrationsThrough(control, controlMigrations, 26);
    await applyMigrationsThrough(tenant, tenantMigrations, options.tenantMaximumMigration ?? 35);
    await run({ control, tenant });
  }, () => cleanupLegacyPair(cluster, control, controlName, tenant, tenantName), "Legacy invitation upgrade live case");
}

async function createMigrationTable(database: Pool): Promise<void> {
  await database.query(`
    CREATE TABLE schema_migrations (
      name text PRIMARY KEY,
      checksum text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )
  `);
}

async function applyMigrationsThrough(
  database: Pool,
  directory: string,
  maximumMigration: number,
): Promise<void> {
  const migrations = readdirSync(directory)
    .filter((file) => /^\d+_.+\.sql$/u.test(file) && Number(file.slice(0, 3)) <= maximumMigration)
    .sort((left, right) => left.localeCompare(right));
  for (const migration of migrations) {
    const sql = readFileSync(path.join(directory, migration), "utf8");
    const client = await database.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query(
        "INSERT INTO schema_migrations(name,checksum) VALUES ($1,$2)",
        [migration, createHash("sha256").update(sql).digest("hex")],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }
}

async function createDatabase(cluster: Pool, databaseName: string): Promise<void> {
  await executeFormatted(
    cluster,
    "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
    [databaseName],
  );
}

async function cleanupLegacyPair(
  cluster: Pool,
  control: Pool,
  controlName: string,
  tenant: Pool,
  tenantName: string,
): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [
      { databaseName: tenantName, databasePools: [tenant], assertSafeDatabaseName: assertLegacyDatabaseName, label: "legacy tenant" },
      { databaseName: controlName, databasePools: [control], assertSafeDatabaseName: assertLegacyDatabaseName, label: "legacy control" },
    ],
    label: "Temporary legacy invitation databases",
  });
}

function assertLegacyDatabaseName(databaseName: string): void {
  if (!/^nom_legacy_(?:control|tenant)_[0-9a-f]{18}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-legacy-upgrade test database");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the legacy upgrade test statement");
  await pool.query(sql);
}

function discoverAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (parsed && typeof parsed === "object" && "DATABASE_ADMIN_URL" in parsed
          && typeof parsed.DATABASE_ADMIN_URL === "string") {
        candidate = parsed.DATABASE_ADMIN_URL;
      }
    }
    if (!candidate) return undefined;
    return assertWorkspacePostgresUrl(candidate, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReachWorkspace(databaseAdminUrl: string): Promise<boolean> {
  const pool = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    connectionTimeoutMillis: 1_500,
    max: 1,
  });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === WORKSPACE_PORT;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)) throw new Error("Invalid local database name");
  const url = new URL(databaseAdminUrl);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      || Number(url.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Legacy upgrade tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}
