import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDirectory = path.join(packageRoot, "migrations", "control");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Invitation reconciliation tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

live("durable invitation reconciliation lease", () => {
  it("rejects a historical accepting row before migration 024 can mutate its schema or tuple", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 23);
      const tenantId = randomUUID();
      const grantorId = randomUUID();
      const recipientId = randomUUID();
      const invitationId = randomUUID();
      await database.query(
        `INSERT INTO tenants(
           id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,
           runtime_secret_ref,database_port,activated_at
         ) VALUES ($1,$2,'Legacy accepting fixture','real','active','America/La_Paz','es',
                   $3,$4,$5,55432,clock_timestamp())`,
        [
          tenantId,
          `legacy-${randomBytes(4).toString("hex")}`,
          `nom_legacy_target_${randomBytes(4).toString("hex")}`,
          `nom_legacy_role_${randomBytes(4).toString("hex")}`,
          `tenant-db/${tenantId}/runtime/v1`,
        ],
      );
      await database.query(
        `INSERT INTO platform_identities(id,email,normalized_email,display_name,password_hash,status)
         VALUES
           ($1,'legacy-grantor@invalid.example','legacy-grantor@invalid.example','Legacy grantor','disabled','active'),
           ($2,'legacy-recipient@invalid.example','legacy-recipient@invalid.example','Legacy recipient','disabled','active')`,
        [grantorId, recipientId],
      );
      await database.query(
        `INSERT INTO tenant_invitations(
           id,tenant_id,email,normalized_email,role_codes,token_hash,status,
           idempotency_key,request_hash,created_by_identity_id,expires_at,
           acceptance_id,acceptance_identity_id,acceptance_started_at
         ) VALUES (
           $1,$2,'legacy-recipient@invalid.example','legacy-recipient@invalid.example',
           ARRAY['AUDITOR']::text[],$3,'accepting',$4,$5,$6,
           clock_timestamp()+interval '1 hour',$7,$8,clock_timestamp()-interval '20 minutes'
         )`,
        [
          invitationId,
          tenantId,
          randomBytes(32).toString("hex"),
          randomUUID(),
          randomBytes(32).toString("hex"),
          grantorId,
          randomUUID(),
          recipientId,
        ],
      );

      const migration = readFileSync(
        path.join(migrationsDirectory, "024_invitation_grantor_revocation_boundary.sql"),
        "utf8",
      );
      const client = await database.connect();
      try {
        await client.query("BEGIN");
        await expect(client.query(migration)).rejects.toMatchObject({
          constraint: "legacy_invitation_acceptance_reconciliation_required",
          code: "23514",
        });
        await client.query("ROLLBACK");
      } finally {
        client.release();
      }
      const unchanged = await database.query<{ status: string; authority_column_count: number }>(
        `SELECT invitation.status,
                (SELECT count(*)::int FROM information_schema.columns
                  WHERE table_schema='public' AND table_name='tenant_invitations'
                    AND column_name='authority_kind') AS authority_column_count
           FROM tenant_invitations invitation
          WHERE invitation.id=$1`,
        [invitationId],
      );
      expect(unchanged.rows).toEqual([{ status: "accepting", authority_column_count: 0 }]);
    });
  }, 120_000);

  it("backs off a poison row, advances another row, and reclaims only an expired crashed-worker lease", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 24);
      const tenantId = randomUUID();
      const grantorId = randomUUID();
      await database.query(
        `INSERT INTO tenants(
           id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,
           runtime_secret_ref,database_port,activated_at
         ) VALUES ($1,$2,'Reconciliation fixture','real','active','America/La_Paz','es',
                   $3,$4,$5,55432,clock_timestamp())`,
        [
          tenantId,
          `reconcile-${randomBytes(4).toString("hex")}`,
          `nom_reconcile_target_${randomBytes(4).toString("hex")}`,
          `nom_reconcile_role_${randomBytes(4).toString("hex")}`,
          `tenant-db/${tenantId}/runtime/v1`,
        ],
      );
      await database.query(
        `INSERT INTO platform_identities(id,email,normalized_email,display_name,password_hash,status)
         VALUES ($1,'grantor@invalid.example','grantor@invalid.example','Grantor','disabled','active')`,
        [grantorId],
      );
      await database.query(
        "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
        [tenantId, grantorId],
      );

      const fixtures = await Promise.all([30, 20, 10].map(async (minutes, index) => {
        const invitationId = randomUUID();
        const acceptanceId = randomUUID();
        const identityId = randomUUID();
        await database.query(
          `INSERT INTO platform_identities(id,email,normalized_email,display_name,password_hash,status)
           VALUES ($1,$2,$2,$3,'disabled','active')`,
          [identityId, `recipient-${index}@invalid.example`, `Recipient ${index}`],
        );
        await database.query(
          `INSERT INTO tenant_invitations(
             id,tenant_id,email,normalized_email,role_codes,token_hash,status,
             idempotency_key,request_hash,created_by_identity_id,expires_at,
             acceptance_id,acceptance_identity_id,acceptance_started_at,revoked_at,
             authority_kind,authority_epoch,acceptance_attempt
           ) VALUES (
             $1,$2,$3,$3,ARRAY['AUDITOR']::text[],$4,'revoked',$5,$6,$7,
             clock_timestamp()+interval '1 hour',$8,$9,
             clock_timestamp()-make_interval(mins => $10),clock_timestamp(),
             'tenant_delegate',0,1
           )`,
          [
            invitationId,
            tenantId,
            `recipient-${index}@invalid.example`,
            randomBytes(32).toString("hex"),
            randomUUID(),
            randomBytes(32).toString("hex"),
            grantorId,
            acceptanceId,
            identityId,
            minutes,
          ],
        );
        return { invitationId, acceptanceId, identityId };
      }));

      const poisonLease = randomUUID();
      const poison = await claim(database, poisonLease);
      expect(poison?.id).toBe(fixtures[0]!.invitationId);
      await expect(finish(database, poison!, poisonLease, false)).resolves.toBe(true);
      const poisonState = await database.query<{
        reconciliation_next_attempt_at: Date | null;
        reconciliation_last_error_code: string | null;
      }>(
        `SELECT reconciliation_next_attempt_at,reconciliation_last_error_code
           FROM tenant_invitations WHERE id=$1`,
        [fixtures[0]!.invitationId],
      );
      expect(poisonState.rows[0]?.reconciliation_next_attempt_at).toBeInstanceOf(Date);
      expect(poisonState.rows[0]?.reconciliation_last_error_code).toBe("TEST_POISON_ROW");

      const healthyLease = randomUUID();
      const healthy = await claim(database, healthyLease);
      expect(healthy?.id).toBe(fixtures[1]!.invitationId);
      await expect(finish(database, healthy!, healthyLease, true)).resolves.toBe(true);
      await expect(database.query(
        "SELECT mark_tenant_invitation_cleanup_completed($1,$2,$3,$4)",
        [healthy!.id, healthy!.acceptance_id, healthy!.acceptance_identity_id, healthy!.acceptance_attempt],
      )).resolves.toMatchObject({ rowCount: 1 });

      const crashedLease = randomUUID();
      const crashed = await claim(database, crashedLease);
      expect(crashed?.id).toBe(fixtures[2]!.invitationId);
      expect(await claim(database, randomUUID())).toBeNull();

      // Simulate elapsed wall time in this UUID-only ephemeral database. The
      // replica mode bypasses only the state-machine trigger; the lease CHECK
      // remains active and the row still has a well-formed historical lease.
      await database.query("SET session_replication_role='replica'");
      try {
        await database.query(
          `UPDATE tenant_invitations
              SET reconciliation_claimed_at=clock_timestamp()-interval '6 minutes',
                  reconciliation_lease_expires_at=clock_timestamp()-interval '1 minute'
            WHERE id=$1`,
          [crashed!.id],
        );
      } finally {
        await database.query("SET session_replication_role='origin'");
      }

      const reclaimedLease = randomUUID();
      const reclaimed = await claim(database, reclaimedLease);
      expect(reclaimed).toMatchObject({
        id: crashed!.id,
        acceptance_id: crashed!.acceptance_id,
        acceptance_identity_id: crashed!.acceptance_identity_id,
        acceptance_attempt: crashed!.acceptance_attempt,
        reconciliation_attempt_count: crashed!.reconciliation_attempt_count + 1,
      });
      await expect(finish(database, crashed!, crashedLease, true)).resolves.toBe(false);
      await expect(finish(database, reclaimed!, reclaimedLease, true)).resolves.toBe(true);
    });
  }, 120_000);
});

interface ClaimedRow {
  readonly id: string;
  readonly acceptance_id: string;
  readonly acceptance_identity_id: string;
  readonly acceptance_attempt: number;
  readonly reconciliation_attempt_count: number;
}

async function claim(database: Pool, leaseToken: string): Promise<ClaimedRow | null> {
  const result = await database.query<ClaimedRow>(
    "SELECT * FROM claim_tenant_invitation_reconciliation($1)",
    [leaseToken],
  );
  return result.rows[0] ?? null;
}

async function finish(
  database: Pool,
  row: ClaimedRow,
  leaseToken: string,
  succeeded: boolean,
): Promise<boolean> {
  const result = await database.query<{ finished: boolean }>(
    "SELECT finish_tenant_invitation_reconciliation($1,$2,$3,$4,$5,$6,$7) AS finished",
    [
      row.id,
      row.acceptance_id,
      row.acceptance_identity_id,
      row.acceptance_attempt,
      leaseToken,
      succeeded,
      succeeded ? null : "TEST_POISON_ROW",
    ],
  );
  return result.rows[0]?.finished === true;
}

async function withTemporaryDatabase(run: (database: Pool) => Promise<void>): Promise<void> {
  if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
  const databaseName = `nom_inv_reconcile_${randomBytes(10).toString("hex")}`;
  const cluster = new Pool({
    connectionString: databaseUrl(adminUrl, "postgres"),
    application_name: "nombramientos-invitation-reconciliation-cluster",
    max: 1,
  });
  const database = new Pool({
    connectionString: databaseUrl(adminUrl, databaseName),
    application_name: "nombramientos-invitation-reconciliation-database",
    max: 2,
  });
  await runWithCleanup(async () => {
    await executeFormatted(
      cluster,
      "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
      [databaseName],
    );
    await run(database);
  }, () => cleanupInvitationReconciliationDatabase(cluster, database, databaseName), "Invitation reconciliation live case");
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

async function applyMigrationsThrough(database: Pool, maximumMigration: number): Promise<void> {
  const migrations = readdirSync(migrationsDirectory)
    .filter((file) => /^\d+_.+\.sql$/u.test(file) && Number(file.slice(0, 3)) <= maximumMigration)
    .sort((left, right) => left.localeCompare(right));
  for (const migration of migrations) {
    const sql = readFileSync(path.join(migrationsDirectory, migration), "utf8");
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

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the reconciliation test statement");
  await pool.query(sql);
}

async function cleanupInvitationReconciliationDatabase(cluster: Pool, database: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [database], assertSafeDatabaseName: assertInvitationReconciliationDatabaseName }],
    label: "Temporary invitation-reconciliation database",
  });
}

function assertInvitationReconciliationDatabaseName(databaseName: string): void {
  if (!/^nom_inv_reconcile_[0-9a-f]{20}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-reconciliation test database");
  }
}

function discoverAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (parsed && typeof parsed === "object" && "DATABASE_ADMIN_URL" in parsed && typeof parsed.DATABASE_ADMIN_URL === "string") {
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
  if (!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
      || Number(url.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Invitation reconciliation tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}
