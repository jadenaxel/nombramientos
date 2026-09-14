import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import {
  listTenantMaintenanceRoutes,
  resolveTenantMaintenanceRoute,
} from "../src/tenant-maintenance-policy.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const controlMigrations = path.join(packageRoot, "migrations", "control");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Pre-024 maintenance tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

live("tenant maintenance compatibility before control migration 024", () => {
  it("resolves a head-023 Demo route without inventing initial-admin authority", async () => {
    await withTemporaryControl(async (control) => {
      const tenantId = randomUUID();
      const grantorId = randomUUID();
      const invitationId = randomUUID();
      const suffix = tenantId.replaceAll("-", "");

      const schema = await control.query<{ authority_kind_columns: number }>(
        `SELECT count(*)::int AS authority_kind_columns
           FROM information_schema.columns
          WHERE table_schema='public'
            AND table_name='tenant_invitations'
            AND column_name='authority_kind'`,
      );
      expect(schema.rows).toEqual([{ authority_kind_columns: 0 }]);

      await control.query(
        `INSERT INTO tenants(
           id,slug,display_name,kind,status,timezone,locale,database_port,
           database_name,runtime_role,runtime_secret_ref,activated_at
         ) VALUES ($1,$2,'Pre-024 backup fixture','demo','active','America/La_Paz','es',
                   55432,$3,$4,$5,clock_timestamp())`,
        [
          tenantId,
          `pre024-${randomBytes(5).toString("hex")}`,
          `nom_t_${suffix}`,
          `nom_r_${suffix}`,
          `tenant-db/${tenantId}/runtime/v1`,
        ],
      );
      await control.query(
        `INSERT INTO platform_identities(
           id,email,normalized_email,display_name,password_hash,password_provisioned,status
         ) VALUES (
           $1,'legacy-grantor@invalid.example','legacy-grantor@invalid.example',
           'Legacy grantor',
           '$argon2id$v=19$m=65536,t=3,p=1$BlX3TtC3KRRD8kjGx9PwxQ$BRboo0FP4y3RHcgkaHeHuBjXcmcJayVDIp/Qp4qMCIY',
           false,'active'
         )`,
        [grantorId],
      );
      // Before 024, CHURCH_ADMIN was only a role request. It is not durable
      // evidence that this is the unique initial-administrator authority.
      await control.query(
        `INSERT INTO tenant_invitations(
           id,tenant_id,email,normalized_email,role_codes,token_hash,status,
           idempotency_key,request_hash,created_by_identity_id,expires_at
         ) VALUES (
           $1,$2,'legacy-recipient@invalid.example','legacy-recipient@invalid.example',
           ARRAY['CHURCH_ADMIN']::text[],$3,'pending',$4,$5,$6,
           clock_timestamp()+interval '1 hour'
         )`,
        [
          invitationId,
          tenantId,
          randomBytes(32).toString("hex"),
          randomUUID(),
          randomBytes(32).toString("hex"),
          grantorId,
        ],
      );

      await expect(resolveTenantMaintenanceRoute(control, tenantId)).resolves.toMatchObject({
        id: tenantId,
        kind: "demo",
        status: "active",
        maintenanceClass: "routable",
      });
      const listed = await listTenantMaintenanceRoutes(control);
      expect(listed).toHaveLength(1);
      expect(listed[0]).toMatchObject({ id: tenantId, maintenanceClass: "routable" });
    });
  }, 180_000);
});

async function withTemporaryControl(run: (control: Pool) => Promise<void>): Promise<void> {
  if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
  const databaseName = `nom_maintenance_pre024_${randomBytes(8).toString("hex")}`;
  const cluster = new Pool({
    connectionString: databaseUrl(adminUrl, "postgres"),
    application_name: "nombramientos-maintenance-pre024-cluster",
    max: 1,
  });
  const control = new Pool({ connectionString: databaseUrl(adminUrl, databaseName), max: 2 });
  await runWithCleanup(async () => {
    await createDatabase(cluster, databaseName);
    await control.query(`
      CREATE TABLE schema_migrations (
        name text PRIMARY KEY,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
      )
    `);
    await applyMigrationsThrough(control, 23);
    await run(control);
  }, () => cleanupMaintenanceDatabase(cluster, control, databaseName), "Pre-024 maintenance live case");
}

async function applyMigrationsThrough(database: Pool, maximumMigration: number): Promise<void> {
  const migrations = readdirSync(controlMigrations)
    .filter((file) => /^\d+_.+\.sql$/u.test(file) && Number(file.slice(0, 3)) <= maximumMigration)
    .sort((left, right) => left.localeCompare(right));
  for (const migration of migrations) {
    const sql = readFileSync(path.join(controlMigrations, migration), "utf8");
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

async function cleanupMaintenanceDatabase(cluster: Pool, control: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [control], assertSafeDatabaseName: assertMaintenanceDatabaseName }],
    label: "Temporary pre-024 maintenance database",
  });
}

function assertMaintenanceDatabaseName(databaseName: string): void {
  if (!/^nom_maintenance_pre024_[0-9a-f]{16}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-maintenance compatibility test database");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the maintenance test statement");
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
    throw new Error("Maintenance compatibility tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}
