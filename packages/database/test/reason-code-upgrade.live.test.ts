import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDirectory = path.join(packageRoot, "migrations", "tenant");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Reason-code upgrade tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

live("tenant reason-code migration upgrade", () => {
  it("upgrades a post-023 schema with the exact internal pair and validates the replacement constraint", async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    const databaseName = `nom_reason_upgrade_${randomBytes(12).toString("hex")}`;
    const cluster = new Pool({
      connectionString: databaseUrl(adminUrl, "postgres"),
      application_name: "nombramientos-reason-upgrade-cluster",
      max: 1,
    });
    const tenant = new Pool({
      connectionString: databaseUrl(adminUrl, databaseName),
      application_name: "nombramientos-reason-upgrade-tenant",
      max: 1,
    });

    await runWithCleanup(async () => {
      await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [databaseName]);
      const post023Migrations = readdirSync(migrationsDirectory)
        .filter((file) => /^\d+_.+\.sql$/u.test(file) && Number(file.slice(0, 3)) <= 23)
        .sort((left, right) => left.localeCompare(right));
      expect(post023Migrations.at(-1)).toBe("023_non_sensitive_reason_codes.sql");
      await tenant.query(`
        CREATE TABLE schema_migrations (
          name text PRIMARY KEY,
          checksum text NOT NULL,
          applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
        )
      `);
      for (const migration of post023Migrations) {
        const sql = readFileSync(path.join(migrationsDirectory, migration), "utf8");
        await tenant.query(sql);
        await tenant.query(
          "INSERT INTO schema_migrations(name,checksum) VALUES ($1,$2)",
          [migration, createHash("sha256").update(sql).digest("hex")],
        );
      }

      const before = await readConstraint(tenant);
      expect(before).toMatchObject({ convalidated: false });
      expect(before.definition).not.toContain("FINAL_LIST_CONFIRMED");

      await tenant.query(readFileSync(path.join(migrationsDirectory, "026_candidacy_review_internal_reason_code.sql"), "utf8"));

      const after = await readConstraint(tenant);
      expect(after).toMatchObject({ convalidated: true });
      expect(after.definition).toContain("CONFIRMED_FOR_BALLOT");
      expect(after.definition).toContain("FINAL_LIST_CONFIRMED");
      expect(after.definition.match(/FINAL_LIST_CONFIRMED/gu)).toHaveLength(1);
    }, () => cleanupReasonDatabase(cluster, tenant, databaseName), "Reason-code upgrade live case");
  }, 120_000);
});

async function readConstraint(pool: Pool): Promise<{ convalidated: boolean; definition: string }> {
  const result = await pool.query<{ convalidated: boolean; definition: string }>(
    `SELECT convalidated,pg_get_constraintdef(oid) AS definition
       FROM pg_constraint
      WHERE conrelid='candidacy_reviews'::regclass
        AND conname='candidacy_reviews_reason_code_allowed'`,
  );
  const row = result.rows[0];
  if (!row) throw new Error("Candidacy reason-code constraint is unavailable");
  return row;
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the reason-code test statement");
  await pool.query(sql);
}

async function cleanupReasonDatabase(cluster: Pool, tenant: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [tenant], assertSafeDatabaseName: assertReasonDatabaseName }],
    label: "Temporary reason-code upgrade database",
  });
}

function assertReasonDatabaseName(databaseName: string): void {
  if (!/^nom_reason_upgrade_[0-9a-f]{24}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-reason-upgrade test database");
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
  const pool = new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), connectionTimeoutMillis: 1_500, max: 1 });
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
  if (!isLoopback(url.hostname) || Number(url.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Reason-code upgrade tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}
