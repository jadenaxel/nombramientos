import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Pool, PoolClient } from "pg";

export type MigrationScope = "control" | "tenant";

export interface MigrationRunOptions {
  readonly scope: MigrationScope;
  readonly directory?: string;
  readonly expectedPendingMigrations?: readonly MigrationPlanEntry[];
  /**
   * Optional NOLOGIN database-owner role used to own every object created by
   * tenant migrations. The administrative connection is retained only to
   * acquire the database-scoped advisory lock.
   */
  readonly executionRole?: string;
  /**
   * Installs narrowly scoped transaction-local evidence required by a specific
   * migration. It runs after BEGIN and SET ROLE, before the migration SQL.
   */
  readonly beforeMigration?: (
    client: PoolClient,
    migration: MigrationPlanEntry,
  ) => Promise<void>;
}

export interface MigrationPlanEntry {
  readonly name: string;
  readonly checksum: string;
}

export interface MigrationPlan {
  readonly scope: MigrationScope;
  readonly applied: readonly MigrationPlanEntry[];
  readonly pending: readonly MigrationPlanEntry[];
}

interface MigrationSource extends MigrationPlanEntry {
  readonly sql: string;
}

export async function inspectMigrationPlan(
  pool: Pool,
  options: Omit<MigrationRunOptions, "expectedPendingMigrations">,
): Promise<MigrationPlan> {
  const directory = options.directory ?? path.resolve(process.cwd(), "migrations", options.scope);
  const sources = await loadMigrationSources(directory);
  const client = await pool.connect();
  try {
    const migrationTable = await client.query<{ name: string | null }>(
      "SELECT to_regclass('public.schema_migrations')::text AS name",
    );
    if (migrationTable.rows[0]?.name !== "schema_migrations") {
      throw new Error("Migration preflight requires an existing schema_migrations table");
    }
    return await buildMigrationPlan(client, options.scope, sources);
  } finally {
    client.release();
  }
}

export async function loadMigrationPlanEntries(
  directory: string,
): Promise<readonly MigrationPlanEntry[]> {
  return (await loadMigrationSources(directory)).map(({ name, checksum }) => ({ name, checksum }));
}

export async function runMigrations(
  pool: Pool,
  options: MigrationRunOptions,
): Promise<readonly string[]> {
  const directory = options.directory ?? path.resolve(process.cwd(), "migrations", options.scope);
  const sources = await loadMigrationSources(directory);
  const client = await pool.connect();
  let lockAcquired = false;
  let executionRoleSet = false;
  try {
    await client.query("SELECT pg_advisory_lock(hashtextextended('nombramientos-schema-migrations:' || current_database(), 0))");
    lockAcquired = true;
    if (options.executionRole !== undefined) {
      assertSafeExecutionRole(options.executionRole);
      const formatted = await client.query<{ sql: string }>(
        "SELECT format('SET ROLE %I', $1::text) AS sql",
        [options.executionRole],
      );
      const sql = formatted.rows[0]?.sql;
      if (!sql) throw new Error("PostgreSQL did not format the migration execution role");
      await client.query(sql);
      executionRoleSet = true;
    }
    await ensureMigrationTable(client);
    const plan = await buildMigrationPlan(client, options.scope, sources);
    if (options.expectedPendingMigrations !== undefined) {
      if (!sameMigrationEntries(plan.pending, options.expectedPendingMigrations)) {
        throw new Error("Migration plan changed after preflight; refusing to apply it");
      }
    }
    const applied: string[] = [];
    const pending = new Set(plan.pending.map(({ name }) => name));
    for (const source of sources) {
      if (!pending.has(source.name)) continue;
      await client.query("BEGIN");
      try {
        await options.beforeMigration?.(client, { name: source.name, checksum: source.checksum });
        await client.query(source.sql);
        await client.query(
          "INSERT INTO schema_migrations(name, checksum) VALUES ($1, $2)",
          [source.name, source.checksum],
        );
        await client.query("COMMIT");
        applied.push(source.name);
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    }
    return applied;
  } finally {
    if (executionRoleSet) await client.query("RESET ROLE").catch(() => undefined);
    if (lockAcquired) {
      await client.query("SELECT pg_advisory_unlock(hashtextextended('nombramientos-schema-migrations:' || current_database(), 0))").catch(() => undefined);
    }
    client.release();
  }
}

function assertSafeExecutionRole(role: string): void {
  if (!/^nom_o_[0-9a-f]{32}$/u.test(role)) {
    throw new Error("Migration execution role must be a deterministic tenant owner role");
  }
}

async function loadMigrationSources(directory: string): Promise<readonly MigrationSource[]> {
  const files = (await readdir(directory))
    .filter((file) => /^\d+_.+\.sql$/.test(file))
    .sort((left, right) => left.localeCompare(right));
  return Promise.all(files.map(async (file) => {
    const sql = await readFile(path.join(directory, file), "utf8");
    return {
      name: file,
      sql,
      checksum: createHash("sha256").update(sql).digest("hex"),
    };
  }));
}

async function buildMigrationPlan(
  client: PoolClient,
  scope: MigrationScope,
  sources: readonly MigrationSource[],
): Promise<MigrationPlan> {
  const recorded = await client.query<{ name: string; checksum: string }>(
    "SELECT name,checksum FROM schema_migrations ORDER BY name",
  );
  const sourceNames = new Set(sources.map(({ name }) => name));
  const unexpected = recorded.rows.find(({ name }) => !sourceNames.has(name));
  if (unexpected) {
    throw new Error("Recorded migration is absent from source inventory");
  }
  const checksums = new Map(recorded.rows.map(({ name, checksum }) => [name, checksum]));
  const applied: MigrationPlanEntry[] = [];
  const pending: MigrationPlanEntry[] = [];
  for (const source of sources) {
    const previousChecksum = checksums.get(source.name);
    if (previousChecksum !== undefined) {
      if (previousChecksum !== source.checksum) {
        throw new Error(`Applied migration checksum differs: ${source.name}`);
      }
      applied.push({ name: source.name, checksum: source.checksum });
    } else {
      pending.push({ name: source.name, checksum: source.checksum });
    }
  }
  return { scope, applied, pending };
}

function sameMigrationEntries(left: readonly MigrationPlanEntry[], right: readonly MigrationPlanEntry[]): boolean {
  return left.length === right.length && left.every((value, index) => {
    const expected = right[index];
    return value.name === expected?.name && value.checksum === expected.checksum;
  });
}

async function ensureMigrationTable(client: PoolClient): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      checksum text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )
  `);
}
