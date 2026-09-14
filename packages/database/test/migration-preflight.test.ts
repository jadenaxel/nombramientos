import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import { runMigrations } from "../src/migrations.js";

describe("migration preflight", () => {
  it("rejects a recorded migration absent from source before applying pending SQL", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "nom-migration-inventory-"));
    const mutatingSql = "SELECT 'must stay pending';";
    try {
      await writeFile(path.join(directory, "001_pending.sql"), mutatingSql, "utf8");
      const harness = migrationPool([{ name: "999_rogue.sql", checksum: "0".repeat(64) }]);
      await expect(runMigrations(harness.pool, { scope: "tenant", directory }))
        .rejects.toThrow(/absent from source inventory/u);
      expect(harness.sql).not.toContain(mutatingSql);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("validates every recorded checksum before applying an earlier pending migration", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "nom-migration-preflight-"));
    const mutatingSql = "SELECT 'would mutate';";
    try {
      await writeFile(path.join(directory, "001_pending.sql"), mutatingSql, "utf8");
      await writeFile(path.join(directory, "002_recorded.sql"), "SELECT 'recorded';", "utf8");
      const harness = migrationPool([{ name: "002_recorded.sql", checksum: "0".repeat(64) }]);
      await expect(runMigrations(harness.pool, { scope: "tenant", directory }))
        .rejects.toThrow(/checksum differs: 002_recorded\.sql/u);
      expect(harness.sql).not.toContain(mutatingSql);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("binds execution to the exact names and checksums accepted during preflight", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "nom-migration-plan-"));
    const mutatingSql = "SELECT 'approved mutation';";
    try {
      await writeFile(path.join(directory, "024_irreversible.sql"), mutatingSql, "utf8");
      const harness = migrationPool([]);
      const actualChecksum = createHash("sha256").update(mutatingSql).digest("hex");
      const wrongChecksum = `${actualChecksum.slice(0, -1)}${actualChecksum.endsWith("0") ? "1" : "0"}`;
      await expect(runMigrations(harness.pool, {
        scope: "tenant",
        directory,
        expectedPendingMigrations: [{ name: "024_irreversible.sql", checksum: wrongChecksum }],
      })).rejects.toThrow(/plan changed after preflight/u);
      expect(harness.sql).not.toContain(mutatingSql);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("runs tenant object creation under the deterministic NOLOGIN owner and resets before unlocking", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "nom-migration-owner-"));
    try {
      await writeFile(path.join(directory, "001_owned.sql"), "CREATE TABLE owned_by_tenant(id integer);", "utf8");
      const harness = migrationPool([]);
      await runMigrations(harness.pool, {
        scope: "tenant",
        directory,
        executionRole: "nom_o_0123456789abcdef0123456789abcdef",
      });
      const setRoleFormat = harness.sql.indexOf("SELECT format('SET ROLE %I', $1::text) AS sql");
      const migration = harness.sql.indexOf("CREATE TABLE owned_by_tenant(id integer);");
      const reset = harness.sql.indexOf("RESET ROLE");
      const unlock = harness.sql.findIndex((statement) => statement.includes("pg_advisory_unlock"));
      expect(setRoleFormat).toBeGreaterThan(-1);
      expect(migration).toBeGreaterThan(setRoleFormat);
      expect(reset).toBeGreaterThan(migration);
      expect(unlock).toBeGreaterThan(reset);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("installs migration-specific evidence inside the same transaction before SQL", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "nom-migration-evidence-"));
    const migrationSql = "SELECT 'uses transaction-local evidence';";
    try {
      await writeFile(path.join(directory, "036_evidence.sql"), migrationSql, "utf8");
      const harness = migrationPool([]);
      await runMigrations(harness.pool, {
        scope: "tenant",
        directory,
        beforeMigration: async (client, migration) => {
          expect(migration.name).toBe("036_evidence.sql");
          await client.query("CREATE TEMP TABLE exact_evidence(id integer) ON COMMIT DROP");
        },
      });
      const begin = harness.sql.indexOf("BEGIN");
      const evidence = harness.sql.indexOf("CREATE TEMP TABLE exact_evidence(id integer) ON COMMIT DROP");
      const migration = harness.sql.indexOf(migrationSql);
      const commit = harness.sql.indexOf("COMMIT");
      expect(begin).toBeGreaterThan(-1);
      expect(evidence).toBeGreaterThan(begin);
      expect(migration).toBeGreaterThan(evidence);
      expect(commit).toBeGreaterThan(migration);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects an arbitrary migration execution role before any DDL", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "nom-migration-role-reject-"));
    try {
      const mutatingSql = "SELECT 'must not run';";
      await writeFile(path.join(directory, "001_owned.sql"), mutatingSql, "utf8");
      const harness = migrationPool([]);
      await expect(runMigrations(harness.pool, {
        scope: "tenant",
        directory,
        executionRole: "nom_admin; DROP DATABASE anything",
      })).rejects.toThrow(/deterministic tenant owner role/u);
      expect(harness.sql).not.toContain(mutatingSql);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

function migrationPool(recorded: readonly { readonly name: string; readonly checksum: string }[]): {
  readonly pool: Pool;
  readonly sql: string[];
} {
  const sql: string[] = [];
  const client = {
    query: vi.fn(async (statement: string) => {
      sql.push(statement);
      if (statement === "SELECT format('SET ROLE %I', $1::text) AS sql") {
        return { rows: [{ sql: "SET ROLE nom_o_0123456789abcdef0123456789abcdef" }], rowCount: 1 };
      }
      return statement.includes("SELECT name,checksum FROM schema_migrations")
        ? { rows: [...recorded], rowCount: recorded.length }
        : { rows: [], rowCount: 0 };
    }),
    release: vi.fn(),
  };
  return {
    pool: { connect: vi.fn(async () => client) } as unknown as Pool,
    sql,
  };
}
