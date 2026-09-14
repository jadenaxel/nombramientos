import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { catalogPackage2025, validateCatalogPackage } from "@nombramientos/catalog";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import {
  readTenantCatalogEvidence,
  reconcileTenantCatalog,
  tenantCatalogTarget,
  type CatalogReadQueryClient,
} from "../src/catalog-reconciliation.js";
import { runMigrations } from "../src/migrations.js";
import { TENANT_OPERATIONAL_TABLES } from "../src/tenant-maintenance-policy.js";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Catalog reconciliation tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

live("versioned catalog reconciliation in an ephemeral tenant", () => {
  it("upgrades safely, preserves identities/FKs/data, is idempotent, detects drift, and rolls back ambiguity", async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    expect(validateCatalogPackage(catalogPackage2025)).toEqual([]);
    const target = tenantCatalogTarget(catalogPackage2025);
    const databaseName = `nom_catalog_reconcile_${randomBytes(12).toString("hex")}`;
    const cluster = new Pool({
      connectionString: databaseUrl(adminUrl, "postgres"),
      application_name: "nombramientos-catalog-reconcile-cluster",
      max: 1,
    });
    const tenant = new Pool({
      connectionString: databaseUrl(adminUrl, databaseName),
      application_name: "nombramientos-catalog-reconcile-tenant",
      max: 1,
    });

    await runWithCleanup(async () => {
      await executeFormatted(
        cluster,
        "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
        [databaseName],
      );
      await runMigrations(tenant, {
        scope: "tenant",
        directory: path.join(packageRoot, "migrations", "tenant"),
      });

      const tenantId = randomUUID();
      const canonicalDepartmentId = randomUUID();
      const canonicalOfficeId = randomUUID();
      const localDepartmentId = randomUUID();
      const localOfficeId = randomUUID();
      const collisionDepartmentId = randomUUID();
      const roleId = randomUUID();
      const identityId = randomUUID();
      const cycleId = randomUUID();
      const vacancyId = randomUUID();
      const office = catalogPackage2025.offices[0]!;
      const department = catalogPackage2025.departments.find(
        ({ canonicalCode }) => canonicalCode === office.departmentCode,
      );
      const collisionDepartment = catalogPackage2025.departments.find(
        ({ canonicalCode }) => canonicalCode !== department?.canonicalCode,
      );
      if (!department || !collisionDepartment) throw new Error("Catalog test requires at least two departments");

      await tenant.query(
        `INSERT INTO tenant_settings(
           tenant_id,display_name,kind,timezone,locale,setup_state,catalog_version
         ) VALUES ($1,'Catalog reconciliation scratch','real','America/Santo_Domingo','es','ready','legacy-v0')`,
        [tenantId],
      );
      await tenant.query(
        `INSERT INTO departments(
           id,canonical_code,names,local_extension,catalog_metadata,active,sort_order,version
         ) VALUES ($1,$2,$3,false,$4,false,999,7)`,
        [canonicalDepartmentId, department.canonicalCode, { es: "Anterior", en: "Legacy", fr: "Ancien" }, { legacy: true }],
      );
      await tenant.query(
        `INSERT INTO offices(
           id,department_id,canonical_code,names,appointment_mechanism,cardinality,
           local_extension,catalog_metadata,active,version
         ) VALUES ($1,$2,$3,$4,'local_configuration_pending',9,false,$5,false,11)`,
        [canonicalOfficeId, canonicalDepartmentId, office.canonicalCode, { es: "Anterior", en: "Legacy", fr: "Ancien" }, { legacy: true }],
      );
      await tenant.query(
        `INSERT INTO departments(
           id,canonical_code,names,local_extension,catalog_metadata,active,sort_order,version
         ) VALUES ($1,'local_preserved',$2,true,$3,true,700,4)`,
        [localDepartmentId, { es: "Local", en: "Local", fr: "Local" }, { tenantOwned: true }],
      );
      await tenant.query(
        `INSERT INTO offices(
           id,department_id,canonical_code,names,appointment_mechanism,cardinality,
           local_extension,catalog_metadata,active,version
         ) VALUES ($1,$2,'local_preserved_office',$3,'board_appointment',2,true,$4,true,5)`,
        [localOfficeId, localDepartmentId, { es: "Local", en: "Local", fr: "Local" }, { tenantOwned: true }],
      );
      await tenant.query(
        `INSERT INTO roles(id,code,name_i18n,system_role)
         VALUES ($1,'LOCAL_CATALOG_SENTINEL',$2,false)`,
        [roleId, { es: "Centinela", en: "Sentinel", fr: "Sentinelle" }],
      );
      await tenant.query(
        "INSERT INTO role_bindings(identity_id,role_id) VALUES ($1,$2)",
        [identityId, roleId],
      );
      await tenant.query(
        `INSERT INTO election_cycles(
           id,name,status,locale,timezone,term_start,term_end,normative_version,created_by_identity_id
         ) VALUES ($1,'Catalog FK sentinel','draft','es','America/Santo_Domingo','2044-01-01','2044-12-31','legacy-v0',$2)`,
        [cycleId, identityId],
      );
      await tenant.query(
        "INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status) VALUES ($1,$2,$3,1,'pending')",
        [vacancyId, cycleId, canonicalOfficeId],
      );

      const protectedBefore = await protectedSnapshot(tenant, {
        localDepartmentId,
        localOfficeId,
        roleId,
        identityId,
        cycleId,
        vacancyId,
      });
      expect(protectedBefore.operationalRowCount).toBe(3);

      // A tenant-owned extension may never be silently converted into a
      // canonical row. The early failure must leave even stale standard rows
      // and tenant settings untouched.
      await tenant.query(
        `INSERT INTO departments(
           id,canonical_code,names,local_extension,catalog_metadata,active,sort_order,version
         ) VALUES ($1,$2,$3,true,'{}'::jsonb,true,701,1)`,
        [collisionDepartmentId, collisionDepartment.canonicalCode, { es: "Colisión", en: "Collision", fr: "Collision" }],
      );
      await expect(reconcileTenantCatalog(tenant, catalogPackage2025)).rejects.toThrow(/not safely reconcilable/u);
      expect(await tenant.query(
        "SELECT catalog_version FROM tenant_settings WHERE singleton=true",
      )).toMatchObject({ rows: [{ catalog_version: "legacy-v0" }] });
      expect(await tenant.query(
        "SELECT catalog_metadata,version FROM departments WHERE id=$1",
        [canonicalDepartmentId],
      )).toMatchObject({ rows: [{ catalog_metadata: { legacy: true }, version: 7 }] });
      await tenant.query("DELETE FROM departments WHERE id=$1", [collisionDepartmentId]);

      const upgraded = await reconcileTenantCatalog(tenant, catalogPackage2025);
      expect(upgraded).toMatchObject({
        changed: true,
        mismatchCount: 0,
        targetVersion: target.version,
        expectedDepartmentCount: target.departmentCount,
        observedDepartmentCount: target.departmentCount,
        expectedOfficeCount: target.officeCount,
        observedOfficeCount: target.officeCount,
        targetCatalogSha256: target.catalogSha256,
        observedCatalogSha256: target.catalogSha256,
      });
      expect(upgraded.mutationCount).toBeGreaterThan(0);

      const canonicalIds = await tenant.query<{ department_id: string; office_id: string }>(
        `SELECT department.id::text AS department_id,office.id::text AS office_id
           FROM departments department
           JOIN offices office ON office.department_id=department.id
          WHERE department.canonical_code=$1 AND office.canonical_code=$2`,
        [department.canonicalCode, office.canonicalCode],
      );
      expect(canonicalIds.rows[0]).toEqual({
        department_id: canonicalDepartmentId,
        office_id: canonicalOfficeId,
      });
      const vacancyReference = await tenant.query<{ office_id: string }>(
        "SELECT office_id::text FROM vacancies WHERE id=$1",
        [vacancyId],
      );
      expect(vacancyReference.rows[0]?.office_id).toBe(canonicalOfficeId);
      expect(await protectedSnapshot(tenant, {
        localDepartmentId,
        localOfficeId,
        roleId,
        identityId,
        cycleId,
        vacancyId,
      })).toEqual(protectedBefore);

      const canonicalAfterUpgrade = await canonicalMutationSnapshot(tenant);
      const settingsAfterUpgrade = await tenant.query(
        "SELECT catalog_version,version,updated_at FROM tenant_settings WHERE singleton=true",
      );
      const replay = await reconcileTenantCatalog(tenant, catalogPackage2025);
      expect(replay).toMatchObject({ changed: false, mutationCount: 0, mismatchCount: 0 });
      expect(await canonicalMutationSnapshot(tenant)).toEqual(canonicalAfterUpgrade);
      expect(await tenant.query(
        "SELECT catalog_version,version,updated_at FROM tenant_settings WHERE singleton=true",
      )).toEqual(settingsAfterUpgrade);

      // Unexpected standard material is not retired destructively. A repair
      // attempted in the same transaction must roll back until the ambiguity
      // is resolved explicitly.
      await tenant.query(
        `INSERT INTO departments(canonical_code,names,local_extension,catalog_metadata,active,sort_order,version)
         VALUES ('rogue_standard',$1,false,'{}'::jsonb,true,9999,1)`,
        [{ es: "Ajeno", en: "Rogue", fr: "Inattendu" }],
      );
      await tenant.query(
        "UPDATE offices SET appointment_mechanism='tampered_mechanism' WHERE id=$1",
        [canonicalOfficeId],
      );
      await expect(reconcileTenantCatalog(tenant, catalogPackage2025)).rejects.toThrow(/not safely reconcilable/u);
      expect((await tenant.query<{ appointment_mechanism: string }>(
        "SELECT appointment_mechanism FROM offices WHERE id=$1",
        [canonicalOfficeId],
      )).rows[0]?.appointment_mechanism).toBe("tampered_mechanism");
      expect((await tenant.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM departments WHERE canonical_code='rogue_standard'",
      )).rows[0]?.count).toBe(1);

      await tenant.query("DELETE FROM departments WHERE canonical_code='rogue_standard'");
      const drift = await readTenantCatalogEvidence(catalogReader(tenant), catalogPackage2025);
      expect(drift.mismatchCount).toBeGreaterThan(0);
      expect(drift.observedCatalogSha256).not.toBe(drift.targetCatalogSha256);
      const repaired = await reconcileTenantCatalog(tenant, catalogPackage2025);
      expect(repaired).toMatchObject({ changed: true, mismatchCount: 0 });
      expect((await tenant.query<{ id: string }>(
        "SELECT id::text FROM offices WHERE canonical_code=$1",
        [office.canonicalCode],
      )).rows[0]?.id).toBe(canonicalOfficeId);
      expect(await protectedSnapshot(tenant, {
        localDepartmentId,
        localOfficeId,
        roleId,
        identityId,
        cycleId,
        vacancyId,
      })).toEqual(protectedBefore);
      expect((await readTenantCatalogEvidence(catalogReader(tenant), catalogPackage2025)).mismatchCount).toBe(0);
    }, () => cleanupCatalogDatabase(cluster, tenant, databaseName), "Catalog-reconciliation live case");
  }, 120_000);

  it("leaves no catalog-reconciliation database behind", async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    const cluster = new Pool({
      connectionString: databaseUrl(adminUrl, "postgres"),
      application_name: "nombramientos-catalog-reconcile-residue-check",
      max: 1,
    });
    try {
      const residue = await cluster.query<{ database_name: string }>(
        `SELECT datname AS database_name
           FROM pg_catalog.pg_database
          WHERE datname LIKE 'nom_catalog_reconcile\\_%' ESCAPE '\\'
          ORDER BY datname`,
      );
      expect(residue.rows).toEqual([]);
    } finally {
      await cluster.end();
    }
  });
});

async function protectedSnapshot(
  pool: Pool,
  ids: {
    readonly localDepartmentId: string;
    readonly localOfficeId: string;
    readonly roleId: string;
    readonly identityId: string;
    readonly cycleId: string;
    readonly vacancyId: string;
  },
): Promise<{
  readonly configuration: readonly unknown[];
  readonly operationalCounts: Readonly<Record<string, number>>;
  readonly operationalRowCount: number;
}> {
  const configuration = await pool.query<{ value: unknown }>(
    `SELECT value FROM (
       SELECT 1 AS ordinal,to_jsonb(department) AS value FROM departments department WHERE id=$1
       UNION ALL
       SELECT 2,to_jsonb(office) FROM offices office WHERE id=$2
       UNION ALL
       SELECT 3,to_jsonb(role_record) FROM roles role_record WHERE id=$3
       UNION ALL
       SELECT 4,to_jsonb(binding) FROM role_bindings binding WHERE identity_id=$4 AND role_id=$3
       UNION ALL
       SELECT 5,to_jsonb(cycle) FROM election_cycles cycle WHERE id=$5
       UNION ALL
       SELECT 6,to_jsonb(vacancy) FROM vacancies vacancy WHERE id=$6
     ) protected ORDER BY ordinal`,
    [ids.localDepartmentId, ids.localOfficeId, ids.roleId, ids.identityId, ids.cycleId, ids.vacancyId],
  );
  const operationalCounts: Record<string, number> = {};
  for (const table of TENANT_OPERATIONAL_TABLES) {
    const count = await pool.query<{ count: number }>(`SELECT count(*)::int AS count FROM ${table}`);
    operationalCounts[table] = count.rows[0]?.count ?? -1;
  }
  return {
    configuration: configuration.rows.map(({ value }) => value),
    operationalCounts,
    operationalRowCount: Object.values(operationalCounts).reduce((total, count) => total + count, 0),
  };
}

async function canonicalMutationSnapshot(pool: Pool): Promise<readonly unknown[]> {
  const snapshot = await pool.query<{ value: unknown }>(
    `SELECT value FROM (
       SELECT jsonb_build_object(
         'kind','department','code',canonical_code,'version',version,'updatedAt',updated_at
       ) AS value FROM departments WHERE NOT local_extension
       UNION ALL
       SELECT jsonb_build_object(
         'kind','office','code',canonical_code,'version',version,'updatedAt',updated_at
       ) FROM offices WHERE NOT local_extension
     ) canonical ORDER BY value->>'kind',value->>'code'`,
  );
  return snapshot.rows.map(({ value }) => value);
}

function catalogReader(pool: Pool): CatalogReadQueryClient {
  return {
    query: async (text, values) => values === undefined
      ? await pool.query(text)
      : await pool.query(text, [...values]),
  };
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the catalog reconciliation test statement");
  await pool.query(sql);
}

async function cleanupCatalogDatabase(cluster: Pool, tenant: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [tenant], assertSafeDatabaseName: assertCatalogDatabaseName }],
    label: "Temporary catalog-reconciliation database",
  });
}

function assertCatalogDatabaseName(databaseName: string): void {
  if (!/^nom_catalog_reconcile_[0-9a-f]{24}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-catalog-reconciliation test database");
  }
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
  if (url.hostname !== "127.0.0.1" || Number(url.port) !== WORKSPACE_PORT) {
    throw new Error("Catalog reconciliation tests refuse PostgreSQL outside 127.0.0.1:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}
