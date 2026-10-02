import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { catalogPackage2025 } from "@nombramientos/catalog";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl, withoutDatabase } from "../scripts/script-config.js";
import { reconcileTenantCatalog, tenantCatalogTarget } from "../src/catalog-reconciliation.js";
import { runMigrations } from "../src/migrations.js";
import { TenantStore } from "../src/tenant-store.js";
import { cleanupTemporaryDatabases } from "./live-database-cleanup.js";
import { PersistentReadOnlyPool } from "./persistent-read-only-fixture.js";

// Explicit opt-in; neither fixture discovery nor ordinary tests write installed tenants.
const enabled = process.env["NOMBRAMIENTOS_PREMIUM_ISOLATED"] === "true";
const live = enabled ? describe.sequential : describe.skip;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const databaseName = `nom_qual_test_${randomBytes(12).toString("hex")}`;
const marker = `nom-owned-storage-policies:${randomUUID()}`;
const tenantId = randomUUID();
let cluster: Pool | undefined;
let tenant: Pool | undefined;
let tenantUrl = "";
let createdOid: number | undefined;

function exactOwnName(value: string): void {
  if (value !== databaseName || !/^nom_qual_test_[0-9a-f]{24}$/u.test(value)) {
    throw new Error("Owned policy fixture refused an unexpected or installed database");
  }
}
function ownTenant(): Pool {
  if (!tenant || createdOid === undefined) throw new Error("Owned policy fixture was not created");
  exactOwnName(databaseName);
  return tenant;
}
async function cleanupOwnedFixture(): Promise<void> {
  if (!cluster) return;
  if (createdOid === undefined) {
    await tenant?.end();
    await cluster.end();
  } else {
    const owner = await cluster.query<{ oid: number; marker: string | null }>(
      "SELECT oid,shobj_description(oid,'pg_database') AS marker FROM pg_database WHERE datname=$1",
      [databaseName],
    );
    if (owner.rows[0]?.oid !== createdOid || owner.rows[0]?.marker !== marker) {
      throw new Error("Owned policy fixture cleanup refused missing ownership evidence");
    }
    await cleanupTemporaryDatabases({
      maintenancePool: cluster,
      targets: [{ databaseName, databasePools: tenant ? [tenant] : [], assertSafeDatabaseName: exactOwnName }],
      label: marker,
    });
    console.info(JSON.stringify({ fixture: "owned-storage-policies", databaseName, marker, cleanupRemainingDatabases: 0 }));
  }
  cluster = undefined;
  tenant = undefined;
  createdOid = undefined;
}

live("outbox and report policy in an owned ephemeral tenant", () => {
  beforeAll(async () => {
    const installation = JSON.parse(readFileSync(path.join(packageRoot, ".local", "install.json"), "utf8")) as { DATABASE_ADMIN_URL?: string };
    if (!installation.DATABASE_ADMIN_URL) throw new Error("Workspace administrator connection is unavailable");
    const adminUrl = assertWorkspacePostgresUrl(installation.DATABASE_ADMIN_URL, "nom_admin", "postgres").toString();
    exactOwnName(databaseName);
    cluster = new Pool({ connectionString: adminUrl, max: 1 });
    try {
      const collision = await cluster.query("SELECT oid FROM pg_database WHERE datname=$1", [databaseName]);
      if (collision.rowCount !== 0) throw new Error("Owned policy fixture refuses a pre-existing target");
      const create = await cluster.query<{ sql: string }>(
        "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L',$1::text,'UTF8') AS sql",
        [databaseName],
      );
      if (!create.rows[0]?.sql) throw new Error("PostgreSQL did not format the owned target");
      await cluster.query(create.rows[0].sql);
      createdOid = (await cluster.query<{ oid: number }>("SELECT oid FROM pg_database WHERE datname=$1", [databaseName])).rows[0]?.oid;
      if (createdOid === undefined) throw new Error("Owned database creation was not attested");
      const comment = await cluster.query<{ sql: string }>(
        "SELECT format('COMMENT ON DATABASE %I IS %L',$1::text,$2::text) AS sql", [databaseName, marker],
      );
      if (!comment.rows[0]?.sql) throw new Error("PostgreSQL did not format the ownership marker");
      await cluster.query(comment.rows[0].sql);
      tenantUrl = withoutDatabase(adminUrl, databaseName);
      tenant = new Pool({ connectionString: tenantUrl, max: 1 });
      await runMigrations(tenant, { scope: "tenant", directory: path.join(packageRoot, "migrations", "tenant") });
      await tenant.query(
        "INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state) VALUES($1,'Owned policy fixture','real','America/La_Paz','es','ready')",
        [tenantId],
      );
      await reconcileTenantCatalog(tenant, catalogPackage2025);
      console.info(JSON.stringify({ fixture: "owned-storage-policies", databaseName, marker, tenantId, createdOid }));
    } catch (error) {
      try { await cleanupOwnedFixture(); }
      catch (cleanupError) { throw new AggregateError([error, cleanupError], "Owned fixture setup and teardown failed"); }
      throw error;
    }
  }, 60_000);
  afterAll(cleanupOwnedFixture, 30_000);

  it("starts empty and carries the canonical catalog without asserting an installed church is empty", async () => {
    const target = tenantCatalogTarget(catalogPackage2025);
    const counts = await ownTenant().query(`SELECT
      (SELECT count(*)::int FROM members) members,
      (SELECT count(*)::int FROM election_cycles) cycles,
      (SELECT count(*)::int FROM encrypted_submissions) submissions,
      (SELECT count(*)::int FROM departments) departments,
      (SELECT count(*)::int FROM offices) offices`);
    expect(counts.rows[0]).toEqual({ members: 0, cycles: 0, submissions: 0, departments: target.departmentCount, offices: target.officeCount });
  });

  it("proves the persistent-test adapter refuses writes at PostgreSQL itself on this owned database", async () => {
    const readOnly = new PersistentReadOnlyPool({ connectionString: tenantUrl, max: 1 });
    try {
      expect((await readOnly.query("SELECT current_setting('transaction_read_only')='on' AS read_only")).rows[0]?.read_only).toBe(true);
      await expect(readOnly.query("INSERT INTO outbox_events(audience,event_type,aggregate_type,payload) VALUES('tenant.authorized','test.denied','test','{}')")).rejects.toMatchObject({ code: "25006" });
      expect((await ownTenant().query("SELECT count(*)::int AS count FROM outbox_events WHERE event_type='test.denied'")).rows[0]?.count).toBe(0);
    } finally { await readOnly.end(); }
  });

  it("never returns an outbox event outside the authorized tenant audience", async () => {
    const tenant = ownTenant();
    const client = await tenant.connect();
    try {
      await client.query("BEGIN");
      const baseline = await client.query<{ sequence: number }>(
        "SELECT COALESCE(max(sequence),0)::bigint AS sequence FROM outbox_events",
      );
      const cursor = Number(baseline.rows[0]?.sequence ?? 0);
      const authorized = await client.query<{ id: string }>(
        `INSERT INTO outbox_events(audience,event_type,aggregate_type,payload)
         VALUES ('tenant.authorized','round.phase','round','{}'::jsonb) RETURNING id`,
      );
      await client.query(
        `INSERT INTO outbox_events(audience,event_type,aggregate_type,payload)
         VALUES ('tenant.secret','internal.preference.delta','round','{}'::jsonb)`,
      );
      const events = await new TenantStore(client).listEvents(cursor, 100);
      expect(events.map((event) => event["id"])).toEqual([authorized.rows[0]?.id]);
      expect(events.every((event) => event["audience"] === "tenant.authorized")).toBe(true);
      await client.query("ROLLBACK");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  });


  it("enforces the report catalog and audience policy at the database boundary", async () => {
    const tenant = ownTenant();
    const insertReport = async (reportType: string, audience: string): Promise<string | null> => {
      const client = await tenant.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          `INSERT INTO report_versions(
             report_type,audience,locale,format,filters,state,requested_by_identity_id
           ) VALUES ($1,$2,'es','pdf','{}'::jsonb,'pending',$3)`,
          [reportType, audience, "10000000-0000-4000-8000-000000000001"],
        );
        await client.query("ROLLBACK");
        return null;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        return typeof error === "object" && error !== null && "code" in error ? String(error.code) : "unknown";
      } finally {
        client.release();
      }
    };
    await expect(insertReport("cycle_summary", "committee")).resolves.toBeNull();
    await expect(insertReport("invented_report", "committee")).resolves.toBe("23514");
    await expect(insertReport("office_round", "church")).resolves.toBe("23514");
    await expect(insertReport("roster_import_incidents", "auditor")).resolves.toBe("23514");
  });


});
