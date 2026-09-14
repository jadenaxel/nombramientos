import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { PoolClient } from "pg";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runMigrations } from "../src/migrations.js";
import { TenantStore } from "../src/tenant-store.js";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReach(adminUrl) : false;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
if (requireLive && !reachable) throw new Error("Organization live test requires the PostgreSQL 18 workspace cluster");
const live = reachable ? describe.sequential : describe.skip;

type OrganizationResponse = {
  cycles: Array<{ id: string; name: string; status: string; termStart: string; termEnd: string }>;
  selectedCycle: { id: string; name: string; status: string; termStart: string; termEnd: string } | null;
  cycleName: string | null;
  stage: "proposal" | "elected";
  items: Array<Record<string, unknown>>;
};

interface Fixture {
  readonly admin: Pool;
  readonly tenant: Pool;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly activeCycleId: string;
  readonly historicalCycleId: string;
  readonly activeMemberId: string;
  readonly proposedMemberId: string;
  readonly electedMemberId: string;
  readonly proposedVacancyId: string;
  readonly baseVacancyId: string;
  readonly linkedVacancyId: string;
  readonly baseAssignmentId: string;
  readonly linkedAssignmentId: string;
  readonly historicalDepartmentId: string;
}

let fixture: Fixture | undefined;

live("cycle-scoped organization projection", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("PostgreSQL administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 60_000);

  it("returns an honest empty result before a tenant has any cycles", async () => {
    const current = requireFixture();
    expect(current.emptyProjection).toEqual({
      cycles: [],
      selectedCycle: null,
      cycleName: null,
      stage: "elected",
      items: [],
    });
  });

  it("selects the active cycle by default and never mixes another cycle into its items", async () => {
    const current = requireFixture();
    const result = await withStore(current, (store) => store.getOrganization()) as OrganizationResponse;
    expect(result.selectedCycle?.id).toBe(current.activeCycleId);
    expect(result.stage).toBe("elected");
    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toMatchObject({ memberId: current.activeMemberId, status: "elected" });
    expect(JSON.stringify(result.items)).not.toContain(current.proposedMemberId);
    expect(JSON.stringify(result.items)).not.toContain(current.electedMemberId);
    expect(result.cycles.map(({ id }) => id)).toEqual([current.activeCycleId, current.historicalCycleId]);
  });

  it("projects preliminary states without ever labelling them as elected", async () => {
    const current = requireFixture();
    const result = await withStore(current, (store) => store.getOrganization({
      cycleId: current.historicalCycleId,
      stage: "proposal",
    })) as OrganizationResponse;
    expect(result.selectedCycle).toMatchObject({
      id: current.historicalCycleId,
      status: "archived",
      termStart: "2024-01-01",
      termEnd: "2024-12-31",
    });
    expect(result.stage).toBe("proposal");
    expect(result.items).toHaveLength(4);
    expect(result.items.every(({ status }) => status !== "elected")).toBe(true);
    expect(result.items.every(({ processState }) => !["ELEGIDA_POR_IGLESIA", "VIGENTE", "FINALIZADA"].includes(String(processState)))).toBe(true);
    expect(result.items.find(({ vacancyId }) => vacancyId === current.proposedVacancyId)).toMatchObject({
      memberId: current.proposedMemberId,
      status: "accepted",
      processState: "ACEPTADA",
    });
    expect(result.items.find(({ vacancyId }) => vacancyId === current.baseVacancyId)).toMatchObject({
      memberId: current.electedMemberId,
      status: "accepted",
      processState: "PRESENTADA_A_IGLESIA",
    });
  });

  it("hides every non-elected identity in the elected view and uses immutable historical snapshots", async () => {
    const current = requireFixture();
    const result = await withStore(current, (store) => store.getOrganization({
      cycleId: current.historicalCycleId,
      stage: "elected",
    })) as OrganizationResponse;
    const proposedSeat = result.items.find(({ vacancyId }) => vacancyId === current.proposedVacancyId);
    expect(proposedSeat).toEqual(expect.objectContaining({
      id: current.proposedVacancyId,
      vacancyId: current.proposedVacancyId,
      status: "vacant",
      processState: null,
    }));
    for (const restrictedField of ["assignmentId", "memberId", "memberSnapshot", "displayEnvelope", "linkedToId", "independent"]) {
      expect(proposedSeat).not.toHaveProperty(restrictedField);
    }
    expect(JSON.stringify(result.items)).not.toContain(current.proposedMemberId);
    expect(JSON.stringify(result.items)).not.toContain("CURRENT_DISPLAY_MUST_NOT_LEAK");
    expect(JSON.stringify(result.items)).not.toContain("CONTACT_MUST_NOT_LEAK");

    const base = result.items.find(({ vacancyId }) => vacancyId === current.baseVacancyId);
    expect(base).toMatchObject({
      id: current.baseAssignmentId,
      assignmentId: current.baseAssignmentId,
      memberId: current.electedMemberId,
      departmentId: current.historicalDepartmentId,
      officeCode: "HISTORIC_BASE",
      officeName: "Responsabilidad histórica base",
      departmentName: "Departamento histórico",
      status: "elected",
      independent: true,
      memberSnapshot: {
        memberId: current.electedMemberId,
        displayEnvelope: { marker: "FROZEN_CYCLE_DISPLAY" },
      },
    });
    const linked = result.items.find(({ vacancyId }) => vacancyId === current.linkedVacancyId);
    expect(linked).toMatchObject({
      id: current.linkedAssignmentId,
      memberId: current.electedMemberId,
      status: "elected",
      independent: false,
      linkedToId: current.baseAssignmentId,
      memberSnapshot: {
        displayEnvelope: { marker: "FROZEN_ASSIGNMENT_DISPLAY" },
        photo: { marker: "FROZEN_ASSIGNMENT_PHOTO" },
      },
      photoSnapshot: { marker: "FROZEN_ASSIGNMENT_PHOTO" },
    });
    expect(result.items.filter((item) => item["memberId"] === current.electedMemberId && item["independent"] === true)).toHaveLength(1);
    expect(result.items.filter((item) => item["memberId"] === current.electedMemberId
      && item["independent"] === false && typeof item["linkedToId"] === "string")).toHaveLength(1);
  });

  it("returns no items and no selected cycle for a foreign cycle identifier", async () => {
    const current = requireFixture();
    const result = await withStore(current, (store) => store.getOrganization({
      cycleId: randomUUID(),
      stage: "elected",
    })) as OrganizationResponse;
    expect(result).toMatchObject({ selectedCycle: null, items: [], stage: "elected" });
  });
});

type FixtureWithEmptyProjection = Fixture & { readonly emptyProjection: OrganizationResponse };

async function createFixture(connectionString: string): Promise<FixtureWithEmptyProjection> {
  const admin = new Pool({ connectionString, max: 1 });
  const databaseName = `nom_test_organization_${randomBytes(6).toString("hex")}`;
  let tenant: Pool | undefined;
  try {
    assertOrganizationDatabaseName(databaseName);
    const formatted = await admin.query<{ sql: string }>("SELECT format('CREATE DATABASE %I', $1::text) AS sql", [databaseName]);
    const createSql = formatted.rows[0]?.sql;
    if (!createSql) throw new Error("PostgreSQL did not format the organization test database statement");
    await admin.query(createSql);
    const tenantUrl = new URL(connectionString);
    tenantUrl.pathname = `/${databaseName}`;
    tenant = new Pool({ connectionString: tenantUrl.toString(), max: 2 });
    await runMigrations(tenant, { scope: "tenant", directory: path.join(packageRoot, "migrations", "tenant") });
    const tenantId = randomUUID();
    await tenant.query(
      `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state,catalog_version)
       VALUES ($1,'Organization fixture','real','America/Santo_Domingo','es','ready','fixture-v1')`,
      [tenantId],
    );
    const emptyProjection = await withRawStore(tenant, tenantId, (store) => store.getOrganization()) as OrganizationResponse;

    const activeCycleId = randomUUID();
    const historicalCycleId = randomUUID();
    const historicalDepartmentId = randomUUID();
    const activeMemberId = randomUUID();
    const proposedMemberId = randomUUID();
    const electedMemberId = randomUUID();
    const proposedVacancyId = randomUUID();
    const baseVacancyId = randomUUID();
    const linkedVacancyId = randomUUID();
    const activeVacancyId = randomUUID();
    const baseAssignmentId = randomUUID();
    const linkedAssignmentId = randomUUID();
    const activeAssignmentId = randomUUID();
    const proposedAssignmentId = randomUUID();
    const officeIds = [randomUUID(), randomUUID(), randomUUID(), randomUUID()] as const;

    await tenant.query(
      `INSERT INTO election_cycles(id,name,status,locale,timezone,term_start,term_end,normative_version)
       VALUES
         ($1,'Mandato activo','active','es','America/Santo_Domingo','2028-01-01','2028-12-31','fixture-v1'),
         ($2,'Mandato histórico','archived','es','America/Santo_Domingo','2024-01-01','2024-12-31','fixture-v1')`,
      [activeCycleId, historicalCycleId],
    );
    await tenant.query(
      `INSERT INTO departments(id,canonical_code,names,sort_order)
       VALUES ($1,'CURRENT_DEPARTMENT',$2,1)`,
      [historicalDepartmentId, { es: "Departamento actual renombrado" }],
    );
    for (let index = 0; index < officeIds.length; index += 1) {
      await tenant.query(
        `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality)
         VALUES ($1,$2,$3,$4,'church_election',1)`,
        [officeIds[index], historicalDepartmentId, `CURRENT_OFFICE_${index + 1}`, { es: `Cargo actual ${index + 1}` }],
      );
    }
    for (const [memberId, stableCode] of [
      [activeMemberId, "ORG-ACTIVE"],
      [proposedMemberId, "ORG-PROPOSED"],
      [electedMemberId, "ORG-ELECTED"],
    ] as const) {
      const displayEnvelope = {
        algorithm: "AES-256-GCM",
        keyId: "organization-display-fixture-key",
        nonce: randomBytes(12).toString("base64url"),
        ciphertext: randomBytes(32).toString("base64url"),
        aad: Buffer.from(JSON.stringify({ tenantId, memberId, purpose: "member-display", schemaVersion: 1 })).toString("base64url"),
        marker: "CURRENT_DISPLAY_MUST_NOT_LEAK",
      };
      await tenant.query(
        `INSERT INTO members(id,stable_code,display_envelope,display_content_hash,eligibility_status,available)
         VALUES ($1,$2,$3,$4,'eligible',true)`,
        [memberId, stableCode, displayEnvelope, fixtureEnvelopeHash(displayEnvelope)],
      );
    }
    await tenant.query(
      `INSERT INTO cycle_member_snapshots(
         cycle_id,member_id,member_version,eligibility_status,available,display_envelope,
         eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
         eligibility_evaluated_on,eligibility_effective
       ) VALUES
         ($1,$2,1,'eligible',true,$5,NULL,NULL,(SELECT (clock_timestamp() AT TIME ZONE timezone)::date FROM tenant_settings WHERE singleton=true),true),
         ($1,$3,1,'eligible',true,$6,NULL,NULL,(SELECT (clock_timestamp() AT TIME ZONE timezone)::date FROM tenant_settings WHERE singleton=true),true),
         ($4,$7,1,'eligible',true,$8,NULL,NULL,(SELECT (clock_timestamp() AT TIME ZONE timezone)::date FROM tenant_settings WHERE singleton=true),true)`,
      [
        historicalCycleId,
        proposedMemberId,
        electedMemberId,
        activeCycleId,
        { marker: "FROZEN_PROPOSED_DISPLAY" },
        { marker: "FROZEN_CYCLE_DISPLAY" },
        activeMemberId,
        { marker: "FROZEN_ACTIVE_DISPLAY" },
      ],
    );
    await tenant.query(
      `INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status)
       VALUES
         ($1,$5,$8,1,'accepted'),
         ($2,$5,$9,1,'elected'),
         ($3,$5,$10,1,'elected'),
         ($4,$5,$11,1,'pending'),
         ($6,$7,$8,1,'elected')`,
      [
        proposedVacancyId, baseVacancyId, linkedVacancyId, randomUUID(), historicalCycleId,
        activeVacancyId, activeCycleId, officeIds[0], officeIds[1], officeIds[2], officeIds[3],
      ],
    );
    const historicDepartmentSnapshot = { es: "Departamento histórico", en: "Historic department", fr: "Département historique" };
    const proposedOfficeSnapshot = {
      officeId: officeIds[0], departmentId: historicalDepartmentId, canonicalCode: "HISTORIC_PROPOSED",
      names: { es: "Responsabilidad histórica propuesta" }, departmentNames: historicDepartmentSnapshot,
    };
    const baseOfficeSnapshot = {
      officeId: officeIds[1], departmentId: historicalDepartmentId, canonicalCode: "HISTORIC_BASE",
      names: { es: "Responsabilidad histórica base" }, departmentNames: historicDepartmentSnapshot,
    };
    const linkedOfficeSnapshot = {
      officeId: officeIds[2], departmentId: historicalDepartmentId, canonicalCode: "HISTORIC_LINKED",
      names: { es: "Responsabilidad histórica vinculada" }, departmentNames: historicDepartmentSnapshot,
    };
    await tenant.query(
      `INSERT INTO assignments(
         id,vacancy_id,member_id,state,effective,independent,linked_to_assignment_id,
         cycle_id,office_id,member_snapshot,office_snapshot
       ) VALUES
         ($1,$2,$3,'ACEPTADA',true,true,NULL,$12,$13,$16,$17),
         ($4,$5,$6,'FINALIZADA',false,true,NULL,$12,$14,NULL,$18),
         ($7,$8,$6,'FINALIZADA',false,false,$4,$12,$15,$19,$20),
         ($9,$10,$11,'VIGENTE',true,true,NULL,$21,$13,NULL,$22)`,
      [
        proposedAssignmentId, proposedVacancyId, proposedMemberId,
        baseAssignmentId, baseVacancyId, electedMemberId,
        linkedAssignmentId, linkedVacancyId,
        activeAssignmentId, activeVacancyId, activeMemberId,
        historicalCycleId, officeIds[0], officeIds[1], officeIds[2],
        { memberId: proposedMemberId, displayEnvelope: { marker: "FROZEN_PROPOSED_ASSIGNMENT" } },
        proposedOfficeSnapshot,
        baseOfficeSnapshot,
        {
          memberId: electedMemberId,
          displayEnvelope: { marker: "FROZEN_ASSIGNMENT_DISPLAY" },
          photo: { marker: "FROZEN_ASSIGNMENT_PHOTO" },
          contactEnvelope: { marker: "CONTACT_MUST_NOT_LEAK" },
        },
        linkedOfficeSnapshot,
        activeCycleId,
        { officeId: officeIds[0], canonicalCode: "ACTIVE_OFFICE", names: { es: "Cargo activo" } },
      ],
    );
    return {
      admin, tenant, databaseName, tenantId, emptyProjection,
      activeCycleId, historicalCycleId, activeMemberId, proposedMemberId, electedMemberId,
      proposedVacancyId, baseVacancyId, linkedVacancyId, baseAssignmentId, linkedAssignmentId,
      historicalDepartmentId,
    };
  } catch (error) {
    return cleanupAfterFailure(
      error,
      () => cleanupOrganizationDatabase(admin, tenant, databaseName),
      "Organization fixture setup",
    );
  }
}

async function withStore<T>(current: Fixture, work: (store: TenantStore) => Promise<T>): Promise<T> {
  return withRawStore(current.tenant, current.tenantId, work);
}

async function withRawStore<T>(tenant: Pool, tenantId: string, work: (store: TenantStore) => Promise<T>): Promise<T> {
  const client = await tenant.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, tenantId);
    const result = await work(new TenantStore(client));
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function setContext(client: PoolClient, tenantId: string): Promise<void> {
  await client.query(
    `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
            set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
    [tenantId, randomUUID(), randomUUID(), randomUUID()],
  );
}

async function cleanupFixture(current: Fixture): Promise<void> {
  await cleanupOrganizationDatabase(current.admin, current.tenant, current.databaseName);
}

async function cleanupOrganizationDatabase(
  admin: Pool,
  tenant: Pool | undefined,
  databaseName: string,
): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: admin,
    targets: [{
      databaseName,
      databasePools: tenant ? [tenant] : [],
      assertSafeDatabaseName: assertOrganizationDatabaseName,
    }],
    label: "Temporary organization database",
  });
}

function assertOrganizationDatabaseName(databaseName: string): void {
  if (!/^nom_test_organization_[0-9a-f]{12}$/u.test(databaseName)) {
    throw new Error("Refusing to clean up a non-organization-test database");
  }
}

function fixtureEnvelopeHash(envelope: Readonly<Record<string, string>>): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(envelope)).digest("hex")}`;
}

function requireFixture(): FixtureWithEmptyProjection {
  if (!fixture) throw new Error("Organization fixture is unavailable");
  return fixture as FixtureWithEmptyProjection;
}

function discoverAdminUrl(): string | undefined {
  if (!existsSync(installFile)) return undefined;
  const parsed = JSON.parse(readFileSync(installFile, "utf8")) as { DATABASE_ADMIN_URL?: string };
  if (!parsed.DATABASE_ADMIN_URL) return undefined;
  try {
    return assertWorkspacePostgresUrl(parsed.DATABASE_ADMIN_URL, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReach(connectionString: string): Promise<boolean> {
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_000 });
  try {
    const result = await pool.query<{ port: string; version: string }>(
      "SELECT current_setting('port') AS port,current_setting('server_version') AS version",
    );
    return result.rows[0]?.port === "55432" && (result.rows[0]?.version.startsWith("18.") ?? false);
  } catch {
    return false;
  } finally {
    await pool.end().catch(() => undefined);
  }
}
