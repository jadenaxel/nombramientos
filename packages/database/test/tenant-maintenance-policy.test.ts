import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import {
  assertCanonicalTenantTableInventory,
  assertExpectedTenantComparisons,
  assertTenantMaintenanceDatabase,
  listTenantMaintenanceRoutes,
  lockTenantMaintenanceRoute,
  TENANT_CONFIGURATION_TABLES,
  TENANT_OPERATIONAL_TABLES,
  tenantMaintenanceClass,
  type TenantMaintenanceRoute,
} from "../src/tenant-maintenance-policy.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tenantId = "0a2a0000-0000-4000-8000-000000000001";

describe("tenant maintenance lifecycle policy", () => {
  it.each([
    ["active", "demo", null, 0, 0, "routable"],
    ["active", "real", "failed", 0, 0, "routable"],
    ["active", "real", "active", 0, 1, "initial_admin_pending"],
    ["active", "real", "active", 1, 1, "routable"],
    ["active", "real", "active", 0, 2, "routable"],
    ["active", "invalid", null, 0, 0, null],
    ["suspended", "real", null, 0, 0, "routable"],
    ["provisioning", "real", "pending_activation", 0, 0, "pending_activation"],
    ["provisioning", "demo", "pending_activation", 0, 0, null],
    ["provisioning", "real", "seeded", 0, 0, null],
    ["provisioning", "real", null, 0, 0, null],
    ["failed", "real", "pending_activation", 0, 0, null],
    ["decommission_pending", "real", "pending_activation", 0, 0, null],
  ])("classifies %s/%s/%s strictly", (
    status,
    kind,
    latestProvisioningState,
    tenantMembershipCount,
    openInitialAdminInvitationCount,
    expected,
  ) => {
    expect(tenantMaintenanceClass({
      status,
      kind,
      latestProvisioningState,
      tenantMembershipCount,
      openInitialAdminInvitationCount,
    })).toBe(expected);
  });

  it("lists active, suspended and only the exact pending-activation real candidate", async () => {
    const query = vi.fn(async (_sql: string) => rows([
      controlRow({ id: "active", status: "active", kind: "demo", latest_provisioning_state: null }),
      controlRow({ id: "suspended", status: "suspended", kind: "real", latest_provisioning_state: "failed" }),
      controlRow({ id: "pending", status: "provisioning", kind: "real", latest_provisioning_state: "pending_activation" }),
      controlRow({ id: "demo-pending", status: "provisioning", kind: "demo", latest_provisioning_state: "pending_activation" }),
      controlRow({ id: "seeded", status: "provisioning", kind: "real", latest_provisioning_state: "seeded" }),
      controlRow({ id: "failed", status: "failed", kind: "real", latest_provisioning_state: "pending_activation" }),
    ]));
    const control = { query } as unknown as Pick<Pool, "query">;

    const routes = await listTenantMaintenanceRoutes(control);

    expect(routes.map(({ id, maintenanceClass }) => [id, maintenanceClass])).toEqual([
      ["active", "routable"],
      ["suspended", "routable"],
      ["pending", "pending_activation"],
    ]);
    const sql = String(query.mock.calls[0]?.[0]);
    expect(sql).toMatch(/LEFT JOIN LATERAL/u);
    expect(sql).toMatch(/ORDER BY job\.updated_at DESC,job\.created_at DESC,job\.id DESC/u);
    expect(sql).toContain("to_jsonb(invitation)->>'authority_kind'='initial_admin'");
    expect(sql).not.toContain("invitation.authority_kind='initial_admin'");
  });
});

describe("pending-activation database invariant", () => {
  it("requires setup_state ready for every routable tenant", async () => {
    const query = vi.fn(async () => rows([settingsRow({ setup_state: "in_progress" })]));
    const client = { query } as unknown as Pick<PoolClient, "query">;

    await expect(assertTenantMaintenanceDatabase(client, route("routable"))).rejects.toThrow(/setup_state.*ready/u);
    expect(query).toHaveBeenCalledTimes(1);
  });

  it("admits a not-started pending tenant only after proving every operational table empty", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("FROM tenant_settings")) return rows([settingsRow({ setup_state: "not_started" })]);
      if (sql.includes("FROM pg_catalog.pg_tables")) return rows([{ name: "members" }, { name: "report_versions" }]);
      if (sql.includes("count(*)")) return rows([{ count: "0" }]);
      throw new Error(`Unexpected query: ${sql}`);
    });
    const client = { query } as unknown as Pick<PoolClient, "query">;

    await expect(assertTenantMaintenanceDatabase(client, route("pending_activation"))).resolves.toBeUndefined();
    expect(query).toHaveBeenCalledTimes(4);
  });

  it("admits an exact active initial-admin-pending tenant only under the same empty invariant", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("FROM tenant_settings")) return rows([settingsRow({ setup_state: "not_started" })]);
      if (sql.includes("FROM pg_catalog.pg_tables")) return rows([{ name: "role_bindings" }]);
      if (sql.includes("count(*)")) return rows([{ count: "0" }]);
      throw new Error(`Unexpected query: ${sql}`);
    });
    const client = { query } as unknown as Pick<PoolClient, "query">;

    await expect(assertTenantMaintenanceDatabase(client, route("initial_admin_pending")))
      .resolves.toBeUndefined();
  });

  it("rejects maintenance while pending onboarding is in progress", async () => {
    const query = vi.fn(async () => rows([settingsRow({ setup_state: "in_progress" })]));
    const client = { query } as unknown as Pick<PoolClient, "query">;

    await expect(assertTenantMaintenanceDatabase(client, route("pending_activation")))
      .rejects.toThrow(/setup_state.*not_started or ready/u);
    expect(query).toHaveBeenCalledTimes(1);
  });

  it("accepts a ready pending tenant only when every existing operational table is empty", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("FROM tenant_settings")) return rows([settingsRow()]);
      if (sql.includes("FROM pg_catalog.pg_tables")) {
        return rows([{ name: "member_qualification_versions" }, { name: "members" }, { name: "report_versions" }]);
      }
      if (sql.includes("count(*)")) return rows([{ count: "0" }]);
      throw new Error(`Unexpected query: ${sql}`);
    });
    const client = { query } as unknown as Pick<PoolClient, "query">;

    await expect(assertTenantMaintenanceDatabase(client, route("pending_activation"))).resolves.toBeUndefined();
    expect(query).toHaveBeenCalledTimes(5);
  });

  it("fails closed when any operational evidence exists", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("FROM tenant_settings")) return rows([settingsRow()]);
      if (sql.includes("FROM pg_catalog.pg_tables")) return rows([{ name: "members" }]);
      if (sql.includes('public."members"')) return rows([{ count: "1" }]);
      throw new Error(`Unexpected query: ${sql}`);
    });
    const client = { query } as unknown as Pick<PoolClient, "query">;

    await expect(assertTenantMaintenanceDatabase(client, route("pending_activation"))).rejects.toThrow(/members=1/u);
  });

  it("does not impose the empty invariant on active or suspended tenants", async () => {
    const query = vi.fn(async () => rows([settingsRow()]));
    const client = { query } as unknown as Pick<PoolClient, "query">;

    await expect(assertTenantMaintenanceDatabase(client, route("routable"))).resolves.toBeUndefined();
    expect(query).toHaveBeenCalledTimes(1);
  });
});

describe("canonical operational inventory", () => {
  it("partitions every tenant CREATE TABLE exactly into 8 configuration and 50 operational tables", () => {
    const migrationDirectory = path.join(packageRoot, "migrations", "tenant");
    const createdTables = readdirSync(migrationDirectory)
      .filter((name) => name.endsWith(".sql"))
      .flatMap((name) => [...readFileSync(path.join(migrationDirectory, name), "utf8")
        .matchAll(/\bCREATE TABLE(?: IF NOT EXISTS)?\s+([a-z][a-z0-9_]*)\s*\(/gu)]
        .map((match) => match[1]!))
      .sort();
    const classified = [...TENANT_CONFIGURATION_TABLES, ...TENANT_OPERATIONAL_TABLES].sort();

    expect(TENANT_CONFIGURATION_TABLES).toHaveLength(8);
    expect(TENANT_OPERATIONAL_TABLES).toHaveLength(50);
    expect(new Set(classified).size).toBe(58);
    expect(createdTables).toHaveLength(58);
    expect(classified).toEqual(createdTables);
    expect(TENANT_OPERATIONAL_TABLES).toEqual(expect.arrayContaining([
      "member_qualification_versions",
      "member_eligibility_workflow_pauses",
      "report_versions",
      "cycle_member_snapshots",
      "candidate_snapshots",
      "candidacies",
      "candidate_list_entries",
      "e2ee_http_devices",
      "e2ee_http_session_bindings",
      "e2ee_http_challenges",
    ]));
  });

  it("requires exact, unique neighbor comparison coverage", () => {
    expect(() => assertExpectedTenantComparisons(["tenant-b", "tenant-a"], ["tenant-a", "tenant-b"]))
      .not.toThrow();
    expect(() => assertExpectedTenantComparisons(["tenant-a", "tenant-b"], ["tenant-a"]))
      .toThrow(/missing=tenant-b/u);
    expect(() => assertExpectedTenantComparisons(["tenant-a"], ["tenant-a", "tenant-c"]))
      .toThrow(/unexpected=tenant-c/u);
    expect(() => assertExpectedTenantComparisons(["tenant-a", "tenant-a"], ["tenant-a"]))
      .toThrow(/must be unique/u);
  });

  it("requires the complete canonical table set only at the explicit grant boundary", async () => {
    const canonical = [
      "schema_migrations",
      ...TENANT_CONFIGURATION_TABLES,
      ...TENANT_OPERATIONAL_TABLES,
    ].sort().map((name) => ({ name }));
    const exactClient = { query: vi.fn(async () => rows(canonical)) } as unknown as Pick<PoolClient, "query">;
    await expect(assertCanonicalTenantTableInventory(exactClient, tenantId)).resolves.toBeUndefined();

    const missingClient = { query: vi.fn(async () => rows(canonical.slice(1))) } as unknown as Pick<PoolClient, "query">;
    await expect(assertCanonicalTenantTableInventory(missingClient, tenantId)).rejects.toThrow(/exact canonical/u);

    const extraClient = { query: vi.fn(async () => rows([...canonical, { name: "rogue_table" }])) } as unknown as Pick<PoolClient, "query">;
    await expect(assertCanonicalTenantTableInventory(extraClient, tenantId)).rejects.toThrow(/exact canonical/u);
  });

  it("holds the tenant advisory, route and provisioning locks before resolving eligibility", async () => {
    const queries: string[] = [];
    const query = vi.fn(async (sql: string) => {
      queries.push(sql);
      if (sql.includes("FROM tenants WHERE id=$1 FOR UPDATE")) return rows([{ id: tenantId }]);
      if (sql.includes("FROM tenants tenant")) return rows([controlRow({})]);
      if (sql.includes("FROM provisioning_jobs")) return rows([]);
      return rows([{ pg_advisory_xact_lock: null }]);
    });
    const client = { query } as unknown as Pick<PoolClient, "query">;

    await expect(lockTenantMaintenanceRoute(client, tenantId)).resolves.toMatchObject({ id: tenantId });
    expect(queries[0]).toContain("pg_advisory_xact_lock");
    expect(queries[1]).toContain("FOR UPDATE");
    expect(queries[2]).toContain("provisioning_jobs");
    expect(queries[3]).toContain("FROM tenants tenant");
  });
});

function route(maintenanceClass: TenantMaintenanceRoute["maintenanceClass"]): TenantMaintenanceRoute {
  return {
    id: tenantId,
    kind: "real",
    status: maintenanceClass === "pending_activation" ? "provisioning" : "active",
    maintenanceClass,
    latestProvisioningState: maintenanceClass === "pending_activation" ? "pending_activation" : null,
    databaseHost: "127.0.0.1",
    databasePort: 55_432,
    databaseName: "nom_t_0a2a0000000040008000000000000001",
    runtimeRole: "nom_r_0a2a0000000040008000000000000001",
    runtimeSecretReference: `tenant-db/${tenantId}/runtime/v1`,
    credentialVersion: 1,
  };
}

function settingsRow(overrides: Partial<ReturnType<typeof settingsRowBase>> = {}): ReturnType<typeof settingsRowBase> {
  return { ...settingsRowBase(), ...overrides };
}

function settingsRowBase() {
  return {
    tenant_id: tenantId,
    kind: "real",
    setup_state: "ready",
    database_name: "nom_t_0a2a0000000040008000000000000001",
  };
}

function controlRow(overrides: Record<string, unknown>) {
  return {
    id: tenantId,
    kind: "real",
    status: "active",
    database_host: "127.0.0.1",
    database_port: 55_432,
    database_name: "nom_t_0a2a0000000040008000000000000001",
    runtime_role: "nom_r_0a2a0000000040008000000000000001",
    runtime_secret_ref: `tenant-db/${tenantId}/runtime/v1`,
    credential_version: 1,
    latest_provisioning_state: null,
    tenant_membership_count: 0,
    open_initial_admin_invitation_count: 0,
    ...overrides,
  };
}

function rows<T>(values: T[]) {
  return { rows: values, rowCount: values.length };
}
