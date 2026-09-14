import { Pool, type PoolConfig } from "pg";
import { z } from "zod";
import { reconcileTenantOwnershipAndRuntimeGrants } from "../src/provisioner.js";
import {
  assertCanonicalTenantTableInventory,
  assertTenantMaintenanceDatabase,
  lockTenantMaintenanceRoute,
  resolveTenantMaintenanceRoute,
  type TenantMaintenanceRoute,
} from "../src/tenant-maintenance-policy.js";
import { assertWorkspacePostgresUrl, loadLocalScriptEnvironment } from "./script-config.js";

const WORKSPACE_PORT = 55_432;
const tenantId = z.string().uuid().parse(process.env["NOMBRAMIENTOS_TENANT_ID"]);
const environment = loadLocalScriptEnvironment();
const administrator = assertWorkspacePostgresUrl(
  environment.DATABASE_ADMIN_URL,
  "nom_admin",
  "postgres",
);

const control = new Pool({
  ...workspaceAdminPoolConfig(administrator, "nombramientos_control"),
  application_name: "nombramientos-runtime-grant-reconcile",
  max: 1,
});

const controlClient = await control.connect();
try {
  await controlClient.query("BEGIN");
  const tenant = await lockTenantMaintenanceRoute(controlClient, tenantId);
  const suffix = tenantId.replaceAll("-", "");
  if (tenant.databaseHost !== administrator.hostname
    || tenant.databasePort !== WORKSPACE_PORT
    || tenant.databaseName !== `nom_t_${suffix}`
    || tenant.runtimeRole !== `nom_r_${suffix}`
    || !Number.isSafeInteger(tenant.credentialVersion)
    || tenant.credentialVersion < 1
    || tenant.runtimeSecretReference !== `tenant-db/${tenantId}/runtime/v${tenant.credentialVersion}`) {
    throw new Error(`Tenant ${tenantId} does not have the deterministic workspace route`);
  }

  const tenantPool = new Pool({
    ...workspaceAdminPoolConfig(administrator, tenant.databaseName),
    application_name: `nombramientos-runtime-grant-${tenantId.slice(0, 8)}`,
    max: 1,
  });
  try {
    const ownerRole = `nom_o_${suffix}`;
    await reconcileTenantOwnershipAndRuntimeGrants(
      tenantPool,
      ownerRole,
      tenant.runtimeRole,
      async (tenantClient) => {
        await assertTenantMaintenanceDatabase(tenantClient, tenant);
        await assertCanonicalTenantTableInventory(tenantClient, tenant.id);
      },
      async () => {
        const confirmedRoute = await resolveTenantMaintenanceRoute(controlClient, tenantId);
        assertRouteUnchanged(tenant, confirmedRoute);
      },
    );
    await controlClient.query("COMMIT");
    process.stdout.write(
      `Object ownership and runtime grants reconciled for ${tenant.maintenanceClass} tenant ${tenantId}.\n`,
    );
  } catch (error) {
    await controlClient.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    await tenantPool.end();
  }
} finally {
  controlClient.release();
  await control.end();
}

function workspaceAdminPoolConfig(administratorUrl: URL, database: string): PoolConfig {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(database)) {
    throw new Error("Runtime grant reconciliation database target is invalid");
  }
  return {
    host: administratorUrl.hostname,
    port: Number(administratorUrl.port),
    user: decodeURIComponent(administratorUrl.username),
    password: decodeURIComponent(administratorUrl.password),
    database,
    ssl: false,
  };
}

function assertRouteUnchanged(before: TenantMaintenanceRoute, after: TenantMaintenanceRoute): void {
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error(`Tenant ${before.id} maintenance route changed during runtime grant reconciliation`);
  }
}
