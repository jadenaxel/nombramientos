import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  MemorySecretProvider,
  TenantProvisioner,
  type ProvisioningCatalog,
} from "@nombramientos/database";
import { Pool } from "pg";

import {
  cleanupStageError,
  collectCleanupFailure,
  dropEphemeralDatabase,
  dropEphemeralRole,
  endPoolAndConfirmDrained,
} from "./ephemeral-postgres-cleanup.js";
import { assertExactWorkspaceAdminUrl } from "./local-test-database-boundary.js";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const migrationsRoot = path.join(workspaceRoot, "packages", "database", "migrations");
const temporaryActiveTenantCatalog: ProvisioningCatalog = {
  version: "api-live-scratch-v1",
  departments: [{
    canonicalCode: "api_live_scratch_department",
    names: {
      es: "Departamento temporal de pruebas API",
      en: "Temporary API test department",
      fr: "Département temporaire de test API",
    },
    parentDepartmentCode: null,
  }],
  offices: [{
    canonicalCode: "api_live_scratch_office",
    departmentCode: "api_live_scratch_department",
    names: {
      es: "Cargo temporal de pruebas API",
      en: "Temporary API test office",
      fr: "Poste temporaire de test API",
    },
    mechanism: "church_election_after_nominating_report",
    cardinality: { minimum: 1, maximum: 1 },
  }],
};

export interface TemporaryActiveTenant {
  readonly tenantId: string;
  readonly idempotencyKey: string;
  readonly slug: string;
  readonly databaseName: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly secretReference: string;
  readonly secrets: MemorySecretProvider;
}

export async function provisionTemporaryActiveTenant(
  databaseAdminUrl: string,
  control: Pool,
  label: string,
): Promise<TemporaryActiveTenant> {
  if (!/^[a-z0-9-]{2,24}$/u.test(label)) throw new Error("Temporary tenant label is invalid");
  const admin = exactWorkspaceAdminConnection(databaseAdminUrl);
  const tenantId = randomUUID();
  const idempotencyKey = randomUUID();
  const suffix = tenantId.replaceAll("-", "");
  const slug = `test-${label}-${suffix.slice(0, 12)}`;
  const secrets = new MemorySecretProvider();
  const expected: TemporaryActiveTenant = {
    tenantId,
    idempotencyKey,
    slug,
    databaseName: `nom_t_${suffix}`,
    ownerRole: `nom_o_${suffix}`,
    runtimeRole: `nom_r_${suffix}`,
    secretReference: `tenant-db/${tenantId}/runtime/v1`,
    secrets,
  };
  const provisioner = new TenantProvisioner({
    admin: {
      ...admin,
      ssl: false,
    },
    catalog: temporaryActiveTenantCatalog,
    control,
    secrets,
    migrationsRoot,
  });
  try {
    const result = await provisioner.provision({
      idempotencyKey,
      tenantId,
      slug,
      displayName: `API live scratch ${label}`,
      kind: "demo",
      timezone: "America/Santo_Domingo",
      locale: "es",
    });
    if (result.state !== "active"
      || result.database !== expected.databaseName
      || result.runtimeRole !== expected.runtimeRole
      || result.secretReference !== expected.secretReference) {
      throw new Error("Temporary tenant provisioning returned an unexpected route");
    }
    return expected;
  } catch (error) {
    try {
      await destroyTemporaryActiveTenant(databaseAdminUrl, control, expected);
    } catch (cleanupError) {
      throw new Error("Temporary tenant provisioning failed and its cleanup did not complete", {
        cause: new AggregateError([error, cleanupError]),
      });
    }
    throw error;
  } finally {
    await provisioner.close();
  }
}

export async function destroyTemporaryActiveTenant(
  databaseAdminUrl: string,
  control: Pool,
  tenant: TemporaryActiveTenant,
): Promise<void> {
  assertTemporaryTenantNames(tenant);
  assertExactWorkspaceAdminUrl(databaseAdminUrl);
  const client = await control.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM provisioning_jobs WHERE tenant_id=$1 AND idempotency_key=$2", [
      tenant.tenantId,
      tenant.idempotencyKey,
    ]);
    await client.query("DELETE FROM tenants WHERE id=$1 AND slug=$2", [tenant.tenantId, tenant.slug]);
    const controlResidue = await client.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM provisioning_jobs WHERE tenant_id=$1 OR idempotency_key=$2)
         + (SELECT count(*) FROM tenants WHERE id=$1 OR slug=$3)
       )::int AS count`,
      [tenant.tenantId, tenant.idempotencyKey, tenant.slug],
    );
    if (controlResidue.rows[0]?.count !== 0) {
      throw new Error("Temporary tenant control rows survived cleanup");
    }
    await client.query("COMMIT");
  } catch (error) {
    const failures = [cleanupStageError("temporary tenant control transaction", error)];
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      failures.push(cleanupStageError("temporary tenant control rollback", rollbackError));
    }
    throw new AggregateError(failures, "Temporary tenant control cleanup failed closed");
  } finally {
    client.release();
  }

  const cluster = new Pool({
    ...exactWorkspaceAdminConnection(databaseAdminUrl),
    ssl: false,
    max: 1,
    application_name: "nombramientos-api-live-scratch-cleanup",
  });
  const failures: Error[] = [];
  try {
    await collectCleanupFailure(failures, "temporary tenant database drop", async () => dropEphemeralDatabase(
      cluster,
      tenant.databaseName,
      { pattern: /^nom_t_[0-9a-f]{32}$/u, label: "temporary tenant database" },
    ));
    await collectCleanupFailure(failures, "temporary tenant runtime role drop", async () => dropEphemeralRole(
      cluster,
      tenant.runtimeRole,
      { pattern: /^nom_r_[0-9a-f]{32}$/u, label: "temporary tenant runtime role" },
    ));
    await collectCleanupFailure(failures, "temporary tenant owner role drop", async () => dropEphemeralRole(
      cluster,
      tenant.ownerRole,
      { pattern: /^nom_o_[0-9a-f]{32}$/u, label: "temporary tenant owner role" },
    ));
    await collectCleanupFailure(failures, "temporary tenant residue attestation", async () => {
      const residue = await cluster.query<{ databases: number; roles: number }>(
        `SELECT
           (SELECT count(*)::int FROM pg_database WHERE datname=$1) AS databases,
           (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
        [tenant.databaseName, [tenant.runtimeRole, tenant.ownerRole]],
      );
      if (residue.rows[0]?.databases !== 0 || residue.rows[0]?.roles !== 0) {
        throw new Error("Temporary tenant database or roles survived cleanup");
      }
    });
  } finally {
    await collectCleanupFailure(failures, "temporary tenant maintenance pool close", async () => {
      await endPoolAndConfirmDrained(cluster, "temporary tenant maintenance pool");
    });
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, "Temporary tenant database cleanup failed closed");
  }
}

function exactWorkspaceAdminConnection(value: string): {
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly password: string;
  readonly database: string;
} {
  const admin = new URL(assertExactWorkspaceAdminUrl(value));
  return {
    host: admin.hostname,
    port: Number(admin.port),
    user: decodeURIComponent(admin.username),
    password: decodeURIComponent(admin.password),
    database: admin.pathname.slice(1),
  };
}

function assertTemporaryTenantNames(tenant: TemporaryActiveTenant): void {
  const suffix = tenant.tenantId.replaceAll("-", "");
  if (!/^[0-9a-f]{32}$/u.test(suffix)
    || tenant.databaseName !== `nom_t_${suffix}`
    || tenant.ownerRole !== `nom_o_${suffix}`
    || tenant.runtimeRole !== `nom_r_${suffix}`
    || tenant.secretReference !== `tenant-db/${tenant.tenantId}/runtime/v1`
    || !tenant.slug.startsWith("test-")) {
    throw new Error("Refusing cleanup outside an exact temporary tenant target");
  }
}
