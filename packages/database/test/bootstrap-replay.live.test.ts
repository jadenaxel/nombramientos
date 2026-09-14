import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import { TenantProvisioner } from "../src/provisioner.js";
import type { TenantProvisionRequest, WritableSecretProvider } from "../src/types.js";
import { assertWorkspacePostgresUrl, withoutDatabase } from "../scripts/script-config.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReach(adminUrl) : false;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";

if (requireLive && !reachable) {
  throw new Error("Bootstrap replay regression requires PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;
const requests = [
  {
    idempotencyKey: "10000000-0000-4000-8000-000000000001",
    tenantId: "d0000000-0000-4000-8000-000000000001",
    slug: "iglesia-demostracion",
    displayName: "Iglesia Demostración",
    kind: "demo",
    timezone: "America/Santo_Domingo",
    locale: "es",
  },
  {
    idempotencyKey: "10000000-0000-4000-8000-000000000002",
    tenantId: "0a2a0000-0000-4000-8000-000000000001",
    slug: "iglesia-adventista-ozama",
    displayName: "Iglesia Adventista Ozama",
    kind: "real",
    timezone: "America/Santo_Domingo",
    locale: "es",
  },
] as const satisfies readonly TenantProvisionRequest[];

live("canonical bootstrap replay", () => {
  it("preserves Demo and pending Ozama byte-for-byte at the control/config/catalog/schema boundaries", async () => {
    if (!adminUrl) throw new Error("Local administrator URL is unavailable");
    const administrator = new URL(adminUrl);
    const control = new Pool({ connectionString: withoutDatabase(adminUrl, "nombramientos_control"), max: 1, connectionTimeoutMillis: 5_000 });
    const secrets = unreachableSecrets();
    const provisioner = new TenantProvisioner({
      admin: {
        host: administrator.hostname,
        port: Number(administrator.port || "5432"),
        user: decodeURIComponent(administrator.username),
        password: decodeURIComponent(administrator.password),
        database: administrator.pathname.slice(1) || "postgres",
        ssl: false,
      },
      catalog: { version: "unused-on-replay", departments: [], offices: [] },
      control,
      secrets,
      migrationsRoot: path.join(packageRoot, "migrations"),
    });
    try {
      const routes = await control.query<{ id: string; database_name: string }>(
        `SELECT id::text,database_name::text FROM tenants WHERE id=ANY($1::uuid[]) ORDER BY id`,
        [requests.map(({ tenantId }) => tenantId)],
      );
      expect(routes.rows).toHaveLength(2);
      const beforeControl = await controlSnapshot(control);
      const beforeTenants = await Promise.all(routes.rows.map((route) => tenantSnapshot(adminUrl, route.database_name)));

      const results = [];
      for (const request of requests) results.push(await provisioner.provision(request));

      const afterControl = await controlSnapshot(control);
      const afterTenants = await Promise.all(routes.rows.map((route) => tenantSnapshot(adminUrl, route.database_name)));
      expect(results).toMatchObject([
        { tenantId: requests[0].tenantId, state: "active", reused: true },
        { tenantId: requests[1].tenantId, state: "pending_activation", reused: true },
      ]);
      expect(afterControl).toEqual(beforeControl);
      expect(afterTenants).toEqual(beforeTenants);
      expect(secrets.hasSecret).not.toHaveBeenCalled();
      expect(secrets.getSecret).not.toHaveBeenCalled();
      expect(secrets.putSecret).not.toHaveBeenCalled();
    } finally {
      await provisioner.close();
      await control.end();
    }
  });
});

async function controlSnapshot(control: Pool): Promise<readonly unknown[]> {
  const snapshot = await control.query(
    `SELECT tenant.id::text,tenant.slug,tenant.display_name,tenant.kind,tenant.status,
            tenant.timezone,tenant.locale,tenant.database_host,tenant.database_port,
            tenant.database_name::text,tenant.runtime_role::text,tenant.runtime_secret_ref,
            tenant.credential_version,tenant.ssl_mode,tenant.version,tenant.activated_at,
            tenant.suspended_at,tenant.suspension_reason,tenant.decommission_request_id,
            tenant.created_at,tenant.updated_at,
            job.id::text AS job_id,job.idempotency_key::text,job.requested_slug,
            job.request_hash,job.state,job.attempt_count,job.last_error_code,
            job.created_at AS job_created_at,job.updated_at AS job_updated_at,
            job.completed_at,job.next_attempt_at
       FROM tenants tenant
       JOIN provisioning_jobs job ON job.tenant_id=tenant.id
      WHERE tenant.id=ANY($1::uuid[])
      ORDER BY tenant.id`,
    [requests.map(({ tenantId }) => tenantId)],
  );
  return snapshot.rows;
}

async function tenantSnapshot(connectionString: string, databaseName: string): Promise<string> {
  const pool = new Pool({ connectionString: withoutDatabase(connectionString, databaseName), max: 1, connectionTimeoutMillis: 5_000 });
  try {
    const snapshot = await pool.query<{ value: string }>(
      `SELECT jsonb_build_object(
         'settings',(SELECT to_jsonb(settings) FROM tenant_settings settings WHERE singleton=true),
         'migrations',(SELECT jsonb_agg(to_jsonb(migration) ORDER BY migration.name) FROM schema_migrations migration),
         'departments',(SELECT jsonb_agg(to_jsonb(department) ORDER BY department.id) FROM departments department),
         'offices',(SELECT jsonb_agg(to_jsonb(office) ORDER BY office.id) FROM offices office)
       )::text AS value`,
    );
    const value = snapshot.rows[0]?.value;
    if (!value) throw new Error(`Tenant snapshot was unavailable for ${databaseName}`);
    return value;
  } finally {
    await pool.end();
  }
}

function unreachableSecrets(): WritableSecretProvider & {
  hasSecret: ReturnType<typeof vi.fn>;
  getSecret: ReturnType<typeof vi.fn>;
  putSecret: ReturnType<typeof vi.fn>;
} {
  return {
    hasSecret: vi.fn(async () => { throw new Error("terminal bootstrap replay must not inspect secrets"); }),
    getSecret: vi.fn(async () => { throw new Error("terminal bootstrap replay must not read secrets"); }),
    putSecret: vi.fn(async () => { throw new Error("terminal bootstrap replay must not write secrets"); }),
  };
}

function discoverAdminUrl(): string | undefined {
  const file = path.join(packageRoot, ".local", "install.json");
  if (!existsSync(file)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { DATABASE_ADMIN_URL?: string };
    if (!parsed.DATABASE_ADMIN_URL) return undefined;
    return assertWorkspacePostgresUrl(parsed.DATABASE_ADMIN_URL, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReach(connectionString: string): Promise<boolean> {
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_000 });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === 55_432;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}
