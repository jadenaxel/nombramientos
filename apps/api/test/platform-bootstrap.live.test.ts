import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseRuntime, runMigrations, type SecretProvider } from "@nombramientos/database";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";
import {
  closePoolOwnerAndConfirmDrained,
  collectCleanupFailure,
  dropEphemeralDatabase,
  dropEphemeralRole,
  endPoolAndConfirmDrained,
} from "./ephemeral-postgres-cleanup.js";
import { assertExactWorkspaceAdminUrl } from "./local-test-database-boundary.js";

const workspacePort = 55_432;
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
if (requireLive && !reachable) throw new Error("Platform bootstrap API live test requires PostgreSQL 18 on loopback:55432");
const live = reachable ? describe.sequential : describe.skip;

live("platform administrator bootstrap HTTP boundary", () => {
  let cluster: Pool | undefined;
  let control: Pool | undefined;
  let runtime: DatabaseRuntime | undefined;
  let app: Awaited<ReturnType<typeof buildServer>> | undefined;
  let databaseName = "";
  let runtimeRole = "";
  let token = "";

  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    databaseName = `nom_bootstrap_api_${randomBytes(10).toString("hex")}`;
    runtimeRole = `nom_bootstrap_runtime_${randomBytes(8).toString("hex")}`;
    const runtimePassword = randomBytes(32).toString("base64url");
    cluster = new Pool({ connectionString: databaseUrl(adminUrl, "postgres"), max: 1 });
    await executeFormatted(
      cluster,
      "SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L', $1::text, $2::text) AS sql",
      [runtimeRole, runtimePassword],
    );
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [databaseName]);
    control = new Pool({ connectionString: databaseUrl(adminUrl, databaseName), max: 2 });
    await runMigrations(control, {
      scope: "control",
      directory: path.join(workspaceRoot, "packages", "database", "migrations", "control"),
    });
    await grantBootstrapRuntime(control, cluster, databaseName, runtimeRole);
    const anchorTenantId = "d0000000-0000-4000-8000-000000000001";
    await control.query(
      `INSERT INTO tenants(
         id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,runtime_secret_ref,
         database_port,activated_at
       ) VALUES ($1,'bootstrap-auth-anchor','Bootstrap authentication anchor','demo','active','America/La_Paz','es',
                 'nom_bootstrap_unreachable','nom_bootstrap_unreachable','tenant-db/bootstrap/runtime/v1',55432,clock_timestamp())`,
      [anchorTenantId],
    );
    token = randomBytes(32).toString("base64url");
    await control.query(
      `INSERT INTO platform_admin_bootstrap_tokens(token_hash,purpose,anchor_tenant_id,expires_at)
       VALUES ($1,'bootstrap',$2,clock_timestamp()+interval '1 hour')`,
      [sha256(token), anchorTenantId],
    );
    const runtimeUrl = databaseUrlForRole(adminUrl, databaseName, runtimeRole, runtimePassword);
    runtime = new DatabaseRuntime({
      control: { connectionString: runtimeUrl, max: 3, ssl: false },
      secretProvider: new DeniedSecretProvider(),
      tenantPoolMax: 1,
      tenantPoolIdleMs: 500,
    });
    const config: ApiConfig = {
      environment: "test",
      host: "127.0.0.1",
      port: 4000,
      corsOrigins: new Set(["http://localhost:3000"]),
      secureCookies: false,
      sessionTtlSeconds: 3_600,
      webauthn: {
        rpName: "Nombramientos",
        rpId: "localhost",
        expectedOrigins: ["http://localhost:3000"],
        challengeTtlSeconds: 300,
        stepUpTtlSeconds: 120,
      },
      authEncryptionKey: Buffer.alloc(32, 11),
      controlDatabaseUrl: runtimeUrl,
      secretMasterKey: Buffer.alloc(32, 12),
      secretFile: "unused-bootstrap-test",
      tenantPoolMax: 1,
      tenantPoolIdleMs: 500,
    };
    // The fixture owns the runtime explicitly so cleanup can attest every pg
    // client removal before a non-FORCE DROP DATABASE.
    app = await buildServer({
      config,
      database: runtime,
      logger: false,
      closeDatabaseOnShutdown: false,
    });
  }, 60_000);

  afterAll(async () => {
    const failures: Error[] = [];
    await collectCleanupFailure(failures, "bootstrap API close", async () => app?.close());
    if (runtime) {
      await collectCleanupFailure(failures, "bootstrap runtime close", async () => {
        await closePoolOwnerAndConfirmDrained(
          [{ pool: runtime!.controlPool, label: "bootstrap runtime control pool" }],
          async () => runtime!.close(),
          "bootstrap database runtime close",
        );
      });
    }
    if (control) {
      await collectCleanupFailure(failures, "bootstrap migration control pool close", async () => {
        await endPoolAndConfirmDrained(control!, "bootstrap migration control pool");
      });
    }
    try {
      await collectCleanupFailure(failures, "bootstrap temporary database drop", async () => {
        if (cluster && databaseName) {
          await dropEphemeralDatabase(cluster, databaseName, {
            pattern: /^nom_bootstrap_api_[0-9a-f]{20}$/u,
            label: "bootstrap test database",
          });
        }
      });
      await collectCleanupFailure(failures, "bootstrap temporary role drop", async () => {
        if (cluster && runtimeRole) {
          await dropEphemeralRole(cluster, runtimeRole, {
            pattern: /^nom_bootstrap_runtime_[0-9a-f]{16}$/u,
            label: "bootstrap test runtime role",
          });
        }
      });
      await collectCleanupFailure(failures, "bootstrap temporary resource residue check", async () => {
        if (!cluster) return;
        const residue = await cluster.query<{ databases: number; roles: number }>(
          `SELECT
             (SELECT count(*)::int FROM pg_database WHERE datname=$1) AS databases,
             (SELECT count(*)::int FROM pg_roles WHERE rolname=$2) AS roles`,
          [databaseName, runtimeRole],
        );
        if (residue.rows[0]?.databases !== 0 || residue.rows[0]?.roles !== 0) {
          throw new Error("Ephemeral bootstrap resources remain after cleanup");
        }
      });
    } finally {
      if (cluster) {
        await collectCleanupFailure(failures, "bootstrap maintenance pool close", async () => {
          await endPoolAndConfirmDrained(cluster!, "bootstrap maintenance pool");
        });
      }
    }
    if (failures.length > 0) {
      throw new AggregateError(failures, "Platform bootstrap fixture cleanup failed safely");
    }
  }, 60_000);

  it("creates one enrollment-only session and blocks every global operation before MFA", async () => {
    if (!app || !control || !runtime) throw new Error("Bootstrap API fixture is unavailable");
    expect((await runtime.controlPool.query<{ current_user: string }>("SELECT current_user")).rows[0]?.current_user)
      .toBe(runtimeRole);
    const payload = {
      token,
      email: "first.platform.admin@invalid.example",
      displayName: "First Platform Administrator",
      password: "Ultra#Secure2026!Bootstrap",
    };
    const response = await app.inject({
      method: "POST",
      url: "/v1/auth/platform-bootstrap/accept",
      headers: { origin: "http://localhost:3000", "user-agent": "platform-bootstrap-live" },
      payload,
    });
    expect(response.statusCode).toBe(201);
    const data = response.json<{ data: Record<string, unknown> }>().data;
    expect(data).toMatchObject({
      status: "mfa_enrollment_required",
      authenticated: true,
      permissions: [],
      keyGrant: null,
      contentAccess: false,
      keyAccess: false,
      security: { mfaRequired: true, mfaEnabled: false, enrollmentOnly: true, assurance: "enrollment_only" },
    });
    expect(JSON.stringify(data)).not.toContain(payload.password);
    expect(JSON.stringify(data)).not.toContain(token);
    const session = response.cookies.find(({ name }) => name === "nom_session");
    const csrf = response.cookies.find(({ name }) => name === "nom_csrf");
    expect(session?.httpOnly).toBe(true);
    expect(csrf?.value).toBeTruthy();
    if (!session || !csrf) throw new Error("Bootstrap cookies were not issued");
    const blocked = await app.inject({
      method: "GET",
      url: "/v1/platform/tenants",
      headers: {
        origin: "http://localhost:3000",
        "user-agent": "platform-bootstrap-live",
        cookie: `nom_session=${session.value}; nom_csrf=${csrf.value}`,
      },
    });
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json<{ error: { code: string } }>().error.code).toBe("MFA_ENROLLMENT_REQUIRED");

    const persisted = await control.query<{
      token_status: string; mfa_required: boolean; mfa_enabled: boolean; assurance_level: string;
      platform_admins: number; audit_events: number;
    }>(
      `SELECT bootstrap.status AS token_status,identity.mfa_required,identity.mfa_enabled,session.assurance_level,
              (SELECT count(*)::int FROM platform_role_bindings WHERE identity_id=identity.id AND role_code='platform_admin') AS platform_admins,
              (SELECT count(*)::int FROM platform_audit_events WHERE actor_identity_id=identity.id AND action='platform.admin_bootstrap_consumed') AS audit_events
         FROM platform_admin_bootstrap_tokens bootstrap
         JOIN platform_identities identity ON identity.id=bootstrap.consumed_by_identity_id
         JOIN auth_sessions session ON session.id=bootstrap.consumed_session_id
        WHERE bootstrap.token_hash=$1`,
      [sha256(token)],
    );
    expect(persisted.rows[0]).toEqual({
      token_status: "consumed", mfa_required: true, mfa_enabled: false,
      assurance_level: "enrollment_only", platform_admins: 1, audit_events: 1,
    });

    const replay = await app.inject({
      method: "POST",
      url: "/v1/auth/platform-bootstrap/accept",
      headers: { origin: "http://localhost:3000", "user-agent": "platform-bootstrap-live" },
      payload: { ...payload, email: "replay@invalid.example", displayName: "Replay Denied" },
    });
    expect(replay.statusCode).toBe(400);
    expect(replay.json<{ error: { code: string } }>().error.code).toBe("PLATFORM_BOOTSTRAP_INVALID");
  }, 30_000);
});

class DeniedSecretProvider implements SecretProvider {
  public async getSecret(): Promise<string> {
    throw new Error("Bootstrap enrollment must never access a tenant secret");
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
    return assertExactWorkspaceAdminUrl(candidate);
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
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === workspacePort;
  } catch {
    return false;
  } finally {
    await endPoolAndConfirmDrained(pool, "bootstrap reachability pool");
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)) throw new Error("Invalid local database name");
  const url = new URL(databaseAdminUrl);
  if (!isLoopback(url.hostname) || Number(url.port || "5432") !== workspacePort) {
    throw new Error("Bootstrap tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function databaseUrlForRole(
  databaseAdminUrl: string,
  databaseName: string,
  role: string,
  password: string,
): string {
  const url = new URL(databaseUrl(databaseAdminUrl, databaseName));
  url.username = role;
  url.password = password;
  return url.toString();
}

async function grantBootstrapRuntime(
  control: Pool,
  cluster: Pool,
  databaseName: string,
  role: string,
): Promise<void> {
  await executeFormatted(
    cluster,
    "SELECT format('GRANT CONNECT ON DATABASE %I TO %I', $1::text, $2::text) AS sql",
    [databaseName, role],
  );
  await control.query("REVOKE ALL ON SCHEMA public FROM PUBLIC");
  await executeFormatted(control, "SELECT format('GRANT USAGE ON SCHEMA public TO %I', $1::text) AS sql", [role]);
  for (const table of [
    "tenants", "provisioning_jobs", "platform_worker_status", "platform_role_bindings",
    "platform_identities", "tenant_memberships", "auth_sessions",
  ]) {
    await executeFormatted(
      control,
      "SELECT format('GRANT SELECT ON TABLE %I TO %I', $1::text, $2::text) AS sql",
      [table, role],
    );
  }
  await executeFormatted(
    control,
    "SELECT format('GRANT SELECT,INSERT ON TABLE platform_audit_events TO %I', $1::text) AS sql",
    [role],
  );
  await executeFormatted(
    control,
    `SELECT format(
       'GRANT UPDATE(last_seen_at,idle_expires_at,last_user_agent_hash,user_agent_change_count,user_agent_context_changed_at,last_ip_prefix_hash,ip_change_count,ip_context_changed_at,revoked_at,revoke_reason) ON TABLE auth_sessions TO %I',
       $1::text
     ) AS sql`,
    [role],
  );
  await executeFormatted(
    control,
    "SELECT format('GRANT USAGE,SELECT ON SEQUENCE platform_audit_events_sequence_seq TO %I', $1::text) AS sql",
    [role],
  );
  await executeFormatted(
    control,
    `SELECT format(
       'GRANT EXECUTE ON FUNCTION consume_platform_admin_bootstrap(text,text,text,text,text,uuid,uuid,text,text,timestamptz,text,text) TO %I',
       $1::text
     ) AS sql`,
    [role],
  );
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the bootstrap test statement");
  await pool.query(sql);
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
