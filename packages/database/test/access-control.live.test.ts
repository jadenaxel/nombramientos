import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool, type PoolClient } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { runMigrations } from "../src/migrations.js";
import { TenantStore } from "../src/tenant-store.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const workspacePort = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tenantMigrationDirectory = path.join(packageRoot, "migrations", "tenant");
const roleAssignmentMigration = "035_system_role_assignment_matrix.sql";
const transactionalGrantorLockMigration = "036_transactional_invitation_grantor_lock.sql";
const gestionChurchFederationMigration = "037_gestionchurch_federation.sql";
const explicitCustodianMigration = "038_gestionchurch_explicit_custodian_role.sql";
const deviceSessionMigration = "039_device_bound_http_sessions.sql";
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;
const supportedInvitationRoles = [
  "AUDITOR",
  "CHURCH_ADMIN",
  "COMMITTEE_CHAIR",
  "COMMITTEE_MEMBER",
  "COMMITTEE_SECRETARY",
  "TALLY_CUSTODIAN",
] as const;

if (requireLive && !reachable) {
  throw new Error("AC-05/06 live tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface Fixture {
  readonly cluster: Pool;
  readonly tenant: Pool;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly actorId: string;
  readonly targetId: string;
  readonly upgradedMigrations: readonly string[];
}

let fixture: Fixture | undefined;

live("AC-05/06 bounded tenant access administration", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 60_000);

  it("upgrades a populated tenant from head 034 through device-bound session head 039", async () => {
    const current = requireFixture();
    expect(current.upgradedMigrations).toEqual([
      roleAssignmentMigration,
      transactionalGrantorLockMigration,
      gestionChurchFederationMigration,
      explicitCustodianMigration,
      deviceSessionMigration,
    ]);
    const ledger = await current.tenant.query<{ count: number; head: string | null }>(
      `SELECT count(*)::int AS count,max(name) AS head
         FROM schema_migrations`,
    );
    expect(ledger.rows).toEqual([{ count: 41, head: deviceSessionMigration }]);
  });

  it("creates and edits only local roles inside the actor's delegable authority", async () => {
    const current = requireFixture();
    const capabilities = await withStore(current, current.actorId, (store) =>
      store.listPermissionCapabilities(current.actorId));
    expect(capabilities).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "member.read", possessed: true, delegable: true }),
      expect.objectContaining({ code: "role.manage", possessed: true, delegable: false }),
      expect.objectContaining({ code: "recovery.activate", possessed: true, delegable: false }),
    ]));
    expect(capabilities.some(({ code }) => code.startsWith("platform."))).toBe(false);

    const roleId = randomUUID();
    const idempotencyKey = randomUUID();
    const created = await withStore(current, current.actorId, (store) => store.createLocalRole({
      identityId: current.actorId,
      idempotencyKey,
      roleId,
      code: `LOCAL_HELPER_${randomBytes(5).toString("hex").toUpperCase()}`,
      name: { es: "Ayudante local", en: "Local helper", fr: "Assistant local" },
      permissionCodes: ["member.read"],
      delegablePermissionCodes: ["member.read"],
    }));
    expect(created).toEqual({ roleId, version: 1, affectedIdentityIds: [] });

    const role = (await withStore(current, current.actorId, (store) => store.listAccessRoles()))
      .find(({ id }) => id === roleId);
    expect(role).toMatchObject({
      id: roleId,
      system: false,
      version: 1,
      permissions: [{ code: "member.read", delegable: true }],
    });

    await expect(withStore(current, current.actorId, (store) => store.createLocalRole({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roleId: randomUUID(),
      code: `LOCAL_ADMIN_${randomBytes(5).toString("hex").toUpperCase()}`,
      name: { es: "Administrador local", en: "Local administrator", fr: "Administrateur local" },
      permissionCodes: ["role.manage"],
      delegablePermissionCodes: [],
    }))).rejects.toMatchObject({ code: "PERMISSION_ESCALATION" });

    await expect(withStore(current, current.actorId, (store) => store.createLocalRole({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roleId: randomUUID(),
      code: `LOCAL_PLATFORM_${randomBytes(4).toString("hex").toUpperCase()}`,
      name: { es: "Operador global", en: "Global operator", fr: "Opérateur global" },
      permissionCodes: ["platform.operation.read"],
      delegablePermissionCodes: [],
    }))).rejects.toMatchObject({ code: "PERMISSION_ESCALATION" });

    const churchAdmin = (await withStore(current, current.actorId, (store) => store.listAccessRoles()))
      .find(({ code }) => code === "CHURCH_ADMIN");
    if (!churchAdmin) throw new Error("CHURCH_ADMIN fixture role is unavailable");
    await expect(withStore(current, current.actorId, (store) => store.updateLocalRole({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roleId: churchAdmin.id,
      expectedVersion: churchAdmin.version,
      name: churchAdmin.name,
      permissionCodes: ["member.read"],
      delegablePermissionCodes: [],
    }))).rejects.toMatchObject({ code: "VERSION_CONFLICT" });

    const replayed = await withStore(current, current.actorId, (store) => store.createLocalRole({
      identityId: current.actorId,
      idempotencyKey,
      roleId,
      code: role!.code,
      name: { es: "Ayudante local", en: "Local helper", fr: "Assistant local" },
      permissionCodes: ["member.read"],
      delegablePermissionCodes: ["member.read"],
    }));
    expect(replayed).toEqual(created);
  });

  it("blocks self-escalation, versions bindings, and reports sessions affected by role edits", async () => {
    const current = requireFixture();
    const role = (await withStore(current, current.actorId, (store) => store.listAccessRoles()))
      .find(({ code }) => code.startsWith("LOCAL_HELPER_"));
    if (!role) throw new Error("Local role fixture is unavailable");

    await expect(withStore(current, current.actorId, (store) => store.grantRoleBinding({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      targetIdentityId: current.actorId,
      roleId: role.id,
    }))).rejects.toMatchObject({ code: "PERMISSION_ESCALATION" });

    const granted = await withStore(current, current.actorId, (store) => store.grantRoleBinding({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      targetIdentityId: current.targetId,
      roleId: role.id,
    }));
    expect(granted).toMatchObject({ identityId: current.targetId, roleId: role.id, active: true, version: 1 });

    const updated = await withStore(current, current.actorId, (store) => store.updateLocalRole({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roleId: role.id,
      expectedVersion: role.version,
      name: { es: "Ayudante verificado", en: "Verified helper", fr: "Assistant vérifié" },
      permissionCodes: ["member.manage", "member.read"],
      delegablePermissionCodes: ["member.read"],
    }));
    expect(updated).toMatchObject({ roleId: role.id, version: 2 });
    expect(updated.affectedIdentityIds).toEqual([current.targetId]);

    await expect(withStore(current, current.actorId, (store) => store.revokeRoleBinding({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      targetIdentityId: current.targetId,
      roleId: role.id,
      expectedVersion: 2,
    }))).rejects.toMatchObject({ code: "VERSION_CONFLICT" });

    const revoked = await withStore(current, current.actorId, (store) => store.revokeRoleBinding({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      targetIdentityId: current.targetId,
      roleId: role.id,
      expectedVersion: 1,
    }));
    expect(revoked).toMatchObject({ identityId: current.targetId, roleId: role.id, active: false, version: 2 });
    expect((await withStore(current, current.actorId, (store) => store.listRoleBindings()))
      .some(({ identityId, roleId }) => identityId === current.targetId && roleId === role.id)).toBe(false);

    const audit = await withStore(current, current.actorId, (store) => store.listAudit(20));
    expect(audit.verified).toBe(true);
    expect(audit.items.map((entry) => entry["action"])).toEqual(expect.arrayContaining([
      "access.role.created",
      "access.binding.granted",
      "access.role.updated",
      "access.binding.revoked",
    ]));
  });

  it("lets a church administrator assign every supported invitation role without vote permissions", async () => {
    const current = requireFixture();
    const operationalVotePermissions = await current.tenant.query<{ permission_code: string }>(
      `SELECT role_permission.permission_code
         FROM roles role
         JOIN role_permissions role_permission ON role_permission.role_id=role.id
        WHERE role.code='CHURCH_ADMIN'
          AND role_permission.permission_code IN ('proposal.submit','ballot.submit')
        ORDER BY role_permission.permission_code`,
    );
    expect(operationalVotePermissions.rows).toEqual([]);

    const matrix = await current.tenant.query<{
      grantor_role_code: string;
      assignable_role_code: string;
    }>(
      `SELECT grantor_role_code,assignable_role_code
         FROM system_role_assignment_matrix
        ORDER BY grantor_role_code,assignable_role_code`,
    );
    expect(matrix.rows).toEqual(supportedInvitationRoles.map((assignableRole) => ({
      grantor_role_code: "CHURCH_ADMIN",
      assignable_role_code: assignableRole,
    })));

    for (const role of supportedInvitationRoles) {
      await withStore(current, current.actorId, (store) => store.assertInvitationRoleDelegation({
        actorIdentityId: current.actorId,
        roles: [role],
      }));
    }
    await withStore(current, current.actorId, (store) => store.assertInvitationRoleDelegation({
      actorIdentityId: current.actorId,
      roles: ["COMMITTEE_MEMBER", "COMMITTEE_SECRETARY", "TALLY_CUSTODIAN"],
    }));
  });

  it("fails closed for malformed sets, an unlisted grantor, a missing matrix edge, and context mismatch", async () => {
    const current = requireFixture();
    await expectSqlRejected(current, current.actorId,
      "SELECT public.assert_local_role_definition_allowed($1,NULL::text[],ARRAY[]::text[])",
      [current.actorId],
      "23502");
    await expectSqlRejected(current, current.actorId,
      "SELECT public.apply_tenant_invitation_roles($1,$2,NULL::text[],$3,$4)",
      [randomUUID(), current.targetId, current.actorId, 1],
      "23502");
    await expectSqlRejected(current, current.actorId,
      "SELECT public.assert_tenant_invitation_role_delegation_allowed($1,ARRAY['COMMITTEE_MEMBER','COMMITTEE_MEMBER']::text[])",
      [current.actorId],
      "23514");
    await expectSqlRejected(current, current.actorId,
      "SELECT public.assert_tenant_invitation_role_delegation_allowed($1,ARRAY['LOCAL_UNKNOWN']::text[])",
      [current.actorId],
      "23514");
    await expectSqlRejected(current, current.targetId,
      "SELECT public.assert_tenant_invitation_role_delegation_allowed($1,ARRAY['COMMITTEE_MEMBER']::text[])",
      [current.actorId],
      "42501");

    const unlistedGrantorId = randomUUID();
    const unlistedRoleId = randomUUID();
    await current.tenant.query(
      `INSERT INTO roles(id,code,name_i18n,system_role)
       VALUES ($1,$2,'{"es":"Gestor aislado","en":"Isolated manager","fr":"Gestionnaire isolé"}'::jsonb,false)`,
      [unlistedRoleId, `LOCAL_MATRIX_${randomBytes(5).toString("hex").toUpperCase()}`],
    );
    await current.tenant.query(
      `INSERT INTO role_permissions(role_id,permission_code,delegable)
       VALUES ($1,'role.manage',false)`,
      [unlistedRoleId],
    );
    await current.tenant.query(
      `INSERT INTO role_bindings(identity_id,role_id)
       VALUES ($1,$2)`,
      [unlistedGrantorId, unlistedRoleId],
    );
    await expectSqlRejected(current, unlistedGrantorId,
      "SELECT public.assert_tenant_invitation_role_delegation_allowed($1,ARRAY['AUDITOR']::text[])",
      [unlistedGrantorId],
      "42501");

    const client = await current.tenant.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `DELETE FROM system_role_assignment_matrix
          WHERE grantor_role_code='CHURCH_ADMIN' AND assignable_role_code='COMMITTEE_MEMBER'`,
      );
      await setContext(client, current.tenantId, current.actorId);
      await expect(client.query(
        "SELECT public.assert_tenant_invitation_role_delegation_allowed($1,ARRAY['COMMITTEE_MEMBER']::text[])",
        [current.actorId],
      )).rejects.toMatchObject({ code: "42501" });
    } finally {
      await client.query("ROLLBACK").catch(() => undefined);
      client.release();
    }
  });

  it("serializes invitation activation with concurrent revocation of the grantor binding", async () => {
    const current = requireFixture();
    const churchAdmin = await current.tenant.query<{ role_id: string; version: number }>(
      `SELECT binding.role_id,binding.version
         FROM role_bindings binding
         JOIN roles role ON role.id=binding.role_id
        WHERE binding.identity_id=$1
          AND binding.revoked_at IS NULL
          AND role.code='CHURCH_ADMIN'`,
      [current.actorId],
    );
    const binding = churchAdmin.rows[0];
    if (!binding) throw new Error("CHURCH_ADMIN grantor binding is unavailable");

    const invitationId = randomUUID();
    const invitedIdentityId = randomUUID();
    const revocation = await current.tenant.connect();
    let activation: PoolClient | undefined;
    try {
      activation = await current.tenant.connect();
      await revocation.query("BEGIN");
      await revocation.query(
        `UPDATE role_bindings
            SET revoked_at=clock_timestamp(),version=version+1,updated_at=clock_timestamp()
          WHERE identity_id=$1 AND role_id=$2 AND revoked_at IS NULL AND version=$3`,
        [current.actorId, binding.role_id, binding.version],
      );

      await activation.query("BEGIN");
      await activation.query("SET LOCAL lock_timeout='250ms'");
      await setContext(activation, current.tenantId, current.actorId);
      await expect(activation.query(
        "SELECT public.apply_tenant_invitation_roles($1,$2,ARRAY['AUDITOR']::text[],$3,$4)",
        [invitationId, invitedIdentityId, current.actorId, 1],
      )).rejects.toMatchObject({ code: "55P03" });
      await activation.query("ROLLBACK");

      await revocation.query("COMMIT");

      await activation.query("BEGIN");
      await setContext(activation, current.tenantId, current.actorId);
      await expect(activation.query(
        "SELECT public.apply_tenant_invitation_roles($1,$2,ARRAY['AUDITOR']::text[],$3,$4)",
        [invitationId, invitedIdentityId, current.actorId, 1],
      )).rejects.toMatchObject({ code: "42501" });
      await activation.query("ROLLBACK");

      const residue = await current.tenant.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM role_bindings WHERE source_invitation_id=$1 OR identity_id=$2",
        [invitationId, invitedIdentityId],
      );
      expect(residue.rows[0]?.count).toBe(0);
    } finally {
      await activation?.query("ROLLBACK").catch(() => undefined);
      await revocation.query("ROLLBACK").catch(() => undefined);
      activation?.release();
      revocation.release();
    }
  });
});

async function createFixture(databaseAdminUrl: string): Promise<Fixture> {
  const databaseName = `nom_access_test_${randomBytes(12).toString("hex")}`;
  const cluster = new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), max: 1 });
  const tenant = new Pool({ connectionString: databaseUrl(databaseAdminUrl, databaseName), max: 3 });
  try {
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [databaseName]);
    const pre035Directory = await createPre035MigrationDirectory();
    try {
      const applied = await runMigrations(tenant, { scope: "tenant", directory: pre035Directory });
      if (applied.length !== 36 || applied.at(-1) !== "034_invitation_role_delegation.sql") {
        throw new Error("The access-control upgrade fixture did not stop exactly at tenant head 034");
      }
    } finally {
      await rm(pre035Directory, { recursive: true, force: true });
    }
    const tenantId = randomUUID();
    const actorId = randomUUID();
    const targetId = randomUUID();
    await tenant.query(
      `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state)
       VALUES ($1,'AC-05 temporary tenant','demo','America/La_Paz','es','ready')`,
      [tenantId],
    );
    const binding = await tenant.query(
      `INSERT INTO role_bindings(identity_id,role_id)
       SELECT $1,id FROM roles WHERE code='CHURCH_ADMIN'`,
      [actorId],
    );
    if (binding.rowCount !== 1) throw new Error("CHURCH_ADMIN fixture role is unavailable");

    const preUpgradeClient = await tenant.connect();
    try {
      await preUpgradeClient.query("BEGIN");
      await setContext(preUpgradeClient, tenantId, actorId);
      let legacyBoundaryDenied = false;
      try {
        await preUpgradeClient.query(
          "SELECT public.assert_tenant_invitation_role_delegation_allowed($1,ARRAY['COMMITTEE_MEMBER']::text[])",
          [actorId],
        );
      } catch (error) {
        if (postgresErrorCode(error) !== "42501") throw error;
        legacyBoundaryDenied = true;
      }
      if (!legacyBoundaryDenied) {
        throw new Error("Tenant head 034 unexpectedly allowed CHURCH_ADMIN to assign COMMITTEE_MEMBER");
      }
    } finally {
      await preUpgradeClient.query("ROLLBACK").catch(() => undefined);
      preUpgradeClient.release();
    }

    const upgradedMigrations = await runMigrations(tenant, {
      scope: "tenant",
      directory: tenantMigrationDirectory,
    });
    if (
      upgradedMigrations.length !== 5
      || upgradedMigrations[0] !== roleAssignmentMigration
      || upgradedMigrations[1] !== transactionalGrantorLockMigration
      || upgradedMigrations[2] !== gestionChurchFederationMigration
      || upgradedMigrations[3] !== explicitCustodianMigration
      || upgradedMigrations[4] !== deviceSessionMigration
    ) {
      throw new Error("The tenant upgrade did not apply exactly migrations 035, 036, 037, 038 and 039");
    }
    return { cluster, tenant, databaseName, tenantId, actorId, targetId, upgradedMigrations };
  } catch (error) {
    return cleanupAfterFailure(error, () => cleanupAccessDatabase(cluster, tenant, databaseName), "Access-control fixture setup");
  }
}

async function createPre035MigrationDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "nom-invitation-role-upgrade-"));
  try {
    const migrations = (await readdir(tenantMigrationDirectory))
      .filter((name) => /^\d+_.+\.sql$/u.test(name) && name.localeCompare(roleAssignmentMigration) < 0)
      .sort((left, right) => left.localeCompare(right));
    for (const migration of migrations) {
      await copyFile(
        path.join(tenantMigrationDirectory, migration),
        path.join(directory, migration),
      );
    }
    return directory;
  } catch (error) {
    await rm(directory, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}

function postgresErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) return undefined;
  const code = error.code;
  return typeof code === "string" ? code : undefined;
}

async function withStore<T>(current: Fixture, identityId: string, work: (store: TenantStore) => Promise<T>): Promise<T> {
  const client = await current.tenant.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, current.tenantId, identityId);
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

async function setContext(client: PoolClient, tenantId: string, identityId: string): Promise<void> {
  await client.query(
    `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
            set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
    [tenantId, identityId, randomUUID(), randomUUID()],
  );
}

async function expectSqlRejected(
  current: Fixture,
  identityId: string,
  sql: string,
  values: readonly unknown[],
  expectedCode: string,
): Promise<void> {
  const client = await current.tenant.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, current.tenantId, identityId);
    await expect(client.query(sql, [...values])).rejects.toMatchObject({ code: expectedCode });
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
}

async function cleanupFixture(current: Fixture): Promise<void> {
  await cleanupAccessDatabase(current.cluster, current.tenant, current.databaseName);
}

async function cleanupAccessDatabase(cluster: Pool, tenant: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [tenant], assertSafeDatabaseName: assertAccessDatabaseName }],
    label: "Temporary access-control database",
  });
}

function assertAccessDatabaseName(databaseName: string): void {
  if (!/^nom_access_test_[0-9a-f]{24}$/u.test(databaseName)) throw new Error("Refusing to drop a non-access-test database");
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the access-control test statement");
  await pool.query(sql);
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
    return assertWorkspacePostgresUrl(candidate, "nom_admin", "postgres").toString();
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
    await pool.end();
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)) throw new Error("Invalid local database name");
  const url = new URL(databaseAdminUrl);
  if (!isLoopback(url.hostname) || Number(url.port || "5432") !== workspacePort) {
    throw new Error("Access-control tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}

function requireFixture(): Fixture {
  if (!fixture) throw new Error("AC-05/06 live fixture is unavailable");
  return fixture;
}
