import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runMigrations } from "@nombramientos/database";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  cleanupStageError,
  collectCleanupFailure,
  dropEphemeralDatabase,
  dropEphemeralRole,
  endPoolAndConfirmDrained,
} from "./ephemeral-postgres-cleanup.js";
import { assertExactWorkspaceAdminUrl } from "./local-test-database-boundary.js";

const workspacePort = 55_432;
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const migrationSourceRoot = path.join(workspaceRoot, "packages", "database", "migrations");
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Initial-administrator audit requires PostgreSQL 18 on loopback:55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface Fixture {
  readonly cluster: Pool;
  readonly control: Pool;
  readonly controlDatabase: string;
  readonly tenantId: string;
  readonly tenantDatabase: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly invitationId: string;
  readonly invitationToken: string;
  readonly recipientEmail: string;
  readonly platformAdminId: string;
  readonly migrationRoot: string;
}

let fixture: Fixture | undefined;

live("initial tenant administrator acceptance at control 023 / tenant 035", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 90_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 90_000);

  it("reproduces the fail-closed but unusable initial-admin invitation", async () => {
    const current = requireFixture(fixture);
    const before = await observe(current);
    expect(before).toEqual({
      controlHead: "023_atomic_authentication_context_lock.sql",
      tenantHead: "035_system_role_assignment_matrix.sql",
      invitationStatus: "pending",
      grantorMemberships: 0,
      recipientIdentities: 0,
      recipientMemberships: 0,
      recipientBindings: 0,
    });

    await expect(attemptHistoricalAcceptance(current)).resolves.toBe("invalid");
    expect(await observe(current)).toEqual(before);
  }, 30_000);

  it("proves the cross-database crash window has no stale-acceptance reconciliation", async () => {
    const current = requireFixture(fixture);
    await current.control.query(
      `INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default)
       VALUES ($1,$2,'active',true)`,
      [current.tenantId, current.platformAdminId],
    );
    const tenant = new Pool({ connectionString: databaseUrl(requireAdminUrl(), current.tenantDatabase), max: 1 });
    try {
      const granted = await tenant.query(
        `INSERT INTO role_bindings(identity_id,role_id)
         SELECT $1,id FROM roles WHERE code='CHURCH_ADMIN'`,
        [current.platformAdminId],
      );
      expect(granted.rowCount).toBe(1);
    } finally {
      await endPoolAndConfirmDrained(tenant, "initial-admin role audit tenant pool");
    }

    const acceptanceId = randomUUID();
    const identityId = randomUUID();
    const claim = await claimHistoricalInvitation023(current.control, {
      token: current.invitationToken,
      normalizedEmail: current.recipientEmail,
      acceptanceId,
      identityId,
    });
    expect(claim).toMatchObject({
      invitationId: current.invitationId,
      tenantId: current.tenantId,
      identityId,
      roles: ["CHURCH_ADMIN"],
      createdByIdentityId: current.platformAdminId,
    });
    if (!claim) throw new Error("Initial-admin crash audit could not claim its invitation");
    // This fixture deliberately stops at tenant 035. Invoke that historical
    // four-argument boundary directly so the diagnostic remains executable
    // after TenantStore advances to the fenced five-argument 036 contract.
    const historicalTenant = new Pool({
      connectionString: databaseUrl(requireAdminUrl(), current.tenantDatabase),
      max: 1,
    });
    try {
      await historicalTenant.query("BEGIN");
      await historicalTenant.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [current.tenantId, current.platformAdminId, acceptanceId, randomUUID()],
      );
      const applied = await historicalTenant.query<{ bound_count: number }>(
        "SELECT apply_tenant_invitation_roles($1,$2,ARRAY['CHURCH_ADMIN']::text[],$3)::int AS bound_count",
        [current.invitationId, identityId, current.platformAdminId],
      );
      expect(applied.rows[0]?.bound_count).toBe(1);
      await historicalTenant.query("COMMIT");
    } catch (error) {
      try {
        await historicalTenant.query("ROLLBACK");
      } catch (rollbackError) {
        throw new AggregateError(
          [
            cleanupStageError("historical invitation transaction", error),
            cleanupStageError("historical invitation rollback", rollbackError),
          ],
          "Historical invitation transaction and rollback failed",
        );
      }
      throw error;
    } finally {
      await endPoolAndConfirmDrained(historicalTenant, "historical invitation tenant pool");
    }

    // Simulate termination after the tenant transaction commits and before
    // complete_tenant_invitation_acceptance starts in the control database.
    await current.control.query(
      "UPDATE tenant_invitations SET acceptance_started_at=clock_timestamp()-interval '20 minutes' WHERE id=$1",
      [current.invitationId],
    );
    const stranded = await observe(current);
    expect(stranded).toMatchObject({
      invitationStatus: "accepting",
      recipientIdentities: 0,
      recipientMemberships: 0,
      recipientBindings: 1,
    });

    // The only periodic-ish read path ages pending rows, but it neither
    // reconciles stale accepting rows nor removes tenant-side grants.
    const listed = await current.control.query<{ status: string }>(
      "SELECT status FROM tenant_invitations WHERE id=$1",
      [current.invitationId],
    );
    expect(listed.rows[0]?.status).toBe("accepting");
    const retry = await claimHistoricalInvitation023(current.control, {
      token: current.invitationToken,
      normalizedEmail: current.recipientEmail,
      acceptanceId: randomUUID(),
      identityId: randomUUID(),
    });
    expect(retry).toBeNull();
    expect(await observe(current)).toEqual(stranded);
  }, 30_000);
});

interface HistoricalInvitationClaim023 {
  readonly invitationId: string;
  readonly acceptanceId: string;
  readonly identityId: string;
  readonly tenantId: string;
  readonly email: string;
  readonly normalizedEmail: string;
  readonly roles: string[];
  readonly createdByIdentityId: string;
}

async function claimHistoricalInvitation023(
  control: Pool,
  input: {
    readonly token: string;
    readonly normalizedEmail: string;
    readonly acceptanceId: string;
    readonly identityId: string;
  },
): Promise<HistoricalInvitationClaim023 | null> {
  const client = await control.connect();
  try {
    await client.query("BEGIN");
    const claimed = await client.query<{
      id: string;
      tenant_id: string;
      email: string;
      normalized_email: string;
      role_codes: string[];
      created_by_identity_id: string;
    }>(
      `UPDATE tenant_invitations invitation
          SET status='accepting',acceptance_id=$3,acceptance_identity_id=$4,
              acceptance_started_at=clock_timestamp(),updated_at=clock_timestamp(),
              version=invitation.version+1
        WHERE invitation.token_hash=$1
          AND invitation.normalized_email=$2
          AND invitation.status='pending'
          AND invitation.expires_at>clock_timestamp()
      RETURNING invitation.id::text,invitation.tenant_id::text,invitation.email,
                invitation.normalized_email,invitation.role_codes,
                invitation.created_by_identity_id::text`,
      [sha256(input.token), input.normalizedEmail, input.acceptanceId, input.identityId],
    );
    await client.query("COMMIT");
    const row = claimed.rows[0];
    if (!row) return null;
    if (claimed.rowCount !== 1) throw new Error("Historical invitation claim was not unique");
    return {
      invitationId: row.id,
      acceptanceId: input.acceptanceId,
      identityId: input.identityId,
      tenantId: row.tenant_id,
      email: row.email,
      normalizedEmail: row.normalized_email,
      roles: row.role_codes,
      createdByIdentityId: row.created_by_identity_id,
    };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      throw new AggregateError(
        [
          cleanupStageError("historical invitation claim", error),
          cleanupStageError("historical invitation claim rollback", rollbackError),
        ],
        "Historical invitation claim and rollback failed",
      );
    }
    throw error;
  } finally {
    client.release();
  }
}

async function attemptHistoricalAcceptance(current: Fixture): Promise<"invalid"> {
  const claim = await claimHistoricalInvitation023(current.control, {
    token: current.invitationToken,
    normalizedEmail: current.recipientEmail,
    acceptanceId: randomUUID(),
    identityId: randomUUID(),
  });
  if (!claim) throw new Error("Historical invitation unexpectedly could not be claimed");
  const tenant = new Pool({ connectionString: databaseUrl(requireAdminUrl(), current.tenantDatabase), max: 1 });
  try {
    await tenant.query("BEGIN");
    await tenant.query(
      `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
              set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
      [claim.tenantId, claim.createdByIdentityId, claim.acceptanceId, randomUUID()],
    );
    await tenant.query(
      "SELECT apply_tenant_invitation_roles($1,$2,$3::text[],$4)",
      [claim.invitationId, claim.identityId, claim.roles, claim.createdByIdentityId],
    );
    await tenant.query("ROLLBACK");
    throw new Error("Historical initial administrator unexpectedly crossed the tenant authority boundary");
  } catch (error) {
    try {
      await tenant.query("ROLLBACK");
    } catch (rollbackError) {
      throw new AggregateError(
        [
          cleanupStageError("historical acceptance tenant transaction", error),
          cleanupStageError("historical acceptance tenant rollback", rollbackError),
        ],
        "Historical acceptance transaction and rollback failed",
      );
    }
    if (postgresCode(error) !== "42501") {
      throw sanitizedHistoricalError("Historical tenant authorization failed unexpectedly", error);
    }
  } finally {
    await endPoolAndConfirmDrained(tenant, "historical acceptance tenant pool");
  }

  const compensated = await current.control.query(
    `UPDATE tenant_invitations
        SET status='pending',acceptance_id=NULL,acceptance_identity_id=NULL,
            acceptance_started_at=NULL,updated_at=clock_timestamp(),version=version+1
      WHERE id=$1 AND status='accepting' AND acceptance_id=$2 AND acceptance_identity_id=$3`,
    [claim.invitationId, claim.acceptanceId, claim.identityId],
  );
  if (compensated.rowCount !== 1) {
    throw new Error("Historical invitation compensation did not restore the exact claim");
  }
  return "invalid";
}

function postgresCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}

function sanitizedHistoricalError(label: string, error: unknown): Error {
  const code = postgresCode(error);
  return new Error(`${label}${code ? ` (${code})` : ""}`);
}

async function createFixture(databaseAdminUrl: string): Promise<Fixture> {
  const runId = randomUUID();
  const suffix = runId.replaceAll("-", "");
  const controlDatabase = `nom_initial_admin_audit_${suffix.slice(0, 20)}`;
  const tenantId = randomUUID();
  const tenantSuffix = tenantId.replaceAll("-", "");
  const tenantDatabase = `nom_t_${tenantSuffix}`;
  const ownerRole = `nom_o_${tenantSuffix}`;
  const runtimeRole = `nom_r_${tenantSuffix}`;
  const platformAdminId = randomUUID();
  const invitationToken = randomBytes(32).toString("base64url");
  const recipientEmail = `initial-admin-${suffix.slice(0, 12)}@invalid.example`;
  const migrationRoot = await createHistoricalMigrationRoot();
  const cluster = new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), max: 1 });
  let control: Pool | undefined;
  try {
    await executeFormatted(
      cluster,
      "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
      [controlDatabase],
    );
    control = new Pool({
      connectionString: databaseUrl(databaseAdminUrl, controlDatabase),
      application_name: "nombramientos-initial-admin-audit-control",
      max: 3,
    });
    const appliedControl = await runMigrations(control, {
      scope: "control",
      directory: path.join(migrationRoot, "control"),
    });
    if (appliedControl.at(-1) !== "023_atomic_authentication_context_lock.sql") {
      throw new Error("Initial-admin audit did not stop exactly at control head 023");
    }
    await control.query(
      `INSERT INTO platform_identities(
         id,email,normalized_email,display_name,password_hash,password_provisioned,
         mfa_enabled,mfa_required,status
       ) VALUES ($1,$2,$2,'Ephemeral Platform Administrator','disabled',false,false,false,'active')`,
      [platformAdminId, `platform-admin-${suffix.slice(0, 12)}@invalid.example`],
    );
    await control.query(
      "INSERT INTO platform_role_bindings(identity_id,role_code) VALUES ($1,'platform_admin')",
      [platformAdminId],
    );

    // This is a historical audit fixture, not a production provisioning test.
    // Build the exact control-023 / tenant-035 state directly instead of
    // running today's provisioner, whose intentional 036 capability and
    // canonical-inventory gates cannot exist at this historical boundary.
    const runtimePassword = randomBytes(32).toString("base64url");
    const runtimeSecretReference = `tenant-db/${tenantId}/runtime/v1`;
    const invitationId = await createHistoricalTenantFixture({
      databaseAdminUrl,
      migrationRoot,
      cluster,
      control,
      tenantId,
      slug: `initial-admin-${tenantSuffix.slice(0, 12)}`,
      displayName: "Initial administrator audit tenant",
      tenantDatabase,
      ownerRole,
      runtimeRole,
      runtimePassword,
      runtimeSecretReference,
      recipientEmail,
      invitationToken,
      platformAdminId,
    });

    return {
      cluster,
      control,
      controlDatabase,
      tenantId,
      tenantDatabase,
      ownerRole,
      runtimeRole,
      invitationId,
      invitationToken,
      recipientEmail,
      platformAdminId,
      migrationRoot,
    };
  } catch (error) {
    const failures = [cleanupStageError("initial-admin fixture setup", error)];
    if (control) {
      const failedControl = control;
      await collectCleanupFailure(failures, "initial-admin control pool close after setup failure", async () => {
        await endPoolAndConfirmDrained(failedControl, "initial-admin control pool");
      });
    }
    try {
      await collectCleanupFailure(failures, "initial-admin PostgreSQL cleanup after setup failure", async () => {
        await cleanupClusterResources(cluster, { controlDatabase, tenantDatabase, ownerRole, runtimeRole });
      });
    } finally {
      await collectCleanupFailure(failures, "initial-admin maintenance pool close after setup failure", async () => {
        await endPoolAndConfirmDrained(cluster, "initial-admin maintenance pool");
      });
      await collectCleanupFailure(failures, "initial-admin migration fixture removal after setup failure", async () => {
        await rm(migrationRoot, { recursive: true, force: true });
      });
    }
    throw new AggregateError(failures, "Initial-admin fixture setup failed closed");
  }
}

async function createHistoricalTenantFixture(input: {
  readonly databaseAdminUrl: string;
  readonly migrationRoot: string;
  readonly cluster: Pool;
  readonly control: Pool;
  readonly tenantId: string;
  readonly slug: string;
  readonly displayName: string;
  readonly tenantDatabase: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly runtimePassword: string;
  readonly runtimeSecretReference: string;
  readonly recipientEmail: string;
  readonly invitationToken: string;
  readonly platformAdminId: string;
}): Promise<string> {
  assertEphemeralTenantNames(input.tenantDatabase, input.ownerRole, input.runtimeRole);
  await executeFormatted(
    input.cluster,
    "SELECT format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', $1::text) AS sql",
    [input.ownerRole],
  );
  await executeFormatted(
    input.cluster,
    "SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L', $1::text, $2::text) AS sql",
    [input.runtimeRole, input.runtimePassword],
  );
  await executeFormatted(
    input.cluster,
    "SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L', $1::text, $2::text, 'UTF8') AS sql",
    [input.tenantDatabase, input.ownerRole],
  );
  await executeFormatted(
    input.cluster,
    "SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', $1::text) AS sql",
    [input.tenantDatabase],
  );
  await executeFormatted(
    input.cluster,
    "SELECT format('GRANT CONNECT ON DATABASE %I TO %I', $1::text, $2::text) AS sql",
    [input.tenantDatabase, input.runtimeRole],
  );

  const tenant = new Pool({
    connectionString: databaseUrl(input.databaseAdminUrl, input.tenantDatabase),
    application_name: "nombramientos-initial-admin-audit-tenant-035",
    max: 1,
  });
  try {
    const applied = await runMigrations(tenant, {
      scope: "tenant",
      directory: path.join(input.migrationRoot, "tenant"),
      executionRole: input.ownerRole,
    });
    if (applied.at(-1) !== "035_system_role_assignment_matrix.sql") {
      throw new Error("Initial-admin audit tenant did not stop exactly at head 035");
    }
    await tenant.query(
      `INSERT INTO tenant_settings(
         tenant_id,display_name,kind,timezone,locale,setup_state,catalog_version
       ) VALUES ($1,$2,'real','America/La_Paz','es','ready','initial-admin-audit-v1')`,
      [input.tenantId, input.displayName],
    );
  } finally {
    await endPoolAndConfirmDrained(tenant, "initial-admin migration tenant pool");
  }

  await input.control.query(
    `INSERT INTO tenants(
       id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,
       runtime_secret_ref,database_port
     ) VALUES ($1,$2,$3,'real','provisioning','America/La_Paz','es',$4,$5,$6,55432)`,
    [
      input.tenantId,
      input.slug,
      input.displayName,
      input.tenantDatabase,
      input.runtimeRole,
      input.runtimeSecretReference,
    ],
  );
  const provisioningIdempotency = randomUUID();
  await input.control.query(
    `INSERT INTO provisioning_jobs(
       idempotency_key,tenant_id,requested_slug,request_hash,state,request_payload,
       requested_by_identity_id,request_id
     ) VALUES ($1,$2,$3,$4,'seeded',$5,$6,$7)`,
    [
      provisioningIdempotency,
      input.tenantId,
      input.slug,
      sha256(`provision:${input.tenantId}`),
      {
        idempotencyKey: provisioningIdempotency,
        tenantId: input.tenantId,
        mode: "historical_initial_admin_audit",
      },
      input.platformAdminId,
      randomUUID(),
    ],
  );
  const activation = await input.control.query<{
    invitation_id: string;
    tenant_version: number;
    reused: boolean;
  }>(
    `SELECT * FROM activate_platform_tenant_initial_admin(
       $1,1,$2,$2,$3,$4,$5,$6,$7
     )`,
    [
      input.tenantId,
      input.recipientEmail,
      sha256(input.invitationToken),
      new Date(Date.now() + 24 * 60 * 60_000),
      randomUUID(),
      sha256(`activation:${input.tenantId}`),
      input.platformAdminId,
    ],
  );
  const activated = activation.rows[0];
  if (
    activation.rowCount !== 1
    || !activated?.invitation_id
    || activated.tenant_version !== 2
    || activated.reused
  ) {
    throw new Error("Historical initial-administrator activation was not created exactly once");
  }
  return activated.invitation_id;
}

async function observe(current: Fixture): Promise<{
  controlHead: string | null;
  tenantHead: string | null;
  invitationStatus: string;
  grantorMemberships: number;
  recipientIdentities: number;
  recipientMemberships: number;
  recipientBindings: number;
}> {
  const control = await current.control.query<{
    control_head: string | null;
    invitation_status: string;
    grantor_memberships: number;
    recipient_identities: number;
    recipient_memberships: number;
  }>(
    `SELECT
       (SELECT max(name) FROM schema_migrations) AS control_head,
       invitation.status AS invitation_status,
       (SELECT count(*)::int FROM tenant_memberships WHERE identity_id=$2 AND tenant_id=$3) AS grantor_memberships,
       (SELECT count(*)::int FROM platform_identities WHERE normalized_email=$4) AS recipient_identities,
       (SELECT count(*)::int FROM tenant_memberships membership
         JOIN platform_identities identity ON identity.id=membership.identity_id
        WHERE identity.normalized_email=$4) AS recipient_memberships
     FROM tenant_invitations invitation
    WHERE invitation.id=$1`,
    [current.invitationId, current.platformAdminId, current.tenantId, current.recipientEmail],
  );
  const row = control.rows[0];
  if (!row) throw new Error("Initial-admin control observation is unavailable");
  const tenant = new Pool({ connectionString: databaseUrl(requireAdminUrl(), current.tenantDatabase), max: 1 });
  try {
    const observed = await tenant.query<{ tenant_head: string | null; recipient_bindings: number }>(
      `SELECT
         (SELECT max(name) FROM schema_migrations) AS tenant_head,
         (SELECT count(*)::int FROM role_bindings binding
           WHERE binding.source_invitation_id=$1) AS recipient_bindings`,
      [current.invitationId],
    );
    const tenantRow = observed.rows[0];
    if (!tenantRow) throw new Error("Initial-admin tenant observation is unavailable");
    return {
      controlHead: row.control_head,
      tenantHead: tenantRow.tenant_head,
      invitationStatus: row.invitation_status,
      grantorMemberships: row.grantor_memberships,
      recipientIdentities: row.recipient_identities,
      recipientMemberships: row.recipient_memberships,
      recipientBindings: tenantRow.recipient_bindings,
    };
  } finally {
    await endPoolAndConfirmDrained(tenant, "initial-admin observation tenant pool");
  }
}

async function cleanupFixture(current: Fixture): Promise<void> {
  const failures: Error[] = [];
  await collectCleanupFailure(failures, "initial-admin control pool close", async () => {
    await endPoolAndConfirmDrained(current.control, "initial-admin control pool");
  });
  try {
    await collectCleanupFailure(failures, "initial-admin PostgreSQL resource cleanup", async () => {
      await cleanupClusterResources(current.cluster, current);
    });
    await collectCleanupFailure(failures, "initial-admin PostgreSQL residue attestation", async () => {
      const residue = await current.cluster.query<{ databases: number; roles: number }>(
        `SELECT
           (SELECT count(*)::int FROM pg_database WHERE datname=ANY($1::text[])) AS databases,
           (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
        [[current.controlDatabase, current.tenantDatabase], [current.ownerRole, current.runtimeRole]],
      );
      if (residue.rows[0]?.databases !== 0 || residue.rows[0]?.roles !== 0) {
        throw new Error("Initial-admin PostgreSQL resources survived cleanup");
      }
    });
  } finally {
    await collectCleanupFailure(failures, "initial-admin maintenance pool close", async () => {
      await endPoolAndConfirmDrained(current.cluster, "initial-admin maintenance pool");
    });
    await collectCleanupFailure(failures, "initial-admin migration fixture removal", async () => {
      await rm(current.migrationRoot, { recursive: true, force: true });
    });
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, "Initial-admin fixture cleanup failed closed");
  }
}

async function cleanupClusterResources(
  cluster: Pool,
  resources: { controlDatabase: string; tenantDatabase: string; ownerRole: string; runtimeRole: string },
): Promise<void> {
  assertEphemeralNames(resources);
  const failures: Error[] = [];
  await collectCleanupFailure(failures, "historical tenant database drop", async () => dropEphemeralDatabase(
    cluster,
    resources.tenantDatabase,
    { pattern: /^nom_t_[0-9a-f]{32}$/u, label: "historical tenant database" },
  ));
  await collectCleanupFailure(failures, "historical control database drop", async () => dropEphemeralDatabase(
    cluster,
    resources.controlDatabase,
    { pattern: /^nom_initial_admin_audit_[0-9a-f]{20}$/u, label: "historical control database" },
  ));
  await collectCleanupFailure(failures, "historical runtime role drop", async () => dropEphemeralRole(
    cluster,
    resources.runtimeRole,
    { pattern: /^nom_r_[0-9a-f]{32}$/u, label: "historical runtime role" },
  ));
  await collectCleanupFailure(failures, "historical owner role drop", async () => dropEphemeralRole(
    cluster,
    resources.ownerRole,
    { pattern: /^nom_o_[0-9a-f]{32}$/u, label: "historical owner role" },
  ));
  if (failures.length > 0) {
    throw new AggregateError(failures, "Initial-admin PostgreSQL resource cleanup failed closed");
  }
}

async function createHistoricalMigrationRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "nom-initial-admin-audit-"));
  try {
    await Promise.all([mkdir(path.join(root, "control")), mkdir(path.join(root, "tenant"))]);
    await copyMigrationsThrough("control", "023_atomic_authentication_context_lock.sql", root);
    await copyMigrationsThrough("tenant", "035_system_role_assignment_matrix.sql", root);
    return root;
  } catch (error) {
    try {
      await rm(root, { recursive: true, force: true });
    } catch (cleanupError) {
      throw new AggregateError(
        [
          cleanupStageError("historical migration fixture creation", error),
          cleanupStageError("historical migration fixture removal", cleanupError),
        ],
        "Historical migration fixture initialization failed closed",
      );
    }
    throw error;
  }
}

async function copyMigrationsThrough(scope: "control" | "tenant", head: string, root: string): Promise<void> {
  const source = path.join(migrationSourceRoot, scope);
  const migrations = (await readdir(source))
    .filter((name) => /^\d+_.+\.sql$/u.test(name) && name.localeCompare(head) <= 0)
    .sort((left, right) => left.localeCompare(right));
  if (migrations.at(-1) !== head) throw new Error(`Historical ${scope} migration head is unavailable`);
  for (const migration of migrations) {
    await copyFile(path.join(source, migration), path.join(root, scope, migration));
  }
}

function assertEphemeralNames(resources: {
  controlDatabase: string;
  tenantDatabase: string;
  ownerRole: string;
  runtimeRole: string;
}): void {
  if (!/^nom_initial_admin_audit_[0-9a-f]{20}$/u.test(resources.controlDatabase)) {
    throw new Error("Refusing cleanup outside exact initial-admin audit resources");
  }
  assertEphemeralTenantNames(resources.tenantDatabase, resources.ownerRole, resources.runtimeRole);
}

function assertEphemeralTenantNames(
  tenantDatabase: string,
  ownerRole: string,
  runtimeRole: string,
): void {
  const suffix = tenantDatabase.replace(/^nom_t_/u, "");
  if (
    !/^[0-9a-f]{32}$/u.test(suffix)
    || ownerRole !== `nom_o_${suffix}`
    || runtimeRole !== `nom_r_${suffix}`
  ) {
    throw new Error("Refusing cleanup outside exact initial-admin audit resources");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const result = await pool.query<{ sql: string }>(query, [...values]);
  const sql = result.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format an initial-admin audit statement");
  await pool.query(sql);
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)) throw new Error("Invalid local database name");
  const url = new URL(assertExactWorkspaceAdminUrl(databaseAdminUrl));
  url.pathname = `/${databaseName}`;
  return url.toString();
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

function requireAdminUrl(): string {
  if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
  return adminUrl;
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
    await endPoolAndConfirmDrained(pool, "initial-admin reachability pool");
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function requireFixture(value: Fixture | undefined): Fixture {
  if (!value) throw new Error("Initial-admin audit fixture is unavailable");
  return value;
}
