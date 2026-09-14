import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hash, verify } from "argon2";
import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDirectory = path.join(packageRoot, "migrations", "control");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Invitation password upgrade tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface LegacyInvitationFixture {
  readonly tenantId: string;
  readonly identityId: string;
  readonly password: string;
  readonly passwordHash: string;
  readonly bootstrapSessionId: string;
}

live("legacy invitation password remediation migration", () => {
  it("scrubs only a provably passwordless 019-era identity and preserves independent credentials", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 19);

      const passwordless = await createLegacyInvitationIdentity(database, false, "passwordless");
      const passwordAllowed = await createLegacyInvitationIdentity(database, true, "password-allowed");
      const passwordSessionId = randomUUID();
      const federatedSessionId = randomUUID();

      await database.query(
        `INSERT INTO auth_sessions(
           id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
           assurance_level,auth_method,aal,phishing_resistant,recovery_limited
         ) VALUES
           ($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour','password','password',1,false,false),
           ($6,$7,$8,$4,$5,clock_timestamp()+interval '1 hour','password','federated',1,false,false)`,
        [
          passwordSessionId,
          randomHex(32),
          randomHex(32),
          passwordless.identityId,
          passwordless.tenantId,
          federatedSessionId,
          randomHex(32),
          randomHex(32),
        ],
      );
      await database.query(
        `INSERT INTO mfa_challenges(
           token_hash,identity_id,tenant_id,origin_hash,expires_at
         ) VALUES ($1,$2,$3,$4,clock_timestamp()+interval '10 minutes')`,
        [randomHex(32), passwordless.identityId, passwordless.tenantId, randomHex(32)],
      );

      await applyMigrationsThrough(database, 21);
      const preUpgrade = await readIdentityPasswords(database, [passwordless.identityId, passwordAllowed.identityId]);
      expect(preUpgrade.get(passwordless.identityId)).toMatchObject({
        password_hash: passwordless.passwordHash,
        password_provisioned: true,
      });
      expect(preUpgrade.get(passwordAllowed.identityId)).toMatchObject({
        password_hash: passwordAllowed.passwordHash,
        password_provisioned: true,
      });

      await applyMigrationsThrough(database, 22);

      const postUpgrade = await readIdentityPasswords(database, [passwordless.identityId, passwordAllowed.identityId]);
      const scrubbed = postUpgrade.get(passwordless.identityId);
      const retained = postUpgrade.get(passwordAllowed.identityId);
      expect(scrubbed).toMatchObject({ password_provisioned: false });
      expect(scrubbed?.legacy_invitation_password_scrubbed_at).toBeInstanceOf(Date);
      expect(scrubbed?.password_hash).not.toBe(passwordless.passwordHash);
      expect(await verify(scrubbed?.password_hash ?? "", passwordless.password)).toBe(false);
      expect(retained).toMatchObject({
        password_hash: passwordAllowed.passwordHash,
        password_provisioned: true,
        legacy_invitation_password_scrubbed_at: null,
      });
      expect(await verify(retained?.password_hash ?? "", passwordAllowed.password)).toBe(true);

      const sessions = await database.query<{
        id: string;
        auth_method: string;
        revoked_at: Date | null;
      }>(
        `SELECT id,auth_method,revoked_at
           FROM auth_sessions
          WHERE id=ANY($1::uuid[])
          ORDER BY id`,
        [[passwordless.bootstrapSessionId, passwordAllowed.bootstrapSessionId, passwordSessionId, federatedSessionId]],
      );
      const sessionsById = new Map(sessions.rows.map((row) => [row.id, row]));
      expect(sessionsById.get(passwordless.bootstrapSessionId)?.revoked_at).toBeInstanceOf(Date);
      expect(sessionsById.get(passwordSessionId)?.revoked_at).toBeInstanceOf(Date);
      expect(sessionsById.get(federatedSessionId)?.revoked_at).toBeNull();
      expect(sessionsById.get(passwordAllowed.bootstrapSessionId)?.revoked_at).toBeNull();

      const challenges = await database.query<{ consumed: boolean }>(
        `SELECT bool_and(consumed_at IS NOT NULL) AS consumed
           FROM mfa_challenges
          WHERE identity_id=$1`,
        [passwordless.identityId],
      );
      expect(challenges.rows[0]?.consumed).toBe(true);

      await database.query(
        `UPDATE tenant_identity_policies
            SET allow_password=true,version=version+1,updated_at=clock_timestamp()
          WHERE tenant_id=$1`,
        [passwordless.tenantId],
      );
      const afterPolicyEnable = await readIdentityPasswords(database, [passwordless.identityId]);
      expect(afterPolicyEnable.get(passwordless.identityId)?.password_provisioned).toBe(false);
      expect(await verify(afterPolicyEnable.get(passwordless.identityId)?.password_hash ?? "", passwordless.password)).toBe(false);

      const overloads = await database.query<{ pronargs: number }>(
        `SELECT procedure.pronargs
           FROM pg_catalog.pg_proc procedure
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=procedure.pronamespace
          WHERE namespace.nspname='public'
            AND procedure.proname='complete_tenant_invitation_acceptance'
          ORDER BY procedure.pronargs`,
      );
      expect(overloads.rows.map(({ pronargs }) => pronargs)).toEqual([14]);
    });
  }, 120_000);

  it("fails closed and rolls back completely when current policy cannot prove the acceptance-time decision", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 19);
      const ambiguous = await createLegacyInvitationIdentity(database, false, "ambiguous");
      await database.query(
        `UPDATE tenant_identity_policies policy
            SET updated_at=invitation.accepted_at+interval '1 second',version=policy.version+1
           FROM tenant_invitations invitation
          WHERE policy.tenant_id=$1
            AND invitation.acceptance_identity_id=$2`,
        [ambiguous.tenantId, ambiguous.identityId],
      );
      await applyMigrationsThrough(database, 21);

      await expect(applyMigrationsThrough(database, 22)).rejects.toMatchObject({
        code: "23514",
        constraint: "legacy_invitation_password_policy_ambiguous",
      });

      const migration = await database.query(
        "SELECT 1 FROM schema_migrations WHERE name='022_legacy_invitation_password_scrub.sql'",
      );
      expect(migration.rowCount).toBe(0);
      const marker = await database.query<{ name: string | null }>(
        `SELECT to_regclass('public.platform_identities')::text AS relation,
                (SELECT column_name
                   FROM information_schema.columns
                  WHERE table_schema='public'
                    AND table_name='platform_identities'
                    AND column_name='legacy_invitation_password_scrubbed_at') AS name`,
      );
      expect(marker.rows[0]?.name).toBeNull();
      const identity = await database.query<{ password_hash: string; password_provisioned: boolean }>(
        "SELECT password_hash,password_provisioned FROM platform_identities WHERE id=$1",
        [ambiguous.identityId],
      );
      expect(identity.rows[0]).toEqual({
        password_hash: ambiguous.passwordHash,
        password_provisioned: true,
      });
      const session = await database.query<{ revoked_at: Date | null }>(
        "SELECT revoked_at FROM auth_sessions WHERE id=$1",
        [ambiguous.bootstrapSessionId],
      );
      expect(session.rows[0]?.revoked_at).toBeNull();
    });
  }, 120_000);
});

async function createLegacyInvitationIdentity(
  database: Pool,
  allowPassword: boolean,
  label: string,
): Promise<LegacyInvitationFixture> {
  const tenantId = randomUUID();
  const grantorId = randomUUID();
  const invitationId = randomUUID();
  const acceptanceId = randomUUID();
  const identityId = randomUUID();
  const bootstrapSessionId = randomUUID();
  const password = randomBytes(24).toString("base64url");
  const passwordHash = await hash(password, { memoryCost: 19_456, timeCost: 2, parallelism: 1 });
  const suffix = randomBytes(8).toString("hex");
  const normalizedEmail = `${label}-${suffix}@upgrade.invalid`;

  await database.query(
    `INSERT INTO tenants(
       id,slug,display_name,kind,status,timezone,locale,database_port,
       database_name,runtime_role,runtime_secret_ref,activated_at
     ) VALUES ($1,$2,$3,'real','active','UTC','es',55432,$4,$5,$6,clock_timestamp())`,
    [
      tenantId,
      `upgrade-${suffix}`,
      `Upgrade ${label}`,
      `nom_upgrade_${suffix}`,
      `nom_r_${suffix.padEnd(32, "0")}`,
      `credential://upgrade/${suffix}`,
    ],
  );
  await database.query(
    `INSERT INTO platform_identities(
       id,email,normalized_email,display_name,password_hash,mfa_enabled,mfa_required,status
     ) VALUES ($1,$2,$2,$3,$4,false,false,'active')`,
    [grantorId, `grantor-${label}-${suffix}@upgrade.invalid`, `Grantor ${label}`, passwordHash],
  );
  await database.query(
    `INSERT INTO tenant_identity_policies(
       tenant_id,version,enforcement_mode,minimum_aal,privileged_minimum_aal,
       require_user_verification,require_phishing_resistant_for_privileged,
       require_device_bound_for_privileged,require_attestation_for_privileged,
       allow_password,allow_totp_fallback,allow_recovery_codes,allow_synced_passkeys,
       minimum_passkey_count,privileged_minimum_passkey_count,maximum_passkeys,
       maximum_active_sessions,idle_timeout_minutes,absolute_session_minutes,
       step_up_ttl_seconds,action_requirements,changed_by_identity_id
     )
     SELECT $1,1,enforcement_mode,minimum_aal,privileged_minimum_aal,
            require_user_verification,require_phishing_resistant_for_privileged,
            require_device_bound_for_privileged,require_attestation_for_privileged,
            $2,allow_totp_fallback,allow_recovery_codes,allow_synced_passkeys,
            minimum_passkey_count,privileged_minimum_passkey_count,maximum_passkeys,
            maximum_active_sessions,idle_timeout_minutes,absolute_session_minutes,
            step_up_ttl_seconds,action_requirements,$3
       FROM identity_policy_baseline
      WHERE policy_key='global'`,
    [tenantId, allowPassword, grantorId],
  );
  await database.query(
    `INSERT INTO tenant_invitations(
       id,tenant_id,email,normalized_email,role_codes,token_hash,status,
       idempotency_key,request_hash,created_by_identity_id,expires_at,
       acceptance_id,acceptance_identity_id,acceptance_started_at
     ) VALUES (
       $1,$2,$3,$3,ARRAY['AUDITOR']::text[],$4,'accepting',
       $5,$6,$7,clock_timestamp()+interval '1 hour',$8,$9,clock_timestamp()
     )`,
    [
      invitationId,
      tenantId,
      normalizedEmail,
      randomHex(32),
      randomUUID(),
      randomHex(32),
      grantorId,
      acceptanceId,
      identityId,
    ],
  );
  const completion = await database.query<{ completed: boolean }>(
    `SELECT completed
       FROM complete_tenant_invitation_acceptance(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
       )`,
    [
      invitationId,
      acceptanceId,
      identityId,
      tenantId,
      normalizedEmail,
      `Invitee ${label}`,
      passwordHash,
      bootstrapSessionId,
      randomHex(32),
      randomHex(32),
      new Date(Date.now() + 10 * 60_000),
      randomHex(32),
      randomHex(32),
    ],
  );
  expect(completion.rows[0]?.completed).toBe(true);
  return { tenantId, identityId, password, passwordHash, bootstrapSessionId };
}

async function readIdentityPasswords(
  database: Pool,
  identityIds: readonly string[],
): Promise<Map<string, {
  password_hash: string;
  password_provisioned: boolean;
  legacy_invitation_password_scrubbed_at: Date | null;
}>> {
  const marker = await database.query<{ exists: boolean }>(
    `SELECT EXISTS(
       SELECT 1
         FROM information_schema.columns
        WHERE table_schema='public'
          AND table_name='platform_identities'
          AND column_name='legacy_invitation_password_scrubbed_at'
     ) AS exists`,
  );
  const markerProjection = marker.rows[0]?.exists
    ? "legacy_invitation_password_scrubbed_at"
    : "NULL::timestamptz AS legacy_invitation_password_scrubbed_at";
  const identities = await database.query<{
    id: string;
    password_hash: string;
    password_provisioned: boolean;
    legacy_invitation_password_scrubbed_at: Date | null;
  }>(
    `SELECT id,password_hash,password_provisioned,${markerProjection}
       FROM platform_identities
      WHERE id=ANY($1::uuid[])`,
    [identityIds],
  );
  return new Map(identities.rows.map(({ id, ...identity }) => [id, identity]));
}

async function withTemporaryDatabase(run: (database: Pool) => Promise<void>): Promise<void> {
  if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
  const databaseName = `nom_inv_pwd_upgrade_${randomBytes(10).toString("hex")}`;
  const cluster = new Pool({
    connectionString: databaseUrl(adminUrl, "postgres"),
    application_name: "nombramientos-invitation-password-upgrade-cluster",
    max: 1,
  });
  const database = new Pool({
    connectionString: databaseUrl(adminUrl, databaseName),
    application_name: "nombramientos-invitation-password-upgrade-database",
    max: 1,
  });
  await runWithCleanup(async () => {
    await executeFormatted(
      cluster,
      "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
      [databaseName],
    );
    await run(database);
  }, () => cleanupInvitationPasswordDatabase(cluster, database, databaseName), "Invitation-password upgrade live case");
}

async function createMigrationTable(database: Pool): Promise<void> {
  await database.query(`
    CREATE TABLE schema_migrations (
      name text PRIMARY KEY,
      checksum text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )
  `);
}

async function applyMigrationsThrough(database: Pool, maximumMigration: number): Promise<void> {
  const migrations = readdirSync(migrationsDirectory)
    .filter((file) => /^\d+_.+\.sql$/u.test(file) && Number(file.slice(0, 3)) <= maximumMigration)
    .sort((left, right) => left.localeCompare(right));
  const alreadyApplied = new Set((await database.query<{ name: string }>("SELECT name FROM schema_migrations")).rows.map(({ name }) => name));
  for (const migration of migrations) {
    if (alreadyApplied.has(migration)) continue;
    const sql = readFileSync(path.join(migrationsDirectory, migration), "utf8");
    const client = await database.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query(
        "INSERT INTO schema_migrations(name,checksum) VALUES ($1,$2)",
        [migration, createHash("sha256").update(sql).digest("hex")],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the invitation password upgrade statement");
  await pool.query(sql);
}

async function cleanupInvitationPasswordDatabase(cluster: Pool, database: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [database], assertSafeDatabaseName: assertInvitationPasswordDatabaseName }],
    label: "Temporary invitation-password upgrade database",
  });
}

function assertInvitationPasswordDatabaseName(databaseName: string): void {
  if (!/^nom_inv_pwd_upgrade_[0-9a-f]{20}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-invitation-password-upgrade test database");
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
  if (!isLoopback(url.hostname) || Number(url.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Invitation password upgrade tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}

function randomHex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}
