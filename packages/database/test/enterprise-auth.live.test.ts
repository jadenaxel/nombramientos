import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { ControlPlaneStore } from "../src/control-store.js";
import { EnterpriseAuthStore, type IdentityPolicyValues } from "../src/enterprise-auth-store.js";
import { runMigrations } from "../src/migrations.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const workspacePort = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Enterprise auth live tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface Fixture {
  readonly cluster: Pool;
  readonly control: Pool;
  readonly auth: EnterpriseAuthStore;
  readonly legacy: ControlPlaneStore;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly identityId: string;
  readonly enrollmentSessionId: string;
}

let fixture: Fixture | undefined;
let credentialId: string | undefined;
let authenticatedSessionId: string | undefined;
let authenticatedTokenHash: string | undefined;

live("enterprise passkey and assurance persistence on isolated PostgreSQL", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 60_000);

  it("registers the first passkey, rotates enrollment-only sessions, and leaves TOTP state independent", async () => {
    const current = requireFixture();
    const rpIds = await current.control.query<{
      localhost_valid: boolean;
      domain_valid: boolean;
      ipv4_invalid: boolean;
      abbreviated_ip_invalid: boolean;
      numeric_suffix_invalid: boolean;
    }>(`SELECT webauthn_rp_id_is_valid('localhost') AS localhost_valid,
              webauthn_rp_id_is_valid('login.example.com') AS domain_valid,
              NOT webauthn_rp_id_is_valid('127.0.0.1') AS ipv4_invalid,
              NOT webauthn_rp_id_is_valid('127.1') AS abbreviated_ip_invalid,
              NOT webauthn_rp_id_is_valid('123.456') AS numeric_suffix_invalid`);
    expect(rpIds.rows[0]).toEqual({
      localhost_valid: true,
      domain_valid: true,
      ipv4_invalid: true,
      abbreviated_ip_invalid: true,
      numeric_suffix_invalid: true,
    });
    const tokenHash = sha256(randomBytes(32));
    const challengeHash = sha256(randomBytes(32));
    const ceremony = await current.auth.createCeremony({
      tokenHash,
      challengeHash,
      type: "registration",
      identityId: current.identityId,
      tenantId: current.tenantId,
      sessionId: current.enrollmentSessionId,
      rpId: "localhost",
      expectedOrigin: "http://localhost:3000",
      requireUserVerification: true,
      policyVersion: 1,
      expiresAt: new Date(Date.now() + 5 * 60_000),
    });
    const result = await current.auth.completeRegistration({
      ceremonyId: ceremony.id,
      tokenHash,
      challengeHash,
      credential: {
        externalId: randomBytes(32).toString("base64url"),
        publicKey: Buffer.alloc(32, 7),
        userHandle: Buffer.from(current.identityId).toString("base64url"),
        counter: 0,
        transports: ["internal", "hybrid"],
        attachment: "platform",
        deviceType: "multiDevice",
        backupEligible: true,
        backedUp: true,
        discoverable: true,
        userVerified: true,
        rpId: "localhost",
        displayName: "Windows Hello",
      },
      newSession: sessionInput("registration-device"),
      requestId: randomUUID(),
    });
    credentialId = result.credentialId;
    const state = await current.control.query<{
      mfa_enabled: boolean;
      passkey_enabled: boolean;
      strong_auth_enabled: boolean;
      old_revoked: boolean;
      assurance_level: string;
      auth_method: string;
      aal: number;
      phishing_resistant: boolean;
    }>(
      `SELECT identity.mfa_enabled,identity.passkey_enabled,identity.strong_auth_enabled,
              old_session.revoked_at IS NOT NULL AS old_revoked,new_session.assurance_level,
              new_session.auth_method,new_session.aal,new_session.phishing_resistant
         FROM platform_identities identity
         JOIN auth_sessions old_session ON old_session.id=$2
         JOIN auth_sessions new_session ON new_session.id=$3
        WHERE identity.id=$1`,
      [current.identityId, current.enrollmentSessionId, result.sessionId],
    );
    expect(state.rows[0]).toEqual({
      mfa_enabled: false,
      passkey_enabled: true,
      strong_auth_enabled: true,
      old_revoked: true,
      assurance_level: "mfa",
      auth_method: "passkey",
      aal: 2,
      phishing_resistant: true,
    });
    await expect(current.auth.completeRegistration({
      ceremonyId: ceremony.id,
      tokenHash,
      challengeHash,
      credential: {
        externalId: randomBytes(32).toString("base64url"), publicKey: Buffer.alloc(32, 8),
        userHandle: Buffer.from(current.identityId).toString("base64url"), counter: 0,
        transports: ["internal"], deviceType: "singleDevice", backupEligible: false,
        backedUp: false, discoverable: true, userVerified: true, rpId: "localhost", displayName: "Replay",
      },
      newSession: sessionInput("replay"),
      requestId: randomUUID(),
    })).rejects.toMatchObject({ code: "CEREMONY_INVALID" });
    const [summary] = await current.auth.listCredentials(current.identityId);
    expect(summary).toMatchObject({ id: result.credentialId, displayName: "Windows Hello", backedUp: true });
    const verification = summary
      ? await current.auth.getCredentialByExternalId(summary.externalId, "localhost")
      : null;
    expect(verification).toMatchObject({ id: result.credentialId, tenantId: current.tenantId, counter: 0 });
  });

  it("authenticates discoverably, records mobile IP changes without rejection, and consumes step-up once", async () => {
    const current = requireFixture();
    if (!credentialId) throw new Error("Passkey fixture is unavailable");
    const credential = (await current.auth.listCredentials(current.identityId))[0];
    if (!credential) throw new Error("Passkey summary is unavailable");

    const authToken = sha256(randomBytes(32));
    const authChallenge = sha256(randomBytes(32));
    const authCeremony = await current.auth.createCeremony({
      tokenHash: authToken,
      challengeHash: authChallenge,
      type: "authentication",
      rpId: "localhost",
      expectedOrigin: "http://localhost:3000",
      requireUserVerification: true,
      policyVersion: 1,
      expiresAt: new Date(Date.now() + 5 * 60_000),
    });
    const newSession = sessionInput("phone-passkey");
    const authentication = await current.auth.completeAuthentication({
      ceremonyId: authCeremony.id,
      tokenHash: authToken,
      challengeHash: authChallenge,
      credentialId,
      newCounter: 0,
      assertedDeviceType: "multiDevice",
      newBackupState: true,
      tenantId: current.tenantId,
      newSession,
      requestId: randomUUID(),
    });
    authenticatedSessionId = authentication.sessionId;
    authenticatedTokenHash = newSession.tokenHash;
    const mobileSession = await current.legacy.getSession(newSession.tokenHash, {
      userAgentHash: sha256("phone-passkey-browser-updated"),
      ipPrefixHash: sha256("cellular-prefix"),
    });
    expect(mobileSession).toMatchObject({
      sessionId: authentication.sessionId,
      authMethod: "passkey",
      phishingResistant: true,
      userAgentContextChanged: true,
      ipContextChanged: true,
      enrollmentOnly: false,
    });

    const stepToken = sha256(randomBytes(32));
    const stepChallenge = sha256(randomBytes(32));
    const operationHash = sha256("operation-payload-v1");
    const stepCeremony = await current.auth.createCeremony({
      tokenHash: stepToken,
      challengeHash: stepChallenge,
      type: "step_up",
      identityId: current.identityId,
      tenantId: current.tenantId,
      sessionId: authentication.sessionId,
      purpose: "auth.passkey.revoke",
      operationHash,
      rpId: "localhost",
      expectedOrigin: "http://localhost:3000",
      requireUserVerification: true,
      policyVersion: 1,
      expiresAt: new Date(Date.now() + 5 * 60_000),
    });
    const grantTokenHash = sha256(randomBytes(32));
    await current.auth.completeWebAuthnStepUp({
      ceremonyId: stepCeremony.id,
      tokenHash: stepToken,
      challengeHash: stepChallenge,
      credentialId,
      newCounter: 0,
      assertedDeviceType: "multiDevice",
      newBackupState: true,
      grantTokenHash,
      grantExpiresAt: new Date(Date.now() + 5 * 60_000),
      requestId: randomUUID(),
    });
    const consume = {
      identityId: current.identityId,
      sessionId: authentication.sessionId,
      tokenHash: grantTokenHash,
      purpose: "auth.passkey.revoke",
      operationHash,
    } as const;
    await expect(current.auth.consumeStepUpGrant(consume)).resolves.toBe(true);
    await expect(current.auth.consumeStepUpGrant(consume)).resolves.toBe(false);
  });

  it("rejects policy downgrade and preserves TOTP when the last passkey is revoked", async () => {
    const current = requireFixture();
    if (!credentialId || !authenticatedSessionId || !authenticatedTokenHash) throw new Error("Authentication fixture is unavailable");
    const baseline = await current.auth.getEffectiveIdentityPolicy(current.tenantId);
    const weaker: IdentityPolicyValues = { ...baseline, minimumAal: 1 };
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: current.tenantId,
      expectedVersion: 0,
      changedByIdentityId: current.identityId,
      policy: weaker,
      requestId: randomUUID(),
    })).rejects.toMatchObject({ code: "POLICY_CONFLICT" });

    const tighter: IdentityPolicyValues = {
      ...baseline,
      maximumActiveSessions: 5,
      idleTimeoutMinutes: 15,
    };
    const persisted = await current.auth.upsertTenantIdentityPolicy({
      tenantId: current.tenantId,
      expectedVersion: 0,
      changedByIdentityId: current.identityId,
      policy: tighter,
      requestId: randomUUID(),
    });
    expect(persisted).toMatchObject({ tenantVersion: 1, idleTimeoutMinutes: 15, maximumActiveSessions: 5 });

    await current.control.query(
      `UPDATE platform_identities
          SET mfa_enabled=true,totp_secret_ciphertext='encrypted-test-value',mfa_enrolled_at=clock_timestamp()
        WHERE id=$1`,
      [current.identityId],
    );
    const revoked = await current.auth.revokeCredential({
      identityId: current.identityId,
      credentialId,
      reason: "compromised",
      requestId: randomUUID(),
    });
    expect(revoked.revoked).toBe(true);
    const identity = await current.control.query<{
      mfa_enabled: boolean; passkey_enabled: boolean; strong_auth_enabled: boolean;
    }>(
      "SELECT mfa_enabled,passkey_enabled,strong_auth_enabled FROM platform_identities WHERE id=$1",
      [current.identityId],
    );
    expect(identity.rows[0]).toEqual({ mfa_enabled: true, passkey_enabled: false, strong_auth_enabled: true });
  });
});

async function createFixture(databaseAdminUrl: string): Promise<Fixture> {
  const cluster = new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), max: 1 });
  const databaseName = `nom_enterprise_auth_${randomBytes(12).toString("hex")}`;
  const control = new Pool({ connectionString: databaseUrl(databaseAdminUrl, databaseName), max: 2 });
  try {
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [databaseName]);
    await runMigrations(control, {
      scope: "control",
      directory: path.join(packageRoot, "migrations", "control"),
    });
    const tenantId = randomUUID();
    const identityId = randomUUID();
    const enrollmentSessionId = randomUUID();
    await control.query(
      `INSERT INTO tenants(
         id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,
         runtime_secret_ref,database_port,activated_at
       ) VALUES ($1,$2,'Enterprise auth tenant','real','active','America/La_Paz','es',$3,$4,$5,55432,clock_timestamp())`,
      [
        tenantId,
        `auth-${randomBytes(4).toString("hex")}`,
        `nom_auth_target_${randomBytes(4).toString("hex")}`,
        `nom_auth_role_${randomBytes(4).toString("hex")}`,
        `tenant-db/${tenantId}/runtime/v1`,
      ],
    );
    await control.query(
      `INSERT INTO platform_identities(
         id,email,normalized_email,display_name,password_hash,mfa_required,status
       ) VALUES ($1,'enterprise@invalid.example','enterprise@invalid.example','Enterprise user','disabled',true,'active')`,
      [identityId],
    );
    await control.query(
      "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
      [tenantId, identityId],
    );
    await control.query(
      `INSERT INTO auth_sessions(
         id,token_hash,csrf_hash,identity_id,active_tenant_id,user_agent_hash,ip_prefix_hash,
         expires_at,assurance_level
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '1 hour','enrollment_only')`,
      [
        enrollmentSessionId,
        sha256(randomBytes(32)),
        sha256(randomBytes(32)),
        identityId,
        tenantId,
        sha256("registration-agent"),
        sha256("registration-prefix"),
      ],
    );
    return {
      cluster,
      control,
      auth: new EnterpriseAuthStore(control),
      legacy: new ControlPlaneStore(control),
      databaseName,
      tenantId,
      identityId,
      enrollmentSessionId,
    };
  } catch (error) {
    return cleanupAfterFailure(error, () => cleanupEnterpriseAuthDatabase(cluster, control, databaseName), "Enterprise-auth fixture setup");
  }
}

function sessionInput(label: string) {
  return {
    tokenHash: sha256(randomBytes(32)),
    csrfHash: sha256(randomBytes(32)),
    expiresAt: new Date(Date.now() + 60 * 60_000),
    userAgentHash: sha256(label),
    ipPrefixHash: sha256(`${label}-wifi`),
    deviceLabel: label,
  };
}

async function cleanupFixture(current: Fixture): Promise<void> {
  await cleanupEnterpriseAuthDatabase(current.cluster, current.control, current.databaseName);
}

async function cleanupEnterpriseAuthDatabase(cluster: Pool, control: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [control], assertSafeDatabaseName: assertEnterpriseAuthDatabaseName }],
    label: "Temporary enterprise-auth database",
  });
}

function assertEnterpriseAuthDatabaseName(databaseName: string): void {
  if (!/^nom_enterprise_auth_[0-9a-f]{24}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-enterprise-auth test database");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const result = await pool.query<{ sql: string }>(query, [...values]);
  const sql = result.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the enterprise auth test statement");
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
  if (!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) || Number(url.port || "5432") !== workspacePort) {
    throw new Error("Enterprise auth tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function requireFixture(): Fixture {
  if (!fixture) throw new Error("Enterprise auth fixture is unavailable");
  return fixture;
}
