import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hash } from "argon2";
import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { ControlPlaneStore, type MfaChallengeRecord } from "../src/control-store.js";
import { EnterpriseAuthStore } from "../src/enterprise-auth-store.js";
import { runMigrations } from "../src/migrations.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const workspacePort = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Platform control live tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface Fixture {
  readonly cluster: Pool;
  readonly control: Pool;
  readonly store: ControlPlaneStore;
  readonly auth: EnterpriseAuthStore;
  readonly databaseName: string;
  readonly actorId: string;
  readonly outsiderId: string;
  readonly tenantIds: readonly [string, string];
  readonly actorSessionId: string;
  readonly outsiderSessionId: string;
}

let fixture: Fixture | undefined;

live("global control-plane boundaries", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 60_000);

  afterEach(async () => {
    if (!fixture) return;
    await fixture.control.query(
      "INSERT INTO platform_role_bindings(identity_id,role_code) VALUES ($1,'platform_admin') ON CONFLICT DO NOTHING",
      [fixture.actorId],
    );
  });

  it("makes the compiled global identity-policy baseline immutable at runtime", async () => {
    const current = requireFixture();
    await expect(current.control.query(
      "UPDATE identity_policy_baseline SET version=version+1 WHERE policy_key='global'",
    )).rejects.toMatchObject({ code: "55000" });
    const baseline = await current.control.query<{ version: string }>(
      "SELECT version::text FROM identity_policy_baseline WHERE policy_key='global'",
    );
    expect(baseline.rows[0]?.version).toBe("1");
  });

  it("lists only an identity's memberships and rotates session/CSRF only into an active membership", async () => {
    const current = requireFixture();
    const memberships = await current.store.listOwnMemberships(current.actorId);
    expect(memberships.map(({ tenantId }) => tenantId).sort()).toEqual([...current.tenantIds].sort());
    expect(JSON.stringify(memberships)).not.toContain("database_name");
    expect(await current.store.listOwnMemberships(current.outsiderId)).toEqual([
      expect.objectContaining({ tenantId: current.tenantIds[0] }),
    ]);

    const tokenHash = sha256(randomBytes(32).toString("base64url"));
    const csrfHash = sha256(randomBytes(32).toString("base64url"));
    const rotatedId = await current.store.rotateSessionTenant({
      currentSessionId: current.actorSessionId,
      identityId: current.actorId,
      targetTenantId: current.tenantIds[1],
      tokenHash,
      csrfHash,
      expiresAt: new Date(Date.now() + 10 * 60_000),
      idleTimeoutMinutes: 30,
    });
    expect(rotatedId).toMatch(/^[0-9a-f-]{36}$/i);
    const rotated = await current.control.query<{
      old_revoked_at: Date | null;
      active_tenant_id: string;
      csrf_hash: string;
      assurance_level: string;
    }>(
      `SELECT old_session.revoked_at AS old_revoked_at,
              new_session.active_tenant_id::text,new_session.csrf_hash,new_session.assurance_level
         FROM auth_sessions old_session
         JOIN auth_sessions new_session ON new_session.id=$2
        WHERE old_session.id=$1`,
      [current.actorSessionId, rotatedId],
    );
    expect(rotated.rows[0]).toMatchObject({
      old_revoked_at: expect.any(Date),
      active_tenant_id: current.tenantIds[1],
      csrf_hash: csrfHash,
      assurance_level: "mfa",
    });
    await expect(current.store.getSession(tokenHash, {})).resolves.toMatchObject({
      sessionId: rotatedId,
      activeTenantId: current.tenantIds[1],
      tenantTimezone: "America/La_Paz",
    });

    const denied = await current.store.rotateSessionTenant({
      currentSessionId: current.outsiderSessionId,
      identityId: current.outsiderId,
      targetTenantId: current.tenantIds[1],
      tokenHash: sha256(randomBytes(32).toString("base64url")),
      csrfHash: sha256(randomBytes(32).toString("base64url")),
      expiresAt: new Date(Date.now() + 10 * 60_000),
      idleTimeoutMinutes: 30,
    });
    expect(denied).toBeNull();
    const outsiderSession = await current.control.query<{ revoked_at: Date | null }>(
      "SELECT revoked_at FROM auth_sessions WHERE id=$1",
      [current.outsiderSessionId],
    );
    expect(outsiderSession.rows[0]?.revoked_at).toBeNull();
  });

  it("keeps password lockout on a fixed window and starts a fresh counter after expiry", async () => {
    const current = requireFixture();
    await current.control.query(
      "UPDATE platform_identities SET failed_login_count=0,locked_until=NULL WHERE id=$1",
      [current.outsiderId],
    );
    try {
      for (let attempt = 0; attempt < 8; attempt += 1) {
        await current.store.recordLoginFailure(current.outsiderId);
      }
      const locked = await current.control.query<{ failed_login_count: number; locked_until: Date | null }>(
        "SELECT failed_login_count,locked_until FROM platform_identities WHERE id=$1",
        [current.outsiderId],
      );
      expect(locked.rows[0]?.failed_login_count).toBe(8);
      expect(locked.rows[0]?.locked_until).toBeInstanceOf(Date);
      expect(locked.rows[0]?.locked_until?.getTime()).toBeGreaterThan(Date.now());
      const fixedExpiry = locked.rows[0]?.locked_until?.getTime();

      await current.store.recordLoginFailure(current.outsiderId);
      const repeated = await current.control.query<{ failed_login_count: number; locked_until: Date | null }>(
        "SELECT failed_login_count,locked_until FROM platform_identities WHERE id=$1",
        [current.outsiderId],
      );
      expect(repeated.rows[0]?.failed_login_count).toBe(8);
      expect(repeated.rows[0]?.locked_until?.getTime()).toBe(fixedExpiry);

      await current.control.query(
        "UPDATE platform_identities SET locked_until=clock_timestamp()-interval '1 second' WHERE id=$1",
        [current.outsiderId],
      );
      await current.store.recordLoginFailure(current.outsiderId);
      const restarted = await current.control.query<{ failed_login_count: number; locked_until: Date | null }>(
        "SELECT failed_login_count,locked_until FROM platform_identities WHERE id=$1",
        [current.outsiderId],
      );
      expect(restarted.rows[0]).toEqual({ failed_login_count: 1, locked_until: null });
    } finally {
      await current.control.query(
        "UPDATE platform_identities SET failed_login_count=0,locked_until=NULL WHERE id=$1",
        [current.outsiderId],
      );
    }
  });

  it("accumulates MFA failures across fresh challenges in the identity-wide fixed window", async () => {
    const current = requireFixture();
    const [tenantId] = current.tenantIds;
    const binding = {
      originHash: sha256("http://localhost:3000"),
      userAgentHash: sha256("mfa-throttle-browser"),
      ipPrefixHash: sha256("127.0.0.0/24"),
    };
    await current.control.query(
      "UPDATE platform_identities SET failed_login_count=0,locked_until=NULL WHERE id=$1",
      [current.actorId],
    );
    try {
      for (let attempt = 0; attempt < 8; attempt += 1) {
        const tokenHash = sha256(`mfa-token-${attempt}-${randomUUID()}`);
        const challenge = await current.store.createMfaChallenge(
          tokenHash,
          current.actorId,
          tenantId,
          new Date(Date.now() + 5 * 60_000),
          binding,
        );
        await expect(current.store.reserveMfaChallengeAttempt(
          tokenHash,
          challenge.challengeId,
          binding,
        )).resolves.toMatchObject({ attemptCount: 1, identityId: current.actorId });
        await current.store.failMfaChallenge(challenge.challengeId);
      }
      const locked = await current.control.query<{ failed_login_count: number; locked_until: Date | null }>(
        "SELECT failed_login_count,locked_until FROM platform_identities WHERE id=$1",
        [current.actorId],
      );
      expect(locked.rows[0]?.failed_login_count).toBe(8);
      expect(locked.rows[0]?.locked_until?.getTime()).toBeGreaterThan(Date.now());
      await expect(current.store.createMfaChallenge(
        sha256(`mfa-token-blocked-${randomUUID()}`),
        current.actorId,
        tenantId,
        new Date(Date.now() + 5 * 60_000),
        { originHash: sha256("http://localhost:3000") },
      )).rejects.toThrow(/did not return a row/i);
    } finally {
      await current.control.query("DELETE FROM mfa_challenges WHERE identity_id=$1", [current.actorId]);
      await current.control.query(
        "UPDATE platform_identities SET failed_login_count=0,locked_until=NULL WHERE id=$1",
        [current.actorId],
      );
    }
  });

  it("atomically caps parallel MFA verification reservations at six attempts", async () => {
    const current = requireFixture();
    const [tenantId] = current.tenantIds;
    const tokenHash = sha256(`mfa-concurrency-${randomUUID()}`);
    const binding = {
      originHash: sha256("http://localhost:3000"),
      userAgentHash: sha256("mfa-concurrency-browser"),
      ipPrefixHash: sha256("127.0.0.0/24"),
    };
    const challenge = await current.store.createMfaChallenge(
      tokenHash,
      current.actorId,
      tenantId,
      new Date(Date.now() + 5 * 60_000),
      binding,
    );
    try {
      const reservations = await Promise.all(Array.from({ length: 8 }, () =>
        current.store.reserveMfaChallengeAttempt(tokenHash, challenge.challengeId, binding)
      ));
      const accepted = reservations.filter((reservation): reservation is MfaChallengeRecord => reservation !== null);
      expect(accepted).toHaveLength(6);
      expect(accepted.map(({ attemptCount }) => attemptCount).sort((left, right) => left - right)).toEqual([1, 2, 3, 4, 5, 6]);
      const persisted = await current.control.query<{ attempt_count: number }>(
        "SELECT attempt_count FROM mfa_challenges WHERE id=$1",
        [challenge.challengeId],
      );
      expect(persisted.rows[0]?.attempt_count).toBe(6);
    } finally {
      await current.control.query("DELETE FROM mfa_challenges WHERE id=$1", [challenge.challengeId]);
    }
  });

  it("resolves an eligible MFA rate-limit identity without reserving an attempt and rejects invalid challenge state", async () => {
    const current = requireFixture();
    const fixtureId = randomUUID();
    const suffix = fixtureId.replaceAll("-", "");
    const tenantId = randomUUID();
    const identityId = randomUUID();
    const tokenHash = sha256(`mfa-rate-limit-token-${fixtureId}`);
    const binding = {
      originHash: sha256("https://mfa-rate-limit.invalid"),
      userAgentHash: sha256(`mfa-rate-limit-agent-${fixtureId}`),
      ipPrefixHash: sha256("192.0.2.0/24"),
    };
    let challengeId: string | undefined;

    try {
      await current.control.query(
        `INSERT INTO tenants(
           id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,runtime_secret_ref,
           database_port,activated_at
         ) VALUES ($1,$2,'MFA rate-limit tenant','demo','active','America/La_Paz','es',$3,$4,$5,55432,clock_timestamp())`,
        [
          tenantId,
          `mfa-rate-limit-${suffix}`,
          `nom_control_target_mfa_${suffix}`,
          `nom_control_role_mfa_${suffix}`,
          `tenant-db/${tenantId}/runtime/v1`,
        ],
      );
      await current.control.query(
        `INSERT INTO platform_identities(
           id,email,normalized_email,display_name,password_hash,mfa_enabled,mfa_required,
           totp_secret_ciphertext,mfa_enrolled_at,status
         ) VALUES ($1,$2,$2,'MFA rate-limit identity','disabled',true,true,'cipher',clock_timestamp(),'active')`,
        [identityId, `mfa-rate-limit-${suffix}@invalid.example`],
      );
      await current.control.query(
        "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
        [tenantId, identityId],
      );
      const challenge = await current.store.createMfaChallenge(
        tokenHash,
        identityId,
        tenantId,
        new Date(Date.now() + 5 * 60_000),
        binding,
      );
      challengeId = challenge.challengeId;
      await current.control.query("UPDATE mfa_challenges SET attempt_count=2 WHERE id=$1", [challengeId]);

      const expectResolution = async (
        candidateTokenHash: string,
        candidateChallengeId: string,
        candidateBinding: typeof binding,
        expectedIdentityId: string | null,
      ): Promise<void> => {
        await expect(current.store.resolveMfaRateLimitIdentity(
          candidateTokenHash,
          candidateChallengeId,
          candidateBinding,
        )).resolves.toBe(expectedIdentityId);
        const attempts = await current.control.query<{ attempt_count: number }>(
          "SELECT attempt_count FROM mfa_challenges WHERE id=$1",
          [challengeId],
        );
        expect(attempts.rows[0]?.attempt_count).toBe(2);
      };

      await expectResolution(tokenHash, challengeId, binding, identityId);
      await expectResolution(sha256(`wrong-token-${fixtureId}`), challengeId, binding, null);
      await expectResolution(tokenHash, randomUUID(), binding, null);
      await expectResolution(tokenHash, challengeId, {
        ...binding,
        originHash: sha256("https://wrong-origin.invalid"),
      }, null);
      await expectResolution(tokenHash, challengeId, {
        ...binding,
        userAgentHash: sha256("wrong-user-agent"),
      }, null);
      await expectResolution(tokenHash, challengeId, {
        ...binding,
        ipPrefixHash: sha256("198.51.100.0/24"),
      }, null);

      await current.control.query(
        "UPDATE mfa_challenges SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
        [challengeId],
      );
      await expectResolution(tokenHash, challengeId, binding, null);
      await current.control.query(
        "UPDATE mfa_challenges SET expires_at=clock_timestamp()+interval '5 minutes',consumed_at=clock_timestamp() WHERE id=$1",
        [challengeId],
      );
      await expectResolution(tokenHash, challengeId, binding, null);
      await current.control.query("UPDATE mfa_challenges SET consumed_at=NULL WHERE id=$1", [challengeId]);

      await current.control.query(
        "UPDATE tenant_memberships SET status='suspended' WHERE tenant_id=$1 AND identity_id=$2",
        [tenantId, identityId],
      );
      await expectResolution(tokenHash, challengeId, binding, null);
      await current.control.query(
        "UPDATE tenant_memberships SET status='active' WHERE tenant_id=$1 AND identity_id=$2",
        [tenantId, identityId],
      );
      await current.control.query(
        "UPDATE platform_identities SET locked_until=clock_timestamp()+interval '5 minutes' WHERE id=$1",
        [identityId],
      );
      await expectResolution(tokenHash, challengeId, binding, null);
    } finally {
      await current.control.query("DELETE FROM mfa_challenges WHERE identity_id=$1 AND tenant_id=$2", [identityId, tenantId]);
      await current.control.query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND identity_id=$2", [tenantId, identityId]);
      await current.control.query("DELETE FROM platform_identities WHERE id=$1", [identityId]);
      await current.control.query("DELETE FROM tenants WHERE id=$1", [tenantId]);
    }
  });

  it("enforces an active-session limit within one tenant without revoking another tenant", async () => {
    const current = requireFixture();
    const [firstTenantId, secondTenantId] = current.tenantIds;
    const create = (tenantId: string, label: string) => current.store.createSession({
      tokenHash: sha256(`${label}-token-${randomUUID()}`),
      csrfHash: sha256(`${label}-csrf-${randomUUID()}`),
      identityId: current.actorId,
      tenantId,
      expiresAt: new Date(Date.now() + 60 * 60_000),
      assuranceLevel: "mfa",
      authMethod: "totp",
      aal: 2,
      idleTimeoutMinutes: 30,
      deviceLabel: label,
    });
    const created = await Promise.all([
      create(firstTenantId, "tenant-one-current"),
      create(firstTenantId, "tenant-one-excess"),
      create(secondTenantId, "tenant-two-one"),
      create(secondTenantId, "tenant-two-two"),
    ]);
    try {
      await expect(current.auth.enforceSessionLimit(
        current.actorId,
        firstTenantId,
        created[0]!,
        1,
      )).resolves.toBeGreaterThanOrEqual(1);
      const rows = await current.control.query<{ id: string; active_tenant_id: string; revoked_at: Date | null }>(
        "SELECT id,active_tenant_id::text,revoked_at FROM auth_sessions WHERE id=ANY($1::uuid[])",
        [created],
      );
      const byId = new Map(rows.rows.map((row) => [row.id, row]));
      expect(byId.get(created[0]!)).toMatchObject({ active_tenant_id: firstTenantId, revoked_at: null });
      expect(byId.get(created[1]!)?.revoked_at).toBeInstanceOf(Date);
      expect(byId.get(created[2]!)).toMatchObject({ active_tenant_id: secondTenantId, revoked_at: null });
      expect(byId.get(created[3]!)).toMatchObject({ active_tenant_id: secondTenantId, revoked_at: null });
    } finally {
      await current.control.query("DELETE FROM auth_sessions WHERE id=ANY($1::uuid[])", [created]);
    }
  });

  it("serializes concurrent session creation and enforces the tenant cap atomically", async () => {
    const current = requireFixture();
    const [tenantId] = current.tenantIds;
    const createdSessionIds: string[] = [];
    await current.control.query(
      `INSERT INTO tenant_identity_policies(
         tenant_id,version,enforcement_mode,minimum_aal,privileged_minimum_aal,
         require_user_verification,require_phishing_resistant_for_privileged,
         require_device_bound_for_privileged,require_attestation_for_privileged,
         allow_password,allow_totp_fallback,allow_recovery_codes,allow_synced_passkeys,
         minimum_passkey_count,privileged_minimum_passkey_count,maximum_passkeys,
         maximum_active_sessions,idle_timeout_minutes,absolute_session_minutes,
         step_up_ttl_seconds,action_requirements,changed_by_identity_id
       )
       SELECT $1,baseline.version,baseline.enforcement_mode,baseline.minimum_aal,
              baseline.privileged_minimum_aal,baseline.require_user_verification,
              baseline.require_phishing_resistant_for_privileged,
              baseline.require_device_bound_for_privileged,
              baseline.require_attestation_for_privileged,baseline.allow_password,
              baseline.allow_totp_fallback,baseline.allow_recovery_codes,
              baseline.allow_synced_passkeys,baseline.minimum_passkey_count,
              baseline.privileged_minimum_passkey_count,baseline.maximum_passkeys,
              2,baseline.idle_timeout_minutes,baseline.absolute_session_minutes,
              baseline.step_up_ttl_seconds,baseline.action_requirements,$2
         FROM identity_policy_baseline baseline
        WHERE baseline.policy_key='global'`,
      [tenantId, current.actorId],
    );
    try {
      const created = await Promise.all(Array.from({ length: 12 }, async (_, index) => current.store.createSession({
        tokenHash: sha256(`concurrent-token-${index}-${randomUUID()}`),
        csrfHash: sha256(`concurrent-csrf-${index}-${randomUUID()}`),
        identityId: current.outsiderId,
        tenantId,
        expiresAt: new Date(Date.now() + 60 * 60_000),
        assuranceLevel: "password",
        idleTimeoutMinutes: 30,
        deviceLabel: `Concurrent browser ${index + 1}`,
      })));
      createdSessionIds.push(...created);
      expect(new Set(created)).toHaveLength(12);

      const sessions = await current.control.query<{ id: string; revoked_at: Date | null; revoke_reason: string | null }>(
        `SELECT id,revoked_at,revoke_reason
           FROM auth_sessions
          WHERE identity_id=$1 AND active_tenant_id=$2
          ORDER BY created_at,id`,
        [current.outsiderId, tenantId],
      );
      const active = sessions.rows.filter(({ revoked_at: revokedAt }) => revokedAt === null);
      expect(active).toHaveLength(2);
      expect(active.every(({ id }) => created.includes(id))).toBe(true);
      expect(sessions.rows.filter(({ revoke_reason: reason }) => reason === "active_session_limit").length).toBeGreaterThanOrEqual(10);
    } finally {
      if (createdSessionIds.length > 0) {
        await current.control.query("DELETE FROM auth_sessions WHERE id=ANY($1::uuid[])", [createdSessionIds]);
      }
      await current.control.query(
        `UPDATE auth_sessions
            SET revoked_at=NULL,revoke_reason=NULL,expires_at=clock_timestamp()+interval '15 minutes',
                idle_expires_at=clock_timestamp()+interval '15 minutes',last_seen_at=clock_timestamp()
          WHERE id=$1`,
        [current.outsiderSessionId],
      );
      await current.control.query("DELETE FROM tenant_identity_policies WHERE tenant_id=$1", [tenantId]);
    }
  });

  it("provides an authoritative active-membership directory for committee selection", async () => {
    const current = requireFixture();
    const [primaryTenantId] = current.tenantIds;
    const active = await current.store.listActiveTenantMembershipIdentities(primaryTenantId);
    expect(active).toEqual(expect.arrayContaining([
      expect.objectContaining({ identityId: current.actorId, membershipStatus: "active" }),
      expect.objectContaining({ identityId: current.outsiderId, membershipStatus: "active" }),
    ]));
    expect(active).toHaveLength(2);
    expect(await current.store.hasActiveMembership(randomUUID(), primaryTenantId)).toBe(false);

    await current.control.query(
      "UPDATE tenant_memberships SET status='suspended' WHERE tenant_id=$1 AND identity_id=$2",
      [primaryTenantId, current.outsiderId],
    );
    try {
      expect(await current.store.listActiveTenantMembershipIdentities(primaryTenantId)).toEqual([
        expect.objectContaining({ identityId: current.actorId, membershipStatus: "active" }),
      ]);
      expect(await current.store.hasActiveMembership(current.outsiderId, primaryTenantId)).toBe(false);
    } finally {
      await current.control.query(
        "UPDATE tenant_memberships SET status='active' WHERE tenant_id=$1 AND identity_id=$2",
        [primaryTenantId, current.outsiderId],
      );
    }
  });

  it("consumes global-admin bootstrap exactly once, expires stale tokens, and loses races closed", async () => {
    const current = requireFixture();
    await current.control.query(
      "DELETE FROM platform_role_bindings WHERE identity_id=$1 AND role_code='platform_admin'",
      [current.actorId],
    );
    const passwordHash = await hash("Bootstrap#Strong2026", {
      type: 2, memoryCost: 19_456, timeCost: 2, parallelism: 1,
    });
    const bootstrapToken = randomBytes(32).toString("base64url");
    await current.control.query(
      `INSERT INTO platform_admin_bootstrap_tokens(token_hash,purpose,anchor_tenant_id,expires_at)
       VALUES ($1,'bootstrap',$2,clock_timestamp()+interval '1 hour')`,
      [sha256(bootstrapToken), current.tenantIds[0]],
    );
    const accepted = await current.store.consumePlatformAdminBootstrap({
      tokenHash: sha256(bootstrapToken),
      email: "global.admin@invalid.example",
      normalizedEmail: "global.admin@invalid.example",
      displayName: "Global administrator",
      passwordHash,
      identityId: randomUUID(),
      sessionId: randomUUID(),
      sessionTokenHash: sha256(randomUUID()),
      csrfHash: sha256(randomUUID()),
      sessionExpiresAt: new Date(Date.now() + 60 * 60_000),
      requestId: randomUUID(),
    });
    expect(accepted).toEqual(expect.objectContaining({ tenantId: current.tenantIds[0] }));
    const persisted = await current.control.query<{
      status: string; mfa_required: boolean; mfa_enabled: boolean; assurance_level: string;
      audit_metadata: unknown;
    }>(
      `SELECT bootstrap.status,identity.mfa_required,identity.mfa_enabled,session.assurance_level,
              audit.metadata AS audit_metadata
         FROM platform_admin_bootstrap_tokens bootstrap
         JOIN platform_identities identity ON identity.id=bootstrap.consumed_by_identity_id
         JOIN platform_role_bindings binding ON binding.identity_id=identity.id AND binding.role_code='platform_admin'
         JOIN auth_sessions session ON session.id=bootstrap.consumed_session_id
         JOIN LATERAL (
           SELECT metadata FROM platform_audit_events
            WHERE action='platform.admin_bootstrap_consumed' AND actor_identity_id=identity.id
            ORDER BY sequence DESC LIMIT 1
         ) audit ON true
        WHERE bootstrap.token_hash=$1`,
      [sha256(bootstrapToken)],
    );
    expect(persisted.rows[0]).toEqual({
      status: "consumed",
      mfa_required: true,
      mfa_enabled: false,
      assurance_level: "enrollment_only",
      audit_metadata: { assurance: "enrollment_only", contentAccess: false, keyAccess: false },
    });
    expect(JSON.stringify(persisted.rows[0])).not.toMatch(/Bootstrap#Strong2026|global\.admin/);
    expect(JSON.stringify(persisted.rows[0])).not.toContain(bootstrapToken);
    await expect(current.store.consumePlatformAdminBootstrap({
      tokenHash: sha256(bootstrapToken),
      email: "replay@invalid.example",
      normalizedEmail: "replay@invalid.example",
      displayName: "Replay denied",
      passwordHash,
      identityId: randomUUID(), sessionId: randomUUID(), sessionTokenHash: sha256(randomUUID()),
      csrfHash: sha256(randomUUID()), sessionExpiresAt: new Date(Date.now() + 60 * 60_000), requestId: randomUUID(),
    })).resolves.toBeNull();

    const expiredToken = randomBytes(32).toString("base64url");
    await current.control.query(
      `INSERT INTO platform_admin_bootstrap_tokens(
         token_hash,purpose,anchor_tenant_id,recovery_reason_code,external_incident_ref_hash,created_at,expires_at
       ) VALUES ($1,'recovery',$2,'AUTHORIZED_RECOVERY',$3,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour')`,
      [sha256(expiredToken), current.tenantIds[0], sha256("INCIDENT-EXPIRED-TEST")],
    );
    const expired = await current.store.consumePlatformAdminBootstrap({
      tokenHash: sha256(expiredToken), email: "expired@invalid.example", normalizedEmail: "expired@invalid.example",
      displayName: "Expired bootstrap", passwordHash, identityId: randomUUID(), sessionId: randomUUID(),
      sessionTokenHash: sha256(randomUUID()), csrfHash: sha256(randomUUID()),
      sessionExpiresAt: new Date(Date.now() + 60 * 60_000), requestId: randomUUID(),
    });
    expect(expired).toBeNull();
    expect((await current.control.query<{ status: string }>(
      "SELECT status FROM platform_admin_bootstrap_tokens WHERE token_hash=$1",
      [sha256(expiredToken)],
    )).rows[0]?.status).toBe("expired");

    const raceToken = randomBytes(32).toString("base64url");
    await current.control.query(
      `INSERT INTO platform_admin_bootstrap_tokens(
         token_hash,purpose,anchor_tenant_id,recovery_reason_code,external_incident_ref_hash,expires_at
       ) VALUES ($1,'recovery',$2,'ADMIN_ACCESS_LOSS',$3,clock_timestamp()+interval '1 hour')`,
      [sha256(raceToken), current.tenantIds[0], sha256("INCIDENT-CONCURRENT-RECOVERY")],
    );

    await expect(current.control.query(
      `INSERT INTO platform_admin_bootstrap_tokens(
         token_hash,purpose,anchor_tenant_id,recovery_reason_code,external_incident_ref_hash,expires_at
       ) VALUES ($1,'recovery',$2,'PERSONA_TIENE_DIAGNOSTICO',$3,clock_timestamp()+interval '1 hour')`,
      [sha256(randomUUID()), current.tenantIds[0], sha256("INCIDENT-PII-SMUGGLE")],
    )).rejects.toMatchObject({ code: "23514" });
    const raceInput = (suffix: string) => ({
      tokenHash: sha256(raceToken), email: `race-${suffix}@invalid.example`, normalizedEmail: `race-${suffix}@invalid.example`,
      displayName: `Race ${suffix}`, passwordHash, identityId: randomUUID(), sessionId: randomUUID(),
      sessionTokenHash: sha256(randomUUID()), csrfHash: sha256(randomUUID()),
      sessionExpiresAt: new Date(Date.now() + 60 * 60_000), requestId: randomUUID(),
    });
    const race = await Promise.all([
      current.store.consumePlatformAdminBootstrap(raceInput("one")),
      current.store.consumePlatformAdminBootstrap(raceInput("two")),
    ]);
    expect(race.filter(Boolean)).toHaveLength(1);
  });

  it("queues idempotent provisioning, exposes no tenant credentials, reports worker health, and suspends globally", async () => {
    const current = requireFixture();
    expect(await current.store.getPlatformPermissions(current.actorId)).toEqual(expect.arrayContaining([
      "platform.operation.read",
      "platform.tenant.provision",
      "platform.tenant.suspend",
    ]));

    const request = {
      idempotencyKey: randomUUID(),
      tenantId: randomUUID(),
      slug: `scratch-${randomBytes(4).toString("hex")}`,
      displayName: "Queued scratch church",
      kind: "real" as const,
      timezone: "America/La_Paz",
      locale: "es" as const,
    };
    const first = await current.store.queueTenantProvisioning(request, current.actorId, randomUUID());
    const replay = await current.store.queueTenantProvisioning(request, current.actorId, randomUUID());
    expect(first).toMatchObject({ state: "requested", reused: false });
    expect(replay).toEqual({ ...first, reused: true });

    const tenants = await current.store.listTenants();
    expect(tenants).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: request.tenantId, slug: request.slug, status: "provisioning", provisioningState: "requested", activationState: "pending_activation" }),
    ]));
    expect(JSON.stringify(tenants)).not.toMatch(/databaseName|runtimeRole|secretReference|database_host|runtime_secret/i);

    await current.control.query(
      `INSERT INTO tenants(
         id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,runtime_secret_ref,
         database_port
       ) VALUES ($1,$2,$3,$4,'provisioning',$5,$6,$7,$8,$9,55432)`,
      [request.tenantId, request.slug, request.displayName, request.kind, request.timezone, request.locale,
        `nom_pending_target_${randomBytes(3).toString("hex")}`,
        `nom_pending_role_${randomBytes(3).toString("hex")}`,
        `tenant-db/${request.tenantId}/runtime/v1`],
    );
    await current.control.query(
      "UPDATE provisioning_jobs SET state='pending_activation' WHERE tenant_id=$1",
      [request.tenantId],
    );
    const invitationToken = randomBytes(32).toString("base64url");
    const activationKey = randomUUID();
    const invitationExpiresAt = new Date(Date.now() + 72 * 60 * 60_000);
    const activated = await current.store.activateTenantInitialAdmin({
      tenantId: request.tenantId,
      expectedVersion: 1,
      email: "first.admin@invalid.example",
      normalizedEmail: "first.admin@invalid.example",
      tokenHash: sha256(invitationToken),
      expiresAt: invitationExpiresAt,
      expiresInHours: 72,
      idempotencyKey: activationKey,
      actorIdentityId: current.actorId,
    });
    expect(activated).toMatchObject({ version: 2, activationState: "invitation_pending", reused: false });
    const activationReplay = await current.store.activateTenantInitialAdmin({
      tenantId: request.tenantId,
      expectedVersion: 1,
      email: "first.admin@invalid.example",
      normalizedEmail: "first.admin@invalid.example",
      tokenHash: sha256(randomBytes(32).toString("base64url")),
      expiresAt: invitationExpiresAt,
      expiresInHours: 72,
      idempotencyKey: activationKey,
      actorIdentityId: current.actorId,
    });
    expect(activationReplay).toEqual({ ...activated, reused: true });
    const invitation = await current.control.query<{
      token_hash: string;
      status: string;
      role_codes: string[];
      tenant_status: string;
      job_state: string;
    }>(
      `SELECT invitation.token_hash,invitation.status,invitation.role_codes,
              tenant.status AS tenant_status,job.state AS job_state
         FROM tenant_invitations invitation
         JOIN tenants tenant ON tenant.id=invitation.tenant_id
         JOIN provisioning_jobs job ON job.tenant_id=tenant.id
        WHERE invitation.id=$1`,
      [activated.invitationId],
    );
    expect(invitation.rows[0]).toEqual({
      token_hash: sha256(invitationToken),
      status: "pending",
      role_codes: ["CHURCH_ADMIN"],
      tenant_status: "active",
      job_state: "active",
    });
    expect(JSON.stringify(invitation.rows[0])).not.toContain(invitationToken);

    expect(await current.store.getProvisioningWorkerStatus()).toMatchObject({ status: "unavailable", healthy: false });
    await current.control.query(
      `INSERT INTO platform_worker_status(worker_code,instance_id,status,started_at,heartbeat_at,processed_count)
       VALUES ('tenant-provisioner',$1,'running',clock_timestamp(),clock_timestamp(),3)`,
      [randomUUID()],
    );
    expect(await current.store.getProvisioningWorkerStatus()).toMatchObject({
      code: "tenant-provisioner",
      status: "running",
      healthy: true,
      processedCount: 3,
    });

    const version = await current.store.suspendTenant({
      tenantId: current.tenantIds[1],
      expectedVersion: 1,
      reasonCode: "operational_hold",
      actorIdentityId: current.actorId,
    });
    expect(version).toBe(2);
    const suspended = await current.control.query<{ status: string; suspension_reason: string; active_sessions: number }>(
      `SELECT tenant.status,tenant.suspension_reason,
              (SELECT count(*)::int FROM auth_sessions session
                WHERE session.active_tenant_id=tenant.id AND session.revoked_at IS NULL) AS active_sessions
         FROM tenants tenant WHERE tenant.id=$1`,
      [current.tenantIds[1]],
    );
    expect(suspended.rows[0]).toEqual({
      status: "suspended",
      suspension_reason: "operational_hold",
      active_sessions: 0,
    });
  });

  it("exports through a privileged job and keeps decommission reversible throughout retention", async () => {
    const current = requireFixture();
    const tenantId = current.tenantIds[1];
    expect(await current.store.getPlatformPermissions(current.actorId)).toEqual(expect.arrayContaining([
      "platform.tenant.export.request",
      "platform.tenant.export.download",
      "platform.tenant.decommission.schedule",
      "platform.tenant.decommission.cancel",
      "platform.tenant.reactivate",
    ]));

    const exportKey = randomUUID();
    const queued = await current.store.queueTenantExport({
      tenantId,
      expectedVersion: 2,
      idempotencyKey: exportKey,
      actorIdentityId: current.actorId,
      requestId: randomUUID(),
    });
    const replay = await current.store.queueTenantExport({
      tenantId,
      expectedVersion: 2,
      idempotencyKey: exportKey,
      actorIdentityId: current.actorId,
      requestId: randomUUID(),
    });
    expect(queued).toMatchObject({ state: "queued", revision: 1, reused: false });
    expect(replay).toEqual({ ...queued, reused: true });

    const backupId = randomUUID();
    const ciphertextSha256 = `sha256:${"7".repeat(64)}`;
    const recoveryPointAt = new Date();
    const publicManifest = {
      format: "nombramientos-tenant-export",
      version: 1,
      backupId,
      tenantId,
      recoveryPointAt: recoveryPointAt.toISOString(),
      completedAt: recoveryPointAt.toISOString(),
      encryption: {
        algorithm: "AES-256-GCM",
        authenticatedCoreSha256: `sha256:${"8".repeat(64)}`,
        keyCustody: "platform-managed-not-exported",
      },
      payload: { file: "database.dump.aesgcm", bytes: 4096, sha256: ciphertextSha256 },
    } as const;
    await current.control.query(
      `UPDATE tenant_export_jobs
          SET state='ready',attempt_count=1,backup_id=$2,artifact_relative_path=$3,
              public_manifest=$4,encrypted_bytes=4096,ciphertext_sha256=$5,recovery_point_at=$6,
              ready_at=clock_timestamp(),updated_at=clock_timestamp(),revision=revision+1
        WHERE id=$1`,
      [queued.jobId, backupId, `${tenantId}/20260911T000000Z-${backupId}`, publicManifest, ciphertextSha256, recoveryPointAt],
    );

    const authorizationKey = randomUUID();
    const authorization = await current.store.authorizeTenantExportDownload({
      authorizationId: randomUUID(),
      tenantId,
      exportJobId: queued.jobId,
      expiresAt: new Date(Date.now() + 5 * 60_000),
      idempotencyKey: authorizationKey,
      actorIdentityId: current.actorId,
    });
    expect(authorization).toMatchObject({ status: "active", revision: 1, reused: false });
    const downloaded = await current.store.consumeTenantExportDownload({
      authorizationId: authorization.authorizationId,
      tenantId,
      exportJobId: queued.jobId,
      actorIdentityId: current.actorId,
    });
    expect(downloaded).toMatchObject({
      artifactRelativePath: `${tenantId}/20260911T000000Z-${backupId}`,
      encryptedBytes: 4096,
      ciphertextSha256,
      backupId,
    });
    await expect(current.store.consumeTenantExportDownload({
      authorizationId: authorization.authorizationId,
      tenantId,
      exportJobId: queued.jobId,
      actorIdentityId: current.actorId,
    })).resolves.toBeNull();

    const revocable = await current.store.authorizeTenantExportDownload({
      authorizationId: randomUUID(), tenantId, exportJobId: queued.jobId,
      expiresAt: new Date(Date.now() + 5 * 60_000), idempotencyKey: randomUUID(),
      actorIdentityId: current.actorId,
    });
    expect(await current.store.revokeTenantExportDownload({
      authorizationId: revocable.authorizationId,
      expectedRevision: revocable.revision,
      actorIdentityId: current.actorId,
    })).toEqual({ status: "revoked", revision: 2 });
    expect(await current.store.revokeTenantExportDownload({
      authorizationId: revocable.authorizationId,
      expectedRevision: revocable.revision,
      actorIdentityId: current.actorId,
    })).toEqual({ status: "revoked", revision: 2 });

    const scheduleKey = randomUUID();
    const scheduled = await current.store.scheduleTenantDecommission({
      tenantId,
      expectedVersion: 2,
      exportJobId: queued.jobId,
      retentionDays: 90,
      reasonCode: "institution_request",
      idempotencyKey: scheduleKey,
      actorIdentityId: current.actorId,
    });
    expect(scheduled).toMatchObject({ state: "scheduled", tenantStatus: "decommission_pending", version: 3, reused: false });
    expect(scheduled.retentionUntil!.getTime()).toBeGreaterThan(Date.now() + 89 * 24 * 60 * 60_000);
    const scheduledReplay = await current.store.scheduleTenantDecommission({
      tenantId, expectedVersion: 2, exportJobId: queued.jobId, retentionDays: 90,
      reasonCode: "institution_request", idempotencyKey: scheduleKey, actorIdentityId: current.actorId,
    });
    expect(scheduledReplay).toEqual({ ...scheduled, sessionsRevoked: 0, reused: true });
    await expect(current.store.getTenantCredential(tenantId)).rejects.toThrow(/active tenant credential/i);

    const lifecycle = await current.store.listTenants();
    expect(lifecycle.find(({ id }) => id === tenantId)).toMatchObject({
      status: "decommission_pending",
      latestExport: { id: queued.jobId, state: "ready", publicManifest },
      decommission: { id: scheduled.decommissionId, state: "scheduled", sourceExportJobId: queued.jobId },
    });

    const cancelKey = randomUUID();
    const cancelled = await current.store.cancelTenantDecommission({
      tenantId,
      decommissionId: scheduled.decommissionId,
      expectedVersion: 3,
      idempotencyKey: cancelKey,
      actorIdentityId: current.actorId,
    });
    expect(cancelled).toMatchObject({ state: "cancelled", tenantStatus: "suspended", version: 4, reused: false });
    const cancelReplay = await current.store.cancelTenantDecommission({
      tenantId, decommissionId: scheduled.decommissionId, expectedVersion: 3,
      idempotencyKey: cancelKey, actorIdentityId: current.actorId,
    });
    expect(cancelReplay).toEqual({ ...cancelled, reused: true });
    await expect(current.store.scheduleTenantDecommission({
      tenantId, expectedVersion: 2, exportJobId: queued.jobId, retentionDays: 90,
      reasonCode: "institution_request", idempotencyKey: scheduleKey, actorIdentityId: current.actorId,
    })).rejects.toMatchObject({ code: "40001" });

    const reactivationKey = randomUUID();
    const reactivationInput = () => ({
      tenantId,
      expectedVersion: 4,
      reasonCode: "operational_hold_resolved" as const,
      idempotencyKey: reactivationKey,
      actorIdentityId: current.actorId,
      requestId: randomUUID(),
    });
    const concurrentReactivation = await Promise.all([
      current.store.reactivateTenant(reactivationInput()),
      current.store.reactivateTenant(reactivationInput()),
    ]);
    expect(concurrentReactivation.map(({ reused }) => reused).sort()).toEqual([false, true]);
    for (const result of concurrentReactivation) {
      expect(result).toMatchObject({
        tenantId,
        status: "active",
        version: 5,
        sessionsRevoked: 0,
        sessionsCreated: 0,
      });
    }

    const retained = await current.control.query<{
      status: string; request_state: string; database_name: string;
      suspension_reason: string | null; suspended_at: Date | null; active_sessions: number;
    }>(
      `SELECT tenant.status,request.state AS request_state,tenant.database_name::text,
              tenant.suspension_reason,tenant.suspended_at,
              (SELECT count(*)::int FROM auth_sessions session
                WHERE session.active_tenant_id=tenant.id AND session.revoked_at IS NULL) AS active_sessions
         FROM tenants tenant
         JOIN tenant_decommission_requests request ON request.tenant_id=tenant.id
        WHERE request.id=$1`,
      [scheduled.decommissionId],
    );
    expect(retained.rows[0]).toMatchObject({
      status: "active",
      request_state: "cancelled",
      suspension_reason: null,
      suspended_at: null,
      active_sessions: 0,
    });
    expect(retained.rows[0]?.database_name).toMatch(/^nom_control_target_/u);
  });
});

async function createFixture(databaseAdminUrl: string): Promise<Fixture> {
  const databaseName = `nom_control_test_${randomBytes(12).toString("hex")}`;
  const cluster = new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), max: 1 });
  const control = new Pool({ connectionString: databaseUrl(databaseAdminUrl, databaseName), max: 3 });
  try {
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [databaseName]);
    await runMigrations(control, { scope: "control", directory: path.join(packageRoot, "migrations", "control") });
    const actorId = randomUUID();
    const outsiderId = randomUUID();
    const tenantIds = [randomUUID(), randomUUID()] as const;
    const actorSessionId = randomUUID();
    const outsiderSessionId = randomUUID();
    for (let index = 0; index < tenantIds.length; index += 1) {
      await control.query(
        `INSERT INTO tenants(
           id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,runtime_secret_ref,
           database_port,activated_at
         ) VALUES ($1,$2,$3,'demo','active','America/La_Paz','es',$4,$5,$6,55432,clock_timestamp())`,
        [tenantIds[index], `control-${index}-${randomBytes(3).toString("hex")}`, `Control tenant ${index + 1}`,
          `nom_control_target_${index}_${randomBytes(3).toString("hex")}`,
          `nom_control_role_${index}_${randomBytes(3).toString("hex")}`,
          `tenant-db/${tenantIds[index]}/runtime/v1`],
      );
    }
    await control.query(
      `INSERT INTO platform_identities(
         id,email,normalized_email,display_name,password_hash,mfa_enabled,mfa_required,
         totp_secret_ciphertext,mfa_enrolled_at,status
       ) VALUES
         ($1,'actor@invalid.example','actor@invalid.example','Platform actor','disabled',true,true,'cipher',clock_timestamp(),'active'),
         ($2,'outsider@invalid.example','outsider@invalid.example','Tenant outsider','disabled',false,false,NULL,NULL,'active')`,
      [actorId, outsiderId],
    );
    await control.query(
      `INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES
         ($1,$3,'active',true),($2,$3,'active',false),($1,$4,'active',true)`,
      [tenantIds[0], tenantIds[1], actorId, outsiderId],
    );
    await control.query(
      "INSERT INTO platform_role_bindings(identity_id,role_code) VALUES ($1,'platform_admin')",
      [actorId],
    );
    await control.query(
      `INSERT INTO auth_sessions(
         id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,assurance_level,mfa_verified_at
       ) VALUES
         ($1,$2,$3,$4,$5,clock_timestamp()+interval '15 minutes','mfa',clock_timestamp()),
         ($6,$7,$8,$9,$5,clock_timestamp()+interval '15 minutes','password',NULL)`,
      [actorSessionId, sha256(randomUUID()), sha256(randomUUID()), actorId, tenantIds[0],
        outsiderSessionId, sha256(randomUUID()), sha256(randomUUID()), outsiderId],
    );
    return {
      cluster,
      control,
      store: new ControlPlaneStore(control),
      auth: new EnterpriseAuthStore(control),
      databaseName,
      actorId,
      outsiderId,
      tenantIds,
      actorSessionId,
      outsiderSessionId,
    };
  } catch (error) {
    return cleanupAfterFailure(error, () => cleanupControlDatabase(cluster, control, databaseName), "Control-plane fixture setup");
  }
}

async function cleanupFixture(current: Fixture): Promise<void> {
  await cleanupControlDatabase(current.cluster, current.control, current.databaseName);
}

async function cleanupControlDatabase(cluster: Pool, control: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [control], assertSafeDatabaseName: assertControlDatabaseName }],
    label: "Temporary control-plane database",
  });
}

function assertControlDatabaseName(databaseName: string): void {
  if (!/^nom_control_test_[0-9a-f]{24}$/u.test(databaseName)) throw new Error("Refusing to drop a non-control-test database");
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the platform test statement");
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
    throw new Error("Platform tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function requireFixture(): Fixture {
  if (!fixture) throw new Error("Platform control fixture is unavailable");
  return fixture;
}
