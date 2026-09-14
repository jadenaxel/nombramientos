import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import {
  EnterpriseAuthStore,
  type IdentityPolicyValues,
  type PasskeyCredentialCreateInput,
} from "../src/enterprise-auth-store.js";
import { InvitationStore } from "../src/invitation-store.js";
import { runMigrations } from "../src/migrations.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const workspacePort = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Enterprise auth invariant tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface Fixture {
  readonly cluster: Pool;
  readonly control: Pool;
  readonly auth: EnterpriseAuthStore;
  readonly databaseName: string;
}

interface TenantIdentity {
  readonly tenantId: string;
  readonly identityId: string;
}

interface SessionRow {
  readonly id: string;
  readonly created_at: Date;
  readonly last_seen_at: Date;
  readonly expires_at: Date;
  readonly idle_expires_at: Date;
  readonly idle_timeout_minutes: number;
  readonly revoked_at: Date | null;
  readonly revoke_reason: string | null;
}

let fixture: Fixture | undefined;

live("enterprise authentication invariants on isolated PostgreSQL", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 60_000);

  it("serializes simultaneous first-passkey completions and persists exactly one credential", async () => {
    const current = requireFixture();
    const account = await createTenantIdentity(current.control, "first-passkey");
    const sourceSessionId = await insertEnrollmentSession(current.control, account);
    const ceremonies = await Promise.all([
      insertRegistrationCeremony(current.control, account, sourceSessionId),
      insertRegistrationCeremony(current.control, account, sourceSessionId),
    ]);

    const completions = await Promise.allSettled(ceremonies.map((ceremony, index) =>
      current.auth.completeRegistration({
        ceremonyId: ceremony.id,
        tokenHash: ceremony.tokenHash,
        challengeHash: ceremony.challengeHash,
        credential: credentialInput(account.identityId, `Concurrent first passkey ${index + 1}`),
        newSession: sessionInput(`first-passkey-${index + 1}`),
        requestId: randomUUID(),
      })
    ));

    assertOneCompletionSucceeded(completions);
    expect(completions.filter(({ status }) => status === "rejected")).toHaveLength(1);
    const state = await current.control.query<{
      active_credentials: number;
      active_sessions: number;
      enrollment_revoked: boolean;
      passkey_enabled: boolean;
    }>(
      `SELECT
         (SELECT count(*)::int FROM webauthn_credentials
           WHERE identity_id=$1 AND revoked_at IS NULL) AS active_credentials,
         (SELECT count(*)::int FROM auth_sessions
           WHERE identity_id=$1 AND revoked_at IS NULL
             AND expires_at>clock_timestamp() AND idle_expires_at>clock_timestamp()) AS active_sessions,
         (SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id=$2) AS enrollment_revoked,
         (SELECT passkey_enabled FROM platform_identities WHERE id=$1) AS passkey_enabled`,
      [account.identityId, sourceSessionId],
    );
    expect(state.rows[0]).toEqual({
      active_credentials: 1,
      active_sessions: 1,
      enrollment_revoked: true,
      passkey_enabled: true,
    });
  }, 20_000);

  it("does not exceed the configured passkey maximum during simultaneous registrations", async () => {
    const current = requireFixture();
    const account = await createTenantIdentity(current.control, "passkey-limit");
    const existingCredentialId = await insertCredential(current.control, account.identityId, "Existing passkey");
    const sessions = await Promise.all([
      insertPasskeySession(current.control, account, existingCredentialId, { label: "limit-source-a" }),
      insertPasskeySession(current.control, account, existingCredentialId, { label: "limit-source-b" }),
    ]);
    const baseline = await current.auth.getEffectiveIdentityPolicy(account.tenantId);
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: account.tenantId,
      expectedVersion: 0,
      changedByIdentityId: account.identityId,
      currentSessionId: sessions[0],
      policy: { ...baseline, maximumPasskeys: 2 },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 1, maximumPasskeys: 2 });

    const ceremonies = await Promise.all(sessions.map((sessionId) =>
      insertRegistrationCeremony(current.control, account, sessionId)
    ));
    const completions = await Promise.allSettled(ceremonies.map((ceremony, index) =>
      current.auth.completeRegistration({
        ceremonyId: ceremony.id,
        tokenHash: ceremony.tokenHash,
        challengeHash: ceremony.challengeHash,
        credential: credentialInput(account.identityId, `Limit contender ${index + 1}`),
        newSession: sessionInput(`limit-contender-${index + 1}`),
        requestId: randomUUID(),
      })
    ));

    assertOneCompletionSucceeded(completions);
    const count = await current.control.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM webauthn_credentials WHERE identity_id=$1 AND revoked_at IS NULL",
      [account.identityId],
    );
    expect(count.rows[0]?.count).toBe(2);
  }, 20_000);

  it("replaces a passkey atomically at the maximum and rolls back the old key when insertion fails", async () => {
    const current = requireFixture();
    const account = await createTenantIdentity(current.control, "atomic-replacement");
    const replacementId = await insertCredential(current.control, account.identityId, "Replaceable key");
    const retainedId = await insertCredential(current.control, account.identityId, "Retained key");
    const sourceSessionId = await insertPasskeySession(current.control, account, retainedId, {
      label: "replacement-source",
    });
    const baseline = await current.auth.getEffectiveIdentityPolicy(account.tenantId);
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: account.tenantId,
      expectedVersion: 0,
      changedByIdentityId: account.identityId,
      currentSessionId: sourceSessionId,
      policy: { ...baseline, maximumPasskeys: 2 },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 1, maximumPasskeys: 2 });

    const retainedExternal = await current.control.query<{ credential_id: string }>(
      "SELECT credential_id FROM webauthn_credentials WHERE id=$1",
      [retainedId],
    );
    const failedTokenHash = sha256(randomBytes(32));
    const failedChallengeHash = sha256(randomBytes(32));
    const failedCeremony = await current.auth.createCeremony({
      tokenHash: failedTokenHash,
      challengeHash: failedChallengeHash,
      type: "registration",
      identityId: account.identityId,
      tenantId: account.tenantId,
      sessionId: sourceSessionId,
      replacementCredentialId: replacementId,
      rpId: "localhost",
      expectedOrigin: "http://localhost:3000",
      requireUserVerification: true,
      policyVersion: 1,
      expiresAt: new Date(Date.now() + 5 * 60_000),
    });
    await expect(current.auth.completeRegistration({
      ceremonyId: failedCeremony.id,
      tokenHash: failedTokenHash,
      challengeHash: failedChallengeHash,
      credential: {
        ...credentialInput(account.identityId, "Replaceable key"),
        externalId: retainedExternal.rows[0]!.credential_id,
      },
      newSession: sessionInput("failed-replacement"),
      requestId: randomUUID(),
    })).rejects.toMatchObject({ code: "CREDENTIAL_CONFLICT" });
    await expect(current.auth.getActiveCeremony({
      id: failedCeremony.id,
      tokenHash: failedTokenHash,
      type: "registration",
    })).resolves.toMatchObject({ replacementCredentialId: replacementId });
    const afterRollback = await current.control.query<{
      replacement_active: boolean;
      source_active: boolean;
      active_count: number;
    }>(
      `SELECT
         EXISTS(SELECT 1 FROM webauthn_credentials WHERE id=$1 AND revoked_at IS NULL) AS replacement_active,
         EXISTS(SELECT 1 FROM auth_sessions WHERE id=$2 AND revoked_at IS NULL) AS source_active,
         (SELECT count(*)::int FROM webauthn_credentials WHERE identity_id=$3 AND revoked_at IS NULL) AS active_count`,
      [replacementId, sourceSessionId, account.identityId],
    );
    expect(afterRollback.rows[0]).toEqual({ replacement_active: true, source_active: true, active_count: 2 });

    const tokenHash = sha256(randomBytes(32));
    const challengeHash = sha256(randomBytes(32));
    const ceremony = await current.auth.createCeremony({
      tokenHash,
      challengeHash,
      type: "registration",
      identityId: account.identityId,
      tenantId: account.tenantId,
      sessionId: sourceSessionId,
      replacementCredentialId: replacementId,
      rpId: "localhost",
      expectedOrigin: "http://localhost:3000",
      requireUserVerification: true,
      policyVersion: 1,
      expiresAt: new Date(Date.now() + 5 * 60_000),
    });
    const completed = await current.auth.completeRegistration({
      ceremonyId: ceremony.id,
      tokenHash,
      challengeHash,
      credential: credentialInput(account.identityId, "Replaceable key"),
      newSession: sessionInput("successful-replacement"),
      requestId: randomUUID(),
    });
    const afterCommit = await current.control.query<{
      old_reason: string | null;
      new_active: boolean;
      active_count: number;
      active_sessions: number;
    }>(
      `SELECT
         (SELECT revocation_reason FROM webauthn_credentials WHERE id=$1) AS old_reason,
         EXISTS(SELECT 1 FROM webauthn_credentials WHERE id=$2 AND revoked_at IS NULL) AS new_active,
         (SELECT count(*)::int FROM webauthn_credentials WHERE identity_id=$3 AND revoked_at IS NULL) AS active_count,
         (SELECT count(*)::int FROM auth_sessions WHERE identity_id=$3 AND revoked_at IS NULL) AS active_sessions`,
      [replacementId, completed.credentialId, account.identityId],
    );
    expect(afterCommit.rows[0]).toEqual({
      old_reason: "replaced",
      new_active: true,
      active_count: 2,
      active_sessions: 1,
    });
  }, 30_000);

  it("prevents a replacement from weakening any active tenant's privileged credential posture", async () => {
    const current = requireFixture();
    const account = await createTenantIdentity(current.control, "replacement-multi-tenant");
    const otherTenant = await createTenantIdentity(current.control, "replacement-policy-owner");
    await insertCredential(current.control, otherTenant.identityId, "Other member compliant key");
    await current.control.query(
      "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',false)",
      [otherTenant.tenantId, account.identityId],
    );
    const firstId = await insertCredential(current.control, account.identityId, "Bound key one");
    const secondId = await insertCredential(current.control, account.identityId, "Bound key two");
    const sourceSessionId = await insertPasskeySession(current.control, account, firstId, {
      label: "multi-policy-source",
    });
    const strictBaseline = await current.auth.getEffectiveIdentityPolicy(otherTenant.tenantId);
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: otherTenant.tenantId,
      expectedVersion: 0,
      changedByIdentityId: account.identityId,
      policy: {
        ...strictBaseline,
        enforcementMode: "enforce",
        requireDeviceBoundForPrivileged: true,
        privilegedMinimumPasskeyCount: 2,
      },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 1, enforcementMode: "enforce" });

    const tokenHash = sha256(randomBytes(32));
    const challengeHash = sha256(randomBytes(32));
    const ceremony = await current.auth.createCeremony({
      tokenHash,
      challengeHash,
      type: "registration",
      identityId: account.identityId,
      tenantId: account.tenantId,
      sessionId: sourceSessionId,
      replacementCredentialId: secondId,
      rpId: "localhost",
      expectedOrigin: "http://localhost:3000",
      requireUserVerification: true,
      policyVersion: 1,
      expiresAt: new Date(Date.now() + 5 * 60_000),
    });
    await expect(current.auth.completeRegistration({
      ceremonyId: ceremony.id,
      tokenHash,
      challengeHash,
      credential: {
        ...credentialInput(account.identityId, "Synced downgrade"),
        deviceType: "multiDevice",
        backupEligible: true,
        backedUp: true,
      },
      newSession: sessionInput("multi-policy-replacement"),
      requestId: randomUUID(),
    })).rejects.toMatchObject({ code: "POLICY_CONFLICT" });
    const preserved = await current.control.query<{ target_active: boolean; active_count: number }>(
      `SELECT
         EXISTS(SELECT 1 FROM webauthn_credentials WHERE id=$1 AND revoked_at IS NULL) AS target_active,
         (SELECT count(*)::int FROM webauthn_credentials WHERE identity_id=$2 AND revoked_at IS NULL) AS active_count`,
      [secondId, account.identityId],
    );
    expect(preserved.rows[0]).toEqual({ target_active: true, active_count: 2 });
  }, 30_000);

  it("serializes concurrent revocations against enforced minimums and protects the last sign-in path", async () => {
    const current = requireFixture();
    const enforced = await createTenantIdentity(current.control, "revocation-minimum");
    const enforcedCredentials = await Promise.all([
      insertCredential(current.control, enforced.identityId, "Minimum key 1"),
      insertCredential(current.control, enforced.identityId, "Minimum key 2"),
      insertCredential(current.control, enforced.identityId, "Minimum key 3"),
    ]);
    const baseline = await current.auth.getEffectiveIdentityPolicy(enforced.tenantId);
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: enforced.tenantId,
      expectedVersion: 0,
      changedByIdentityId: enforced.identityId,
      policy: {
        ...baseline,
        enforcementMode: "enforce",
        allowPassword: false,
        minimumPasskeyCount: 2,
        privilegedMinimumPasskeyCount: 2,
        maximumPasskeys: 3,
      },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 1, enforcementMode: "enforce" });

    const revocations = await Promise.allSettled(enforcedCredentials.slice(0, 2).map((credentialId) =>
      current.auth.revokeCredential({
        identityId: enforced.identityId,
        credentialId,
        reason: "policy_change",
        requestId: randomUUID(),
      })
    ));
    expect(revocations.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    expect(revocations.filter(({ status }) => status === "rejected")).toHaveLength(1);
    const rejection = revocations.find(({ status }) => status === "rejected");
    expect(rejection).toMatchObject({ status: "rejected", reason: { code: "POLICY_CONFLICT" } });
    const activeAfterRace = await current.control.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM webauthn_credentials WHERE identity_id=$1 AND revoked_at IS NULL",
      [enforced.identityId],
    );
    expect(activeAfterRace.rows[0]?.count).toBe(2);

    const noFallback = await createTenantIdentity(current.control, "last-sign-in-path");
    const onlyCredentialId = await insertCredential(current.control, noFallback.identityId, "Only sign-in key");
    const noFallbackBaseline = await current.auth.getEffectiveIdentityPolicy(noFallback.tenantId);
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: noFallback.tenantId,
      expectedVersion: 0,
      changedByIdentityId: noFallback.identityId,
      policy: { ...noFallbackBaseline, allowPassword: false },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 1, allowPassword: false });
    await expect(current.auth.revokeCredential({
      identityId: noFallback.identityId,
      credentialId: onlyCredentialId,
      reason: "user_revoked",
      requestId: randomUUID(),
    })).rejects.toMatchObject({ code: "POLICY_CONFLICT" });
  }, 20_000);

  it("permits monitor rollout, rejects unready enforcement atomically, then invalidates stale authorizations on a valid update", async () => {
    const current = requireFixture();
    const administrator = await createTenantIdentity(current.control, "policy-readiness");
    const subjectIdentityId = await insertIdentity(current.control, "policy-subject");
    await current.control.query(
      "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
      [administrator.tenantId, subjectIdentityId],
    );
    const credentialIds = await Promise.all([
      insertCredential(current.control, administrator.identityId, "Administrator key 1"),
      insertCredential(current.control, administrator.identityId, "Administrator key 2"),
    ]);
    const currentSessionId = await insertPasskeySession(
      current.control,
      administrator,
      credentialIds[0]!,
      { label: "policy-current" },
    );
    const baseline = await current.auth.getEffectiveIdentityPolicy(administrator.tenantId);
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: administrator.tenantId,
      expectedVersion: 0,
      changedByIdentityId: administrator.identityId,
      currentSessionId,
      policy: { ...baseline, idleTimeoutMinutes: 25 },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 1, enforcementMode: "monitor", idleTimeoutMinutes: 25 });

    const staleCeremonyTokenHash = sha256(randomBytes(32));
    const staleCeremony = await current.auth.createCeremony({
      tokenHash: staleCeremonyTokenHash,
      challengeHash: sha256(randomBytes(32)),
      type: "authentication",
      identityId: administrator.identityId,
      tenantId: administrator.tenantId,
      rpId: "localhost",
      expectedOrigin: "http://localhost:3000",
      requireUserVerification: true,
      policyVersion: 1,
      expiresAt: new Date(Date.now() + 5 * 60_000),
    });
    const grant = await insertStepUpGrant(
      current.control,
      administrator,
      currentSessionId,
      credentialIds[0]!,
    );
    const staleMfaChallenge = await current.control.query<{ id: string }>(
      `INSERT INTO mfa_challenges(
         token_hash,identity_id,tenant_id,expires_at,origin_hash,user_agent_hash,ip_prefix_hash
       ) VALUES ($1,$2,$3,clock_timestamp()+interval '5 minutes',$4,$5,$6)
       RETURNING id`,
      [
        sha256(randomBytes(32)),
        administrator.identityId,
        administrator.tenantId,
        sha256("http://localhost:3000"),
        sha256("policy-test-agent"),
        sha256("127.0.0.0/24"),
      ],
    );
    const staleMfaChallengeId = staleMfaChallenge.rows[0]?.id;
    if (!staleMfaChallengeId) throw new Error("MFA challenge fixture was not created");

    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: administrator.tenantId,
      expectedVersion: 1,
      changedByIdentityId: administrator.identityId,
      currentSessionId,
      policy: { ...baseline, enforcementMode: "enforce", idleTimeoutMinutes: 20 },
      requestId: randomUUID(),
    })).rejects.toMatchObject({ code: "POLICY_CONFLICT" });
    await expect(current.auth.getEffectiveIdentityPolicy(administrator.tenantId)).resolves.toMatchObject({
      tenantVersion: 1,
      enforcementMode: "monitor",
      idleTimeoutMinutes: 25,
    });
    await expect(current.auth.getActiveCeremony({
      id: staleCeremony.id,
      tokenHash: staleCeremonyTokenHash,
    })).resolves.toMatchObject({ id: staleCeremony.id, tenantId: administrator.tenantId });

    const afterRejectedUpdate = await current.control.query<{
      ceremony_active: boolean;
      mfa_challenge_active: boolean;
      grant_active: boolean;
    }>(
      `SELECT
         EXISTS(SELECT 1 FROM webauthn_ceremonies WHERE id=$1 AND consumed_at IS NULL AND failed_at IS NULL)
           AS ceremony_active,
         EXISTS(SELECT 1 FROM mfa_challenges WHERE id=$3 AND consumed_at IS NULL)
           AS mfa_challenge_active,
         EXISTS(SELECT 1 FROM authentication_step_up_grants WHERE id=$2 AND consumed_at IS NULL AND revoked_at IS NULL)
           AS grant_active`,
      [staleCeremony.id, grant.id, staleMfaChallengeId],
    );
    expect(afterRejectedUpdate.rows[0]).toEqual({
      ceremony_active: true,
      mfa_challenge_active: true,
      grant_active: true,
    });

    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: administrator.tenantId,
      expectedVersion: 1,
      changedByIdentityId: administrator.identityId,
      currentSessionId,
      policy: { ...baseline, idleTimeoutMinutes: 20 },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 2, enforcementMode: "monitor", idleTimeoutMinutes: 20 });
    const invalidated = await current.control.query<{
      ceremony_invalidated: boolean;
      mfa_challenge_invalidated: boolean;
      grant_revoked: boolean;
    }>(
      `SELECT
         EXISTS(SELECT 1 FROM webauthn_ceremonies WHERE id=$1 AND failed_at IS NOT NULL)
           AS ceremony_invalidated,
         EXISTS(SELECT 1 FROM mfa_challenges WHERE id=$3 AND consumed_at IS NOT NULL)
           AS mfa_challenge_invalidated,
         EXISTS(SELECT 1 FROM authentication_step_up_grants WHERE id=$2 AND revoked_at IS NOT NULL)
           AS grant_revoked`,
      [staleCeremony.id, grant.id, staleMfaChallengeId],
    );
    expect(invalidated.rows[0]).toEqual({
      ceremony_invalidated: true,
      mfa_challenge_invalidated: true,
      grant_revoked: true,
    });
    await expect(current.auth.getActiveCeremony({
      id: staleCeremony.id,
      tokenHash: staleCeremonyTokenHash,
    })).resolves.toBeNull();
    await expect(current.auth.consumeStepUpGrant({
      identityId: administrator.identityId,
      sessionId: currentSessionId,
      tokenHash: grant.tokenHash,
      purpose: grant.purpose,
      operationHash: grant.operationHash,
    })).resolves.toBe(false);
  }, 20_000);

  it("does not count a policy-prohibited synced key toward the privileged minimum", async () => {
    const current = requireFixture();
    const administrator = await createTenantIdentity(current.control, "privileged-eligible-readiness");
    await insertCredential(current.control, administrator.identityId, "Eligible device-bound key");
    await insertCredential(
      current.control,
      administrator.identityId,
      "Policy-prohibited synced key",
      "multiDevice",
    );
    const baseline = await current.auth.getEffectiveIdentityPolicy(administrator.tenantId);

    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: administrator.tenantId,
      expectedVersion: 0,
      changedByIdentityId: administrator.identityId,
      policy: {
        ...baseline,
        enforcementMode: "enforce",
        allowSyncedPasskeys: false,
        minimumPasskeyCount: 1,
        privilegedMinimumPasskeyCount: 2,
      },
      requestId: randomUUID(),
    })).rejects.toMatchObject({ code: "POLICY_CONFLICT" });

    await expect(current.auth.getEffectiveIdentityPolicy(administrator.tenantId)).resolves.toMatchObject({
      tenantVersion: null,
      enforcementMode: "monitor",
      allowSyncedPasskeys: true,
    });
  }, 20_000);

  it("uses only a disabled random hash when completion queues behind a newly passwordless policy", async () => {
    const current = requireFixture();
    const administrator = await createTenantIdentity(current.control, "invitation-policy-race");
    await Promise.all([
      insertCredential(current.control, administrator.identityId, "Administrator key 1"),
      insertCredential(current.control, administrator.identityId, "Administrator key 2"),
    ]);
    const baseline = await current.auth.getEffectiveIdentityPolicy(administrator.tenantId);
    const invitationId = randomUUID();
    const acceptanceId = randomUUID();
    const invitedIdentityId = randomUUID();
    const sessionId = randomUUID();
    const invitedEmail = `invited-${randomBytes(5).toString("hex")}@invalid.example`;
    await current.control.query(
      `INSERT INTO tenant_invitations(
         id,tenant_id,email,normalized_email,role_codes,token_hash,status,idempotency_key,
         request_hash,created_by_identity_id,expires_at,acceptance_id,acceptance_identity_id,
         acceptance_started_at,acceptance_attempt
       ) VALUES ($1,$2,$3,$3,ARRAY['AUDITOR']::text[],$4,'accepting',$5,$6,$7,
                  clock_timestamp()+interval '1 hour',$8,$9,clock_timestamp(),1)`,
      [
        invitationId,
        administrator.tenantId,
        invitedEmail,
        sha256(randomBytes(32)),
        randomUUID(),
        sha256(randomBytes(32)),
        administrator.identityId,
        acceptanceId,
        invitedIdentityId,
      ],
    );

    // Hold an existing member while policy activation takes the shared tenant
    // serialization key and blocks in its readiness scan. Completion must then
    // run only after the stricter policy commits.
    const memberLock = await current.control.connect();
    try {
      await memberLock.query("BEGIN");
      await memberLock.query(
        "SELECT identity_id FROM tenant_memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE",
        [administrator.tenantId, administrator.identityId],
      );
      const policyUpdate = current.auth.upsertTenantIdentityPolicy({
        tenantId: administrator.tenantId,
        expectedVersion: 0,
        changedByIdentityId: administrator.identityId,
        policy: {
          ...baseline,
          enforcementMode: "enforce",
          allowPassword: false,
          minimumPasskeyCount: 1,
          privilegedMinimumPasskeyCount: 2,
        },
        requestId: randomUUID(),
      });
      await waitForReadinessLock(current.control);
      const completion = new InvitationStore(current.control).complete({
        claim: {
          invitationId,
          acceptanceId,
          identityId: invitedIdentityId,
          tenantId: administrator.tenantId,
          email: invitedEmail,
          normalizedEmail: invitedEmail,
          roles: ["AUDITOR"],
          expiresAt: new Date(Date.now() + 60 * 60_000),
          createdByIdentityId: administrator.identityId,
          authorityKind: "tenant_delegate",
          authorityEpoch: 0,
          acceptanceAttempt: 1,
        },
        displayName: "Invited user",
        passwordHash: "$argon2id$invitation-policy-race",
        disabledPasswordHash: "$argon2id$disabled-invitation-policy-race",
        bootstrapSession: {
          sessionId,
          tokenHash: sha256(randomBytes(32)),
          csrfHash: sha256(randomBytes(32)),
          expiresAt: new Date(Date.now() + 10 * 60_000),
        },
        requestId: randomUUID(),
      });
      await memberLock.query("COMMIT");
      await expect(policyUpdate).resolves.toMatchObject({ enforcementMode: "enforce", allowPassword: false });
      await expect(completion).resolves.toMatchObject({
        status: "accepted",
        enrollmentSession: { id: sessionId },
      });
    } catch (error) {
      await memberLock.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      memberLock.release();
    }
    const state = await current.control.query<{
      password_hash: string;
      password_provisioned: boolean;
      membership_count: number;
      invitation_status: string;
      session_count: number;
    }>(
      `SELECT
         identity.password_hash,identity.password_provisioned,
         (SELECT count(*)::int FROM tenant_memberships WHERE tenant_id=$2 AND identity_id=$1) AS membership_count,
         (SELECT status FROM tenant_invitations WHERE id=$3) AS invitation_status,
         (SELECT count(*)::int FROM auth_sessions WHERE id=$4 AND identity_id=$1) AS session_count
        FROM platform_identities identity WHERE identity.id=$1`,
      [invitedIdentityId, administrator.tenantId, invitationId, sessionId],
    );
    expect(state.rows[0]).toEqual({
      password_hash: "$argon2id$disabled-invitation-policy-race",
      password_provisioned: false,
      membership_count: 1,
      invitation_status: "accepted",
      session_count: 1,
    });
  }, 20_000);

  it("requires an omitted invitation password atomically when current policy allows password login", async () => {
    const current = requireFixture();
    const administrator = await createTenantIdentity(current.control, "password-required-invitation");
    const invitationId = randomUUID();
    const acceptanceId = randomUUID();
    const invitedIdentityId = randomUUID();
    const sessionId = randomUUID();
    const invitedEmail = `password-required-${randomBytes(5).toString("hex")}@invalid.example`;
    await current.control.query(
      `INSERT INTO tenant_invitations(
         id,tenant_id,email,normalized_email,role_codes,token_hash,status,idempotency_key,
         request_hash,created_by_identity_id,expires_at,acceptance_id,acceptance_identity_id,
         acceptance_started_at,acceptance_attempt
       ) VALUES ($1,$2,$3,$3,ARRAY['AUDITOR']::text[],$4,'accepting',$5,$6,$7,
                  clock_timestamp()+interval '1 hour',$8,$9,clock_timestamp(),1)`,
      [
        invitationId,
        administrator.tenantId,
        invitedEmail,
        sha256(randomBytes(32)),
        randomUUID(),
        sha256(randomBytes(32)),
        administrator.identityId,
        acceptanceId,
        invitedIdentityId,
      ],
    );

    await expect(new InvitationStore(current.control).complete({
      claim: {
        invitationId,
        acceptanceId,
        identityId: invitedIdentityId,
        tenantId: administrator.tenantId,
        email: invitedEmail,
        normalizedEmail: invitedEmail,
        roles: ["AUDITOR"],
        expiresAt: new Date(Date.now() + 60 * 60_000),
        createdByIdentityId: administrator.identityId,
        authorityKind: "tenant_delegate",
        authorityEpoch: 0,
        acceptanceAttempt: 1,
      },
      displayName: "Password required invitee",
      disabledPasswordHash: "$argon2id$discarded-password-required-secret",
      bootstrapSession: {
        sessionId,
        tokenHash: sha256(randomBytes(32)),
        csrfHash: sha256(randomBytes(32)),
        expiresAt: new Date(Date.now() + 10 * 60_000),
      },
      requestId: randomUUID(),
    })).rejects.toMatchObject({ code: "PASSWORD_REQUIRED" });

    const state = await current.control.query<{
      invitation_status: string;
      identities: number;
      memberships: number;
      sessions: number;
    }>(
      `SELECT
         (SELECT status FROM tenant_invitations WHERE id=$2) AS invitation_status,
         (SELECT count(*)::int FROM platform_identities WHERE id=$1) AS identities,
         (SELECT count(*)::int FROM tenant_memberships WHERE identity_id=$1) AS memberships,
         (SELECT count(*)::int FROM auth_sessions WHERE identity_id=$1) AS sessions`,
      [invitedIdentityId, invitationId],
    );
    expect(state.rows[0]).toEqual({
      invitation_status: "accepting",
      identities: 0,
      memberships: 0,
      sessions: 0,
    });
  }, 20_000);

  it("atomically accepts a passwordless invitation into an invitation-bound enrollment session", async () => {
    const current = requireFixture();
    const administrator = await createTenantIdentity(current.control, "passwordless-invitation-bootstrap");
    await Promise.all([
      insertCredential(current.control, administrator.identityId, "Administrator key 1"),
      insertCredential(current.control, administrator.identityId, "Administrator key 2"),
    ]);
    const baseline = await current.auth.getEffectiveIdentityPolicy(administrator.tenantId);
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: administrator.tenantId,
      expectedVersion: 0,
      changedByIdentityId: administrator.identityId,
      policy: {
        ...baseline,
        enforcementMode: "enforce",
        allowPassword: false,
        minimumPasskeyCount: 1,
        privilegedMinimumPasskeyCount: 2,
      },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ enforcementMode: "enforce", allowPassword: false });
    const invitationId = randomUUID();
    const acceptanceId = randomUUID();
    const invitedIdentityId = randomUUID();
    const sessionId = randomUUID();
    const invitedEmail = `passwordless-${randomBytes(5).toString("hex")}@invalid.example`;
    await current.control.query(
      `INSERT INTO tenant_invitations(
         id,tenant_id,email,normalized_email,role_codes,token_hash,status,idempotency_key,
         request_hash,created_by_identity_id,expires_at,acceptance_id,acceptance_identity_id,
         acceptance_started_at,acceptance_attempt
       ) VALUES ($1,$2,$3,$3,ARRAY['AUDITOR']::text[],$4,'accepting',$5,$6,$7,
                  clock_timestamp()+interval '1 hour',$8,$9,clock_timestamp(),1)`,
      [
        invitationId,
        administrator.tenantId,
        invitedEmail,
        sha256(randomBytes(32)),
        randomUUID(),
        sha256(randomBytes(32)),
        administrator.identityId,
        acceptanceId,
        invitedIdentityId,
      ],
    );
    const completion = await new InvitationStore(current.control).complete({
      claim: {
        invitationId,
        acceptanceId,
        identityId: invitedIdentityId,
        tenantId: administrator.tenantId,
        email: invitedEmail,
        normalizedEmail: invitedEmail,
        roles: ["AUDITOR"],
        expiresAt: new Date(Date.now() + 60 * 60_000),
        createdByIdentityId: administrator.identityId,
        authorityKind: "tenant_delegate",
        authorityEpoch: 0,
        acceptanceAttempt: 1,
      },
      displayName: "Passwordless invitee",
      disabledPasswordHash: "$argon2id$discarded-random-passwordless-secret",
      bootstrapSession: {
        sessionId,
        tokenHash: sha256(randomBytes(32)),
        csrfHash: sha256(randomBytes(32)),
        // Deliberately overlong: the function must return the hard-capped
        // effective expiry, rather than trust the caller's deadline.
        expiresAt: new Date(Date.now() + 60 * 60_000),
        userAgentHash: sha256("passwordless-invitation-agent"),
        ipPrefixHash: sha256("passwordless-invitation-network"),
      },
      requestId: randomUUID(),
    });
    expect(completion?.enrollmentSession).toMatchObject({ id: sessionId });
    expect(completion?.enrollmentSession?.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 10 * 60_000 + 1_000);
    const state = await current.control.query<{
      invitation_status: string;
      identity_created: boolean;
      membership_created: boolean;
      assurance_level: string;
      auth_method: string;
      enrollment_source: string | null;
      invitation_id: string | null;
      password_hash: string;
      password_provisioned: boolean;
      permissions: number;
      remaining_ms: number;
    }>(
      `SELECT
         (SELECT status FROM tenant_invitations WHERE id=$3) AS invitation_status,
         EXISTS(SELECT 1 FROM platform_identities WHERE id=$1) AS identity_created,
         EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=$2 AND identity_id=$1) AS membership_created,
         session.assurance_level,session.auth_method,session.enrollment_source,session.invitation_id,
         identity.password_hash,identity.password_provisioned,
         (SELECT count(*)::int FROM platform_role_bindings WHERE identity_id=$1) AS permissions,
         extract(epoch FROM (session.expires_at-clock_timestamp()))::int * 1000 AS remaining_ms
       FROM auth_sessions session
       JOIN platform_identities identity ON identity.id=session.identity_id
      WHERE session.id=$4`,
      [invitedIdentityId, administrator.tenantId, invitationId, sessionId],
    );
    expect(state.rows[0]).toMatchObject({
      invitation_status: "accepted",
      identity_created: true,
      membership_created: true,
      assurance_level: "enrollment_only",
      auth_method: "bootstrap",
      enrollment_source: "invitation",
      invitation_id: invitationId,
      password_hash: "$argon2id$discarded-random-passwordless-secret",
      password_provisioned: false,
      permissions: 0,
    });
    expect(state.rows[0]?.remaining_ms).toBeGreaterThan(0);
    expect(state.rows[0]?.remaining_ms).toBeLessThanOrEqual(10 * 60_000 + 1_000);

    // The marker cannot be rebound to a different identity, even for a
    // privileged direct caller. Runtime column grants provide the additional
    // non-forgeability boundary for normal application connections.
    await expect(current.control.query(
      `INSERT INTO auth_sessions(
         id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,assurance_level,
         auth_method,aal,phishing_resistant,recovery_limited,idle_timeout_minutes,idle_expires_at,
         enrollment_source,invitation_id
       ) VALUES ($1,$2,$3,$4,$5,clock_timestamp()+interval '5 minutes','enrollment_only',
                 'bootstrap',1,false,false,10,clock_timestamp()+interval '5 minutes','invitation',$6)`,
      [randomUUID(), sha256(randomBytes(32)), sha256(randomBytes(32)), administrator.identityId, administrator.tenantId, invitationId],
    )).rejects.toMatchObject({ code: "23514", constraint: "auth_sessions_invitation_enrollment_source_guard" });
  }, 20_000);

  it("reconciles existing session count and deadlines while preserving the declared current session", async () => {
    const current = requireFixture();
    const account = await createTenantIdentity(current.control, "session-reconciliation");
    const credentialId = await insertCredential(current.control, account.identityId, "Session policy key");
    const now = Date.now();
    const currentSessionId = await insertPasskeySession(current.control, account, credentialId, {
      label: "declared-current",
      createdAt: new Date(now - 20 * 60_000),
      lastSeenAt: new Date(now - 2 * 60_000),
      expiresAt: new Date(now + 5 * 60 * 60_000),
      idleExpiresAt: new Date(now + 2 * 60 * 60_000),
    });
    const leastRecentSessionId = await insertPasskeySession(current.control, account, credentialId, {
      label: "least-recent",
      createdAt: new Date(now - 15 * 60_000),
      lastSeenAt: new Date(now - 3 * 60_000),
      expiresAt: new Date(now + 5 * 60 * 60_000),
      idleExpiresAt: new Date(now + 2 * 60 * 60_000),
    });
    const newestSessionId = await insertPasskeySession(current.control, account, credentialId, {
      label: "newest",
      createdAt: new Date(now - 10 * 60_000),
      lastSeenAt: new Date(now - 60_000),
      expiresAt: new Date(now + 5 * 60 * 60_000),
      idleExpiresAt: new Date(now + 2 * 60 * 60_000),
    });
    const baseline = await current.auth.getEffectiveIdentityPolicy(account.tenantId);

    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: account.tenantId,
      expectedVersion: 0,
      changedByIdentityId: account.identityId,
      currentSessionId,
      policy: {
        ...baseline,
        maximumActiveSessions: 2,
        idleTimeoutMinutes: 10,
        absoluteSessionMinutes: 60,
      },
      requestId: randomUUID(),
    })).resolves.toMatchObject({
      tenantVersion: 1,
      maximumActiveSessions: 2,
      idleTimeoutMinutes: 10,
      absoluteSessionMinutes: 60,
    });

    const sessions = await current.control.query<SessionRow>(
      `SELECT id,created_at,last_seen_at,expires_at,idle_expires_at,idle_timeout_minutes,
              revoked_at,revoke_reason
         FROM auth_sessions WHERE id=ANY($1::uuid[]) ORDER BY id`,
      [[currentSessionId, leastRecentSessionId, newestSessionId]],
    );
    const byId = new Map(sessions.rows.map((row) => [row.id, row]));
    expect(byId.get(currentSessionId)).toMatchObject({ revoked_at: null, idle_timeout_minutes: 10 });
    expect(byId.get(newestSessionId)).toMatchObject({ revoked_at: null, idle_timeout_minutes: 10 });
    expect(byId.get(leastRecentSessionId)).toMatchObject({
      revoke_reason: "identity_policy_session_limit",
    });
    for (const id of [currentSessionId, newestSessionId]) {
      const session = byId.get(id);
      if (!session) throw new Error(`Expected reconciled session ${id}`);
      expect(session.expires_at.getTime()).toBeLessThanOrEqual(session.created_at.getTime() + 60 * 60_000 + 1_000);
      expect(session.idle_expires_at.getTime()).toBeLessThanOrEqual(session.last_seen_at.getTime() + 10 * 60_000 + 1_000);
      expect(session.idle_expires_at.getTime()).toBeLessThanOrEqual(session.expires_at.getTime());
    }
    const audit = await current.control.query<{
      sessions_revoked: number;
      sessions_reconciled: number;
    }>(
      `SELECT (metadata->>'sessionsRevoked')::int AS sessions_revoked,
              (metadata->>'sessionsReconciled')::int AS sessions_reconciled
         FROM platform_audit_events
        WHERE tenant_id=$1 AND action='auth.identity_policy_updated'
        ORDER BY sequence DESC LIMIT 1`,
      [account.tenantId],
    );
    expect(audit.rows[0]).toEqual({ sessions_revoked: 1, sessions_reconciled: 3 });
  }, 20_000);

  it("expires and permanently revokes password-chain sessions before cap and policy rollback", async () => {
    const current = requireFixture();
    const account = await createTenantIdentity(current.control, "policy-session-eligibility");
    const deviceBoundCredentialId = await insertCredential(
      current.control,
      account.identityId,
      "Policy device-bound primary",
    );
    const secondDeviceBoundCredentialId = await insertCredential(
      current.control,
      account.identityId,
      "Policy device-bound backup",
    );
    const syncedCredentialId = await insertCredential(
      current.control,
      account.identityId,
      "Policy synced passkey",
      "multiDevice",
    );
    const now = Date.now();
    const expiredCurrentSessionId = await insertPasskeySession(current.control, account, deviceBoundCredentialId, {
      label: "expired-declared-current",
      createdAt: new Date(now - 10 * 60_000),
      lastSeenAt: new Date(now - 1_000),
      expiresAt: new Date(now + 60 * 60_000),
      idleExpiresAt: new Date(now + 30 * 60_000),
    });
    const healthySessionId = await insertPasskeySession(current.control, account, secondDeviceBoundCredentialId, {
      label: "healthy-post-policy",
      createdAt: new Date(now - 60_000),
      lastSeenAt: new Date(now - 1_000),
      expiresAt: new Date(now + 60 * 60_000),
      idleExpiresAt: new Date(now + 30 * 60_000),
    });
    const passwordSessionId = await insertPolicySession(current.control, account, {
      label: "disallowed-password", authMethod: "password",
    });
    const totpSessionId = await insertPolicySession(current.control, account, {
      label: "disallowed-totp", authMethod: "totp",
    });
    const recoverySessionId = await insertPolicySession(current.control, account, {
      label: "disallowed-recovery", authMethod: "recovery_code",
    });
    const bootstrapSessionId = await insertPolicySession(current.control, account, {
      label: "unscoped-bootstrap", authMethod: "bootstrap",
    });
    const syncedSessionId = await insertPasskeySession(current.control, account, syncedCredentialId, {
      label: "disallowed-synced-passkey",
    });
    const lowAalFederatedSessionId = await insertPolicySession(current.control, account, {
      label: "low-aal-federated", authMethod: "federated",
    });
    const revokedSessionIds = [
      expiredCurrentSessionId,
      passwordSessionId,
      totpSessionId,
      recoverySessionId,
      bootstrapSessionId,
      syncedSessionId,
      lowAalFederatedSessionId,
    ];
    const grants = await Promise.all(revokedSessionIds.map((sessionId) =>
      insertStepUpGrant(current.control, account, sessionId, deviceBoundCredentialId)
    ));
    const baseline = await current.auth.getEffectiveIdentityPolicy(account.tenantId);

    // Rolling policy settings back changes future admission only; revoked
    // rows must remain terminal and cannot become valid sessions again.
    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: account.tenantId,
      expectedVersion: 0,
      changedByIdentityId: account.identityId,
      currentSessionId: expiredCurrentSessionId,
      policy: {
        ...baseline,
        enforcementMode: "enforce",
        allowPassword: false,
        // These remain allowed individually: disabling the password root must
        // still permanently revoke the entire password-derived session chain.
        allowTotpFallback: true,
        allowRecoveryCodes: true,
        allowSyncedPasskeys: false,
        maximumActiveSessions: 1,
        idleTimeoutMinutes: 5,
        absoluteSessionMinutes: 5,
      },
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 1, maximumActiveSessions: 1 });

    const reconciled = await current.control.query<{
      id: string;
      revoked_at: Date | null;
      revoke_reason: string | null;
    }>(
      `SELECT id,revoked_at,revoke_reason FROM auth_sessions
        WHERE id=ANY($1::uuid[]) ORDER BY id`,
      [[...revokedSessionIds, healthySessionId]],
    );
    const sessionsById = new Map(reconciled.rows.map((session) => [session.id, session]));
    expect(sessionsById.get(healthySessionId)).toMatchObject({ revoked_at: null });
    expect(sessionsById.get(expiredCurrentSessionId)).toMatchObject({
      revoke_reason: "identity_policy_session_expired",
    });
    for (const sessionId of [
      passwordSessionId,
      totpSessionId,
      recoverySessionId,
      bootstrapSessionId,
      syncedSessionId,
      lowAalFederatedSessionId,
    ]) {
      expect(sessionsById.get(sessionId)).toMatchObject({
        revoke_reason: "identity_policy_authentication_prohibited",
      });
    }
    const revokedGrants = await current.control.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM authentication_step_up_grants
        WHERE id=ANY($1::uuid[]) AND revoked_at IS NOT NULL`,
      [grants.map(({ id }) => id)],
    );
    expect(revokedGrants.rows[0]?.count).toBe(grants.length);

    await expect(current.auth.upsertTenantIdentityPolicy({
      tenantId: account.tenantId,
      expectedVersion: 1,
      changedByIdentityId: account.identityId,
      policy: baseline,
      requestId: randomUUID(),
    })).resolves.toMatchObject({ tenantVersion: 2 });
    const stillRevoked = await current.control.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM auth_sessions
        WHERE id=ANY($1::uuid[]) AND revoked_at IS NOT NULL`,
      [revokedSessionIds],
    );
    expect(stillRevoked.rows[0]?.count).toBe(revokedSessionIds.length);
  }, 20_000);
});

async function createFixture(databaseAdminUrl: string): Promise<Fixture> {
  const cluster = new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), max: 1 });
  const databaseName = `nom_enterprise_invariants_${randomBytes(10).toString("hex")}`;
  const control = new Pool({ connectionString: databaseUrl(databaseAdminUrl, databaseName), max: 12 });
  try {
    await executeFormatted(
      cluster,
      "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
      [databaseName],
    );
    await runMigrations(control, {
      scope: "control",
      directory: path.join(packageRoot, "migrations", "control"),
    });
    return { cluster, control, auth: new EnterpriseAuthStore(control), databaseName };
  } catch (error) {
    return cleanupAfterFailure(error, () => cleanupEnterpriseInvariantDatabase(cluster, control, databaseName), "Enterprise-auth invariant fixture setup");
  }
}

async function createTenantIdentity(pool: Pool, label: string): Promise<TenantIdentity> {
  const tenantId = randomUUID();
  const identityId = await insertIdentity(pool, label);
  await pool.query(
    `INSERT INTO tenants(
       id,slug,display_name,kind,status,timezone,locale,database_name,runtime_role,
       runtime_secret_ref,database_port,activated_at
     ) VALUES ($1,$2,$3,'real','active','America/La_Paz','es',$4,$5,$6,55432,clock_timestamp())`,
    [
      tenantId,
      `invariant-${randomBytes(4).toString("hex")}`,
      `Invariant ${label}`,
      `nom_invariant_target_${randomBytes(4).toString("hex")}`,
      `nom_invariant_role_${randomBytes(4).toString("hex")}`,
      `tenant-db/${tenantId}/runtime/v1`,
    ],
  );
  await pool.query(
    "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
    [tenantId, identityId],
  );
  return { tenantId, identityId };
}

async function insertIdentity(pool: Pool, label: string): Promise<string> {
  const identityId = randomUUID();
  const email = `${label}-${randomBytes(5).toString("hex")}@invalid.example`;
  await pool.query(
    `INSERT INTO platform_identities(id,email,normalized_email,display_name,password_hash,status)
     VALUES ($1,$2,$2,$3,'disabled','active')`,
    [identityId, email, `Invariant ${label}`],
  );
  return identityId;
}

async function insertCredential(
  pool: Pool,
  identityId: string,
  displayName: string,
  deviceType: "singleDevice" | "multiDevice" = "singleDevice",
): Promise<string> {
  const inserted = await pool.query<{ id: string }>(
    `INSERT INTO webauthn_credentials(
       identity_id,credential_id,public_key,user_handle,sign_count,transports,
       attachment,device_type,backup_eligible,backup_state,discoverable,user_verified,
       trust_level,rp_id,display_name
     ) VALUES ($1,$2,$3,$4,0,ARRAY['internal']::text[],'platform',$5,$6,$6,true,true,'unverified','localhost',$7)
     RETURNING id`,
    [
      identityId,
      randomBytes(32).toString("base64url"),
      Buffer.alloc(32, 9),
      Buffer.from(identityId).toString("base64url"),
      deviceType,
      deviceType === "multiDevice",
      displayName,
    ],
  );
  const credentialId = inserted.rows[0]?.id;
  if (!credentialId) throw new Error("Invariant credential was not inserted");
  await pool.query(
    `UPDATE platform_identities
        SET passkey_enabled=true,passkey_enrolled_at=COALESCE(passkey_enrolled_at,clock_timestamp())
      WHERE id=$1`,
    [identityId],
  );
  return credentialId;
}

async function insertEnrollmentSession(pool: Pool, account: TenantIdentity): Promise<string> {
  const id = randomUUID();
  await pool.query(
    `INSERT INTO auth_sessions(
       id,token_hash,csrf_hash,identity_id,active_tenant_id,user_agent_hash,ip_prefix_hash,
       expires_at,assurance_level
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '1 hour','enrollment_only')`,
    [
      id,
      sha256(randomBytes(32)),
      sha256(randomBytes(32)),
      account.identityId,
      account.tenantId,
      sha256("invariant-enrollment-agent"),
      sha256("invariant-enrollment-network"),
    ],
  );
  return id;
}

async function insertPasskeySession(
  pool: Pool,
  account: TenantIdentity,
  credentialId: string,
  options: {
    readonly label: string;
    readonly createdAt?: Date;
    readonly lastSeenAt?: Date;
    readonly expiresAt?: Date;
    readonly idleExpiresAt?: Date;
  },
): Promise<string> {
  const id = randomUUID();
  const createdAt = options.createdAt ?? new Date();
  const lastSeenAt = options.lastSeenAt ?? createdAt;
  const expiresAt = options.expiresAt ?? new Date(Date.now() + 60 * 60_000);
  const idleExpiresAt = options.idleExpiresAt ?? new Date(Date.now() + 30 * 60_000);
  const userAgentHash = sha256(`${options.label}-agent`);
  const ipPrefixHash = sha256(`${options.label}-network`);
  await pool.query(
    `INSERT INTO auth_sessions(
       id,token_hash,csrf_hash,identity_id,active_tenant_id,user_agent_hash,ip_prefix_hash,
       created_at,last_seen_at,expires_at,assurance_level,authenticated_at,mfa_verified_at,
       auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,
       idle_timeout_minutes,idle_expires_at,last_user_agent_hash,last_ip_prefix_hash,device_label
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'mfa',$8,$8,
               'passkey',2,true,$11,false,30,$12,$6,$7,$13)`,
    [
      id,
      sha256(randomBytes(32)),
      sha256(randomBytes(32)),
      account.identityId,
      account.tenantId,
      userAgentHash,
      ipPrefixHash,
      createdAt,
      lastSeenAt,
      expiresAt,
      credentialId,
      idleExpiresAt,
      options.label,
    ],
  );
  return id;
}

async function insertPolicySession(
  pool: Pool,
  account: TenantIdentity,
  options: {
    readonly label: string;
    readonly authMethod: "password" | "totp" | "recovery_code" | "federated" | "bootstrap";
  },
): Promise<string> {
  const id = randomUUID();
  const userAgentHash = sha256(`${options.label}-agent`);
  const ipPrefixHash = sha256(`${options.label}-network`);
  const mfa = options.authMethod === "totp";
  const recovery = options.authMethod === "recovery_code";
  await pool.query(
    `INSERT INTO auth_sessions(
       id,token_hash,csrf_hash,identity_id,active_tenant_id,user_agent_hash,ip_prefix_hash,
       expires_at,assurance_level,authenticated_at,mfa_verified_at,auth_method,aal,
       phishing_resistant,authenticated_credential_id,recovery_limited,idle_timeout_minutes,
       idle_expires_at,last_user_agent_hash,last_ip_prefix_hash,device_label
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '1 hour',$8,clock_timestamp(),$9,
               $10,$11,false,NULL,$12,30,clock_timestamp()+interval '30 minutes',$6,$7,$13)`,
    [
      id,
      sha256(randomBytes(32)),
      sha256(randomBytes(32)),
      account.identityId,
      account.tenantId,
      userAgentHash,
      ipPrefixHash,
      recovery ? "recovery_limited" : mfa ? "mfa" : options.authMethod === "bootstrap" ? "enrollment_only" : "password",
      mfa ? new Date() : null,
      options.authMethod,
      mfa ? 2 : 1,
      recovery,
      options.label,
    ],
  );
  return id;
}

async function insertRegistrationCeremony(
  pool: Pool,
  account: TenantIdentity,
  sessionId: string,
): Promise<{ readonly id: string; readonly tokenHash: string; readonly challengeHash: string }> {
  const id = randomUUID();
  const tokenHash = sha256(randomBytes(32));
  const challengeHash = sha256(randomBytes(32));
  await pool.query(
    `INSERT INTO webauthn_ceremonies(
       id,token_hash,challenge_hash,ceremony_type,identity_id,tenant_id,session_id,
       rp_id,expected_origin,require_user_verification,policy_version,expires_at
     ) VALUES ($1,$2,$3,'registration',$4,$5,$6,'localhost','http://localhost:3000',true,1,
               clock_timestamp()+interval '5 minutes')`,
    [id, tokenHash, challengeHash, account.identityId, account.tenantId, sessionId],
  );
  return { id, tokenHash, challengeHash };
}

async function insertStepUpGrant(
  pool: Pool,
  account: TenantIdentity,
  sessionId: string,
  credentialId: string,
): Promise<{
  readonly id: string;
  readonly tokenHash: string;
  readonly purpose: string;
  readonly operationHash: string;
}> {
  const id = randomUUID();
  const tokenHash = sha256(randomBytes(32));
  const purpose = "auth.passkey.revoke";
  const operationHash = sha256(randomBytes(32));
  await pool.query(
    `INSERT INTO authentication_step_up_grants(
       id,token_hash,identity_id,tenant_id,session_id,credential_id,purpose,operation_hash,expires_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+interval '5 minutes')`,
    [id, tokenHash, account.identityId, account.tenantId, sessionId, credentialId, purpose, operationHash],
  );
  return { id, tokenHash, purpose, operationHash };
}

function credentialInput(identityId: string, displayName: string): PasskeyCredentialCreateInput {
  return {
    externalId: randomBytes(32).toString("base64url"),
    publicKey: Buffer.alloc(32, 7),
    userHandle: Buffer.from(identityId).toString("base64url"),
    counter: 0,
    transports: ["internal"],
    attachment: "platform",
    deviceType: "singleDevice",
    backupEligible: false,
    backedUp: false,
    discoverable: true,
    userVerified: true,
    rpId: "localhost",
    displayName,
  };
}

function sessionInput(label: string) {
  return {
    tokenHash: sha256(randomBytes(32)),
    csrfHash: sha256(randomBytes(32)),
    expiresAt: new Date(Date.now() + 60 * 60_000),
    userAgentHash: sha256(`${label}-agent`),
    ipPrefixHash: sha256(`${label}-network`),
    deviceLabel: label,
  };
}

function assertOneCompletionSucceeded(results: readonly PromiseSettledResult<unknown>[]): void {
  const fulfilled = results.filter(({ status }) => status === "fulfilled");
  if (fulfilled.length !== 1) {
    const failures = results.map((result) => {
      if (result.status === "fulfilled") return "fulfilled";
      const reason: unknown = result.reason;
      if (reason instanceof Error) {
        const code = "code" in reason ? String(reason.code) : "no-code";
        return `${reason.name}/${code}: ${reason.message}`;
      }
      return String(reason);
    });
    throw new Error(`Expected exactly one registration completion; observed ${failures.join(" | ")}`);
  }
}

async function waitForReadinessLock(pool: Pool): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await pool.query<{ waiting: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM pg_stat_activity
          WHERE datname=current_database()
            AND wait_event_type='Lock'
            AND query LIKE '%FROM tenant_memberships membership%'
       ) AS waiting`,
    );
    if (result.rows[0]?.waiting) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Policy update did not reach the membership readiness lock");
}

async function cleanupFixture(current: Fixture): Promise<void> {
  await cleanupEnterpriseInvariantDatabase(current.cluster, current.control, current.databaseName);
}

async function cleanupEnterpriseInvariantDatabase(cluster: Pool, control: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [control], assertSafeDatabaseName: assertEnterpriseInvariantDatabaseName }],
    label: "Temporary enterprise-auth invariant database",
  });
}

function assertEnterpriseInvariantDatabaseName(databaseName: string): void {
  if (!/^nom_enterprise_invariants_[0-9a-f]{20}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-enterprise-auth-invariants test database");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const result = await pool.query<{ sql: string }>(query, [...values]);
  const sql = result.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the enterprise auth invariant statement");
  await pool.query(sql);
}

function discoverAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (
        parsed
        && typeof parsed === "object"
        && "DATABASE_ADMIN_URL" in parsed
        && typeof parsed.DATABASE_ADMIN_URL === "string"
      ) {
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
  const pool = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    connectionTimeoutMillis: 1_500,
    max: 1,
  });
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
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || Number(url.port || "5432") !== workspacePort) {
    throw new Error("Enterprise auth invariant tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function requireFixture(): Fixture {
  if (!fixture) throw new Error("Enterprise auth invariant fixture is unavailable");
  return fixture;
}
