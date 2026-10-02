import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { bindDirectFixtureSession } from "./direct-device-session-fixture.js";
import { Pool, type PoolClient } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import {
  hashKeyLifecycleRequest,
  KeyLifecycleError,
  KeyLifecycleStore,
  runMigrations,
  type KeyLifecycleOperation,
} from "../src/index.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
if (requireLive && !reachable) throw new Error("Key-lifecycle live test requires PostgreSQL 18 on loopback:55432");
const live = reachable ? describe.sequential : describe.skip;

const actorA = "30000000-0000-4000-8000-000000000001";
const actorB = "30000000-0000-4000-8000-000000000002";
const actorC = "30000000-0000-4000-8000-000000000003";
const actorD = "30000000-0000-4000-8000-000000000004";
const deviceA = "30000000-0000-4000-8000-000000000011";
const deviceB = "30000000-0000-4000-8000-000000000012";
const deviceC = "30000000-0000-4000-8000-000000000013";
const deviceD = "30000000-0000-4000-8000-000000000014";
const sessionA = "30000000-0000-4000-8000-000000000021";
const sessionB = "30000000-0000-4000-8000-000000000022";
const sessionC = "30000000-0000-4000-8000-000000000023";
const sessionD = "30000000-0000-4000-8000-000000000024";
const tenantId = "30000000-0000-4000-8000-000000000031";
const isolatedTenantId = "30000000-0000-4000-8000-000000000032";

live("AC-32 tenant-key lifecycle on isolated PostgreSQL", () => {
  let cluster: Pool | undefined;
  let tenant: Pool | undefined;
  let isolated: Pool | undefined;
  let databaseName = "";
  let isolatedDatabaseName = "";
  let winningActor = actorA;
  let winningDevice = deviceA;
  let winningSession = sessionA;
  let currentTenantKeyId = "";
  let currentGeneration = 1;
  let activeGrantIds: string[] = [];

  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    databaseName = `nom_key_lifecycle_${randomBytes(10).toString("hex")}`;
    isolatedDatabaseName = `nom_key_lifecycle_${randomBytes(10).toString("hex")}`;
    cluster = new Pool({ connectionString: databaseUrl(adminUrl, "postgres"), max: 1 });
    tenant = new Pool({ connectionString: databaseUrl(adminUrl, databaseName), max: 8 });
    isolated = new Pool({ connectionString: databaseUrl(adminUrl, isolatedDatabaseName), max: 2 });
    try {
      await createDatabase(cluster, databaseName);
      await createDatabase(cluster, isolatedDatabaseName);
      for (const [pool, id, name] of [
        [tenant, tenantId, "Lifecycle tenant"],
        [isolated, isolatedTenantId, "Isolated tenant"],
      ] as const) {
        await runMigrations(pool, {
          scope: "tenant",
          directory: path.join(workspaceRoot, "packages", "database", "migrations", "tenant"),
        });
        await pool.query(
          `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state)
           VALUES ($1,$2,'real','America/La_Paz','es','in_progress')`,
          [id, name],
        );
      }
    } catch (error) {
      const cleanupCluster = cluster;
      const cleanupTenant = tenant;
      const cleanupIsolated = isolated;
      const cleanupDatabaseName = databaseName;
      const cleanupIsolatedDatabaseName = isolatedDatabaseName;
      cluster = undefined;
      tenant = undefined;
      isolated = undefined;
      databaseName = "";
      isolatedDatabaseName = "";
      return cleanupAfterFailure(
        error,
        () => cleanupKeyLifecycleDatabases(
          cleanupCluster,
          cleanupTenant,
          cleanupDatabaseName,
          cleanupIsolated,
          cleanupIsolatedDatabaseName,
        ),
        "Key-lifecycle fixture setup",
      );
    }
  }, 60_000);

  afterAll(async () => {
    if (!cluster && !tenant && !isolated && !databaseName && !isolatedDatabaseName) return;
    if (!cluster || !tenant || !isolated || !databaseName || !isolatedDatabaseName) {
      throw new Error("Key-lifecycle teardown refused an incomplete fixture handle set");
    }
    const cleanupCluster = cluster;
    const cleanupTenant = tenant;
    const cleanupIsolated = isolated;
    const cleanupDatabaseName = databaseName;
    const cleanupIsolatedDatabaseName = isolatedDatabaseName;
    cluster = undefined;
    tenant = undefined;
    isolated = undefined;
    databaseName = "";
    isolatedDatabaseName = "";
    await cleanupKeyLifecycleDatabases(
      cleanupCluster,
      cleanupTenant,
      cleanupDatabaseName,
      cleanupIsolated,
      cleanupIsolatedDatabaseName,
    );
  }, 60_000);

  it("registers devices, rejects expired challenges and keeps an exact idempotent result", async () => {
    if (!tenant) throw new Error("Tenant pool is unavailable");
    const registeredA = await register(tenant, actorA, sessionA, deviceA, fingerprint("a"));
    const registeredB = await register(tenant, actorB, sessionB, deviceB, fingerprint("b"));
    expect(registeredA.status).toBe("pending");
    expect(registeredB.status).toBe("pending");

    const intent = deviceIntent(deviceC, fingerprint("c"));
    const requestHash = hashKeyLifecycleRequest(intent);
    const challenge = await inTenantTransaction(tenant, actorC, sessionC, async (store) =>
      store.issueChallenge({
        actorIdentityId: actorC,
        sessionId: sessionC,
        operation: "device.register",
        requestHash,
        idempotencyKey: randomUUID(),
        ttlSeconds: 30,
      }));
    await tenant.query(
      `UPDATE e2ee_key_challenges
          SET created_at=clock_timestamp()-interval '2 minutes',
              expires_at=clock_timestamp()-interval '1 minute'
        WHERE id=$1`,
      [challenge.challengeId],
    );
    await expect(inTenantTransaction(tenant, actorC, sessionC, (store) => store.registerDevice({
      actorIdentityId: actorC,
      sessionId: sessionC,
      idempotencyKey: randomUUID(),
      challengeId: challenge.challengeId,
      requestHash,
      deviceId: deviceC,
      label: intent.label,
      wrappingPublicKey: intent.wrappingPublicKey,
      wrappingKeyFingerprint: intent.wrappingPublicKey.fingerprint,
    }))).rejects.toMatchObject({ code: "KEY_LIFECYCLE_CHALLENGE_INVALID" });
  });

  it("allows exactly one initial key grant under a concurrent race", async () => {
    if (!tenant) throw new Error("Tenant pool is unavailable");
    const keyA = "30000000-0000-4000-8000-000000000041";
    const keyB = "30000000-0000-4000-8000-000000000042";
    const candidates = [
      { actor: actorA, session: sessionA, device: deviceA, key: keyA, fingerprint: fingerprint("a") },
      { actor: actorB, session: sessionB, device: deviceB, key: keyB, fingerprint: fingerprint("b") },
    ];
    const prepared = await Promise.all(candidates.map(async (candidate) => {
      const intent = initializeIntent(candidate.device, candidate.key, candidate.fingerprint);
      const requestHash = hashKeyLifecycleRequest(intent);
      const challenge = await issue(tenant!, candidate.actor, candidate.session, "grant.initialize", requestHash);
      return { ...candidate, intent, requestHash, challengeId: challenge.challengeId };
    }));
    const results = await Promise.allSettled(prepared.map((candidate) =>
      inTenantTransaction(tenant!, candidate.actor, candidate.session, (store) => store.initializeGrant({
        actorIdentityId: candidate.actor,
        sessionId: candidate.session,
        idempotencyKey: randomUUID(),
        challengeId: candidate.challengeId,
        requestHash: candidate.requestHash,
        deviceId: candidate.device,
        deviceFingerprint: candidate.fingerprint,
        tenantKeyId: candidate.key,
        envelope: candidate.intent.envelope,
        envelopeHash: candidate.intent.envelopeHash,
        recoveryPublicKey: candidate.intent.recoveryPublicKey,
        recoveryKeyFingerprint: candidate.intent.recoveryFingerprint,
      }))));
    const fulfilled = results.flatMap((result, index) => result.status === "fulfilled" ? [{ result: result.value, candidate: prepared[index]! }] : []);
    const rejected = results.filter((result) => result.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({ code: "KEY_LIFECYCLE_ALREADY_INITIALIZED" });
    const winner = fulfilled[0]!;
    winningActor = winner.candidate.actor;
    winningDevice = winner.candidate.device;
    winningSession = winner.candidate.session;
    currentTenantKeyId = winner.candidate.key;
    activeGrantIds = [winner.result.grantId];
    const counts = await tenant.query<{ generations: number; grants: number }>(
      `SELECT (SELECT count(*)::int FROM e2ee_key_generations) AS generations,
              (SELECT count(*)::int FROM e2ee_key_grants) AS grants`,
    );
    expect(counts.rows[0]).toEqual({ generations: 1, grants: 1 });
  });

  it("approves another registered device and leaves the second tenant empty", async () => {
    if (!tenant || !isolated) throw new Error("Tenant pools are unavailable");
    const targetActor = winningActor === actorA ? actorB : actorA;
    const targetDevice = winningDevice === deviceA ? deviceB : deviceA;
    const targetFingerprint = winningDevice === deviceA ? fingerprint("b") : fingerprint("a");
    const intent = {
      targetIdentityId: targetActor,
      targetDeviceId: targetDevice,
      tenantKeyId: currentTenantKeyId,
      generation: currentGeneration,
      envelope: opaqueEnvelope(targetDevice, targetFingerprint, currentTenantKeyId, currentGeneration),
    };
    const requestHash = hashKeyLifecycleRequest(intent);
    const challenge = await issue(tenant, winningActor, winningSession, "grant.approve", requestHash);
    const grant = await inTenantTransaction(tenant, winningActor, winningSession, (store) => store.approveGrant({
      actorIdentityId: winningActor,
      sessionId: winningSession,
      idempotencyKey: randomUUID(),
      challengeId: challenge.challengeId,
      requestHash,
      targetIdentityId: targetActor,
      targetDeviceId: targetDevice,
      targetDeviceFingerprint: targetFingerprint,
      tenantKeyId: currentTenantKeyId,
      generation: currentGeneration,
      envelope: intent.envelope,
      envelopeHash: intent.envelope.envelopeHash,
    }));
    activeGrantIds.push(grant.grantId);
    expect(grant.grantKind).toBe("admin_approved");
    const managerState = await inTenantTransaction(tenant, winningActor, winningSession, (store) => store.getState(winningActor, true));
    expect(managerState.managedGrants?.some(({ grantId }) => grantId === grant.grantId)).toBe(true);
    const memberState = await inTenantTransaction(tenant, winningActor, winningSession, (store) => store.getState(winningActor, false));
    expect(memberState.managedGrants).toBeUndefined();
    expect(memberState.ownGrants.every(({ identityId }) => identityId === winningActor)).toBe(true);
    const isolatedState = await inTenantTransaction(isolated, actorA, sessionA, (store) => store.getState(actorA, true), isolatedTenantId);
    expect(isolatedState.devices).toEqual([]);
    expect(isolatedState.generations).toEqual([]);
    expect(isolatedState.ownGrants).toEqual([]);
  });

  it("rotates atomically, keeps retired grants readable, and rejects stale generation input", async () => {
    if (!tenant) throw new Error("Tenant pool is unavailable");
    const newKey = "30000000-0000-4000-8000-000000000043";
    const intent = {
      expectedTenantKeyId: currentTenantKeyId,
      expectedGeneration: currentGeneration,
      newTenantKeyId: newKey,
      reasonCode: "SCHEDULED_ROTATION",
      recoveryPublicKey: recoveryPublic(fingerprint("e")),
      grants: [{
        targetIdentityId: winningActor,
        targetDeviceId: winningDevice,
        targetDeviceFingerprint: winningDevice === deviceA ? fingerprint("a") : fingerprint("b"),
        envelope: opaqueEnvelope(winningDevice, winningDevice === deviceA ? fingerprint("a") : fingerprint("b"), newKey, 2),
      }],
    };
    const requestHash = hashKeyLifecycleRequest(intent);
    const challenge = await issue(tenant, winningActor, winningSession, "key.rotate", requestHash);
    const result = await inTenantTransaction(tenant, winningActor, winningSession, (store) => store.rotateKey({
      actorIdentityId: winningActor,
      sessionId: winningSession,
      idempotencyKey: randomUUID(),
      challengeId: challenge.challengeId,
      requestHash,
      expectedTenantKeyId: intent.expectedTenantKeyId,
      expectedGeneration: intent.expectedGeneration,
      newTenantKeyId: intent.newTenantKeyId,
      reasonCode: intent.reasonCode,
      recoveryPublicKey: intent.recoveryPublicKey,
      recoveryKeyFingerprint: intent.recoveryPublicKey.fingerprint,
      grants: intent.grants.map((grant) => ({ ...grant, envelopeHash: grant.envelope.envelopeHash })),
    }));
    expect(result).toMatchObject({ tenantKeyId: newKey, generation: 2, grantCount: 1 });
    currentTenantKeyId = newKey;
    currentGeneration = 2;
    const state = await inTenantTransaction(tenant, winningActor, winningSession, (store) => store.getState(winningActor, true));
    expect(state.generations.map(({ status }) => status)).toEqual(["active", "retired"]);
    const retiredGrant = state.ownGrants.find(({ status }) => status === "retired");
    expect(retiredGrant).toMatchObject({
      tenantKeyId: intent.expectedTenantKeyId,
      generation: intent.expectedGeneration,
      identityId: winningActor,
      deviceId: winningDevice,
      status: "retired",
    });
    expect(retiredGrant?.envelope).toMatchObject({
      keyId: intent.expectedTenantKeyId,
      generation: intent.expectedGeneration,
      deviceId: winningDevice,
    });

    const staleKey = "30000000-0000-4000-8000-000000000044";
    const staleIntent = {
      expectedTenantKeyId: currentTenantKeyId,
      expectedGeneration: currentGeneration - 1,
      newTenantKeyId: staleKey,
      reasonCode: "SCHEDULED_ROTATION",
      recoveryPublicKey: recoveryPublic(fingerprint("f")),
      grants: [{
        targetIdentityId: winningActor,
        targetDeviceId: winningDevice,
        targetDeviceFingerprint: winningDevice === deviceA ? fingerprint("a") : fingerprint("b"),
        envelope: opaqueEnvelope(
          winningDevice,
          winningDevice === deviceA ? fingerprint("a") : fingerprint("b"),
          staleKey,
          currentGeneration,
        ),
      }],
    };
    const staleRequestHash = hashKeyLifecycleRequest(staleIntent);
    const staleChallenge = await issue(tenant, winningActor, winningSession, "key.rotate", staleRequestHash);
    const staleIdempotencyKey = randomUUID();
    await expect(inTenantTransaction(tenant, winningActor, winningSession, (store) => store.rotateKey({
      actorIdentityId: winningActor,
      sessionId: winningSession,
      idempotencyKey: staleIdempotencyKey,
      challengeId: staleChallenge.challengeId,
      requestHash: staleRequestHash,
      expectedTenantKeyId: staleIntent.expectedTenantKeyId,
      expectedGeneration: staleIntent.expectedGeneration,
      newTenantKeyId: staleIntent.newTenantKeyId,
      reasonCode: staleIntent.reasonCode,
      recoveryPublicKey: staleIntent.recoveryPublicKey,
      recoveryKeyFingerprint: staleIntent.recoveryPublicKey.fingerprint,
      grants: staleIntent.grants.map((grant) => ({ ...grant, envelopeHash: grant.envelope.envelopeHash })),
    }))).rejects.toMatchObject({ statusCode: 409, code: "KEY_GENERATION_CHANGED" });
    const staleRollback = await tenant.query<{
      challenge_status: string;
      idempotency_count: number;
      active_tenant_key_id: string;
      active_generation: number;
      stale_generation_count: number;
      audit_count: number;
      outbox_count: number;
    }>(
      `SELECT challenge.status AS challenge_status,
              (SELECT count(*)::int FROM idempotency_records
                WHERE identity_id=$2 AND operation='e2ee.key.rotate' AND idempotency_key=$3) AS idempotency_count,
              (SELECT tenant_key_id::text FROM e2ee_key_generations WHERE status='active') AS active_tenant_key_id,
              (SELECT generation FROM e2ee_key_generations WHERE status='active') AS active_generation,
              (SELECT count(*)::int FROM e2ee_key_generations WHERE tenant_key_id=$4::uuid) AS stale_generation_count,
              (SELECT count(*)::int FROM audit_events
                WHERE action='e2ee.key.rotated' AND metadata->>'tenantKeyId'=$4::text) AS audit_count,
              (SELECT count(*)::int FROM outbox_events
                WHERE event_type='e2ee.key.rotated' AND payload->>'tenantKeyId'=$4::text) AS outbox_count
         FROM e2ee_key_challenges challenge
        WHERE challenge.id=$1`,
      [staleChallenge.challengeId, winningActor, staleIdempotencyKey, staleKey],
    );
    expect(staleRollback.rows[0]).toEqual({
      challenge_status: "pending",
      idempotency_count: 0,
      active_tenant_key_id: currentTenantKeyId,
      active_generation: currentGeneration,
      stale_generation_count: 0,
      audit_count: 0,
      outbox_count: 0,
    });
    activeGrantIds = state.ownGrants.filter(({ status }) => status === "active").map(({ grantId }) => grantId);
  });

  it("onboards after rotation and delegates one retired generation exactly once under a race", async () => {
    if (!tenant) throw new Error("Tenant pool is unavailable");
    const registered = await register(tenant, actorC, sessionC, deviceC, fingerprint("c"));
    expect(registered.status).toBe("pending");

    const currentIntent = {
      targetIdentityId: actorC,
      targetDeviceId: deviceC,
      tenantKeyId: currentTenantKeyId,
      generation: currentGeneration,
      envelope: opaqueEnvelope(deviceC, fingerprint("c"), currentTenantKeyId, currentGeneration),
    };
    const currentRequestHash = hashKeyLifecycleRequest(currentIntent);
    const currentChallenge = await issue(tenant, winningActor, winningSession, "grant.approve", currentRequestHash);
    const currentGrant = await inTenantTransaction(tenant, winningActor, winningSession, (store) => store.approveGrant({
      actorIdentityId: winningActor,
      sessionId: winningSession,
      idempotencyKey: randomUUID(),
      challengeId: currentChallenge.challengeId,
      requestHash: currentRequestHash,
      targetIdentityId: actorC,
      targetDeviceId: deviceC,
      targetDeviceFingerprint: fingerprint("c"),
      tenantKeyId: currentTenantKeyId,
      generation: currentGeneration,
      envelope: currentIntent.envelope,
      envelopeHash: currentIntent.envelope.envelopeHash,
    }));
    expect(currentGrant.status).toBe("active");
    activeGrantIds.push(currentGrant.grantId);

    const state = await inTenantTransaction(tenant, winningActor, winningSession, (store) =>
      store.getState(winningActor, true));
    const retiredGeneration = state.generations.find(({ status }) => status === "retired");
    expect(retiredGeneration).toBeDefined();
    if (!retiredGeneration) throw new Error("Retired generation is unavailable");
    const historicalIntent = {
      targetIdentityId: actorC,
      targetDeviceId: deviceC,
      tenantKeyId: retiredGeneration.tenantKeyId,
      generation: retiredGeneration.generation,
      envelope: opaqueEnvelope(deviceC, fingerprint("c"), retiredGeneration.tenantKeyId, retiredGeneration.generation),
    };
    const historicalRequestHash = hashKeyLifecycleRequest(historicalIntent);
    const competitors = await Promise.all([0, 1].map(async () => ({
      challenge: await issue(tenant!, winningActor, winningSession, "grant.approve", historicalRequestHash),
      idempotencyKey: randomUUID(),
    })));
    expect(new Set(competitors.map(({ challenge }) => challenge.challengeId)).size).toBe(2);
    expect(new Set(competitors.map(({ idempotencyKey }) => idempotencyKey)).size).toBe(2);
    const raced = await Promise.allSettled(competitors.map(({ challenge, idempotencyKey }) => {
      const input = {
        actorIdentityId: winningActor,
        sessionId: winningSession,
        idempotencyKey,
        challengeId: challenge.challengeId,
        requestHash: historicalRequestHash,
        targetIdentityId: actorC,
        targetDeviceId: deviceC,
        targetDeviceFingerprint: fingerprint("c"),
        tenantKeyId: retiredGeneration.tenantKeyId,
        generation: retiredGeneration.generation,
        envelope: historicalIntent.envelope,
        envelopeHash: historicalIntent.envelope.envelopeHash,
      } as const;
      return inTenantTransaction(tenant!, winningActor, winningSession, (store) => store.approveGrant(input))
        .then((result) => ({ input, result }));
    }));
    const fulfilled = raced.flatMap((result) => result.status === "fulfilled" ? [result.value] : []);
    const rejected = raced.filter((result): result is PromiseRejectedResult => result.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason).toMatchObject({ code: "DEVICE_GRANT_ALREADY_EXISTS" });

    const winner = fulfilled[0]!;
    expect(winner.result).toMatchObject({
      tenantKeyId: retiredGeneration.tenantKeyId,
      generation: retiredGeneration.generation,
      identityId: actorC,
      deviceId: deviceC,
      envelope: historicalIntent.envelope,
      envelopeHash: historicalIntent.envelope.envelopeHash,
      status: "retired",
    });
    expect(winner.result.retiredAt).not.toBeNull();
    const replay = await inTenantTransaction(tenant, winningActor, winningSession, (store) =>
      store.approveGrant(winner.input));
    expect(replay).toEqual(winner.result);

    const persisted = await tenant.query<{
      id: string;
      status: string;
      retired_at: Date | null;
      envelope: Record<string, unknown>;
      envelope_hash: string;
      count: number;
    }>(
      `SELECT key_grant.id,key_grant.status,key_grant.retired_at,
              key_grant.envelope,key_grant.envelope_hash,
              (count(*) OVER ())::int AS count
         FROM e2ee_key_grants key_grant
         JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id
        WHERE generation.tenant_key_id=$1 AND key_grant.device_id=$2`,
      [retiredGeneration.tenantKeyId, deviceC],
    );
    expect(persisted.rows).toHaveLength(1);
    expect(persisted.rows[0]).toMatchObject({
      id: winner.result.grantId,
      status: "retired",
      envelope: historicalIntent.envelope,
      envelope_hash: historicalIntent.envelope.envelopeHash,
      count: 1,
    });
    expect(persisted.rows[0]?.retired_at).not.toBeNull();

    const targetState = await inTenantTransaction(tenant, actorC, sessionC, (store) =>
      store.getState(actorC, false));
    expect(targetState.ownGrants.find((grant) => grant.grantId === winner.result.grantId)).toMatchObject({
      tenantKeyId: retiredGeneration.tenantKeyId,
      generation: retiredGeneration.generation,
      envelope: historicalIntent.envelope,
      envelopeHash: historicalIntent.envelope.envelopeHash,
      status: "retired",
    });

    const [audit, outbox] = await Promise.all([
      tenant.query<{ metadata: Record<string, unknown> }>(
        "SELECT metadata FROM audit_events WHERE action='e2ee.grant.approved' AND entity_id=$1",
        [winner.result.grantId],
      ),
      tenant.query<{ payload: Record<string, unknown> }>(
        "SELECT payload FROM outbox_events WHERE event_type='e2ee.grant.approved' AND aggregate_id=$1",
        [winner.result.grantId],
      ),
    ]);
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0]?.metadata).toMatchObject({
      tenantKeyId: retiredGeneration.tenantKeyId,
      generation: retiredGeneration.generation,
      grantStatus: "retired",
      targetIdentityId: actorC,
      targetDeviceId: deviceC,
    });
    expect(outbox.rows).toHaveLength(1);
    expect(outbox.rows[0]?.payload).toMatchObject({
      tenantKeyId: retiredGeneration.tenantKeyId,
      generation: retiredGeneration.generation,
      status: "retired",
      identityId: actorC,
      deviceId: deviceC,
    });
    expect(JSON.stringify({ audit: audit.rows, outbox: outbox.rows })).not.toContain("opaque-ciphertext");

    const loserIndex = raced.findIndex((result) => result.status === "rejected");
    const loser = competitors[loserIndex];
    expect(loser).toBeDefined();
    const loserRollback = await tenant.query<{
      challenge_status: string;
      idempotency_count: number;
      audit_count: number;
      outbox_count: number;
    }>(
      `SELECT challenge.status AS challenge_status,
              (SELECT count(*)::int FROM idempotency_records
                WHERE identity_id=$2 AND operation='e2ee.grant.approve' AND idempotency_key=$3) AS idempotency_count,
              (SELECT count(*)::int FROM audit_events
                WHERE action='e2ee.grant.approved'
                  AND metadata->>'tenantKeyId'=$4
                  AND metadata->>'targetDeviceId'=$5) AS audit_count,
              (SELECT count(*)::int FROM outbox_events
                WHERE event_type='e2ee.grant.approved'
                  AND payload->>'tenantKeyId'=$4
                  AND payload->>'deviceId'=$5) AS outbox_count
         FROM e2ee_key_challenges challenge
        WHERE challenge.id=$1`,
      [
        loser!.challenge.challengeId,
        winningActor,
        loser!.idempotencyKey,
        retiredGeneration.tenantKeyId,
        deviceC,
      ],
    );
    expect(loserRollback.rows[0]).toEqual({
      challenge_status: "pending",
      idempotency_count: 0,
      audit_count: 1,
      outbox_count: 1,
    });

    const targetWithoutCurrent = winningActor === actorA
      ? { identityId: actorB, deviceId: deviceB, fingerprint: fingerprint("b") }
      : { identityId: actorA, deviceId: deviceA, fingerprint: fingerprint("a") };
    const priorGrantCount = await tenant.query<{ count: number }>(
      `SELECT count(*)::int AS count
         FROM e2ee_key_grants key_grant
         JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id
        WHERE generation.tenant_key_id=$1 AND key_grant.device_id=$2`,
      [retiredGeneration.tenantKeyId, targetWithoutCurrent.deviceId],
    );
    const deniedIntent = {
      targetIdentityId: targetWithoutCurrent.identityId,
      targetDeviceId: targetWithoutCurrent.deviceId,
      tenantKeyId: retiredGeneration.tenantKeyId,
      generation: retiredGeneration.generation,
      envelope: opaqueEnvelope(
        targetWithoutCurrent.deviceId,
        targetWithoutCurrent.fingerprint,
        retiredGeneration.tenantKeyId,
        retiredGeneration.generation,
      ),
    };
    const deniedRequestHash = hashKeyLifecycleRequest(deniedIntent);
    const deniedChallenge = await issue(tenant, winningActor, winningSession, "grant.approve", deniedRequestHash);
    const deniedIdempotencyKey = randomUUID();
    await expect(inTenantTransaction(tenant, winningActor, winningSession, (store) => store.approveGrant({
      actorIdentityId: winningActor,
      sessionId: winningSession,
      idempotencyKey: deniedIdempotencyKey,
      challengeId: deniedChallenge.challengeId,
      requestHash: deniedRequestHash,
      targetIdentityId: targetWithoutCurrent.identityId,
      targetDeviceId: targetWithoutCurrent.deviceId,
      targetDeviceFingerprint: targetWithoutCurrent.fingerprint,
      tenantKeyId: retiredGeneration.tenantKeyId,
      generation: retiredGeneration.generation,
      envelope: deniedIntent.envelope,
      envelopeHash: deniedIntent.envelope.envelopeHash,
    }))).rejects.toMatchObject({ code: "CURRENT_KEY_GRANT_REQUIRED" });
    const rollback = await tenant.query<{
      challenge_status: string; idempotency_count: number; grant_count: number;
    }>(
      `SELECT challenge.status AS challenge_status,
              (SELECT count(*)::int FROM idempotency_records
                WHERE identity_id=$2 AND operation='e2ee.grant.approve' AND idempotency_key=$3) AS idempotency_count,
              (SELECT count(*)::int
                 FROM e2ee_key_grants key_grant
                 JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id
                WHERE generation.tenant_key_id=$4 AND key_grant.device_id=$5) AS grant_count
         FROM e2ee_key_challenges challenge
        WHERE challenge.id=$1`,
      [
        deniedChallenge.challengeId,
        winningActor,
        deniedIdempotencyKey,
        retiredGeneration.tenantKeyId,
        targetWithoutCurrent.deviceId,
      ],
    );
    expect(rollback.rows[0]).toEqual({
      challenge_status: "pending",
      idempotency_count: 0,
      grant_count: priorGrantCount.rows[0]?.count,
    });
  });

  it("recovers with a non-replayable nonce, then records irreversible loss after all grants are revoked", async () => {
    if (!tenant) throw new Error("Tenant pool is unavailable");
    const registeredD = await register(tenant, actorD, sessionD, deviceD, fingerprint("d"));
    expect(registeredD.status).toBe("pending");
    const envelope = opaqueEnvelope(deviceD, fingerprint("d"), currentTenantKeyId, currentGeneration);
    const recoveryNonce = "30000000-0000-4000-8000-000000000051";
    const intent = {
      tenantKeyId: currentTenantKeyId,
      targetIdentityId: actorD,
      targetDeviceId: deviceD,
      envelope,
      recoveryNonce,
    };
    const requestHash = hashKeyLifecycleRequest(intent);
    const challenge = await issue(tenant, winningActor, winningSession, "key.recover", requestHash);
    const recovered = await inTenantTransaction(tenant, winningActor, winningSession, (store) => store.recoverGrant({
      actorIdentityId: winningActor,
      sessionId: winningSession,
      idempotencyKey: randomUUID(),
      challengeId: challenge.challengeId,
      requestHash,
      tenantKeyId: currentTenantKeyId,
      generation: currentGeneration,
      recoveryKeyFingerprint: fingerprint("e"),
      recoveryNonce,
      targetIdentityId: actorD,
      targetDeviceId: deviceD,
      targetDeviceFingerprint: fingerprint("d"),
      envelope,
      envelopeHash: envelope.envelopeHash,
    }));
    activeGrantIds.push(recovered.grantId);

    const replayTarget = winningDevice === deviceA
      ? { identityId: actorB, deviceId: deviceB, deviceFingerprint: fingerprint("b") }
      : { identityId: actorA, deviceId: deviceA, deviceFingerprint: fingerprint("a") };
    const replayEnvelope = opaqueEnvelope(
      replayTarget.deviceId,
      replayTarget.deviceFingerprint,
      currentTenantKeyId,
      currentGeneration,
    );
    const replayIntent = {
      tenantKeyId: currentTenantKeyId,
      targetIdentityId: replayTarget.identityId,
      targetDeviceId: replayTarget.deviceId,
      envelope: replayEnvelope,
      recoveryNonce,
    };
    const replayRequestHash = hashKeyLifecycleRequest(replayIntent);
    const replayChallenge = await issue(tenant, winningActor, winningSession, "key.recover", replayRequestHash);
    const replayIdempotencyKey = randomUUID();
    await expect(inTenantTransaction(tenant, winningActor, winningSession, (store) => store.recoverGrant({
      actorIdentityId: winningActor,
      sessionId: winningSession,
      idempotencyKey: replayIdempotencyKey,
      challengeId: replayChallenge.challengeId,
      requestHash: replayRequestHash,
      tenantKeyId: currentTenantKeyId,
      generation: currentGeneration,
      recoveryKeyFingerprint: fingerprint("e"),
      recoveryNonce,
      targetIdentityId: replayTarget.identityId,
      targetDeviceId: replayTarget.deviceId,
      targetDeviceFingerprint: replayTarget.deviceFingerprint,
      envelope: replayEnvelope,
      envelopeHash: replayEnvelope.envelopeHash,
    }))).rejects.toMatchObject({ statusCode: 409, code: "RECOVERY_REPLAYED" });
    const replayRollback = await tenant.query<{
      challenge_status: string;
      idempotency_count: number;
      nonce_count: number;
      target_grant_count: number;
      audit_count: number;
    }>(
      `SELECT challenge.status AS challenge_status,
              (SELECT count(*)::int FROM idempotency_records
                WHERE identity_id=$2 AND operation='e2ee.key.recover' AND idempotency_key=$3) AS idempotency_count,
              (SELECT count(*)::int FROM e2ee_key_grants WHERE recovery_nonce=$4::uuid) AS nonce_count,
              (SELECT count(*)::int
                 FROM e2ee_key_grants key_grant
                 JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id
                WHERE generation.tenant_key_id=$5 AND key_grant.device_id=$6) AS target_grant_count,
              (SELECT count(*)::int FROM audit_events
                WHERE action='e2ee.key.recovered' AND metadata->>'recoveryNonce'=$4::text) AS audit_count
         FROM e2ee_key_challenges challenge
        WHERE challenge.id=$1`,
      [
        replayChallenge.challengeId,
        winningActor,
        replayIdempotencyKey,
        recoveryNonce,
        currentTenantKeyId,
        replayTarget.deviceId,
      ],
    );
    expect(replayRollback.rows[0]).toEqual({
      challenge_status: "pending",
      idempotency_count: 0,
      nonce_count: 1,
      target_grant_count: 0,
      audit_count: 1,
    });

    for (const grantId of [...activeGrantIds].reverse()) {
      const row = await tenant.query<{ version: number }>("SELECT version FROM e2ee_key_grants WHERE id=$1", [grantId]);
      const intentRevoke = { grantId, expectedVersion: row.rows[0]!.version, reasonCode: "DEVICE_RETIRED", confirmLastActiveGrant: true };
      const revokeHash = hashKeyLifecycleRequest(intentRevoke);
      const revokeChallenge = await issue(tenant, winningActor, winningSession, "grant.revoke", revokeHash);
      await inTenantTransaction(tenant, winningActor, winningSession, (store) => store.revokeGrant({
        actorIdentityId: winningActor,
        sessionId: winningSession,
        idempotencyKey: randomUUID(),
        challengeId: revokeChallenge.challengeId,
        requestHash: revokeHash,
        ...intentRevoke,
      }));
    }
    const lossIntent = {
      tenantKeyId: currentTenantKeyId,
      confirmation: "PERMANENTLY_LOSE_TENANT_KEY" as const,
      reasonCode: "RECOVERY_MATERIAL_UNAVAILABLE",
    };
    const lossHash = hashKeyLifecycleRequest(lossIntent);
    // A revoked browser cannot continue; an explicitly registered, bound new
    // pending browser may perform this narrow irreversible-loss operation.
    const lossSession = randomUUID();
    const lossDevice = randomUUID();
    await register(tenant, winningActor, lossSession, lossDevice, fingerprint("f"));
    const lossChallenge = await issue(tenant, winningActor, lossSession, "key.declare_lost", lossHash);
    const lost = await inTenantTransaction(tenant, winningActor, lossSession, (store) => store.declareKeyLost({
      actorIdentityId: winningActor,
      sessionId: lossSession,
      idempotencyKey: randomUUID(),
      challengeId: lossChallenge.challengeId,
      requestHash: lossHash,
      ...lossIntent,
    }));
    expect(lost.status).toBe("lost");
    await expect(inTenantTransaction(tenant, winningActor, winningSession, (store) =>
      store.getRecoveryVerificationMaterial(currentTenantKeyId))).rejects.toBeInstanceOf(KeyLifecycleError);

    const audit = await tenant.query<{ metadata: string }>(
      "SELECT metadata::text AS metadata FROM audit_events WHERE action LIKE 'e2ee.%' ORDER BY sequence",
    );
    const serialized = audit.rows.map(({ metadata }) => metadata).join("\n");
    expect(serialized).not.toContain("opaque-ciphertext");
    expect(serialized).not.toContain("public-material");
    expect(serialized).not.toContain("privateKey");
    expect(serialized).toContain('"reasonCode": "SCHEDULED_ROTATION"');
    expect(serialized).toContain('"reasonCode": "DEVICE_RETIRED"');
    expect(serialized).toContain('"reasonCode": "RECOVERY_MATERIAL_UNAVAILABLE"');
    expect(serialized).not.toContain("reasonLength");
  });
});

async function register(pool: Pool, actor: string, session: string, device: string, keyFingerprint: `sha256:${string}`) {
  const intent = deviceIntent(device, keyFingerprint);
  const requestHash = hashKeyLifecycleRequest(intent);
  const challenge = await issue(pool, actor, session, "device.register", requestHash);
  const idempotencyKey = randomUUID();
  const input = {
    actorIdentityId: actor,
    sessionId: session,
    idempotencyKey,
    challengeId: challenge.challengeId,
    requestHash,
    deviceId: device,
    label: intent.label,
    wrappingPublicKey: intent.wrappingPublicKey,
    wrappingKeyFingerprint: keyFingerprint,
  } as const;
  const first = await inTenantTransaction(pool, actor, session, (store) => store.registerDevice(input));
  const replay = await inTenantTransaction(pool, actor, session, (store) => store.registerDevice(input));
  expect(replay).toEqual(first);
  return first;
}

async function issue(
  pool: Pool,
  actor: string,
  session: string,
  operation: KeyLifecycleOperation,
  requestHash: `sha256:${string}`,
) {
  return inTenantTransaction(pool, actor, session, (store) => store.issueChallenge({
    actorIdentityId: actor,
    sessionId: session,
    operation,
    requestHash,
    idempotencyKey: randomUUID(),
    ttlSeconds: 300,
  }));
}

async function inTenantTransaction<T>(
  pool: Pool,
  actor: string,
  session: string,
  work: (store: KeyLifecycleStore) => Promise<T>,
  contextTenantId = tenantId,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, contextTenantId, actor, session);
    const result = await work(new KeyLifecycleStore(client));
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function setContext(client: PoolClient, id: string, actor: string, session: string): Promise<void> {
  await client.query(
    `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
            set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
    [id, actor, session, randomUUID()],
  );
  await bindDirectFixtureSession(client);
}

function deviceIntent(deviceId: string, keyFingerprint: `sha256:${string}`) {
  return {
    deviceId,
    label: `Browser ${deviceId.slice(-4)}`,
    wrappingPublicKey: {
      format: "nombramientos.hpke-public-key",
      version: 1,
      publicKey: "public-material",
      fingerprint: keyFingerprint,
    },
  };
}

function initializeIntent(deviceId: string, keyId: string, keyFingerprint: `sha256:${string}`) {
  const envelope = opaqueEnvelope(deviceId, keyFingerprint, keyId, 1);
  return {
    deviceId,
    tenantKeyId: keyId,
    envelope,
    envelopeHash: envelope.envelopeHash,
    recoveryPublicKey: recoveryPublic(fingerprint("d")),
    recoveryFingerprint: fingerprint("d"),
  };
}

function opaqueEnvelope(deviceId: string, keyFingerprint: `sha256:${string}`, keyId: string, generation: number) {
  const body = { format: "test-opaque-grant", deviceId, keyId, generation, ciphertext: "opaque-ciphertext" };
  return { ...body, envelopeHash: hashKeyLifecycleRequest(body), deviceFingerprint: keyFingerprint };
}

function recoveryPublic(keyFingerprint: `sha256:${string}`) {
  return { format: "test-recovery-public", publicKey: "public-material", fingerprint: keyFingerprint };
}

function fingerprint(character: string): `sha256:${string}` {
  return `sha256:${character.repeat(64)}`;
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
    throw new Error("Key-lifecycle tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

async function createDatabase(cluster: Pool, databaseName: string): Promise<void> {
  const formatted = await cluster.query<{ sql: string }>(
    "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L',$1::text,'UTF8') AS sql",
    [databaseName],
  );
  await cluster.query(formatted.rows[0]!.sql);
}

async function cleanupKeyLifecycleDatabases(
  cluster: Pool,
  tenant: Pool,
  databaseName: string,
  isolated: Pool,
  isolatedDatabaseName: string,
): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [
      { databaseName, databasePools: [tenant], assertSafeDatabaseName: assertKeyLifecycleDatabaseName, label: "primary lifecycle tenant" },
      {
        databaseName: isolatedDatabaseName,
        databasePools: [isolated],
        assertSafeDatabaseName: assertKeyLifecycleDatabaseName,
        label: "isolated lifecycle tenant",
      },
    ],
    label: "Temporary key-lifecycle databases",
  });
}

function assertKeyLifecycleDatabaseName(databaseName: string): void {
  if (!/^nom_key_lifecycle_[0-9a-f]{20}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-key-lifecycle test database");
  }
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}
