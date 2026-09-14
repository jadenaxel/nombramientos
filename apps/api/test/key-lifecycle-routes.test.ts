import { createECDH, createHash, randomUUID } from "node:crypto";

import rateLimit from "@fastify/rate-limit";
import { KeyLifecycleError, type DatabaseRuntime } from "@nombramientos/database";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { afterEach, describe, expect, it } from "vitest";

import { ApiError } from "../src/lib/errors.js";
import { lifecycleIntentRequestHash, type TenantKeyGrantEnvelopeInput } from "../src/modules/key-lifecycle-contract.js";
import {
  lifecycleChallengeRateLimitMax,
  registerKeyLifecycleRoutes,
} from "../src/modules/key-lifecycle-routes.js";

const tenantId = "10000000-0000-4000-8000-000000000001";
const actorIdentityId = "10000000-0000-4000-8000-000000000002";
const targetIdentityId = "10000000-0000-4000-8000-000000000003";
const targetDeviceId = "10000000-0000-4000-8000-000000000004";
const retiredTenantKeyId = "10000000-0000-4000-8000-000000000005";
const sessionId = "10000000-0000-4000-8000-000000000006";
const challengeId = "10000000-0000-4000-8000-000000000007";
const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("historical key-grant route", () => {
  it("allows thirteen grant approvals while keeping the default challenge limit at twelve", async () => {
    expect(lifecycleChallengeRateLimitMax({ body: { operation: "grant.approve" } } as FastifyRequest)).toBe(100);
    expect(lifecycleChallengeRateLimitMax({ body: { operation: "device.register" } } as FastifyRequest)).toBe(12);
    expect(lifecycleChallengeRateLimitMax({ body: null } as FastifyRequest)).toBe(12);

    const app = await fixtureApp({ enableRateLimit: true });
    const request = approveFixture();
    for (let attempt = 0; attempt < 13; attempt += 1) {
      const response = await app.inject({
        method: "POST",
        url: "/v1/key-lifecycle/challenges",
        headers: { "idempotency-key": randomUUID() },
        payload: { operation: "grant.approve", request },
      });
      expect(response.statusCode, `challenge ${attempt + 1}`).toBe(201);
    }

    const defaultLimitedApp = await fixtureApp({ enableRateLimit: true });
    for (let attempt = 0; attempt < 13; attempt += 1) {
      const response = await defaultLimitedApp.inject({
        method: "POST",
        url: "/v1/key-lifecycle/challenges",
        headers: { "idempotency-key": randomUUID() },
        payload: { operation: "device.register", request: {} },
      });
      if (attempt < 12) expect(response.statusCode, `default challenge ${attempt + 1}`).not.toBe(429);
      else expect(response.statusCode).toBe(429);
    }
  });

  it("reuses the challenge-bound grant endpoint for an exact retired generation", async () => {
    let challenged: Record<string, unknown> | undefined;
    let approved: Record<string, unknown> | undefined;
    const app = await fixtureApp({
      issueChallenge: async (input) => {
        challenged = input;
        return {
          challengeId,
          operation: "grant.approve",
          requestHash: input["requestHash"],
          status: "pending",
          expiresAt: new Date(Date.now() + 300_000).toISOString(),
        };
      },
      approveGrant: async (input) => {
        approved = input;
        return { grantId: randomUUID(), status: "retired", retiredAt: new Date().toISOString() };
      },
    });
    const request = approveFixture();
    const challengedResponse = await app.inject({
      method: "POST",
      url: "/v1/key-lifecycle/challenges",
      headers: { "idempotency-key": randomUUID() },
      payload: { operation: "grant.approve", request },
    });
    expect(challengedResponse.statusCode).toBe(201);
    expect(challenged).toMatchObject({
      operation: "grant.approve",
      actorIdentityId,
      sessionId,
      requestHash: lifecycleIntentRequestHash(request),
    });

    const response = await app.inject({
      method: "POST",
      url: "/v1/key-lifecycle/grants",
      headers: { "idempotency-key": randomUUID() },
      payload: { ...request, challengeId },
    });
    expect(response.statusCode).toBe(201);
    expect(response.json().data).toMatchObject({ status: "retired" });
    expect(approved).toMatchObject({
      actorIdentityId,
      sessionId,
      challengeId,
      targetIdentityId,
      targetDeviceId,
      targetDeviceFingerprint: request.envelope.aad.deviceFingerprint,
      tenantKeyId: retiredTenantKeyId,
      generation: 1,
      envelopeHash: request.envelope.envelopeHash,
    });
  });

  it("requires manager step-up and active target membership before any store mutation", async () => {
    let calls = 0;
    const request = approveFixture();
    const inactive = await fixtureApp({
      membership: false,
      approveGrant: async () => { calls += 1; return {}; },
    });
    const inactiveResponse = await inactive.inject({
      method: "POST",
      url: "/v1/key-lifecycle/grants",
      headers: { "idempotency-key": randomUUID() },
      payload: { ...request, challengeId },
    });
    expect(inactiveResponse.statusCode).toBe(403);
    expect(inactiveResponse.json().error.code).toBe("PERMISSION_DENIED");

    const stale = await fixtureApp({ staleMfa: true });
    const staleResponse = await stale.inject({
      method: "POST",
      url: "/v1/key-lifecycle/challenges",
      headers: { "idempotency-key": randomUUID() },
      payload: { operation: "grant.approve", request },
    });
    expect(staleResponse.statusCode).toBe(428);
    expect(staleResponse.json().error.code).toBe("MFA_STEP_UP_REQUIRED");

    const nonManager = await fixtureApp({ permissions: [] });
    const forbiddenResponse = await nonManager.inject({
      method: "POST",
      url: "/v1/key-lifecycle/grants",
      headers: { "idempotency-key": randomUUID() },
      payload: { ...request, challengeId },
    });
    expect(forbiddenResponse.statusCode).toBe(403);
    expect(calls).toBe(0);
  });

  it("rejects fingerprint, generation and AAD drift before the transactional store", async () => {
    let calls = 0;
    const app = await fixtureApp({
      approveGrant: async () => { calls += 1; return {}; },
    });
    const request = approveFixture();
    const drifted = {
      ...request,
      generation: 2,
    };
    const response = await app.inject({
      method: "POST",
      url: "/v1/key-lifecycle/grants",
      headers: { "idempotency-key": randomUUID() },
      payload: { ...drifted, challengeId },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe("KEY_GRANT_CONTEXT_MISMATCH");
    expect(calls).toBe(0);
  });

  it.each([
    [410, "TENANT_KEY_PERMANENTLY_LOST"],
    [409, "CURRENT_KEY_GRANT_REQUIRED"],
    [403, "AUTHORIZED_ADMIN_GRANT_REQUIRED"],
  ] as const)("maps store rejection %s/%s without leaking a raw 500", async (statusCode, code) => {
    const app = await fixtureApp({
      approveGrant: async () => {
        throw new KeyLifecycleError(statusCode, code, "Historical grant rejected");
      },
    });
    const response = await app.inject({
      method: "POST",
      url: "/v1/key-lifecycle/grants",
      headers: { "idempotency-key": randomUUID() },
      payload: { ...approveFixture(), challengeId },
    });
    expect(response.statusCode).toBe(statusCode);
    expect(response.json().error).toEqual({ code, message: "Historical grant rejected" });
  });
});

type FixtureOptions = {
  readonly enableRateLimit?: boolean;
  readonly membership?: boolean;
  readonly permissions?: readonly string[];
  readonly staleMfa?: boolean;
  readonly issueChallenge?: (input: Record<string, unknown>) => Promise<unknown>;
  readonly approveGrant?: (input: Record<string, unknown>) => Promise<unknown>;
};

async function fixtureApp(options: FixtureOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  if (options.enableRateLimit) {
    await app.register(rateLimit, {
      global: false,
      keyGenerator: (request) => request.ip,
    });
  }
  const principal = {
    sessionId,
    identityId: actorIdentityId,
    activeTenantId: tenantId,
    email: "historical-grant-test@invalid.example",
    displayName: "Historical grant test",
    tenantSlug: "historical-grant-test",
    tenantName: "Historical grant test",
    tenantKind: "real" as const,
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa" as const,
    authenticatedAt: new Date(),
    mfaVerifiedAt: options.staleMfa ? new Date(Date.now() - 10 * 60_000) : new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions: new Set(options.permissions ?? ["recovery.activate"]),
  };
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = principal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", () => async () => undefined);
  const store = {
    issueChallenge: options.issueChallenge ?? (async () => ({ challengeId })),
    approveGrant: options.approveGrant ?? (async () => ({ grantId: randomUUID(), status: "retired" })),
    recordDenial: async () => undefined,
  };
  const database = {
    control: {
      hasActiveMembership: async (identity: string, tenant: string) => {
        expect(identity).toBe(targetIdentityId);
        expect(tenant).toBe(tenantId);
        return options.membership ?? true;
      },
    },
    enterpriseAuth: {
      getEffectiveIdentityPolicy: async () => ({
        enforcementMode: "monitor",
        privilegedMinimumAal: 2,
        requirePhishingResistantForPrivileged: true,
        actionRequirements: {},
      }),
    },
    withKeyLifecyclePrincipal: async <T>(
      _principal: unknown,
      _requestId: string,
      work: (keyStore: typeof store) => Promise<T>,
    ): Promise<T> => work(store),
  } as unknown as DatabaseRuntime;
  app.decorate("database", database);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message },
        meta: { requestId: request.id },
      });
    }
    throw error;
  });
  await registerKeyLifecycleRoutes(app);
  await app.ready();
  return app;
}

function approveFixture() {
  const publicKey = createECDH("prime256v1").generateKeys();
  const fingerprint = digest(publicKey);
  const body = {
    format: "nombramientos.tenant-key-grant" as const,
    version: 1 as const,
    suite: {
      kem: "DHKEM(P-256, HKDF-SHA256)" as const,
      kemId: 16 as const,
      kdf: "HKDF-SHA256" as const,
      kdfId: 1 as const,
      aead: "AES-256-GCM" as const,
      aeadId: 2 as const,
    },
    aad: {
      purpose: "nombramientos.tenant-key-grant" as const,
      schemaVersion: 1 as const,
      tenantId,
      tenantKeyId: retiredTenantKeyId,
      generation: 1,
      identityId: targetIdentityId,
      deviceId: targetDeviceId,
      deviceFingerprint: fingerprint,
    },
    recipientId: `tenant:${tenantId}:device:${targetDeviceId}`,
    recipientFingerprint: fingerprint,
    enc: publicKey.toString("base64url"),
    ciphertext: Buffer.alloc(48, 7).toString("base64url"),
  };
  const envelope: TenantKeyGrantEnvelopeInput = {
    ...body,
    envelopeHash: lifecycleIntentRequestHash(body),
  };
  return {
    targetIdentityId,
    targetDeviceId,
    tenantKeyId: retiredTenantKeyId,
    generation: 1,
    envelope,
  };
}

function digest(value: Buffer): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
