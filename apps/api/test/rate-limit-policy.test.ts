import { randomUUID } from "node:crypto";
import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { ApiError } from "../src/lib/errors.js";
import {
  passkeyAuthenticationOptionsRateLimitMax,
  type SecurityRateLimitPolicy,
} from "../src/lib/rate-limit-policy.js";
import { registerAuthRoutes } from "../src/modules/auth-routes.js";
import { sha256, type AuthService } from "../src/modules/auth-service.js";
import { registerSecurity } from "../src/security.js";

const apps: FastifyInstance[] = [];
const origin = "http://localhost:3000";
const userAgent = "rate-limit-policy-test";
const defaultRatePolicy: SecurityRateLimitPolicy = {
  sessionOrAnonymousMax: 100,
  aggregateIdentityMax: 200,
  aggregateIpMax: 200,
  timeWindow: "1 minute",
};

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe("NAT-safe authentication rate limits", () => {
  it("gives discoverable passkey discovery an enterprise-NAT budget without widening identified login", () => {
    expect(passkeyAuthenticationOptionsRateLimitMax({ body: {} } as never)).toBe(1_200);
    expect(passkeyAuthenticationOptionsRateLimitMax({
      body: { email: "person@example.invalid" },
    } as never)).toBe(12);
  });

  it("shares the login budget across normalized identifiers and source IPs", async () => {
    const { app, login } = await authApp();
    const statuses: number[] = [];
    for (let index = 0; index < 11; index += 1) {
      const response = await loginRequest(
        app,
        index % 2 === 0 ? "Demo.User@Example.invalid" : "demo.user@example.invalid",
        `192.0.2.${index + 1}`,
      );
      statuses.push(response.statusCode);
    }

    expect(statuses.slice(0, 10)).toEqual(Array.from({ length: 10 }, () => 200));
    expect(statuses[10]).toBe(429);
    expect(login).toHaveBeenCalledTimes(10);
  });

  it("does not make distinct login identifiers behind one NAT consume each other's budget", async () => {
    const { app } = await authApp();
    const responses = await Promise.all(Array.from({ length: 11 }, (_, index) =>
      loginRequest(app, `person-${index}@example.invalid`, "198.51.100.20")));
    expect(responses.map((response) => response.statusCode)).toEqual(Array.from({ length: 11 }, () => 200));
  });

  it("isolates valid MFA identities behind one NAT and never stores a challenge bearer as a key", async () => {
    const challenges = challengeFixtures(9, (index) => uuid(index + 1));
    const { app, resolveMfaRateLimitIdentity } = await authApp({ challenges });
    const responses = [];
    for (const challenge of challenges) {
      responses.push(await mfaRequest(app, challenge, "203.0.113.40"));
    }

    expect(responses.map((response) => response.statusCode)).toEqual(Array.from({ length: 9 }, () => 200));
    expect(resolveMfaRateLimitIdentity).toHaveBeenCalledTimes(9);
    expect(resolveMfaRateLimitIdentity.mock.calls[0]?.[0]).toBe(sha256(challenges[0]!.token));
    expect(resolveMfaRateLimitIdentity.mock.calls[0]?.[0]).not.toContain(challenges[0]!.token);
    expect(resolveMfaRateLimitIdentity.mock.calls[0]?.[2]).toEqual(expect.objectContaining({
      originHash: sha256(origin),
      userAgentHash: sha256(userAgent),
    }));
  });

  it("shares the MFA budget across rotated challenges for the same verified identity", async () => {
    const identityId = uuid(90);
    const challenges = challengeFixtures(9, () => identityId);
    const { app, verifyMfa } = await authApp({ challenges });
    const statuses: number[] = [];
    for (const challenge of challenges) {
      statuses.push((await mfaRequest(app, challenge, "203.0.113.41")).statusCode);
    }

    expect(statuses.slice(0, 8)).toEqual(Array.from({ length: 8 }, () => 200));
    expect(statuses[8]).toBe(429);
    expect(verifyMfa).toHaveBeenCalledTimes(8);
  });

  it("keeps fake MFA cookies in the IP bucket and under the aggregate IP ceiling", async () => {
    const challenges = challengeFixtures(4, () => null);
    const { app, resolveMfaRateLimitIdentity } = await authApp({
      challenges,
      ratePolicy: { ...defaultRatePolicy, aggregateIpMax: 3 },
    });
    const responses = [];
    for (const challenge of challenges) {
      responses.push(await mfaRequest(app, challenge, "203.0.113.42"));
    }

    expect(responses.slice(0, 3).map((response) => response.statusCode)).toEqual([401, 401, 401]);
    expect(responses[3]!.statusCode).toBe(429);
    expect(responses[3]!.headers["x-ratelimit-limit"]).toBe("3");
    expect(resolveMfaRateLimitIdentity).toHaveBeenCalledTimes(3);
  });
});

describe("verified-session global rate limits", () => {
  it("enforces an explicit route budget by verified identity before sensitive preHandlers", async () => {
    const identityId = uuid(100);
    const sessions = [sessionFixture(91, identityId), sessionFixture(92, identityId)];
    const app = Fastify({ logger: false });
    apps.push(app);
    app.decorate("apiConfig", apiConfig());
    app.decorate("database", databaseFixture(sessions));
    await registerSecurity(app, {
      sessionOrAnonymousMax: 20,
      aggregateIdentityMax: 20,
      aggregateIpMax: 20,
      timeWindow: "1 minute",
    });
    const sensitiveEffect = vi.fn();
    app.post("/sensitive", {
      config: { rateLimit: { max: 1, timeWindow: "1 minute" } },
      preHandler: [app.authenticate, async () => { sensitiveEffect(); }],
    }, async () => ({ ok: true }));
    await app.ready();

    const first = await app.inject({
      method: "POST",
      url: "/sensitive",
      remoteAddress: "198.51.100.79",
      headers: { cookie: `nom_session=${sessions[0]!.token}`, "user-agent": userAgent },
    });
    const second = await app.inject({
      method: "POST",
      url: "/sensitive",
      remoteAddress: "198.51.100.79",
      headers: { cookie: `nom_session=${sessions[1]!.token}`, "user-agent": userAgent },
    });

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(429);
    expect(sensitiveEffect).toHaveBeenCalledTimes(1);
  });

  it("applies the aggregate source ceiling to generated CORS preflight routes", async () => {
    const app = Fastify({ logger: false });
    apps.push(app);
    app.decorate("apiConfig", apiConfig());
    app.decorate("database", databaseFixture([]));
    await registerSecurity(app, {
      sessionOrAnonymousMax: 20,
      aggregateIdentityMax: 20,
      aggregateIpMax: 1,
      timeWindow: "1 minute",
    });
    app.get("/preflight-target", async () => ({ ok: true }));
    await app.ready();
    const request = () => app.inject({
      method: "OPTIONS",
      url: "/preflight-target",
      remoteAddress: "198.51.100.78",
      headers: {
        origin,
        "access-control-request-method": "GET",
      },
    });

    expect((await request()).statusCode).toBe(204);
    expect((await request()).statusCode).toBe(429);
  });

  it("isolates two verified sessions under the same IP", async () => {
    const identityId = uuid(101);
    const sessions = [sessionFixture(1, identityId), sessionFixture(2, identityId)];
    const app = await protectedApp(sessions, {
      sessionOrAnonymousMax: 2,
      aggregateIdentityMax: 20,
      aggregateIpMax: 20,
      timeWindow: "1 minute",
    });

    expect(await protectedStatuses(app, sessions[0]!, 3)).toEqual([200, 200, 429]);
    expect(await protectedStatuses(app, sessions[1]!, 2)).toEqual([200, 200]);
  });

  it("caps one identity across multiple verified sessions", async () => {
    const identityId = uuid(102);
    const sessions = [sessionFixture(3, identityId), sessionFixture(4, identityId)];
    const app = await protectedApp(sessions, {
      sessionOrAnonymousMax: 10,
      aggregateIdentityMax: 4,
      aggregateIpMax: 20,
      timeWindow: "1 minute",
    });

    expect(await protectedStatuses(app, sessions[0]!, 2)).toEqual([200, 200]);
    expect(await protectedStatuses(app, sessions[1]!, 2)).toEqual([200, 200]);
    const limited = await protectedRequest(app, sessions[0]!);
    expect(limited.statusCode).toBe(429);
    expect(limited.headers["x-ratelimit-limit"]).toBe("4");
  });

  it("retains an aggregate IP ceiling across distinct verified identities", async () => {
    const sessions = Array.from({ length: 4 }, (_, index) => sessionFixture(index + 10, uuid(index + 110)));
    const app = await protectedApp(sessions, {
      sessionOrAnonymousMax: 10,
      aggregateIdentityMax: 10,
      aggregateIpMax: 3,
      timeWindow: "1 minute",
    });
    const responses = [];
    for (const session of sessions) responses.push(await protectedRequest(app, session));

    expect(responses.slice(0, 3).map((response) => response.statusCode)).toEqual([200, 200, 200]);
    expect(responses[3]!.statusCode).toBe(429);
    expect(responses[3]!.headers["x-ratelimit-limit"]).toBe("3");
  });

  it("does not let unverified session cookies mint independent buckets", async () => {
    const app = await protectedApp([], {
      sessionOrAnonymousMax: 2,
      aggregateIdentityMax: 20,
      aggregateIpMax: 20,
      timeWindow: "1 minute",
    }, false);
    const responses = [];
    for (const token of [opaqueToken(40), opaqueToken(41), opaqueToken(42)]) {
      responses.push(await app.inject({
        method: "GET",
        url: "/anonymous",
        remoteAddress: "198.51.100.70",
        headers: { cookie: `nom_session=${token}`, "user-agent": userAgent },
      }));
    }
    expect(responses.map((response) => response.statusCode)).toEqual([200, 200, 429]);
  });
});

type ChallengeFixture = {
  readonly challengeId: string;
  readonly token: string;
  readonly identityId: string | null;
};

type SessionFixture = {
  readonly token: string;
  readonly principal: RequestPrincipal;
};

async function authApp(options: {
  readonly challenges?: readonly ChallengeFixture[];
  readonly ratePolicy?: SecurityRateLimitPolicy;
} = {}) {
  const app = Fastify({ logger: false });
  apps.push(app);
  const identities = new Map(options.challenges?.map((challenge) => [challenge.challengeId, challenge.identityId]) ?? []);
  const resolveMfaRateLimitIdentity = vi.fn(async (_tokenHash: string, challengeId: string, _binding: unknown) =>
    identities.get(challengeId) ?? null);
  const login = vi.fn(async () => ({
    status: "mfa_required" as const,
    challengeId: randomUUID(),
    expiresAt: new Date(Date.now() + 60_000),
    challengeToken: opaqueToken(200),
  }));
  const verifyMfa = vi.fn(async (input: { readonly challengeId: string }) => {
    if (!identities.get(input.challengeId)) throw new ApiError(401, "MFA_CHALLENGE_INVALID", "MFA challenge is invalid or expired");
    return {
      status: "authenticated" as const,
      sessionToken: opaqueToken(201),
      csrfToken: opaqueToken(202),
      expiresAt: new Date(Date.now() + 60_000),
    };
  });
  const database = databaseFixture([], resolveMfaRateLimitIdentity);
  app.decorate("apiConfig", apiConfig());
  app.decorate("database", database);
  app.decorate("authService", { login, verifyMfa } as unknown as AuthService);
  await registerSecurity(app, options.ratePolicy ?? defaultRatePolicy);
  await registerAuthRoutes(app);
  await app.ready();
  return { app, login, verifyMfa, resolveMfaRateLimitIdentity };
}

async function protectedApp(
  sessions: readonly SessionFixture[],
  ratePolicy: SecurityRateLimitPolicy,
  protectedRoute = true,
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  app.decorate("apiConfig", apiConfig());
  app.decorate("database", databaseFixture(sessions));
  await registerSecurity(app, ratePolicy);
  if (protectedRoute) {
    app.get("/protected", { preHandler: [app.authenticate] }, async (request) => ({
      identityId: request.principal!.identityId,
      sessionId: request.principal!.sessionId,
    }));
  } else {
    app.get("/anonymous", async () => ({ ok: true }));
  }
  await app.ready();
  return app;
}

function databaseFixture(
  sessions: readonly SessionFixture[],
  resolveMfaRateLimitIdentity = vi.fn().mockResolvedValue(null),
): DatabaseRuntime {
  const principals = new Map(sessions.map(({ token, principal }) => [sha256(token), principal]));
  return {
    getPrincipal: vi.fn(async (tokenHash: string) => principals.get(tokenHash) ?? null),
    control: { resolveMfaRateLimitIdentity },
    enterpriseAuth: {
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(identityPolicy()),
      listCredentials: vi.fn().mockResolvedValue([]),
    },
  } as unknown as DatabaseRuntime;
}

function sessionFixture(seed: number, identityId: string): SessionFixture {
  return {
    token: opaqueToken(seed),
    principal: {
      sessionId: uuid(seed + 1_000),
      identityId,
      activeTenantId: uuid(9_000),
      email: `identity-${identityId}@example.invalid`,
      displayName: "Rate limit identity",
      tenantSlug: "fixture",
      tenantName: "Fixture",
      tenantKind: "real",
      tenantTimezone: "America/La_Paz",
      csrfHash: sha256("csrf"),
      expiresAt: new Date(Date.now() + 60_000),
      assuranceLevel: "mfa",
      authenticatedAt: new Date(),
      mfaVerifiedAt: new Date(),
      mfaRequired: true,
      mfaEnabled: true,
      passkeyEnabled: false,
      strongAuthEnabled: true,
      authMethod: "totp",
      aal: 2,
      phishingResistant: false,
      recoveryLimited: false,
      enrollmentOnly: false,
      permissions: new Set(),
    },
  };
}

async function loginRequest(app: FastifyInstance, email: string, remoteAddress: string) {
  return app.inject({
    method: "POST",
    url: "/v1/auth/login",
    remoteAddress,
    headers: { origin, "user-agent": userAgent },
    payload: { email, password: "CorrectHorseBattery!1" },
  });
}

async function mfaRequest(app: FastifyInstance, challenge: ChallengeFixture, remoteAddress: string) {
  return app.inject({
    method: "POST",
    url: "/v1/auth/mfa/verify",
    remoteAddress,
    headers: { origin, "user-agent": userAgent, cookie: `nom_mfa=${challenge.token}` },
    payload: { challengeId: challenge.challengeId, code: "123456" },
  });
}

async function protectedRequest(app: FastifyInstance, session: SessionFixture) {
  return app.inject({
    method: "GET",
    url: "/protected",
    remoteAddress: "198.51.100.80",
    headers: { cookie: `nom_session=${session.token}`, "user-agent": userAgent },
  });
}

async function protectedStatuses(app: FastifyInstance, session: SessionFixture, count: number): Promise<number[]> {
  const statuses: number[] = [];
  for (let index = 0; index < count; index += 1) statuses.push((await protectedRequest(app, session)).statusCode);
  return statuses;
}

function challengeFixtures(count: number, identityId: (index: number) => string | null): ChallengeFixture[] {
  return Array.from({ length: count }, (_, index) => ({
    challengeId: uuid(index + 300),
    token: opaqueToken(index + 60),
    identityId: identityId(index),
  }));
}

function opaqueToken(seed: number): string {
  return Buffer.alloc(32, seed % 256).toString("base64url");
}

function uuid(seed: number): string {
  return `00000000-0000-4000-8000-${String(seed).padStart(12, "0")}`;
}

function identityPolicy() {
  return {
    enforcementMode: "monitor" as const,
    minimumAal: 1 as const,
    privilegedMinimumAal: 2 as const,
    requireUserVerification: true,
    requirePhishingResistantForPrivileged: true,
    requireDeviceBoundForPrivileged: false,
    requireAttestationForPrivileged: false,
    allowPassword: true,
    allowTotpFallback: true,
    allowRecoveryCodes: true,
    allowSyncedPasskeys: true,
    minimumPasskeyCount: 0,
    privilegedMinimumPasskeyCount: 1,
    maximumPasskeys: 10,
    maximumActiveSessions: 10,
    idleTimeoutMinutes: 30,
    absoluteSessionMinutes: 720,
    stepUpTtlSeconds: 120,
    actionRequirements: {},
  };
}

function apiConfig(): ApiConfig {
  return {
    environment: "test",
    host: "127.0.0.1",
    port: 0,
    corsOrigins: new Set([origin]),
    secureCookies: false,
    sessionTtlSeconds: 3_600,
    webauthn: {
      rpName: "Nombramientos",
      rpId: "localhost",
      expectedOrigins: [origin],
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    },
    authEncryptionKey: Buffer.alloc(32, 1),
    controlDatabaseUrl: "postgresql://unused:unused@127.0.0.1:55432/unused",
    secretMasterKey: Buffer.alloc(32, 2),
    secretFile: "unused",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
}
