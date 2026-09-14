import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import {
  opaqueRateLimitKey,
  publicCeremonyRateLimitKey,
} from "../src/lib/rate-limit-policy.js";
import { registerInitialAdminOnboardingRecoveryRoutes } from "../src/modules/initial-admin-onboarding-recovery-routes.js";
import { registerInvitationRoutes } from "../src/modules/invitation-routes.js";
import type { InvitationService } from "../src/modules/invitation-service.js";
import { registerPlatformBootstrapRoutes } from "../src/modules/platform-bootstrap-routes.js";

const apps: FastifyInstance[] = [];
const origin = "http://localhost:3000";

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe("public ceremony rate-limit identities", () => {
  it("validates and pseudonymizes bearer material with a conservative IP fallback", () => {
    const token = "t".repeat(43);
    const tokenKey = publicCeremonyRateLimitKey("test-token", [
      { field: "token", format: "opaque-256" },
    ]);

    expect(tokenKey(requestFixture({ token }))).toBe(opaqueRateLimitKey("test-token", token));
    expect(tokenKey(requestFixture({ token }))).not.toContain(token);
    expect(tokenKey(requestFixture({ token: "not-an-opaque-token" }))).toBe("ip:198.51.100.10");
    expect(tokenKey(requestFixture({}))).toBe("ip:198.51.100.10");

    const recoveryKey = publicCeremonyRateLimitKey("test-recovery", [
      { field: "recoveryId", format: "uuid" },
      { field: "token", format: "opaque-256" },
    ]);
    const recoveryId = "10000000-0000-4000-8000-000000000001";
    expect(recoveryKey(requestFixture({ recoveryId, token })))
      .toBe(recoveryKey(requestFixture({ recoveryId })));
    expect(recoveryKey(requestFixture({ recoveryId: recoveryId.toUpperCase(), token: "u".repeat(43) })))
      .toBe(recoveryKey(requestFixture({ recoveryId })));
    expect(recoveryKey(requestFixture({ recoveryId: "invalid", token })))
      .toBe(opaqueRateLimitKey("test-recovery", token));
    expect(recoveryKey(requestFixture({
      recoveryId: "10000000-0000-9000-8000-000000000001",
      token,
    }))).toBe(opaqueRateLimitKey("test-recovery", token));
    expect(recoveryKey(requestFixture({ recoveryId }))).not.toContain(recoveryId);
  });

  it("isolates invitation acceptance budgets by token behind one NAT", async () => {
    const app = await invitationApp();
    const firstToken = "a".repeat(43);
    const allowed = [];
    for (let index = 0; index < 6; index += 1) {
      allowed.push(await invitationAcceptance(app, firstToken));
    }

    expect(allowed.map(({ statusCode }) => statusCode)).toEqual([428, 428, 428, 428, 428, 428]);
    expect((await invitationAcceptance(app, firstToken)).statusCode).toBe(429);
    expect((await invitationAcceptance(app, "b".repeat(43))).statusCode).toBe(428);
  });

  it("isolates platform bootstrap acceptance budgets by token behind one NAT", async () => {
    const app = await bootstrapApp();
    const firstToken = "c".repeat(43);
    const allowed = [];
    for (let index = 0; index < 3; index += 1) {
      allowed.push(await bootstrapAcceptance(app, firstToken));
    }

    expect(allowed.map(({ statusCode }) => statusCode)).toEqual([400, 400, 400]);
    expect((await bootstrapAcceptance(app, firstToken)).statusCode).toBe(429);
    expect((await bootstrapAcceptance(app, "d".repeat(43))).statusCode).toBe(400);
  });

  it("keeps initial-admin redemption stable across token consumption and NAT peers", async () => {
    const app = await recoveryApp();
    const firstRecoveryId = "20000000-0000-4000-8000-000000000001";
    const allowed = [];
    for (let index = 0; index < 4; index += 1) {
      allowed.push(await recoveryRedemption(app, firstRecoveryId, "e".repeat(43)));
    }
    for (let index = 0; index < 4; index += 1) {
      allowed.push(await recoveryRedemption(app, firstRecoveryId));
    }

    expect(allowed.map(({ statusCode }) => statusCode))
      .toEqual([428, 428, 428, 428, 428, 428, 428, 428]);
    expect((await recoveryRedemption(app, firstRecoveryId)).statusCode).toBe(429);
    expect((await recoveryRedemption(
      app,
      "30000000-0000-4000-8000-000000000001",
      "f".repeat(43),
    )).statusCode).toBe(428);
  });

  it("gives empty invitation recovery-context requests the 1,200 per 15 minute NAT budget", async () => {
    let routeRateLimit: unknown;
    const app = await baseApp();
    app.addHook("onRoute", (options) => {
      if (options.method === "POST" && options.url === "/v1/invitations/recovery-context") {
        routeRateLimit = options.config?.rateLimit;
      }
    });
    decorateInvitationApp(app);
    await registerInvitationRoutes(app);
    await app.ready();

    expect(routeRateLimit).toMatchObject({ max: 1_200, timeWindow: "15 minutes" });
  });
});

function requestFixture(body: unknown): FastifyRequest {
  return { body, ip: "198.51.100.10" } as FastifyRequest;
}

async function baseApp(): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  await app.register(cookie);
  app.decorate("apiConfig", developmentConfig());
  await app.register(rateLimit, {
    global: true,
    max: 10_000,
    timeWindow: "1 hour",
    hook: "preValidation",
    keyGenerator: (request) => `test-global:${request.ip}`,
  });
  return app;
}

async function invitationApp(): Promise<FastifyInstance> {
  const app = await baseApp();
  decorateInvitationApp(app);
  await registerInvitationRoutes(app);
  await app.ready();
  return app;
}

function decorateInvitationApp(app: FastifyInstance): void {
  app.decorate("invitationService", { accept: vi.fn() } as unknown as InvitationService);
  app.decorate("authenticate", async () => undefined);
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", () => async () => undefined);
}

async function bootstrapApp(): Promise<FastifyInstance> {
  const app = await baseApp();
  await registerPlatformBootstrapRoutes(app);
  await app.ready();
  return app;
}

async function recoveryApp(): Promise<FastifyInstance> {
  const app = await baseApp();
  app.decorate("initialAdminRecoveryService", { redeem: vi.fn() } as never);
  app.decorate("authenticate", async () => undefined);
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", () => async () => undefined);
  app.decorateRequest("principal", null);
  await registerInitialAdminOnboardingRecoveryRoutes(app);
  await app.ready();
  return app;
}

function invitationAcceptance(app: FastifyInstance, token: string) {
  return app.inject({
    method: "POST",
    url: "/v1/invitations/accept",
    remoteAddress: "198.51.100.20",
    headers: { origin },
    payload: { token, email: "recipient@example.test", displayName: "Recipient" },
  });
}

function bootstrapAcceptance(app: FastifyInstance, token: string) {
  return app.inject({
    method: "POST",
    url: "/v1/auth/platform-bootstrap/accept",
    remoteAddress: "198.51.100.21",
    headers: { origin },
    payload: { token },
  });
}

function recoveryRedemption(app: FastifyInstance, recoveryId: string, token?: string) {
  return app.inject({
    method: "POST",
    url: "/v1/auth/initial-admin-recovery/redeem",
    remoteAddress: "198.51.100.22",
    headers: { origin },
    payload: { recoveryId, ...(token === undefined ? {} : { token }) },
  });
}

function developmentConfig(): ApiConfig {
  return {
    environment: "development",
    host: "127.0.0.1",
    port: 4000,
    corsOrigins: new Set([origin]),
    trustedProxyCidrs: [],
    secureCookies: false,
    sessionTtlSeconds: 3_600,
    webauthn: {
      rpName: "Nombramientos",
      rpId: "localhost",
      expectedOrigins: [origin],
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    },
    authEncryptionKey: Buffer.alloc(32, 7),
    controlDatabaseUrl: "postgresql://runtime:unused@127.0.0.1:55432/nombramientos_control",
    secretMasterKey: Buffer.alloc(32, 9),
    secretFile: "unused-in-this-test",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
}
