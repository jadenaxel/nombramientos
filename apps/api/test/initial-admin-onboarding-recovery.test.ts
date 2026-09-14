import { createHash } from "node:crypto";
import cookie from "@fastify/cookie";
import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { ApiError } from "../src/lib/errors.js";
import { hashStepUpOperation } from "../src/modules/enterprise-auth-contract.js";
import {
  deriveInitialAdminRecoveryProof,
  INITIAL_ADMIN_RECOVERY_COOKIE_PREFIX,
  registerInitialAdminOnboardingRecoveryRoutes,
} from "../src/modules/initial-admin-onboarding-recovery-routes.js";
import { InitialAdminOnboardingRecoveryService } from "../src/modules/initial-admin-onboarding-recovery-service.js";

const recoveryId = "10000000-0000-4000-8000-000000000001";
const source = {
  tenantId: "20000000-0000-4000-8000-000000000001",
  invitationId: "30000000-0000-4000-8000-000000000001",
  acceptanceId: "40000000-0000-4000-8000-000000000001",
  acceptanceIdentityId: "50000000-0000-4000-8000-000000000001",
  acceptanceAttempt: 1,
  authorityEpoch: 1,
  invitationVersion: 7,
};

describe("initial-admin recovery HTTP boundary", () => {
  it("precommits an empty Strict HttpOnly response and retains twelve authentic roots out of order", async () => {
    const redeem = vi.fn().mockResolvedValue({
      sessionToken: "s".repeat(43),
      csrfToken: "c".repeat(43),
      expiresAt: new Date(Date.now() + 60_000),
      publicSession: { recovered: true, status: "mfa_enrollment_required" },
    });
    const app = await recoveryApp({ redeem });
    try {
      const preflights = await Promise.all(Array.from({ length: 13 }, () => app.inject({
        method: "POST",
        url: "/v1/auth/initial-admin-recovery/prepare-context",
        headers: { origin: "http://localhost:3000" },
        payload: {},
      })));
      for (const response of preflights) {
        expect(response.statusCode).toBe(204);
        expect(response.body).toBe("");
      }
      const roots = preflights.map((response) => response.cookies.find(({ name }) =>
        name.startsWith(INITIAL_ADMIN_RECOVERY_COOKIE_PREFIX))!);
      expect(new Set(roots.map(({ name }) => name))).toHaveProperty("size", 13);
      for (const root of roots) {
        expect(root).toMatchObject({
          httpOnly: true,
          sameSite: "Strict",
          path: "/v1/auth/initial-admin-recovery",
          maxAge: 30 * 60,
        });
      }

      const shuffled = [roots[8]!, roots[1]!, roots[12]!, ...roots.filter((_, index) => ![8, 1, 12].includes(index))];
      const response = await app.inject({
        method: "POST",
        url: "/v1/auth/initial-admin-recovery/redeem",
        headers: {
          origin: "http://localhost:3000",
          cookie: shuffled.map(({ name, value }) => `${name}=${value}`).join("; "),
        },
        payload: { recoveryId, token: "t".repeat(43) },
      });
      expect(response.statusCode).toBe(200);
      const retained = [...roots]
        .sort((left, right) => left.name.localeCompare(right.name, "en-US"))
        .slice(0, 12);
      expect(redeem).toHaveBeenCalledWith(expect.objectContaining({
        recoveryId,
        contextProofs: retained.map(({ value }) => deriveInitialAdminRecoveryProof(value, recoveryId)),
      }));
      const discarded = roots.find(({ name }) => !retained.some((candidate) => candidate.name === name));
      expect(response.cookies).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: discarded?.name, value: "", maxAge: 0 }),
      ]));
      // Retained recovery roots are not cleared by a successful redemption.
      for (const root of retained) {
        expect(response.cookies).not.toEqual(expect.arrayContaining([
          expect.objectContaining({ name: root.name, value: "", maxAge: 0 }),
        ]));
      }
    } finally {
      await app.close();
    }
  });

  it("computes exact operation evidence without pre-consuming the WebAuthn grant", async () => {
    const requestRecovery = vi.fn().mockResolvedValue({
      recoveryId,
      version: 1,
      status: "pending",
      created: true,
    });
    const app = await recoveryApp({ request: requestRecovery });
    const body = {
      recoveryId,
      source,
      reasonCode: "browser_context_lost",
      caseReference: "INC-2026-0001",
      expiresInMinutes: 60,
    };
    try {
      const missing = await app.inject({
        method: "POST",
        url: "/v1/platform/initial-admin-recoveries",
        headers: { "idempotency-key": "60000000-0000-4000-8000-000000000001" },
        payload: body,
      });
      expect(missing.statusCode).toBe(428);
      expect(missing.json()).toMatchObject({
        error: {
          code: "WEBAUTHN_STEP_UP_REQUIRED",
          details: {
            purpose: "platform_administration",
            operationHash: hashStepUpOperation(
              "platform_administration",
              "POST",
              "/v1/platform/initial-admin-recoveries",
              body,
            ),
          },
        },
      });
      expect(requestRecovery).not.toHaveBeenCalled();

      const granted = await app.inject({
        method: "POST",
        url: "/v1/platform/initial-admin-recoveries",
        headers: {
          "idempotency-key": "60000000-0000-4000-8000-000000000001",
          "x-step-up-grant": "g".repeat(43),
        },
        payload: body,
      });
      expect(granted.statusCode).toBe(201);
      expect(requestRecovery).toHaveBeenCalledWith(expect.objectContaining({
        stepUp: {
          tokenHash: createHash("sha256").update("g".repeat(43)).digest("hex"),
          operationHash: hashStepUpOperation(
            "platform_administration",
            "POST",
            "/v1/platform/initial-admin-recoveries",
            body,
          ),
        },
      }));
    } finally {
      await app.close();
    }
  });

  it("does not expose a newly generated token on approval replay and fails closed in production", async () => {
    const tokenExpiresAt = new Date(Date.now() + 10 * 60_000);
    const summary = vi.fn().mockResolvedValue({ requestExpiresAt: tokenExpiresAt });
    const approve = vi.fn().mockImplementation(async (input: { recoveryTokenHash: string }) => ({
      recoveryId,
      version: 2,
      status: "finalization_pending",
      deliveryState: "delivered",
      recipientEmail: "target@example.test",
      tokenExpiresAt,
      reused: false,
      persistedHash: input.recoveryTokenHash,
    }));
    const database = {
      initialAdminRecovery: { getSummary: summary, approve },
    } as unknown as DatabaseRuntime;
    const freshService = new InitialAdminOnboardingRecoveryService(
      database,
      developmentConfig(),
      {} as never,
    );
    const body = {
      recoveryId,
      expectedVersion: 1,
      source,
      deliveryChannel: "local_console" as const,
      verifiedChannelReference: "INC-2026-0001",
    };
    const fresh = await freshService.approve({
      principal: principal(),
      body,
      stepUp: { tokenHash: "a".repeat(64), operationHash: "b".repeat(64) },
      requestId: "70000000-0000-4000-8000-000000000001",
    });
    expect(fresh.reused).toBe(false);
    expect(fresh.developmentToken).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(approve.mock.calls[0]?.[0].recoveryTokenHash)
      .toBe(createHash("sha256").update(fresh.developmentToken!).digest("hex"));

    approve.mockResolvedValueOnce({
      recoveryId,
      version: 2,
      status: "finalization_pending",
      deliveryState: "delivered",
      recipientEmail: "target@example.test",
      tokenExpiresAt,
      reused: true,
    });
    const replay = await freshService.approve({
      principal: principal(), body,
      stepUp: { tokenHash: "a".repeat(64), operationHash: "b".repeat(64) },
      requestId: "70000000-0000-4000-8000-000000000002",
    });
    expect(replay.reused).toBe(true);
    expect(replay).not.toHaveProperty("developmentToken");

    const productionService = new InitialAdminOnboardingRecoveryService(
      database,
      { ...developmentConfig(), environment: "production" },
      {} as never,
    );
    await expect(productionService.approve({
      principal: principal(), body,
      stepUp: { tokenHash: "a".repeat(64), operationHash: "b".repeat(64) },
      requestId: "70000000-0000-4000-8000-000000000003",
    })).rejects.toMatchObject({ statusCode: 503, code: "RECOVERY_DELIVERY_UNAVAILABLE" });
    expect(summary).toHaveBeenCalledTimes(2);
  });
});

async function recoveryApp(serviceOverrides: Readonly<Record<string, unknown>>) {
  const app = Fastify({ logger: false });
  await app.register(cookie);
  app.decorate("apiConfig", developmentConfig());
  app.decorate("initialAdminRecoveryService", serviceOverrides as never);
  app.decorate("authenticate", async (request) => { request.principal = principal(); });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", () => async () => undefined);
  app.decorateRequest("principal", null);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message, details: error.details },
        meta: { requestId: request.id },
      });
    }
    throw error;
  });
  await registerInitialAdminOnboardingRecoveryRoutes(app);
  return app;
}

function principal(): RequestPrincipal {
  return {
    sessionId: "80000000-0000-4000-8000-000000000001",
    identityId: "90000000-0000-4000-8000-000000000001",
    activeTenantId: "20000000-0000-4000-8000-000000000001",
    email: "admin@example.test",
    displayName: "Platform Admin",
    tenantSlug: "fixture",
    tenantName: "Fixture",
    tenantKind: "real",
    tenantTimezone: "UTC",
    csrfHash: "c".repeat(64),
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa",
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions: new Set(["platform.security.manage"]),
  };
}

function developmentConfig(): ApiConfig {
  return {
    environment: "development",
    host: "127.0.0.1",
    port: 4000,
    corsOrigins: new Set(["http://localhost:3000"]),
    trustedProxyCidrs: [],
    secureCookies: false,
    sessionTtlSeconds: 28_800,
    webauthn: {
      rpName: "Nombramientos",
      rpId: "localhost",
      expectedOrigins: ["http://localhost:3000"],
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    },
    authEncryptionKey: Buffer.alloc(32, 7),
    controlDatabaseUrl: "postgresql://nom_control:test@127.0.0.1:55432/nombramientos_control",
    secretMasterKey: Buffer.alloc(32, 9),
    secretFile: "unused",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
}
