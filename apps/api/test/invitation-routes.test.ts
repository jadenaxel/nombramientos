import cookie from "@fastify/cookie";
import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { ApiError } from "../src/lib/errors.js";
import { CSRF_COOKIE, SESSION_COOKIE } from "../src/modules/auth-service.js";
import { hashStepUpOperation } from "../src/modules/enterprise-auth-contract.js";
import {
  deriveInvitationRecoveryProof,
  INVITATION_RECOVERY_COOKIE_PREFIX,
  registerInvitationRoutes,
} from "../src/modules/invitation-routes.js";
import type { InvitationService } from "../src/modules/invitation-service.js";

describe("invitation acceptance session delivery", () => {
  it.each([
    ["missing", undefined],
    ["CORS-only noncanonical", "http://127.0.0.1:3000"],
    ["untrusted", "https://evil.example.test"],
  ] as const)("rejects a %s Origin before invitation work or cookie issuance", async (_label, origin) => {
    const accept = vi.fn();
    const app = Fastify();
    await app.register(cookie);
    app.decorate("apiConfig", {
      ...developmentConfig(),
      corsOrigins: new Set(["http://localhost:3000", "http://127.0.0.1:3000"]),
    });
    app.decorate("invitationService", { accept } as unknown as InvitationService);
    app.decorate("authenticate", async () => undefined);
    app.decorate("verifyCsrf", async () => undefined);
    app.decorate("requirePermission", () => async () => undefined);
    app.setErrorHandler((error, request, reply) => {
      if (error instanceof ApiError) {
        return reply.status(error.statusCode).send({
          error: { code: error.code, message: error.message },
          meta: { requestId: request.id },
        });
      }
      throw error;
    });
    await registerInvitationRoutes(app);
    try {
      const response = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: origin === undefined ? {} : { origin },
        payload: {
          token: "t".repeat(43),
          email: "recipient@example.test",
          displayName: "Recipient",
        },
      });
      expect(response.statusCode).toBe(403);
      expect(response.json<{ error: { code: string } }>().error.code).toBe("ORIGIN_NOT_ALLOWED");
      expect(response.headers["set-cookie"]).toBeUndefined();
      expect(accept).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });

  it("establishes only an Origin-locked HttpOnly recovery cookie and rejects alternate proof channels", async () => {
    const accept = vi.fn();
    const app = Fastify();
    await app.register(cookie);
    app.decorate("apiConfig", { ...developmentConfig(), secureCookies: true });
    app.decorate("invitationService", { accept } as unknown as InvitationService);
    app.decorate("authenticate", async () => undefined);
    app.decorate("verifyCsrf", async () => undefined);
    app.decorate("requirePermission", () => async () => undefined);
    app.setErrorHandler((error, request, reply) => {
      if (error instanceof ApiError) {
        return reply.status(error.statusCode).send({
          error: { code: error.code, message: error.message },
          meta: { requestId: request.id },
        });
      }
      throw error;
    });
    await registerInvitationRoutes(app);
    try {
      const missingOrigin = await app.inject({
        method: "POST",
        url: "/v1/invitations/recovery-context",
        payload: {},
      });
      expect(missingOrigin.statusCode).toBe(403);
      expect(missingOrigin.headers["set-cookie"]).toBeUndefined();

      const secretInBody = await app.inject({
        method: "POST",
        url: "/v1/invitations/recovery-context",
        headers: { origin: "http://localhost:3000" },
        payload: { recoveryProof: "r".repeat(43) },
      });
      expect(secretInBody.statusCode).toBe(400);
      expect(secretInBody.headers["set-cookie"]).toBeUndefined();

      const prepared = await app.inject({
        method: "POST",
        url: "/v1/invitations/recovery-context",
        headers: { origin: "http://localhost:3000" },
        payload: {},
      });
      expect(prepared.statusCode).toBe(200);
      const issued = prepared.cookies.find(({ name }) => name.startsWith(INVITATION_RECOVERY_COOKIE_PREFIX));
      expect(issued?.name).toMatch(/^nom_invitation_recovery_[A-Za-z0-9_-]{22}$/u);
      expect(issued).toMatchObject({
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        path: "/v1/invitations",
        maxAge: 24 * 60 * 60,
      });
      expect(issued?.value).toMatch(/^[A-Za-z0-9_-]{43}$/u);

      const reused = await app.inject({
        method: "POST",
        url: "/v1/invitations/recovery-context",
        headers: {
          origin: "http://localhost:3000",
          cookie: `${issued?.name ?? "invalid"}=${issued?.value ?? ""}`,
        },
        payload: {},
      });
      expect(reused.cookies.find(({ name }) => name === issued?.name)?.value).toBe(issued?.value);
      const firstDerived = deriveInvitationRecoveryProof(
        issued?.value ?? "",
        "t".repeat(43),
        "recipient@example.test",
      );
      const secondDerived = deriveInvitationRecoveryProof(
        issued?.value ?? "",
        "u".repeat(43),
        "recipient@example.test",
      );
      expect(firstDerived).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(firstDerived).not.toBe(issued?.value);
      expect(secondDerived).not.toBe(firstDerived);

      const missingCookie = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: { origin: "http://localhost:3000" },
        payload: {
          token: "t".repeat(43),
          email: "recipient@example.test",
          displayName: "Recipient",
        },
      });
      expect(missingCookie.statusCode).toBe(428);
      expect(missingCookie.json()).toMatchObject({ error: { code: "INVITATION_RECOVERY_CONTEXT_REQUIRED" } });

      const alternateBodyProof = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: {
          origin: "http://localhost:3000",
          cookie: `${issued?.name ?? "invalid"}=${issued?.value ?? ""}`,
        },
        payload: {
          token: "t".repeat(43),
          recoveryProof: "r".repeat(43),
          email: "recipient@example.test",
          displayName: "Recipient",
        },
      });
      expect(alternateBodyProof.statusCode).toBe(400);
      expect(accept).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });

  it("keeps signed recovery roots deterministic and recovers when only root thirteen is bound", async () => {
    const accept = vi.fn().mockResolvedValue({
      sessionToken: "session",
      csrfToken: "csrf",
      expiresAt: new Date(Date.now() + 60_000),
    });
    const app = Fastify();
    await app.register(cookie);
    const config = { ...developmentConfig(), authEncryptionKey: Buffer.alloc(32, 7) };
    app.decorate("apiConfig", config);
    app.decorate("invitationService", { accept } as unknown as InvitationService);
    app.decorate("authenticate", async () => undefined);
    app.decorate("verifyCsrf", async () => undefined);
    app.decorate("requirePermission", () => async () => undefined);
    app.setErrorHandler((error, request, reply) => {
      if (error instanceof ApiError) {
        return reply.status(error.statusCode).send({
          error: { code: error.code, message: error.message },
          meta: { requestId: request.id },
        });
      }
      throw error;
    });
    await registerInvitationRoutes(app);
    const preflight = () => app.inject({
      method: "POST",
      url: "/v1/invitations/recovery-context",
      headers: { origin: "http://localhost:3000" },
      payload: {},
    });
    try {
      // Empty-jar requests can race at the HTTP boundary. Dynamic MAC-bound
      // names mean delayed Set-Cookie responses coexist instead of overwriting.
      const initial = await Promise.all([preflight(), preflight(), preflight(), preflight(), preflight()]);
      const roots = initial.map((response) =>
        response.cookies.find(({ name }) => name.startsWith(INVITATION_RECOVERY_COOKIE_PREFIX))!);
      expect(new Set(roots.map(({ name }) => name)).size).toBe(5);
      expect(new Set(roots.map(({ value }) => value)).size).toBe(5);
      const fiveCookieHeader = roots.map(({ name, value }) => `${name}=${value}`).join("; ");

      const fifthSequential = await app.inject({
        method: "POST",
        url: "/v1/invitations/recovery-context",
        headers: { origin: "http://localhost:3000", cookie: fiveCookieHeader },
        payload: {},
      });
      expect(fifthSequential.statusCode).toBe(200);
      expect(fifthSequential.cookies).toHaveLength(5);
      expect(new Set(fifthSequential.cookies.map(({ name }) => name)))
        .toEqual(new Set(roots.map(({ name }) => name)));

      const token = "t".repeat(43);
      const accepted = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: { origin: "http://localhost:3000", cookie: fiveCookieHeader },
        payload: { token, email: "RECIPIENT@example.test", displayName: "Recipient" },
      });
      expect(accepted.statusCode).toBe(201);
      const orderedRoots = [...roots].sort((left, right) => left.name.localeCompare(right.name, "en-US"));
      expect(accept).toHaveBeenLastCalledWith(expect.objectContaining({
        recoveryProofs: orderedRoots.map(({ value }) =>
          deriveInvitationRecoveryProof(value, token, "recipient@example.test")),
      }));
      for (const { value } of roots) expect(JSON.stringify(accept.mock.calls)).not.toContain(value);

      // Invalid names/values never consume one of the twelve logical slots or
      // displace a valid signed root. Excessive total parsing work fails closed.
      const malformed = Array.from({ length: 59 }, (_, index) => `junk${index}=x`).join("; ");
      const validWithMalformed = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: {
          origin: "http://localhost:3000",
          cookie: `${malformed}; ${roots[0]!.name}=${roots[0]!.value}`,
        },
        payload: { token, email: "recipient@example.test", displayName: "Recipient" },
      });
      expect(validWithMalformed.statusCode).toBe(201);
      expect(accept).toHaveBeenLastCalledWith(expect.objectContaining({
        recoveryProofs: [deriveInvitationRecoveryProof(
          roots[0]!.value,
          token,
          "recipient@example.test",
        )],
      }));
      const bomb = Array.from({ length: 65 }, (_, index) => `junk${index}=x`).join("; ");
      const bombed = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: { origin: "http://localhost:3000", cookie: bomb },
        payload: { token, email: "recipient@example.test", displayName: "Recipient" },
      });
      expect(bombed.statusCode).toBe(428);
      expect(bombed.json()).toMatchObject({ error: { code: "INVITATION_RECOVERY_CONTEXT_OVERFLOW" } });

      // Build additional authentic roots from another empty cookie jar using
      // the same server key. The service contract receives bounded batches but
      // the route must preserve every authentic root admitted by the cookie
      // header/count caps.
      const secondApp = Fastify();
      await secondApp.register(cookie);
      secondApp.decorate("apiConfig", config);
      secondApp.decorate("invitationService", { accept } as unknown as InvitationService);
      secondApp.decorate("authenticate", async () => undefined);
      secondApp.decorate("verifyCsrf", async () => undefined);
      secondApp.decorate("requirePermission", () => async () => undefined);
      secondApp.setErrorHandler((error, request, reply) => {
        if (error instanceof ApiError) {
          return reply.status(error.statusCode).send({
            error: { code: error.code, message: error.message },
            meta: { requestId: request.id },
          });
        }
        throw error;
      });
      await registerInvitationRoutes(secondApp);
      const extraResponses = await Promise.all(Array.from({ length: 8 }, () => secondApp.inject({
        method: "POST",
        url: "/v1/invitations/recovery-context",
        headers: { origin: "http://localhost:3000" },
        payload: {},
      })));
      const extraRoots = extraResponses.map((response) =>
        response.cookies.find(({ name }) => name.startsWith(INVITATION_RECOVERY_COOKIE_PREFIX))!);
      await secondApp.close();

      const twelveRoots = [...roots, ...extraRoots.slice(0, 7)];
      const twelveHeader = twelveRoots.map(({ name, value }) => `${name}=${value}`).join("; ");
      const twelveAccepted = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: { origin: "http://localhost:3000", cookie: twelveHeader },
        payload: { token, email: "recipient@example.test", displayName: "Recipient" },
      });
      expect(twelveAccepted.statusCode).toBe(201);
      expect((accept.mock.lastCall?.[0] as { recoveryProofs: string[] }).recoveryProofs).toHaveLength(12);

      const thirteenthRoot = extraRoots[7]!;
      const allThirteen = [...twelveRoots, thirteenthRoot]
        .sort((left, right) => left.name.localeCompare(right.name, "en-US"));
      const boundRoot = allThirteen[12]!;
      const boundProof = deriveInvitationRecoveryProof(boundRoot.value, token, "recipient@example.test");
      const acceptCallsBeforeRecovery = accept.mock.calls.length;
      accept.mockImplementationOnce(async (input: {
        recoveryProofs: readonly string[];
        additionalRecoveryProofBatches?: readonly (readonly string[])[];
      }) => {
        const submitted = [input.recoveryProofs, ...(input.additionalRecoveryProofBatches ?? [])].flat();
        if (!submitted.includes(boundProof)) throw new Error("bound recovery proof was omitted");
        return {
          sessionToken: "session",
          csrfToken: "csrf",
          expiresAt: new Date(Date.now() + 60_000),
        };
      });
      const recoveredFromThirteenth = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: {
          origin: "http://localhost:3000",
          cookie: `${twelveHeader}; ${thirteenthRoot.name}=${thirteenthRoot.value}`,
        },
        payload: { token, email: "recipient@example.test", displayName: "Recipient" },
      });
      expect(recoveredFromThirteenth.statusCode).toBe(201);
      expect(accept).toHaveBeenCalledTimes(acceptCallsBeforeRecovery + 1);
      const submitted = accept.mock.lastCall?.[0] as {
        recoveryProofs: readonly string[];
        additionalRecoveryProofBatches?: readonly (readonly string[])[];
      };
      expect(submitted.recoveryProofs).toEqual(allThirteen.slice(0, 12).map(({ value }) =>
        deriveInvitationRecoveryProof(value, token, "recipient@example.test")));
      expect(submitted.additionalRecoveryProofBatches).toEqual([[boundProof]]);
      expect([submitted.recoveryProofs, ...(submitted.additionalRecoveryProofBatches ?? [])].flat())
        .toEqual(allThirteen.map(({ value }) =>
          deriveInvitationRecoveryProof(value, token, "recipient@example.test")));
      for (const { value } of allThirteen) expect(JSON.stringify(submitted)).not.toContain(value);
      expect(recoveredFromThirteenth.cookies.filter(({ name }) =>
        name.startsWith(INVITATION_RECOVERY_COOKIE_PREFIX))).toHaveLength(0);
    } finally {
      await app.close();
    }
  });

  it("sets database-clamped session cookies and never serializes the bearer token", async () => {
    const expiresAt = new Date(Date.now() + 8 * 60_000);
    const accept = vi.fn().mockResolvedValue({
      accepted: true,
      signInRequired: false,
      enrollmentRequired: true,
      tenantId: "40000000-0000-4000-8000-000000000001",
      roles: ["AUDITOR"],
      status: "mfa_enrollment_required",
      authenticated: true,
      user: {
        id: "30000000-0000-4000-8000-000000000001",
        displayName: "Recipient",
        email: "recipient@example.test",
      },
      tenant: {
        id: "40000000-0000-4000-8000-000000000001",
        slug: "fixture",
        name: "Fixture",
        kind: "real",
        timezone: "America/La_Paz",
      },
      permissions: [],
      csrfToken: "csrf-secret",
      keyGrant: null,
      security: {
        mfaRequired: true,
        mfaEnabled: false,
        enrollmentOnly: true,
        assurance: "enrollment_only",
        aal: 1,
        authMethod: "bootstrap",
        phishingResistant: false,
        recoveryRestricted: false,
        passkeyEnabled: false,
        strongAuthEnabled: false,
        passkeyCount: 0,
        idleExpiresAt: expiresAt,
        risk: { elevated: false, userAgentContextChanged: false, ipContextChanged: false },
      },
      expiresAt,
      sessionToken: "session-bearer-secret",
    });
    const app = Fastify();
    await app.register(cookie);
    app.decorate("apiConfig", developmentConfig());
    app.decorate("invitationService", { accept } as unknown as InvitationService);
    app.decorate("authenticate", async () => undefined);
    app.decorate("verifyCsrf", async () => undefined);
    app.decorate("requirePermission", () => async () => undefined);
    await registerInvitationRoutes(app);

    try {
      const prepared = await app.inject({
        method: "POST",
        url: "/v1/invitations/recovery-context",
        headers: { origin: "http://localhost:3000" },
        payload: {},
      });
      expect(prepared.statusCode).toBe(200);
      const recoveryCookie = prepared.cookies.find(({ name }) => name.startsWith(INVITATION_RECOVERY_COOKIE_PREFIX));
      expect(recoveryCookie).toMatchObject({
        httpOnly: true,
        sameSite: "Strict",
        path: "/v1/invitations",
        maxAge: 24 * 60 * 60,
      });
      expect(recoveryCookie?.value).toMatch(/^[A-Za-z0-9_-]{43}$/u);

      const response = await app.inject({
        method: "POST",
        url: "/v1/invitations/accept",
        headers: {
          origin: "http://localhost:3000",
          "user-agent": "Invitation route test",
          cookie: `${recoveryCookie?.name ?? "invalid"}=${recoveryCookie?.value ?? ""}`,
        },
        remoteAddress: "203.0.113.42",
        payload: {
          token: "t".repeat(43),
          email: "recipient@example.test",
          displayName: "Recipient",
        },
      });

      expect(response.statusCode).toBe(201);
      const data = response.json<{ data: Record<string, unknown> }>().data;
      expect(data).toMatchObject({
        accepted: true,
        signInRequired: false,
        enrollmentRequired: true,
        csrfToken: "csrf-secret",
        status: "mfa_enrollment_required",
      });
      expect(data).not.toHaveProperty("sessionToken");
      const sessionCookie = response.cookies.find(({ name }) => name === SESSION_COOKIE);
      const csrfCookie = response.cookies.find(({ name }) => name === CSRF_COOKIE);
      expect(sessionCookie).toMatchObject({
        value: "session-bearer-secret",
        httpOnly: true,
        sameSite: "Lax",
        path: "/",
      });
      expect(csrfCookie).toMatchObject({
        value: "csrf-secret",
        sameSite: "Lax",
        path: "/",
      });
      expect(csrfCookie).not.toHaveProperty("httpOnly");
      const cookieExpiry = Math.floor(expiresAt.getTime() / 1_000) * 1_000;
      expect(sessionCookie?.expires?.getTime()).toBe(cookieExpiry);
      expect(csrfCookie?.expires?.getTime()).toBe(cookieExpiry);
      expect(accept).toHaveBeenCalledWith(expect.objectContaining({
        recoveryProofs: [deriveInvitationRecoveryProof(
          recoveryCookie?.value ?? "",
          "t".repeat(43),
          "recipient@example.test",
        )],
        userAgent: "Invitation route test",
        ip: "203.0.113.42",
      }));
      expect(JSON.stringify(accept.mock.calls)).not.toContain(recoveryCookie?.value);
      expect(accept.mock.calls[0]?.[0]).not.toHaveProperty("password");
    } finally {
      await app.close();
    }
  });

  it("binds invitation mutations to a one-use role-administration grant under enforced policy", async () => {
    const payload = {
      email: "recipient@example.test",
      roles: ["AUDITOR"],
      expiresInHours: 24,
    };
    const principal = {
      sessionId: "20000000-0000-4000-8000-000000000001",
      identityId: "30000000-0000-4000-8000-000000000001",
      activeTenantId: "40000000-0000-4000-8000-000000000001",
      assuranceLevel: "mfa",
      enrollmentOnly: false,
      aal: 2,
      mfaVerifiedAt: new Date(),
    } as RequestPrincipal;
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const database = {
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(enforcedIdentityPolicy()),
        consumeStepUpGrant,
      },
      control: { appendAudit: vi.fn().mockResolvedValue(undefined) },
    } as unknown as DatabaseRuntime;
    const create = vi.fn().mockResolvedValue({
      invitation: {
        id: "10000000-0000-4000-8000-000000000001",
        tenantId: principal.activeTenantId,
        email: payload.email,
        roles: payload.roles,
        status: "pending",
        expiresAt: new Date(Date.now() + 60_000),
        createdAt: new Date(),
        acceptedAt: null,
        revokedAt: null,
        version: 1,
      },
      delivery: "local_one_time_token",
      acceptanceToken: "one-time-invitation-token",
      created: true,
    });
    const app = Fastify();
    await app.register(cookie);
    app.decorate("apiConfig", developmentConfig());
    app.decorate("database", database);
    app.decorate("invitationService", { create } as unknown as InvitationService);
    app.decorate("authenticate", async (request) => { request.principal = principal; });
    app.decorate("verifyCsrf", async () => undefined);
    app.decorate("requirePermission", () => async () => undefined);
    app.setErrorHandler((error, request, reply) => {
      if (error instanceof ApiError) {
        return reply.status(error.statusCode).send({
          error: { code: error.code, message: error.message, details: error.details },
          meta: { requestId: request.id },
        });
      }
      return reply.send(error);
    });
    await registerInvitationRoutes(app);

    try {
      const expectedOperationHash = hashStepUpOperation(
        "role_administration",
        "POST",
        "/v1/invitations",
        payload,
      );
      const challenge = await app.inject({
        method: "POST",
        url: "/v1/invitations",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "50000000-0000-4000-8000-000000000001",
          "x-csrf-token": "csrf",
        },
        payload,
      });
      expect(challenge.statusCode).toBe(428);
      expect(challenge.json()).toMatchObject({
        error: {
          code: "WEBAUTHN_STEP_UP_REQUIRED",
          details: {
            purpose: "role_administration",
            operationHash: expectedOperationHash,
          },
        },
      });
      expect(create).not.toHaveBeenCalled();

      const granted = await app.inject({
        method: "POST",
        url: "/v1/invitations",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "50000000-0000-4000-8000-000000000001",
          "x-csrf-token": "csrf",
          "x-step-up-grant": "g".repeat(43),
        },
        payload,
      });
      expect(granted.statusCode).toBe(201);
      expect(create).toHaveBeenCalledOnce();
      expect(consumeStepUpGrant).toHaveBeenCalledWith(expect.objectContaining({
        identityId: principal.identityId,
        sessionId: principal.sessionId,
        purpose: "role_administration",
        operationHash: expectedOperationHash,
      }));
    } finally {
      await app.close();
    }
  });
});

function developmentConfig(): ApiConfig {
  return {
    environment: "development",
    host: "127.0.0.1",
    port: 4000,
    corsOrigins: new Set(["http://localhost:3000"]),
    secureCookies: false,
    sessionTtlSeconds: 3_600,
    webauthn: {
      rpName: "Nombramientos",
      rpId: "localhost",
      expectedOrigins: ["http://localhost:3000"],
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    },
    authEncryptionKey: Buffer.alloc(32),
    controlDatabaseUrl: "postgresql://runtime:unused@127.0.0.1:55432/nombramientos_control",
    secretMasterKey: Buffer.alloc(32),
    secretFile: "unused-in-this-test",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
}

function enforcedIdentityPolicy() {
  return {
    baselineVersion: 1,
    tenantVersion: 1,
    enforcementMode: "enforce" as const,
    minimumAal: 1 as const,
    requireUserVerification: true,
    privilegedMinimumAal: 2 as const,
    requireDeviceBoundForPrivileged: false,
    requireAttestationForPrivileged: false,
    requirePhishingResistantForPrivileged: true,
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
