import cookie from "@fastify/cookie";
import type { DatabaseRuntime, DeviceSessionStore, RequestPrincipal } from "@nombramientos/database";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { registerEnterpriseAuthRoutes, registerSessionManagementRoutes } from "../src/modules/enterprise-auth-routes.js";
import type { EnterpriseAuthService } from "../src/modules/enterprise-auth-service.js";

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe("enterprise authentication route contracts", () => {
  it("identifies own federated browsers using exact tenant-local bindings without modifying sessions", async () => {
    const sessions = [
      { id: "10000000-0000-4000-8000-000000000001", current: true, deviceLabel: null },
      { id: "10000000-0000-4000-8000-000000000002", current: false, deviceLabel: null },
      { id: "10000000-0000-4000-8000-000000000003", current: false, deviceLabel: "Original label" },
    ];
    const getOwnSessionLabels = vi.fn().mockResolvedValue(new Map([
      [sessions[0]!.id, "Computadora A"], [sessions[1]!.id, "Teléfono B"],
      ["10000000-0000-4000-8000-000000000099", "Another identity/tenant must never appear"],
    ]));
    const app = await fixtureApp([], sessions, {}, true, { getOwnSessionLabels });
    const response = await app.inject({ method: "GET", url: "/v1/auth/sessions" });
    expect(response.statusCode).toBe(200);
    expect(response.json().data.items).toEqual([
      { ...sessions[0], deviceLabel: "Computadora A" },
      { ...sessions[1], deviceLabel: "Teléfono B" }, sessions[2],
    ]);
    expect(getOwnSessionLabels).toHaveBeenCalledExactlyOnceWith(principalFixture().identityId, sessions.map((item) => item.id));
    expect(sessions.map((item) => item.deviceLabel)).toEqual([null, null, "Original label"]);
    expect(response.body).not.toContain("Another identity/tenant");
  });

  it("fails closed instead of returning an unlabeled list when the tenant binding lookup fails", async () => {
    const getOwnSessionLabels = vi.fn().mockRejectedValue(new Error("Binding lookup unavailable"));
    const app = await fixtureApp([], [{ id: "10000000-0000-4000-8000-000000000001", deviceLabel: null }], {}, true,
      { getOwnSessionLabels });
    const response = await app.inject({ method: "GET", url: "/v1/auth/sessions" });
    expect(response.statusCode).toBe(500);
    expect(response.json()).not.toHaveProperty("data.items");
  });

  it("preserves demo session labels without opening any tenant key-device binding query", async () => {
    const getOwnSessionLabels = vi.fn().mockRejectedValue(new Error("Must not run in demo"));
    const sessions = [{ id: "10000000-0000-4000-8000-000000000001", deviceLabel: "Demo browser" }];
    const app = await fixtureApp([], sessions, {}, true, { getOwnSessionLabels, tenantKind: "demo" });
    const response = await app.inject({ method: "GET", url: "/v1/auth/sessions" });
    expect(response.statusCode).toBe(200);
    expect(response.json().data.items).toEqual(sessions);
    expect(getOwnSessionLabels).not.toHaveBeenCalled();
  });

  it("exposes session self-management for federated login without enabling standalone MFA/passkey routes", async () => {
    const revokeSession = vi.fn().mockResolvedValue({ revoked: true, current: false });
    const revokeOtherSessions = vi.fn().mockResolvedValue({ revoked: 2 });
    const sessions = [{ id: "10000000-0000-4000-8000-000000000001", current: true }];
    const app = await fixtureApp([], sessions, { revokeSession, revokeOtherSessions }, true);
    expect((await app.inject({ method: "GET", url: "/v1/auth/sessions" })).json().data).toEqual({ items: sessions });
    const closed = await app.inject({ method: "DELETE", url: "/v1/auth/sessions/10000000-0000-4000-8000-000000000002", payload: { reason: "user_revoked" } });
    expect(closed.statusCode).toBe(200);
    expect(revokeSession).toHaveBeenCalledWith(expect.objectContaining({
      principal: expect.objectContaining({ authMethod: "federated" }),
      sessionId: "10000000-0000-4000-8000-000000000002",
    }));
    const others = await app.inject({ method: "POST", url: "/v1/auth/sessions/revoke-others", payload: { reason: "user_revoked" } });
    expect(others.statusCode).toBe(200);
    expect(others.json().data).toEqual({ revoked: 2 });
    expect(revokeOtherSessions).toHaveBeenCalledWith(expect.objectContaining({ principal: expect.objectContaining({ authMethod: "federated" }) }));
    for (const url of ["/v1/auth/passkeys", "/v1/auth/policy"]) {
      expect((await app.inject({ method: "GET", url })).statusCode).toBe(404);
    }
    for (const url of ["/v1/auth/passkeys/registration/options", "/v1/auth/passkeys/authentication/options", "/v1/auth/mfa/enrollment/start"]) {
      expect((await app.inject({ method: "POST", url, payload: {} })).statusCode).toBe(404);
    }
  });

  it("wraps passkey and session collections in an items envelope", async () => {
    const passkeys = [{ id: "40000000-0000-4000-8000-000000000001", name: "Laptop" }];
    const sessions = [{ id: "10000000-0000-4000-8000-000000000001", current: true }];
    const app = await fixtureApp(passkeys, sessions);

    const passkeyResponse = await app.inject({ method: "GET", url: "/v1/auth/passkeys" });
    expect(passkeyResponse.statusCode).toBe(200);
    expect(passkeyResponse.json<{ data: unknown }>().data).toEqual({ items: passkeys });

    const sessionResponse = await app.inject({ method: "GET", url: "/v1/auth/sessions" });
    expect(sessionResponse.statusCode).toBe(200);
    expect(sessionResponse.json<{ data: unknown }>().data).toEqual({ items: sessions });
  });

  it("clears session cookies when the atomic passkey revoke reports the current session revoked", async () => {
    const revokePasskey = vi.fn().mockResolvedValue({
      revoked: true,
      sessionsRevoked: 2,
      currentSessionRevoked: true,
    });
    const app = await fixtureApp([], [], { revokePasskey });
    const response = await app.inject({
      method: "DELETE",
      url: "/v1/auth/passkeys/40000000-0000-4000-8000-000000000001",
      headers: { "x-step-up-grant": "g".repeat(43) },
      payload: { reason: "compromised" },
    });

    expect(response.statusCode).toBe(200);
    const data = response.json<{ data: Record<string, unknown> }>().data;
    expect(data).toMatchObject({ signedOut: true, sessionsRevoked: 2 });
    expect(data).not.toHaveProperty("currentSessionRevoked");
    const cookies = response.headers["set-cookie"];
    expect(cookies).toEqual(expect.arrayContaining([
      expect.stringContaining("nom_session=;"),
      expect.stringContaining("nom_csrf=;"),
    ]));
  });

  it("correlates concurrent authentication, registration, and step-up cookies without clobbering", async () => {
    const expiresAt = new Date(Date.now() + 120_000);
    const ceremonies = {
      authentication: { id: "50000000-0000-4000-8000-000000000001", token: canonicalToken(1) },
      registration: { id: "50000000-0000-4000-8000-000000000002", token: canonicalToken(2) },
      stepUp: { id: "50000000-0000-4000-8000-000000000003", token: canonicalToken(3) },
    } as const;
    const verifyAuthentication = vi.fn().mockResolvedValue({
      sessionToken: "n".repeat(43),
      csrfToken: "c".repeat(43),
      expiresAt,
    });
    const verifyRegistration = vi.fn().mockResolvedValue({
      verified: true,
      credential: { id: "40000000-0000-4000-8000-000000000001" },
      session: { sessionToken: "m".repeat(43), csrfToken: "d".repeat(43), expiresAt },
    });
    const verifyStepUp = vi.fn().mockResolvedValue({
      verified: true,
      purpose: "data_export",
      operationHash: "f".repeat(64),
      grantToken: "g".repeat(43),
      expiresAt,
    });
    const app = await fixtureApp([], [], {
      authenticationOptions: vi.fn().mockResolvedValue({
        ceremonyId: ceremonies.authentication.id,
        ceremonyToken: ceremonies.authentication.token,
        expiresAt,
        options: { challenge: "Y2hhbGxlbmdl", rpId: "localhost" },
      }),
      registrationOptions: vi.fn().mockResolvedValue({
        ceremonyId: ceremonies.registration.id,
        ceremonyToken: ceremonies.registration.token,
        expiresAt,
        options: { challenge: "Y2hhbGxlbmdl" },
      }),
      stepUpOptions: vi.fn().mockResolvedValue({
        ceremonyId: ceremonies.stepUp.id,
        ceremonyToken: ceremonies.stepUp.token,
        expiresAt,
        options: { challenge: "Y2hhbGxlbmdl", rpId: "localhost" },
      }),
      verifyAuthentication,
      verifyRegistration,
      verifyStepUp,
    });
    const originHeaders = { origin: "http://localhost:3000" };
    const [authenticationOptions, registrationOptions, stepUpOptions] = await Promise.all([
      app.inject({
        method: "POST",
        url: "/v1/auth/passkeys/authentication/options",
        headers: originHeaders,
        payload: { mediation: "optional" },
      }),
      app.inject({
        method: "POST",
        url: "/v1/auth/passkeys/registration/options",
        headers: originHeaders,
        payload: {},
      }),
      app.inject({
        method: "POST",
        url: "/v1/auth/passkeys/step-up/options",
        headers: originHeaders,
        payload: { purpose: "data_export", operationHash: "f".repeat(64) },
      }),
    ]);
    expect([authenticationOptions.statusCode, registrationOptions.statusCode, stepUpOptions.statusCode]).toEqual([201, 201, 201]);

    const cookiePairs = [authenticationOptions, registrationOptions, stepUpOptions].map(requiredSetCookiePair);
    const cookieNames = cookiePairs.map((cookiePair) => cookiePair.slice(0, cookiePair.indexOf("=")));
    expect(new Set(cookieNames).size).toBe(3);
    for (const response of [authenticationOptions, registrationOptions, stepUpOptions]) {
      const serialized = String(response.headers["set-cookie"]);
      expect(serialized).toContain("HttpOnly");
      expect(serialized).toContain("SameSite=Strict");
      expect(serialized).toContain("Path=/v1/auth/passkeys");
      for (const { token } of Object.values(ceremonies)) expect(serialized).not.toContain(token);
    }
    const cookieHeader = cookiePairs.join("; ");
    const authenticationResponse = authenticationCredentialResponse();
    const [authenticationVerify, registrationVerify, stepUpVerify] = await Promise.all([
      app.inject({
        method: "POST",
        url: "/v1/auth/passkeys/authentication/verify",
        headers: { ...originHeaders, cookie: cookieHeader },
        payload: { ceremonyId: ceremonies.authentication.id, response: authenticationResponse },
      }),
      app.inject({
        method: "POST",
        url: "/v1/auth/passkeys/registration/verify",
        headers: { ...originHeaders, cookie: cookieHeader },
        payload: {
          ceremonyId: ceremonies.registration.id,
          response: registrationCredentialResponse(),
          name: "Laptop",
        },
      }),
      app.inject({
        method: "POST",
        url: "/v1/auth/passkeys/step-up/verify",
        headers: { ...originHeaders, cookie: cookieHeader },
        payload: { ceremonyId: ceremonies.stepUp.id, response: authenticationResponse },
      }),
    ]);
    expect([authenticationVerify.statusCode, registrationVerify.statusCode, stepUpVerify.statusCode]).toEqual([200, 201, 200]);
    expect(verifyAuthentication).toHaveBeenCalledWith(expect.objectContaining({
      ceremonyId: ceremonies.authentication.id,
      ceremonyToken: ceremonies.authentication.token,
    }));
    expect(verifyRegistration).toHaveBeenCalledWith(expect.objectContaining({
      ceremonyId: ceremonies.registration.id,
      ceremonyToken: ceremonies.registration.token,
    }));
    expect(verifyStepUp).toHaveBeenCalledWith(expect.objectContaining({
      ceremonyId: ceremonies.stepUp.id,
      ceremonyToken: ceremonies.stepUp.token,
    }));
    expect(String(authenticationVerify.headers["set-cookie"])).toContain(`${cookieNames[0]}=;`);
    expect(String(registrationVerify.headers["set-cookie"])).toContain(`${cookieNames[1]}=;`);
    expect(String(stepUpVerify.headers["set-cookie"])).toContain(`${cookieNames[2]}=;`);
  });
});

async function fixtureApp(
  passkeys: readonly unknown[],
  sessions: readonly unknown[],
  serviceOverrides: Record<string, unknown> = {},
  sessionManagementOnly = false,
  bindingOptions: { getOwnSessionLabels?: ReturnType<typeof vi.fn>; tenantKind?: "real" | "demo" } = {},
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  await app.register(cookie);
  const principal = principalFixture();
  if (bindingOptions.tenantKind) Object.assign(principal, { tenantKind: bindingOptions.tenantKind });
  if (sessionManagementOnly) Object.assign(principal, { authMethod: "federated", assuranceLevel: "password", aal: 1 });
  app.decorate("apiConfig", {
    environment: "test",
    host: "127.0.0.1",
    port: 0,
    corsOrigins: new Set(["http://localhost:3000"]),
    secureCookies: false,
    sessionTtlSeconds: 3_600,
    authEncryptionKey: Buffer.alloc(32, 7),
    webauthn: {
      rpName: "Nombramientos",
      rpId: "localhost",
      expectedOrigins: ["http://localhost:3000"],
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    },
    controlDatabaseUrl: "postgresql://unused:unused@127.0.0.1:55432/unused",
    secretMasterKey: Buffer.alloc(32, 8),
    secretFile: "unused",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  } satisfies ApiConfig);
  app.decorate("database", {
    withDeviceSessionPrincipal: vi.fn(async (_principal: RequestPrincipal, _requestId: string,
      work: (store: DeviceSessionStore) => Promise<unknown>) => work({
        getOwnSessionLabels: bindingOptions.getOwnSessionLabels ?? vi.fn().mockResolvedValue(new Map()),
      } as unknown as DeviceSessionStore)),
    enterpriseAuth: {
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
        enforcementMode: "monitor",
        privilegedMinimumAal: 2,
        actionRequirements: {},
      }),
      consumeStepUpGrant: vi.fn().mockResolvedValue(true),
    },
  } as unknown as DatabaseRuntime);
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = principal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", () => async () => undefined);
  app.decorate("enterpriseAuthService", {
    listPasskeys: vi.fn().mockResolvedValue(passkeys),
    listSessions: vi.fn().mockResolvedValue(sessions),
    ...serviceOverrides,
  } as unknown as EnterpriseAuthService);
  if (sessionManagementOnly) await registerSessionManagementRoutes(app);
  else await registerEnterpriseAuthRoutes(app);
  await app.ready();
  return app;
}

function principalFixture(): RequestPrincipal {
  return {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "fixture@example.invalid",
    displayName: "Fixture",
    tenantSlug: "fixture",
    tenantName: "Fixture tenant",
    tenantKind: "real",
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa",
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions: new Set(),
  };
}

function requiredSetCookiePair(response: {
  readonly headers: Readonly<Record<string, number | string | string[] | undefined>>;
}): string {
  const header = response.headers["set-cookie"];
  const first = Array.isArray(header) ? header[0] : typeof header === "string" ? header : undefined;
  if (!first) throw new Error("Expected a Set-Cookie header");
  const pair = first.split(";", 1)[0];
  if (!pair) throw new Error("Expected a cookie pair");
  return pair;
}

function canonicalToken(fill: number): string {
  return Buffer.alloc(32, fill).toString("base64url");
}

function authenticationCredentialResponse() {
  const credentialId = "Y3JlZGVudGlhbA";
  return {
    id: credentialId,
    rawId: credentialId,
    type: "public-key" as const,
    clientExtensionResults: {},
    response: {
      clientDataJSON: "e30",
      authenticatorData: "YXV0aA",
      signature: "c2ln",
      userHandle: "dXNlcg",
    },
  };
}

function registrationCredentialResponse() {
  const credentialId = "Y3JlZGVudGlhbA";
  return {
    id: credentialId,
    rawId: credentialId,
    type: "public-key" as const,
    clientExtensionResults: {},
    response: {
      clientDataJSON: "e30",
      attestationObject: "YXR0ZXN0YXRpb24",
    },
  };
}
