import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { registerSecurity } from "../src/security.js";

describe("recovery-limited route boundary", () => {
  it("allows read-only passkey inventory for atomic replacement but keeps mutation routes blocked", async () => {
    const app = Fastify({ logger: false });
    const principal = recoveryPrincipal();
    const database = {
      getPrincipal: vi.fn().mockResolvedValue(principal),
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy()),
        listCredentials: vi.fn().mockResolvedValue([{ revokedAt: null, userVerified: true, deviceType: "singleDevice" }]),
      },
    } as unknown as DatabaseRuntime;
    app.decorate("apiConfig", config());
    app.decorate("database", database);
    await registerSecurity(app);
    app.get("/v1/auth/passkeys", { preHandler: [app.authenticate] }, async () => ({ ok: true }));
    app.patch("/v1/auth/passkeys/:id", { preHandler: [app.authenticate] }, async () => ({ ok: true }));

    const headers = { cookie: "nom_session=recovery-session-token" };
    const inventory = await app.inject({ method: "GET", url: "/v1/auth/passkeys", headers });
    expect(inventory.statusCode, inventory.body).toBe(200);

    const mutation = await app.inject({
      method: "PATCH",
      url: "/v1/auth/passkeys/40000000-0000-4000-8000-000000000001",
      headers,
      payload: { name: "Changed" },
    });
    expect(mutation.statusCode).toBe(403);
    expect(mutation.json<{ code: string }>().code).toBe("RECOVERY_RESTRICTED");
    await app.close();
  });
});

function recoveryPrincipal(): RequestPrincipal {
  return {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "recovery@example.invalid",
    displayName: "Recovery user",
    tenantSlug: "fixture",
    tenantName: "Fixture",
    tenantKind: "real",
    tenantTimezone: "America/La_Paz",
    csrfHash: "unused",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "recovery_limited",
    authenticatedAt: new Date(),
    mfaVerifiedAt: null,
    mfaRequired: true,
    mfaEnabled: true,
    passkeyEnabled: true,
    strongAuthEnabled: true,
    authMethod: "recovery_code",
    aal: 1,
    phishingResistant: false,
    recoveryLimited: true,
    enrollmentOnly: true,
    permissions: new Set(),
  };
}

function policy() {
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

function config(): ApiConfig {
  return {
    environment: "test",
    host: "127.0.0.1",
    port: 0,
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
    controlDatabaseUrl: "postgresql://unused:unused@127.0.0.1:55432/unused",
    secretMasterKey: Buffer.alloc(32),
    secretFile: "unused",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
}
