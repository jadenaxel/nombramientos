import cookie from "@fastify/cookie";
import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { unauthorized } from "../src/lib/errors.js";
import { registerAuthRoutes } from "../src/modules/auth-routes.js";
import { AuthService } from "../src/modules/auth-service.js";

describe("authoritative session observation time", () => {
  it.each(["2100-01-01T00:00:00.000Z", "1970-01-01T00:00:00.000Z", "not-a-date"])(
    "ignores client clock hints %s and keeps the stored expiry unchanged",
    async (clockHint) => {
      const principal = fixturePrincipal();
      const { app, publicSession } = await fixture(principal);
      try {
        const absoluteExpiry = principal.expiresAt.toISOString();
        const idleExpiry = principal.idleExpiresAt!.toISOString();
        const before = Date.now();
        const response = await app.inject({ method: "GET",
          url: `/v1/session?serverTime=${encodeURIComponent(clockHint)}&expiresAt=2100-01-01&sessionId=90000000-0000-4000-8000-000000000099`,
          headers: { cookie: "nom_csrf=fixture-csrf", "x-client-time": clockHint, "x-session-id": "90000000-0000-4000-8000-000000000099" } });
        const after = Date.now();
        expect(response.statusCode, response.body).toBe(200);
        const data = response.json<{ data: { sessionId: string; serverTime: string; expiresAt: string; security: { idleExpiresAt: string } } }>().data;
        expect(data.sessionId).toBe(principal.sessionId);
        expect(data.sessionId).toMatch(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u);
        expect(data.serverTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u);
        expect(Date.parse(data.serverTime)).toBeGreaterThanOrEqual(before);
        expect(Date.parse(data.serverTime)).toBeLessThanOrEqual(after);
        expect(data.expiresAt).toBe(absoluteExpiry);
        expect(data.security.idleExpiresAt).toBe(idleExpiry);
        expect(principal.expiresAt.toISOString()).toBe(absoluteExpiry);
        expect(principal.idleExpiresAt!.toISOString()).toBe(idleExpiry);
        expect(publicSession).toHaveBeenCalledExactlyOnceWith(principal, "fixture-csrf", null, 0);
        expect(response.headers["cache-control"]).toBe("no-store");
      } finally { await app.close(); }
    },
  );

  it("does not revive an expired session or invoke the snapshot service", async () => {
    const principal = { ...fixturePrincipal(), expiresAt: new Date(Date.now()-1000) };
    const { app, publicSession } = await fixture(principal);
    try {
      const response = await app.inject({ method: "GET", url: "/v1/session?serverTime=1970-01-01",
        headers: { cookie: "nom_csrf=fixture-csrf" } });
      expect(response.statusCode).toBe(401);
      expect(publicSession).not.toHaveBeenCalled();
      expect(response.body).not.toContain("serverTime");
      expect(response.body).not.toContain(principal.sessionId);
    } finally { await app.close(); }
  });
});

async function fixture(principal: RequestPrincipal) {
  const app = Fastify({ logger: false });
  await app.register(cookie);
  app.decorate("apiConfig", { gestionChurchIntegration: { enabled: true } } as ApiConfig);
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: Parameters<typeof app.authenticate>[0]) => {
    // This route test observes the authenticator boundary, not a substitute
    // for the independently tested database/source-session expiry checks.
    if (principal.expiresAt.getTime() <= Date.now()) throw unauthorized();
    request.principal = principal;
  });
  app.decorate("verifyCsrf", async () => undefined);
  const getKeyGrant = vi.fn().mockResolvedValue(null);
  const listCredentials = vi.fn().mockResolvedValue([]);
  app.decorate("database", {
    withPrincipal: vi.fn(async (_principal, _requestId, work: (store: { getKeyGrant: typeof getKeyGrant }) => Promise<unknown>) => work({ getKeyGrant })),
    enterpriseAuth: { listCredentials },
  } as unknown as DatabaseRuntime);
  const publicSession = vi.fn(AuthService.prototype.publicSession.bind({} as AuthService));
  app.decorate("authService", { publicSession } as unknown as AuthService);
  await registerAuthRoutes(app);
  return { app, publicSession };
}

function fixturePrincipal(): RequestPrincipal {
  return { sessionId: "10000000-0000-4000-8000-000000000001", identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001", email: "fixture@example.invalid", displayName: "Fixture",
    tenantSlug: "fixture", tenantName: "Fixture", tenantKind: "demo", tenantTimezone: "America/La_Paz", csrfHash: "fixture",
    expiresAt: new Date(Date.now()+60_000), idleExpiresAt: new Date(Date.now()+30_000),
    assuranceLevel: "password", authenticatedAt: new Date(), mfaVerifiedAt: null, mfaRequired: false, mfaEnabled: false,
    enrollmentOnly: false, permissions: new Set() };
}
