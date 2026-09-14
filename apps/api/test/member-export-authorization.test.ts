import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { randomUUID } from "node:crypto";
import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import { registerTenantRoutes } from "../src/modules/tenant-routes.js";

const apps: FastifyInstance[] = [];
const identityId = "20000000-0000-4000-8000-000000000001";
const digest = `sha256:${"a".repeat(64)}` as const;

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("roster export authorization boundary", () => {
  it("passes only bounded opaque metadata into an audited tenant authorization", async () => {
    const authorizeMemberExport = vi.fn(async (input: Record<string, unknown>) => ({
      authorizationId: "40000000-0000-4000-8000-000000000001",
      format: input["format"],
      rowCount: input["rowCount"],
      includeContact: input["includeContact"],
      selectionSha256: input["selectionSha256"],
      authorizedAt: "2026-09-11T12:00:00.000Z",
      expiresAt: "2026-09-11T12:05:00.000Z",
    }));
    const app = await fixtureApp(principal(), authorizeMemberExport);
    const response = await app.inject({
      method: "POST",
      url: "/v1/members/export-authorizations",
      headers: { "idempotency-key": "50000000-0000-4000-8000-000000000001" },
      payload: {
        format: "xlsx",
        rowCount: 17,
        filters: { status: "active", queryApplied: true },
        selectionSha256: digest,
      },
    });

    expect(response.statusCode).toBe(201);
    expect(authorizeMemberExport).toHaveBeenCalledWith({
      identityId,
      idempotencyKey: "50000000-0000-4000-8000-000000000001",
      format: "xlsx",
      rowCount: 17,
      includeContact: false,
      filters: { status: "active", queryApplied: true },
      selectionSha256: digest,
    });
    expect(JSON.stringify(authorizeMemberExport.mock.calls)).not.toMatch(/name|email|plaintext/iu);
  });

  it("rejects a stale MFA proof before tenant storage is called", async () => {
    const authorizeMemberExport = vi.fn();
    const app = await fixtureApp(principal({ mfaVerifiedAt: new Date(Date.now() - 5 * 60_000) }), authorizeMemberExport);
    const response = await app.inject({
      method: "POST",
      url: "/v1/members/export-authorizations",
      headers: { "idempotency-key": randomUUID() },
      payload: { format: "csv", rowCount: 1, filters: { status: "all", queryApplied: false }, selectionSha256: digest },
    });

    expect(response.statusCode).toBe(428);
    expect(response.json<{ error: { code: string } }>().error.code).toBe("MFA_STEP_UP_REQUIRED");
    expect(authorizeMemberExport).not.toHaveBeenCalled();
  });

  it("requires the same fresh proof at broad report and tenant-configuration boundaries", async () => {
    const authorizeMemberExport = vi.fn();
    const app = await fixtureApp(principal({
      mfaVerifiedAt: new Date(Date.now() - 5 * 60_000),
      permissions: new Set(["report.export", "report.read", "tenant.settings.manage"]),
    }), authorizeMemberExport);
    const mutationHeaders = { "idempotency-key": randomUUID() };
    const attempts = [
      app.inject({ method: "PATCH", url: "/v1/tenant/settings", headers: mutationHeaders, payload: {} }),
      app.inject({ method: "POST", url: "/v1/reports/generate", headers: mutationHeaders, payload: {} }),
      app.inject({ method: "GET", url: "/v1/reports/40000000-0000-4000-8000-000000000001/artifact" }),
      app.inject({ method: "POST", url: "/v1/reports/40000000-0000-4000-8000-000000000001/print", headers: mutationHeaders, payload: {} }),
    ];

    for (const response of await Promise.all(attempts)) {
      expect(response.statusCode).toBe(428);
      expect(response.json<{ error: { code: string } }>().error.code).toBe("MFA_STEP_UP_REQUIRED");
    }
  });

  it("rejects clear or unrecognized fields instead of accepting export content", async () => {
    const authorizeMemberExport = vi.fn();
    const app = await fixtureApp(principal(), authorizeMemberExport);
    const response = await app.inject({
      method: "POST",
      url: "/v1/members/export-authorizations",
      headers: { "idempotency-key": randomUUID() },
      payload: {
        format: "csv",
        rowCount: 1,
        filters: { status: "all", queryApplied: false },
        selectionSha256: digest,
        displayName: "must never cross this boundary",
      },
    });

    expect(response.statusCode).toBe(400);
    expect(authorizeMemberExport).not.toHaveBeenCalled();
  });

  it("requires contact-read authority before authorizing contact columns", async () => {
    const authorizeMemberExport = vi.fn();
    const app = await fixtureApp(principal(), authorizeMemberExport);
    const response = await app.inject({
      method: "POST",
      url: "/v1/members/export-authorizations",
      headers: { "idempotency-key": randomUUID() },
      payload: { format: "csv", rowCount: 1, includeContact: true, filters: { status: "all", queryApplied: false }, selectionSha256: digest },
    });

    expect(response.statusCode).toBe(403);
    expect(authorizeMemberExport).not.toHaveBeenCalled();
  });
});

async function fixtureApp(
  currentPrincipal: RequestPrincipal,
  authorizeMemberExport: (input: Record<string, unknown>) => Promise<unknown>,
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = currentPrincipal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", (permission: string) => async (request: FastifyRequest) => {
    if (!request.principal?.permissions.has(permission)) throw new ApiError(403, "PERMISSION_DENIED", "Denied");
  });
  const tenant = { authorizeMemberExport };
  app.decorate("database", {
    enterpriseAuth: {
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
        enforcementMode: "monitor",
        privilegedMinimumAal: 2,
        requirePhishingResistantForPrivileged: true,
        actionRequirements: {},
      }),
    },
    withPrincipal: async <T>(_principal: unknown, _requestId: string, work: (store: typeof tenant) => Promise<T>): Promise<T> => work(tenant),
  } as unknown as DatabaseRuntime);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({ error: { code: error.code, message: error.message }, meta: { requestId: request.id } });
    }
    if (typeof error === "object" && error !== null && "name" in error && error.name === "ZodError") {
      return reply.status(400).send({ error: { code: "VALIDATION_ERROR", message: "Invalid" }, meta: { requestId: request.id } });
    }
    return reply.status(500).send({ error: { code: "INTERNAL_ERROR", message: "Unexpected" }, meta: { requestId: request.id } });
  });
  await registerTenantRoutes(app);
  return app;
}

function principal(overrides: Partial<RequestPrincipal> = {}): RequestPrincipal {
  return {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId,
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "exporter@example.invalid",
    displayName: "Exporter",
    tenantSlug: "fixture",
    tenantName: "Fixture",
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
    permissions: new Set(["report.export"]),
    ...overrides,
  };
}
