import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import type { DatabaseRuntime } from "@nombramientos/database";
import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import { organizationQuerySchema } from "../src/modules/tenant-routes.js";
import { registerTenantRoutes } from "../src/modules/tenant-routes.js";

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("organization route contract", () => {
  it("defaults to the elected view and accepts only a UUID cycle plus a known stage", () => {
    expect(organizationQuerySchema.parse({})).toEqual({ stage: "elected" });
    expect(organizationQuerySchema.parse({ stage: "proposal" })).toEqual({ stage: "proposal" });
    expect(organizationQuerySchema.safeParse({ cycleId: "not-a-cycle" }).success).toBe(false);
    expect(organizationQuerySchema.safeParse({ stage: "current" }).success).toBe(false);
    expect(organizationQuerySchema.safeParse({ stage: "elected", includePrivate: "true" }).success).toBe(false);
  });

  it("keeps the route behind the dedicated organigram permission", () => {
    const testDirectory = path.dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(path.resolve(testDirectory, "../src/modules/tenant-routes.ts"), "utf8");
    expect(source).toContain('app.get("/v1/organization", { preHandler: protectedRead(app, "organigram.read") }');
    expect(source).toContain("tenant.getOrganization({");
  });

  it("enforces permission, strict query parsing, cycle availability, and no-store delivery", async () => {
    const calls: Array<{ cycleId?: string; stage: "proposal" | "elected" }> = [];
    const permissions = new Set<string>();
    const app = await fixtureApp(permissions, calls);
    const denied = await app.inject({ method: "GET", url: "/v1/organization?stage=elected" });
    expect(denied.statusCode).toBe(403);
    expect(calls).toHaveLength(0);

    permissions.add("organigram.read");
    const invalid = await app.inject({
      method: "GET",
      url: "/v1/organization?stage=elected&tenantId=90000000-0000-4000-8000-000000000001&private=true",
    });
    expect(invalid.statusCode).toBe(400);
    expect(invalid.json<{ error: { code: string } }>().error.code).toBe("VALIDATION_ERROR");

    const cycleId = "40000000-0000-4000-8000-000000000001";
    const valid = await app.inject({ method: "GET", url: `/v1/organization?cycleId=${cycleId}&stage=proposal` });
    expect(valid.statusCode).toBe(200);
    expect(valid.headers["cache-control"]).toBe("private, no-store");
    expect(calls).toEqual([{ cycleId, stage: "proposal" }]);

    const unavailableId = "50000000-0000-4000-8000-000000000001";
    const unavailable = await app.inject({ method: "GET", url: `/v1/organization?cycleId=${unavailableId}` });
    expect(unavailable.statusCode).toBe(404);
    expect(unavailable.json<{ error: { code: string } }>().error.code).toBe("CYCLE_UNAVAILABLE");
  });
});

async function fixtureApp(
  permissions: Set<string>,
  calls: Array<{ cycleId?: string; stage: "proposal" | "elected" }>,
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  const principal = {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "organigram-reader@invalid.example",
    displayName: "Organigram reader",
    tenantSlug: "organigram-reader",
    tenantName: "Organigram reader tenant",
    tenantKind: "real" as const,
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa" as const,
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions,
  };
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = principal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", (permission: string) => async (request: FastifyRequest) => {
    if (!request.principal?.permissions.has(permission)) {
      throw new ApiError(403, "PERMISSION_DENIED", `Missing required permission: ${permission}`);
    }
  });
  const tenant = {
    getOrganization: async (input: { cycleId?: string; stage: "proposal" | "elected" }) => {
      calls.push(input);
      if (input.cycleId?.startsWith("50000000")) {
        return { cycles: [], selectedCycle: null, cycleName: null, stage: input.stage, items: [] };
      }
      return {
        cycles: input.cycleId ? [{ id: input.cycleId, name: "Cycle", status: "active", termStart: "2028-01-01", termEnd: "2028-12-31" }] : [],
        selectedCycle: input.cycleId ? { id: input.cycleId, name: "Cycle", status: "active", termStart: "2028-01-01", termEnd: "2028-12-31" } : null,
        cycleName: input.cycleId ? "Cycle" : null,
        stage: input.stage,
        items: [],
      };
    },
  };
  app.decorate("database", {
    withPrincipal: async <T>(_principal: unknown, _requestId: string, work: (store: typeof tenant) => Promise<T>): Promise<T> => work(tenant),
  } as unknown as DatabaseRuntime);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({ error: { code: error.code, message: error.message }, meta: { requestId: request.id } });
    }
    return reply.status(500).send({ error: { code: "INTERNAL_ERROR", message: "Unexpected" }, meta: { requestId: request.id } });
  });
  await registerTenantRoutes(app);
  return app;
}
