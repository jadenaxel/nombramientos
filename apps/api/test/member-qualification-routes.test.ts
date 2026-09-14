import { createHash, randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { MemberQualificationStoreError, type DatabaseRuntime } from "@nombramientos/database";
import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import { memberQualificationAadContext } from "../src/modules/member-qualification-contract.js";
import { registerMemberQualificationRoutes } from "../src/modules/member-qualification-routes.js";

const tenantId = "11111111-1111-4111-8111-111111111111";
const identityId = "22222222-2222-4222-8222-222222222222";
const sessionId = "33333333-3333-4333-8333-333333333333";
const memberId = "44444444-4444-4444-8444-444444444444";
const qualificationId = "55555555-5555-4555-8555-555555555555";
const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("member qualification routes", () => {
  it("reads only with the atomic permission and private no-store headers", async () => {
    const list = { memberId, eligibilityInference: false as const, items: [] };
    const app = await fixtureApp({
      permissions: ["member.qualification.read"],
      listForMember: async (actual) => {
        expect(actual).toBe(memberId);
        return list;
      },
    });
    const response = await app.inject({ method: "GET", url: `/v1/members/${memberId}/qualifications` });
    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("private, no-store, max-age=0");
    expect(response.headers["pragma"]).toBe("no-cache");
    expect(response.headers["vary"]).toBe("Cookie");
    expect(response.json()).toMatchObject({ data: list });

    const denied = await fixtureApp({ permissions: [] });
    expect((await denied.inject({ method: "GET", url: `/v1/members/${memberId}/qualifications` })).statusCode)
      .toBe(403);
  });

  it("creates with recent MFA and exact AAD while the transactional store enforces the current lifecycle grant", async () => {
    let stored: Record<string, unknown> | undefined;
    const body = qualificationFixture({ version: 1 });
    const app = await fixtureApp({
      permissions: ["member.qualification.manage"],
      create: async (input) => {
        stored = input;
        return metadata(1);
      },
    });
    const missingKey = await app.inject({
      method: "POST", url: `/v1/members/${memberId}/qualifications`, payload: body,
    });
    expect(missingKey.statusCode).toBe(400);
    expect(missingKey.json().error.code).toBe("IDEMPOTENCY_KEY_REQUIRED");

    const response = await app.inject({
      method: "POST",
      url: `/v1/members/${memberId}/qualifications`,
      headers: { "idempotency-key": randomUUID() },
      payload: body,
    });
    expect(response.statusCode).toBe(201);
    expect(stored).toMatchObject({
      identityId,
      memberId,
      qualificationId,
      type: "ordination",
      status: "verified",
      effectiveOn: "2026-09-12",
      expiresOn: null,
    });
    expect(JSON.stringify(stored)).not.toContain("Elder ordination");
  });

  it("appends a revision with optimistic version and rejects stale MFA or mismatched AAD", async () => {
    let revised: Record<string, unknown> | undefined;
    const app = await fixtureApp({
      permissions: ["member.qualification.manage"],
      revise: async (input) => {
        revised = input;
        return metadata(2);
      },
    });
    const body = { ...qualificationFixture({ version: 2 }), expectedVersion: 1 };
    delete (body as { qualificationId?: string }).qualificationId;
    const response = await app.inject({
      method: "POST",
      url: `/v1/members/${memberId}/qualifications/${qualificationId}/revisions`,
      headers: { "idempotency-key": randomUUID() },
      payload: body,
    });
    expect(response.statusCode).toBe(201);
    expect(revised).toMatchObject({ qualificationId, expectedVersion: 1 });
    expect(revised).not.toHaveProperty("version");

    const wrong = qualificationFixture({ version: 1, aadTenantId: randomUUID() });
    const mismatch = await app.inject({
      method: "POST",
      url: `/v1/members/${memberId}/qualifications`,
      headers: { "idempotency-key": randomUUID() },
      payload: wrong,
    });
    expect(mismatch.statusCode).toBe(409);
    expect(mismatch.json().error.code).toBe("ENVELOPE_CONTEXT_MISMATCH");

    const stale = await fixtureApp({ permissions: ["member.qualification.manage"], staleMfa: true });
    const staleResponse = await stale.inject({
      method: "POST",
      url: `/v1/members/${memberId}/qualifications`,
      headers: { "idempotency-key": randomUUID() },
      payload: qualificationFixture({ version: 1 }),
    });
    expect(staleResponse.statusCode).toBe(428);
    expect(staleResponse.json().error.code).toBe("MFA_STEP_UP_REQUIRED");
  });

  it("maps unknown and foreign identifiers to the same neutral store error", async () => {
    const app = await fixtureApp({
      permissions: ["member.qualification.read"],
      listForMember: async () => {
        throw new MemberQualificationStoreError(
          404,
          "MEMBER_QUALIFICATION_NOT_FOUND",
          "Member qualification record was not found",
        );
      },
    });
    const response = await app.inject({ method: "GET", url: `/v1/members/${memberId}/qualifications` });
    expect(response.statusCode).toBe(404);
    expect(response.json().error).toEqual({
      code: "MEMBER_QUALIFICATION_NOT_FOUND",
      message: "Member qualification record was not found",
    });
  });

  it("maps atomic lifecycle grant and envelope-key conflicts without a legacy grant lookup", async () => {
    for (const error of [
      new MemberQualificationStoreError(409, "KEY_GRANT_REQUIRED", "An active tenant key grant is required"),
      new MemberQualificationStoreError(409, "ENVELOPE_KEY_MISMATCH", "Envelope does not use the current tenant key"),
    ]) {
      const app = await fixtureApp({
        permissions: ["member.qualification.manage"],
        create: async () => { throw error; },
      });
      const response = await app.inject({
        method: "POST",
        url: `/v1/members/${memberId}/qualifications`,
        headers: { "idempotency-key": randomUUID() },
        payload: qualificationFixture({ version: 1 }),
      });
      expect(response.statusCode).toBe(409);
      expect(response.json().error).toMatchObject({ code: error.code, message: error.message });
    }
  });
});

type FixtureOptions = {
  readonly permissions: readonly string[];
  readonly staleMfa?: boolean;
  readonly listForMember?: (memberId: string) => Promise<unknown>;
  readonly create?: (input: Record<string, unknown>) => Promise<unknown>;
  readonly revise?: (input: Record<string, unknown>) => Promise<unknown>;
};

async function fixtureApp(options: FixtureOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  const principal = {
    sessionId,
    identityId,
    activeTenantId: tenantId,
    email: "qualification-test@invalid.example",
    displayName: "Qualification test",
    tenantSlug: "qualification-test",
    tenantName: "Qualification test",
    tenantKind: "demo" as const,
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa" as const,
    authenticatedAt: new Date(),
    mfaVerifiedAt: options.staleMfa ? new Date(Date.now() - 10 * 60_000) : new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions: new Set(options.permissions),
  };
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = principal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", (permission: string) => async (request: FastifyRequest) => {
    if (!request.principal?.permissions.has(permission)) {
      throw new ApiError(403, "PERMISSION_DENIED", `Missing required permission: ${permission}`);
    }
  });
  const store = {
    listForMember: options.listForMember ?? (async () => ({ memberId, eligibilityInference: false, items: [] })),
    create: options.create ?? (async () => metadata(1)),
    revise: options.revise ?? (async () => metadata(2)),
  };
  const database = {
    withPrincipal: async () => {
      throw new Error("member qualification routes must not consult the legacy key-grant store");
    },
    withMemberQualificationPrincipal: async <T>(
      _principal: unknown,
      _requestId: string,
      work: (qualificationStore: unknown) => Promise<T>,
    ) => work(store),
  } as unknown as DatabaseRuntime;
  app.decorate("database", database);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message }, meta: { requestId: request.id },
      });
    }
    throw error;
  });
  await registerMemberQualificationRoutes(app);
  await app.ready();
  return app;
}

function qualificationFixture(input: { readonly version: number; readonly aadTenantId?: string }) {
  const aad = memberQualificationAadContext({
    tenantId: input.aadTenantId ?? tenantId,
    memberId,
    qualificationId,
    version: input.version,
    type: "ordination",
    status: "verified",
    effectiveOn: "2026-09-12",
    expiresOn: null,
  });
  const envelope = {
    algorithm: "AES-256-GCM" as const,
    keyId: "tenant-qualification-key-v1",
    nonce: Buffer.alloc(12).toString("base64url"),
    ciphertext: Buffer.alloc(48).toString("base64url"),
    aad: Buffer.from(JSON.stringify(aad)).toString("base64url"),
  };
  return {
    qualificationId,
    type: "ordination" as const,
    status: "verified" as const,
    effectiveOn: "2026-09-12",
    expiresOn: null,
    detailsEnvelope: envelope,
    detailsContentHash: `sha256:${createHash("sha256").update(JSON.stringify(envelope)).digest("hex")}`,
  };
}

function metadata(version: number) {
  return {
    qualificationId,
    memberId,
    version,
    type: "ordination" as const,
    status: "verified" as const,
    effectiveOn: "2026-09-12",
    expiresOn: null,
    hasDetails: true,
    reviewerIdentityId: identityId,
    recordedAt: new Date(0).toISOString(),
  };
}
