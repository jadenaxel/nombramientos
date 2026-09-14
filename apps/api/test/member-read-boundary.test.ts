import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { createHash } from "node:crypto";
import type { DatabaseRuntime } from "@nombramientos/database";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import { registerTenantRoutes } from "../src/modules/tenant-routes.js";

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("AC-09 member.read privacy boundary", () => {
  it("returns only the public encrypted profile projection and denies administrative/report surfaces", async () => {
    const { app, listMembers } = await fixtureApp(["member.read"]);
    const members = await app.inject({ method: "GET", url: "/v1/members?limit=10" });
    expect(members.statusCode).toBe(200);
    const serialized = members.body;
    const member = members.json<{ data: { items: Array<Record<string, unknown>> } }>().data.items[0];
    expect(member).toHaveProperty("displayEnvelope");
    expect(member).not.toHaveProperty("contactEnvelope");
    expect(member).not.toHaveProperty("eligibilityEnvelope");
    expect(serialized).not.toContain("eligibilityEnvelope");
    expect(serialized).not.toContain("restrictedNoteEnvelope");
    expect(serialized).not.toContain("privateNote");
    expect(serialized).not.toContain("legacy-profile-ciphertext");
    expect(listMembers).toHaveBeenCalledWith(10, undefined, false, false, false);
    expect(members.headers["cache-control"]).toBe("private, no-store");

    const managed = await app.inject({ method: "GET", url: "/v1/members/manage?limit=10" });
    expect(managed.statusCode).toBe(403);
    const reports = await app.inject({ method: "GET", url: "/v1/reports" });
    expect(reports.statusCode).toBe(403);
    const exportAttempt = await app.inject({ method: "POST", url: "/v1/reports/generate", payload: {} });
    expect(exportAttempt.statusCode).toBe(403);
  });

  it("does not reveal the eligibility envelope through the management channel without private-note.read", async () => {
    const { app, listMembers } = await fixtureApp(["member.read", "member.manage"]);
    const response = await app.inject({ method: "GET", url: "/v1/members/manage?limit=10" });

    expect(response.statusCode).toBe(200);
    expect(response.json<{ data: { items: Array<Record<string, unknown>> } }>().data.items[0])
      .not.toHaveProperty("eligibilityEnvelope");
    expect(response.body).not.toContain("eligibilityEnvelope");
    expect(listMembers).toHaveBeenCalledWith(10, undefined, true, false, false);
  });

  it("projects the encrypted eligibility note only for a principal with private-note.read", async () => {
    const { app, listMembers } = await fixtureApp(["member.read", "private-note.read"]);
    const response = await app.inject({ method: "GET", url: "/v1/members?limit=10" });

    expect(response.statusCode).toBe(200);
    expect(response.json<{ data: { items: Array<Record<string, unknown>> } }>().data.items[0])
      .toHaveProperty("eligibilityEnvelope", eligibilityEnvelope);
    expect(listMembers).toHaveBeenCalledWith(10, undefined, false, true, false);
    expect(response.headers["cache-control"]).toBe("private, no-store");
  });

  it("does not let private-note.read bypass the member.read boundary", async () => {
    const { app, listMembers } = await fixtureApp(["private-note.read"]);
    const response = await app.inject({ method: "GET", url: "/v1/members?limit=10" });

    expect(response.statusCode).toBe(403);
    expect(listMembers).not.toHaveBeenCalled();
    expect(response.body).not.toContain("eligibilityEnvelope");
  });

  it("projects contact only with the independent contact permission", async () => {
    const { app, listMembers } = await fixtureApp(["member.read", "member.contact.read"]);
    const response = await app.inject({ method: "GET", url: "/v1/members?limit=10" });

    expect(response.statusCode).toBe(200);
    expect(response.json<{ data: { items: Array<Record<string, unknown>> } }>().data.items[0])
      .toHaveProperty("contactEnvelope", contactEnvelope);
    expect(listMembers).toHaveBeenCalledWith(10, undefined, false, false, true);
    expect(response.headers["cache-control"]).toBe("private, no-store");
  });

  it("allows identity-only creation without contact authority", async () => {
    const { app, createMember } = await fixtureApp(["member.manage", "member.eligibility.manage"]);
    const id = "40000000-0000-4000-8000-000000000002";
    const response = await app.inject({
      method: "POST",
      url: "/v1/members",
      headers: { "idempotency-key": "50000000-0000-4000-8000-000000000001" },
      payload: {
        id,
        eligible: true,
        displayEnvelope: envelopeFor(id, "member-display"),
        displayContentHash: envelopeHash(envelopeFor(id, "member-display")),
      },
    });

    expect(response.statusCode).toBe(201);
    expect(createMember).toHaveBeenCalledWith(expect.objectContaining({ memberId: id }));
    expect(createMember.mock.calls[0]?.[0]).not.toHaveProperty("contactEnvelope");
    expect(response.body).not.toContain("contactEnvelope");
  });

  it("requires contact-manage authority to create, remove, or replace contact", async () => {
    const permissions = ["member.manage", "member.eligibility.manage"];
    const { app, createMember } = await fixtureApp(permissions);
    const id = "40000000-0000-4000-8000-000000000003";
    const create = await app.inject({
      method: "POST",
      url: "/v1/members",
      headers: { "idempotency-key": "50000000-0000-4000-8000-000000000002" },
      payload: {
        id,
        eligible: true,
        displayEnvelope: envelopeFor(id, "member-display"),
        displayContentHash: `sha256:${"0".repeat(64)}`,
        contactEnvelope: envelopeFor(id, "member-contact"),
        contactContentHash: `sha256:${"1".repeat(64)}`,
      },
    });
    const remove = await app.inject({
      method: "PATCH",
      url: `/v1/members/${id}`,
      headers: { "idempotency-key": "50000000-0000-4000-8000-000000000003" },
      payload: { expectedVersion: 1, contactEnvelope: null },
    });

    expect(create.statusCode).toBe(403);
    expect(remove.statusCode).toBe(403);
    expect(createMember).not.toHaveBeenCalled();
  });
});

const eligibilityEnvelope = {
  algorithm: "AES-256-GCM",
  keyId: "tenant-key",
  nonce: "eligibility-nonce",
  ciphertext: "eligibility-ciphertext",
  aad: "eligibility-aad",
};
const contactEnvelope = {
  algorithm: "AES-256-GCM",
  keyId: "tenant-key",
  nonce: "contact-nonce",
  ciphertext: "contact-ciphertext",
  aad: "contact-aad",
};

async function fixtureApp(permissionList: readonly string[]): Promise<{
  app: FastifyInstance;
  listMembers: ReturnType<typeof vi.fn>;
  createMember: ReturnType<typeof vi.fn>;
}> {
  const app = Fastify({ logger: false });
  apps.push(app);
  const principal = {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "member-reader@invalid.example",
    displayName: "Member reader",
    tenantSlug: "member-reader",
    tenantName: "Member reader tenant",
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
    permissions: new Set(permissionList),
  };
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = principal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", (permission: string) => async (request: FastifyRequest) => {
    if (!request.principal?.permissions.has(permission)) {
      throw new ApiError(403, "PERMISSION_DENIED", `Missing required permission: ${permission}`);
    }
  });
  const listMembers = vi.fn(async (
    _limit: number,
    _cursor: string | undefined,
    _includeArchived: boolean,
    includeEligibilityEnvelope: boolean,
    includeContactEnvelope: boolean,
  ) => ({
      items: [{
        id: "40000000-0000-4000-8000-000000000001",
        shortId: "MEM-0001",
        displayEnvelope: { algorithm: "AES-256-GCM", keyId: "tenant-key", nonce: "opaque", ciphertext: "opaque", aad: "opaque" },
        profileMigrationRequired: false,
        ...(includeContactEnvelope ? { contactEnvelope } : {}),
        ...(includeEligibilityEnvelope ? { eligibilityEnvelope } : {}),
        eligible: true,
        archived: false,
        archivedAt: null,
        currentResponsibilities: 0,
        version: 1,
      }],
      total: 1,
      nextCursor: null,
    }));
  const createMember = vi.fn(async (input: Record<string, unknown>) => ({
    id: input["memberId"],
    shortId: input["stableCode"],
    displayEnvelope: input["displayEnvelope"],
    profileMigrationRequired: false,
    eligible: input["eligibilityStatus"] === "eligible" && input["available"] === true,
    version: 1,
  }));
  const tenant = {
    listMembers,
    createMember,
    getKeyGrant: vi.fn(async () => ({ tenantKeyId: "tenant-key-v1" })),
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
  return { app, listMembers, createMember };
}

function envelopeFor(memberId: string, purpose: "member-display" | "member-contact") {
  return {
    algorithm: "AES-256-GCM" as const,
    keyId: "tenant-key-v1",
    nonce: Buffer.alloc(12).toString("base64url"),
    ciphertext: Buffer.alloc(32).toString("base64url"),
    aad: Buffer.from(JSON.stringify({
      tenantId: "30000000-0000-4000-8000-000000000001",
      memberId,
      purpose,
      schemaVersion: 1,
    })).toString("base64url"),
  };
}

function envelopeHash(envelope: ReturnType<typeof envelopeFor>): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(envelope), "utf8").digest("hex")}`;
}
