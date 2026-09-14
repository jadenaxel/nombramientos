import { createHash, randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { PhotoStoreError, type DatabaseRuntime } from "@nombramientos/database";
import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import { photoAadContext } from "../src/modules/photo-contract.js";
import { registerPhotoRoutes } from "../src/modules/photo-routes.js";

const tenantId = "11111111-1111-4111-8111-111111111111";
const identityId = "22222222-2222-4222-8222-222222222222";
const sessionId = "33333333-3333-4333-8333-333333333333";
const memberId = "44444444-4444-4444-8444-444444444444";
const photoId = "55555555-5555-4555-8555-555555555555";

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("member photo routes", () => {
  it("returns only the active tenant object's opaque envelope with private no-store headers", async () => {
    const photo = { ...photoMetadata(), envelope: uploadFixture().envelope };
    const app = await fixtureApp({
      permissions: ["member.read"],
      getPhoto: async (actualMemberId) => {
        expect(actualMemberId).toBe(memberId);
        return photo;
      },
    });
    const response = await app.inject({ method: "GET", url: `/v1/members/${memberId}/photo` });
    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("private, no-store, max-age=0");
    expect(response.headers["pragma"]).toBe("no-cache");
    expect(response.headers["vary"]).toBe("Cookie");
    expect(response.json()).toMatchObject({ data: photo });
  });

  it("returns only the bounded write precondition needed to recreate archived photo history", async () => {
    const app = await fixtureApp({
      permissions: ["member.photo.manage"],
      getPhotoWriteContext: async (actualMemberId) => {
        expect(actualMemberId).toBe(memberId);
        return { expectedVersion: 0, nextVersion: 3 };
      },
    });
    const response = await app.inject({ method: "GET", url: `/v1/members/${memberId}/photo/write-context` });
    expect(response.statusCode).toBe(200);
    expect(response.headers["cache-control"]).toBe("private, no-store, max-age=0");
    expect(response.json()).toMatchObject({ data: { expectedVersion: 0, nextVersion: 3 } });
  });

  it("maps a foreign and unknown object to the same neutral 404", async () => {
    const app = await fixtureApp({
      permissions: ["member.read"],
      getPhoto: async () => {
        throw new PhotoStoreError(404, "PHOTO_NOT_FOUND", "Photograph was not found");
      },
    });
    const foreign = await app.inject({ method: "GET", url: `/v1/members/${memberId}/photo` });
    const unknown = await app.inject({ method: "GET", url: `/v1/members/${randomUUID()}/photo` });
    expect(foreign.statusCode).toBe(404);
    expect(unknown.statusCode).toBe(404);
    expect(foreign.json().error).toEqual(unknown.json().error);
    expect(foreign.json().error).toEqual({ code: "PHOTO_NOT_FOUND", message: "Photograph was not found" });
  });

  it("requires photo management, CSRF/idempotency, a current tenant key and exact AAD", async () => {
    let stored: Record<string, unknown> | undefined;
    const valid = uploadFixture();
    const app = await fixtureApp({
      permissions: ["member.photo.manage"],
      putPhoto: async (input) => {
        stored = input;
        return photoMetadata();
      },
    });
    const missingIdempotency = await app.inject({
      method: "POST",
      url: `/v1/members/${memberId}/photo`,
      payload: valid,
    });
    expect(missingIdempotency.statusCode).toBe(400);
    expect(missingIdempotency.json().error.code).toBe("IDEMPOTENCY_KEY_REQUIRED");

    const response = await app.inject({
      method: "POST",
      url: `/v1/members/${memberId}/photo`,
      headers: { "idempotency-key": randomUUID() },
      payload: valid,
    });
    expect(response.statusCode).toBe(201);
    expect(stored).toMatchObject({
      memberId,
      photoId,
      expectedVersion: 0,
      version: 1,
      mediaType: "image/jpeg",
      width: 512,
      height: 512,
      plaintextBytes: 128,
    });

    const wrongTenantAad = uploadFixture({ tenantId: "11111111-1111-4111-8111-111111111112" });
    const rejected = await app.inject({
      method: "POST",
      url: `/v1/members/${memberId}/photo`,
      headers: { "idempotency-key": randomUUID() },
      payload: wrongTenantAad,
    });
    expect(rejected.statusCode).toBe(409);
    expect(rejected.json().error.code).toBe("ENVELOPE_CONTEXT_MISMATCH");

    const noPermission = await fixtureApp({ permissions: [] });
    const forbidden = await noPermission.inject({
      method: "POST",
      url: `/v1/members/${memberId}/photo`,
      headers: { "idempotency-key": randomUUID() },
      payload: valid,
    });
    expect(forbidden.statusCode).toBe(403);
    expect(forbidden.json().error.code).toBe("PERMISSION_DENIED");
  });

  it("rejects clear original metadata and archives with an optimistic version", async () => {
    let archiveInput: Record<string, unknown> | undefined;
    const app = await fixtureApp({
      permissions: ["member.photo.manage"],
      archivePhoto: async (input) => {
        archiveInput = input;
        return { ...photoMetadata(), archivedAt: new Date(0).toISOString() };
      },
    });
    const leaked = await app.inject({
      method: "POST",
      url: `/v1/members/${memberId}/photo`,
      headers: { "idempotency-key": randomUUID() },
      payload: { ...uploadFixture(), originalFilename: "private-person.jpg", exif: { GPSLatitude: 18.4 } },
    });
    expect(leaked.statusCode).toBe(400);
    expect(leaked.json().error.code).toBe("VALIDATION_ERROR");

    const archived = await app.inject({
      method: "POST",
      url: `/v1/members/${memberId}/photo/archive`,
      headers: { "idempotency-key": randomUUID() },
      payload: { expectedVersion: 1 },
    });
    expect(archived.statusCode).toBe(200);
    expect(archiveInput).toMatchObject({ identityId, memberId, expectedVersion: 1 });
  });
});

type FixtureOptions = {
  readonly permissions: readonly string[];
  readonly getPhoto?: (memberId: string) => Promise<unknown>;
  readonly getPhotoWriteContext?: (memberId: string) => Promise<unknown>;
  readonly putPhoto?: (input: Record<string, unknown>) => Promise<unknown>;
  readonly archivePhoto?: (input: Record<string, unknown>) => Promise<unknown>;
};

async function fixtureApp(options: FixtureOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  const principal = {
    sessionId,
    identityId,
    activeTenantId: tenantId,
    email: "photo-test@invalid.example",
    displayName: "Photo test",
    tenantSlug: "photo-test",
    tenantName: "Photo test",
    tenantKind: "demo" as const,
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa" as const,
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(),
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
  const database = {
    withPrincipal: async <T>(_principal: unknown, _requestId: string, work: (store: unknown) => Promise<T>): Promise<T> =>
      work({ getKeyGrant: async () => ({ tenantKeyId: "tenant-photo-key-v1" }) }),
    withPhotoPrincipal: async <T>(_principal: unknown, _requestId: string, work: (store: unknown) => Promise<T>): Promise<T> =>
      work({
        getActivePhoto: options.getPhoto ?? (async () => { throw new PhotoStoreError(404, "PHOTO_NOT_FOUND", "Photograph was not found"); }),
        getPhotoWriteContext: options.getPhotoWriteContext ?? (async () => ({ expectedVersion: 0, nextVersion: 1 })),
        putPhoto: options.putPhoto ?? (async () => photoMetadata()),
        archivePhoto: options.archivePhoto ?? (async () => photoMetadata()),
      }),
  } as unknown as DatabaseRuntime;
  app.decorate("database", database);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message },
        meta: { requestId: request.id },
      });
    }
    throw error;
  });
  await registerPhotoRoutes(app);
  await app.ready();
  return app;
}

function uploadFixture(overrides: { readonly tenantId?: string } = {}) {
  const aad = photoAadContext({
    tenantId: overrides.tenantId ?? tenantId,
    memberId,
    photoId,
    version: 1,
    mediaType: "image/jpeg",
    width: 512,
    height: 512,
    plaintextBytes: 128,
  });
  const envelope = {
    algorithm: "AES-256-GCM" as const,
    keyId: "tenant-photo-key-v1",
    nonce: Buffer.alloc(12).toString("base64url"),
    ciphertext: Buffer.alloc(144).toString("base64url"),
    aad: Buffer.from(JSON.stringify(aad)).toString("base64url"),
  };
  return {
    photoId,
    expectedVersion: 0,
    version: 1,
    mediaType: "image/jpeg" as const,
    width: 512,
    height: 512,
    plaintextBytes: 128,
    envelope,
    contentHash: `sha256:${createHash("sha256").update(JSON.stringify(envelope)).digest("hex")}`,
  };
}

function photoMetadata() {
  return {
    id: photoId,
    memberId,
    version: 1,
    mediaType: "image/jpeg" as const,
    width: 512,
    height: 512,
    plaintextBytes: 128,
    contentHash: `sha256:${"a".repeat(64)}`,
    createdAt: new Date(0).toISOString(),
    archivedAt: null,
  };
}
