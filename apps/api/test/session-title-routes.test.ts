import { createHash, randomUUID } from "node:crypto";
import type { DatabaseRuntime } from "@nombramientos/database";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import { registerCoreWorkflowRoutes } from "../src/modules/core-workflow-routes.js";

const tenantId = "11111111-1111-4111-8111-111111111111";
const identityId = "22222222-2222-4222-8222-222222222222";
const authSessionId = "33333333-3333-4333-8333-333333333333";
const cycleId = "44444444-4444-4444-8444-444444444444";
const workflowSessionId = "55555555-5555-4555-8555-555555555555";
const agendaItemId = "66666666-6666-4666-8666-666666666666";
const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("session title E2EE route boundary", () => {
  it("accepts only the exact create AAD and forwards no plaintext title", async () => {
    let stored: Record<string, unknown> | undefined;
    const app = await fixtureApp({
      addSession: async (input) => {
        stored = input;
        return { id: workflowSessionId };
      },
    });
    const payload = sessionCreateFixture();
    const accepted = await app.inject({
      method: "POST",
      url: `/v1/cycles/${cycleId}/sessions`,
      headers: { "idempotency-key": randomUUID() },
      payload,
    });
    expect(accepted.statusCode).toBe(201);
    expect(stored).toMatchObject({
      cycleId,
      sessionId: workflowSessionId,
      expectedCycleVersion: 1,
      sequence: 1,
      titleEnvelope: payload.titleEnvelope,
    });
    expect(stored).not.toHaveProperty("title");
    expect(stored).not.toHaveProperty("titleContentHash");

    const replay = sessionCreateFixture({
      cycleId: "77777777-7777-4777-8777-777777777777",
    });
    const rejected = await app.inject({
      method: "POST",
      url: `/v1/cycles/${cycleId}/sessions`,
      headers: { "idempotency-key": randomUUID() },
      payload: replay,
    });
    expect(rejected.statusCode).toBe(409);
    expect(rejected.json().error.code).toBe("ENVELOPE_CONTEXT_MISMATCH");

    const withExtraAadField = sessionCreateFixture({}, { unexpected: "private-label" });
    const extraRejected = await app.inject({
      method: "POST",
      url: `/v1/cycles/${cycleId}/sessions`,
      headers: { "idempotency-key": randomUUID() },
      payload: withExtraAadField,
    });
    expect(extraRejected.statusCode).toBe(409);
    expect(extraRejected.json().error.code).toBe("ENVELOPE_CONTEXT_MISMATCH");
  });

  it("validates the complete-envelope hash before persistence", async () => {
    let calls = 0;
    const app = await fixtureApp({ addSession: async () => { calls += 1; return {}; } });
    const payload = sessionCreateFixture();
    const rejected = await app.inject({
      method: "POST",
      url: `/v1/cycles/${cycleId}/sessions`,
      headers: { "idempotency-key": randomUUID() },
      payload: { ...payload, titleContentHash: `sha256:${"0".repeat(64)}` },
    });
    expect(rejected.statusCode).toBe(400);
    expect(rejected.json().error.code).toBe("CONTENT_HASH_MISMATCH");
    expect(calls).toBe(0);
  });

  it("binds title replacement to the independent next title version", async () => {
    let updated: Record<string, unknown> | undefined;
    const app = await fixtureApp({
      getSession: async () => ({ cycleId, sequence: 1, titleVersion: 4 }),
      updateSession: async (input) => {
        updated = input;
        return { id: workflowSessionId, titleVersion: 5 };
      },
    });
    const valid = updateFixture(5);
    const accepted = await app.inject({
      method: "PATCH",
      url: `/v1/sessions/${workflowSessionId}`,
      headers: { "idempotency-key": randomUUID() },
      payload: valid,
    });
    expect(accepted.statusCode).toBe(200);
    expect(updated).toMatchObject({ expectedVersion: 27, titleEnvelope: valid.titleEnvelope });
    expect(updated).not.toHaveProperty("title");

    const replay = updateFixture(4);
    const rejected = await app.inject({
      method: "PATCH",
      url: `/v1/sessions/${workflowSessionId}`,
      headers: { "idempotency-key": randomUUID() },
      payload: replay,
    });
    expect(rejected.statusCode).toBe(409);
    expect(rejected.json().error.code).toBe("ENVELOPE_CONTEXT_MISMATCH");
  });

  it("requires a client agenda id and exact agenda-title AAD", async () => {
    let stored: Record<string, unknown> | undefined;
    const app = await fixtureApp({
      addSessionAgendaItem: async (input) => {
        stored = input;
        return { id: agendaItemId };
      },
    });
    const payload = agendaFixture();
    const accepted = await app.inject({
      method: "POST",
      url: `/v1/sessions/${workflowSessionId}/agenda`,
      headers: { "idempotency-key": randomUUID() },
      payload,
    });
    expect(accepted.statusCode).toBe(201);
    expect(stored).toMatchObject({
      sessionId: workflowSessionId,
      itemId: agendaItemId,
      titleEnvelope: payload.titleEnvelope,
    });
    expect(stored).not.toHaveProperty("title");

    const missingId = await app.inject({
      method: "POST",
      url: `/v1/sessions/${workflowSessionId}/agenda`,
      headers: { "idempotency-key": randomUUID() },
      payload: { ...payload, itemId: undefined },
    });
    expect(missingId.statusCode).toBe(400);
    expect(missingId.json().error.code).toBe("VALIDATION_ERROR");
  });
});

type WorkflowMethods = {
  readonly addSession?: (input: Record<string, unknown>) => Promise<unknown>;
  readonly getSession?: (sessionId: string) => Promise<Record<string, unknown> | null>;
  readonly updateSession?: (input: Record<string, unknown>) => Promise<unknown>;
  readonly addSessionAgendaItem?: (input: Record<string, unknown>) => Promise<unknown>;
};

async function fixtureApp(methods: WorkflowMethods): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  const principal = {
    sessionId: authSessionId,
    identityId,
    activeTenantId: tenantId,
    email: "session-title-test@invalid.example",
    displayName: "Session title test",
    tenantSlug: "session-title-test",
    tenantName: "Session title test",
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
    permissions: new Set(["cycle.manage"]),
  };
  const workflow = {
    addSession: methods.addSession ?? (async () => ({})),
    getSession: methods.getSession ?? (async () => ({ cycleId, sequence: 1, titleVersion: 1 })),
    updateSession: methods.updateSession ?? (async () => ({})),
    addSessionAgendaItem: methods.addSessionAgendaItem ?? (async () => ({})),
  };
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = principal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", (permission: string) => async (request: FastifyRequest) => {
    if (!request.principal?.permissions.has(permission)) {
      throw new ApiError(403, "PERMISSION_DENIED", `Missing required permission: ${permission}`);
    }
  });
  app.decorate("database", {
    control: { listActiveTenantMembershipIdentities: async () => [] },
    withCoreWorkflowPrincipal: async <T>(
      _principal: unknown,
      _requestId: string,
      work: (store: typeof workflow) => Promise<T>,
    ): Promise<T> => work(workflow),
  } as unknown as DatabaseRuntime);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message },
        meta: { requestId: request.id },
      });
    }
    throw error;
  });
  await registerCoreWorkflowRoutes(app);
  await app.ready();
  return app;
}

function sessionCreateFixture(
  overrides: { readonly cycleId?: string } = {},
  extraAad: Readonly<Record<string, unknown>> = {},
) {
  const titleEnvelope = envelope({
    tenantId,
    cycleId: overrides.cycleId ?? cycleId,
    sessionId: workflowSessionId,
    purpose: "session-title",
    schemaVersion: 1,
    titleVersion: 1,
    ...extraAad,
  });
  return {
    sessionId: workflowSessionId,
    expectedCycleVersion: 1,
    sequence: 1,
    titleEnvelope,
    titleContentHash: hashEnvelope(titleEnvelope),
    startsAt: "2026-09-11T13:00:00.000Z",
    endsAt: "2026-09-11T14:00:00.000Z",
  };
}

function updateFixture(titleVersion: number) {
  const titleEnvelope = envelope({
    tenantId,
    cycleId,
    sessionId: workflowSessionId,
    purpose: "session-title",
    schemaVersion: 1,
    titleVersion,
  });
  return { expectedVersion: 27, titleEnvelope, titleContentHash: hashEnvelope(titleEnvelope) };
}

function agendaFixture() {
  const titleEnvelope = envelope({
    tenantId,
    sessionId: workflowSessionId,
    agendaItemId,
    purpose: "session-agenda-title",
    schemaVersion: 1,
    titleVersion: 1,
  });
  return {
    expectedSessionVersion: 1,
    itemId: agendaItemId,
    position: 1,
    titleEnvelope,
    titleContentHash: hashEnvelope(titleEnvelope),
  };
}

function envelope(aad: Readonly<Record<string, unknown>>) {
  return {
    algorithm: "AES-256-GCM" as const,
    keyId: "tenant-session-title-key-v1",
    nonce: Buffer.alloc(12).toString("base64url"),
    ciphertext: Buffer.alloc(64).toString("base64url"),
    aad: Buffer.from(JSON.stringify(aad)).toString("base64url"),
  };
}

function hashEnvelope(value: ReturnType<typeof envelope>): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}
