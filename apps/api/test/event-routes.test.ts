import type { FastifyInstance } from "fastify";
import type { DatabaseRuntime, RequestPrincipal, TenantStore } from "@nombramientos/database";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";

const allowedOrigin = "http://127.0.0.1:3000";
const tenantId = "d0000000-0000-4000-8000-000000000001";
const otherTenantId = "d0000000-0000-4000-8000-000000000002";
const identityId = "d1000000-0000-4000-8000-000000000001";
const sessionId = "d3000000-0000-4000-8000-000000000001";
const roundId = "d4000000-0000-4000-8000-000000000001";
const memberId = "d2000000-0000-4000-8000-000000000001";

const activeHarnesses = new Set<TestHarness>();

afterEach(async () => {
  await Promise.all([...activeHarnesses].map((harness) => harness.close()));
  activeHarnesses.clear();
});

describe("SSE event route", () => {
  it("anchors a new stream at the authorized tail instead of replaying stale history", async () => {
    const events: Array<Record<string, unknown>> = [{
      sequence: 40,
      event_type: "round.phase",
      payload: { roundId, phase: "PROPUESTAS_ABIERTAS", version: 1 },
    }];
    const harness = await createHarness(events, new Set(["aggregate.read"]));
    const stream = await openStream(harness);
    try {
      const ready = await readUntil(stream.reader, "event: ready");
      expect(ready).toContain('"cursor":40');
      expect(ready).not.toContain("id: 40");
      expect(harness.latestEventSequence).toHaveBeenCalledTimes(1);

      events.push({
        sequence: 41,
        event_type: "round.phase",
        payload: { roundId, phase: "PROPUESTAS_CERRADAS", version: 2 },
      });
      const next = await readUntil(stream.reader, "id: 41");
      expect(next).toContain("event: round.phase");
      expect(next).not.toContain("id: 40");
    } finally {
      await stream.close();
    }
  });

  it("streams only permitted fields, resumes with Last-Event-ID and closes cleanly", async () => {
    const events: Array<Record<string, unknown>> = [
      {
        sequence: 41,
        event_type: "member.changed",
        payload: { memberId, version: 1, privateNote: "must-not-leak" },
      },
      {
        sequence: 42,
        event_type: "round.phase",
        payload: { roundId, phase: "VOTACION_ABIERTA", version: 2, privateNote: "must-not-leak" },
        audience: "tenant.authorized",
        aggregate_id: roundId,
      },
    ];
    const harness = await createHarness(events, new Set(["aggregate.read"]));
    const first = await openStream(harness, { after: 40 });
    try {
      expect(first.response.status).toBe(200);
      expect(first.response.headers.get("content-type")).toContain("text/event-stream");
      expect(first.response.headers.get("access-control-allow-origin")).toBe(allowedOrigin);
      expect(first.response.headers.get("access-control-allow-credentials")).toBe("true");
      expect(first.response.headers.get("vary")).toContain("Origin");
      expect(first.response.headers.get("cache-control")).toContain("no-transform");
      expect(first.response.headers.get("x-accel-buffering")).toBe("no");

      const firstFrames = await readUntil(first.reader, "id: 42");
      expect(firstFrames).toContain("event: ready");
      expect(firstFrames).toContain(`\"tenantId\":\"${tenantId}\"`);
      expect(firstFrames).toContain("event: round.phase");
      expect(firstFrames).not.toContain("member.changed");
      expect(firstFrames).not.toContain(memberId);
      expect(firstFrames).not.toContain("privateNote");
      expect(firstFrames).not.toContain("aggregate_id");
    } finally {
      await first.close();
    }

    events.push({
      sequence: 43,
      event_type: "round.participation",
      payload: { roundId, identityId: "must-not-leak" },
    });
    const resumed = await openStream(harness, { lastEventId: 42 });
    try {
      const resumedFrames = await readUntil(resumed.reader, "id: 43");
      expect(resumedFrames).toContain("id: 43");
      expect(resumedFrames).not.toContain("id: 42");
      expect(resumedFrames).not.toContain("identityId");
      expect(harness.listEvents).toHaveBeenCalledWith(42, 100);
    } finally {
      await resumed.close();
    }
  });

  it("lets a submit-only session receive empty round revalidation signals and nothing else", async () => {
    const events: Array<Record<string, unknown>> = [];
    const harness = await createHarness(events, new Set(["proposal.submit"]));
    const stream = await openStream(harness);
    try {
      const ready = await readUntil(stream.reader, "event: ready");
      expect(ready).toContain(`\"tenantId\":\"${tenantId}\"`);
      expect(ready).not.toContain("cursor");

      events.push(
        {
          sequence: 1,
          event_type: "round.participation",
          payload: { roundId, received: 99, required: 100, privateNote: "must-not-leak" },
        },
        {
          sequence: 2,
          event_type: "round.phase",
          payload: { roundId, phase: "PROPUESTAS_CERRADAS", version: 2, privateNote: "must-not-leak" },
        },
        {
          sequence: 3,
          event_type: "round.closed",
          payload: { roundId, previousPhase: "PROPUESTAS_ABIERTAS", newPhase: "PROPUESTAS_CERRADAS", version: 2, closedAt: "2026-09-11T12:00:00.000Z" },
        },
      );

      const frames = await readUntil(stream.reader, "event: round.closed");
      expect(frames).toContain("event: round.phase");
      expect(frames).toContain("event: round.closed");
      expect(frames.match(/\"payload\":\{\}/g)).toHaveLength(2);
      expect(frames).not.toContain("round.participation");
      expect(frames).not.toContain(roundId);
      expect(frames).not.toContain("PROPUESTAS");
      expect(frames).not.toContain("received");
      expect(frames).not.toContain("required");
      expect(frames).not.toContain("privateNote");
      expect(frames).not.toContain("closedAt");
    } finally {
      await stream.close();
    }
  });

  it("rejects a session whose permissions are unrelated to round revalidation", async () => {
    const harness = await createHarness([], new Set(["member.read"]));
    const response = await fetch(`${harness.baseUrl}/v1/events?tenantId=${tenantId}`, {
      headers: streamHeaders(),
    });
    expect(response.status).toBe(403);
    expect((await response.json() as { error: { code: string } }).error.code).toBe("PERMISSION_DENIED");
  });

  it("returns stable errors for origins, tenant context and unsafe cursors", async () => {
    const harness = await createHarness([], new Set(["aggregate.read"]));
    const rejectedOrigin = await fetch(`${harness.baseUrl}/v1/events?tenantId=${tenantId}`, {
      headers: { cookie: "nom_session=test-session", origin: "http://127.0.0.1:3999" },
    });
    expect(rejectedOrigin.status).toBe(403);
    expect(rejectedOrigin.headers.get("access-control-allow-origin")).toBeNull();
    expect((await rejectedOrigin.json() as { error: { code: string } }).error.code).toBe("CORS_ORIGIN_DENIED");

    const missingOrigin = await fetch(`${harness.baseUrl}/v1/events?tenantId=${tenantId}`, {
      headers: { cookie: "nom_session=test-session" },
    });
    expect(missingOrigin.status).toBe(403);

    const wrongTenant = await fetch(`${harness.baseUrl}/v1/events?tenantId=${otherTenantId}`, {
      headers: streamHeaders(),
    });
    expect(wrongTenant.status).toBe(403);

    const unsafeHeader = await fetch(`${harness.baseUrl}/v1/events?tenantId=${tenantId}`, {
      headers: streamHeaders({ "last-event-id": String(Number.MAX_SAFE_INTEGER + 1) }),
    });
    expect(unsafeHeader.status).toBe(400);
    expect((await unsafeHeader.json() as { error: { code: string } }).error.code).toBe("EVENT_CURSOR_INVALID");

    const unsafeQuery = await fetch(`${harness.baseUrl}/v1/events?tenantId=${tenantId}&after=${Number.MAX_SAFE_INTEGER + 1}`, {
      headers: streamHeaders(),
    });
    expect(unsafeQuery.status).toBe(400);
  });

  it("limits concurrent streams per session and releases the slot after disconnect", async () => {
    const harness = await createHarness([], new Set(["aggregate.read"]));
    const streams: OpenStream[] = [];
    try {
      for (let index = 0; index < 3; index += 1) streams.push(await openStream(harness));
      const limited = await fetch(`${harness.baseUrl}/v1/events?tenantId=${tenantId}`, {
        headers: streamHeaders(),
      });
      expect(limited.status).toBe(429);
      expect(limited.headers.get("retry-after")).toBe("5");

      const released = streams.shift();
      if (!released) throw new Error("Expected an open stream");
      await released.close();
      await wait(50);

      const replacement = await openStream(harness);
      expect(replacement.response.status).toBe(200);
      streams.push(replacement);
    } finally {
      await Promise.all(streams.map((stream) => stream.close()));
    }
  });

  it("terminates active streams during server shutdown", async () => {
    const harness = await createHarness([], new Set(["aggregate.read"]));
    const stream = await openStream(harness);
    const closedPromptly = await Promise.race([
      harness.close().then(() => true),
      wait(1_000).then(() => false),
    ]);
    expect(closedPromptly).toBe(true);
    await stream.close();
  });
});

interface TestHarness {
  readonly app: FastifyInstance;
  readonly baseUrl: string;
  readonly listEvents: ReturnType<typeof vi.fn<(afterSequence: number, limit: number) => Promise<readonly Record<string, unknown>[]>>>;
  readonly latestEventSequence: ReturnType<typeof vi.fn<() => Promise<number>>>;
  close(): Promise<void>;
}

interface OpenStream {
  readonly response: Response;
  readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  close(): Promise<void>;
}

async function createHarness(
  events: Array<Record<string, unknown>>,
  permissions: ReadonlySet<string>,
): Promise<TestHarness> {
  const principal: RequestPrincipal = {
    sessionId,
    identityId,
    activeTenantId: tenantId,
    email: "sse-test@example.invalid",
    displayName: "SSE Test",
    tenantSlug: "sse-test",
    tenantName: "SSE Test",
    tenantKind: "demo",
    tenantTimezone: "America/La_Paz",
    csrfHash: "unused",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa",
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions,
  };
  const latestEventSequence = vi.fn(async () => events.reduce(
    (latest, event) => Math.max(latest, Number(event["sequence"] ?? 0)),
    0,
  ));
  const listEvents = vi.fn(async (afterSequence: number, limit: number) =>
    events.filter((event) => Number(event["sequence"]) > afterSequence).slice(0, limit));
  const database = {
    getPrincipal: vi.fn(async () => principal),
    enterpriseAuth: {
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
        enforcementMode: "monitor",
        minimumAal: 1,
        minimumPasskeyCount: 0,
        allowPassword: true,
        allowTotpFallback: true,
        allowRecoveryCodes: true,
        allowSyncedPasskeys: true,
      }),
      listCredentials: vi.fn().mockResolvedValue([]),
    },
    withPrincipal: vi.fn(async (
      _principal: RequestPrincipal,
      _requestId: string,
      work: (tenant: TenantStore) => Promise<unknown>,
    ) => work({ latestEventSequence, listEvents } as unknown as TenantStore)),
  } as unknown as DatabaseRuntime;
  const config: ApiConfig = {
    environment: "test",
    host: "127.0.0.1",
    port: 0,
    corsOrigins: new Set([allowedOrigin]),
    secureCookies: false,
    sessionTtlSeconds: 3_600,
    webauthn: {
      rpName: "Nombramientos",
      rpId: "localhost",
      expectedOrigins: ["http://localhost:3000"],
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    },
    authEncryptionKey: Buffer.alloc(32, 1),
    controlDatabaseUrl: "postgresql://unused:unused@127.0.0.1:55432/unused",
    secretMasterKey: Buffer.alloc(32, 2),
    secretFile: "unused",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
  const app = await buildServer({ config, database, logger: false, closeDatabaseOnShutdown: false });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const address = app.server.address();
  if (!address || typeof address === "string") throw new Error("Expected a TCP test server address");
  let closed = false;
  const harness: TestHarness = {
    app,
    baseUrl: `http://127.0.0.1:${address.port}`,
    listEvents,
    latestEventSequence,
    async close() {
      if (closed) return;
      closed = true;
      activeHarnesses.delete(harness);
      await app.close();
    },
  };
  activeHarnesses.add(harness);
  return harness;
}

async function openStream(
  harness: TestHarness,
  options: { readonly after?: number; readonly lastEventId?: number } = {},
): Promise<OpenStream> {
  const controller = new AbortController();
  const query = new URLSearchParams({ tenantId });
  if (options.after !== undefined) query.set("after", String(options.after));
  const response = await fetch(`${harness.baseUrl}/v1/events?${query}`, {
    headers: streamHeaders(options.lastEventId === undefined ? {} : { "last-event-id": String(options.lastEventId) }),
    signal: controller.signal,
  });
  if (!response.body) throw new Error("Expected an SSE response body");
  const reader = response.body.getReader();
  let closed = false;
  return {
    response,
    reader,
    async close() {
      if (closed) return;
      closed = true;
      await reader.cancel().catch(() => undefined);
      controller.abort();
    },
  };
}

function streamHeaders(additional: Readonly<Record<string, string>> = {}): Record<string, string> {
  return {
    cookie: "nom_session=test-session",
    origin: allowedOrigin,
    "user-agent": "nombramientos-sse-test",
    ...additional,
  };
}

async function readUntil(reader: ReadableStreamDefaultReader<Uint8Array>, expected: string): Promise<string> {
  const decoder = new TextDecoder();
  let output = "";
  const deadline = Date.now() + 2_000;
  while (!output.includes(expected)) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error(`Timed out waiting for SSE frame: ${expected}`);
    const result = await Promise.race([
      reader.read(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`Timed out waiting for SSE frame: ${expected}`)), remaining)),
    ]);
    if (result.done) throw new Error(`SSE stream ended before frame: ${expected}`);
    output += decoder.decode(result.value, { stream: true });
  }
  return output;
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
