import type { ServerResponse } from "node:http";
import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import { ApiError, forbidden, unauthorized } from "../lib/errors.js";
import { safeLogError } from "../lib/log-safety.js";
import { createSessionBinding, SESSION_COOKIE, sha256 } from "./auth-service.js";

const querySchema = z.object({
  after: z.coerce.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
  tenantId: z.string().uuid(),
});

const maxConnectionsPerSession = 3;
const maxConnectionsPerIdentity = 6;
const ROUND_REVALIDATION_PERMISSIONS = [
  "proposal.submit",
  "ballot.submit",
  "proposal.open",
  "ballot.open",
  "proposal.close",
  "ballot.close",
] as const;
const ROUND_STREAM_PERMISSIONS = ["aggregate.read", ...ROUND_REVALIDATION_PERMISSIONS] as const;

const eventPolicies: Readonly<Record<string, {
  readonly permissions: readonly string[];
  readonly fields: readonly string[];
  readonly nonAggregateFields?: readonly string[];
}>> = {
  "round.participation": { permissions: ["aggregate.read"], fields: ["roundId"] },
  "round.phase": { permissions: ROUND_STREAM_PERMISSIONS, fields: ["roundId", "phase", "version"], nonAggregateFields: [] },
  "round.closed": { permissions: ROUND_STREAM_PERMISSIONS, fields: ["roundId", "previousPhase", "newPhase", "version", "closedAt"], nonAggregateFields: [] },
  "member.changed": { permissions: ["member.read"], fields: ["memberId", "version"] },
  "members.imported": { permissions: ["member.import"], fields: ["importId", "created", "updated", "rejected", "total"] },
  "report.requested": { permissions: ["report.read"], fields: ["reportId"] },
  "assignment.changed": { permissions: ["organigram.read"], fields: ["assignmentId", "state", "version"] },
};

export async function registerEventRoutes(app: FastifyInstance): Promise<void> {
  const activeBySession = new Map<string, number>();
  const activeByIdentity = new Map<string, number>();
  const activeStreams = new Map<ServerResponse, AbortController>();

  app.addHook("preClose", async () => {
    for (const [response, controller] of activeStreams) {
      controller.abort();
      response.destroy();
    }
  });

  app.get("/v1/events", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    if (!hasAnyPermission(request.principal.permissions, ROUND_STREAM_PERMISSIONS)) {
      throw forbidden(ROUND_STREAM_PERMISSIONS.join("|"));
    }
    const initialPrincipal = request.principal;
    const sessionToken = request.cookies[SESSION_COOKIE];
    if (!sessionToken) throw unauthorized();
    const sessionTokenHash = sha256(sessionToken);
    const sessionBinding = createSessionBinding(request.headers["user-agent"], request.ip);
    const origin = request.headers.origin;
    if (typeof origin !== "string" || !app.apiConfig.corsOrigins.has(origin)) throw forbidden("allowed-origin");
    const query = querySchema.parse(request.query);
    if (query.tenantId !== initialPrincipal.activeTenantId) throw forbidden("tenant-context");
    const headerCursor = parseCursorHeader(request.headers["last-event-id"]);
    const requestedCursor = headerCursor ?? query.after;
    let cursor = requestedCursor ?? await app.database.withPrincipal(initialPrincipal, request.id, (tenant) =>
      tenant.latestEventSequence(),
    );
    const releaseConnection = reserveConnection(
      initialPrincipal.sessionId,
      initialPrincipal.identityId,
      activeBySession,
      activeByIdentity,
      reply,
    );
    const response = reply.raw;
    const controller = new AbortController();
    const stop = () => controller.abort();
    activeStreams.set(response, controller);
    response.once("close", stop);
    response.once("finish", stop);
    response.once("error", stop);

    try {
      reply.hijack();
      response.writeHead(200, {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-store, no-transform, must-revalidate",
        connection: "keep-alive",
        "access-control-allow-origin": origin,
        "access-control-allow-credentials": "true",
        vary: "Origin",
        "x-accel-buffering": "no",
        "x-request-id": request.id,
      });
      const readyPayload = initialPrincipal.permissions.has("aggregate.read")
        ? { requestId: request.id, tenantId: query.tenantId, cursor }
        : { requestId: request.id, tenantId: query.tenantId };
      if (!await writeSse(
        response,
        `retry: 3000\nevent: ready\ndata: ${JSON.stringify(readyPayload)}\n\n`,
        controller.signal,
      )) return;

      let heartbeatAt = Date.now();
      while (!controller.signal.aborted && !response.destroyed && !response.writableEnded) {
        const refreshedPrincipal = await app.database.getPrincipal(sessionTokenHash, request.id, sessionBinding).catch((error: unknown) => {
          if (!controller.signal.aborted) app.log.warn({ safeError: safeLogError(error), requestId: request.id }, "SSE session revalidation failed");
          return null;
        });
        if (controller.signal.aborted) break;
        if (
          !refreshedPrincipal
          || refreshedPrincipal.sessionId !== initialPrincipal.sessionId
          || refreshedPrincipal.identityId !== initialPrincipal.identityId
          || refreshedPrincipal.activeTenantId !== initialPrincipal.activeTenantId
          || !hasAnyPermission(refreshedPrincipal.permissions, ROUND_STREAM_PERMISSIONS)
        ) break;

        let fetchFailed = false;
        const events = await app.database.withPrincipal(refreshedPrincipal, request.id, (tenant) =>
          tenant.listEvents(cursor, 100),
        ).catch((error: unknown) => {
          fetchFailed = true;
          if (!controller.signal.aborted) app.log.warn({ safeError: safeLogError(error), requestId: request.id }, "SSE event fetch failed");
          return [];
        });
        if (controller.signal.aborted || fetchFailed) break;

        for (const rawEvent of events) {
          if (controller.signal.aborted || response.destroyed || response.writableEnded) break;
          const sequence = parseSafeSequence(rawEvent["sequence"]);
          if (sequence === null || sequence <= cursor) {
            app.log.warn({ requestId: request.id }, "SSE outbox returned an invalid sequence");
            stop();
            break;
          }
          cursor = sequence;
          const event = authorizeEvent(rawEvent, refreshedPrincipal.permissions, sequence);
          if (!event) continue;
          if (!await writeSse(
            response,
            `id: ${sequence}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
            controller.signal,
          )) {
            stop();
            break;
          }
        }
        if (controller.signal.aborted) break;
        if (Date.now() - heartbeatAt >= 15_000) {
          if (!await writeSse(response, `: heartbeat ${Date.now()}\n\n`, controller.signal)) break;
          heartbeatAt = Date.now();
        }
        await delay(1_000, controller.signal);
      }
    } finally {
      stop();
      response.off("close", stop);
      response.off("finish", stop);
      response.off("error", stop);
      activeStreams.delete(response);
      releaseConnection();
      safeEnd(response);
    }
  });
}

function reserveConnection(
  sessionId: string,
  identityId: string,
  activeBySession: Map<string, number>,
  activeByIdentity: Map<string, number>,
  reply: FastifyReply,
): () => void {
  const sessionConnections = activeBySession.get(sessionId) ?? 0;
  const identityConnections = activeByIdentity.get(identityId) ?? 0;
  if (sessionConnections >= maxConnectionsPerSession || identityConnections >= maxConnectionsPerIdentity) {
    reply.header("retry-after", "5");
    throw new ApiError(429, "SSE_CONNECTION_LIMIT", "Too many live event connections");
  }
  activeBySession.set(sessionId, sessionConnections + 1);
  activeByIdentity.set(identityId, identityConnections + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    decrement(activeBySession, sessionId);
    decrement(activeByIdentity, identityId);
  };
}

function decrement(counts: Map<string, number>, key: string): void {
  const next = (counts.get(key) ?? 1) - 1;
  if (next <= 0) counts.delete(key);
  else counts.set(key, next);
}

function parseCursorHeader(value: string | readonly string[] | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw invalidCursor();
  const cursor = parseSafeSequence(value);
  if (cursor === null) throw invalidCursor();
  return cursor;
}

function invalidCursor(): ApiError {
  return new ApiError(400, "EVENT_CURSOR_INVALID", "Last-Event-ID must be a safe non-negative integer");
}

function parseSafeSequence(value: unknown): number | null {
  if (typeof value === "number") return Number.isSafeInteger(value) && value >= 0 ? value : null;
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function authorizeEvent(
  rawEvent: Readonly<Record<string, unknown>>,
  permissions: ReadonlySet<string>,
  sequence: number,
): { readonly sequence: number; readonly type: string; readonly payload: Readonly<Record<string, string | number | boolean | null>> } | null {
  const type = rawEvent["event_type"];
  if (typeof type !== "string") return null;
  const policy = eventPolicies[type];
  if (!policy || !hasAnyPermission(permissions, policy.permissions)) return null;
  const source = isRecord(rawEvent["payload"]) ? rawEvent["payload"] : {};
  const payload: Record<string, string | number | boolean | null> = {};
  const fields = !permissions.has("aggregate.read") && policy.nonAggregateFields
    ? policy.nonAggregateFields
    : policy.fields;
  for (const field of fields) {
    const value = safeScalar(source[field]);
    if (value !== undefined) payload[field] = value;
  }
  return { sequence, type: safeEventName(type), payload };
}

function hasAnyPermission(permissions: ReadonlySet<string>, required: readonly string[]): boolean {
  return required.some((permission) => permissions.has(permission));
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeScalar(value: unknown): string | number | boolean | null | undefined {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isSafeInteger(value) ? value : undefined;
  if (typeof value === "string" && value.length <= 256) return value;
  return undefined;
}

function safeEventName(value: string): string {
  return /^[a-z0-9_.-]{1,80}$/i.test(value) ? value : "message";
}

async function writeSse(response: ServerResponse, value: string, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted || response.destroyed || response.writableEnded) return false;
  try {
    if (response.write(value)) return true;
    return await waitForDrain(response, signal);
  } catch {
    return false;
  }
}

function waitForDrain(response: ServerResponse, signal: AbortSignal): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: boolean) => {
      if (settled) return;
      settled = true;
      response.off("drain", onDrain);
      response.off("close", onClosed);
      response.off("finish", onClosed);
      response.off("error", onClosed);
      signal.removeEventListener("abort", onAborted);
      resolve(value);
    };
    const onDrain = () => finish(true);
    const onClosed = () => finish(false);
    const onAborted = () => finish(false);
    response.once("drain", onDrain);
    response.once("close", onClosed);
    response.once("finish", onClosed);
    response.once("error", onClosed);
    signal.addEventListener("abort", onAborted, { once: true });
    if (signal.aborted || response.destroyed || response.writableEnded) finish(false);
  });
}

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(finish, milliseconds);
    const onAborted = () => finish();
    function finish() {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAborted);
      resolve();
    }
    signal.addEventListener("abort", onAborted, { once: true });
  });
}

function safeEnd(response: ServerResponse): void {
  if (response.destroyed || response.writableEnded) return;
  try {
    response.end();
  } catch {
    response.destroy();
  }
}
