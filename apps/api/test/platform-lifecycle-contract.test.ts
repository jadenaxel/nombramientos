import { randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ZodError } from "zod";
import { ApiError } from "../src/lib/errors.js";
import { hashStepUpOperation } from "../src/modules/enterprise-auth-contract.js";
import { registerPlatformRoutes } from "../src/modules/platform-routes.js";

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("platform tenant lifecycle HTTP contract", () => {
  it("queues a real privileged export job with MFA, atomic permission, OCC, and idempotency", async () => {
    const queueTenantExport = vi.fn().mockResolvedValue({ jobId: randomUUID(), state: "queued", revision: 1, reused: false });
    const appendAudit = vi.fn().mockResolvedValue(undefined);
    const app = await fixtureApp({ queueTenantExport, appendAudit });
    const tenantId = randomUUID();
    const response = await app.inject({
      method: "POST",
      url: `/v1/platform/tenants/${tenantId}/exports`,
      headers: { "idempotency-key": randomUUID(), "x-step-up-grant": "g".repeat(43) },
      payload: { expectedVersion: 7 },
    });

    expect(response.statusCode).toBe(202);
    expect(queueTenantExport).toHaveBeenCalledWith(expect.objectContaining({ tenantId, expectedVersion: 7 }));
    expect(appendAudit).toHaveBeenCalledWith(expect.objectContaining({
      tenantId,
      action: "platform.tenant_export_queued",
      metadata: expect.objectContaining({ contentAccess: false, keyAccess: false }),
    }));
    expect(JSON.stringify(appendAudit.mock.calls)).not.toMatch(/database_name|runtime_secret|artifact_relative_path/i);
  });

  it("schedules and cancels decommission without accepting free-text reasons or deletion semantics", async () => {
    const tenantId = randomUUID();
    const exportJobId = randomUUID();
    const decommissionId = randomUUID();
    const retentionUntil = new Date(Date.now() + 90 * 24 * 60 * 60_000);
    const scheduleTenantDecommission = vi.fn().mockResolvedValue({
      decommissionId,
      state: "scheduled",
      tenantStatus: "decommission_pending",
      version: 8,
      retentionUntil,
      sessionsRevoked: 3,
      reused: false,
    });
    const cancelTenantDecommission = vi.fn().mockResolvedValue({
      decommissionId,
      state: "cancelled",
      tenantStatus: "active",
      version: 9,
      retentionUntil: null,
      sessionsRevoked: 0,
      reused: false,
    });
    const appendAudit = vi.fn().mockResolvedValue(undefined);
    const evict = vi.fn().mockResolvedValue(undefined);
    const app = await fixtureApp({ scheduleTenantDecommission, cancelTenantDecommission, appendAudit }, evict);

    const invalid = await app.inject({
      method: "POST",
      url: `/v1/platform/tenants/${tenantId}/decommission`,
      headers: { "idempotency-key": randomUUID(), "x-step-up-grant": "g".repeat(43) },
      payload: { expectedVersion: 7, exportJobId, retentionDays: 90, reason: "human free text" },
    });
    expect(invalid.statusCode).toBe(400);
    expect(scheduleTenantDecommission).not.toHaveBeenCalled();

    const scheduled = await app.inject({
      method: "POST",
      url: `/v1/platform/tenants/${tenantId}/decommission`,
      headers: { "idempotency-key": randomUUID(), "x-step-up-grant": "g".repeat(43) },
      payload: { expectedVersion: 7, exportJobId, retentionDays: 90, reasonCode: "institution_request" },
    });
    expect(scheduled.statusCode).toBe(202);
    expect(scheduleTenantDecommission).toHaveBeenCalledWith(expect.objectContaining({
      tenantId, expectedVersion: 7, exportJobId, retentionDays: 90, reasonCode: "institution_request",
    }));
    expect(evict).toHaveBeenCalledWith(tenantId);

    const cancelled = await app.inject({
      method: "POST",
      url: `/v1/platform/tenants/${tenantId}/decommission/${decommissionId}/cancel`,
      headers: { "idempotency-key": randomUUID(), "x-step-up-grant": "g".repeat(43) },
      payload: { expectedVersion: 8 },
    });
    expect(cancelled.statusCode).toBe(200);
    expect(cancelTenantDecommission).toHaveBeenCalledWith(expect.objectContaining({ tenantId, decommissionId, expectedVersion: 8 }));
    expect(JSON.stringify(appendAudit.mock.calls)).toContain('"irreversibleDeletion":false');
    expect(JSON.stringify(appendAudit.mock.calls)).not.toMatch(/drop database|delete from|human free text/i);
  });

  it("rejects legacy free-text suspension reasons before touching storage", async () => {
    const suspendTenant = vi.fn();
    const app = await fixtureApp({ suspendTenant });
    const response = await app.inject({
      method: "POST",
      url: `/v1/platform/tenants/${randomUUID()}/suspend`,
      headers: { "x-step-up-grant": "g".repeat(43) },
      payload: { expectedVersion: 1, reason: "Contains private operational narrative" },
    });
    expect(response.statusCode).toBe(400);
    expect(suspendTenant).not.toHaveBeenCalled();
  });

  it("reactivates only through a closed resolution code without recreating sessions", async () => {
    const tenantId = randomUUID();
    const reactivateTenant = vi.fn().mockResolvedValue({
      tenantId,
      status: "active",
      version: 12,
      sessionsRevoked: 0,
      sessionsCreated: 0,
      reused: false,
    });
    const appendAudit = vi.fn().mockResolvedValue(undefined);
    const hasPlatformPermission = vi.fn().mockResolvedValue(true);
    const evict = vi.fn().mockResolvedValue(undefined);
    const app = await fixtureApp({ reactivateTenant, appendAudit, hasPlatformPermission }, evict);

    const invalid = await app.inject({
      method: "POST",
      url: `/v1/platform/tenants/${tenantId}/reactivate`,
      headers: { "idempotency-key": randomUUID(), "x-step-up-grant": "g".repeat(43) },
      payload: { expectedVersion: 11, reason: "Private narrative about the incident" },
    });
    expect(invalid.statusCode).toBe(400);
    expect(reactivateTenant).not.toHaveBeenCalled();

    const idempotencyKey = randomUUID();
    const response = await app.inject({
      method: "POST",
      url: `/v1/platform/tenants/${tenantId}/reactivate`,
      headers: { "idempotency-key": idempotencyKey, "x-step-up-grant": "g".repeat(43) },
      payload: { expectedVersion: 11, reasonCode: "operational_hold_resolved" },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      data: { tenantId, status: "active", version: 12, sessionsCreated: 0, reused: false },
    });
    expect(reactivateTenant).toHaveBeenCalledWith(expect.objectContaining({
      tenantId,
      expectedVersion: 11,
      reasonCode: "operational_hold_resolved",
      idempotencyKey,
    }));
    expect(hasPlatformPermission).toHaveBeenCalledWith(expect.any(String), "platform.tenant.reactivate");
    expect(evict).toHaveBeenCalledWith(tenantId);
    expect(appendAudit).toHaveBeenCalledWith(expect.objectContaining({
      tenantId,
      action: "platform.tenant_reactivated",
      metadata: expect.objectContaining({
        reasonCode: "operational_hold_resolved",
        sessionsCreated: 0,
        contentAccess: false,
        keyAccess: false,
      }),
    }));
    expect(JSON.stringify(appendAudit.mock.calls)).not.toMatch(/private narrative|email|database_name|runtime_secret/i);
  });

  it("requires an exact one-use passkey grant as a global platform floor regardless of active tenant policy", async () => {
    const tenantId = randomUUID();
    const body = { expectedVersion: 4, reasonCode: "security_review" } as const;
    const suspendTenant = vi.fn().mockResolvedValue(5);
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const app = await fixtureApp({ suspendTenant }, undefined, {
      enforcementMode: "monitor",
      actionRequirements: {},
      consumeStepUpGrant,
    });
    const path = `/v1/platform/tenants/${tenantId}/suspend`;
    const operationHash = hashStepUpOperation("platform_administration", "POST", path, body);

    const challenged = await app.inject({ method: "POST", url: path, payload: body });
    expect(challenged.statusCode).toBe(428);
    expect(challenged.json<{ error: { details: unknown } }>().error.details).toEqual({
      purpose: "platform_administration",
      operationHash,
    });
    expect(suspendTenant).not.toHaveBeenCalled();

    const accepted = await app.inject({
      method: "POST",
      url: path,
      headers: { "x-step-up-grant": "g".repeat(43) },
      payload: body,
    });
    expect(accepted.statusCode).toBe(200);
    expect(consumeStepUpGrant).toHaveBeenCalledWith(expect.objectContaining({ operationHash }));
    expect(suspendTenant).toHaveBeenCalledTimes(1);
  });
});

async function fixtureApp(
  controlMethods: Readonly<Record<string, unknown>>,
  evict = vi.fn().mockResolvedValue(undefined),
  identityPolicy: {
    readonly enforcementMode?: "monitor" | "enforce";
    readonly actionRequirements?: Readonly<Record<string, unknown>>;
    readonly consumeStepUpGrant?: ReturnType<typeof vi.fn>;
  } = {},
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  const currentPrincipal = principal();
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = currentPrincipal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", () => async () => undefined);
  app.decorate("apiConfig", {
    environment: "test", host: "127.0.0.1", port: 4000, corsOrigins: new Set(["http://127.0.0.1:3000"]),
    secureCookies: false, sessionTtlSeconds: 3600, authEncryptionKey: Buffer.alloc(32),
    webauthn: { rpName: "Nombramientos", rpId: "localhost", expectedOrigins: ["http://localhost:3000"], challengeTtlSeconds: 300, stepUpTtlSeconds: 120 },
    controlDatabaseUrl: "postgresql://unused.invalid/control", secretMasterKey: Buffer.alloc(32),
    secretFile: "unused", tenantPoolMax: 1, tenantPoolIdleMs: 1000,
  });
  app.decorate("database", {
    control: {
      hasPlatformPermission: vi.fn().mockResolvedValue(true),
      appendAudit: vi.fn().mockResolvedValue(undefined),
      ...controlMethods,
    },
    enterpriseAuth: {
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
        enforcementMode: identityPolicy.enforcementMode ?? "monitor",
        actionRequirements: identityPolicy.actionRequirements ?? {},
      }),
      consumeStepUpGrant: identityPolicy.consumeStepUpGrant ?? vi.fn().mockResolvedValue(true),
    },
    tenantPools: { evict },
  } as unknown as DatabaseRuntime);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message, ...(error.details === undefined ? {} : { details: error.details }) },
        meta: { requestId: request.id },
      });
    }
    if (error instanceof ZodError) {
      return reply.status(400).send({ error: { code: "VALIDATION_ERROR", message: "Request is invalid" }, meta: { requestId: request.id } });
    }
    return reply.status(500).send({ error: { code: "INTERNAL_ERROR", message: "Unexpected" }, meta: { requestId: request.id } });
  });
  await registerPlatformRoutes(app);
  return app;
}

function principal(): RequestPrincipal {
  return {
    sessionId: randomUUID(), identityId: randomUUID(), activeTenantId: randomUUID(),
    email: "admin@example.invalid", displayName: "Admin", tenantSlug: "fixture", tenantName: "Fixture",
    tenantKind: "real", tenantTimezone: "America/La_Paz", csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000), assuranceLevel: "mfa", authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(), mfaRequired: true, mfaEnabled: true, enrollmentOnly: false,
    permissions: new Set(),
  };
}
