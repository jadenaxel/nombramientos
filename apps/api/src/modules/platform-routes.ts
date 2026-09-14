import { randomBytes, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { realpath } from "node:fs/promises";
import path from "node:path";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { hashFile } from "@nombramientos/database";
import { z } from "zod";
import { ApiError, forbidden, unauthorized } from "../lib/errors.js";
import { parseBody, parseParams, requireIdempotencyKey, respond } from "../lib/http.js";
import {
  requireGovernedOperationStepUp,
  requireOperationStepUp,
} from "../lib/operation-step-up.js";
import { requireMfaAssurance, requireRecentMfa } from "../lib/recent-mfa.js";
import { ianaTimezoneSchema } from "../lib/timezone.js";
import { sha256 } from "./auth-service.js";
import { normalizeEmail } from "./invitation-service.js";

const uuid = z.string().uuid();
export const platformTenantProvisionSchema = z.object({
  tenantId: uuid,
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),
  displayName: z.string().trim().min(2).max(160),
  kind: z.enum(["demo", "real"]),
  timezone: ianaTimezoneSchema,
  locale: z.enum(["es", "en", "fr"]),
  initialAdmin: z.discriminatedUnion("mode", [
    z.object({ mode: z.literal("pending") }).strict(),
    z.object({
      mode: z.literal("invitation"),
      email: z.string().email().max(320),
      expiresInHours: z.number().int().min(1).max(168).default(72),
    }).strict(),
  ]),
}).strict();
const suspendSchema = z.object({
  expectedVersion: z.number().int().positive(),
  reasonCode: z.enum(["security_review", "operational_hold", "institution_request", "compliance_review"]),
}).strict();
const reactivateSchema = z.object({
  expectedVersion: z.number().int().positive(),
  reasonCode: z.enum([
    "security_review_completed",
    "operational_hold_resolved",
    "institution_request_resumed",
    "compliance_review_completed",
  ]),
}).strict();
const initialAdminSchema = z.object({
  expectedVersion: z.number().int().positive(),
  email: z.string().email().max(320),
  expiresInHours: z.number().int().min(1).max(168).default(72),
}).strict();
const exportRequestSchema = z.object({
  expectedVersion: z.number().int().positive(),
}).strict();
const downloadAuthorizationSchema = z.object({}).strict();
const downloadSchema = z.object({ authorizationId: uuid }).strict();
const revokeDownloadSchema = z.object({ expectedRevision: z.number().int().positive() }).strict();
const decommissionSchema = z.object({
  expectedVersion: z.number().int().positive(),
  exportJobId: uuid,
  retentionDays: z.number().int().min(7).max(3_650),
  reasonCode: z.enum(["institution_request", "duplicate_tenant", "service_ended", "legal_retention"]),
}).strict();
const cancelDecommissionSchema = z.object({ expectedVersion: z.number().int().positive() }).strict();
const publicExportManifestSchema = z.object({
  format: z.literal("nombramientos-tenant-export"),
  version: z.literal(1),
  backupId: uuid,
  tenantId: uuid,
  recoveryPointAt: z.string().datetime({ offset: true }),
  completedAt: z.string().datetime({ offset: true }),
  encryption: z.object({
    algorithm: z.literal("AES-256-GCM"),
    authenticatedCoreSha256: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    keyCustody: z.literal("platform-managed-not-exported"),
  }).strict(),
  payload: z.object({
    file: z.literal("database.dump.aesgcm"),
    bytes: z.number().int().positive(),
    sha256: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  }).strict(),
}).strict();

export async function registerPlatformRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/platform/tenants", { preHandler: [app.authenticate, requireMfaAssurance("platform operations")] }, async (request, reply) => {
    await requirePlatformPermission(app, request, "platform.operation.read");
    const [items, worker] = await Promise.all([
      app.database.control.listTenants(),
      app.database.control.getProvisioningWorkerStatus(),
    ]);
    reply.header("cache-control", "no-store");
    return respond(request, reply, { items, worker, contentAccess: false, keyAccess: false });
  });

  app.post("/v1/platform/tenants/provisioning", {
    preHandler: [app.authenticate, app.verifyCsrf, requireGovernedOperationStepUp({
      action: "platform.tenant.provision",
      purpose: "platform_administration",
    })],
    config: { rateLimit: { max: 12, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.provision");
    const body = parseBody(platformTenantProvisionSchema, request);
    if (body.initialAdmin.mode === "invitation") {
      await requirePlatformPermission(app, request, "platform.security.manage");
    }
    const idempotencyKey = requireIdempotencyKey(request);
    const acceptanceToken = randomBytes(32).toString("base64url");
    const expiresAt = body.initialAdmin.mode === "invitation"
      ? new Date(Date.now() + body.initialAdmin.expiresInHours * 60 * 60_000)
      : undefined;
    let result;
    try {
      result = await app.database.control.queueTenantProvisioning(
        {
          idempotencyKey,
          tenantId: body.tenantId,
          slug: body.slug,
          displayName: body.displayName,
          kind: body.kind,
          timezone: body.timezone,
          locale: body.locale,
          initialAdmin: body.initialAdmin.mode === "pending" ? { mode: "pending" } : {
            mode: "invitation",
            email: body.initialAdmin.email.trim().normalize("NFKC"),
            normalizedEmail: normalizeEmail(body.initialAdmin.email),
            expiresInHours: body.initialAdmin.expiresInHours,
            expiresAt: expiresAt!.toISOString(),
            tokenHash: sha256(acceptanceToken),
            createdByIdentityId: principal.identityId,
          },
        },
        principal.identityId,
        request.id,
      );
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId: body.tenantId,
      action: "platform.tenant_provisioning_queued",
      entityType: "provisioning_job",
      entityId: result.jobId,
      result: "success",
      requestId: request.id,
      metadata: { reused: result.reused, slug: body.slug, kind: body.kind },
    });
    return respond(request, reply, {
      ...result,
      initialAdmin: body.initialAdmin.mode === "pending"
        ? { mode: "pending", activationState: "pending_activation" }
        : {
            mode: "invitation",
            activationState: "invitation_queued",
            delivery: result.reused ? "token_already_issued" : "local_one_time_token",
            ...(result.reused ? {} : { acceptanceToken, expiresAt }),
          },
    }, result.reused ? 200 : 202);
  });

  app.post("/v1/platform/tenants/:tenantId/initial-admin-invitation", {
    preHandler: [app.authenticate, app.verifyCsrf, requireOperationStepUp("platform_administration")],
    config: { rateLimit: { max: 6, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.security.manage");
    const { tenantId } = parseParams(z.object({ tenantId: uuid }), request);
    const body = parseBody(initialAdminSchema, request);
    const idempotencyKey = requireIdempotencyKey(request);
    const acceptanceToken = randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + body.expiresInHours * 60 * 60_000);
    let result;
    try {
      result = await app.database.control.activateTenantInitialAdmin({
        tenantId,
        expectedVersion: body.expectedVersion,
        email: body.email.trim().normalize("NFKC"),
        normalizedEmail: normalizeEmail(body.email),
        tokenHash: sha256(acceptanceToken),
        expiresAt,
        expiresInHours: body.expiresInHours,
        idempotencyKey,
        actorIdentityId: principal.identityId,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId,
      action: "platform.initial_admin_invited",
      entityType: "tenant_invitation",
      entityId: result.invitationId,
      result: "success",
      requestId: request.id,
      metadata: { reused: result.reused, expiresAt: expiresAt.toISOString(), roles: ["CHURCH_ADMIN"] },
    });
    return respond(request, reply, {
      ...result,
      delivery: result.reused ? "token_already_issued" : "local_one_time_token",
      ...(result.reused ? {} : { acceptanceToken, expiresAt }),
    }, result.reused ? 200 : 201);
  });

  app.post("/v1/platform/tenants/:tenantId/suspend", {
    preHandler: [app.authenticate, app.verifyCsrf, requireGovernedOperationStepUp({
      action: "platform.tenant.suspend",
      purpose: "platform_administration",
    })],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.suspend");
    const { tenantId } = parseParams(z.object({ tenantId: uuid }), request);
    const body = parseBody(suspendSchema, request);
    let version;
    try {
      version = await app.database.control.suspendTenant({
        tenantId,
        expectedVersion: body.expectedVersion,
        reasonCode: body.reasonCode,
        actorIdentityId: principal.identityId,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.tenantPools.evict(tenantId);
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId,
      action: "platform.tenant_suspended",
      entityType: "tenant",
      entityId: tenantId,
      result: "success",
      requestId: request.id,
      metadata: { previousVersion: body.expectedVersion, version, reasonCode: body.reasonCode },
    });
    return respond(request, reply, { tenantId, status: "suspended", version, sessionsRevoked: true });
  });

  app.post("/v1/platform/tenants/:tenantId/reactivate", {
    preHandler: [app.authenticate, app.verifyCsrf, requireOperationStepUp("platform_administration")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.reactivate");
    const { tenantId } = parseParams(z.object({ tenantId: uuid }), request);
    const body = parseBody(reactivateSchema, request);
    const idempotencyKey = requireIdempotencyKey(request);
    let result;
    try {
      result = await app.database.control.reactivateTenant({
        tenantId,
        expectedVersion: body.expectedVersion,
        reasonCode: body.reasonCode,
        idempotencyKey,
        actorIdentityId: principal.identityId,
        requestId: request.id,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.tenantPools.evict(tenantId);
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId,
      action: "platform.tenant_reactivated",
      entityType: "tenant",
      entityId: tenantId,
      result: "success",
      requestId: request.id,
      metadata: {
        previousVersion: body.expectedVersion,
        version: result.version,
        reasonCode: body.reasonCode,
        sessionsRevoked: result.sessionsRevoked,
        sessionsCreated: 0,
        reused: result.reused,
        contentAccess: false,
        keyAccess: false,
      },
    });
    return respond(request, reply, result);
  });

  app.post("/v1/platform/tenants/:tenantId/exports", {
    preHandler: [app.authenticate, app.verifyCsrf, requireOperationStepUp("data_export")],
    config: { rateLimit: { max: 12, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.export.request");
    const { tenantId } = parseParams(z.object({ tenantId: uuid }), request);
    const body = parseBody(exportRequestSchema, request);
    const idempotencyKey = requireIdempotencyKey(request);
    let result;
    try {
      result = await app.database.control.queueTenantExport({
        tenantId,
        expectedVersion: body.expectedVersion,
        idempotencyKey,
        actorIdentityId: principal.identityId,
        requestId: request.id,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId,
      action: "platform.tenant_export_queued",
      entityType: "tenant_export_job",
      entityId: result.jobId,
      result: "success",
      requestId: request.id,
      metadata: {
        expectedVersion: body.expectedVersion,
        revision: result.revision,
        reused: result.reused,
        contentAccess: false,
        keyAccess: false,
      },
    });
    return respond(request, reply, { ...result, tenantId }, result.reused ? 200 : 202);
  });

  app.post("/v1/platform/tenants/:tenantId/exports/:exportId/download-authorizations", {
    preHandler: [app.authenticate, app.verifyCsrf, requireGovernedOperationStepUp({
      action: "platform.tenant.export.download",
      purpose: "data_export",
    })],
    config: { rateLimit: { max: 20, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.export.download");
    const { tenantId, exportId } = parseParams(z.object({ tenantId: uuid, exportId: uuid }), request);
    parseBody(downloadAuthorizationSchema, request);
    const idempotencyKey = requireIdempotencyKey(request);
    const expiresAt = new Date(Date.now() + 5 * 60_000);
    let result;
    try {
      result = await app.database.control.authorizeTenantExportDownload({
        authorizationId: randomUUID(),
        tenantId,
        exportJobId: exportId,
        expiresAt,
        idempotencyKey,
        actorIdentityId: principal.identityId,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId,
      action: "platform.tenant_export_download_authorized",
      entityType: "tenant_export_download_authorization",
      entityId: result.authorizationId,
      result: "success",
      requestId: request.id,
      metadata: { exportJobId: exportId, expiresAt: result.expiresAt.toISOString(), reused: result.reused },
    });
    return respond(request, reply, result, result.reused ? 200 : 201);
  });

  app.post("/v1/platform/tenants/:tenantId/exports/:exportId/download", {
    preHandler: [app.authenticate, app.verifyCsrf, requireRecentMfa("downloading an encrypted tenant export")],
    config: { rateLimit: { max: 20, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.export.download");
    const { tenantId, exportId } = parseParams(z.object({ tenantId: uuid, exportId: uuid }), request);
    const { authorizationId } = parseBody(downloadSchema, request);
    let artifact;
    try {
      artifact = await app.database.control.consumeTenantExportDownload({
        authorizationId,
        tenantId,
        exportJobId: exportId,
        actorIdentityId: principal.identityId,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    if (!artifact) throw new ApiError(409, "EXPORT_DOWNLOAD_AUTHORIZATION_UNAVAILABLE", "Download authorization is expired, consumed, revoked, or unavailable");
    const manifest = publicExportManifestSchema.parse(artifact.publicManifest);
    if (manifest.tenantId !== tenantId || manifest.backupId !== artifact.backupId
      || manifest.payload.bytes !== artifact.encryptedBytes
      || manifest.payload.sha256 !== artifact.ciphertextSha256) {
      throw new ApiError(409, "EXPORT_ARTIFACT_INVALID", "Encrypted export metadata is inconsistent");
    }
    const payloadPath = await resolveExportPayloadPath(app.apiConfig.secretFile, artifact.artifactRelativePath);
    const actual = await hashFile(payloadPath);
    if (actual.bytes !== artifact.encryptedBytes || actual.sha256 !== artifact.ciphertextSha256) {
      throw new ApiError(409, "EXPORT_ARTIFACT_INVALID", "Encrypted export failed its integrity check");
    }
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId,
      action: "platform.tenant_export_downloaded",
      entityType: "tenant_export_job",
      entityId: exportId,
      result: "success",
      requestId: request.id,
      metadata: {
        authorizationId,
        backupId: artifact.backupId,
        encryptedBytes: artifact.encryptedBytes,
        ciphertextSha256: artifact.ciphertextSha256,
        contentAccess: false,
        keyAccess: false,
      },
    });
    reply.header("cache-control", "private, no-store, max-age=0");
    reply.header("pragma", "no-cache");
    reply.header("content-type", "application/vnd.nombramientos.tenant-backup+aesgcm");
    reply.header("content-length", String(artifact.encryptedBytes));
    reply.header("content-disposition", `attachment; filename="tenant-export-${artifact.tenantSlug}-${artifact.backupId}.aesgcm"`);
    return reply.send(createReadStream(payloadPath));
  });

  app.post("/v1/platform/export-download-authorizations/:authorizationId/revoke", {
    preHandler: [app.authenticate, app.verifyCsrf, requireOperationStepUp("data_export")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.export.download");
    const { authorizationId } = parseParams(z.object({ authorizationId: uuid }), request);
    const body = parseBody(revokeDownloadSchema, request);
    let result;
    try {
      result = await app.database.control.revokeTenantExportDownload({
        authorizationId,
        expectedRevision: body.expectedRevision,
        actorIdentityId: principal.identityId,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      action: "platform.tenant_export_download_authorization_revoked",
      entityType: "tenant_export_download_authorization",
      entityId: authorizationId,
      result: "success",
      requestId: request.id,
      metadata: { revision: result.revision },
    });
    return respond(request, reply, result);
  });

  app.post("/v1/platform/tenants/:tenantId/decommission", {
    preHandler: [app.authenticate, app.verifyCsrf, requireGovernedOperationStepUp({
      action: "platform.tenant.decommission.schedule",
      purpose: "platform_administration",
    })],
    config: { rateLimit: { max: 6, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.decommission.schedule");
    const { tenantId } = parseParams(z.object({ tenantId: uuid }), request);
    const body = parseBody(decommissionSchema, request);
    const idempotencyKey = requireIdempotencyKey(request);
    let result;
    try {
      result = await app.database.control.scheduleTenantDecommission({
        tenantId,
        expectedVersion: body.expectedVersion,
        exportJobId: body.exportJobId,
        retentionDays: body.retentionDays,
        reasonCode: body.reasonCode,
        idempotencyKey,
        actorIdentityId: principal.identityId,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.tenantPools.evict(tenantId);
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId,
      action: "platform.tenant_decommission_scheduled",
      entityType: "tenant_decommission_request",
      entityId: result.decommissionId,
      result: "success",
      requestId: request.id,
      metadata: {
        exportJobId: body.exportJobId,
        reasonCode: body.reasonCode,
        retentionDays: body.retentionDays,
        retentionUntil: result.retentionUntil?.toISOString(),
        version: result.version,
        sessionsRevoked: result.sessionsRevoked,
        reused: result.reused,
        irreversibleDeletion: false,
      },
    });
    return respond(request, reply, result, result.reused ? 200 : 202);
  });

  app.post("/v1/platform/tenants/:tenantId/decommission/:decommissionId/cancel", {
    preHandler: [app.authenticate, app.verifyCsrf, requireOperationStepUp("platform_administration")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    await requirePlatformPermission(app, request, "platform.tenant.decommission.cancel");
    const { tenantId, decommissionId } = parseParams(z.object({ tenantId: uuid, decommissionId: uuid }), request);
    const body = parseBody(cancelDecommissionSchema, request);
    const idempotencyKey = requireIdempotencyKey(request);
    let result;
    try {
      result = await app.database.control.cancelTenantDecommission({
        tenantId,
        decommissionId,
        expectedVersion: body.expectedVersion,
        idempotencyKey,
        actorIdentityId: principal.identityId,
      });
    } catch (error) {
      throw mapPlatformDatabaseError(error);
    }
    await app.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId,
      action: "platform.tenant_decommission_cancelled",
      entityType: "tenant_decommission_request",
      entityId: decommissionId,
      result: "success",
      requestId: request.id,
      metadata: { restoredStatus: result.tenantStatus, version: result.version, reused: result.reused },
    });
    return respond(request, reply, result);
  });
}

async function resolveExportPayloadPath(secretFile: string, relativeDirectory: string): Promise<string> {
  if (!/^[0-9a-f-]{36}\/[0-9TZ]+-[0-9a-f-]{36}$/u.test(relativeDirectory)) {
    throw new ApiError(409, "EXPORT_ARTIFACT_INVALID", "Encrypted export storage reference is invalid");
  }
  const backupRoot = await realpath(path.join(path.dirname(secretFile), "backups"));
  const payload = await realpath(path.join(backupRoot, ...relativeDirectory.split("/"), "database.dump.aesgcm"));
  if (!payload.startsWith(`${backupRoot}${path.sep}`)) {
    throw new ApiError(409, "EXPORT_ARTIFACT_INVALID", "Encrypted export storage boundary is invalid");
  }
  return payload;
}

async function requirePlatformPermission(
  app: FastifyInstance,
  request: FastifyRequest,
  permission: string,
): Promise<void> {
  const principal = requirePrincipal(request);
  if (!await app.database.control.hasPlatformPermission(principal.identityId, permission)) throw forbidden(permission);
}

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}

function mapPlatformDatabaseError(error: unknown): Error {
  if (typeof error === "object" && error !== null && "code" in error) {
    if (error.code === "42501") return forbidden();
    if (error.code === "40001") return new ApiError(409, "VERSION_CONFLICT", "Tenant state changed; reload before retrying");
    if (error.code === "23505") return new ApiError(409, "PROVISIONING_CONFLICT", "Tenant or idempotency input conflicts with an existing job");
    if (error.code === "23503") return new ApiError(409, "PLATFORM_REFERENCE_CONFLICT", "Platform operation references unavailable state");
    if (error.code === "23514") return new ApiError(400, "PLATFORM_REQUEST_INVALID", "Platform operation input is invalid");
  }
  return error instanceof Error ? error : new Error("Platform database operation failed");
}
