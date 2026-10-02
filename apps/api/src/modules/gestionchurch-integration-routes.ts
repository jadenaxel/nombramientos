import { createHash, randomBytes } from "node:crypto";
import { hash } from "argon2";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { RequestPrincipal } from "@nombramientos/database";
import { ApiError, unauthorized } from "../lib/errors.js";
import { requireTrustedBrowserOrigin } from "../lib/browser-origin.js";
import { parseBody, respond } from "../lib/http.js";
import { ipRateLimitKey } from "../lib/rate-limit-policy.js";
import { setSessionCookies } from "./auth-routes.js";
import { logGestionChurchUpstreamRejection, type GestionChurchRejectionLogger, type GestionChurchUpstreamOperation } from "./gestionchurch-upstream-diagnostics.js";

const exchangeSchema = z.object({
  code: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
}).strict();

const gestionChurchRoles = z.enum([
  "GLOBAL_ADMIN", "TENANT_ADMIN", "PASTOR", "BOARD_SECRETARY", "FIRST_ELDER", "ELDER",
  "REVIEWER", "DEPARTMENT_LEADER", "DEPARTMENT_PLANNER", "NOMINATIONS_USER", "VIEWER", "AUDITOR",
  "NOMINATIONS_COMMISSION_MEMBER", "NOMINATIONS_BALLOT_CUSTODIAN",
]);

const redemptionSchema = z.object({
  subject: z.object({
    id: z.string().uuid(),
    scope: z.enum(["global", "tenant"]),
    email: z.string().email(),
    name: z.string().min(2).max(160),
    roles: z.array(gestionChurchRoles).min(1).max(14),
    roleFingerprint: z.string().regex(/^[0-9a-f]{64}$/),
    sourceSessionId: z.string().uuid(),
  }).strict(),
  tenant: z.object({
    id: z.string().uuid(),
    slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),
    name: z.string().min(2).max(160),
    timezone: z.string().min(1).max(80),
  }).strict(),
}).strict();

const authorizationSchema = z.object({
  authorized: z.boolean(),
  roles: z.array(gestionChurchRoles).min(1).max(14).optional(),
  roleFingerprint: z.string().regex(/^[0-9a-f]{64}$/).optional(),
}).strict();

const organizationDirectorySchema = z.object({
  source: z.literal("gestionchurch"),
  tenantId: z.string().uuid(),
  tenantName: z.string().min(2).max(160),
  generatedAt: z.string().datetime(),
  sourceUpdatedAt: z.string().datetime().nullable(),
  summary: z.object({
    departments: z.number().int().nonnegative(),
    people: z.number().int().nonnegative(),
    appointments: z.number().int().nonnegative(),
  }).strict(),
  items: z.array(z.object({
    id: z.string().uuid(),
    memberId: z.string().uuid(),
    departmentId: z.string().uuid(),
    officeCode: z.string().min(1).max(160),
    officeName: z.string().min(1).max(240),
    officeNames: z.object({ es: z.string(), en: z.string(), fr: z.string() }).strict(),
    departmentName: z.string().min(1).max(160),
    departmentNames: z.object({ es: z.string(), en: z.string(), fr: z.string() }).strict(),
    displayName: z.string().min(2).max(160),
    status: z.literal("elected"),
    processState: z.literal("VIGENTE"),
    effective: z.literal(true),
    independent: z.literal(true),
    source: z.string().max(240),
  }).strict()).max(10_000),
}).strict();

export type GestionChurchOrganizationDirectory = z.infer<typeof organizationDirectorySchema>;

const federationSubjectPattern = /^(global|tenant):([0-9a-f-]{36}):([0-9a-f-]{36})$/u;

export async function registerGestionChurchIntegrationRoutes(app: FastifyInstance): Promise<void> {
  const integration = app.apiConfig.gestionChurchIntegration;
  if (!integration?.enabled) return;

  app.post("/v1/integrations/gestionchurch/session", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: { rateLimit: { max: 12, timeWindow: "5 minutes", keyGenerator: ipRateLimitKey } },
  }, async (request, reply) => {
    const body = parseBody(exchangeSchema, request);
    const redeemed = await callGestionChurch(integration, integration.redeemUrl!, { code: body.code }, "redeem", app.log);
    const context = redemptionSchema.parse(redeemed);
    const calculatedFingerprint = roleFingerprint(context.subject.roles);
    if (calculatedFingerprint !== context.subject.roleFingerprint) {
      throw new ApiError(502, "GESTIONCHURCH_ASSERTION_INVALID", "GestionChurch returned an inconsistent role assertion");
    }
    const nominationRoles = mapNombramientosRoles(context.subject.roles);
    const federationSubject = `${context.subject.scope}:${context.tenant.id}:${context.subject.id}`;
    const disabledPasswordHash = await hash(`federated-only:${randomBytes(32).toString("base64url")}`);
    let identity;
    try {
      identity = await app.database.control.syncGestionChurchFederatedIdentity({
        gestionChurchTenantId: context.tenant.id,
        gestionChurchTenantSlug: context.tenant.slug,
        tenantName: context.tenant.name,
        gestionChurchSubject: federationSubject,
        email: context.subject.email,
        displayName: context.subject.name,
        gestionChurchRoles: context.subject.roles,
        roleFingerprint: context.subject.roleFingerprint,
        disabledPasswordHash,
      });
      await app.database.syncGestionChurchFederatedRoles({
        tenantId: identity.tenantId,
        identityId: identity.identityId,
        roleCodes: nominationRoles,
        requestId: request.id,
      });
    } catch (error) {
      if (error instanceof Error && /not been provisioned/u.test(error.message)) {
        throw new ApiError(503, "NOMINATIONS_TENANT_NOT_READY", "The church workspace is still being prepared in Nombramientos");
      }
      throw error;
    }
    const result = await app.authService.createFederatedSession({
      identityId: identity.identityId,
      tenantId: identity.tenantId,
      sourceSessionId: context.subject.sourceSessionId,
      requestId: request.id,
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    await app.database.control.appendAudit({
      actorIdentityId: identity.identityId,
      tenantId: identity.tenantId,
      action: "auth.gestionchurch_federated",
      entityType: "session",
      entityId: identity.identityId,
      result: "success",
      requestId: request.id,
      metadata: { sourceScope: context.subject.scope, mappedRoles: nominationRoles },
    });
    setSessionCookies(app, reply, result.sessionToken, result.csrfToken, result.expiresAt);
    const { sessionToken: _sessionToken, ...publicResult } = result;
    reply.header("cache-control", "no-store");
    return respond(request, reply, publicResult);
  });
}

export async function requireCurrentGestionChurchAccess(
  app: FastifyInstance,
  principal: RequestPrincipal,
): Promise<void> {
  const integration = app.apiConfig.gestionChurchIntegration;
  if (!integration?.enabled) {
    if (principal.authMethod === 'federated') throw unauthorized('GestionChurch integration is not available');
    return;
  }
  const metadata = await app.database.control.getGestionChurchFederation(principal.identityId, principal.activeTenantId);
  if (!metadata) {
    if (principal.authMethod === 'federated') throw unauthorized('GestionChurch federation context is missing');
    return;
  }
  const sourceSessionId = await app.database.control.getGestionChurchSessionBinding(principal.sessionId, principal.identityId, principal.activeTenantId);
  if (!sourceSessionId) {
    await app.database.control.revokeSession(principal.sessionId, 'gestionchurch_session_unbound');
    throw unauthorized('Open the module again from GestionChurch to renew your session');
  }
  const subject = federationSubjectPattern.exec(metadata.subject);
  if (!subject || subject[2] !== metadata.gestionChurchTenantId) {
    await app.database.control.revokeSession(principal.sessionId, "gestionchurch_context_invalid");
    throw unauthorized("GestionChurch federation context is invalid");
  }
  const response = authorizationSchema.parse(await callGestionChurch(
    integration,
    integration.authorizeUrl!,
    { tenantId: metadata.gestionChurchTenantId, subjectId: subject[3], subjectScope: subject[1], sourceSessionId },
    "authorize", app.log,
  ));
  if (!response.authorized || response.roleFingerprint !== metadata.roleFingerprint
    || (response.roles && roleFingerprint(response.roles) !== response.roleFingerprint)) {
    await app.database.control.revokeSession(principal.sessionId, "gestionchurch_access_changed");
    throw unauthorized("GestionChurch access changed; open the module again from GestionChurch");
  }
}

export async function getGestionChurchOrganizationDirectory(
  app: FastifyInstance,
  principal: RequestPrincipal,
): Promise<GestionChurchOrganizationDirectory | null> {
  const integration = app.apiConfig.gestionChurchIntegration;
  if (!integration?.enabled) return null;
  const metadata = await app.database.control.getGestionChurchFederation(principal.identityId, principal.activeTenantId);
  if (!metadata) return null;
  const subject = federationSubjectPattern.exec(metadata.subject);
  if (!subject || subject[2] !== metadata.gestionChurchTenantId) {
    throw new ApiError(403, "GESTIONCHURCH_CONTEXT_INVALID", "The GestionChurch tenant context is invalid");
  }
  if (subject[1] !== "tenant") {
    throw new ApiError(403, "TENANT_MEMBERSHIP_REQUIRED", "The organization chart requires a user from the selected church");
  }
  const sourceSessionId = await app.database.control.getGestionChurchSessionBinding(principal.sessionId, principal.identityId, principal.activeTenantId);
  if (!sourceSessionId) throw unauthorized('GestionChurch source session is missing');
  const value = organizationDirectorySchema.parse(await callGestionChurch(
    integration,
    integration.organizationUrl!,
    { tenantId: metadata.gestionChurchTenantId, subjectId: subject[3], subjectScope: subject[1], sourceSessionId },
    "organization", app.log,
  ));
  if (value.tenantId !== metadata.gestionChurchTenantId) {
    throw new ApiError(502, "GESTIONCHURCH_TENANT_MISMATCH", "GestionChurch returned data for a different tenant");
  }
  return value;
}

async function callGestionChurch(
  integration: NonNullable<FastifyInstance["apiConfig"]["gestionChurchIntegration"]>,
  url: string,
  body: unknown,
  operation: GestionChurchUpstreamOperation,
  logger: GestionChurchRejectionLogger | undefined,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-integration-secret": integration.sharedSecret!,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    throw new ApiError(503, "GESTIONCHURCH_UNAVAILABLE", "GestionChurch identity service is unavailable");
  }
  if (!response.ok) {
    logGestionChurchUpstreamRejection(logger, operation, response.status);
    throw new ApiError(response.status === 401 ? 401 : 502, "GESTIONCHURCH_EXCHANGE_REJECTED", "GestionChurch rejected the identity exchange");
  }
  return response.json().catch(() => undefined);
}

function roleFingerprint(roles: readonly string[]): string {
  return createHash("sha256").update([...roles].sort().join("\n")).digest("hex");
}

export function mapNombramientosRoles(roles: readonly z.infer<typeof gestionChurchRoles>[]): string[] {
  const mapped = new Set<string>();
  // Preserve the existing base-role precedence; operations require an explicit
  // central assignment, including the historical NOMINATIONS_USER grant.
  if (roles.includes("GLOBAL_ADMIN") || roles.includes("TENANT_ADMIN")) mapped.add("CHURCH_ADMIN");
  else if (roles.includes("BOARD_SECRETARY")) mapped.add("COMMITTEE_SECRETARY");
  else if (roles.includes("AUDITOR")) mapped.add("AUDITOR");
  if (roles.includes("NOMINATIONS_USER") || roles.includes("NOMINATIONS_COMMISSION_MEMBER")) mapped.add("COMMITTEE_MEMBER");
  if (roles.includes("NOMINATIONS_BALLOT_CUSTODIAN")) mapped.add("TALLY_CUSTODIAN");
  if (mapped.size === 0) throw new ApiError(403, "NOMINATIONS_ROLE_REQUIRED", "GestionChurch did not grant a Nombramientos role");
  return [...mapped].sort();
}
