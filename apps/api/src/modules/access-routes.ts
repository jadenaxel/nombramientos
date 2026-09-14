import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApiError, forbidden, unauthorized } from "../lib/errors.js";
import { parseBody, parseParams, requireIdempotencyKey, respond } from "../lib/http.js";
import { requireTrustedBrowserOrigin } from "../lib/browser-origin.js";
import { requirePolicyAwareOperationStepUp } from "../lib/operation-step-up.js";
import { requireMfaAssurance } from "../lib/recent-mfa.js";
import { CSRF_COOKIE, SESSION_COOKIE } from "./auth-service.js";

const uuid = z.string().uuid();
const localizedNameSchema = z.object({
  es: z.string().trim().min(2).max(120),
  en: z.string().trim().min(2).max(120),
  fr: z.string().trim().min(2).max(120),
}).strict();
const roleDefinitionFields = {
  name: localizedNameSchema,
  permissionCodes: z.array(z.string().min(3).max(100)).min(1).max(40),
  delegablePermissionCodes: z.array(z.string().min(3).max(100)).max(40).default([]),
} as const;
function validateRoleDefinition(
  value: {
    name: z.infer<typeof localizedNameSchema>;
    permissionCodes: string[];
    delegablePermissionCodes: string[];
  },
  context: z.RefinementCtx,
): void {
  if (new Set(value.permissionCodes).size !== value.permissionCodes.length) {
    context.addIssue({ code: "custom", path: ["permissionCodes"], message: "Permission codes must be unique" });
  }
  if (new Set(value.delegablePermissionCodes).size !== value.delegablePermissionCodes.length) {
    context.addIssue({ code: "custom", path: ["delegablePermissionCodes"], message: "Delegable codes must be unique" });
  }
  if (value.delegablePermissionCodes.some((permission) => !value.permissionCodes.includes(permission))) {
    context.addIssue({ code: "custom", path: ["delegablePermissionCodes"], message: "Delegable codes must belong to the role" });
  }
}
const createRoleSchema = z.object({
  ...roleDefinitionFields,
  id: uuid,
  code: z.string().regex(/^LOCAL_[A-Z0-9_]{3,54}$/),
}).strict().superRefine(validateRoleDefinition);
const updateRoleSchema = z.object({
  ...roleDefinitionFields,
  expectedVersion: z.number().int().positive(),
}).strict().superRefine(validateRoleDefinition);
const bindingSchema = z.object({ targetIdentityId: uuid, roleId: uuid }).strict();
const revokeBindingSchema = bindingSchema.extend({ expectedVersion: z.number().int().positive() });
const switchTenantSchema = z.object({ tenantId: uuid }).strict();

export async function registerAccessRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/memberships", { preHandler: [app.authenticate] }, async (request, reply) => {
    const principal = requirePrincipal(request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, {
      items: await app.database.control.listOwnMemberships(principal.identityId),
      activeTenantId: principal.activeTenantId,
    });
  });

  app.post("/v1/session/switch-tenant", {
    preHandler: [requireTrustedBrowserOrigin(app), app.authenticate, app.verifyCsrf],
    config: { rateLimit: { max: 12, timeWindow: "5 minutes" } },
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const body = parseBody(switchTenantSchema, request);
    const result = await app.authService.switchTenant({
      principal,
      targetTenantId: body.tenantId,
      requestId: request.id,
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    setRotatedSessionCookies(app, reply, result.sessionToken, result.csrfToken, result.expiresAt);
    const { sessionToken: _sessionToken, ...publicResult } = result;
    reply.header("cache-control", "no-store");
    return respond(request, reply, publicResult);
  });

  app.get("/v1/access/permissions", { preHandler: accessRead(app) }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const items = await app.database.withPrincipal(principal, request.id, (tenant) =>
      tenant.listPermissionCapabilities(principal.identityId));
    return respond(request, reply, { items });
  });

  app.get("/v1/access/roles", { preHandler: accessRead(app) }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const items = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.listAccessRoles());
    return respond(request, reply, { items });
  });

  app.get("/v1/access/bindings", { preHandler: accessRead(app) }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const [bindings, identities] = await Promise.all([
      app.database.withPrincipal(principal, request.id, (tenant) => tenant.listRoleBindings()),
      app.database.control.listTenantMembershipIdentities(principal.activeTenantId),
    ]);
    const identityMap = new Map(identities.map((identity) => [identity.identityId, identity]));
    return respond(request, reply, {
      items: bindings.map((binding) => ({ ...binding, identity: identityMap.get(binding.identityId) ?? null })),
      identities,
    });
  });

  app.post("/v1/access/roles", { preHandler: accessMutation(app) }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const body = parseBody(createRoleSchema, request);
    await assertDelegableDefinition(app, request, body.permissionCodes, body.delegablePermissionCodes);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.createLocalRole({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      roleId: body.id,
      code: body.code,
      name: body.name,
      permissionCodes: body.permissionCodes,
      delegablePermissionCodes: body.delegablePermissionCodes,
    }));
    return respond(request, reply, result, 201);
  });

  app.patch("/v1/access/roles/:roleId", { preHandler: accessMutation(app) }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roleId } = parseParams(z.object({ roleId: uuid }), request);
    const body = parseBody(updateRoleSchema, request);
    await assertDelegableDefinition(app, request, body.permissionCodes, body.delegablePermissionCodes);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.updateLocalRole({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      roleId,
      expectedVersion: body.expectedVersion,
      name: body.name,
      permissionCodes: body.permissionCodes,
      delegablePermissionCodes: body.delegablePermissionCodes,
    }));
    const revokedSessions = await app.database.control.revokeTenantIdentitySessions(
      principal.activeTenantId,
      result.affectedIdentityIds,
      "tenant_role_changed",
    );
    return respond(request, reply, { ...result, revokedSessions });
  });

  app.post("/v1/access/bindings", { preHandler: accessMutation(app) }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const body = parseBody(bindingSchema, request);
    await assertBindingAllowed(app, request, body.targetIdentityId, body.roleId);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.grantRoleBinding({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      targetIdentityId: body.targetIdentityId,
      roleId: body.roleId,
    }));
    const revokedSessions = await app.database.control.revokeTenantIdentitySessions(
      principal.activeTenantId,
      [body.targetIdentityId],
      "tenant_role_binding_changed",
    );
    return respond(request, reply, { ...result, revokedSessions }, 201);
  });

  app.post("/v1/access/bindings/revoke", { preHandler: accessMutation(app) }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const body = parseBody(revokeBindingSchema, request);
    await assertBindingAllowed(app, request, body.targetIdentityId, body.roleId);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.revokeRoleBinding({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      targetIdentityId: body.targetIdentityId,
      roleId: body.roleId,
      expectedVersion: body.expectedVersion,
    }));
    const revokedSessions = await app.database.control.revokeTenantIdentitySessions(
      principal.activeTenantId,
      [body.targetIdentityId],
      "tenant_role_binding_changed",
    );
    return respond(request, reply, { ...result, revokedSessions });
  });
}

function accessRead(app: FastifyInstance) {
  return [app.authenticate, app.requirePermission("role.manage"), requireMfaAssurance("access administration")];
}

function accessMutation(app: FastifyInstance) {
  return [
    app.authenticate,
    app.verifyCsrf,
    app.requirePermission("role.manage"),
    requirePolicyAwareOperationStepUp({
      action: "role.administration",
      purpose: "role_administration",
      recentMfaPurpose: "changing access administration",
    }),
  ];
}

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}

async function assertDelegableDefinition(
  app: FastifyInstance,
  request: FastifyRequest,
  permissionCodes: readonly string[],
  delegatedCodes: readonly string[],
): Promise<void> {
  const principal = requirePrincipal(request);
  const capabilities = await app.database.withPrincipal(principal, request.id, (tenant) =>
    tenant.listPermissionCapabilities(principal.identityId));
  const delegable = new Set(capabilities.filter((item) => item.delegable).map((item) => item.code));
  if (
    permissionCodes.some((permission) => permission.startsWith("platform.") || !delegable.has(permission))
    || delegatedCodes.some((permission) => !delegable.has(permission))
  ) {
    throw new ApiError(403, "PERMISSION_ESCALATION", "A local role cannot exceed the actor's delegable permissions");
  }
}

async function assertBindingAllowed(
  app: FastifyInstance,
  request: FastifyRequest,
  targetIdentityId: string,
  roleId: string,
): Promise<void> {
  const principal = requirePrincipal(request);
  if (targetIdentityId === principal.identityId) {
    throw new ApiError(403, "SELF_ESCALATION_DENIED", "Self-assignment and self-revocation are not permitted");
  }
  if (!await app.database.control.hasActiveMembership(targetIdentityId, principal.activeTenantId)) {
    throw forbidden("active tenant membership");
  }
  const [roles, capabilities] = await app.database.withPrincipal(principal, request.id, async (tenant) => [
    await tenant.listAccessRoles(),
    await tenant.listPermissionCapabilities(principal.identityId),
  ] as const);
  const role = roles.find((item) => item.id === roleId);
  if (!role) throw new ApiError(404, "ROLE_NOT_FOUND", "The requested tenant role is unavailable");
  const delegable = new Set(capabilities.filter((item) => item.delegable).map((item) => item.code));
  if (role.permissions.some((permission) => !delegable.has(permission.code))) {
    throw new ApiError(403, "PERMISSION_ESCALATION", "The role exceeds the actor's delegable permissions");
  }
}

function setRotatedSessionCookies(
  app: FastifyInstance,
  reply: FastifyReply,
  sessionToken: string,
  csrfToken: string,
  expiresAt: Date,
): void {
  reply.setCookie(SESSION_COOKIE, sessionToken, {
    httpOnly: true,
    secure: app.apiConfig.secureCookies,
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
  });
  reply.setCookie(CSRF_COOKIE, csrfToken, {
    httpOnly: false,
    secure: app.apiConfig.secureCookies,
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
  });
}
