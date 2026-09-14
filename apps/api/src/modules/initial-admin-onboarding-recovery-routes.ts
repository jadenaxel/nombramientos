import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { requireTrustedBrowserOrigin } from "../lib/browser-origin.js";
import { ApiError, unauthorized } from "../lib/errors.js";
import { parseBody, parseParams, parseQuery, requireIdempotencyKey, respond } from "../lib/http.js";
import { ipRateLimitKey, publicCeremonyRateLimitKey } from "../lib/rate-limit-policy.js";
import { setSessionCookies } from "./auth-routes.js";
import { sha256 } from "./auth-service.js";
import { hashStepUpOperation } from "./enterprise-auth-contract.js";
import {
  approveInitialAdminRecoverySchema,
  initialAdminRecoveryCandidatesQuerySchema,
  initialAdminRecoveryQueueQuerySchema,
  prepareInitialAdminRecoveryContextSchema,
  redeemInitialAdminRecoverySchema,
  requestInitialAdminRecoverySchema,
  revokeInitialAdminRecoverySchema,
} from "./initial-admin-onboarding-recovery-contract.js";

export const INITIAL_ADMIN_RECOVERY_COOKIE_PREFIX = "nom_initial_admin_recovery_";
const INITIAL_ADMIN_RECOVERY_CONTEXT_TTL_SECONDS = 30 * 60;
const MAX_RECOVERY_CONTEXT_ROOTS = 12;
const MAX_COOKIE_HEADER_BYTES = 8_192;
const MAX_PARSED_COOKIES = 64;
const opaque256Pattern = /^[A-Za-z0-9_-]{43}$/u;
const recoveryCookieNamePattern = /^nom_initial_admin_recovery_[A-Za-z0-9_-]{22}$/u;
const recoveryIdParamsSchema = z.object({ recoveryId: z.string().uuid() }).strict();
const recoveryRedemptionRateLimitKey = publicCeremonyRateLimitKey("initial-admin-recovery-redeem", [
  { field: "recoveryId", format: "uuid" },
  { field: "token", format: "opaque-256" },
]);

export async function registerInitialAdminOnboardingRecoveryRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/platform/initial-admin-recoveries/candidates", {
    preHandler: [app.authenticate, app.requirePermission("platform.security.manage")],
  }, async (request, reply) => {
    const query = parseQuery(initialAdminRecoveryCandidatesQuerySchema, request);
    const principal = requirePrincipal(request);
    return respond(request, reply, await app.initialAdminRecoveryService.listCandidates({
      principal,
      ...(query.tenantId ? { tenantId: query.tenantId } : {}),
      limit: query.limit,
      requestId: request.id,
    }));
  });

  app.get("/v1/platform/initial-admin-recoveries", {
    preHandler: [app.authenticate, app.requirePermission("platform.security.manage")],
  }, async (request, reply) => {
    const query = parseQuery(initialAdminRecoveryQueueQuerySchema, request);
    const principal = requirePrincipal(request);
    return respond(request, reply, await app.initialAdminRecoveryService.listRecoveries({
      principal,
      ...(query.tenantId ? { tenantId: query.tenantId } : {}),
      ...(query.status ? { status: query.status } : {}),
      ...(query.beforeRequestedAt ? { beforeRequestedAt: new Date(query.beforeRequestedAt) } : {}),
      ...(query.beforeRecoveryId ? { beforeRecoveryId: query.beforeRecoveryId } : {}),
      limit: query.limit,
      requestId: request.id,
    }));
  });

  app.post("/v1/platform/initial-admin-recoveries", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("platform.security.manage")],
    config: { rateLimit: { max: 6, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const body = parseBody(requestInitialAdminRecoverySchema, request);
    const stepUp = governedStepUpEvidence(request);
    const result = await app.initialAdminRecoveryService.request({
      principal: requirePrincipal(request),
      body,
      stepUp,
      idempotencyKey: requireIdempotencyKey(request),
      requestId: request.id,
    });
    return respond(request, reply, result, result.created ? 201 : 200);
  });

  app.post("/v1/platform/initial-admin-recoveries/:recoveryId/approve", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("platform.security.manage")],
    config: { rateLimit: { max: 6, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const { recoveryId } = parseParams(recoveryIdParamsSchema, request);
    const body = parseBody(approveInitialAdminRecoverySchema, request);
    if (body.recoveryId !== recoveryId) throw routeRecoveryMismatch();
    const result = await app.initialAdminRecoveryService.approve({
      principal: requirePrincipal(request),
      body,
      stepUp: governedStepUpEvidence(request),
      requestId: request.id,
    });
    return respond(request, reply, result);
  });

  app.post("/v1/platform/initial-admin-recoveries/:recoveryId/revoke", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("platform.security.manage")],
    config: { rateLimit: { max: 12, timeWindow: "1 hour" } },
  }, async (request, reply) => {
    const { recoveryId } = parseParams(recoveryIdParamsSchema, request);
    const body = parseBody(revokeInitialAdminRecoverySchema, request);
    if (body.recoveryId !== recoveryId) throw routeRecoveryMismatch();
    const result = await app.initialAdminRecoveryService.revoke({
      principal: requirePrincipal(request),
      recoveryId,
      expectedVersion: body.expectedVersion,
      source: body.source,
      reasonCode: body.reasonCode,
      stepUp: governedStepUpEvidence(request),
      requestId: request.id,
    });
    return respond(request, reply, result);
  });

  app.post("/v1/auth/initial-admin-recovery/prepare-context", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: { rateLimit: { max: 18, timeWindow: "15 minutes", keyGenerator: ipRateLimitKey } },
  }, async (request, reply) => {
    parseBody(prepareInitialAdminRecoveryContextSchema, request);
    const allExisting = initialAdminRecoveryRoots(request, app.apiConfig.authEncryptionKey);
    const existing = allExisting.slice(0, MAX_RECOVERY_CONTEXT_ROOTS);
    for (const excess of allExisting.slice(MAX_RECOVERY_CONTEXT_ROOTS)) {
      clearInitialAdminRecoveryCookie(app, reply, excess.cookieName);
    }
    if (existing.length < MAX_RECOVERY_CONTEXT_ROOTS) {
      setInitialAdminRecoveryCookie(
        app,
        reply,
        newInitialAdminRecoveryRoot(app.apiConfig.authEncryptionKey),
      );
    }
    reply.header("cache-control", "no-store");
    // A completed, body-less response is an explicit precommit barrier. No
    // bearer is accepted or database state mutated on this endpoint.
    return reply.status(204).send();
  });

  app.post("/v1/auth/initial-admin-recovery/redeem", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: { rateLimit: { max: 8, timeWindow: "15 minutes", keyGenerator: recoveryRedemptionRateLimitKey } },
  }, async (request, reply) => {
    const body = parseBody(redeemInitialAdminRecoverySchema, request);
    const allRoots = initialAdminRecoveryRoots(request, app.apiConfig.authEncryptionKey);
    const roots = allRoots.slice(0, MAX_RECOVERY_CONTEXT_ROOTS);
    for (const excess of allRoots.slice(MAX_RECOVERY_CONTEXT_ROOTS)) {
      clearInitialAdminRecoveryCookie(app, reply, excess.cookieName);
    }
    if (roots.length === 0) {
      throw new ApiError(
        428,
        "INITIAL_ADMIN_RECOVERY_CONTEXT_REQUIRED",
        "Establish a secure browser recovery context before redeeming this credential",
      );
    }
    const contextProofs = roots.map(({ rootSecret }) =>
      deriveInitialAdminRecoveryProof(rootSecret, body.recoveryId));
    const result = await app.initialAdminRecoveryService.redeem({
      recoveryId: body.recoveryId,
      ...(body.token ? { token: body.token } : {}),
      contextProofs,
      requestId: request.id,
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    setSessionCookies(app, reply, result.sessionToken, result.csrfToken, result.expiresAt);
    return respond(request, reply, result.publicSession);
  });
}

/** Derive an operation proof without ever exposing or persisting the root. */
export function deriveInitialAdminRecoveryProof(rootSecret: string, recoveryId: string): string {
  if (!opaque256Pattern.test(rootSecret) || !z.string().uuid().safeParse(recoveryId).success) {
    throw new Error("Initial-admin recovery proof derivation input is invalid");
  }
  return createHmac("sha256", rootSecret)
    .update("nombramientos.initial-admin-recovery.browser-context.v1\0", "utf8")
    .update(recoveryId, "utf8")
    .digest("base64url");
}

interface InitialAdminRecoveryRoot {
  readonly cookieName: string;
  readonly rootSecret: string;
}

function governedStepUpEvidence(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  if (["enrollment_only", "recovery_limited"].includes(request.principal.assuranceLevel)) {
    throw new ApiError(403, "RECOVERY_RESTRICTED", "A recovery or enrollment session cannot authorize governed recovery");
  }
  const operationHash = hashStepUpOperation(
    "platform_administration",
    request.method,
    request.url,
    request.body,
  );
  const grantToken = request.headers["x-step-up-grant"];
  if (typeof grantToken !== "string" || grantToken.length < 32 || grantToken.length > 256) {
    throw new ApiError(
      428,
      "WEBAUTHN_STEP_UP_REQUIRED",
      "A fresh passkey verification is required for this exact operation",
      { purpose: "platform_administration", operationHash },
    );
  }
  return { tokenHash: sha256(grantToken), operationHash };
}

function newInitialAdminRecoveryRoot(serverKey: Buffer): InitialAdminRecoveryRoot {
  const rootSecret = randomBytes(32).toString("base64url");
  return { cookieName: initialAdminRecoveryCookieName(serverKey, rootSecret), rootSecret };
}

function initialAdminRecoveryCookieName(serverKey: Buffer, rootSecret: string): string {
  const identifier = createHmac("sha256", serverKey)
    .update("nombramientos.initial-admin-recovery-cookie.v1\0", "utf8")
    .update(rootSecret, "utf8")
    .digest()
    .subarray(0, 16)
    .toString("base64url");
  return `${INITIAL_ADMIN_RECOVERY_COOKIE_PREFIX}${identifier}`;
}

function initialAdminRecoveryRoots(request: FastifyRequest, serverKey: Buffer): InitialAdminRecoveryRoot[] {
  const rawCookieHeader = request.headers.cookie;
  if (typeof rawCookieHeader === "string" && Buffer.byteLength(rawCookieHeader, "utf8") > MAX_COOKIE_HEADER_BYTES) {
    throw contextOverflow();
  }
  const cookieNames = Object.keys(request.cookies);
  if (cookieNames.length > MAX_PARSED_COOKIES) throw contextOverflow();
  const shaped = cookieNames.flatMap((cookieName): [string, string][] => {
    const rootSecret = request.cookies[cookieName];
    return recoveryCookieNamePattern.test(cookieName)
      && typeof rootSecret === "string"
      && opaque256Pattern.test(rootSecret)
      ? [[cookieName, rootSecret]]
      : [];
  });
  const authentic = shaped.filter(([cookieName, rootSecret]) => {
    const expected = Buffer.from(initialAdminRecoveryCookieName(serverKey, rootSecret), "utf8");
    const actual = Buffer.from(cookieName, "utf8");
    return expected.byteLength === actual.byteLength && timingSafeEqual(expected, actual);
  });
  return authentic
    .map(([cookieName, rootSecret]) => ({ cookieName, rootSecret }))
    .sort((left, right) => left.cookieName.localeCompare(right.cookieName, "en-US"));
}

function clearInitialAdminRecoveryCookie(
  app: FastifyInstance,
  reply: FastifyReply,
  cookieName: string,
): void {
  reply.clearCookie(cookieName, {
    httpOnly: true,
    secure: app.apiConfig.secureCookies,
    sameSite: "strict",
    path: "/v1/auth/initial-admin-recovery",
  });
}

function setInitialAdminRecoveryCookie(
  app: FastifyInstance,
  reply: FastifyReply,
  context: InitialAdminRecoveryRoot,
): void {
  reply.setCookie(context.cookieName, context.rootSecret, {
    httpOnly: true,
    secure: app.apiConfig.secureCookies,
    sameSite: "strict",
    path: "/v1/auth/initial-admin-recovery",
    maxAge: INITIAL_ADMIN_RECOVERY_CONTEXT_TTL_SECONDS,
  });
}

function contextOverflow(): ApiError {
  return new ApiError(
    428,
    "INITIAL_ADMIN_RECOVERY_CONTEXT_OVERFLOW",
    "Secure recovery browser context input is excessive",
  );
}

function routeRecoveryMismatch(): ApiError {
  return new ApiError(400, "INITIAL_ADMIN_RECOVERY_ID_MISMATCH", "Route and body recovery identifiers must match");
}

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}
