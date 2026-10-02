import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import type { FastifyInstance, FastifyRequest } from "fastify";
import type { IdentitySessionPolicyDecision } from "./lib/identity-policy-enforcement.js";
import { forbidden, unauthorized, ApiError } from "./lib/errors.js";
import { evaluateIdentitySessionPolicy } from "./lib/identity-policy-enforcement.js";
import {
  aggregateIpRateLimitKey,
  DEFAULT_SECURITY_RATE_LIMIT_POLICY,
  type SecurityRateLimitPolicy,
  verifiedIdentityRateLimitKey,
  verifiedSessionOrIdentityOrIpRateLimitKey,
} from "./lib/rate-limit-policy.js";
import { createSessionBinding, CSRF_COOKIE, SESSION_COOKIE, sha256 } from "./modules/auth-service.js";
import { requireCurrentGestionChurchAccess } from "./modules/gestionchurch-integration-routes.js";
import { requireDeviceSessionProof, registerDeviceProofBodyHash } from "./modules/device-session-proof.js";

export async function registerSecurity(
  app: FastifyInstance,
  rateLimitPolicy: SecurityRateLimitPolicy = DEFAULT_SECURITY_RATE_LIMIT_POLICY,
): Promise<void> {
  await app.register(cookie);
  app.decorateRequest("principal", null);
  registerDeviceProofBodyHash(app);

  // Route-specific limits inherit this verified-identity key. Running at
  // preValidation lets the optional resolver below authenticate the session
  // before selecting a bucket, without running mutation/step-up preHandlers.
  await app.register(rateLimit, {
    global: true,
    max: rateLimitPolicy.sessionOrAnonymousMax,
    timeWindow: rateLimitPolicy.timeWindow,
    hook: "preValidation",
    keyGenerator: verifiedSessionOrIdentityOrIpRateLimitKey,
  });

  // The high aggregate ceiling executes before cookie/session lookup, so a
  // hostile source cannot turn arbitrary cookies into unlimited database work.
  // It supplements rather than replaces the session, identity and anonymous
  // budgets below.
  const enforceAggregateIpCeiling = app.createRateLimit({
    max: rateLimitPolicy.aggregateIpMax,
    timeWindow: rateLimitPolicy.timeWindow,
    keyGenerator: aggregateIpRateLimitKey,
  });
  const enforceAggregateIdentityCeiling = app.createRateLimit({
    max: rateLimitPolicy.aggregateIdentityMax,
    timeWindow: rateLimitPolicy.timeWindow,
    keyGenerator: verifiedIdentityRateLimitKey,
  });
  app.addHook("onRequest", async (request, reply) => {
    const result = await enforceAggregateIpCeiling(request);
    if (result.isAllowed || !result.isExceeded) return;
    reply.header("x-ratelimit-limit", result.max);
    reply.header("x-ratelimit-remaining", 0);
    reply.header("x-ratelimit-reset", result.ttlInSeconds);
    reply.header("retry-after", Math.max(1, result.ttlInSeconds));
    throw new ApiError(429, "RATE_LIMIT_EXCEEDED", "Request rate limit exceeded");
  });

  // Register CORS only after the aggregate hook. Its generated OPTIONS route
  // may terminate during onRequest, but preflights must still consume the
  // source-IP ceiling rather than bypassing all admission control.
  await app.register(helmet, {
    global: true,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  });
  await app.register(cors, {
    credentials: true,
    origin(origin, callback) {
      if (!origin || app.apiConfig.corsOrigins.has(origin)) callback(null, true);
      else callback(new ApiError(403, "CORS_ORIGIN_DENIED", "Origin is not allowed"), false);
    },
    allowedHeaders: ["content-type", "x-csrf-token", "x-step-up-grant", "idempotency-key", "last-event-id", "x-device-proof"],
    exposedHeaders: ["x-request-id"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  });

  type ResolvedPrincipal = NonNullable<FastifyRequest["principal"]>;
  const principalResolutions = new WeakMap<FastifyRequest, Promise<ResolvedPrincipal | null>>();
  const policyResolutions = new WeakMap<FastifyRequest, Promise<IdentitySessionPolicyDecision>>();
  const resolvePrincipal = async (request: FastifyRequest): Promise<ResolvedPrincipal | null> => {
    const existing = principalResolutions.get(request);
    if (existing) return existing;
    const resolution = (async () => {
      const token = request.cookies[SESSION_COOKIE];
      if (!token) return null;
      return app.database.getPrincipal(
        sha256(token),
        request.id,
        createSessionBinding(request.headers["user-agent"], request.ip),
      );
    })();
    principalResolutions.set(request, resolution);
    const principal = await resolution;
    request.principal = principal;
    return principal;
  };
  const resolvePolicy = (
    request: FastifyRequest,
    principal: ResolvedPrincipal,
  ): Promise<IdentitySessionPolicyDecision> => {
    const existing = policyResolutions.get(request);
    if (existing) return existing;
    const resolution = evaluateIdentitySessionPolicy(app.database, principal);
    policyResolutions.set(request, resolution);
    return resolution;
  };

  // A raw cookie never chooses a bucket. Only a principal returned by the
  // bound session lookup can move this request out of the anonymous IP bucket.
  app.addHook("preValidation", async (request) => {
    if (request.cookies[SESSION_COOKIE]) await resolvePrincipal(request);
  });
  app.addHook("preValidation", async (request, reply) => {
    if (!request.principal) return;
    const result = await enforceAggregateIdentityCeiling(request);
    if (result.isAllowed || !result.isExceeded) return;
    reply.header("x-ratelimit-limit", result.max);
    reply.header("x-ratelimit-remaining", 0);
    reply.header("x-ratelimit-reset", result.ttlInSeconds);
    reply.header("retry-after", Math.max(1, result.ttlInSeconds));
    throw new ApiError(429, "RATE_LIMIT_EXCEEDED", "Request rate limit exceeded");
  });

  app.decorate("authenticate", async (request) => {
    const principal = await resolvePrincipal(request);
    if (!principal) throw unauthorized(request.cookies[SESSION_COOKIE] ? "Session is invalid or expired" : undefined);
    await requireCurrentGestionChurchAccess(app, principal);
    const path = request.url.split("?", 1)[0] ?? "";
    if (principal.assuranceLevel === "recovery_limited" && !RECOVERY_LIMITED_ROUTES.has(path)) {
      throw new ApiError(403, "RECOVERY_RESTRICTED", "Complete security recovery before using application data or administration");
    }
    if (principal.enrollmentOnly && !MFA_ENROLLMENT_ONLY_ROUTES.has(path)) {
      throw new ApiError(403, "MFA_ENROLLMENT_REQUIRED", "MFA enrollment must be completed before using privileged access");
    }
    const decision = await resolvePolicy(request, principal);
    request.principal = decision.principal;
    if (decision.policyRestricted && !IDENTITY_POLICY_UPGRADE_ROUTES.has(path)) {
      throw new ApiError(
        403,
        "IDENTITY_SECURITY_UPGRADE_REQUIRED",
        "The current session does not satisfy the active identity security policy",
      );
    }
    await requireDeviceSessionProof(app, request);
  });
  app.decorate("verifyCsrf", async (request) => {
    if (!request.principal) throw unauthorized();
    const cookieToken = request.cookies[CSRF_COOKIE];
    const headerToken = request.headers["x-csrf-token"];
    if (!cookieToken || typeof headerToken !== "string" || cookieToken !== headerToken) {
      throw new ApiError(403, "CSRF_INVALID", "CSRF validation failed");
    }
    if (sha256(cookieToken) !== request.principal.csrfHash) {
      throw new ApiError(403, "CSRF_INVALID", "CSRF validation failed");
    }
  });
  app.decorate("requirePermission", (permission: string) => async (request) => {
    if (!request.principal) throw unauthorized();
    if (!request.principal.permissions.has(permission)) throw forbidden(permission);
  });
}

const MFA_ENROLLMENT_ONLY_ROUTES = new Set([
  "/v1/session",
  "/v1/auth/policy",
  "/v1/auth/logout",
  "/v1/auth/mfa/enrollment/start",
  "/v1/auth/mfa/enrollment/pending",
  "/v1/auth/mfa/enrollment/cancel",
  "/v1/auth/mfa/enrollment/confirm",
  "/v1/auth/passkeys",
  "/v1/auth/passkeys/registration/options",
  "/v1/auth/passkeys/registration/verify",
]);

const IDENTITY_POLICY_UPGRADE_ROUTES = new Set([
  ...MFA_ENROLLMENT_ONLY_ROUTES,
  // Preserve a non-recovery escape path if a target policy changes after an
  // already-atomic tenant rotation and restricts the newly loaded session.
  "/v1/session/switch-tenant",
  "/v1/auth/passkeys/step-up/options",
  "/v1/auth/passkeys/step-up/verify",
]);

const RECOVERY_LIMITED_ROUTES = new Set([
  "/v1/session",
  "/v1/auth/policy",
  "/v1/auth/logout",
  "/v1/auth/mfa/enrollment/start",
  "/v1/auth/mfa/enrollment/pending",
  "/v1/auth/mfa/enrollment/cancel",
  "/v1/auth/mfa/enrollment/confirm",
  "/v1/auth/passkeys",
  "/v1/auth/passkeys/registration/options",
  "/v1/auth/passkeys/registration/verify",
]);
