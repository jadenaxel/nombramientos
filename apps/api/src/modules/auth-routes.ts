import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import { unauthorized } from "../lib/errors.js";
import { requireTrustedBrowserOrigin } from "../lib/browser-origin.js";
import { parseBody, respond } from "../lib/http.js";
import { requireFactorChangeStepUp } from "../lib/operation-step-up.js";
import {
  ipRateLimitKey,
  loginIdentifierRateLimitKey,
  opaqueRateLimitKey,
} from "../lib/rate-limit-policy.js";
import {
  CSRF_COOKIE,
  createMfaChallengeBinding,
  MFA_COOKIE,
  SESSION_COOKIE,
  sha256,
} from "./auth-service.js";

const opaque256Pattern = /^[A-Za-z0-9_-]{43}$/u;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

const loginSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(1).max(1_024),
});
const mfaSchema = z.object({
  challengeId: z.string().uuid(),
  code: z.string().regex(/^\d{6}$/).optional(),
  recoveryCode: z.string().trim().regex(/^(?:[A-Za-z2-7]{4}-){3}[A-Za-z2-7]{4}$/).optional(),
}).strict().superRefine((value, context) => {
  if (Number(Boolean(value.code)) + Number(Boolean(value.recoveryCode)) !== 1) {
    context.addIssue({ code: "custom", message: "Provide exactly one MFA verification method" });
  }
});
const enrollmentIdSchema = z.object({ enrollmentId: z.string().uuid() }).strict();
const enrollmentConfirmationSchema = enrollmentIdSchema.extend({ code: z.string().regex(/^\d{6}$/) }).strict();

export async function registerAuthRoutes(app: FastifyInstance): Promise<void> {
  const mfaRateLimitKey = async (request: Parameters<typeof ipRateLimitKey>[0]): Promise<string> => {
    const token = request.cookies[MFA_COOKIE];
    const body = request.body;
    const challengeId = typeof body === "object" && body !== null && "challengeId" in body
      ? (body as { readonly challengeId?: unknown }).challengeId
      : undefined;
    if (typeof token !== "string" || !opaque256Pattern.test(token)
      || typeof challengeId !== "string" || !uuidPattern.test(challengeId)) {
      return ipRateLimitKey(request);
    }
    const identityId = await app.database.control.resolveMfaRateLimitIdentity(
      sha256(token),
      challengeId,
      createMfaChallengeBinding(request.headers.origin, request.headers["user-agent"], request.ip),
    );
    return identityId
      ? opaqueRateLimitKey("mfa-identity", identityId)
      : ipRateLimitKey(request);
  };

  app.post("/v1/auth/login", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: { rateLimit: { max: 10, timeWindow: "15 minutes", keyGenerator: loginIdentifierRateLimitKey } },
  }, async (request, reply) => {
    const body = parseBody(loginSchema, request);
    const result = await app.authService.login({
      ...body,
      requestId: request.id,
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
      ...(request.headers.origin ? { origin: request.headers.origin } : {}),
    });
    reply.header("cache-control", "no-store");
    if (result.status === "mfa_required") {
      setMfaCookie(app, reply, result.challengeToken);
      return respond(request, reply, {
        status: result.status,
        challengeId: result.challengeId,
        expiresAt: result.expiresAt,
      });
    }
    setSessionCookies(app, reply, result.sessionToken, result.csrfToken, result.expiresAt);
    const { sessionToken: _sessionToken, ...publicResult } = result;
    return respond(request, reply, publicResult);
  });

  app.post("/v1/auth/mfa/verify", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: { rateLimit: { max: 8, timeWindow: "5 minutes", keyGenerator: mfaRateLimitKey } },
  }, async (request, reply) => {
    const body = parseBody(mfaSchema, request);
    const challengeToken = request.cookies[MFA_COOKIE];
    if (!challengeToken) throw unauthorized("MFA challenge is missing or expired");
    const result = await app.authService.verifyMfa({
      challengeToken,
      challengeId: body.challengeId,
      ...(body.code ? { code: body.code } : {}),
      ...(body.recoveryCode ? { recoveryCode: body.recoveryCode } : {}),
      requestId: request.id,
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
      ...(request.headers.origin ? { origin: request.headers.origin } : {}),
    });
    clearCookie(app, reply, MFA_COOKIE, "/v1/auth/mfa/verify");
    setSessionCookies(app, reply, result.sessionToken, result.csrfToken, result.expiresAt);
    const { sessionToken: _sessionToken, ...publicResult } = result;
    return respond(request, reply, publicResult);
  });

  app.post("/v1/auth/mfa/enrollment/start", {
    preHandler: [app.authenticate, app.verifyCsrf],
    config: { rateLimit: { max: 4, timeWindow: "15 minutes" } },
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    reply.header("cache-control", "no-store");
    reply.header("pragma", "no-cache");
    return respond(request, reply, await app.authService.startMfaEnrollment({
      principal: request.principal,
      requestId: request.id,
    }), 201);
  });

  app.get("/v1/auth/mfa/enrollment/pending", {
    preHandler: [app.authenticate],
    config: { rateLimit: { max: 12, timeWindow: "15 minutes" } },
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    reply.header("cache-control", "no-store");
    reply.header("pragma", "no-cache");
    return respond(request, reply, await app.authService.getPendingMfaEnrollment({
      principal: request.principal,
    }));
  });

  app.post("/v1/auth/mfa/enrollment/cancel", {
    preHandler: [app.authenticate, app.verifyCsrf],
    config: { rateLimit: { max: 6, timeWindow: "15 minutes" } },
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const body = parseBody(enrollmentIdSchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.authService.cancelMfaEnrollment({
      principal: request.principal,
      enrollmentId: body.enrollmentId,
      requestId: request.id,
    }));
  });

  app.post("/v1/auth/mfa/enrollment/confirm", {
    preHandler: [requireTrustedBrowserOrigin(app), app.authenticate, app.verifyCsrf, requireFactorChangeStepUp()],
    config: { rateLimit: { max: 6, timeWindow: "15 minutes" } },
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const body = parseBody(enrollmentConfirmationSchema, request);
    const result = await app.authService.confirmMfaEnrollment({
      principal: request.principal,
      enrollmentId: body.enrollmentId,
      code: body.code,
      requestId: request.id,
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    setSessionCookies(app, reply, result.sessionToken, result.csrfToken, result.expiresAt);
    const { sessionToken: _sessionToken, ...publicResult } = result;
    reply.header("cache-control", "no-store");
    reply.header("pragma", "no-cache");
    return respond(request, reply, publicResult);
  });

  app.post("/v1/auth/logout", {
    preHandler: [app.authenticate, app.verifyCsrf],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    await app.database.control.revokeSession(request.principal.sessionId, "user_logout");
    await app.database.control.appendAudit({
      actorIdentityId: request.principal.identityId,
      tenantId: request.principal.activeTenantId,
      action: "auth.logout",
      entityType: "session",
      entityId: request.principal.sessionId,
      result: "success",
      requestId: request.id,
    });
    clearCookie(app, reply, SESSION_COOKIE, "/");
    clearCookie(app, reply, CSRF_COOKIE, "/");
    return respond(request, reply, { loggedOut: true, status: "signed_out" });
  });

  app.get("/v1/session", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const csrfToken = request.cookies[CSRF_COOKIE];
    if (!csrfToken) throw unauthorized("Session CSRF binding is missing");
    const keyGrant = request.principal.enrollmentOnly
      || request.principal.recoveryLimited === true
      || request.principal.assuranceLevel === "recovery_limited"
      ? null
      : await app.database.withPrincipal(request.principal, request.id, (tenant) =>
          tenant.getKeyGrant(request.principal!.identityId));
    const passkeyCount = (await app.database.enterpriseAuth.listCredentials(request.principal.identityId))
      .filter((credential) => credential.revokedAt === null).length;
    reply.header("cache-control", "no-store");
    return respond(request, reply, app.authService.publicSession(request.principal, csrfToken, keyGrant, passkeyCount));
  });
}

export function setSessionCookies(
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

function setMfaCookie(app: FastifyInstance, reply: FastifyReply, token: string): void {
  reply.setCookie(MFA_COOKIE, token, {
    httpOnly: true,
    secure: app.apiConfig.secureCookies,
    sameSite: "strict",
    path: "/v1/auth/mfa/verify",
    maxAge: 5 * 60,
  });
}

export function clearCookie(app: FastifyInstance, reply: FastifyReply, name: string, path: string): void {
  reply.clearCookie(name, {
    httpOnly: name !== CSRF_COOKIE,
    secure: app.apiConfig.secureCookies,
    sameSite: name === MFA_COOKIE ? "strict" : "lax",
    path,
  });
}
