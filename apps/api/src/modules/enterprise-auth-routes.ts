import type { FastifyInstance, FastifyReply } from "fastify";
import { requireTrustedBrowserOrigin } from "../lib/browser-origin.js";
import {
  ipRateLimitKey,
  loginIdentifierRateLimitKey,
  opaqueRateLimitKey,
  passkeyAuthenticationOptionsRateLimitMax,
} from "../lib/rate-limit-policy.js";
import { ApiError, unauthorized } from "../lib/errors.js";
import { parseBody, parseParams, respond } from "../lib/http.js";
import {
  requireGovernedOperationStepUp,
  requireOperationStepUp,
} from "../lib/operation-step-up.js";
import {
  asAuthenticationResponse,
  asRegistrationResponse,
  identityPolicyUpdateSchema,
  passkeyAuthenticationOptionsSchema,
  passkeyAuthenticationVerificationSchema,
  passkeyNameSchema,
  passkeyRegistrationOptionsSchema,
  passkeyRegistrationVerificationSchema,
  passkeyRevocationSchema,
  resourceIdSchema,
  sessionRevocationSchema,
  stepUpOptionsSchema,
  stepUpVerificationSchema,
} from "./enterprise-auth-contract.js";
import {
  CSRF_COOKIE,
  SESSION_COOKIE,
} from "./auth-service.js";
import { clearCookie, setSessionCookies } from "./auth-routes.js";
import {
  openWebAuthnCeremonyCookie,
  sealWebAuthnCeremonyCookie,
  webAuthnCeremonyCookieName,
  webAuthnCeremonyCookiePath,
  type WebAuthnCeremonyCookieType,
} from "./webauthn-ceremony-cookie.js";

export async function registerEnterpriseAuthRoutes(app: FastifyInstance): Promise<void> {
  const authenticationCeremonyRateLimitKey = (request: Parameters<typeof ipRateLimitKey>[0]): string => {
    const body = request.body;
    const ceremonyId = typeof body === "object" && body !== null && "ceremonyId" in body
      ? (body as { readonly ceremonyId?: unknown }).ceremonyId
      : undefined;
    if (typeof ceremonyId !== "string") return ipRateLimitKey(request);
    let cookieName: string;
    try {
      cookieName = webAuthnCeremonyCookieName(ceremonyId);
    } catch {
      return ipRateLimitKey(request);
    }
    const ceremonyToken = openWebAuthnCeremonyCookie({
      value: request.cookies[cookieName],
      ceremonyId,
      ceremonyType: "authentication",
      encryptionKey: app.apiConfig.authEncryptionKey,
    });
    return ceremonyToken
      ? opaqueRateLimitKey("webauthn-authentication", ceremonyToken)
      : ipRateLimitKey(request);
  };

  app.get("/v1/auth/policy", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    return respond(request, reply, await app.enterpriseAuthService.getEffectivePolicy(request.principal));
  });

  app.patch("/v1/auth/policy", {
    preHandler: [
      app.authenticate,
      app.verifyCsrf,
      app.requirePermission("tenant.settings.manage"),
      requireOperationStepUp("tenant_administration"),
    ],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const body = parseBody(identityPolicyUpdateSchema, request);
    return respond(request, reply, await app.enterpriseAuthService.updateIdentityPolicy({
      principal: request.principal,
      expectedVersion: body.expectedVersion,
      policy: body.policy,
      requestId: request.id,
    }));
  });

  app.post("/v1/auth/passkeys/authentication/options", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: {
      rateLimit: {
        max: passkeyAuthenticationOptionsRateLimitMax,
        timeWindow: "5 minutes",
        keyGenerator: loginIdentifierRateLimitKey,
      },
    },
  }, async (request, reply) => {
    const body = parseBody(passkeyAuthenticationOptionsSchema, request);
    const result = await app.enterpriseAuthService.authenticationOptions({
      ...(body.email ? { email: body.email } : {}),
      mediation: body.mediation,
      ...(request.headers.origin ? { origin: request.headers.origin } : {}),
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    setWebAuthnCookie(app, reply, {
      ceremonyId: result.ceremonyId,
      ceremonyType: "authentication",
      ceremonyToken: result.ceremonyToken,
      expiresAt: result.expiresAt,
    });
    const { ceremonyToken: _ceremonyToken, ...publicResult } = result;
    return respond(request, reply, publicResult, 201);
  });

  app.post("/v1/auth/passkeys/authentication/verify", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: { rateLimit: { max: 8, timeWindow: "5 minutes", keyGenerator: authenticationCeremonyRateLimitKey } },
  }, async (request, reply) => {
    const body = parseBody(passkeyAuthenticationVerificationSchema, request);
    const ceremonyCookieName = webAuthnCeremonyCookieName(body.ceremonyId);
    const ceremonyToken = requireCeremonyCookie(app, request.cookies[ceremonyCookieName], {
      ceremonyId: body.ceremonyId,
      ceremonyType: "authentication",
    });
    const result = await app.enterpriseAuthService.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      ceremonyToken,
      response: asAuthenticationResponse(body.response),
      requestId: request.id,
      ...(request.headers.origin ? { origin: request.headers.origin } : {}),
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    clearCookie(app, reply, ceremonyCookieName, webAuthnCeremonyCookiePath());
    setSessionCookies(app, reply, result.sessionToken, result.csrfToken, result.expiresAt);
    const { sessionToken: _sessionToken, ...publicResult } = result;
    return respond(request, reply, publicResult);
  });

  app.post("/v1/auth/passkeys/registration/options", {
    preHandler: [requireTrustedBrowserOrigin(app), app.authenticate, app.verifyCsrf],
    config: { rateLimit: { max: 6, timeWindow: "15 minutes" } },
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const body = parseBody(passkeyRegistrationOptionsSchema, request);
    const result = await app.enterpriseAuthService.registrationOptions({
      principal: request.principal,
      requestId: request.id,
      ...(body.replacementCredentialId
        ? { replacementCredentialId: body.replacementCredentialId }
        : {}),
      ...(typeof request.headers["x-step-up-grant"] === "string"
        ? { grantToken: request.headers["x-step-up-grant"] }
        : {}),
      ...(request.headers.origin ? { origin: request.headers.origin } : {}),
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    setWebAuthnCookie(app, reply, {
      ceremonyId: result.ceremonyId,
      ceremonyType: "registration",
      ceremonyToken: result.ceremonyToken,
      expiresAt: result.expiresAt,
    });
    const { ceremonyToken: _ceremonyToken, ...publicResult } = result;
    return respond(request, reply, publicResult, 201);
  });

  app.post("/v1/auth/passkeys/registration/verify", {
    preHandler: [requireTrustedBrowserOrigin(app), app.authenticate, app.verifyCsrf],
    config: { rateLimit: { max: 6, timeWindow: "15 minutes" } },
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const body = parseBody(passkeyRegistrationVerificationSchema, request);
    const ceremonyCookieName = webAuthnCeremonyCookieName(body.ceremonyId);
    const ceremonyToken = requireCeremonyCookie(app, request.cookies[ceremonyCookieName], {
      ceremonyId: body.ceremonyId,
      ceremonyType: "registration",
    });
    const result = await app.enterpriseAuthService.verifyRegistration({
      principal: request.principal,
      ceremonyId: body.ceremonyId,
      ceremonyToken,
      response: asRegistrationResponse(body.response),
      displayName: body.name,
      requestId: request.id,
      ...(request.headers.origin ? { origin: request.headers.origin } : {}),
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    clearCookie(app, reply, ceremonyCookieName, webAuthnCeremonyCookiePath());
    setSessionCookies(app, reply, result.session.sessionToken, result.session.csrfToken, result.session.expiresAt);
    const { sessionToken: _sessionToken, ...publicSession } = result.session;
    return respond(request, reply, {
      verified: true,
      credential: result.credential,
      session: publicSession,
    }, 201);
  });

  app.post("/v1/auth/passkeys/step-up/options", {
    preHandler: [requireTrustedBrowserOrigin(app), app.authenticate, app.verifyCsrf],
    config: { rateLimit: { max: 8, timeWindow: "5 minutes" } },
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const body = parseBody(stepUpOptionsSchema, request);
    const result = await app.enterpriseAuthService.stepUpOptions({
      principal: request.principal,
      purpose: body.purpose,
      operationHash: body.operationHash,
      ...(request.headers.origin ? { origin: request.headers.origin } : {}),
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    setWebAuthnCookie(app, reply, {
      ceremonyId: result.ceremonyId,
      ceremonyType: "step_up",
      ceremonyToken: result.ceremonyToken,
      expiresAt: result.expiresAt,
    });
    const { ceremonyToken: _ceremonyToken, ...publicResult } = result;
    return respond(request, reply, publicResult, 201);
  });

  app.post("/v1/auth/passkeys/step-up/verify", {
    preHandler: [requireTrustedBrowserOrigin(app), app.authenticate, app.verifyCsrf],
    config: { rateLimit: { max: 8, timeWindow: "5 minutes" } },
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const body = parseBody(stepUpVerificationSchema, request);
    const ceremonyCookieName = webAuthnCeremonyCookieName(body.ceremonyId);
    const ceremonyToken = requireCeremonyCookie(app, request.cookies[ceremonyCookieName], {
      ceremonyId: body.ceremonyId,
      ceremonyType: "step_up",
    });
    const result = await app.enterpriseAuthService.verifyStepUp({
      principal: request.principal,
      ceremonyId: body.ceremonyId,
      ceremonyToken,
      response: asAuthenticationResponse(body.response),
      requestId: request.id,
      ...(request.headers.origin ? { origin: request.headers.origin } : {}),
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    clearCookie(app, reply, ceremonyCookieName, webAuthnCeremonyCookiePath());
    return respond(request, reply, result);
  });

  app.get("/v1/auth/passkeys", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    return respond(request, reply, {
      items: await app.enterpriseAuthService.listPasskeys(request.principal.identityId),
    });
  });

  app.patch("/v1/auth/passkeys/:id", {
    preHandler: [app.authenticate, app.verifyCsrf],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const params = parseParams(resourceIdSchema, request);
    const body = parseBody(passkeyNameSchema, request);
    return respond(request, reply, await app.enterpriseAuthService.renamePasskey({
      principal: request.principal,
      credentialId: params.id,
      displayName: body.name,
      expectedVersion: body.expectedVersion,
      requestId: request.id,
    }));
  });

  app.delete("/v1/auth/passkeys/:id", {
    preHandler: [app.authenticate, app.verifyCsrf, requireGovernedOperationStepUp({
      action: "auth.passkey.revoke",
      purpose: "identity_security_change",
    })],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const params = parseParams(resourceIdSchema, request);
    const body = parseBody(passkeyRevocationSchema, request);
    const result = await app.enterpriseAuthService.revokePasskey({
      principal: request.principal,
      credentialId: params.id,
      reason: body.reason,
      requestId: request.id,
    });
    if (result.currentSessionRevoked) clearSessionCookies(app, reply);
    const { currentSessionRevoked, ...publicResult } = result;
    return respond(request, reply, { ...publicResult, signedOut: currentSessionRevoked });
  });

  await registerSessionManagementRoutes(app);
}

/**
 * Session self-management remains available with GestionChurch SSO. Register
 * only these routes in module mode: exposing this surface must not activate
 * Nombramientos' standalone password, passkey or MFA enrollment endpoints.
 * Authentication, device proof and the same ownership/CSRF boundaries still
 * apply; only the identity-provider step-up policy is delegated.
 */
export async function registerSessionManagementRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/auth/sessions", { preHandler: [app.authenticate] }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const items = await app.enterpriseAuthService.listSessions(request.principal);
    const labels = request.principal.tenantKind === "real"
      ? await app.database.withDeviceSessionPrincipal(request.principal, request.id,
        (store) => store.getOwnSessionLabels(request.principal!.identityId, items.map((item) => item.id)))
      : new Map<string, string>();
    return respond(request, reply, {
      items: items.map((item) => labels.has(item.id) ? { ...item, deviceLabel: labels.get(item.id)! } : item),
    });
  });

  app.delete("/v1/auth/sessions/:id", {
    preHandler: [app.authenticate, app.verifyCsrf, requireOperationStepUp("session_revocation")],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const params = parseParams(resourceIdSchema, request);
    parseBody(sessionRevocationSchema, request);
    const result = await app.enterpriseAuthService.revokeSession({
      principal: request.principal,
      sessionId: params.id,
      requestId: request.id,
    });
    if (result.current) clearSessionCookies(app, reply);
    return respond(request, reply, result);
  });

  app.post("/v1/auth/sessions/revoke-others", {
    preHandler: [app.authenticate, app.verifyCsrf, requireGovernedOperationStepUp({
      action: "auth.session.revoke_others",
      purpose: "session_revocation",
    })],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    parseBody(sessionRevocationSchema, request);
    return respond(request, reply, await app.enterpriseAuthService.revokeOtherSessions({
      principal: request.principal,
      requestId: request.id,
    }));
  });
}

function setWebAuthnCookie(app: FastifyInstance, reply: FastifyReply, input: {
  readonly ceremonyId: string;
  readonly ceremonyType: WebAuthnCeremonyCookieType;
  readonly ceremonyToken: string;
  readonly expiresAt: Date;
}): void {
  const cookieName = webAuthnCeremonyCookieName(input.ceremonyId);
  const remainingSeconds = Math.max(1, Math.ceil((input.expiresAt.getTime() - Date.now()) / 1_000));
  reply.setCookie(cookieName, sealWebAuthnCeremonyCookie({
    ...input,
    encryptionKey: app.apiConfig.authEncryptionKey,
  }), {
    httpOnly: true,
    secure: app.apiConfig.secureCookies,
    sameSite: "strict",
    path: webAuthnCeremonyCookiePath(),
    maxAge: remainingSeconds,
  });
}

function requireCeremonyCookie(
  app: FastifyInstance,
  value: string | undefined,
  expected: {
    readonly ceremonyId: string;
    readonly ceremonyType: WebAuthnCeremonyCookieType;
  },
): string {
  const token = openWebAuthnCeremonyCookie({
    value,
    ...expected,
    encryptionKey: app.apiConfig.authEncryptionKey,
  });
  if (!token) throw new ApiError(401, "WEBAUTHN_CEREMONY_INVALID", "WebAuthn ceremony is missing or expired");
  return token;
}

function clearSessionCookies(app: FastifyInstance, reply: FastifyReply): void {
  clearCookie(app, reply, SESSION_COOKIE, "/");
  clearCookie(app, reply, CSRF_COOKIE, "/");
}
