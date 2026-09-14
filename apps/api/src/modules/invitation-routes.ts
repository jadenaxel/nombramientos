import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { TENANT_INVITATION_ROLES } from "@nombramientos/database";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApiError, unauthorized } from "../lib/errors.js";
import { requireTrustedBrowserOrigin } from "../lib/browser-origin.js";
import { ipRateLimitKey, publicCeremonyRateLimitKey } from "../lib/rate-limit-policy.js";
import { parseBody, parseParams, parseQuery, requireIdempotencyKey, respond } from "../lib/http.js";
import { requirePolicyAwareOperationStepUp } from "../lib/operation-step-up.js";
import { invitationRevokeReasonCodeSchema } from "../lib/reason-code.js";
import { setSessionCookies } from "./auth-routes.js";
import { normalizeEmail } from "./invitation-service.js";

export const INVITATION_RECOVERY_COOKIE_PREFIX = "nom_invitation_recovery_";
const INVITATION_RECOVERY_TTL_SECONDS = 24 * 60 * 60;
const MAX_INVITATION_RECOVERY_PROOFS_PER_BATCH = 12;
const MAX_COOKIE_HEADER_BYTES = 8_192;
const MAX_PARSED_COOKIES = 64;
const recoveryProofPattern = /^[A-Za-z0-9_-]{43}$/u;
const recoveryCookieNamePattern = /^nom_invitation_recovery_[A-Za-z0-9_-]{22}$/u;
const invitationAcceptanceRateLimitKey = publicCeremonyRateLimitKey("invitation-accept", [
  { field: "token", format: "opaque-256" },
]);

const uuid = z.string().uuid();
const email = z.string().trim().email().max(320);
const role = z.enum(TENANT_INVITATION_ROLES);
const createInvitationSchema = z.object({
  email,
  roles: z.array(role).min(1).max(3).refine((roles) => new Set(roles).size === roles.length, "Roles must be unique"),
  expiresInHours: z.number().int().min(1).max(168).default(48),
}).strict();
const listInvitationsSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
}).strict();
export const revokeInvitationSchema = z.object({
  reasonCode: invitationRevokeReasonCodeSchema.optional(),
}).strict();
const password = z.string().min(14).max(256)
  .refine((value) => /[a-z]/.test(value), "Password must contain a lowercase letter")
  .refine((value) => /[A-Z]/.test(value), "Password must contain an uppercase letter")
  .refine((value) => /\d/.test(value), "Password must contain a number")
  .refine((value) => /[^A-Za-z0-9]/.test(value), "Password must contain a symbol")
  .refine((value) => ![
    "password123!", "contraseña123!", "administrador123!", "nombramientos123!",
  ].includes(value.normalize("NFKC").toLocaleLowerCase("en-US")), "Password is too common");
const acceptInvitationSchema = z.object({
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  email,
  displayName: z.string().trim().min(2).max(120)
    .refine((value) => !/[\p{Cc}\p{Cf}]/u.test(value), "Display name contains unsupported control characters"),
  password: password.optional(),
}).strict().superRefine((value, context) => {
  if (value.password === undefined) return;
  const normalizedPassword = value.password.normalize("NFKC").toLocaleLowerCase("en-US");
  const emailLocalPart = value.email.split("@")[0]?.normalize("NFKC").toLocaleLowerCase("en-US") ?? "";
  const nameTokens = value.displayName.normalize("NFKC").toLocaleLowerCase("en-US").split(/[^\p{L}\p{N}]+/u)
    .filter((item) => item.length >= 4);
  if ((emailLocalPart.length >= 3 && normalizedPassword.includes(emailLocalPart))
      || nameTokens.some((item) => normalizedPassword.includes(item))) {
    context.addIssue({ code: "custom", path: ["password"], message: "Password must not contain the email or display name" });
  }
});

export async function registerInvitationRoutes(app: FastifyInstance): Promise<void> {
  app.post("/v1/invitations/recovery-context", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: { rateLimit: { max: 1_200, timeWindow: "15 minutes", keyGenerator: ipRateLimitKey } },
  }, async (request, reply) => {
    // This deliberately accepts no invitation material.  It establishes a
    // browser-held possession secret before any acceptance can mutate either
    // database, so an ambiguous/lost acceptance response remains recoverable
    // after a tab or browser restart without making the invitation link alone
    // a post-acceptance bearer.
    parseBody(z.object({}).strict(), request);
    const existing = invitationRecoveryRoots(request, app.apiConfig.authEncryptionKey);
    const contexts = existing.length > 0
      ? existing
      : [newInvitationRecoveryRoot(app.apiConfig.authEncryptionKey)];
    reply.header("cache-control", "no-store");
    for (const context of contexts) setInvitationRecoveryCookie(app, reply, context);
    return respond(request, reply, { prepared: true });
  });

  app.post("/v1/invitations/accept", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: { rateLimit: { max: 6, timeWindow: "15 minutes", keyGenerator: invitationAcceptanceRateLimitKey } },
  }, async (request, reply) => {
    const body = parseBody(acceptInvitationSchema, request);
    reply.header("cache-control", "no-store");
    const recoveryRoots = invitationRecoveryRoots(request, app.apiConfig.authEncryptionKey);
    if (recoveryRoots.length === 0) {
      throw new ApiError(
        428,
        "INVITATION_RECOVERY_CONTEXT_REQUIRED",
        "A secure invitation recovery context must be established before acceptance",
      );
    }
    const normalizedEmail = normalizeEmail(body.email);
    const invitationRecoveryProofs = recoveryRoots.map(({ rootSecret }) =>
      deriveInvitationRecoveryProof(rootSecret, body.token, normalizedEmail));
    const [recoveryProofs, ...additionalRecoveryProofBatches] = chunkRecoveryProofs(invitationRecoveryProofs);
    const result = await app.invitationService.accept({
      token: body.token,
      recoveryProofs: recoveryProofs!,
      ...(additionalRecoveryProofBatches.length === 0 ? {} : { additionalRecoveryProofBatches }),
      email: body.email,
      displayName: body.displayName,
      ...(body.password === undefined ? {} : { password: body.password }),
      requestId: request.id,
      ...(request.headers["user-agent"] ? { userAgent: request.headers["user-agent"] } : {}),
      ip: request.ip,
    });
    setSessionCookies(app, reply, result.sessionToken, result.csrfToken, result.expiresAt);
    const { sessionToken: _sessionToken, ...publicResult } = result;
    return respond(request, reply, publicResult, 201);
  });

  app.post("/v1/invitations", {
    preHandler: invitationMutation(app),
  }, async (request, reply) => {
    const body = parseBody(createInvitationSchema, request);
    const principal = requirePrincipal(request);
    const result = await app.invitationService.create({
      principal,
      ...body,
      idempotencyKey: requireIdempotencyKey(request),
      requestId: request.id,
    });
    reply.header("cache-control", "no-store");
    return respond(request, reply, result, result.created ? 201 : 200);
  });

  app.get("/v1/invitations", {
    preHandler: invitationRead(app),
  }, async (request, reply) => {
    const { limit } = parseQuery(listInvitationsSchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.invitationService.list(requirePrincipal(request), limit));
  });

  app.post("/v1/invitations/:invitationId/revoke", {
    preHandler: invitationMutation(app),
  }, async (request, reply) => {
    const { invitationId } = parseParams(z.object({ invitationId: uuid }).strict(), request);
    const body = parseBody(revokeInvitationSchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.invitationService.revoke({
      principal: requirePrincipal(request),
      invitationId,
      ...(body.reasonCode ? { reasonCode: body.reasonCode } : {}),
      requestId: request.id,
    }));
  });
}

export function deriveInvitationRecoveryProof(
  rootSecret: string,
  invitationToken: string,
  normalizedEmail: string,
): string {
  if (!recoveryProofPattern.test(rootSecret) || !recoveryProofPattern.test(invitationToken)) {
    throw new Error("Invitation recovery derivation input is invalid");
  }
  return createHmac("sha256", rootSecret)
    .update("nombramientos.invitation-recovery.v1\0", "utf8")
    .update(invitationToken, "utf8")
    .update("\0", "utf8")
    .update(normalizedEmail, "utf8")
    .digest("base64url");
}

interface InvitationRecoveryRoot {
  readonly cookieName: string;
  readonly rootSecret: string;
}

function newInvitationRecoveryRoot(serverKey: Buffer): InvitationRecoveryRoot {
  const rootSecret = randomBytes(32).toString("base64url");
  return { cookieName: invitationRecoveryCookieName(serverKey, rootSecret), rootSecret };
}

function invitationRecoveryCookieName(serverKey: Buffer, rootSecret: string): string {
  const identifier = createHmac("sha256", serverKey)
    .update("nombramientos.invitation-recovery-cookie.v1\0", "utf8")
    .update(rootSecret, "utf8")
    .digest()
    .subarray(0, 16)
    .toString("base64url");
  return `${INVITATION_RECOVERY_COOKIE_PREFIX}${identifier}`;
}

function invitationRecoveryRoots(request: FastifyRequest, serverKey: Buffer): InvitationRecoveryRoot[] {
  const rawCookieHeader = request.headers.cookie;
  if (typeof rawCookieHeader === "string" && Buffer.byteLength(rawCookieHeader, "utf8") > MAX_COOKIE_HEADER_BYTES) {
    throw new ApiError(428, "INVITATION_RECOVERY_CONTEXT_OVERFLOW", "Invitation recovery cookie input is excessive");
  }
  const cookieNames = Object.keys(request.cookies);
  if (cookieNames.length > MAX_PARSED_COOKIES) {
    throw new ApiError(428, "INVITATION_RECOVERY_CONTEXT_OVERFLOW", "Invitation recovery cookie input is excessive");
  }
  const shaped = cookieNames.flatMap((cookieName): [string, string][] => {
    const rootSecret = request.cookies[cookieName];
    return recoveryCookieNamePattern.test(cookieName)
      && typeof rootSecret === "string"
      && recoveryProofPattern.test(rootSecret)
      ? [[cookieName, rootSecret]]
      : [];
  });
  return shaped
    .filter(([cookieName, rootSecret]) => {
      const expected = Buffer.from(invitationRecoveryCookieName(serverKey, rootSecret), "utf8");
      const actual = Buffer.from(cookieName, "utf8");
      return expected.byteLength === actual.byteLength && timingSafeEqual(expected, actual);
    })
    .map(([cookieName, rootSecret]) => ({ cookieName, rootSecret }))
    .sort((left, right) => left.cookieName.localeCompare(right.cookieName, "en-US"));
}

function setInvitationRecoveryCookie(
  app: FastifyInstance,
  reply: FastifyReply,
  context: InvitationRecoveryRoot,
): void {
  reply.setCookie(context.cookieName, context.rootSecret, {
    httpOnly: true,
    secure: app.apiConfig.secureCookies,
    sameSite: "strict",
    path: "/v1/invitations",
    maxAge: INVITATION_RECOVERY_TTL_SECONDS,
  });
}

function chunkRecoveryProofs(proofs: readonly string[]): string[][] {
  const batches: string[][] = [];
  for (let index = 0; index < proofs.length; index += MAX_INVITATION_RECOVERY_PROOFS_PER_BATCH) {
    batches.push(proofs.slice(index, index + MAX_INVITATION_RECOVERY_PROOFS_PER_BATCH));
  }
  return batches;
}

function invitationRead(app: FastifyInstance) {
  return [app.authenticate, app.requirePermission("role.manage")];
}

function invitationMutation(app: FastifyInstance) {
  return [
    app.authenticate,
    app.verifyCsrf,
    app.requirePermission("role.manage"),
    requirePolicyAwareOperationStepUp({
      action: "role.administration",
      purpose: "role_administration",
      recentMfaPurpose: "managing tenant invitations",
    }),
  ];
}

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}
