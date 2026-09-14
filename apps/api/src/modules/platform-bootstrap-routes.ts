import { randomBytes, randomUUID } from "node:crypto";
import { hash } from "argon2";
import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import { ApiError } from "../lib/errors.js";
import { requireTrustedBrowserOrigin } from "../lib/browser-origin.js";
import { parseBody, respond } from "../lib/http.js";
import { publicCeremonyRateLimitKey } from "../lib/rate-limit-policy.js";
import {
  createSessionBinding,
  CSRF_COOKIE,
  SESSION_COOKIE,
  sha256,
} from "./auth-service.js";
import { normalizeEmail } from "./invitation-service.js";

const platformBootstrapAcceptanceRateLimitKey = publicCeremonyRateLimitKey("platform-bootstrap-accept", [
  { field: "token", format: "opaque-256" },
]);

const password = z.string().min(14).max(256)
  .refine((value) => /[a-z]/.test(value), "Password must contain a lowercase letter")
  .refine((value) => /[A-Z]/.test(value), "Password must contain an uppercase letter")
  .refine((value) => /\d/.test(value), "Password must contain a number")
  .refine((value) => /[^A-Za-z0-9]/.test(value), "Password must contain a symbol")
  .refine((value) => ![
    "password123!", "contraseña123!", "administrador123!", "nombramientos123!",
  ].includes(value.normalize("NFKC").toLocaleLowerCase("en-US")), "Password is too common");

export const platformBootstrapSchema = z.object({
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  email: z.string().trim().email().max(320),
  displayName: z.string().trim().min(2).max(120)
    .refine((value) => !/[\p{Cc}\p{Cf}]/u.test(value), "Display name contains unsupported control characters"),
  password,
}).strict().superRefine((value, context) => {
  const normalizedPassword = value.password.normalize("NFKC").toLocaleLowerCase("en-US");
  const emailLocalPart = value.email.split("@")[0]?.normalize("NFKC").toLocaleLowerCase("en-US") ?? "";
  const nameTokens = value.displayName.normalize("NFKC").toLocaleLowerCase("en-US").split(/[^\p{L}\p{N}]+/u)
    .filter((item) => item.length >= 4);
  if ((emailLocalPart.length >= 3 && normalizedPassword.includes(emailLocalPart))
      || nameTokens.some((item) => normalizedPassword.includes(item))) {
    context.addIssue({ code: "custom", path: ["password"], message: "Password must not contain the email or display name" });
  }
});

export async function registerPlatformBootstrapRoutes(app: FastifyInstance): Promise<void> {
  app.post("/v1/auth/platform-bootstrap/accept", {
    preHandler: [requireTrustedBrowserOrigin(app)],
    config: {
      rateLimit: {
        max: 3,
        timeWindow: "30 minutes",
        keyGenerator: platformBootstrapAcceptanceRateLimitKey,
      },
    },
  }, async (request, reply) => {
    const body = parseBody(platformBootstrapSchema, request);
    const passwordHash = await hash(body.password, {
      type: 2,
      memoryCost: 65_536,
      timeCost: 3,
      parallelism: 1,
    });
    const sessionToken = randomBytes(32).toString("base64url");
    const csrfToken = randomBytes(32).toString("base64url");
    const sessionId = randomUUID();
    const binding = createSessionBinding(request.headers["user-agent"], request.ip);
    const expiresAt = new Date(Date.now() + app.apiConfig.sessionTtlSeconds * 1_000);
    let accepted;
    try {
      accepted = await app.database.control.consumePlatformAdminBootstrap({
        tokenHash: sha256(body.token),
        email: body.email.trim().normalize("NFKC"),
        normalizedEmail: normalizeEmail(body.email),
        displayName: body.displayName.trim().normalize("NFKC").replace(/\s+/g, " "),
        passwordHash,
        identityId: randomUUID(),
        sessionId,
        sessionTokenHash: sha256(sessionToken),
        csrfHash: sha256(csrfToken),
        sessionExpiresAt: expiresAt,
        requestId: request.id,
        ...(binding.userAgentHash ? { userAgentHash: binding.userAgentHash } : {}),
        ...(binding.ipPrefixHash ? { ipPrefixHash: binding.ipPrefixHash } : {}),
      });
    } catch (error) {
      if (isBootstrapConflict(error)) throw invalidBootstrap();
      throw error;
    }
    if (!accepted) throw invalidBootstrap();

    const principal = await app.database.getPrincipal(sha256(sessionToken), request.id, binding);
    if (!principal || principal.sessionId !== accepted.sessionId || !principal.enrollmentOnly || !principal.mfaRequired) {
      await app.database.control.revokeSession(accepted.sessionId, "platform_bootstrap_context_failed");
      throw new Error("Platform bootstrap session could not be loaded with enrollment-only assurance");
    }
    setSessionCookies(app, reply, sessionToken, csrfToken, expiresAt);
    reply.header("cache-control", "no-store");
    reply.header("pragma", "no-cache");
    return respond(request, reply, {
      ...app.authService.publicSession(principal, csrfToken, null),
      contentAccess: false,
      keyAccess: false,
    }, 201);
  });
}

function setSessionCookies(
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

function invalidBootstrap(): ApiError {
  return new ApiError(400, "PLATFORM_BOOTSTRAP_INVALID", "Platform administrator activation is invalid or unavailable");
}

function isBootstrapConflict(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error
    && ["23505", "23514", "40001"].includes(String(error.code));
}
