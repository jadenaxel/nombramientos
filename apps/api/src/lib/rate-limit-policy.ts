import { createHash } from "node:crypto";
import type { FastifyRequest } from "fastify";

const opaque256Pattern = /^[A-Za-z0-9_-]{43}$/u;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const rateLimitNamespacePattern = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u;

type PublicCeremonyIdentityCandidate = {
  readonly field: string;
  readonly format: "opaque-256" | "uuid";
};

/**
 * A normal browser session gets the original request budget. The aggregate
 * identity and IP ceilings are deliberately higher so unrelated people behind
 * an enterprise NAT do not consume one another's budget, while one identity or
 * source still cannot create unbounded work for the API.
 */
export const DEFAULT_SECURITY_RATE_LIMIT_POLICY = Object.freeze({
  sessionOrAnonymousMax: 240,
  aggregateIdentityMax: 1_200,
  aggregateIpMax: 2_400,
  timeWindow: "1 minute",
});

export type SecurityRateLimitPolicy = {
  readonly sessionOrAnonymousMax: number;
  readonly aggregateIdentityMax: number;
  readonly aggregateIpMax: number;
  readonly timeWindow: number | string;
};

/** Fallback and low-volume public ceremony budgets remain scoped to source IP. */
export function ipRateLimitKey(request: FastifyRequest): string {
  return `ip:${request.ip}`;
}

/**
 * `principal` is populated only after the opaque session cookie has been
 * resolved through DatabaseRuntime.getPrincipal with its UA/IP binding. A raw
 * client-supplied cookie is never a rate-limit identity.
 */
export function verifiedSessionOrIdentityOrIpRateLimitKey(request: FastifyRequest): string {
  if (!request.principal) return ipRateLimitKey(request);
  // An explicit route budget protects a security-sensitive operation across
  // all of the identity's sessions. The ordinary global budget is per bound
  // session so parallel users and devices do not interfere with one another.
  const routeRateLimit = request.routeOptions.config.rateLimit;
  return routeRateLimit
    ? opaqueRateLimitKey("identity", request.principal.identityId)
    : opaqueRateLimitKey("session", request.principal.sessionId);
}

export function verifiedIdentityRateLimitKey(request: FastifyRequest): string {
  return request.principal
    ? opaqueRateLimitKey("aggregate-identity", request.principal.identityId)
    : ipRateLimitKey(request);
}

export function aggregateIpRateLimitKey(request: FastifyRequest): string {
  return `aggregate-ip:${request.ip}`;
}

/**
 * Login identifiers are canonicalized and pseudonymized before entering the
 * in-memory limiter. The key is identity-wide across source IPs; the
 * aggregate IP ceiling independently constrains identifier-rotation floods.
 */
export function loginIdentifierRateLimitKey(request: FastifyRequest): string {
  const normalized = normalizedLoginIdentifier(request);
  if (!normalized) return ipRateLimitKey(request);
  return `login-identifier:${digestRateLimitMaterial(normalized)}`;
}

/**
 * Builds a public-ceremony key from the first valid body credential. Only a
 * SHA-256 digest enters the limiter; malformed or absent credentials stay in
 * the source-IP bucket instead of becoming attacker-chosen identities.
 *
 * Candidate order is significant. Put a stable identifier first when a
 * one-time bearer may be omitted on a response-loss retry.
 */
export function publicCeremonyRateLimitKey(
  namespace: string,
  candidates: readonly PublicCeremonyIdentityCandidate[],
): (request: FastifyRequest) => string {
  if (!rateLimitNamespacePattern.test(namespace) || candidates.length === 0) {
    throw new Error("Public ceremony rate-limit key configuration is invalid");
  }
  const configuredCandidates = candidates.map((candidate) => ({ ...candidate }));
  return (request) => {
    const body = request.body;
    if (typeof body !== "object" || body === null) return ipRateLimitKey(request);
    for (const candidate of configuredCandidates) {
      const value = (body as Record<string, unknown>)[candidate.field];
      const normalized = normalizePublicCeremonyIdentity(value, candidate.format);
      if (normalized !== null) return opaqueRateLimitKey(namespace, normalized);
    }
    return ipRateLimitKey(request);
  };
}

/**
 * Discoverable/conditional passkey flows intentionally have no identifier.
 * Give an enterprise NAT enough room for office-wide sign-in discovery while
 * retaining the independent 2,400-request/minute aggregate source ceiling.
 */
export function passkeyAuthenticationOptionsRateLimitMax(request: FastifyRequest): number {
  return normalizedLoginIdentifier(request) ? 12 : 1_200;
}

export function opaqueRateLimitKey(namespace: string, value: string): string {
  return `${namespace}:${digestRateLimitMaterial(value)}`;
}

function digestRateLimitMaterial(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizePublicCeremonyIdentity(
  value: unknown,
  format: PublicCeremonyIdentityCandidate["format"],
): string | null {
  if (typeof value !== "string") return null;
  if (format === "opaque-256") return opaque256Pattern.test(value) ? value : null;
  return uuidPattern.test(value) ? value.toLocaleLowerCase("en-US") : null;
}

function normalizedLoginIdentifier(request: FastifyRequest): string | null {
  const body = request.body;
  const email = typeof body === "object" && body !== null && "email" in body
    ? (body as { readonly email?: unknown }).email
    : undefined;
  if (typeof email !== "string" || email.length < 1 || email.length > 320) return null;
  const normalized = email.trim().normalize("NFKC").toLocaleLowerCase("en-US");
  return normalized.length >= 1 && normalized.length <= 320 ? normalized : null;
}
