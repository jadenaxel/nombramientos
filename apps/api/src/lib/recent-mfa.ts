import type { RequestPrincipal } from "@nombramientos/database";
import type { FastifyRequest } from "fastify";
import { ApiError, unauthorized } from "./errors.js";

/**
 * A privileged operation must start close enough to the second-factor proof
 * that an unattended, long-lived browser session cannot perform it.
 */
export const RECENT_MFA_WINDOW_MS = 5 * 60_000;

export interface MfaRequirementOptions {
  readonly purpose: string;
  readonly now?: Date;
  readonly staleCode?: string;
  readonly staleMessage?: string;
}

export function hasSessionContextRisk(principal: RequestPrincipal): boolean {
  return principal.userAgentContextChanged === true || principal.ipContextChanged === true;
}

export function assertMfaAssurance(principal: RequestPrincipal, purpose: string): void {
  // GestionChurch is the identity provider for federated module sessions. The
  // suite-wide MFA policy will be enforced there when it is enabled; the
  // embedded module must not demand a second, local factor in the meantime.
  if (principal.authMethod === "federated") return;
  const strongAuthenticator = principal.authMethod === "passkey"
    ? principal.phishingResistant === true
    : principal.mfaEnabled;
  if (
    principal.assuranceLevel !== "mfa"
    || (principal.aal ?? 2) < 2
    || !strongAuthenticator
    || !principal.mfaVerifiedAt
  ) {
    throw new ApiError(403, "MFA_ASSURANCE_REQUIRED", `MFA verification is required for ${purpose}`);
  }
  if (hasSessionContextRisk(principal)) throw sessionRiskError(principal, purpose);
}

export function assertPhishingResistantAssurance(principal: RequestPrincipal, purpose: string): void {
  if (principal.authMethod === "federated") return;
  assertMfaAssurance(principal, purpose);
  if (principal.authMethod !== "passkey" || principal.phishingResistant !== true) {
    throw new ApiError(
      428,
      "PHISHING_RESISTANT_STEP_UP_REQUIRED",
      `A passkey verification is required for ${purpose}`,
      { purpose },
    );
  }
}

export function assertRecentMfa(principal: RequestPrincipal, options: MfaRequirementOptions): void {
  if (principal.authMethod === "federated") return;
  assertMfaAssurance(principal, options.purpose);
  const now = options.now ?? new Date();
  const verifiedAt = principal.mfaVerifiedAt!.getTime();
  if (!Number.isFinite(verifiedAt) || verifiedAt <= now.getTime() - RECENT_MFA_WINDOW_MS) {
    throw new ApiError(
      428,
      options.staleCode ?? "MFA_STEP_UP_REQUIRED",
      options.staleMessage ?? `Sign in again with password and MFA before ${options.purpose}`,
      { maxAgeSeconds: RECENT_MFA_WINDOW_MS / 1_000, purpose: options.purpose },
    );
  }
}

export function requireMfaAssurance(purpose: string) {
  return async (request: FastifyRequest): Promise<void> => {
    if (!request.principal) throw unauthorized();
    if (hasSessionContextRisk(request.principal)) await auditRiskDenial(request, purpose);
    assertMfaAssurance(request.principal, purpose);
  };
}

export function requireRecentMfa(purpose: string) {
  return async (request: FastifyRequest): Promise<void> => {
    if (!request.principal) throw unauthorized();
    if (hasSessionContextRisk(request.principal)) await auditRiskDenial(request, purpose);
    assertRecentMfa(request.principal, { purpose });
  };
}

function sessionRiskError(principal: RequestPrincipal, purpose: string): ApiError {
  return new ApiError(
    428,
    "SESSION_RISK_STEP_UP_REQUIRED",
    `A fresh phishing-resistant verification is required for ${purpose}`,
    {
      purpose,
      userAgentContextChanged: principal.userAgentContextChanged === true,
      ipContextChanged: principal.ipContextChanged === true,
    },
  );
}

async function auditRiskDenial(request: FastifyRequest, purpose: string): Promise<void> {
  const principal = request.principal;
  if (!principal) return;
  await request.server.database.control.appendAudit({
    actorIdentityId: principal.identityId,
    tenantId: principal.activeTenantId,
    action: "auth.session_risk_sensitive_operation_denied",
    entityType: "session",
    entityId: principal.sessionId,
    result: "denied",
    requestId: request.id,
    metadata: {
      purpose,
      userAgentContextChanged: principal.userAgentContextChanged === true,
      ipContextChanged: principal.ipContextChanged === true,
    },
  }).catch(() => undefined);
}
