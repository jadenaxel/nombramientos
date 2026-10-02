import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import type { FastifyRequest } from "fastify";
import { ApiError, unauthorized } from "./errors.js";
import { assertRecentMfa, hasSessionContextRisk } from "./recent-mfa.js";
import {
  hashStepUpOperation,
  type StepUpPurpose,
} from "../modules/enterprise-auth-contract.js";
import { sha256 } from "../modules/auth-service.js";

export async function assertOperationStepUp(input: {
  readonly database: DatabaseRuntime;
  readonly principal: RequestPrincipal;
  readonly grantToken: string | undefined;
  readonly purpose: StepUpPurpose;
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
}): Promise<void> {
  if (input.principal.authMethod === "federated") return;
  if (["enrollment_only", "recovery_limited"].includes(input.principal.assuranceLevel)) {
    throw new ApiError(403, "RECOVERY_RESTRICTED", "A recovery or enrollment session cannot authorize privileged operations");
  }
  const operationHash = hashStepUpOperation(input.purpose, input.method, input.path, input.body);
  if (!input.grantToken || input.grantToken.length < 32 || input.grantToken.length > 256) {
    throw stepUpRequired(input.purpose, operationHash);
  }
  const consumed = await input.database.enterpriseAuth.consumeStepUpGrant({
    identityId: input.principal.identityId,
    sessionId: input.principal.sessionId,
    tokenHash: sha256(input.grantToken),
    purpose: input.purpose,
    operationHash,
  });
  if (!consumed) throw stepUpRequired(input.purpose, operationHash);
}

export async function assertPolicyAwareOperationStepUp(input: {
  readonly database: DatabaseRuntime;
  readonly principal: RequestPrincipal;
  readonly grantToken: string | undefined;
  readonly action: string;
  readonly purpose: StepUpPurpose;
  readonly recentMfaPurpose: string;
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly requestId?: string;
}): Promise<void> {
  if (input.principal.authMethod === "federated") return;
  const policy = await input.database.enterpriseAuth.getEffectiveIdentityPolicy(input.principal.activeTenantId);
  const requirement = policy.actionRequirements[input.action];
  const contextRisk = hasSessionContextRisk(input.principal);
  if (policy.enforcementMode !== "enforce" && !contextRisk) {
    assertRecentMfa(input.principal, { purpose: input.recentMfaPurpose });
    return;
  }

  // Every route that opts into this prehandler is a privileged mutation. The
  // tenant-wide privileged posture is therefore the floor even when a named
  // action has not yet been added to the baseline map; action-specific policy
  // may only tighten it.
  const minimumAal = Math.max(policy.privilegedMinimumAal, requirement?.minAal ?? 1);
  const requiresPasskey = policy.requirePhishingResistantForPrivileged
    || requirement?.stepUpRequired === true
    || requirement?.phishingResistant === true
    || contextRisk;
  const sessionAal = input.principal.aal ?? (input.principal.assuranceLevel === "mfa" ? 2 : 1);
  // A WebAuthn operation grant is AAL2. AAL3 must already be represented by
  // the authenticated session and is separately constrained by attestation.
  if (minimumAal > Math.max(sessionAal, requiresPasskey ? 2 : 0)) {
    throw new ApiError(403, "ACTION_ASSURANCE_REQUIRED", "The session cannot satisfy this operation's assurance policy");
  }
  if (!requiresPasskey) {
    assertRecentMfa(input.principal, { purpose: input.recentMfaPurpose });
    return;
  }
  try {
    await assertOperationStepUp(input);
  } catch (error) {
    if (contextRisk && input.requestId) {
      await input.database.control.appendAudit({
        actorIdentityId: input.principal.identityId,
        tenantId: input.principal.activeTenantId,
        action: "auth.session_risk_sensitive_operation_denied",
        entityType: "session",
        entityId: input.principal.sessionId,
        result: "denied",
        requestId: input.requestId,
        metadata: {
          action: input.action,
          purpose: input.purpose,
          userAgentContextChanged: input.principal.userAgentContextChanged === true,
          ipContextChanged: input.principal.ipContextChanged === true,
        },
      }).catch(() => undefined);
    }
    throw error;
  }
}

/**
 * Enforce the product-wide WebAuthn floor for high-risk mutations while still
 * honoring a named action requirement when an enforced tenant policy tightens
 * its minimum assurance. Neither monitor mode nor an omitted/looser action can
 * downgrade this boundary to TOTP.
 */
export async function assertGovernedOperationStepUp(input: {
  readonly database: DatabaseRuntime;
  readonly principal: RequestPrincipal;
  readonly grantToken: string | undefined;
  readonly action: string;
  readonly purpose: StepUpPurpose;
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
}): Promise<void> {
  if (input.principal.authMethod === "federated") return;
  const policy = await input.database.enterpriseAuth.getEffectiveIdentityPolicy(input.principal.activeTenantId);
  const requirement = policy.actionRequirements[input.action];
  if (policy.enforcementMode === "enforce") {
    const minimumAal = Math.max(policy.privilegedMinimumAal, requirement?.minAal ?? 1);
    const sessionAal = input.principal.aal ?? (input.principal.assuranceLevel === "mfa" ? 2 : 1);
    // The mandatory operation-bound WebAuthn grant supplies AAL2. A named AAL3
    // requirement therefore also needs an already-established AAL3 session.
    if (minimumAal > Math.max(sessionAal, 2)) {
      throw new ApiError(403, "ACTION_ASSURANCE_REQUIRED", "The session cannot satisfy this operation's assurance policy");
    }
  }
  await assertOperationStepUp(input);
}

/**
 * Require phishing-resistant authorization before committing a fallback-factor
 * replacement whenever the identity already has a passkey, or enforced policy
 * mandates a passkey posture. Bootstrap and recovery sessions remain able to
 * establish a strong factor because they have no usable passkey by definition.
 */
export function requireFactorChangeStepUp() {
  return async (request: FastifyRequest): Promise<void> => {
    if (!request.principal) throw unauthorized();
    if (["enrollment_only", "recovery_limited"].includes(request.principal.assuranceLevel)) return;
    const [policy, credentials] = await Promise.all([
      request.server.database.enterpriseAuth.getEffectiveIdentityPolicy(request.principal.activeTenantId),
      request.server.database.enterpriseAuth.listCredentials(request.principal.identityId),
    ]);
    const hasActivePasskey = credentials.some((credential) => credential.revokedAt === null);
    const actionRequirement = policy.actionRequirements["auth.mfa.enrollment"];
    const policyRequiresPasskey = hasSessionContextRisk(request.principal) || (
      policy.enforcementMode === "enforce" && (
        policy.minimumPasskeyCount > 0
        || policy.requirePhishingResistantForPrivileged
        || actionRequirement?.stepUpRequired === true
        || actionRequirement?.phishingResistant === true
      )
    );
    if (!hasActivePasskey && !policyRequiresPasskey) return;
    const header = request.headers["x-step-up-grant"];
    await assertOperationStepUp({
      database: request.server.database,
      principal: request.principal,
      grantToken: typeof header === "string" ? header : undefined,
      purpose: "identity_security_change",
      method: request.method,
      path: request.url,
      body: request.body,
    });
  };
}

/**
 * Consume a short-lived, one-use WebAuthn authorization bound to the exact
 * request method, path, body, identity, session, and declared purpose.
 */
export function requireOperationStepUp(purpose: StepUpPurpose) {
  return async (request: FastifyRequest): Promise<void> => {
    if (!request.principal) throw unauthorized();
    const header = request.headers["x-step-up-grant"];
    await assertOperationStepUp({
      database: request.server.database,
      principal: request.principal,
      grantToken: typeof header === "string" ? header : undefined,
      purpose,
      method: request.method,
      // Step-up grants are bound to an exact mutation. Protected routes do not
      // currently define query parameters, so reject every query string rather
      // than silently omitting potentially security-relevant inputs.
      path: request.url,
      body: request.body,
    });
  };
}

export function requirePolicyAwareOperationStepUp(options: {
  readonly action: string;
  readonly purpose: StepUpPurpose;
  readonly recentMfaPurpose: string;
}) {
  return async (request: FastifyRequest): Promise<void> => {
    if (!request.principal) throw unauthorized();
    const header = request.headers["x-step-up-grant"];
    await assertPolicyAwareOperationStepUp({
      database: request.server.database,
      principal: request.principal,
      grantToken: typeof header === "string" ? header : undefined,
      action: options.action,
      purpose: options.purpose,
      recentMfaPurpose: options.recentMfaPurpose,
      method: request.method,
      path: request.url,
      body: request.body,
      requestId: request.id,
    });
  };
}

export function requireGovernedOperationStepUp(options: {
  readonly action: string;
  readonly purpose: StepUpPurpose;
}) {
  return async (request: FastifyRequest): Promise<void> => {
    if (!request.principal) throw unauthorized();
    const header = request.headers["x-step-up-grant"];
    await assertGovernedOperationStepUp({
      database: request.server.database,
      principal: request.principal,
      grantToken: typeof header === "string" ? header : undefined,
      action: options.action,
      purpose: options.purpose,
      method: request.method,
      path: request.url,
      body: request.body,
    });
  };
}

function stepUpRequired(purpose: StepUpPurpose, operationHash: string): ApiError {
  return new ApiError(
    428,
    "WEBAUTHN_STEP_UP_REQUIRED",
    "A fresh passkey verification is required for this exact operation",
    { purpose, operationHash },
  );
}
