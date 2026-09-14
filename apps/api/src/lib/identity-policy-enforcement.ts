import type {
  DatabaseRuntime,
  EffectiveIdentityPolicy,
  RequestPrincipal,
} from "@nombramientos/database";

export interface IdentitySessionPolicyDecision {
  readonly policy: EffectiveIdentityPolicy;
  readonly principal: RequestPrincipal;
  readonly activePasskeyCount: number;
  readonly policyEligiblePasskeyCount: number;
  readonly policyRestricted: boolean;
  readonly findings: readonly string[];
}

/**
 * Re-evaluate identity policy for every authenticated session boundary.
 * Explicit authentication-method controls are active in both rollout modes;
 * AAL/passkey-count targets become blocking only in `enforce` mode.
 */
export async function evaluateIdentitySessionPolicy(
  database: DatabaseRuntime,
  principal: RequestPrincipal,
  knownPolicy?: EffectiveIdentityPolicy,
): Promise<IdentitySessionPolicyDecision> {
  const [policy, credentials] = await Promise.all([
    knownPolicy ?? database.enterpriseAuth.getEffectiveIdentityPolicy(principal.activeTenantId),
    database.enterpriseAuth.listCredentials(principal.identityId),
  ]);
  const activeCredentials = credentials.filter((credential) => credential.revokedAt === null);
  const activePasskeyCount = activeCredentials.length;
  const policyEligiblePasskeyCount = activeCredentials.filter((credential) =>
    credential.userVerified
    && (policy.allowSyncedPasskeys || credential.deviceType === "singleDevice")
  ).length;
  const aal = principal.aal ?? (principal.assuranceLevel === "mfa" ? 2 : 1);
  const method = principal.authMethod ?? fallbackAuthMethod(principal.assuranceLevel);
  const currentCredential = principal.authenticatedCredentialId
    ? activeCredentials.find((credential) => credential.id === principal.authenticatedCredentialId)
    : undefined;
  const findings: string[] = [];

  let activeControlViolation = false;
  // TOTP and recovery codes are continuations of a successfully verified
  // password challenge, not independent primary authentication methods.
  if (["password", "bootstrap", "totp", "recovery_code"].includes(method) && !policy.allowPassword) {
    findings.push("password_authentication_disabled");
    activeControlViolation = true;
  }
  if (method === "totp" && !policy.allowTotpFallback) {
    findings.push("totp_authentication_disabled");
    activeControlViolation = true;
  }
  if (method === "recovery_code" && !policy.allowRecoveryCodes) {
    findings.push("recovery_code_authentication_disabled");
    activeControlViolation = true;
  }
  if (
    method === "passkey"
    && !policy.allowSyncedPasskeys
    && (!currentCredential || currentCredential.deviceType !== "singleDevice")
  ) {
    findings.push("synced_passkey_authentication_disabled");
    activeControlViolation = true;
  }
  if (principal.mfaRequired && aal < 2) {
    findings.push("identity_mfa_required");
    activeControlViolation = true;
  }

  let assuranceTargetViolation = false;
  if (aal < policy.minimumAal) {
    findings.push("session_aal_below_minimum");
    assuranceTargetViolation = true;
  }
  if (policyEligiblePasskeyCount < policy.minimumPasskeyCount) {
    findings.push("passkey_count_below_minimum");
    assuranceTargetViolation = true;
  }

  const policyRestricted = activeControlViolation
    || (policy.enforcementMode === "enforce" && assuranceTargetViolation);
  return {
    policy,
    activePasskeyCount,
    policyEligiblePasskeyCount,
    policyRestricted,
    findings,
    principal: policyRestricted
      ? { ...principal, enrollmentOnly: true, permissions: new Set<string>() }
      : principal,
  };
}

function fallbackAuthMethod(
  assurance: RequestPrincipal["assuranceLevel"],
): "password" | "totp" | "recovery_code" | "bootstrap" {
  if (assurance === "mfa") return "totp";
  if (assurance === "recovery_limited") return "recovery_code";
  if (assurance === "enrollment_only") return "bootstrap";
  return "password";
}
