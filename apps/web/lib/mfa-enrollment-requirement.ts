export interface StrongAuthenticationState {
  readonly mfaRequired: boolean;
  readonly mfaEnabled: boolean;
  readonly passkeyEnabled?: boolean;
  readonly strongAuthEnabled?: boolean;
}

/**
 * TOTP is a fallback enrollment path, not a second mandatory enrollment after
 * a verified passkey already satisfies the account's strong-auth requirement.
 */
export function isTotpEnrollmentRequired(
  requiredGate: boolean,
  security: StrongAuthenticationState,
): boolean {
  const strongAuthenticationSatisfied = security.mfaEnabled
    || security.passkeyEnabled === true
    || security.strongAuthEnabled === true;
  return !strongAuthenticationSatisfied && (requiredGate || security.mfaRequired);
}
