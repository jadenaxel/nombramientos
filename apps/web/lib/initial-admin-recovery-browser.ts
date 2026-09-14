import {
  ApiError,
  type AuthenticatedSession,
  type InitialAdminRecoveryRedemption,
} from "./api.ts";

type RecoveryBrowserTransport = Readonly<{
  readSession: () => Promise<AuthenticatedSession>;
  prepareContext: () => Promise<void>;
  redeem: (recoveryId: string, token?: string) => Promise<InitialAdminRecoveryRedemption>;
  beforeMutation: () => void;
}>;

let inProcessRecoveryQueue: Promise<void> = Promise.resolve();

export async function redeemInitialAdminRecoverySafely(
  recoveryId: string,
  token: string,
  transport: RecoveryBrowserTransport,
): Promise<AuthenticatedSession> {
  return withInitialAdminRecoveryBrowserLock(recoveryId, async () => {
    const baseline = await readOptionalSession(transport.readSession);
    transport.beforeMutation();
    await transport.prepareContext();

    let canonicalResponse: InitialAdminRecoveryRedemption | undefined;
    try {
      const result = await transport.redeem(recoveryId, token);
      assertRecoveryRedemption(result);
      canonicalResponse = result;
    } catch (firstFailure) {
      if (!isRetryableRecoveryTransportFailure(firstFailure)) throw firstFailure;
      try {
        // The database accepts the exact token replay for the same bounded
        // context. Retrying the identical bearer first covers both a request
        // that never arrived and a response lost after commit.
        const result = await transport.redeem(recoveryId, token);
        assertRecoveryRedemption(result);
        canonicalResponse = result;
      } catch { /* The pre-commit context remains the bounded repair path. */ }
    }

    const installedAfterExactAttempt = await readOptionalSession(transport.readSession);
    if (canonicalResponse && isConclusiveRecoverySession(baseline, installedAfterExactAttempt, canonicalResponse)) {
      return installedAfterExactAttempt;
    }

    try {
      // A pre-commit HttpOnly context can repair a session response whose
      // token was consumed but whose Set-Cookie never reached the browser.
      // This is also required when a valid JSON response arrives but its
      // corresponding session cookie is missing or has lost a browser race.
      const repair = await transport.redeem(recoveryId);
      assertRecoveryRedemption(repair);
      canonicalResponse = repair;
    } catch {
      throw recoverySessionNotConfirmed();
    }
    const installedAfterContextRepair = await readOptionalSession(transport.readSession);
    if (isConclusiveRecoverySession(baseline, installedAfterContextRepair, canonicalResponse)) {
      return installedAfterContextRepair;
    }

    throw recoverySessionNotConfirmed();
  });
}

export function isRestrictedInitialAdminRecoverySession(session: AuthenticatedSession): boolean {
  return session.authenticated === true
    && session.status === "mfa_enrollment_required"
    && session.security.enrollmentOnly === true
    && session.security.assurance === "enrollment_only"
    && session.permissions.length === 0
    && !session.keyGrant
    && typeof session.csrfToken === "string"
    && session.csrfToken.length >= 16
    && Number.isFinite(Date.parse(session.expiresAt))
    && Date.parse(session.expiresAt) > Date.now();
}

export function isRetryableRecoveryTransportFailure(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 408 || error.status >= 500;
}

function assertRecoveryRedemption(result: InitialAdminRecoveryRedemption): void {
  if (
    result.recovered !== true
    || result.status !== "mfa_enrollment_required"
    || !isRestrictedInitialAdminRecoverySession(result)
    || !Number.isFinite(Date.parse(result.expiresAt))
    || Date.parse(result.expiresAt) <= Date.now()
  ) {
    throw new ApiError(502, "INVALID_RECOVERY_RESPONSE", "The recovery response is invalid");
  }
}

async function readOptionalSession(readSession: () => Promise<AuthenticatedSession>): Promise<AuthenticatedSession | null> {
  try {
    return await readSession();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

function isConclusiveRecoverySession(
  baseline: AuthenticatedSession | null,
  candidate: AuthenticatedSession | null,
  canonicalResponse: InitialAdminRecoveryRedemption,
): candidate is AuthenticatedSession {
  if (!candidate || !isRestrictedInitialAdminRecoverySession(candidate)) return false;
  if (baseline && candidate.csrfToken === baseline.csrfToken) return false;
  return candidate.csrfToken === canonicalResponse.csrfToken
    && candidate.user.id === canonicalResponse.user.id
    && candidate.tenant.id === canonicalResponse.tenant.id;
}

function recoverySessionNotConfirmed(): ApiError {
  return new ApiError(
    409,
    "INITIAL_ADMIN_RECOVERY_SESSION_NOT_CONFIRMED",
    "The browser session could not be correlated to this recovery",
  );
}

async function withInitialAdminRecoveryBrowserLock<T>(recoveryId: string, work: () => Promise<T>): Promise<T> {
  if (typeof navigator !== "undefined" && navigator.locks && crypto.subtle) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(recoveryId.toLowerCase()));
    const lockSuffix = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    return navigator.locks.request("nombramientos.initial-admin-recovery.session.v1", () =>
      navigator.locks.request(`nombramientos.initial-admin-recovery.${lockSuffix}`, work));
  }

  const previous = inProcessRecoveryQueue;
  let release: () => void = () => {};
  inProcessRecoveryQueue = new Promise<void>((resolve) => { release = resolve; });
  await previous;
  try {
    return await work();
  } finally {
    release();
  }
}
