import { createHash, randomBytes, randomUUID } from "node:crypto";
import { hash, verify } from "argon2";
import * as OTPAuth from "otpauth";
import {
  DatabaseRuntime,
  decryptServerSecret,
  encryptServerSecret,
  MfaStoreError,
  type EffectiveIdentityPolicy,
  type RequestPrincipal,
  type SessionBinding,
} from "@nombramientos/database";
import type { ApiConfig } from "../config.js";
import { ApiError } from "../lib/errors.js";
import { evaluateIdentitySessionPolicy } from "../lib/identity-policy-enforcement.js";

export const SESSION_COOKIE = "nom_session";
export const CSRF_COOKIE = "nom_csrf";
export const MFA_COOKIE = "nom_mfa";
const NONEXISTENT_TIMING_TENANT_ID = "00000000-0000-4000-8000-000000000000";
export const MFA_ENROLLMENT_WINDOW_MINUTES = 10;
export const RECOVERY_SESSION_WINDOW_MINUTES = 15;
export const MFA_TOTP_PERIOD_SECONDS = 30;
export const MFA_TOTP_ACCEPTANCE_WINDOW = 0;

export interface AuthenticatedResult {
  readonly status: "authenticated" | "mfa_enrollment_required" | "security_recovery_required";
  readonly authenticated: true;
  readonly user: { readonly id: string; readonly displayName: string; readonly email: string };
  readonly tenant: {
    readonly id: string;
    readonly slug: string;
    readonly name: string;
    readonly kind: string;
    readonly timezone: string;
  };
  readonly permissions: readonly string[];
  readonly csrfToken: string;
  readonly keyGrant: unknown;
  readonly security: {
    readonly mfaRequired: boolean;
    readonly mfaEnabled: boolean;
    readonly enrollmentOnly: boolean;
    readonly assurance: "enrollment_only" | "password" | "mfa" | "recovery_limited";
    readonly aal: 1 | 2 | 3;
    readonly authMethod: "password" | "totp" | "recovery_code" | "passkey" | "federated" | "bootstrap";
    readonly phishingResistant: boolean;
    readonly recoveryRestricted: boolean;
    readonly passkeyEnabled: boolean;
    readonly strongAuthEnabled: boolean;
    readonly passkeyCount: number;
    readonly idleExpiresAt: Date | null;
    readonly risk: {
      readonly elevated: boolean;
      readonly userAgentContextChanged: boolean;
      readonly ipContextChanged: boolean;
    };
  };
  readonly sessionToken: string;
  readonly expiresAt: Date;
}

export interface MfaRequiredResult {
  readonly status: "mfa_required";
  readonly challengeId: string;
  readonly expiresAt: Date;
  readonly challengeToken: string;
}

/** GET /v1/session includes the authoritative observation time without
 * modifying the session's stored absolute or idle expiration. */
export type SessionSnapshotResult = Omit<AuthenticatedResult, "sessionToken"> & {
  readonly serverTime: string;
  readonly sessionId: string;
};

export interface MfaEnrollmentStartedResult {
  readonly enrollmentId: string;
  readonly secret: string;
  readonly otpauthUri: string;
  readonly expiresAt: Date;
  readonly algorithm: "SHA1";
  readonly digits: 6;
  readonly period: 30;
}

export interface MfaEnrollmentPendingResult {
  readonly enrollmentId: string;
  readonly expiresAt: Date;
}

export class AuthService {
  readonly #dummyHash: Promise<string>;

  public constructor(
    private readonly database: DatabaseRuntime,
    private readonly config: ApiConfig,
  ) {
    this.#dummyHash = hash(randomBytes(24), {
      type: 2,
      memoryCost: 65_536,
      timeCost: 3,
      parallelism: 1,
    });
  }

  public async login(input: {
    email: string;
    password: string;
    requestId: string;
    userAgent?: string;
    ip?: string;
    origin?: string;
  }): Promise<AuthenticatedResult | MfaRequiredResult> {
    const normalizedEmail = input.email.trim().normalize("NFKC").toLocaleLowerCase("en-US");
    const identity = await this.database.control.findIdentityForLogin(normalizedEmail);
    // A password hash is an authentication credential only when both the
    // identity marker and the current tenant policy say so. For unknown,
    // passwordless and administratively disabled identities, verify the same
    // Argon2id dummy hash and return the same public denial. In particular, do
    // not test a compatibility hash that might later become usable after a
    // policy change.
    let policy: EffectiveIdentityPolicy | null = null;
    try {
      policy = await this.database.enterpriseAuth.getEffectiveIdentityPolicy(
        identity?.tenantId ?? NONEXISTENT_TIMING_TENANT_ID,
      );
    } catch (error) {
      // Unknown emails still execute the same effective-policy query shape as
      // known identities. A missing policy for a known identity is an
      // integrity failure and must not be disguised as a credential denial.
      if (identity) throw error;
    }
    const passwordEnabled = identity?.passwordProvisioned === true && policy?.allowPassword === true;
    const passwordHash = passwordEnabled ? identity.passwordHash : await this.#dummyHash;
    const valid = await verify(passwordHash, input.password).catch(() => false);
    if (!identity || !passwordEnabled || !valid || (identity.lockedUntil !== null && identity.lockedUntil > new Date())) {
      // Disabled/non-provisioned password attempts must not let an attacker
      // lock a passkey-only identity out of its valid authentication method.
      if (identity && passwordEnabled) await this.database.control.recordLoginFailure(identity.identityId);
      await this.database.control.appendAudit({
        ...(identity ? { actorIdentityId: identity.identityId, tenantId: identity.tenantId } : {}),
        action: "auth.login_denied",
        entityType: "identity",
        ...(identity ? { entityId: identity.identityId } : {}),
        result: "denied",
        requestId: input.requestId,
      });
      throw new ApiError(401, "INVALID_CREDENTIALS", "Email or password is incorrect");
    }
    if (!policy) throw new Error("Authenticated identity policy was not loaded");
    if (identity.mfaRequired && !identity.mfaEnabled && identity.passkeyEnabled) {
      await this.database.control.appendAudit({
        actorIdentityId: identity.identityId,
        tenantId: identity.tenantId,
        action: "auth.password_verified_passkey_required",
        entityType: "identity",
        entityId: identity.identityId,
        result: "denied",
        requestId: input.requestId,
      });
      throw new ApiError(428, "PASSKEY_REQUIRED", "Continue with a registered passkey");
    }
    if (identity.mfaEnabled) {
      if (!policy.allowTotpFallback && !policy.allowRecoveryCodes) {
        throw new ApiError(428, "PASSKEY_REQUIRED", "This organization does not permit TOTP fallback");
      }
      const challengeToken = randomToken();
      const expiresAt = new Date(Date.now() + 5 * 60_000);
      const challenge = await this.database.control.createMfaChallenge(
        sha256(challengeToken),
        identity.identityId,
        identity.tenantId,
        expiresAt,
        createMfaChallengeBinding(input.origin, input.userAgent, input.ip),
      );
      await this.database.control.appendAudit({
        actorIdentityId: identity.identityId,
        tenantId: identity.tenantId,
        action: "auth.password_verified",
        entityType: "mfa_challenge",
        entityId: challenge.challengeId,
        result: "success",
        requestId: input.requestId,
      });
      return {
        status: "mfa_required",
        challengeId: challenge.challengeId,
        expiresAt: challenge.expiresAt,
        challengeToken,
      };
    }
    // Password is terminal only for identities without a second factor. When
    // MFA is pending, keep the identity-wide failure budget intact across newly
    // issued challenges and reset it only after successful MFA verification.
    await this.database.control.recordLoginSuccess(identity.identityId);
    return this.createSession({
      identityId: identity.identityId,
      tenantId: identity.tenantId,
      requestId: input.requestId,
      assuranceLevel: identity.mfaRequired ? "enrollment_only" : "password",
      authMethod: identity.mfaRequired ? "bootstrap" : "password",
      aal: 1,
      phishingResistant: false,
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
      ...(input.ip ? { ip: input.ip } : {}),
    });
  }

  public async verifyMfa(input: {
    challengeToken: string;
    challengeId: string;
    code?: string;
    recoveryCode?: string;
    requestId: string;
    userAgent?: string;
    ip?: string;
    origin?: string;
  }): Promise<AuthenticatedResult> {
    const challenge = await this.database.control.reserveMfaChallengeAttempt(
      sha256(input.challengeToken),
      input.challengeId,
      createMfaChallengeBinding(input.origin, input.userAgent, input.ip),
    );
    if (!challenge) throw new ApiError(401, "MFA_CHALLENGE_INVALID", "MFA challenge is invalid or expired");
    const policy = await this.database.enterpriseAuth.getEffectiveIdentityPolicy(challenge.tenantId);
    if (
      !policy.allowPassword
      || (input.code && !policy.allowTotpFallback)
      || (input.recoveryCode && !policy.allowRecoveryCodes)
    ) {
      // Policy transitions are not authentication failures and must not let an
      // attacker consume the shared identity guessing budget. Consume the stale
      // challenge once and require a policy-compliant sign-in method.
      await this.database.control.consumeMfaChallenge(challenge.challengeId).catch(() => undefined);
      await this.database.control.appendAudit({
        actorIdentityId: challenge.identityId,
        tenantId: challenge.tenantId,
        action: "auth.mfa_policy_denied",
        entityType: "mfa_challenge",
        entityId: challenge.challengeId,
        result: "denied",
        requestId: input.requestId,
        metadata: { method: input.recoveryCode ? "recovery_code" : "totp" },
      });
      throw new ApiError(403, "MFA_METHOD_POLICY_DENIED", "This verification method is disabled by organization policy");
    }

    let recoveryUsed = false;
    let accepted = false;
    if (input.code) {
      const secret = decryptServerSecret(challenge.totpSecretCiphertext, this.config.authEncryptionKey);
      const timestamp = Date.now();
      // A TOTP is valid only in its current 30-second step. Accepting adjacent
      // windows would extend the lifetime beyond the ASVS 5.0.0 L2 limit.
      const delta = createTotp(secret).validate({ token: input.code, window: MFA_TOTP_ACCEPTANCE_WINDOW, timestamp });
      if (delta !== null) {
        const acceptedTimeStep = Math.floor(timestamp / 30_000) + delta;
        try {
          accepted = await this.database.mfa.consumeTotpChallenge({
            challengeId: challenge.challengeId,
            identityId: challenge.identityId,
            acceptedTimeStep,
          });
        } catch (error) {
          if (!(error instanceof MfaStoreError) || error.code !== "MFA_REPLAYED") throw error;
          accepted = false;
        }
      }
    } else if (input.recoveryCode) {
      const normalizedCode = normalizeRecoveryCode(input.recoveryCode);
      const candidates = await this.database.mfa.listActiveRecoveryCodes(challenge.identityId);
      let matchedId: string | undefined;
      for (const candidate of candidates) {
        const matches = await verify(candidate.hash, normalizedCode).catch(() => false);
        if (matches && !matchedId) matchedId = candidate.id;
      }
      if (matchedId) {
        accepted = await this.database.mfa.consumeRecoveryChallenge({
          challengeId: challenge.challengeId,
          identityId: challenge.identityId,
          recoveryCodeId: matchedId,
          tenantId: challenge.tenantId,
          requestId: input.requestId,
        });
        recoveryUsed = accepted;
      }
    }

    if (!accepted) {
      await this.database.control.failMfaChallenge(challenge.challengeId);
      await this.database.control.appendAudit({
        actorIdentityId: challenge.identityId,
        tenantId: challenge.tenantId,
        action: "auth.mfa_denied",
        entityType: "mfa_challenge",
        entityId: challenge.challengeId,
        result: "denied",
        requestId: input.requestId,
        metadata: { method: input.recoveryCode ? "recovery_code" : "totp" },
      });
      throw new ApiError(401, "MFA_CODE_INVALID", "The verification code is invalid or has already been used");
    }

    await this.database.control.recordLoginSuccess(challenge.identityId);
    if (!recoveryUsed) {
      await this.database.control.appendAudit({
        actorIdentityId: challenge.identityId,
        tenantId: challenge.tenantId,
        action: "auth.mfa_verified",
        entityType: "mfa_challenge",
        entityId: challenge.challengeId,
        result: "success",
        requestId: input.requestId,
        metadata: { method: "totp" },
      });
    }
    return this.createSession({
      identityId: challenge.identityId,
      tenantId: challenge.tenantId,
      requestId: input.requestId,
      assuranceLevel: recoveryUsed ? "recovery_limited" : "mfa",
      authMethod: recoveryUsed ? "recovery_code" : "totp",
      aal: recoveryUsed ? 1 : 2,
      phishingResistant: false,
      recoveryLimited: recoveryUsed,
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
      ...(input.ip ? { ip: input.ip } : {}),
    });
  }

  public async startMfaEnrollment(input: {
    principal: RequestPrincipal;
    requestId: string;
  }): Promise<MfaEnrollmentStartedResult> {
    await this.assertTotpEnrollmentAllowed(input.principal.activeTenantId);
    const secret = new OTPAuth.Secret({ size: 20 });
    const enrollmentId = randomUUID();
    let record;
    try {
      record = await this.database.mfa.startEnrollment({
        sessionId: input.principal.sessionId,
        identityId: input.principal.identityId,
        enrollmentId,
        secretCiphertext: encryptServerSecret(secret.base32, this.config.authEncryptionKey),
        recentWindowMinutes: MFA_ENROLLMENT_WINDOW_MINUTES,
      });
    } catch (error) {
      throw enrollmentApiError(error);
    }
    await this.database.control.appendAudit({
      actorIdentityId: record.identityId,
      tenantId: record.tenantId,
      action: "auth.mfa_enrollment_started",
      entityType: "identity",
      entityId: record.identityId,
      result: "success",
      requestId: input.requestId,
      metadata: { rotation: record.mfaEnabled, expiresInSeconds: MFA_ENROLLMENT_WINDOW_MINUTES * 60 },
    });
    return mfaEnrollmentResult(record, secret.base32, enrollmentId);
  }

  public async getPendingMfaEnrollment(input: {
    principal: RequestPrincipal;
  }): Promise<MfaEnrollmentPendingResult | null> {
    let record;
    try {
      record = await this.database.mfa.getPendingEnrollment({
        sessionId: input.principal.sessionId,
        identityId: input.principal.identityId,
        recentWindowMinutes: MFA_ENROLLMENT_WINDOW_MINUTES,
      });
    } catch (error) {
      throw enrollmentApiError(error);
    }
    if (!record?.enrollmentId || !record.enrollmentStartedAt) return null;
    return {
      enrollmentId: record.enrollmentId,
      expiresAt: new Date(record.enrollmentStartedAt.getTime() + MFA_ENROLLMENT_WINDOW_MINUTES * 60_000),
    };
  }

  public async cancelMfaEnrollment(input: {
    principal: RequestPrincipal;
    enrollmentId: string;
    requestId: string;
  }): Promise<{ cancelled: true }> {
    let cancelled;
    try {
      cancelled = await this.database.mfa.cancelEnrollment({
        sessionId: input.principal.sessionId,
        identityId: input.principal.identityId,
        enrollmentId: input.enrollmentId,
        recentWindowMinutes: MFA_ENROLLMENT_WINDOW_MINUTES,
      });
    } catch (error) {
      throw enrollmentApiError(error);
    }
    if (!cancelled) throw new ApiError(409, "MFA_ENROLLMENT_INVALID", "MFA enrollment is invalid or expired");
    await this.database.control.appendAudit({
      actorIdentityId: input.principal.identityId,
      tenantId: input.principal.activeTenantId,
      action: "auth.mfa_enrollment_cancelled",
      entityType: "identity",
      entityId: input.principal.identityId,
      result: "success",
      requestId: input.requestId,
    });
    return { cancelled: true };
  }

  public async confirmMfaEnrollment(input: {
    principal: RequestPrincipal;
    enrollmentId: string;
    code: string;
    requestId: string;
    userAgent?: string;
    ip?: string;
  }): Promise<AuthenticatedResult & { readonly recoveryCodes: readonly string[] }> {
    await this.assertTotpEnrollmentAllowed(input.principal.activeTenantId);
    let record;
    try {
      record = await this.database.mfa.getEnrollmentForConfirmation({
        sessionId: input.principal.sessionId,
        identityId: input.principal.identityId,
        enrollmentId: input.enrollmentId,
        recentWindowMinutes: MFA_ENROLLMENT_WINDOW_MINUTES,
      });
    } catch (error) {
      throw enrollmentApiError(error);
    }
    if (!record?.enrollmentSecretCiphertext) {
      throw new ApiError(409, "MFA_ENROLLMENT_INVALID", "MFA enrollment is invalid or expired");
    }
    const secret = decryptServerSecret(record.enrollmentSecretCiphertext, this.config.authEncryptionKey);
    const timestamp = Date.now();
    const delta = createTotp(secret).validate({ token: input.code, window: MFA_TOTP_ACCEPTANCE_WINDOW, timestamp });
    if (delta === null) {
      await this.database.control.appendAudit({
        actorIdentityId: record.identityId,
        tenantId: record.tenantId,
        action: "auth.mfa_enrollment_denied",
        entityType: "identity",
        entityId: record.identityId,
        result: "denied",
        requestId: input.requestId,
      });
      throw new ApiError(401, "MFA_CODE_INVALID", "The verification code is invalid");
    }

    const recoveryCodes = Array.from({ length: 10 }, () => createRecoveryCode());
    const recoveryCodeHashes: string[] = [];
    for (const recoveryCode of recoveryCodes) {
      recoveryCodeHashes.push(await hash(normalizeRecoveryCode(recoveryCode), {
        type: 2,
        memoryCost: 19_456,
        timeCost: 2,
        parallelism: 1,
      }));
    }
    const policy = await this.database.enterpriseAuth.getEffectiveIdentityPolicy(record.tenantId);
    const sessionToken = randomToken();
    const csrfToken = randomToken();
    const expiresAt = new Date(Date.now() + Math.min(
      this.config.sessionTtlSeconds,
      policy.absoluteSessionMinutes * 60,
    ) * 1_000);
    let completed: { readonly generation: number; readonly sessionId: string };
    try {
      completed = await this.database.mfa.completeEnrollment({
        sessionId: input.principal.sessionId,
        identityId: record.identityId,
        enrollmentId: input.enrollmentId,
        acceptedTimeStep: Math.floor(timestamp / 30_000) + delta,
        recoveryCodeHashes,
        recentWindowMinutes: MFA_ENROLLMENT_WINDOW_MINUTES,
        tenantId: record.tenantId,
        requestId: input.requestId,
        newSession: {
          id: randomUUID(),
          tokenHash: sha256(sessionToken),
          csrfHash: sha256(csrfToken),
          expiresAt,
          idleTimeoutMinutes: policy.idleTimeoutMinutes,
          ...(input.userAgent ? { userAgentHash: sha256(input.userAgent) } : {}),
          ...(input.ip ? { ipPrefixHash: sha256(coarsenIp(input.ip)) } : {}),
        },
      });
    } catch (error) {
      throw enrollmentApiError(error);
    }
    const session = await this.hydrateCreatedSession({
      expectedSessionId: completed.sessionId,
      sessionToken,
      csrfToken,
      requestId: input.requestId,
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
      ...(input.ip ? { ip: input.ip } : {}),
    });
    return { ...session, recoveryCodes };
  }

  public publicSession(
    principal: RequestPrincipal,
    csrfToken: string,
    keyGrant: unknown,
    passkeyCount = principal.passkeyEnabled ? 1 : 0,
  ): Omit<AuthenticatedResult, "sessionToken"> {
    return {
      status: principal.assuranceLevel === "recovery_limited"
        ? "security_recovery_required"
        : principal.enrollmentOnly
          ? "mfa_enrollment_required"
          : "authenticated",
      authenticated: true,
      user: { id: principal.identityId, displayName: principal.displayName, email: principal.email },
      tenant: {
        id: principal.activeTenantId,
        slug: principal.tenantSlug,
        name: principal.tenantName,
        kind: principal.tenantKind,
        timezone: principal.tenantTimezone,
      },
      permissions: [...principal.permissions].sort(),
      csrfToken,
      keyGrant,
      security: {
        mfaRequired: principal.mfaRequired,
        mfaEnabled: principal.mfaEnabled,
        enrollmentOnly: principal.enrollmentOnly,
        assurance: principal.assuranceLevel,
        aal: principal.aal ?? (principal.assuranceLevel === "mfa" ? 2 : 1),
        authMethod: principal.authMethod ?? defaultAuthMethod(principal.assuranceLevel),
        phishingResistant: principal.phishingResistant ?? false,
        recoveryRestricted: principal.recoveryLimited ?? principal.assuranceLevel === "recovery_limited",
        passkeyEnabled: principal.passkeyEnabled ?? false,
        strongAuthEnabled: principal.strongAuthEnabled ?? principal.mfaEnabled,
        passkeyCount,
        idleExpiresAt: principal.idleExpiresAt ?? null,
        risk: {
          elevated: principal.userAgentContextChanged === true || principal.ipContextChanged === true,
          userAgentContextChanged: principal.userAgentContextChanged === true,
          ipContextChanged: principal.ipContextChanged === true,
        },
      },
      expiresAt: principal.expiresAt,
    };
  }

  public async switchTenant(input: {
    readonly principal: RequestPrincipal;
    readonly targetTenantId: string;
    readonly requestId: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<AuthenticatedResult> {
    const hasTargetMembership = await this.database.control.hasActiveMembership(
      input.principal.identityId,
      input.targetTenantId,
    );
    if (!hasTargetMembership) {
      await this.database.control.appendAudit({
        actorIdentityId: input.principal.identityId,
        tenantId: input.principal.activeTenantId,
        action: "auth.tenant_switch_denied",
        entityType: "tenant",
        entityId: input.targetTenantId,
        result: "denied",
        requestId: input.requestId,
      });
      throw new ApiError(403, "TENANT_MEMBERSHIP_REQUIRED", "The requested tenant is not available to this identity");
    }
    const targetPolicy = await this.database.enterpriseAuth.getEffectiveIdentityPolicy(input.targetTenantId);
    const targetDecision = await evaluateIdentitySessionPolicy(
      this.database,
      { ...input.principal, activeTenantId: input.targetTenantId },
      targetPolicy,
    );
    if (targetDecision.policyRestricted) {
      await this.database.control.appendAudit({
        actorIdentityId: input.principal.identityId,
        tenantId: input.principal.activeTenantId,
        action: "auth.tenant_switch_policy_denied",
        entityType: "tenant",
        entityId: input.targetTenantId,
        result: "denied",
        requestId: input.requestId,
        metadata: { findings: targetDecision.findings },
      });
      throw new ApiError(
        428,
        "TARGET_TENANT_SECURITY_UPGRADE_REQUIRED",
        "Authenticate with a method that satisfies the target tenant security policy before switching",
        { findings: targetDecision.findings },
      );
    }
    const sessionToken = randomToken();
    const csrfToken = randomToken();
    const targetExpiresAt = new Date(Math.min(
      input.principal.expiresAt.getTime(),
      Date.now() + targetPolicy.absoluteSessionMinutes * 60_000,
    ));
    const rotatedSessionId = await this.database.control.rotateSessionTenant({
      currentSessionId: input.principal.sessionId,
      identityId: input.principal.identityId,
      targetTenantId: input.targetTenantId,
      tokenHash: sha256(sessionToken),
      csrfHash: sha256(csrfToken),
      expiresAt: targetExpiresAt,
      idleTimeoutMinutes: targetPolicy.idleTimeoutMinutes,
      ...(input.userAgent ? { userAgentHash: sha256(input.userAgent) } : {}),
      ...(input.ip ? { ipPrefixHash: sha256(coarsenIp(input.ip)) } : {}),
    });
    if (!rotatedSessionId) {
      await this.database.control.appendAudit({
        actorIdentityId: input.principal.identityId,
        tenantId: input.principal.activeTenantId,
        action: "auth.tenant_switch_denied",
        entityType: "tenant",
        entityId: input.targetTenantId,
        result: "denied",
        requestId: input.requestId,
      });
      throw new ApiError(403, "TENANT_MEMBERSHIP_REQUIRED", "The requested tenant is not available to this identity");
    }
    const loadedPrincipal = await this.database.getPrincipal(
      sha256(sessionToken),
      input.requestId,
      createSessionBinding(input.userAgent, input.ip),
    );
    if (!loadedPrincipal || loadedPrincipal.sessionId !== rotatedSessionId) {
      await this.database.control.revokeSession(rotatedSessionId, "tenant_switch_context_failed");
      throw new Error("Rotated tenant session could not be loaded");
    }
    // Re-read after the atomic rotation. A concurrent policy update may have
    // tightened the target between the advisory pre-clamp and insertion.
    const decision = await evaluateIdentitySessionPolicy(this.database, loadedPrincipal);
    const principal = decision.principal;
    const keyGrant = principal.enrollmentOnly
      || principal.recoveryLimited === true
      || principal.assuranceLevel === "recovery_limited"
      ? null
      : await this.database.withPrincipal(principal, input.requestId, (tenant) =>
          tenant.getKeyGrant(principal.identityId));
    await this.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId: principal.activeTenantId,
      action: "auth.tenant_switched",
      entityType: "session",
      entityId: principal.sessionId,
      result: "success",
      requestId: input.requestId,
      metadata: { previousTenantId: input.principal.activeTenantId },
    });
    return {
      ...this.publicSession(
        principal,
        csrfToken,
        keyGrant,
        decision.activePasskeyCount,
      ),
      sessionToken,
      expiresAt: principal.expiresAt,
    };
  }

  public async createFederatedSession(input: {
    readonly identityId: string;
    readonly tenantId: string;
    readonly sourceSessionId: string;
    readonly requestId: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<AuthenticatedResult> {
    const result = await this.createSession({
      identityId: input.identityId,
      tenantId: input.tenantId,
      requestId: input.requestId,
      assuranceLevel: "password",
      authMethod: "federated",
      aal: 1,
      phishingResistant: false,
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
      ...(input.ip ? { ip: input.ip } : {}),
    });
    await this.database.control.bindGestionChurchSession(sha256(result.sessionToken), input.identityId, input.sourceSessionId);
    return result;
  }

  private async createSession(input: {
    identityId: string;
    tenantId: string;
    requestId: string;
    assuranceLevel: "enrollment_only" | "password" | "mfa" | "recovery_limited";
    authMethod: "password" | "totp" | "recovery_code" | "passkey" | "federated" | "bootstrap";
    aal: 1 | 2 | 3;
    phishingResistant: boolean;
    recoveryLimited?: boolean;
    userAgent?: string;
    ip?: string;
  }): Promise<AuthenticatedResult> {
    const policy = await this.database.enterpriseAuth.getEffectiveIdentityPolicy(input.tenantId);
    const sessionToken = randomToken();
    const csrfToken = randomToken();
    const recoveryWindowMinutes = input.assuranceLevel === "recovery_limited"
      ? RECOVERY_SESSION_WINDOW_MINUTES
      : Number.POSITIVE_INFINITY;
    const expiresAt = new Date(Date.now() + Math.min(
      this.config.sessionTtlSeconds,
      policy.absoluteSessionMinutes * 60,
      recoveryWindowMinutes * 60,
    ) * 1_000);
    const sessionId = await this.database.control.createSession({
      tokenHash: sha256(sessionToken),
      csrfHash: sha256(csrfToken),
      identityId: input.identityId,
      tenantId: input.tenantId,
      expiresAt,
      assuranceLevel: input.assuranceLevel,
      authMethod: input.authMethod,
      aal: input.aal,
      phishingResistant: input.phishingResistant,
      recoveryLimited: input.recoveryLimited ?? false,
      idleTimeoutMinutes: Math.min(policy.idleTimeoutMinutes, recoveryWindowMinutes),
      ...(input.userAgent ? { userAgentHash: sha256(input.userAgent) } : {}),
      ...(input.ip ? { ipPrefixHash: sha256(coarsenIp(input.ip)) } : {}),
    });
    await this.database.enterpriseAuth.enforceSessionLimit(
      input.identityId,
      input.tenantId,
      sessionId,
      policy.maximumActiveSessions,
    );
    return this.hydrateCreatedSession({
      expectedSessionId: sessionId,
      sessionToken,
      csrfToken,
      requestId: input.requestId,
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
      ...(input.ip ? { ip: input.ip } : {}),
    });
  }

  private async hydrateCreatedSession(input: {
    expectedSessionId: string;
    sessionToken: string;
    csrfToken: string;
    requestId: string;
    userAgent?: string;
    ip?: string;
  }): Promise<AuthenticatedResult> {
    const loadedPrincipal = await this.database.getPrincipal(
      sha256(input.sessionToken),
      input.requestId,
      createSessionBinding(input.userAgent, input.ip),
    );
    if (!loadedPrincipal || loadedPrincipal.sessionId !== input.expectedSessionId) {
      if (loadedPrincipal) {
        await this.database.control.revokeSession(
          loadedPrincipal.sessionId,
          "session_context_hydration_failed",
        );
      }
      throw new Error("Newly created session could not be loaded");
    }
    // Do not authorize from the pre-insert snapshot: createSession validates
    // against the database policy atomically, then this read reflects any
    // immediately following policy transition before a key grant is issued.
    const decision = await evaluateIdentitySessionPolicy(this.database, loadedPrincipal);
    const principal = decision.principal;
    const keyGrant = principal.enrollmentOnly
      || principal.recoveryLimited === true
      || principal.assuranceLevel === "recovery_limited"
      ? null
      : await this.database.withPrincipal(principal, input.requestId, (tenant) =>
          tenant.getKeyGrant(principal.identityId));
    await this.database.control.appendAudit({
      actorIdentityId: principal.identityId,
      tenantId: principal.activeTenantId,
      action: "auth.session_created",
      entityType: "session",
      entityId: principal.sessionId,
      result: "success",
      requestId: input.requestId,
      metadata: {
        assurance: principal.assuranceLevel,
        enrollmentOnly: principal.enrollmentOnly,
        policyRestricted: decision.policyRestricted,
      },
    });
    return {
      ...this.publicSession(
        principal,
        input.csrfToken,
        keyGrant,
        decision.activePasskeyCount,
      ),
      sessionToken: input.sessionToken,
      expiresAt: principal.expiresAt,
    };
  }

  private async assertTotpEnrollmentAllowed(tenantId: string): Promise<void> {
    const policy = await this.database.enterpriseAuth.getEffectiveIdentityPolicy(tenantId);
    if (!policy.allowPassword || !policy.allowTotpFallback) {
      throw new ApiError(403, "TOTP_POLICY_DENIED", "This organization requires passkeys and does not permit TOTP fallback");
    }
  }
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createSessionBinding(userAgent?: string, ip?: string): SessionBinding {
  return {
    ...(userAgent ? { userAgentHash: sha256(userAgent) } : {}),
    ...(ip ? { ipPrefixHash: sha256(coarsenIp(ip)) } : {}),
  };
}

export function normalizeRecoveryCode(value: string): string {
  return value.normalize("NFKC").toUpperCase().replace(/[\s-]+/g, "");
}

function createTotp(secret: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    algorithm: "SHA1",
    digits: 6,
    period: MFA_TOTP_PERIOD_SECONDS,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
}

function mfaEnrollmentResult(
  record: {
    readonly tenantSlug: string;
    readonly email: string;
    readonly enrollmentStartedAt: Date | null;
  },
  secret: string,
  enrollmentId: string,
): MfaEnrollmentStartedResult {
  if (!record.enrollmentStartedAt) throw new Error("MFA enrollment start time is missing");
  const totp = new OTPAuth.TOTP({
    issuer: "Nombramientos",
    label: `${record.tenantSlug}:${record.email}`,
    algorithm: "SHA1",
    digits: 6,
    period: MFA_TOTP_PERIOD_SECONDS,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
  return {
    enrollmentId,
    secret,
    otpauthUri: totp.toString(),
    expiresAt: new Date(record.enrollmentStartedAt.getTime() + MFA_ENROLLMENT_WINDOW_MINUTES * 60_000),
    algorithm: "SHA1",
    digits: 6,
    period: MFA_TOTP_PERIOD_SECONDS,
  };
}

function createRecoveryCode(): string {
  const base32 = new OTPAuth.Secret({ size: 10 }).base32;
  return base32.match(/.{1,4}/g)!.join("-");
}

export function createMfaChallengeBinding(origin?: string, userAgent?: string, ip?: string) {
  return {
    originHash: sha256(origin ?? "same-origin"),
    ...(userAgent ? { userAgentHash: sha256(userAgent) } : {}),
    ...(ip ? { ipPrefixHash: sha256(coarsenIp(ip)) } : {}),
  };
}

function enrollmentApiError(error: unknown): ApiError {
  if (error instanceof MfaStoreError) {
    if (error.code === "RECENT_AUTH_REQUIRED") {
      return new ApiError(401, "MFA_RECENT_AUTH_REQUIRED", "Sign in again before changing MFA");
    }
    if (error.code === "ENROLLMENT_ALREADY_STARTED") {
      return new ApiError(409, "MFA_ENROLLMENT_ALREADY_STARTED", "The active enrollment secret cannot be returned again; cancel it first");
    }
    if (error.code === "RECOVERY_GOVERNANCE_INVALID") {
      return new ApiError(
        409,
        "INITIAL_ADMIN_RECOVERY_GOVERNANCE_WITHDRAWN",
        "The governed recovery was revoked because its dual-control authority changed",
      );
    }
    return new ApiError(409, "MFA_ENROLLMENT_INVALID", "MFA enrollment is invalid or expired");
  }
  throw error;
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function defaultAuthMethod(
  assurance: "enrollment_only" | "password" | "mfa" | "recovery_limited",
): "password" | "totp" | "recovery_code" | "bootstrap" {
  if (assurance === "mfa") return "totp";
  if (assurance === "recovery_limited") return "recovery_code";
  if (assurance === "enrollment_only") return "bootstrap";
  return "password";
}

function coarsenIp(ip: string): string {
  if (ip.includes(":")) return ip.split(":").slice(0, 4).join(":");
  return ip.split(".").slice(0, 3).join(".");
}
