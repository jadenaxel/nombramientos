import { hash } from "argon2";
import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import { describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import {
  AuthService,
  MFA_TOTP_ACCEPTANCE_WINDOW,
  MFA_TOTP_PERIOD_SECONDS,
  RECOVERY_SESSION_WINDOW_MINUTES,
} from "../src/modules/auth-service.js";

describe("authentication security policy", () => {
  it("limits TOTP acceptance to the current 30-second step", () => {
    expect(MFA_TOTP_PERIOD_SECONDS).toBe(30);
    expect(MFA_TOTP_ACCEPTANCE_WINDOW).toBe(0);
  });

  it("requires registered passkey continuation instead of stranding password login in enrollment", async () => {
    const passwordHash = await hash("correct-password", { memoryCost: 19_456, timeCost: 2, parallelism: 1 });
    const createSession = vi.fn();
    const database = databaseFixture(passwordHash, true, createSession);
    const service = new AuthService(database, config());
    await expect(service.login({
      email: "user@example.invalid",
      password: "correct-password",
      requestId: "passkey-required",
      origin: "http://localhost:3000",
    })).rejects.toMatchObject({ statusCode: 428, code: "PASSKEY_REQUIRED" });
    expect(createSession).not.toHaveBeenCalled();
  });

  it("keeps first-time users with no strong authenticator in restricted enrollment", async () => {
    const passwordHash = await hash("correct-password", { memoryCost: 19_456, timeCost: 2, parallelism: 1 });
    const createSession = vi.fn().mockResolvedValue("10000000-0000-4000-8000-000000000001");
    const database = databaseFixture(passwordHash, false, createSession);
    const service = new AuthService(database, config());
    const result = await service.login({
      email: "user@example.invalid",
      password: "correct-password",
      requestId: "first-enrollment",
    });
    expect(result.status).toBe("mfa_enrollment_required");
    expect(createSession).toHaveBeenCalledWith(expect.objectContaining({
      assuranceLevel: "enrollment_only",
      authMethod: "bootstrap",
      aal: 1,
    }));
    expect(database.enterpriseAuth.enforceSessionLimit).toHaveBeenCalledWith(
      "20000000-0000-4000-8000-000000000001",
      "30000000-0000-4000-8000-000000000001",
      "10000000-0000-4000-8000-000000000001",
      10,
    );
  });

  it.each([
    [false, true, "not provisioned"],
    [true, false, "disabled by policy"],
  ] as const)("returns the same generic password denial when the credential is %s/%s (%s)", async (
    passwordProvisioned,
    allowPassword,
    _description,
  ) => {
    const passwordHash = await hash("correct-password", { memoryCost: 19_456, timeCost: 2, parallelism: 1 });
    const recordLoginFailure = vi.fn();
    const appendAudit = vi.fn().mockResolvedValue(undefined);
    const database = {
      control: {
        findIdentityForLogin: vi.fn().mockResolvedValue({
          identityId: "20000000-0000-4000-8000-000000000001",
          tenantId: "30000000-0000-4000-8000-000000000001",
          email: "user@example.invalid",
          displayName: "User",
          passwordHash,
          passwordProvisioned,
          mfaEnabled: false,
          mfaRequired: false,
          passkeyEnabled: true,
          strongAuthEnabled: true,
          totpSecretCiphertext: null,
          lockedUntil: null,
        }),
        recordLoginFailure,
        appendAudit,
      },
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({ allowPassword }),
      },
    } as unknown as DatabaseRuntime;

    await expect(new AuthService(database, config()).login({
      email: "user@example.invalid",
      password: "correct-password",
      requestId: "generic-password-denial",
    })).rejects.toMatchObject({
      statusCode: 401,
      code: "INVALID_CREDENTIALS",
      message: "Email or password is incorrect",
    });
    expect(recordLoginFailure).not.toHaveBeenCalled();
    expect(appendAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: "auth.login_denied",
      result: "denied",
    }));
  });

  it("turns a recovery code into a restricted session, never a full MFA session", async () => {
    const startedAt = Date.now();
    const recoveryCode = "ABCD-EFGH-JKLM-NPQR";
    const recoveryHash = await hash("ABCDEFGHJKLMNPQR", { memoryCost: 19_456, timeCost: 2, parallelism: 1 });
    const createSession = vi.fn().mockResolvedValue("10000000-0000-4000-8000-000000000099");
    const withPrincipal = vi.fn();
    const recoveryPrincipal: RequestPrincipal = {
      sessionId: "10000000-0000-4000-8000-000000000099",
      identityId: "20000000-0000-4000-8000-000000000001",
      activeTenantId: "30000000-0000-4000-8000-000000000001",
      email: "user@example.invalid",
      displayName: "User",
      tenantSlug: "fixture",
      tenantName: "Fixture",
      tenantKind: "real",
      tenantTimezone: "America/La_Paz",
      csrfHash: "csrf",
      expiresAt: new Date(Date.now() + 60_000),
      assuranceLevel: "recovery_limited",
      authenticatedAt: new Date(),
      mfaVerifiedAt: null,
      mfaRequired: true,
      mfaEnabled: true,
      passkeyEnabled: true,
      strongAuthEnabled: true,
      authMethod: "recovery_code",
      aal: 1,
      phishingResistant: false,
      recoveryLimited: true,
      enrollmentOnly: true,
      permissions: new Set(),
    };
    const database = {
      control: {
        reserveMfaChallengeAttempt: vi.fn().mockResolvedValue({
          challengeId: "50000000-0000-4000-8000-000000000001",
          identityId: recoveryPrincipal.identityId,
          tenantId: recoveryPrincipal.activeTenantId,
          totpSecretCiphertext: "unused-in-recovery-branch",
          attemptCount: 1,
          expiresAt: new Date(Date.now() + 60_000),
        }),
        failMfaChallenge: vi.fn(),
        recordLoginSuccess: vi.fn(),
        appendAudit: vi.fn(),
        createSession,
        revokeSession: vi.fn(),
      },
      mfa: {
        listActiveRecoveryCodes: vi.fn().mockResolvedValue([{ id: "60000000-0000-4000-8000-000000000001", hash: recoveryHash }]),
        consumeRecoveryChallenge: vi.fn().mockResolvedValue(true),
      },
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
          allowPassword: true,
          allowTotpFallback: true,
          allowRecoveryCodes: true,
          absoluteSessionMinutes: 720,
          idleTimeoutMinutes: 30,
          maximumActiveSessions: 10,
        }),
        enforceSessionLimit: vi.fn().mockResolvedValue(0),
        listCredentials: vi.fn().mockResolvedValue([{ revokedAt: null }]),
      },
      getPrincipal: vi.fn().mockResolvedValue(recoveryPrincipal),
      withPrincipal,
    } as unknown as DatabaseRuntime;
    const result = await new AuthService(database, config()).verifyMfa({
      challengeToken: "challenge-token",
      challengeId: "50000000-0000-4000-8000-000000000001",
      recoveryCode,
      requestId: "recovery",
    });
    expect(createSession).toHaveBeenCalledWith(expect.objectContaining({
      assuranceLevel: "recovery_limited",
      authMethod: "recovery_code",
      aal: 1,
      phishingResistant: false,
      recoveryLimited: true,
      idleTimeoutMinutes: RECOVERY_SESSION_WINDOW_MINUTES,
    }));
    const recoverySessionInput = createSession.mock.calls[0]![0] as { expiresAt: Date };
    expect(recoverySessionInput.expiresAt.getTime()).toBeGreaterThan(startedAt);
    expect(recoverySessionInput.expiresAt.getTime()).toBeLessThanOrEqual(
      startedAt + RECOVERY_SESSION_WINDOW_MINUTES * 60_000 + 1_000,
    );
    expect(result.status).toBe("security_recovery_required");
    expect(result.security.recoveryRestricted).toBe(true);
    expect(result.permissions).toEqual([]);
    expect(result.keyGrant).toBeNull();
    expect(withPrincipal).not.toHaveBeenCalled();
  });

  it("returns only non-secret metadata when resuming a pending TOTP enrollment", async () => {
    const enrollmentId = "70000000-0000-4000-8000-000000000001";
    const enrollmentStartedAt = new Date();
    const database = {
      mfa: {
        getPendingEnrollment: vi.fn().mockResolvedValue({
          enrollmentId,
          enrollmentStartedAt,
          enrollmentSecretCiphertext: "deliberately-not-valid-ciphertext",
        }),
      },
    } as unknown as DatabaseRuntime;
    const result = await new AuthService(database, config()).getPendingMfaEnrollment({
      principal: databaseFixturePrincipal(),
    });
    expect(result).toEqual({
      enrollmentId,
      expiresAt: new Date(enrollmentStartedAt.getTime() + 10 * 60_000),
    });
    expect(JSON.stringify(result)).not.toMatch(/secret|otpauth/iu);
  });

  it("does not enroll a password-derived TOTP factor when password authentication is disabled", async () => {
    const startEnrollment = vi.fn();
    const database = {
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
          allowPassword: false,
          allowTotpFallback: true,
        }),
      },
      mfa: { startEnrollment },
    } as unknown as DatabaseRuntime;
    await expect(new AuthService(database, config()).startMfaEnrollment({
      principal: databaseFixturePrincipal(),
      requestId: "totp-password-disabled",
    })).rejects.toMatchObject({ statusCode: 403, code: "TOTP_POLICY_DENIED" });
    expect(startEnrollment).not.toHaveBeenCalled();
  });

  it("creates an MFA challenge for recovery when TOTP fallback is disabled", async () => {
    const passwordHash = await hash("correct-password", { memoryCost: 19_456, timeCost: 2, parallelism: 1 });
    const challengeId = "50000000-0000-4000-8000-000000000001";
    const createMfaChallenge = vi.fn().mockResolvedValue({ challengeId, expiresAt: new Date(Date.now() + 60_000) });
    const database = {
      control: {
        findIdentityForLogin: vi.fn().mockResolvedValue({
          identityId: "20000000-0000-4000-8000-000000000001",
          tenantId: "30000000-0000-4000-8000-000000000001",
          email: "user@example.invalid",
          displayName: "User",
          passwordHash,
          passwordProvisioned: true,
          mfaEnabled: true,
          mfaRequired: true,
          passkeyEnabled: true,
          strongAuthEnabled: true,
          totpSecretCiphertext: "encrypted",
          lockedUntil: null,
        }),
        recordLoginSuccess: vi.fn(),
        appendAudit: vi.fn(),
        createMfaChallenge,
      },
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
          allowPassword: true,
          allowTotpFallback: false,
          allowRecoveryCodes: true,
        }),
      },
    } as unknown as DatabaseRuntime;
    await expect(new AuthService(database, config()).login({
      email: "user@example.invalid",
      password: "correct-password",
      requestId: "recovery-initiation",
    })).resolves.toMatchObject({ status: "mfa_required", challengeId });
    expect(createMfaChallenge).toHaveBeenCalledTimes(1);
    expect(database.control.recordLoginSuccess).not.toHaveBeenCalled();
  });

  it("invalidates an in-flight password MFA challenge when password authentication is disabled", async () => {
    const challengeId = "50000000-0000-4000-8000-000000000088";
    const consumeMfaChallenge = vi.fn().mockResolvedValue(true);
    const failMfaChallenge = vi.fn();
    const appendAudit = vi.fn().mockResolvedValue(undefined);
    const database = {
      control: {
        reserveMfaChallengeAttempt: vi.fn().mockResolvedValue({
          challengeId,
          identityId: "20000000-0000-4000-8000-000000000001",
          tenantId: "30000000-0000-4000-8000-000000000001",
          totpSecretCiphertext: "must-not-be-decrypted",
          attemptCount: 1,
          expiresAt: new Date(Date.now() + 60_000),
        }),
        consumeMfaChallenge,
        failMfaChallenge,
        appendAudit,
      },
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
          allowPassword: false,
          allowTotpFallback: true,
          allowRecoveryCodes: true,
        }),
      },
    } as unknown as DatabaseRuntime;

    await expect(new AuthService(database, config()).verifyMfa({
      challengeToken: "challenge-token",
      challengeId,
      code: "123456",
      requestId: "password-disabled-mid-challenge",
    })).rejects.toMatchObject({ statusCode: 403, code: "MFA_METHOD_POLICY_DENIED" });
    expect(consumeMfaChallenge).toHaveBeenCalledWith(challengeId);
    expect(failMfaChallenge).not.toHaveBeenCalled();
    expect(appendAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: "auth.mfa_policy_denied",
      result: "denied",
    }));
  });

  it("performs verification work only after an atomic MFA-attempt reservation", async () => {
    const challengeId = "50000000-0000-4000-8000-000000000077";
    let reservationNumber = 0;
    const reserveMfaChallengeAttempt = vi.fn(async () => {
      reservationNumber += 1;
      return reservationNumber <= 6
        ? {
            challengeId,
            identityId: "20000000-0000-4000-8000-000000000001",
            tenantId: "30000000-0000-4000-8000-000000000001",
            totpSecretCiphertext: "unused-for-empty-recovery-list",
            attemptCount: reservationNumber,
            expiresAt: new Date(Date.now() + 60_000),
          }
        : null;
    });
    const listActiveRecoveryCodes = vi.fn().mockResolvedValue([]);
    const failMfaChallenge = vi.fn().mockResolvedValue(undefined);
    const database = {
      control: {
        reserveMfaChallengeAttempt,
        failMfaChallenge,
        appendAudit: vi.fn().mockResolvedValue(undefined),
      },
      mfa: { listActiveRecoveryCodes },
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
          allowPassword: true,
          allowTotpFallback: true,
          allowRecoveryCodes: true,
        }),
      },
    } as unknown as DatabaseRuntime;
    const service = new AuthService(database, config());
    const attempts = await Promise.allSettled(Array.from({ length: 8 }, (_, index) => service.verifyMfa({
      challengeToken: "challenge-token",
      challengeId,
      recoveryCode: `ABCD-EFGH-JKLM-${String(index).padStart(4, "A")}`,
      requestId: `parallel-mfa-${index}`,
    })));
    const errorCodes = attempts.map((attempt) =>
      attempt.status === "rejected" ? (attempt.reason as { code?: string }).code : "unexpected-success"
    );
    expect(errorCodes.filter((code) => code === "MFA_CODE_INVALID")).toHaveLength(6);
    expect(errorCodes.filter((code) => code === "MFA_CHALLENGE_INVALID")).toHaveLength(2);
    expect(listActiveRecoveryCodes).toHaveBeenCalledTimes(6);
    expect(failMfaChallenge).toHaveBeenCalledTimes(6);
  });

  it("exposes non-sensitive session risk state to the authenticated client", () => {
    const result = new AuthService({} as DatabaseRuntime, config()).publicSession(
      databaseFixturePrincipal({ userAgentContextChanged: true, ipContextChanged: false }),
      "csrf",
      null,
    );
    expect(result.security.risk).toEqual({
      elevated: true,
      userAgentContextChanged: true,
      ipContextChanged: false,
    });
  });

  it("clamps a tenant switch to the target session policy", async () => {
    const before = Date.now();
    const targetTenantId = "30000000-0000-4000-8000-000000000099";
    const rotatedSessionId = "10000000-0000-4000-8000-000000000099";
    const source = databaseFixturePrincipal({
      assuranceLevel: "mfa",
      authMethod: "totp",
      aal: 2,
      mfaEnabled: true,
      enrollmentOnly: false,
      expiresAt: new Date(before + 2 * 60 * 60_000),
      permissions: new Set(["member.read"]),
    });
    const targetExpiresAt = new Date(before + 10 * 60_000);
    const loaded = {
      ...source,
      sessionId: rotatedSessionId,
      activeTenantId: targetTenantId,
      expiresAt: targetExpiresAt,
    };
    const rotateSessionTenant = vi.fn().mockResolvedValue(rotatedSessionId);
    const targetPolicy = {
      baselineVersion: 1,
      tenantVersion: null,
      enforcementMode: "monitor" as const,
      minimumAal: 1 as const,
      privilegedMinimumAal: 2 as const,
      requireUserVerification: true,
      requirePhishingResistantForPrivileged: true,
      requireDeviceBoundForPrivileged: false,
      requireAttestationForPrivileged: false,
      allowPassword: true,
      allowTotpFallback: true,
      allowRecoveryCodes: true,
      allowSyncedPasskeys: true,
      minimumPasskeyCount: 0,
      privilegedMinimumPasskeyCount: 1,
      maximumPasskeys: 10,
      maximumActiveSessions: 3,
      idleTimeoutMinutes: 5,
      absoluteSessionMinutes: 10,
      stepUpTtlSeconds: 120,
      actionRequirements: {},
    };
    const database = {
      control: {
        hasActiveMembership: vi.fn().mockResolvedValue(true),
        rotateSessionTenant,
        appendAudit: vi.fn(),
        revokeSession: vi.fn(),
      },
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(targetPolicy),
        listCredentials: vi.fn().mockResolvedValue([]),
      },
      getPrincipal: vi.fn().mockResolvedValue(loaded),
      withPrincipal: vi.fn(async (
        _principal: RequestPrincipal,
        _requestId: string,
        work: (tenant: { getKeyGrant(identityId: string): Promise<unknown> }) => Promise<unknown>,
      ) => work({ getKeyGrant: vi.fn().mockResolvedValue({ tenantKeyId: "target-key" }) })),
    } as unknown as DatabaseRuntime;

    const result = await new AuthService(database, config()).switchTenant({
      principal: source,
      targetTenantId,
      requestId: "switch-target-policy",
    });
    expect(rotateSessionTenant).toHaveBeenCalledWith(expect.objectContaining({
      currentSessionId: source.sessionId,
      targetTenantId,
      idleTimeoutMinutes: 5,
    }));
    const rotation = rotateSessionTenant.mock.calls[0]![0] as { expiresAt: Date };
    expect(rotation.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 10 * 60_000 - 1_000);
    expect(rotation.expiresAt.getTime()).toBeLessThanOrEqual(before + 10 * 60_000 + 1_000);
    expect(result.expiresAt).toEqual(targetExpiresAt);
  });

  it("rejects an incompatible target policy before rotating or revoking the source session", async () => {
    const targetTenantId = "30000000-0000-4000-8000-000000000098";
    const source = databaseFixturePrincipal({
      assuranceLevel: "password",
      authMethod: "password",
      aal: 1,
      mfaRequired: false,
      enrollmentOnly: false,
    });
    const rotateSessionTenant = vi.fn();
    const revokeSession = vi.fn();
    const database = {
      control: {
        hasActiveMembership: vi.fn().mockResolvedValue(true),
        rotateSessionTenant,
        appendAudit: vi.fn(),
        revokeSession,
      },
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
          baselineVersion: 1,
          tenantVersion: 2,
          enforcementMode: "monitor",
          minimumAal: 1,
          privilegedMinimumAal: 2,
          requireUserVerification: true,
          requirePhishingResistantForPrivileged: true,
          requireDeviceBoundForPrivileged: false,
          requireAttestationForPrivileged: false,
          allowPassword: false,
          allowTotpFallback: true,
          allowRecoveryCodes: true,
          allowSyncedPasskeys: true,
          minimumPasskeyCount: 0,
          privilegedMinimumPasskeyCount: 1,
          maximumPasskeys: 10,
          maximumActiveSessions: 3,
          idleTimeoutMinutes: 5,
          absoluteSessionMinutes: 10,
          stepUpTtlSeconds: 120,
          actionRequirements: {},
        }),
        listCredentials: vi.fn().mockResolvedValue([]),
      },
    } as unknown as DatabaseRuntime;

    await expect(new AuthService(database, config()).switchTenant({
      principal: source,
      targetTenantId,
      requestId: "switch-target-policy-denied",
    })).rejects.toMatchObject({
      statusCode: 428,
      code: "TARGET_TENANT_SECURITY_UPGRADE_REQUIRED",
      details: { findings: ["password_authentication_disabled"] },
    });
    expect(rotateSessionTenant).not.toHaveBeenCalled();
    expect(revokeSession).not.toHaveBeenCalled();
  });

  it.each([
    ["monitor", "authenticated", false],
    ["enforce", "mfa_enrollment_required", true],
  ] as const)("applies minimum assurance targets in %s mode without leaking tenant grants", async (
    enforcementMode,
    expectedStatus,
    restricted,
  ) => {
    const passwordHash = await hash("correct-password", { memoryCost: 19_456, timeCost: 2, parallelism: 1 });
    const sessionId = "10000000-0000-4000-8000-000000000077";
    const loadedPrincipal: RequestPrincipal = {
      sessionId,
      identityId: "20000000-0000-4000-8000-000000000001",
      activeTenantId: "30000000-0000-4000-8000-000000000001",
      email: "user@example.invalid",
      displayName: "User",
      tenantSlug: "fixture",
      tenantName: "Fixture",
      tenantKind: "real",
      tenantTimezone: "America/La_Paz",
      csrfHash: "csrf",
      expiresAt: new Date(Date.now() + 60_000),
      assuranceLevel: "password",
      authenticatedAt: new Date(),
      mfaVerifiedAt: null,
      mfaRequired: false,
      mfaEnabled: false,
      passkeyEnabled: false,
      strongAuthEnabled: false,
      authMethod: "password",
      aal: 1,
      phishingResistant: false,
      enrollmentOnly: false,
      permissions: new Set(["member.read"]),
    };
    const withPrincipal = vi.fn(async (
      _principal: RequestPrincipal,
      _requestId: string,
      work: (tenant: { getKeyGrant(identityId: string): Promise<unknown> }) => Promise<unknown>,
    ) => work({ getKeyGrant: vi.fn().mockResolvedValue({ tenantKeyId: "key" }) }));
    const database = {
      control: {
        findIdentityForLogin: vi.fn().mockResolvedValue({
          identityId: loadedPrincipal.identityId,
          email: loadedPrincipal.email,
          displayName: loadedPrincipal.displayName,
          passwordHash,
          passwordProvisioned: true,
          mfaEnabled: false,
          mfaRequired: false,
          passkeyEnabled: false,
          strongAuthEnabled: false,
          totpSecretCiphertext: null,
          tenantId: loadedPrincipal.activeTenantId,
          lockedUntil: null,
        }),
        appendAudit: vi.fn(),
        recordLoginSuccess: vi.fn(),
        createSession: vi.fn().mockResolvedValue(sessionId),
      },
      enterpriseAuth: {
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
          enforcementMode,
          minimumAal: 2,
          minimumPasskeyCount: 1,
          allowPassword: true,
          allowTotpFallback: true,
          allowRecoveryCodes: true,
          allowSyncedPasskeys: true,
          absoluteSessionMinutes: 720,
          idleTimeoutMinutes: 30,
          maximumActiveSessions: 10,
        }),
        enforceSessionLimit: vi.fn().mockResolvedValue(0),
        listCredentials: vi.fn().mockResolvedValue([]),
      },
      getPrincipal: vi.fn().mockResolvedValue(loadedPrincipal),
      withPrincipal,
    } as unknown as DatabaseRuntime;
    const result = await new AuthService(database, config()).login({
      email: loadedPrincipal.email,
      password: "correct-password",
      requestId: `policy-${enforcementMode}`,
    });
    expect(result.status).toBe(expectedStatus);
    if (!("authenticated" in result)) throw new Error("Expected an authenticated session response");
    expect(result.permissions).toEqual(restricted ? [] : ["member.read"]);
    expect(result.keyGrant).toEqual(restricted ? null : { tenantKeyId: "key" });
    expect(withPrincipal).toHaveBeenCalledTimes(restricted ? 0 : 1);
  });
});

function databaseFixture(passwordHash: string, passkeyEnabled: boolean, createSession: ReturnType<typeof vi.fn>): DatabaseRuntime {
  const principal = databaseFixturePrincipal({
    passkeyEnabled,
    strongAuthEnabled: passkeyEnabled,
  });
  return {
    control: {
      findIdentityForLogin: vi.fn().mockResolvedValue({
        identityId: principal.identityId,
        email: principal.email,
        displayName: principal.displayName,
        passwordHash,
        passwordProvisioned: true,
        mfaEnabled: false,
        mfaRequired: true,
        passkeyEnabled,
        strongAuthEnabled: passkeyEnabled,
        totpSecretCiphertext: null,
        tenantId: principal.activeTenantId,
        lockedUntil: null,
      }),
      appendAudit: vi.fn().mockResolvedValue(undefined),
      recordLoginSuccess: vi.fn().mockResolvedValue(undefined),
      createSession,
      revokeSession: vi.fn().mockResolvedValue(undefined),
    },
    enterpriseAuth: {
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
        allowPassword: true,
        allowTotpFallback: true,
        absoluteSessionMinutes: 720,
        idleTimeoutMinutes: 30,
        maximumActiveSessions: 10,
      }),
      enforceSessionLimit: vi.fn().mockResolvedValue(0),
      listCredentials: vi.fn().mockResolvedValue([]),
    },
    getPrincipal: vi.fn().mockResolvedValue(principal),
  } as unknown as DatabaseRuntime;
}

function databaseFixturePrincipal(overrides: Partial<RequestPrincipal> = {}): RequestPrincipal {
  return {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "user@example.invalid",
    displayName: "User",
    tenantSlug: "fixture",
    tenantName: "Fixture",
    tenantKind: "real",
    tenantTimezone: "America/La_Paz",
    csrfHash: "csrf",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "enrollment_only",
    authenticatedAt: new Date(),
    mfaVerifiedAt: null,
    mfaRequired: true,
    mfaEnabled: false,
    passkeyEnabled: false,
    strongAuthEnabled: false,
    authMethod: "bootstrap",
    aal: 1,
    phishingResistant: false,
    enrollmentOnly: true,
    permissions: new Set(),
    ...overrides,
  };
}

function config(): ApiConfig {
  return {
    environment: "test",
    host: "127.0.0.1",
    port: 0,
    corsOrigins: new Set(["http://localhost:3000"]),
    secureCookies: false,
    sessionTtlSeconds: 3_600,
    webauthn: { rpName: "Nombramientos", rpId: "localhost", expectedOrigins: ["http://localhost:3000"], challengeTtlSeconds: 300, stepUpTtlSeconds: 120 },
    authEncryptionKey: Buffer.alloc(32),
    controlDatabaseUrl: "postgresql://unused:unused@127.0.0.1:55432/unused",
    secretMasterKey: Buffer.alloc(32),
    secretFile: "unused",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
}
