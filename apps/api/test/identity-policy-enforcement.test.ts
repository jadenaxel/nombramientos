import type {
  DatabaseRuntime,
  EffectiveIdentityPolicy,
  RequestPrincipal,
} from "@nombramientos/database";
import { describe, expect, it, vi } from "vitest";
import { evaluateIdentitySessionPolicy } from "../src/lib/identity-policy-enforcement.js";

describe("identity session policy enforcement", () => {
  it("reports AAL/passkey targets in monitor mode without removing access", async () => {
    const principal = principalFixture();
    const decision = await evaluateIdentitySessionPolicy(
      databaseFixture(policy({ enforcementMode: "monitor", minimumAal: 2, minimumPasskeyCount: 1 })),
      principal,
    );
    expect(decision.policyRestricted).toBe(false);
    expect(decision.principal).toBe(principal);
    expect(decision.findings).toEqual(expect.arrayContaining([
      "session_aal_below_minimum",
      "passkey_count_below_minimum",
    ]));
  });

  it("removes permissions and marks the session for upgrade when enforce targets are unmet", async () => {
    const decision = await evaluateIdentitySessionPolicy(
      databaseFixture(policy({ enforcementMode: "enforce", minimumAal: 2, minimumPasskeyCount: 1 })),
      principalFixture(),
    );
    expect(decision.policyRestricted).toBe(true);
    expect(decision.principal.enrollmentOnly).toBe(true);
    expect([...decision.principal.permissions]).toEqual([]);
  });

  it("enforces explicit authentication-method denial even during monitor rollout", async () => {
    const decision = await evaluateIdentitySessionPolicy(
      databaseFixture(policy({ enforcementMode: "monitor", allowPassword: false })),
      principalFixture(),
    );
    expect(decision.policyRestricted).toBe(true);
    expect(decision.findings).toContain("password_authentication_disabled");
    expect([...decision.principal.permissions]).toEqual([]);
  });

  it.each(["totp", "recovery_code"] as const)(
    "treats %s as password-derived when password authentication is disabled",
    async (authMethod) => {
      const decision = await evaluateIdentitySessionPolicy(
        databaseFixture(policy({ enforcementMode: "monitor", allowPassword: false })),
        principalFixture({
          assuranceLevel: authMethod === "totp" ? "mfa" : "recovery_limited",
          authMethod,
          aal: authMethod === "totp" ? 2 : 1,
          mfaRequired: true,
          mfaEnabled: true,
          recoveryLimited: authMethod === "recovery_code",
        }),
      );
      expect(decision.policyRestricted).toBe(true);
      expect(decision.findings).toContain("password_authentication_disabled");
      expect([...decision.principal.permissions]).toEqual([]);
    },
  );

  it("does not count a synced passkey toward an enforced device-bound minimum", async () => {
    const decision = await evaluateIdentitySessionPolicy(
      databaseFixture(
        policy({ enforcementMode: "enforce", allowSyncedPasskeys: false, minimumPasskeyCount: 1 }),
        [{ revokedAt: null, userVerified: true, deviceType: "multiDevice" }],
      ),
      principalFixture({ assuranceLevel: "mfa", authMethod: "totp", aal: 2, mfaRequired: true, mfaEnabled: true }),
    );
    expect(decision.activePasskeyCount).toBe(1);
    expect(decision.policyEligiblePasskeyCount).toBe(0);
    expect(decision.policyRestricted).toBe(true);
    expect(decision.findings).toContain("passkey_count_below_minimum");
  });
});

function databaseFixture(
  effectivePolicy: EffectiveIdentityPolicy,
  credentials: readonly Record<string, unknown>[] = [],
): DatabaseRuntime {
  return {
    enterpriseAuth: {
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(effectivePolicy),
      listCredentials: vi.fn().mockResolvedValue(credentials),
    },
  } as unknown as DatabaseRuntime;
}

function policy(overrides: Partial<EffectiveIdentityPolicy> = {}): EffectiveIdentityPolicy {
  return {
    tenantId: "30000000-0000-4000-8000-000000000001",
    baselineVersion: 1,
    tenantVersion: null,
    enforcementMode: "monitor",
    minimumAal: 1,
    privilegedMinimumAal: 2,
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
    maximumActiveSessions: 10,
    idleTimeoutMinutes: 30,
    absoluteSessionMinutes: 720,
    stepUpTtlSeconds: 120,
    actionRequirements: {},
    ...overrides,
  };
}

function principalFixture(overrides: Partial<RequestPrincipal> = {}): RequestPrincipal {
  return {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "fixture@example.invalid",
    displayName: "Fixture",
    tenantSlug: "fixture",
    tenantName: "Fixture tenant",
    tenantKind: "real",
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
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
    ...overrides,
  };
}
