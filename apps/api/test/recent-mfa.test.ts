import type { RequestPrincipal } from "@nombramientos/database";
import { describe, expect, it } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import {
  RECENT_MFA_WINDOW_MS,
  assertMfaAssurance,
  assertPhishingResistantAssurance,
  assertRecentMfa,
} from "../src/lib/recent-mfa.js";

const now = new Date("2026-09-11T12:00:00.000Z");

describe("recent MFA boundary", () => {
  it("trusts the GestionChurch federated session without requesting a second local factor", () => {
    const federated = principal({
      assuranceLevel: "password",
      authMethod: "federated",
      aal: 1,
      mfaEnabled: false,
      mfaRequired: false,
      mfaVerifiedAt: null,
      phishingResistant: false,
    });
    expect(() => assertMfaAssurance(federated, "access administration")).not.toThrow();
    expect(() => assertRecentMfa(federated, { purpose: "access administration", now })).not.toThrow();
    expect(() => assertPhishingResistantAssurance(federated, "access administration")).not.toThrow();
  });

  it("accepts a current second-factor proof within the shared five-minute window", () => {
    expect(() => assertRecentMfa(principal({
      mfaVerifiedAt: new Date(now.getTime() - RECENT_MFA_WINDOW_MS + 1),
    }), { purpose: "exporting", now })).not.toThrow();
  });

  it("requires step-up at the exact expiry boundary", () => {
    expectApiError(() => assertRecentMfa(principal({
      mfaVerifiedAt: new Date(now.getTime() - RECENT_MFA_WINDOW_MS),
    }), { purpose: "exporting", now }), 428, "MFA_STEP_UP_REQUIRED");
  });

  it.each([
    ["user agent", { userAgentContextChanged: true }],
    ["IP prefix", { ipContextChanged: true }],
  ] as const)("requires phishing-resistant reauthentication when %s risk is elevated", (_label, risk) => {
    expectApiError(() => assertRecentMfa(principal(risk), {
      purpose: "changing security settings",
      now,
    }), 428, "SESSION_RISK_STEP_UP_REQUIRED");
  });

  it("does not treat password-only or disabled MFA as strong assurance", () => {
    expectApiError(() => assertMfaAssurance(principal({
      assuranceLevel: "password",
      mfaEnabled: false,
      mfaVerifiedAt: null,
    }), "access administration"), 403, "MFA_ASSURANCE_REQUIRED");
  });

  it("lets an established flow retain a specific stale-step-up code", () => {
    expectApiError(() => assertRecentMfa(principal({
      mfaVerifiedAt: new Date(now.getTime() - RECENT_MFA_WINDOW_MS),
    }), {
      purpose: "tenant-key lifecycle operations",
      now,
      staleCode: "KEY_LIFECYCLE_STEP_UP_REQUIRED",
    }), 428, "KEY_LIFECYCLE_STEP_UP_REQUIRED");
  });

  it("recognizes a user-verified passkey as AAL2 without conflating TOTP state", () => {
    const passkeyPrincipal = principal({
      mfaEnabled: false,
      passkeyEnabled: true,
      strongAuthEnabled: true,
      authMethod: "passkey",
      aal: 2,
      phishingResistant: true,
    });
    expect(() => assertMfaAssurance(passkeyPrincipal, "security administration")).not.toThrow();
    expect(() => assertPhishingResistantAssurance(passkeyPrincipal, "security administration")).not.toThrow();
  });

  it("never treats TOTP or recovery as phishing resistant", () => {
    expectApiError(() => assertPhishingResistantAssurance(principal({
      authMethod: "totp",
      aal: 2,
      phishingResistant: false,
    }), "exporting"), 428, "PHISHING_RESISTANT_STEP_UP_REQUIRED");
    expectApiError(() => assertMfaAssurance(principal({
      assuranceLevel: "recovery_limited",
      authMethod: "recovery_code",
      aal: 1,
      phishingResistant: false,
      recoveryLimited: true,
      mfaVerifiedAt: null,
    }), "exporting"), 403, "MFA_ASSURANCE_REQUIRED");
  });
});

function principal(overrides: Partial<RequestPrincipal> = {}): RequestPrincipal {
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
    expiresAt: new Date(now.getTime() + 60_000),
    assuranceLevel: "mfa",
    authenticatedAt: new Date(now.getTime() - 60_000),
    mfaVerifiedAt: now,
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions: new Set(),
    ...overrides,
  };
}

function expectApiError(work: () => void, statusCode: number, code: string): void {
  try {
    work();
    throw new Error("Expected MFA policy to reject the principal");
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ statusCode, code });
  }
}
