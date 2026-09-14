import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import {
  authenticationResponseSchema,
  challengeMatchesDigest,
  hashStepUpOperation,
  identityPolicyValuesSchema,
  passkeyRegistrationOptionsSchema,
  registrationResponseSchema,
  requireExactWebAuthnOrigin,
} from "../src/modules/enterprise-auth-contract.js";

describe("enterprise authentication wire contract", () => {
  it("rejects credentials whose id and rawId diverge", () => {
    const common = {
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
    };
    expect(registrationResponseSchema.safeParse({
      ...common,
      id: "credential-a",
      rawId: "credential-b",
      response: { clientDataJSON: "Y2xpZW50", attestationObject: "YXR0ZXN0YXRpb24" },
    }).success).toBe(false);
    expect(authenticationResponseSchema.safeParse({
      ...common,
      id: "credential-a",
      rawId: "credential-b",
      response: { clientDataJSON: "Y2xpZW50", authenticatorData: "YXV0aA", signature: "c2ln" },
    }).success).toBe(false);
  });

  it("matches a challenge only through its SHA-256 digest", () => {
    const challenge = "private-ceremony-challenge";
    const digest = createHash("sha256").update(challenge).digest("hex");
    expect(challengeMatchesDigest(challenge, digest)).toBe(true);
    expect(challengeMatchesDigest(`${challenge}-replayed`, digest)).toBe(false);
    expect(challengeMatchesDigest(challenge, "not-a-digest")).toBe(false);
  });

  it("binds step-up grants to purpose, method, path, and body digest", () => {
    const path = "/v1/auth/passkeys/10000000-0000-4000-8000-000000000001";
    const body = { reason: "lost", nested: { b: 2, a: 1 } };
    const expected = hashStepUpOperation("identity_security_change", "DELETE", path, body);
    expect(hashStepUpOperation("identity_security_change", "DELETE", path, { nested: { a: 1, b: 2 }, reason: "lost" })).toBe(expected);
    expect(hashStepUpOperation("session_revocation", "DELETE", path, body)).not.toBe(expected);
    expect(hashStepUpOperation("identity_security_change", "PATCH", path, body)).not.toBe(expected);
    expect(hashStepUpOperation("identity_security_change", "DELETE", path, { ...body, reason: "compromised" })).not.toBe(expected);
    expect(() => hashStepUpOperation("identity_security_change", "DELETE", `${path}?force=true`, body))
      .toThrowError(expect.objectContaining({ code: "STEP_UP_OPERATION_INVALID" }));
  });

  it("requires the exact configured origin instead of accepting a related host", () => {
    const origins = ["https://login.example.test"] as const;
    expect(requireExactWebAuthnOrigin(origins[0], origins)).toBe(origins[0]);
    expect(() => requireExactWebAuthnOrigin("https://evil.example.test", origins)).toThrow(ApiError);
    expect(() => requireExactWebAuthnOrigin(undefined, origins)).toThrow(ApiError);
  });

  it("rejects a privileged passkey minimum below the ordinary minimum", () => {
    expect(identityPolicyValuesSchema.safeParse({
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
      minimumPasskeyCount: 2,
      privilegedMinimumPasskeyCount: 1,
      maximumPasskeys: 10,
      maximumActiveSessions: 10,
      idleTimeoutMinutes: 30,
      absoluteSessionMinutes: 720,
      stepUpTtlSeconds: 120,
      actionRequirements: {},
    }).success).toBe(false);
  });

  it("accepts only an optional UUID for atomic passkey replacement", () => {
    const replacementCredentialId = "40000000-0000-4000-8000-000000000001";
    expect(passkeyRegistrationOptionsSchema.parse({ replacementCredentialId })).toEqual({ replacementCredentialId });
    expect(passkeyRegistrationOptionsSchema.safeParse({ replacementCredentialId: "not-a-uuid" }).success).toBe(false);
    expect(passkeyRegistrationOptionsSchema.safeParse({ replacementCredentialId, force: true }).success).toBe(false);
  });
});
