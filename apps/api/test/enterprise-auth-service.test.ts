import { createHash } from "node:crypto";
import {
  EnterpriseAuthStoreError,
  type DatabaseRuntime,
  type RequestPrincipal,
} from "@nombramientos/database";
import type {
  AuthenticationResponseJSON,
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import { describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import { ApiError } from "../src/lib/errors.js";
import { hashStepUpOperation } from "../src/modules/enterprise-auth-contract.js";
import { AuthService, createSessionBinding } from "../src/modules/auth-service.js";
import {
  EnterpriseAuthService,
  type WebAuthnEngine,
} from "../src/modules/enterprise-auth-service.js";

const identityId = "20000000-0000-4000-8000-000000000001";
const tenantId = "30000000-0000-4000-8000-000000000001";
const sessionId = "10000000-0000-4000-8000-000000000001";
const credentialInternalId = "40000000-0000-4000-8000-000000000001";
const credentialExternalId = "Y3JlZGVudGlhbC0x";
const challenge = "d2ViYXV0aG4tY2hhbGxlbmdl";
const origin = "http://localhost:3000";
const secondaryOrigin = "http://localhost:3001";

describe("EnterpriseAuthService security boundary", () => {
  it("keeps public passkey options usernameless and independent of password lock state", async () => {
    const generate = vi.fn(async (_options: GenerateAuthenticationOptionsOpts) => authenticationOptions());
    const store = storeFixture();
    const findIdentityForLogin = vi.fn();
    const service = serviceFixture(store, { generateAuthenticationOptions: generate }, { findIdentityForLogin });

    const withEmail = await service.authenticationOptions({
      email: "known@example.invalid",
      mediation: "optional",
      origin,
    });
    const withoutEmail = await service.authenticationOptions({ mediation: "conditional", origin });

    expect(findIdentityForLogin).not.toHaveBeenCalled();
    expect(generate).toHaveBeenCalledTimes(2);
    for (const [options] of generate.mock.calls) expect(options).not.toHaveProperty("allowCredentials");
    expect(withEmail.options).toEqual(withoutEmail.options);
    expect(store.createCeremony).toHaveBeenCalledWith(expect.not.objectContaining({ identityId: expect.anything() }));
  });

  it("allows a cryptographically valid passkey session without consulting password lockout", async () => {
    const completedSessionId = "10000000-0000-4000-8000-000000000099";
    const findIdentityForLogin = vi.fn(() => {
      throw new Error("password lock state must not be consulted by passkey authentication");
    });
    const store = storeFixture({
      listCredentials: vi.fn().mockResolvedValue([storedCredential()]),
      completeAuthentication: vi.fn().mockResolvedValue({
        sessionId: completedSessionId,
        identityId,
        tenantId,
      }),
    });
    const loadedPrincipal = principal({
      sessionId: completedSessionId,
      authMethod: "passkey",
      authenticatedCredentialId: credentialInternalId,
      assuranceLevel: "mfa",
      aal: 2,
      phishingResistant: true,
      passkeyEnabled: true,
      strongAuthEnabled: true,
    });
    const database = {
      enterpriseAuth: store,
      control: {
        findIdentityForLogin,
        recordLoginSuccess: vi.fn().mockResolvedValue(undefined),
        revokeSession: vi.fn().mockResolvedValue(undefined),
      },
      getPrincipal: vi.fn().mockResolvedValue(loadedPrincipal),
      withPrincipal: vi.fn(async (
        _principal: RequestPrincipal,
        _requestId: string,
        work: (tenant: { getKeyGrant(identityId: string): Promise<unknown> }) => Promise<unknown>,
      ) => work({ getKeyGrant: vi.fn().mockResolvedValue(null) })),
    } as unknown as DatabaseRuntime;
    const authService = new AuthService(database, config());
    const service = new EnterpriseAuthService(database, config(), authService, {
      generateRegistrationOptions: vi.fn(async () => registrationOptions()),
      verifyRegistrationResponse: vi.fn(),
      generateAuthenticationOptions: vi.fn(async () => authenticationOptions()),
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication()),
    } as unknown as WebAuthnEngine);

    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "passkey-bypasses-password-lock",
      origin,
    })).resolves.toMatchObject({
      authenticated: true,
      status: "authenticated",
      security: { authMethod: "passkey", aal: 2, phishingResistant: true },
    });
    expect(findIdentityForLogin).not.toHaveBeenCalled();
    expect(database.control.recordLoginSuccess).toHaveBeenCalledWith(identityId);
    expect(store.enforceSessionLimit).toHaveBeenCalledWith(identityId, tenantId, completedSessionId, 10);
  });

  it("requires exact origin before consulting credentials or cryptography", async () => {
    const store = storeFixture();
    const verify = vi.fn();
    const service = serviceFixture(store, { verifyAuthenticationResponse: verify });
    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-origin",
      origin: "http://127.0.0.1:3000",
    })).rejects.toMatchObject({ statusCode: 403, code: "WEBAUTHN_ORIGIN_DENIED" });
    expect(store.getActiveCeremony).not.toHaveBeenCalled();
    expect(verify).not.toHaveBeenCalled();
  });

  it.each([
    [
      "stored origin",
      ceremony({ expectedOrigin: secondaryOrigin }),
      { origin },
      { originMismatch: true, userAgentMismatch: false, ipContextMismatch: false },
    ],
    [
      "user agent",
      ceremony({ userAgentHash: createSessionBinding("Expected Browser").userAgentHash }),
      { origin, userAgent: "Different Browser" },
      { originMismatch: false, userAgentMismatch: true, ipContextMismatch: false },
    ],
    [
      "coarse IP prefix",
      ceremony({ ipPrefixHash: createSessionBinding(undefined, "203.0.113.17").ipPrefixHash }),
      { origin, ip: "198.51.100.9" },
      { originMismatch: false, userAgentMismatch: false, ipContextMismatch: true },
    ],
  ] as const)("fails closed when the ceremony %s binding changes", async (_label, activeCeremony, context, mismatch) => {
    const store = storeFixture({}, activeCeremony);
    const verify = vi.fn();
    const appendAudit = vi.fn().mockResolvedValue(undefined);
    const service = serviceFixture(store, { verifyAuthenticationResponse: verify }, { appendAudit });

    await expect(service.verifyAuthentication({
      ceremonyId: activeCeremony.id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-binding",
      ...context,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_CEREMONY_INVALID" });
    expect(verify).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
    expect(appendAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: "auth.webauthn_ceremony_binding_denied",
      result: "denied",
      metadata: expect.objectContaining(mismatch),
    }));
  });

  it.each([
    ["cross-origin", { crossOrigin: true }],
    ["top-origin", { crossOrigin: false, topOrigin: "https://embedder.example.invalid" }],
    ["malformed cross-origin", { crossOrigin: "false" }],
  ] as const)("rejects %s authentication client data before cryptographic verification", async (_label, clientData) => {
    const store = storeFixture();
    const verify = vi.fn();
    const service = serviceFixture(store, { verifyAuthenticationResponse: verify });

    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(clientData),
      requestId: `request-client-data-${_label}`,
      origin,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_VERIFICATION_FAILED" });
    expect(verify).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["cross-origin", { crossOrigin: true }],
    ["top-origin", { crossOrigin: false, topOrigin: "https://embedder.example.invalid" }],
  ] as const)("rejects %s registration client data before cryptographic verification", async (_label, clientData) => {
    const activeCeremony = ceremony({ type: "registration", identityId, tenantId, sessionId });
    const store = storeFixture({}, activeCeremony);
    const verify = vi.fn();
    const service = serviceFixture(store, { verifyRegistrationResponse: verify });

    await expect(service.verifyRegistration({
      principal: principal(),
      ceremonyId: activeCeremony.id,
      ceremonyToken: "c".repeat(43),
      response: registrationResponse(clientData),
      displayName: "Laptop",
      requestId: `request-registration-client-data-${_label}`,
      origin,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_VERIFICATION_FAILED" });
    expect(verify).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it("applies the same cross-origin rejection to step-up assertions", async () => {
    const activeCeremony = ceremony({
      type: "step_up",
      identityId,
      tenantId,
      sessionId,
      purpose: "data_export",
      operationHash: "f".repeat(64),
    });
    const store = storeFixture({}, activeCeremony);
    const verify = vi.fn();
    const service = serviceFixture(store, { verifyAuthenticationResponse: verify });

    await expect(service.verifyStepUp({
      principal: principal(),
      ceremonyId: activeCeremony.id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse({ crossOrigin: true }),
      requestId: "request-step-up-cross-origin",
      origin,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_VERIFICATION_FAILED" });
    expect(verify).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it("fails a ceremony when challenge or user verification is invalid", async () => {
    const store = storeFixture();
    const verify = vi.fn(async (options: Parameters<WebAuthnEngine["verifyAuthenticationResponse"]>[0]) => {
      expect(typeof options.expectedChallenge).toBe("function");
      expect(await (options.expectedChallenge as (candidate: string) => boolean)("a-different-challenge")).toBe(false);
      throw new Error("cryptographic detail must not escape");
    });
    const service = serviceFixture(store, { verifyAuthenticationResponse: verify as WebAuthnEngine["verifyAuthenticationResponse"] });
    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-challenge",
      origin,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_VERIFICATION_FAILED" });
    expect(store.failCeremony).toHaveBeenCalledTimes(1);

    const uvService = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication({ userVerified: false })),
    });
    await expect(uvService.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-uv",
      origin,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_VERIFICATION_FAILED" });
    expect(store.failCeremony).toHaveBeenCalledTimes(2);
  });

  it("rejects an authentication assertion whose immutable device type changed", async () => {
    const store = storeFixture();
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(
        verifiedAuthentication({ credentialDeviceType: "multiDevice" }),
      ),
    });
    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-auth-device-type",
      origin,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_VERIFICATION_FAILED" });
    expect(store.completeAuthentication).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it("rejects a step-up assertion whose immutable device type changed", async () => {
    const activeCeremony = ceremony({
      type: "step_up",
      identityId,
      tenantId,
      sessionId,
      purpose: "data_export",
      operationHash: "f".repeat(64),
    });
    const store = storeFixture({}, activeCeremony);
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(
        verifiedAuthentication({ credentialDeviceType: "multiDevice" }),
      ),
    });
    await expect(service.verifyStepUp({
      principal: principal(),
      ceremonyId: activeCeremony.id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-step-up-device-type",
      origin,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_VERIFICATION_FAILED" });
    expect(store.completeWebAuthnStepUp).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it("rejects revoked or unknown credentials before signature verification", async () => {
    const store = storeFixture({ getCredentialByExternalId: vi.fn().mockResolvedValue(null) });
    const verify = vi.fn();
    const service = serviceFixture(store, { verifyAuthenticationResponse: verify });
    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-revoked",
      origin,
    })).rejects.toMatchObject({ statusCode: 401, code: "WEBAUTHN_VERIFICATION_FAILED" });
    expect(verify).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it("uses the same public failure for a revoked credential", async () => {
    const store = storeFixture({
      getCredentialByExternalId: vi.fn().mockResolvedValue(credential({ revokedAt: new Date() })),
    });
    const verify = vi.fn();
    const service = serviceFixture(store, { verifyAuthenticationResponse: verify });
    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-revoked",
      origin,
    })).rejects.toMatchObject({
      statusCode: 401,
      code: "WEBAUTHN_VERIFICATION_FAILED",
      message: "Passkey verification failed",
    });
    expect(verify).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it("denies public authentication with a policy-disabled synced passkey", async () => {
    const store = storeFixture({
      getCredentialByExternalId: vi.fn().mockResolvedValue(credential({ deviceType: "multiDevice" })),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({ allowSyncedPasskeys: false })),
    });
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication({ credentialDeviceType: "multiDevice" })),
    });
    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-synced-login",
      origin,
    })).rejects.toMatchObject({ statusCode: 403, code: "PASSKEY_POLICY_DENIED" });
    expect(store.completeAuthentication).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it("maps an atomic counter/ceremony replay to a generic authentication failure", async () => {
    const store = storeFixture({
      completeAuthentication: vi.fn().mockRejectedValue(
        new EnterpriseAuthStoreError("CREDENTIAL_REPLAYED", "sensitive counter detail"),
      ),
    });
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication()),
    });
    await expect(service.verifyAuthentication({
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-replay",
      origin,
    })).rejects.toMatchObject({
      statusCode: 401,
      code: "WEBAUTHN_VERIFICATION_FAILED",
      message: "Passkey verification failed",
    });
  });

  it.each([
    ["device-bound", { enforcementMode: "enforce", requireDeviceBoundForPrivileged: true }, credential({ deviceType: "multiDevice" }), "DEVICE_BOUND_PASSKEY_REQUIRED"],
    ["attested", { enforcementMode: "enforce", requireAttestationForPrivileged: true }, credential({ trustLevel: "unverified" }), "ATTESTED_PASSKEY_REQUIRED"],
    ["AAL3", { enforcementMode: "enforce", privilegedMinimumAal: 3 }, credential(), "AAL3_REQUIRED"],
  ] as const)("fails closed when privileged policy requires %s", async (_label, policyOverride, passkey, code) => {
    const store = storeFixture({
      getCredentialByExternalId: vi.fn().mockResolvedValue(passkey),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy(policyOverride)),
    }, ceremony({ type: "step_up", identityId, tenantId, sessionId, purpose: "data_export", operationHash: "a".repeat(64) }));
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication({
        credentialDeviceType: passkey.deviceType as "singleDevice" | "multiDevice",
      })),
    });
    await expect(service.verifyStepUp({
      principal: principal(),
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-policy",
      origin,
    })).rejects.toMatchObject({ statusCode: 403, code });
    expect(store.completeWebAuthnStepUp).not.toHaveBeenCalled();
    expect(store.failCeremony).toHaveBeenCalledTimes(1);
  });

  it("reports tightened privileged policy in monitor mode without blocking valid WebAuthn", async () => {
    const store = storeFixture({
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({
        enforcementMode: "monitor",
        privilegedMinimumAal: 3,
        requireDeviceBoundForPrivileged: true,
        requireAttestationForPrivileged: true,
      })),
      completeWebAuthnStepUp: vi.fn().mockResolvedValue({
        grantId: "70000000-0000-4000-8000-000000000001",
        expiresAt: new Date(Date.now() + 60_000),
      }),
    }, ceremony({ type: "step_up", identityId, tenantId, sessionId, purpose: "data_export", operationHash: "a".repeat(64) }));
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication()),
    });
    await expect(service.verifyStepUp({
      principal: principal(),
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-monitor-policy",
      origin,
    })).resolves.toMatchObject({ verified: true, purpose: "data_export", operationHash: "a".repeat(64) });
    expect(store.completeWebAuthnStepUp).toHaveBeenCalledWith(expect.objectContaining({
      assertedDeviceType: "singleDevice",
    }));
  });

  it("permits step-up in an active non-default tenant for an identity-global credential", async () => {
    const defaultTenantId = "30000000-0000-4000-8000-000000000099";
    const activeCeremony = ceremony({
      type: "step_up",
      identityId,
      tenantId,
      sessionId,
      purpose: "tenant_administration",
      operationHash: "e".repeat(64),
    });
    const store = storeFixture({
      getCredentialByExternalId: vi.fn().mockResolvedValue(credential({ tenantId: defaultTenantId })),
      completeWebAuthnStepUp: vi.fn().mockResolvedValue({
        grantId: "70000000-0000-4000-8000-000000000099",
        expiresAt: new Date(Date.now() + 60_000),
      }),
    }, activeCeremony);
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication()),
    });

    await expect(service.verifyStepUp({
      principal: principal({ activeTenantId: tenantId }),
      ceremonyId: activeCeremony.id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-non-default-tenant",
      origin,
    })).resolves.toMatchObject({ verified: true, purpose: "tenant_administration" });
    expect(store.completeWebAuthnStepUp).toHaveBeenCalledTimes(1);
  });

  it("keeps personal security remediation available with any valid UV passkey", async () => {
    const passkey = credential({ deviceType: "multiDevice", trustLevel: "unverified" });
    const store = storeFixture({
      getCredentialByExternalId: vi.fn().mockResolvedValue(passkey),
      listCredentials: vi.fn().mockResolvedValue([storedCredential({ deviceType: "multiDevice" })]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({
        enforcementMode: "enforce",
        privilegedMinimumAal: 3,
        requireDeviceBoundForPrivileged: true,
        requireAttestationForPrivileged: true,
        allowSyncedPasskeys: false,
      })),
      completeWebAuthnStepUp: vi.fn().mockResolvedValue({
        grantId: "70000000-0000-4000-8000-000000000001",
        expiresAt: new Date(Date.now() + 60_000),
      }),
    }, ceremony({
      type: "step_up",
      identityId,
      tenantId,
      sessionId,
      purpose: "passkey_enrollment",
      operationHash: "b".repeat(64),
    }));
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication({ credentialDeviceType: "multiDevice" })),
    });

    await expect(service.verifyStepUp({
      principal: principal(),
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-remediation",
      origin,
    })).resolves.toMatchObject({ verified: true, purpose: "passkey_enrollment" });
    expect(store.completeWebAuthnStepUp).toHaveBeenCalledTimes(1);
  });

  it("does not exempt destructive identity-security changes from active method policy", async () => {
    const passkey = credential({ deviceType: "multiDevice" });
    const generate = vi.fn(async () => authenticationOptions());
    const store = storeFixture({
      getCredentialByExternalId: vi.fn().mockResolvedValue(passkey),
      listCredentials: vi.fn().mockResolvedValue([storedCredential({ deviceType: "multiDevice" })]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({
        enforcementMode: "monitor",
        allowSyncedPasskeys: false,
      })),
    }, ceremony({ type: "step_up", identityId, tenantId, sessionId, purpose: "identity_security_change", operationHash: "c".repeat(64) }));
    const service = serviceFixture(store, {
      generateAuthenticationOptions: generate,
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication({ credentialDeviceType: "multiDevice" })),
    });

    await expect(service.stepUpOptions({
      principal: principal(),
      purpose: "identity_security_change",
      operationHash: "c".repeat(64),
      origin,
    })).rejects.toMatchObject({ statusCode: 403, code: "PASSKEY_POLICY_DENIED" });
    expect(generate).not.toHaveBeenCalled();

    await expect(service.verifyStepUp({
      principal: principal(),
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-synced-denied",
      origin,
    })).rejects.toMatchObject({ statusCode: 403, code: "PASSKEY_POLICY_DENIED" });
    expect(store.completeWebAuthnStepUp).not.toHaveBeenCalled();
  });

  it("enforces the privileged passkey-count floor before issuing a grant", async () => {
    const store = storeFixture({
      listCredentials: vi.fn().mockResolvedValue([storedCredential()]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({
        enforcementMode: "enforce",
        privilegedMinimumPasskeyCount: 2,
      })),
    }, ceremony({ type: "step_up", identityId, tenantId, sessionId, purpose: "data_export", operationHash: "d".repeat(64) }));
    const service = serviceFixture(store, {
      verifyAuthenticationResponse: vi.fn().mockResolvedValue(verifiedAuthentication()),
    });
    await expect(service.verifyStepUp({
      principal: principal(),
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-passkey-floor",
      origin,
    })).rejects.toMatchObject({ statusCode: 403, code: "PASSKEY_POLICY_MINIMUM" });
    expect(store.completeWebAuthnStepUp).not.toHaveBeenCalled();
  });

  it("does not count a policy-disabled synced passkey toward the privileged floor", async () => {
    const store = storeFixture({
      listCredentials: vi.fn().mockResolvedValue([
        storedCredential(),
        storedCredential({
          id: "40000000-0000-4000-8000-000000000002",
          externalId: "Y3JlZGVudGlhbC0y",
          deviceType: "multiDevice",
          backupEligible: true,
        }),
      ]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({
        enforcementMode: "enforce",
        allowSyncedPasskeys: false,
        privilegedMinimumPasskeyCount: 2,
      })),
    }, ceremony({
      type: "step_up",
      identityId,
      tenantId,
      sessionId,
      purpose: "data_export",
      operationHash: "9".repeat(64),
    }));
    await expect(serviceFixture(store).verifyStepUp({
      principal: principal(),
      ceremonyId: ceremony().id,
      ceremonyToken: "c".repeat(43),
      response: authenticationResponse(),
      requestId: "request-eligible-passkey-floor",
      origin,
    })).rejects.toMatchObject({ statusCode: 403, code: "PASSKEY_POLICY_MINIMUM" });
    expect(store.completeWebAuthnStepUp).not.toHaveBeenCalled();
  });

  it("does not claim privileged compliance when required device or attestation posture is unknown", async () => {
    const store = storeFixture({
      listCredentials: vi.fn().mockResolvedValue([{
        ...credential(),
        displayName: "Security key",
        attachment: "cross-platform",
        discoverable: true,
        aaguid: null,
        createdAt: new Date(),
        lastUsedAt: null,
        revocationReason: null,
        version: 1,
      }]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({
        enforcementMode: "monitor",
        requireDeviceBoundForPrivileged: true,
        requireAttestationForPrivileged: true,
      })),
    });
    const service = serviceFixture(store);
    const result = await service.getEffectivePolicy(principal({ authenticatedCredentialId: null }));
    expect(result.compliance).toMatchObject({
      enforcementMode: "monitor",
      privilegedSessionReady: false,
      deviceBoundCredential: null,
      attestedCredential: null,
    });
    expect(result.compliance.findings).toEqual(expect.arrayContaining([
      "device_bound_passkey_required",
      "attested_passkey_required",
    ]));
  });

  it("requires UV and resident credentials for registration, with algorithms constrained", async () => {
    const generate = vi.fn(async () => registrationOptions());
    const store = storeFixture();
    const service = serviceFixture(store, { generateRegistrationOptions: generate });
    const result = await service.registrationOptions({ principal: principal({ assuranceLevel: "enrollment_only", enrollmentOnly: true }), requestId: "registration", origin });
    expect(result.options.challenge).toBe(challenge);
    expect(generate).toHaveBeenCalledWith(expect.objectContaining({
      rpID: "localhost",
      attestationType: "none",
      supportedAlgorithmIDs: [-7, -257],
      authenticatorSelection: expect.objectContaining({ residentKey: "required", userVerification: "required" }),
    }));
  });

  it.each([
    ["TOTP", principal({ mfaVerifiedAt: new Date(Date.now() - 6 * 60_000) })],
    ["password", principal({
      assuranceLevel: "password",
      authMethod: "password",
      aal: 1,
      mfaRequired: false,
      mfaEnabled: false,
      mfaVerifiedAt: null,
      authenticatedAt: new Date(Date.now() - 6 * 60_000),
    })],
  ] as const)("rejects stale ordinary %s sessions before first-passkey enrollment", async (_method, stalePrincipal) => {
    const generate = vi.fn(async () => registrationOptions());
    const service = serviceFixture(storeFixture(), { generateRegistrationOptions: generate });
    await expect(service.registrationOptions({
      principal: stalePrincipal,
      requestId: "stale-first-passkey",
      origin,
    })).rejects.toMatchObject({
      statusCode: 428,
      code: "PASSKEY_ENROLLMENT_REAUTHENTICATION_REQUIRED",
    });
    expect(generate).not.toHaveBeenCalled();
  });

  it.each([
    ["TOTP", principal()],
    ["password", principal({
      assuranceLevel: "password",
      authMethod: "password",
      aal: 1,
      mfaRequired: false,
      mfaEnabled: false,
      mfaVerifiedAt: null,
      authenticatedAt: new Date(),
    })],
  ] as const)("allows a freshly authenticated ordinary %s session to enroll its first passkey", async (_method, freshPrincipal) => {
    await expect(serviceFixture(storeFixture()).registrationOptions({
      principal: freshPrincipal,
      requestId: "fresh-first-passkey",
      origin,
    })).resolves.toMatchObject({ ceremonyId: ceremony().id });
  });

  it("bounds the first-passkey ceremony by the remaining fresh-authentication window", async () => {
    const generate = vi.fn(async (_options: GenerateRegistrationOptionsOpts) => registrationOptions());
    const proofAt = new Date(Date.now() - 4 * 60_000);
    await serviceFixture(storeFixture(), { generateRegistrationOptions: generate }).registrationOptions({
      principal: principal({ mfaVerifiedAt: proofAt }),
      requestId: "bounded-first-passkey",
      origin,
    });
    const timeout = generate.mock.calls[0]![0].timeout;
    expect(timeout).toBeGreaterThan(0);
    expect(timeout).toBeLessThanOrEqual(60_000);
  });

  it.each([
    ["monitor", "none"],
    ["enforce", "direct"],
  ] as const)("uses privacy-conscious attestation collection in %s mode", async (enforcementMode, attestationType) => {
    const generate = vi.fn(async () => registrationOptions());
    const store = storeFixture({
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({
        enforcementMode,
        requireAttestationForPrivileged: true,
      })),
    });
    const service = serviceFixture(store, { generateRegistrationOptions: generate });
    await service.registrationOptions({
      principal: principal({ assuranceLevel: "enrollment_only", enrollmentOnly: true }),
      requestId: `registration-${enforcementMode}`,
      origin,
    });
    expect(generate).toHaveBeenCalledWith(expect.objectContaining({ attestationType }));
  });

  it("requires a one-use operation-bound passkey grant before adding another passkey", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const store = storeFixture({
      consumeStepUpGrant,
      listCredentials: vi.fn().mockResolvedValue([{
        ...credential(),
        displayName: "Existing passkey",
        attachment: "platform",
        discoverable: true,
        aaguid: null,
        createdAt: new Date(),
        lastUsedAt: null,
        revocationReason: null,
        version: 1,
      }]),
    });
    const service = serviceFixture(store);
    const input = { principal: principal(), requestId: "second-passkey", origin } as const;
    await expect(service.registrationOptions(input)).rejects.toMatchObject({
      statusCode: 428,
      code: "WEBAUTHN_STEP_UP_REQUIRED",
      details: {
        purpose: "passkey_enrollment",
        operationHash: hashStepUpOperation(
          "passkey_enrollment",
          "POST",
          "/v1/auth/passkeys/registration/options",
          {},
        ),
      },
    });
    expect(consumeStepUpGrant).not.toHaveBeenCalled();

    await expect(service.registrationOptions({ ...input, grantToken: "g".repeat(43) })).resolves.toMatchObject({
      ceremonyId: ceremony().id,
    });
    expect(consumeStepUpGrant).toHaveBeenCalledWith(expect.objectContaining({
      identityId,
      sessionId,
      purpose: "passkey_enrollment",
      operationHash: hashStepUpOperation(
        "passkey_enrollment",
        "POST",
        "/v1/auth/passkeys/registration/options",
        {},
      ),
    }));
  });

  it("requires and binds an atomic replacement target when the passkey limit is reached", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const store = storeFixture({
      consumeStepUpGrant,
      listCredentials: vi.fn().mockResolvedValue([storedCredential()]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({ maximumPasskeys: 1 })),
    });
    const service = serviceFixture(store);
    const common = { principal: principal(), requestId: "replace-at-limit", origin } as const;

    await expect(service.registrationOptions(common)).rejects.toMatchObject({
      statusCode: 409,
      code: "PASSKEY_LIMIT_REACHED",
    });
    await expect(service.registrationOptions({
      ...common,
      replacementCredentialId: credentialInternalId,
      grantToken: "g".repeat(43),
    })).resolves.toMatchObject({ ceremonyId: ceremony().id });
    expect(consumeStepUpGrant).toHaveBeenCalledWith(expect.objectContaining({
      purpose: "passkey_enrollment",
      operationHash: hashStepUpOperation(
        "passkey_enrollment",
        "POST",
        "/v1/auth/passkeys/registration/options",
        { replacementCredentialId: credentialInternalId },
      ),
    }));
    expect(store.createCeremony).toHaveBeenCalledWith(expect.objectContaining({
      replacementCredentialId: credentialInternalId,
    }));
  });

  it("allows a recovery-limited session to atomically replace its own active passkey", async () => {
    const store = storeFixture({
      listCredentials: vi.fn().mockResolvedValue([storedCredential()]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({ maximumPasskeys: 1 })),
    });
    await expect(serviceFixture(store).registrationOptions({
      principal: principal({ assuranceLevel: "recovery_limited", enrollmentOnly: true, recoveryLimited: true }),
      replacementCredentialId: credentialInternalId,
      requestId: "recovery-replacement",
      origin,
    })).resolves.toMatchObject({ ceremonyId: ceremony().id });
    expect(store.consumeStepUpGrant).not.toHaveBeenCalled();
    expect(store.createCeremony).toHaveBeenCalledWith(expect.objectContaining({
      replacementCredentialId: credentialInternalId,
    }));
  });

  it("never permits replacing a credential outside the current identity's active inventory", async () => {
    const store = storeFixture({ listCredentials: vi.fn().mockResolvedValue([storedCredential()]) });
    await expect(serviceFixture(store).registrationOptions({
      principal: principal(),
      replacementCredentialId: "40000000-0000-4000-8000-000000000099",
      requestId: "invalid-replacement",
      origin,
    })).rejects.toMatchObject({ statusCode: 404, code: "PASSKEY_REPLACEMENT_INVALID" });
    expect(store.createCeremony).not.toHaveBeenCalled();
  });

  it.each([
    ["AAL3", { privilegedMinimumAal: 3 }],
    ["attestation", { requireAttestationForPrivileged: true }],
    ["action AAL3", { actionRequirements: { "data.export": { minAal: 3 } } }],
  ] as const)("rejects unsafe policy activation for %s", async (_label, override) => {
    const store = storeFixture({ listCredentials: vi.fn().mockResolvedValue([storedCredential()]) });
    const service = serviceFixture(store);
    await expect(service.updateIdentityPolicy({
      principal: principal(),
      expectedVersion: 0,
      policy: policyValues({ enforcementMode: "enforce", ...override }),
      requestId: "unsafe-policy",
    })).rejects.toMatchObject({ statusCode: 409, code: "IDENTITY_POLICY_ACTIVATION_UNSAFE" });
    expect(store.upsertTenantIdentityPolicy).not.toHaveBeenCalled();
  });

  it("delegates method-control readiness to the transactional tenant-wide store check", async () => {
    const updatedPolicy = policy({
      tenantVersion: 1,
      enforcementMode: "monitor",
      allowPassword: false,
      allowTotpFallback: false,
      allowRecoveryCodes: false,
      allowSyncedPasskeys: false,
    });
    const upsertTenantIdentityPolicy = vi.fn().mockResolvedValue(updatedPolicy);
    const store = storeFixture({ upsertTenantIdentityPolicy });

    await expect(serviceFixture(store).updateIdentityPolicy({
      principal: principal(),
      expectedVersion: 0,
      policy: policyValues(updatedPolicy),
      requestId: "method-policy-ready",
    })).resolves.toEqual(updatedPolicy);

    expect(upsertTenantIdentityPolicy).toHaveBeenCalledWith(expect.objectContaining({
      currentSessionId: sessionId,
      policy: expect.objectContaining({
        allowPassword: false,
        allowTotpFallback: false,
        allowRecoveryCodes: false,
        allowSyncedPasskeys: false,
      }),
    }));
  });

  it("maps a transactional tenant readiness failure to a deterministic activation error", async () => {
    const store = storeFixture({
      upsertTenantIdentityPolicy: vi.fn().mockRejectedValue(
        new EnterpriseAuthStoreError("POLICY_CONFLICT", "identity readiness detail"),
      ),
    });

    await expect(serviceFixture(store).updateIdentityPolicy({
      principal: principal(),
      expectedVersion: 0,
      policy: policyValues({ enforcementMode: "monitor", allowPassword: false }),
      requestId: "method-policy-unsafe",
    })).rejects.toMatchObject({
      statusCode: 409,
      code: "IDENTITY_POLICY_ACTIVATION_UNSAFE",
      message: "The requested identity policy cannot be applied without locking out an active identity",
    });
  });

  it("requires eligible device-bound credentials before activating a strict passkey posture", async () => {
    const store = storeFixture({
      listCredentials: vi.fn().mockResolvedValue([storedCredential({ deviceType: "multiDevice" })]),
    });
    await expect(serviceFixture(store).updateIdentityPolicy({
      principal: principal(),
      expectedVersion: 0,
      policy: policyValues({
        enforcementMode: "enforce",
        allowSyncedPasskeys: false,
        requireDeviceBoundForPrivileged: true,
      }),
      requestId: "device-policy-not-ready",
    })).rejects.toMatchObject({
      statusCode: 409,
      code: "IDENTITY_POLICY_ACTIVATION_UNSAFE",
      details: { activePasskeyCount: 0, requiredPasskeyCount: 1 },
    });
    expect(store.upsertTenantIdentityPolicy).not.toHaveBeenCalled();
  });

  it("requires the updater to meet passkey-count floors before enforce activation", async () => {
    const store = storeFixture({ listCredentials: vi.fn().mockResolvedValue([storedCredential()]) });
    const service = serviceFixture(store);
    await expect(service.updateIdentityPolicy({
      principal: principal(),
      expectedVersion: 0,
      policy: policyValues({
        enforcementMode: "enforce",
        minimumPasskeyCount: 2,
        privilegedMinimumPasskeyCount: 2,
      }),
      requestId: "not-ready-policy",
    })).rejects.toMatchObject({
      statusCode: 409,
      code: "IDENTITY_POLICY_ACTIVATION_UNSAFE",
      details: { activePasskeyCount: 1, requiredPasskeyCount: 2 },
    });
    expect(store.upsertTenantIdentityPolicy).not.toHaveBeenCalled();
  });

  it("prevents enforce-mode revocation below ordinary or privileged passkey floors", async () => {
    const revokeCredential = vi.fn();
    const store = storeFixture({
      revokeCredential,
      listCredentials: vi.fn().mockResolvedValue([storedCredential()]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({
        enforcementMode: "enforce",
        minimumPasskeyCount: 1,
        privilegedMinimumPasskeyCount: 1,
      })),
    });
    await expect(serviceFixture(store).revokePasskey({
      principal: principal(),
      credentialId: credentialInternalId,
      reason: "user_revoked",
      requestId: "revoke-floor",
    })).rejects.toMatchObject({ statusCode: 409, code: "PASSKEY_POLICY_MINIMUM" });
    expect(revokeCredential).not.toHaveBeenCalled();
  });

  it("allows monitor-mode revocation when another recovery path remains", async () => {
    const revokeCredential = vi.fn().mockResolvedValue({
      revoked: true,
      sessionsRevoked: 1,
      currentSessionRevoked: false,
    });
    const store = storeFixture({
      revokeCredential,
      listCredentials: vi.fn().mockResolvedValue([storedCredential()]),
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy({ enforcementMode: "monitor" })),
    });
    await expect(serviceFixture(store).revokePasskey({
      principal: principal(),
      credentialId: credentialInternalId,
      reason: "compromised",
      requestId: "revoke-monitor",
    })).resolves.toEqual({ revoked: true, sessionsRevoked: 1, currentSessionRevoked: false });
    expect(revokeCredential).toHaveBeenCalledWith(expect.objectContaining({ currentSessionId: sessionId }));
  });

  it("maps an atomic revocation-policy race to the passkey policy error", async () => {
    const store = storeFixture({
      listCredentials: vi.fn().mockResolvedValue([
        storedCredential(),
        storedCredential({ id: "40000000-0000-4000-8000-000000000002" }),
      ]),
      revokeCredential: vi.fn().mockRejectedValue(
        new EnterpriseAuthStoreError("POLICY_CONFLICT", "concurrent policy detail"),
      ),
    });
    await expect(serviceFixture(store).revokePasskey({
      principal: principal(),
      credentialId: credentialInternalId,
      reason: "user_revoked",
      requestId: "revoke-policy-race",
    })).rejects.toMatchObject({
      statusCode: 409,
      code: "PASSKEY_POLICY_MINIMUM",
    });
  });
});

function serviceFixture(
  store: ReturnType<typeof storeFixture>,
  engineOverrides: Partial<WebAuthnEngine> = {},
  control: Record<string, unknown> = {},
): EnterpriseAuthService {
  const engine = {
    generateRegistrationOptions: vi.fn(async () => registrationOptions()),
    verifyRegistrationResponse: vi.fn(),
    generateAuthenticationOptions: vi.fn(async () => authenticationOptions()),
    verifyAuthenticationResponse: vi.fn(async () => verifiedAuthentication()),
    ...engineOverrides,
  } as unknown as WebAuthnEngine;
  const database = { enterpriseAuth: store, control } as unknown as DatabaseRuntime;
  return new EnterpriseAuthService(database, config(), {} as AuthService, engine);
}

function storeFixture(overrides: Record<string, unknown> = {}, activeCeremony = ceremony()) {
  return {
    createCeremony: vi.fn(async (input: Record<string, unknown>) => ({ ...activeCeremony, ...input, id: activeCeremony.id })),
    getActiveCeremony: vi.fn().mockResolvedValue(activeCeremony),
    failCeremony: vi.fn().mockResolvedValue(undefined),
    getEffectiveIdentityPolicy: vi.fn().mockResolvedValue(policy()),
    upsertTenantIdentityPolicy: vi.fn(),
    getCredentialByExternalId: vi.fn().mockResolvedValue(credential()),
    listCredentials: vi.fn().mockResolvedValue([]),
    completeRegistration: vi.fn(),
    completeAuthentication: vi.fn(),
    completeWebAuthnStepUp: vi.fn(),
    renameCredential: vi.fn(),
    revokeCredential: vi.fn(),
    listIdentitySessions: vi.fn(),
    revokeIdentitySession: vi.fn(),
    revokeOtherIdentitySessions: vi.fn(),
    consumeStepUpGrant: vi.fn().mockResolvedValue(false),
    enforceSessionLimit: vi.fn().mockResolvedValue(0),
    ...overrides,
  };
}

function config(): ApiConfig {
  return {
    environment: "test",
    host: "127.0.0.1",
    port: 0,
    corsOrigins: new Set([origin]),
    secureCookies: false,
    sessionTtlSeconds: 3_600,
    webauthn: { rpName: "Nombramientos", rpId: "localhost", expectedOrigins: [origin, secondaryOrigin], challengeTtlSeconds: 300, stepUpTtlSeconds: 120 },
    authEncryptionKey: Buffer.alloc(32),
    controlDatabaseUrl: "postgresql://unused:unused@127.0.0.1:55432/unused",
    secretMasterKey: Buffer.alloc(32),
    secretFile: "unused",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
}

function ceremony(overrides: Record<string, unknown> = {}) {
  return {
    id: "50000000-0000-4000-8000-000000000001",
    type: "authentication",
    challengeHash: createHash("sha256").update(challenge).digest("hex"),
    identityId: null,
    tenantId: null,
    sessionId: null,
    purpose: null,
    operationHash: null,
    rpId: "localhost",
    expectedOrigin: origin,
    requireUserVerification: true,
    policyVersion: 1,
    replacementCredentialId: null,
    userAgentHash: null,
    ipPrefixHash: null,
    attemptCount: 0,
    expiresAt: new Date(Date.now() + 60_000),
    ...overrides,
  };
}

function credential(overrides: Record<string, unknown> = {}) {
  return {
    id: credentialInternalId,
    externalId: credentialExternalId,
    identityId,
    tenantId,
    publicKey: Buffer.alloc(32, 7),
    userHandle: Buffer.from(identityId).toString("base64url"),
    counter: 4,
    transports: ["internal"],
    deviceType: "singleDevice",
    backupEligible: false,
    backedUp: false,
    userVerified: true,
    trustLevel: "unverified",
    rpId: "localhost",
    revokedAt: null,
    ...overrides,
  };
}

function storedCredential(overrides: Record<string, unknown> = {}) {
  return {
    ...credential(),
    displayName: "Security key",
    attachment: "platform",
    discoverable: true,
    aaguid: null,
    createdAt: new Date(),
    lastUsedAt: null,
    revocationReason: null,
    version: 1,
    ...overrides,
  };
}

function policy(overrides: Record<string, unknown> = {}) {
  return {
    baselineVersion: 1,
    tenantVersion: null,
    enforcementMode: "monitor",
    minimumAal: 1,
    privilegedMinimumAal: 2,
    requireUserVerification: true,
    requireDeviceBoundForPrivileged: false,
    requireAttestationForPrivileged: false,
    requirePhishingResistantForPrivileged: true,
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
    stepUpTtlSeconds: 300,
    actionRequirements: {},
    ...overrides,
  };
}

function policyValues(
  overrides: Record<string, unknown> = {},
): Parameters<EnterpriseAuthService["updateIdentityPolicy"]>[0]["policy"] {
  const { baselineVersion: _baselineVersion, tenantVersion: _tenantVersion, ...values } = policy(overrides);
  return values as Parameters<EnterpriseAuthService["updateIdentityPolicy"]>[0]["policy"];
}

function authenticationOptions(): PublicKeyCredentialRequestOptionsJSON {
  return { challenge, rpId: "localhost", userVerification: "required" };
}

function registrationOptions(): PublicKeyCredentialCreationOptionsJSON {
  return {
    challenge,
    rp: { id: "localhost", name: "Nombramientos" },
    user: { id: Buffer.from(identityId).toString("base64url"), name: "fixture@example.invalid", displayName: "Fixture" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  };
}

function authenticationResponse(clientData: Readonly<Record<string, unknown>> = {}): AuthenticationResponseJSON {
  return {
    id: credentialExternalId,
    rawId: credentialExternalId,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: encodedClientData("webauthn.get", clientData),
      authenticatorData: "YXV0aA",
      signature: "c2ln",
      userHandle: Buffer.from(identityId).toString("base64url"),
    },
  };
}

function registrationResponse(clientData: Readonly<Record<string, unknown>> = {}): RegistrationResponseJSON {
  return {
    id: credentialExternalId,
    rawId: credentialExternalId,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: encodedClientData("webauthn.create", clientData),
      attestationObject: "YXR0ZXN0YXRpb24",
    },
  };
}

function encodedClientData(type: "webauthn.create" | "webauthn.get", overrides: Readonly<Record<string, unknown>>): string {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false, ...overrides }), "utf8").toString("base64url");
}

function verifiedAuthentication(overrides: Partial<VerifiedAuthenticationResponse["authenticationInfo"]> = {}): VerifiedAuthenticationResponse {
  return {
    verified: true,
    authenticationInfo: {
      credentialID: credentialExternalId,
      newCounter: 5,
      userVerified: true,
      credentialDeviceType: "singleDevice",
      credentialBackedUp: false,
      origin,
      rpID: "localhost",
      ...overrides,
    },
  };
}

function principal(overrides: Partial<RequestPrincipal> = {}): RequestPrincipal {
  return {
    sessionId,
    identityId,
    activeTenantId: tenantId,
    email: "fixture@example.invalid",
    displayName: "Fixture",
    tenantSlug: "fixture",
    tenantName: "Fixture tenant",
    tenantKind: "real",
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa",
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    authMethod: "totp",
    aal: 2,
    phishingResistant: false,
    enrollmentOnly: false,
    permissions: new Set(),
    ...overrides,
  };
}
