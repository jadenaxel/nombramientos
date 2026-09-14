import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { evaluateWebAuthnOrigin } from "./webauthn.ts";
import { evaluatePreAuthOrigin } from "./auth-origin.ts";
import { scheduleMfaEnrollmentExpiry } from "./mfa-enrollment-lifetime.ts";
import { isTotpEnrollmentRequired } from "./mfa-enrollment-requirement.ts";
import { validatedTotpEnrollmentUri } from "./totp-enrollment.ts";

const webRoot = path.resolve(import.meta.dirname, "..");

test("WebAuthn accepts a secure domain or localhost and gives IP users the exact safe local URL", () => {
  const route = {
    port: "3000",
    pathname: "/es/auth/sign-in",
    search: "?source=test",
    hash: "#access",
  } as const;

  assert.deepEqual(evaluateWebAuthnOrigin({ ...route, hostname: "localhost", protocol: "http:", secureContext: true }), { eligible: true });
  assert.deepEqual(evaluateWebAuthnOrigin({ ...route, hostname: "login.example.com", protocol: "https:", secureContext: true }), { eligible: true });
  assert.deepEqual(evaluateWebAuthnOrigin({ ...route, hostname: "login.example.com", protocol: "http:", secureContext: false }), { eligible: false });
  assert.deepEqual(evaluateWebAuthnOrigin({ ...route, hostname: "127.0.0.1", protocol: "http:", secureContext: true }), {
    eligible: false,
    canonicalUrl: "http://localhost:3000/es/auth/sign-in?source=test#access",
  });
});

test("human pre-authentication is gated on the canonical operational origin without losing route state", () => {
  const route = {
    port: "3000",
    protocol: "http:",
    pathname: "/es/auth/invitation",
    search: "?source=manual",
    hash: "#activate",
  } as const;
  assert.deepEqual(evaluatePreAuthOrigin({ ...route, hostname: "127.0.0.1" }), {
    eligible: false,
    canonicalUrl: "http://localhost:3000/es/auth/invitation?source=manual#activate",
  });
  assert.deepEqual(evaluatePreAuthOrigin({ ...route, hostname: "[::1]", protocol: "https:" }), {
    eligible: false,
    canonicalUrl: "https://localhost:3000/es/auth/invitation?source=manual#activate",
  });
  assert.deepEqual(evaluatePreAuthOrigin({ ...route, hostname: "127.0.0.1", automated: true }), { eligible: true });
  assert.deepEqual(evaluatePreAuthOrigin({ ...route, hostname: "127.0.0.1", port: "3301" }), { eligible: true });
  assert.deepEqual(evaluatePreAuthOrigin({ ...route, hostname: "localhost" }), { eligible: true });
  assert.deepEqual(evaluatePreAuthOrigin({ ...route, hostname: "login.example.test", protocol: "https:", port: "" }), { eligible: true });
});

test("passkey and TOTP wiring preserves usernameless privacy and keeps enrollment secrets memory-only", () => {
  const login = readFileSync(path.join(webRoot, "components/nombramientos/login-form.tsx"), "utf8");
  const security = readFileSync(path.join(webRoot, "components/nombramientos/security-center.tsx"), "utf8");
  const enrollment = readFileSync(path.join(webRoot, "components/nombramientos/mfa-enrollment.tsx"), "utf8");
  const invitation = readFileSync(path.join(webRoot, "components/nombramientos/invitation-accept-form.tsx"), "utf8");
  const shell = readFileSync(path.join(webRoot, "components/nombramientos/app-shell.tsx"), "utf8");
  const apiSource = readFileSync(path.join(webRoot, "lib/api.ts"), "utf8");
  const headers = readFileSync(path.join(webRoot, "next.config.ts"), "utf8");

  assert.ok((login.match(/passkeyAuthenticationOptions\(undefined,/gu) ?? []).length >= 2);
  assert.doesNotMatch(login, /passkeyAuthenticationOptions\([^\n]*normalizedEmail/gu);
  assert.match(login, /autoComplete="username webauthn"/u);
  assert.match(login, /isPasskeyCancellation/u);
  assert.match(login, /currentPreAuthOriginGateUrl/u);
  assert.match(login, /disabled=\{!preAuthReady \|\| busy \|\| passkeyBusy\}/u);
  assert.match(invitation, /apiRequest<\{ prepared: true \}>\("\/v1\/invitations\/recovery-context"/u);
  assert.match(invitation, /apiRequest<AuthenticatedSession>\("\/v1\/session"\)/u);
  assert.match(invitation, /navigator\.locks\.request\("nombramientos\.invitation-recovery-context\.v1"/u);
  assert.match(invitation, /acceptedResponse\.user\.id/u);
  assert.match(invitation, /acceptedResponse\.tenantId/u);
  assert.match(invitation, /INVITATION_BROWSER_SESSION_CONFLICT/u);
  assert.match(invitation, /isRetryableAcceptanceFailure/u);
  assert.doesNotMatch(invitation, /if \(isRestrictedEnrollmentSession\(recovered\)\) \{\s*installInvitationSession/u);
  assert.match(invitation, /INVITATION_PASSWORD_REQUIRED/u);
  assert.match(invitation, /isRestrictedInvitationSession\(session\)/u);
  assert.match(invitation, /queryClient\.setQueryData\(\["session"\], session\)[\s\S]*router\.replace\(`\/\$\{locale\}\/app\/settings`\)/u);
  assert.doesNotMatch(invitation, /localStorage|sessionStorage|recoveryProof/u);
  assert.match(security, /registerPasskey\(ceremony\.options\)/u);
  assert.match(security, /passkeyRegistrationOptions\(replacementCredentialId \|\| undefined\)/u);
  assert.match(apiSource, /passkeyRegistrationOptions: \(replacementCredentialId\?: string\)[\s\S]*JSON\.stringify\(replacementCredentialId \? \{ replacementCredentialId \} : \{\}\)/u);
  assert.match(security, /previous passkey stays active|llave anterior seguirá activa|ancienne clé et ses sessions restent actives/u);
  assert.match(security, /cancelPasskeyCeremony\(\)/u);
  assert.match(security, /\["allowPassword", text\.passwordAllowed\]/u);
  assert.match(security, /\["allowTotpFallback", text\.totpAllowed\]/u);
  assert.match(security, /\["allowRecoveryCodes", text\.recoveryAllowed\]/u);
  assert.match(security, /\["allowSyncedPasskeys", text\.syncedAllowed\]/u);
  assert.match(security, /setNumber\("maximumActiveSessions"/u);
  assert.match(security, /setNumber\("idleTimeoutMinutes"/u);
  assert.match(security, /setNumber\("absoluteSessionMinutes"/u);
  assert.match(security, /setNumber\("stepUpTtlSeconds"/u);
  assert.match(security, /Object\.entries\(draft\.actionRequirements\)/u);
  assert.match(security, /policySafetyNotice/u);
  assert.match(apiSource, /revoked: true; signedOut: boolean; sessionsRevoked: number/u);
  assert.match(apiSource, /risk\?: \{[\s\S]*elevated: boolean;[\s\S]*ipContextChanged: boolean;/u);
  assert.match(security, /session\.security\.risk\?\.elevated/u);
  assert.match(security, /item\.risk\?\.elevated/u);
  assert.match(
    security,
    /function clearLocalAuthentication\(\)[\s\S]*vault\.lock\(\)[\s\S]*setCsrfToken\(undefined\)[\s\S]*queryClient\.clear\(\)[\s\S]*router\.replace/u,
  );
  assert.match(security, /result\.signedOut[\s\S]*clearLocalAuthentication\(\)/u);
  assert.match(security, /PASSKEY_ENROLLMENT_REAUTHENTICATION_REQUIRED/u);
  assert.match(security, /riskContextLabel\(session\.security\.risk, text\)/u);
  assert.match(security, /riskContextLabel\(item\.risk, text\)/u);
  assert.match(apiSource, /confirmMfaEnrollment:[\s\S]*apiRequest<MfaEnrollmentCompleted>/u);
  assert.match(shell, /assurance === "recovery_limited"/u);
  assert.match(enrollment, /Pick<MfaEnrollmentStarted, "enrollmentId" \| "expiresAt">/u);
  assert.match(enrollment, /import\("qrcode"\)/u);
  assert.match(enrollment, /href=\{safeOtpAuthUri\}/u);
  assert.match(enrollment, /validatedTotpEnrollmentUri\(started\)/u);
  assert.doesNotMatch(enrollment, /sessionStorage\.setItem\([^\n]*(?:secret|otpauthUri|recoveryCodes)/u);
  assert.match(enrollment, /scheduleMfaEnrollmentExpiry/u);
  assert.match(enrollment, /visibilityState !== "hidden"[\s\S]*setStarted\(undefined\)[\s\S]*setQr\(undefined\)[\s\S]*setCode\(""\)/u);
  assert.match(enrollment, /addEventListener\("pagehide"[\s\S]*removeEventListener\("pagehide"/u);
  assert.match(enrollment, /if \(!validatedTotpEnrollmentUri\(enrollment\)\)[\s\S]*savePendingEnrollment\(undefined\)[\s\S]*cancelMfaEnrollment\(enrollment\.enrollmentId\)/u);
  assert.match(enrollment, /async function cancel\(\)[\s\S]*finally \{[\s\S]*setStarted\(undefined\); setQr\(undefined\); setCode\(""\); setCopied\(undefined\);[\s\S]*savePendingEnrollment\(undefined\)/u);
  assert.match(headers, /publickey-credentials-create=\(self\)/u);
  assert.match(headers, /publickey-credentials-get=\(self\)/u);
});

test("TOTP enrollment URI validation rejects alternate authorities, parameters, and contract drift", () => {
  const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const valid = {
    enrollmentId: "10000000-0000-4000-8000-000000000102",
    secret,
    otpauthUri: `otpauth://totp/demo%3Auser%40example.invalid?secret=${secret}&issuer=Nombramientos&algorithm=SHA1&digits=6&period=30`,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    algorithm: "SHA1" as const,
    digits: 6 as const,
    period: 30 as const,
  };
  assert.equal(validatedTotpEnrollmentUri(valid), valid.otpauthUri);
  assert.equal(validatedTotpEnrollmentUri({ ...valid, otpauthUri: valid.otpauthUri.replace("otpauth://totp/", "otpauth://user@totp/") }), undefined);
  assert.equal(validatedTotpEnrollmentUri({ ...valid, otpauthUri: `${valid.otpauthUri}&secret=${secret}` }), undefined);
  assert.equal(validatedTotpEnrollmentUri({ ...valid, otpauthUri: valid.otpauthUri.replace("algorithm=SHA1", "algorithm=SHA256") }), undefined);
  assert.equal(validatedTotpEnrollmentUri({ ...valid, otpauthUri: valid.otpauthUri.replace("issuer=Nombramientos", "issuer=Nombramientos&next=https%3A%2F%2Fevil.invalid") }), undefined);
  assert.equal(validatedTotpEnrollmentUri({ ...valid, otpauthUri: valid.otpauthUri.replace("otpauth:", "https:") }), undefined);
});

test("TOTP enrollment expiry purges secrets exactly at the deadline with a fake clock", (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"], now: 1_000 });
  let expired = false;
  const cancel = scheduleMfaEnrollmentExpiry(new Date(2_000).toISOString(), () => { expired = true; }, 1_000);
  context.mock.timers.tick(999);
  assert.equal(expired, false);
  context.mock.timers.tick(1);
  assert.equal(expired, true);
  cancel();

  expired = false;
  scheduleMfaEnrollmentExpiry(new Date(999).toISOString(), () => { expired = true; }, 1_000);
  assert.equal(expired, true);
});

test("a passkey satisfies strong authentication without falsely making fallback TOTP mandatory", () => {
  assert.equal(isTotpEnrollmentRequired(false, {
    mfaRequired: true,
    mfaEnabled: false,
    passkeyEnabled: true,
    strongAuthEnabled: true,
  }), false);
  assert.equal(isTotpEnrollmentRequired(false, {
    mfaRequired: true,
    mfaEnabled: false,
    passkeyEnabled: false,
    strongAuthEnabled: false,
  }), true);
  assert.equal(isTotpEnrollmentRequired(true, {
    mfaRequired: true,
    mfaEnabled: false,
    passkeyEnabled: true,
    strongAuthEnabled: true,
  }), false);
});

test("TOTP rotation and recovery-code regeneration perform one operation-bound step-up and retry the identical confirmation", async () => {
  const publicKeyCredentialDescriptor = Object.getOwnPropertyDescriptor(globalThis, "PublicKeyCredential");
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const originalFetch = globalThis.fetch;
  const calls: Array<{ url: string; method: string; body: string; headers: Headers }> = [];
  let responseIndex = 0;
  const operationHash = "a".repeat(64);
  const enrollmentId = "10000000-0000-4000-8000-000000000099";
  const mutationBody = JSON.stringify({ enrollmentId, code: "123456" });

  class TestPublicKeyCredential {
    static isConditionalMediationAvailable = async () => true;
    static isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
  }
  const assertionBytes = Uint8Array.of(1, 2, 3).buffer;
  const testNavigator = {
    credentials: {
      get: async () => ({
        id: "credential-id",
        rawId: assertionBytes,
        response: {
          authenticatorData: assertionBytes,
          clientDataJSON: assertionBytes,
          signature: assertionBytes,
          userHandle: null,
        },
        type: "public-key",
        authenticatorAttachment: "platform",
        getClientExtensionResults: () => ({}),
      }),
    },
  };
  const responses = [
    () => jsonResponse({ error: { code: "WEBAUTHN_STEP_UP_REQUIRED", message: "step up", details: { purpose: "identity_security_change", operationHash } } }, 428),
    () => jsonResponse({ data: { ceremonyId: "10000000-0000-4000-8000-000000000100", options: { challenge: "AQ", rpId: "localhost", timeout: 60_000, userVerification: "required" }, expiresAt: new Date(Date.now() + 60_000).toISOString() } }),
    () => jsonResponse({ data: { verified: true, grantToken: "g".repeat(43), expiresAt: new Date(Date.now() + 60_000).toISOString(), purpose: "identity_security_change", operationHash } }),
    () => jsonResponse({ error: { code: "WEBAUTHN_STEP_UP_REQUIRED", message: "used", details: { purpose: "identity_security_change", operationHash } } }, 428),
  ];

  try {
    Object.defineProperty(globalThis, "PublicKeyCredential", { configurable: true, value: TestPublicKeyCredential });
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: testNavigator });
    globalThis.fetch = (async (input, init) => {
      calls.push({
        url: String(input),
        method: init?.method ?? "GET",
        body: typeof init?.body === "string" ? init.body : "",
        headers: new Headers(init?.headers),
      });
      const next = responses[responseIndex++];
      assert.ok(next, "the client attempted more than one step-up ceremony");
      return next();
    }) as typeof fetch;

    const { api, ApiError } = await import("./api.ts");
    await assert.rejects(
      api.confirmMfaEnrollment(enrollmentId, "123456"),
      (error: unknown) => error instanceof ApiError && error.status === 428,
    );

    assert.equal(calls.length, 4);
    assert.equal(calls[0]?.url, "http://localhost:4000/v1/auth/mfa/enrollment/confirm");
    assert.equal(calls[0]?.body, mutationBody);
    assert.equal(calls[1]?.url, "http://localhost:4000/v1/auth/passkeys/step-up/options");
    assert.deepEqual(JSON.parse(calls[1]?.body ?? "{}"), { purpose: "identity_security_change", operationHash });
    assert.equal(calls[2]?.url, "http://localhost:4000/v1/auth/passkeys/step-up/verify");
    assert.equal(calls[3]?.url, calls[0]?.url);
    assert.equal(calls[3]?.body, calls[0]?.body);
    assert.equal(calls[3]?.headers.get("x-step-up-grant"), "g".repeat(43));
    assert.equal(calls[3]?.headers.get("idempotency-key"), calls[0]?.headers.get("idempotency-key"));
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobal("PublicKeyCredential", publicKeyCredentialDescriptor);
    restoreGlobal("navigator", navigatorDescriptor);
  }
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-request-id": "10000000-0000-4000-8000-000000000101" },
  });
}

function restoreGlobal(name: "PublicKeyCredential" | "navigator", descriptor: PropertyDescriptor | undefined): void {
  if (descriptor) Object.defineProperty(globalThis, name, descriptor);
  else Reflect.deleteProperty(globalThis, name);
}
