"use client";

import {
  WebAuthnAbortService,
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  platformAuthenticatorIsAvailable,
  startAuthentication,
  startRegistration,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/browser";

export type PasskeyAuthenticationOptions = PublicKeyCredentialRequestOptionsJSON;
export type PasskeyRegistrationOptions = PublicKeyCredentialCreationOptionsJSON;
export type PasskeyAuthenticationResponse = AuthenticationResponseJSON;
export type PasskeyRegistrationResponse = RegistrationResponseJSON;

export type PasskeyCapability = {
  supported: boolean;
  conditional: boolean;
  platform: boolean;
  reason?: "unsupported" | "invalid_origin";
  canonicalUrl?: string;
};

export type WebAuthnLocationContext = Readonly<{
  hostname: string;
  port: string;
  protocol: string;
  pathname: string;
  search: string;
  hash: string;
  secureContext: boolean;
}>;

function isRpIdHostname(hostname: string): boolean {
  return hostname === "localhost"
    || /^((xn--[a-z0-9-]+|[a-z0-9]+(?:-[a-z0-9]+)*)\.)+([a-z]{2,}|xn--[a-z0-9-]+)$/iu.test(hostname);
}

export function evaluateWebAuthnOrigin(
  { hostname, port, protocol, pathname, search, hash, secureContext }: WebAuthnLocationContext,
): { eligible: boolean; canonicalUrl?: string } {
  const secureEnough = secureContext || hostname === "localhost";
  if (isRpIdHostname(hostname) && secureEnough) return { eligible: true };
  if (hostname === "127.0.0.1" || hostname === "[::1]") {
    const canonicalProtocol = protocol === "https:" ? "https:" : "http:";
    return { eligible: false, canonicalUrl: `${canonicalProtocol}//localhost${port ? `:${port}` : ""}${pathname}${search}${hash}` };
  }
  return { eligible: false };
}

export function webAuthnOriginStatus(): { eligible: boolean; canonicalUrl?: string } {
  if (typeof window === "undefined") return { eligible: false };
  const { hostname, port, protocol, pathname, search, hash } = window.location;
  return evaluateWebAuthnOrigin({
    hostname,
    port,
    protocol,
    pathname,
    search,
    hash,
    secureContext: window.isSecureContext,
  });
}

export async function detectPasskeyCapability(): Promise<PasskeyCapability> {
  const origin = webAuthnOriginStatus();
  if (!origin.eligible) {
    return { supported: false, conditional: false, platform: false, reason: "invalid_origin", canonicalUrl: origin.canonicalUrl };
  }
  if (!browserSupportsWebAuthn()) {
    return { supported: false, conditional: false, platform: false, reason: "unsupported" };
  }

  const [conditional, platform] = await Promise.all([
    browserSupportsWebAuthnAutofill().catch(() => false),
    platformAuthenticatorIsAvailable().catch(() => false),
  ]);
  return { supported: true, conditional, platform };
}

export function cancelPasskeyCeremony(): void {
  WebAuthnAbortService.cancelCeremony();
}

export function authenticateWithPasskey(
  optionsJSON: PasskeyAuthenticationOptions,
  useBrowserAutofill = false,
): Promise<PasskeyAuthenticationResponse> {
  return startAuthentication({ optionsJSON, useBrowserAutofill });
}

export function registerPasskey(
  optionsJSON: PasskeyRegistrationOptions,
): Promise<PasskeyRegistrationResponse> {
  return startRegistration({ optionsJSON });
}

/**
 * Browser cancellation is an expected outcome and must not be presented as a
 * failed sign-in. Security or server failures still surface to the user.
 */
export function isPasskeyCancellation(error: unknown): boolean {
  if (error instanceof DOMException) {
    return error.name === "AbortError" || error.name === "NotAllowedError";
  }
  if (!(error instanceof Error)) return false;
  return error.name === "AbortError"
    || error.name === "NotAllowedError"
    || /ceremony was sent an abort signal|request has been cancelled|operation either timed out or was not allowed/iu.test(error.message);
}

export function isPasskeyUnsupported(error: unknown): boolean {
  return error instanceof Error
    && /webauthn is not supported|browser does not support webauthn|publickeycredential/iu.test(error.message);
}
