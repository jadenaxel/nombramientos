import { expect, test, type BrowserContext, type Page } from "@playwright/test";

const fixture = readFixture();

type JsonRecord = Record<string, unknown>;
type ApiResponse = { readonly status: number; readonly body: unknown };
type StoredCookie = Awaited<ReturnType<BrowserContext["cookies"]>>[number];

test("real discoverable passkey registration, authentication, step-up, and revocation", async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  }) as { readonly authenticatorId: string };

  try {
    await page.goto(fixture.harnessBaseUrl);
    await expect(page.locator("body")).toHaveAttribute("data-marker", fixture.marker);
    await seedInitialSession(context);

    const registrationOptionsResponse = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/registration/options",
      {},
      { csrfToken: fixture.passkey.csrfToken },
    );
    expect(registrationOptionsResponse.status).toBe(201);
    const registrationOptionsData = responseData(registrationOptionsResponse);
    const registrationCeremonyId = uuidField(registrationOptionsData, "ceremonyId");
    const registrationOptions = recordField(registrationOptionsData, "options");
    expect(recordField(registrationOptions, "rp")["id"]).toBe("localhost");
    const registrationCeremonyCookie = await requiredCookie(context, webAuthnCookieName(registrationCeremonyId));

    const registrationResponse = await createPasskey(page, registrationOptions);
    const registrationVerificationResponse = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/registration/verify",
      {
        ceremonyId: registrationCeremonyId,
        response: registrationResponse,
        name: "Llave de seguridad local E2E",
      },
      { csrfToken: fixture.passkey.csrfToken },
    );
    expect(registrationVerificationResponse.status).toBe(201);
    const registrationVerification = responseData(registrationVerificationResponse);
    expect(registrationVerification["verified"]).toBe(true);
    const registeredCredential = recordField(registrationVerification, "credential");
    const credentialId = uuidField(registeredCredential, "id");
    expect(registeredCredential).toMatchObject({
      name: "Llave de seguridad local E2E",
      deviceType: "singleDevice",
      backedUp: false,
      revokedAt: null,
    });
    assertAal2PasskeySession(recordField(registrationVerification, "session"));

    // Registration atomically rotates the source TOTP session. Prove the old
    // bearer cannot be reused, then restore the newly issued browser session.
    const rotatedSessionCookie = await requiredCookie(context, "nom_session");
    const rotatedCsrfCookie = await requiredCookie(context, "nom_csrf");
    await seedInitialSession(context);
    expect((await apiRequest(page, "GET", "/v1/session")).status).toBe(401);
    await restoreCookies(context, [rotatedSessionCookie, rotatedCsrfCookie]);

    // Restore the consumed, HttpOnly ceremony cookie and replay the exact
    // signed response. The server must reject it without revealing details.
    await restoreCookies(context, [registrationCeremonyCookie]);
    const registrationReplay = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/registration/verify",
      {
        ceremonyId: registrationCeremonyId,
        response: registrationResponse,
        name: "Llave de seguridad local E2E",
      },
      { csrfToken: rotatedCsrfCookie.value },
    );
    expect(registrationReplay.status).toBe(401);
    expect(errorCode(registrationReplay)).toBe("WEBAUTHN_CEREMONY_INVALID");

    const passkeyListResponse = await apiRequest(page, "GET", "/v1/auth/passkeys");
    expect(passkeyListResponse.status).toBe(200);
    const passkeyList = responseItems(passkeyListResponse);
    expect(passkeyList).toHaveLength(1);
    expect(recordValue(passkeyList[0])["id"]).toBe(credentialId);

    const logoutResponse = await apiRequest(page, "POST", "/v1/auth/logout", {}, {
      csrfToken: rotatedCsrfCookie.value,
    });
    expect(logoutResponse.status).toBe(200);
    expect((await apiRequest(page, "GET", "/v1/session")).status).toBe(401);

    // No email or allowCredentials list is sent: the resident credential and
    // userHandle perform a genuinely discoverable (usernameless) sign-in.
    const authenticationOptionsResponse = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/authentication/options",
      { mediation: "optional" },
    );
    expect(authenticationOptionsResponse.status).toBe(201);
    const authenticationOptionsData = responseData(authenticationOptionsResponse);
    const authenticationCeremonyId = uuidField(authenticationOptionsData, "ceremonyId");
    const authenticationOptions = recordField(authenticationOptionsData, "options");
    expect(authenticationOptions["rpId"]).toBe("localhost");
    expect(authenticationOptions["allowCredentials"] ?? []).toEqual([]);
    const authenticationCeremonyCookie = await requiredCookie(context, webAuthnCookieName(authenticationCeremonyId));
    const authenticationResponse = await getPasskey(page, authenticationOptions);

    const authenticationVerificationResponse = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/authentication/verify",
      { ceremonyId: authenticationCeremonyId, response: authenticationResponse },
    );
    expect(authenticationVerificationResponse.status).toBe(200);
    const authenticatedSession = responseData(authenticationVerificationResponse);
    assertAal2PasskeySession(authenticatedSession);
    expect(recordField(authenticatedSession, "user")["email"]).toBe(fixture.passkey.email);
    const authenticatedCsrf = await requiredCookie(context, "nom_csrf");

    await restoreCookies(context, [authenticationCeremonyCookie]);
    const authenticationReplay = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/authentication/verify",
      { ceremonyId: authenticationCeremonyId, response: authenticationResponse },
    );
    expect(authenticationReplay.status).toBe(401);
    expect(errorCode(authenticationReplay)).toBe("WEBAUTHN_CEREMONY_INVALID");

    const sessionsResponse = await apiRequest(page, "GET", "/v1/auth/sessions");
    expect(sessionsResponse.status).toBe(200);
    const activeSessions = responseItems(sessionsResponse).map(recordValue);
    expect(activeSessions).toHaveLength(1);
    expect(activeSessions[0]).toMatchObject({
      current: true,
      authMethod: "passkey",
      assurance: "mfa",
      aal: 2,
      phishingResistant: true,
      revokedAt: null,
    });

    const revokeBody = { reason: "user_revoked" } as const;
    const revokePath = `/v1/auth/passkeys/${credentialId}`;
    const stepUpRequired = await apiRequest(page, "DELETE", revokePath, revokeBody, {
      csrfToken: authenticatedCsrf.value,
    });
    expect(stepUpRequired.status).toBe(428);
    expect(errorCode(stepUpRequired)).toBe("WEBAUTHN_STEP_UP_REQUIRED");
    const stepUpDetails = errorDetails(stepUpRequired);
    expect(stepUpDetails["purpose"]).toBe("identity_security_change");
    const operationHash = stringField(stepUpDetails, "operationHash");
    expect(operationHash).toMatch(/^[0-9a-f]{64}$/u);

    const stepUpOptionsResponse = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/step-up/options",
      { purpose: "identity_security_change", operationHash },
      { csrfToken: authenticatedCsrf.value },
    );
    expect(stepUpOptionsResponse.status).toBe(201);
    const stepUpOptionsData = responseData(stepUpOptionsResponse);
    const stepUpResponse = await getPasskey(page, recordField(stepUpOptionsData, "options"));
    const stepUpVerificationResponse = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/step-up/verify",
      { ceremonyId: uuidField(stepUpOptionsData, "ceremonyId"), response: stepUpResponse },
      { csrfToken: authenticatedCsrf.value },
    );
    expect(stepUpVerificationResponse.status).toBe(200);
    const stepUpVerification = responseData(stepUpVerificationResponse);
    expect(stepUpVerification["verified"]).toBe(true);
    expect(stepUpVerification["purpose"]).toBe("identity_security_change");
    expect(stepUpVerification["operationHash"]).toBe(operationHash);
    const grantToken = stringField(stepUpVerification, "grantToken");
    if (!/^[A-Za-z0-9_-]{40,}$/u.test(grantToken)) throw new Error("Step-up grant token is malformed");

    const revokeResponse = await apiRequest(page, "DELETE", revokePath, revokeBody, {
      csrfToken: authenticatedCsrf.value,
      stepUpGrant: grantToken,
    });
    expect(revokeResponse.status).toBe(200);
    expect(responseData(revokeResponse)).toMatchObject({ revoked: true, signedOut: true });
    expect((await apiRequest(page, "GET", "/v1/session")).status).toBe(401);

    // The virtual authenticator still possesses the private credential. The
    // server-side revocation must nevertheless make its next real signature
    // unusable for authentication.
    const deniedOptionsResponse = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/authentication/options",
      { mediation: "optional" },
    );
    expect(deniedOptionsResponse.status).toBe(201);
    const deniedOptionsData = responseData(deniedOptionsResponse);
    const deniedAssertion = await getPasskey(page, recordField(deniedOptionsData, "options"));
    const deniedAuthentication = await apiRequest(
      page,
      "POST",
      "/v1/auth/passkeys/authentication/verify",
      { ceremonyId: uuidField(deniedOptionsData, "ceremonyId"), response: deniedAssertion },
    );
    expect(deniedAuthentication.status).toBe(401);
    expect(errorCode(deniedAuthentication)).toBe("WEBAUTHN_VERIFICATION_FAILED");
  } finally {
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => undefined);
    await cdp.send("WebAuthn.disable").catch(() => undefined);
  }
});

async function seedInitialSession(context: BrowserContext): Promise<void> {
  await context.clearCookies();
  await context.addCookies([{
    name: "nom_session",
    value: fixture.passkey.sessionToken,
    url: fixture.apiBaseUrl,
    httpOnly: true,
    secure: false,
    sameSite: "Strict",
  }, {
    name: "nom_csrf",
    value: fixture.passkey.csrfToken,
    url: fixture.apiBaseUrl,
    httpOnly: false,
    secure: false,
    sameSite: "Strict",
  }]);
}

async function apiRequest(
  page: Page,
  method: "GET" | "POST" | "DELETE",
  pathname: string,
  body?: unknown,
  security: { readonly csrfToken?: string; readonly stepUpGrant?: string } = {},
): Promise<ApiResponse> {
  if (!pathname.startsWith("/v1/") || pathname.includes("//")) throw new Error("Invalid real-stack API path");
  return page.evaluate(async ({ apiBaseUrl, method: requestMethod, pathname: requestPath, body: requestBody, csrfToken, stepUpGrant }) => {
    const headers: Record<string, string> = {};
    if (requestBody !== undefined) headers["content-type"] = "application/json";
    if (csrfToken) headers["x-csrf-token"] = csrfToken;
    if (stepUpGrant) headers["x-step-up-grant"] = stepUpGrant;
    const response = await fetch(`${apiBaseUrl}${requestPath}`, {
      method: requestMethod,
      credentials: "include",
      cache: "no-store",
      headers,
      ...(requestBody === undefined ? {} : { body: JSON.stringify(requestBody) }),
    });
    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      responseBody = null;
    }
    return { status: response.status, body: responseBody };
  }, {
    apiBaseUrl: fixture.apiBaseUrl,
    method,
    pathname,
    body,
    csrfToken: security.csrfToken,
    stepUpGrant: security.stepUpGrant,
  });
}

async function createPasskey(page: Page, json: JsonRecord): Promise<JsonRecord> {
  return page.evaluate(async (optionsJson) => {
    const decode = (value: string): ArrayBuffer => {
      const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
      const binary = atob(base64);
      return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
    };
    const encode = (value: ArrayBuffer): string => {
      const bytes = new Uint8Array(value);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    };
    const source = optionsJson as unknown as {
      readonly challenge: string;
      readonly user: { readonly id: string } & Record<string, unknown>;
      readonly excludeCredentials?: readonly ({ readonly id: string } & Record<string, unknown>)[];
    } & Record<string, unknown>;
    const publicKey = {
      ...source,
      challenge: decode(source.challenge),
      user: { ...source.user, id: decode(source.user.id) },
      excludeCredentials: source.excludeCredentials?.map((credential) => ({ ...credential, id: decode(credential.id) })),
    } as PublicKeyCredentialCreationOptions;
    const created = await navigator.credentials.create({ publicKey });
    if (!(created instanceof PublicKeyCredential) || !(created.response instanceof AuthenticatorAttestationResponse)) {
      throw new Error("Virtual authenticator did not create a public-key credential");
    }
    const attestation = created.response;
    const publicKeyBytes = attestation.getPublicKey();
    const authenticatorData = attestation.getAuthenticatorData();
    return {
      id: created.id,
      rawId: encode(created.rawId),
      response: {
        clientDataJSON: encode(attestation.clientDataJSON),
        attestationObject: encode(attestation.attestationObject),
        transports: attestation.getTransports(),
        publicKeyAlgorithm: attestation.getPublicKeyAlgorithm(),
        ...(publicKeyBytes ? { publicKey: encode(publicKeyBytes) } : {}),
        ...(authenticatorData ? { authenticatorData: encode(authenticatorData) } : {}),
      },
      ...(created.authenticatorAttachment ? { authenticatorAttachment: created.authenticatorAttachment } : {}),
      clientExtensionResults: created.getClientExtensionResults(),
      type: created.type,
    };
  }, json) as Promise<JsonRecord>;
}

async function getPasskey(page: Page, json: JsonRecord): Promise<JsonRecord> {
  return page.evaluate(async (optionsJson) => {
    const decode = (value: string): ArrayBuffer => {
      const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
      const binary = atob(base64);
      return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
    };
    const encode = (value: ArrayBuffer): string => {
      const bytes = new Uint8Array(value);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    };
    const source = optionsJson as unknown as {
      readonly challenge: string;
      readonly allowCredentials?: readonly ({ readonly id: string } & Record<string, unknown>)[];
    } & Record<string, unknown>;
    const publicKey = {
      ...source,
      challenge: decode(source.challenge),
      allowCredentials: source.allowCredentials?.map((credential) => ({ ...credential, id: decode(credential.id) })),
    } as PublicKeyCredentialRequestOptions;
    const received = await navigator.credentials.get({ publicKey });
    if (!(received instanceof PublicKeyCredential) || !(received.response instanceof AuthenticatorAssertionResponse)) {
      throw new Error("Virtual authenticator did not return a public-key assertion");
    }
    const assertion = received.response;
    return {
      id: received.id,
      rawId: encode(received.rawId),
      response: {
        clientDataJSON: encode(assertion.clientDataJSON),
        authenticatorData: encode(assertion.authenticatorData),
        signature: encode(assertion.signature),
        ...(assertion.userHandle ? { userHandle: encode(assertion.userHandle) } : {}),
      },
      ...(received.authenticatorAttachment ? { authenticatorAttachment: received.authenticatorAttachment } : {}),
      clientExtensionResults: received.getClientExtensionResults(),
      type: received.type,
    };
  }, json) as Promise<JsonRecord>;
}

function assertAal2PasskeySession(session: JsonRecord): void {
  expect(session["status"]).toBe("authenticated");
  expect(recordField(session, "security")).toMatchObject({
    enrollmentOnly: false,
    assurance: "mfa",
    aal: 2,
    authMethod: "passkey",
    phishingResistant: true,
    recoveryRestricted: false,
    passkeyEnabled: true,
    strongAuthEnabled: true,
    passkeyCount: 1,
  });
}

async function requiredCookie(context: BrowserContext, name: string): Promise<StoredCookie> {
  // Ceremony cookies are scoped below /v1/auth/passkeys and therefore are not
  // returned when filtering cookies against the API root URL.
  const cookie = (await context.cookies()).find((candidate) => (
    candidate.name === name && candidate.domain.replace(/^\./u, "") === "localhost"
  ));
  if (!cookie || cookie.value.length < 1) throw new Error(`Expected ${name} browser cookie is absent`);
  return cookie;
}

function webAuthnCookieName(ceremonyId: string): string {
  return `nom_webauthn_${ceremonyId.toLowerCase().replaceAll("-", "")}`;
}

async function restoreCookies(context: BrowserContext, cookies: readonly StoredCookie[]): Promise<void> {
  await context.addCookies(cookies.map((cookie) => ({
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path,
    expires: cookie.expires,
    httpOnly: cookie.httpOnly,
    secure: cookie.secure,
    sameSite: cookie.sameSite,
  })));
}

function responseData(response: ApiResponse): JsonRecord {
  return recordField(recordValue(response.body), "data");
}

function responseItems(response: ApiResponse): unknown[] {
  const items = responseData(response)["items"];
  if (!Array.isArray(items)) throw new Error("Expected an item-list API response");
  return items;
}

function errorCode(response: ApiResponse): string {
  return stringField(recordField(recordValue(response.body), "error"), "code");
}

function errorDetails(response: ApiResponse): JsonRecord {
  return recordField(recordField(recordValue(response.body), "error"), "details");
}

function recordValue(value: unknown): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected an object value");
  return value as JsonRecord;
}

function recordField(value: JsonRecord, key: string): JsonRecord {
  return recordValue(value[key]);
}

function stringField(value: JsonRecord, key: string): string {
  const field = value[key];
  if (typeof field !== "string") throw new Error(`Expected string field ${key}`);
  return field;
}

function uuidField(value: JsonRecord, key: string): string {
  const field = stringField(value, key);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(field)) {
    throw new Error(`Expected UUIDv4 field ${key}`);
  }
  return field;
}

function readFixture(): {
  readonly marker: "nombramientos-real-browser-stack-v1";
  readonly runId: string;
  readonly apiBaseUrl: string;
  readonly harnessBaseUrl: string;
  readonly tenantId: string;
  readonly passkey: { readonly email: string; readonly sessionToken: string; readonly csrfToken: string };
} {
  const encoded = process.env["NOMBRAMIENTOS_REAL_STACK_PASSKEY_FIXTURE_B64"];
  if (process.env["TEST_WORKER_INDEX"] !== undefined) {
    delete process.env["NOMBRAMIENTOS_REAL_STACK_PASSKEY_FIXTURE_B64"];
  }
  if (!encoded || !/^[A-Za-z0-9_-]+$/u.test(encoded)) throw new Error("Real-stack passkey fixture is unavailable");
  const bytes = Buffer.from(encoded, "base64url");
  let value: JsonRecord;
  try {
    value = recordValue(JSON.parse(bytes.toString("utf8")) as unknown);
  } finally {
    bytes.fill(0);
  }
  if (value["schemaVersion"] !== 1
    || value["marker"] !== "nombramientos-real-browser-stack-v1"
    || value["userAgent"] !== "nombramientos-real-browser-stack-e2e/1") {
    throw new Error("Real-stack passkey fixture marker is invalid");
  }
  const apiBaseUrl = localhostOrigin(value["apiBaseUrl"], "API");
  const harnessBaseUrl = localhostOrigin(value["harnessBaseUrl"], "harness");
  if (apiBaseUrl === harnessBaseUrl) throw new Error("Real-stack passkey origins must differ");
  const passkey = recordField(value, "passkey");
  const email = stringField(passkey, "email");
  const sessionToken = stringField(passkey, "sessionToken");
  const csrfToken = stringField(passkey, "csrfToken");
  if (!/^real-browser-passkey-[0-9a-f]{32}@invalid\.example$/u.test(email)
    || !/^[A-Za-z0-9_-]{40,}$/u.test(sessionToken)
    || !/^[A-Za-z0-9_-]{40,}$/u.test(csrfToken)
    || sessionToken === csrfToken) {
    throw new Error("Real-stack passkey identity or session is invalid");
  }
  return {
    marker: "nombramientos-real-browser-stack-v1",
    runId: requiredUuid(value, "runId"),
    apiBaseUrl,
    harnessBaseUrl,
    tenantId: requiredUuid(value, "tenantId"),
    passkey: { email, sessionToken, csrfToken },
  };
}

function localhostOrigin(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`Real-stack ${label} origin is missing`);
  const parsed = new URL(value);
  const port = Number(parsed.port);
  if (parsed.protocol !== "http:" || parsed.hostname !== "localhost" || parsed.host !== `localhost:${parsed.port}`
    || !Number.isInteger(port) || port < 1 || port > 65_535
    || [3_000, 4_000, 55_432].includes(port) || parsed.origin !== value) {
    throw new Error(`Real-stack ${label} origin is not an isolated localhost port`);
  }
  return parsed.origin;
}

function requiredUuid(record: JsonRecord, key: string): string {
  return uuidField(record, key);
}
