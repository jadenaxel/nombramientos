import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { resolveLocalQaOrigins } from "../scripts/local-qa-boundary.ts";

const { apiOrigin, webOrigin } = resolveLocalQaOrigins();

test("public invitation activation is localized, responsive and never reads a token from the URL", async ({ page }) => {
  const headings = { es: "Activar acceso invitado", en: "Activate invited access", fr: "Activer l’accès invité" } as const;
  const summaries = { es: "Hay 3 errores en el formulario", en: "3 form errors", fr: "3 erreurs dans le formulaire" } as const;
  for (const locale of ["es", "en", "fr"] as const) {
    await page.goto(`/${locale}/auth/invitation?token=not-accepted-from-url`);
    await expect(page.locator("html")).toHaveAttribute("lang", locale);
    await expect(page.getByRole("heading", { name: headings[locale] })).toBeVisible();
    await expect(page.locator("#accept-token")).toHaveValue("");
    await expect(page.locator("#accept-password")).toHaveCount(0);
    await page.getByRole("button", { name: /Activate and continue|Activar y continuar|Activer et continuer/u }).click();
    await expect(page.locator("form")).toHaveAttribute("novalidate", "");
    await expect(page.locator("#accept-validation-summary")).toBeFocused();
    await expect(page.locator("#accept-validation-summary-title")).toHaveText(summaries[locale]);
    for (const field of ["accept-token", "accept-email", "accept-name"]) {
      await expect(page.locator(`#${field}`)).toHaveAttribute("aria-invalid", "true");
      await expect(page.locator(`#${field}`)).toHaveAttribute("aria-describedby", new RegExp(`${field}-(?:error|help)`, "u"));
    }
  }

  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("/es/auth/invitation");
  const activationButton = page.getByRole("button", { name: "Activar y continuar" });
  await activationButton.scrollIntoViewIfNeeded();
  await expect(activationButton).toBeVisible();
  expect((await activationButton.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(44);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(result.violations).toEqual([]);
});

test("the real recovery context installs an origin-bound HttpOnly cookie and stays cross-site silent", async ({ context, page }) => {
  await page.goto("/es/auth/invitation");
  const prepared = await page.evaluate(async (origin) => {
    const response = await fetch(`${origin}/v1/invitations/recovery-context`, {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    return {
      status: response.status,
      cacheControl: response.headers.get("cache-control"),
      payload: await response.json() as unknown,
    };
  }, apiOrigin);
  expect(prepared).toMatchObject({
    status: 200,
    cacheControl: "no-store",
    payload: { data: { prepared: true } },
  });

  const recoveryCookies = (await context.cookies(`${apiOrigin}/v1/invitations`))
    .filter(({ name }) => name.startsWith("nom_invitation_recovery_"));
  expect(recoveryCookies).toHaveLength(1);
  expect(recoveryCookies[0]).toMatchObject({
    domain: "localhost",
    httpOnly: true,
    path: "/v1/invitations",
    secure: false,
  });
  expect(recoveryCookies[0]?.name).toMatch(/^nom_invitation_recovery_[A-Za-z0-9_-]{22}$/u);
  expect(recoveryCookies[0]?.value).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  const nowSeconds = Math.floor(Date.now() / 1_000);
  const expirySeconds = Math.floor(recoveryCookies[0]?.expires ?? 0);
  expect(expirySeconds).toBeGreaterThan(nowSeconds + 86_300);
  expect(expirySeconds).toBeLessThanOrEqual(nowSeconds + 86_400);

  // Playwright 1.63's WebKit protocol reports SameSite=None even for this real
  // API-issued Strict cookie, while Set-Cookie is intentionally unavailable to
  // browser JavaScript. The API route unit test verifies the exact serialized
  // SameSite=Strict attribute. Here we verify the browser behavior directly:
  // the bearer must not accompany a credentialed request from another site.
  const crossSiteOrigin = "http://127.0.0.1:49152";
  let crossSiteCookieHeader: string | undefined;
  await context.route(`${crossSiteOrigin}/cookie-origin`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html",
    body: "<!doctype html><html lang=\"es\"><title>Cross-site cookie probe</title><body></body></html>",
  }));
  await context.route(`${apiOrigin}/v1/invitations/cross-site-cookie-probe`, (route) => {
    crossSiteCookieHeader = route.request().headers()["cookie"];
    return route.fulfill({
      status: 204,
      headers: {
        "access-control-allow-credentials": "true",
        "access-control-allow-origin": crossSiteOrigin,
        "cache-control": "no-store",
      },
    });
  });
  await page.goto(`${crossSiteOrigin}/cookie-origin`);
  const crossSiteStatus = await page.evaluate(async (origin) => {
    const response = await fetch(`${origin}/v1/invitations/cross-site-cookie-probe`, {
      credentials: "include",
      cache: "no-store",
    });
    return response.status;
  }, apiOrigin);
  expect(crossSiteStatus).toBe(204);
  expect(crossSiteCookieHeader).toBeUndefined();

  // Probe from a document whose path matches the cookie. If HttpOnly were not
  // effective, document.cookie would reveal the recovery bearer here.
  await page.route(`${webOrigin}/v1/invitations/cookie-visibility-probe`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html",
    body: "<!doctype html><html lang=\"es\"><title>Cookie visibility probe</title><body></body></html>",
  }));
  await page.goto(`${webOrigin}/v1/invitations/cookie-visibility-probe`);
  expect(await page.evaluate(() => document.cookie)).not.toContain("nom_invitation_recovery_");
});

test("invitation activation clears the password and preserves the server correlation identifier", async ({ page }) => {
  let attempts = 0;
  const submittedBodies: unknown[] = [];
  const recoveryContextProof = "R".repeat(43);
  const recoveryContextCookie = `nom_invitation_recovery_${"C".repeat(22)}`;
  const recoveryContextExpiresAt = Math.floor(Date.now() / 1_000) + 86_400;
  await page.route("**/v1/invitations/recovery-context", async (route) => {
    expect(route.request().postDataJSON()).toEqual({});
    // route.fulfill's synthetic Set-Cookie is exposed as SameSite=None by
    // WebKit. Install the browser fixture through Playwright's cookie API so
    // every engine models the exact server-only contract. Production header
    // serialization is covered independently by the API invitation-route test.
    await page.context().addCookies([{
      name: recoveryContextCookie,
      value: recoveryContextProof,
      domain: "localhost",
      path: "/v1/invitations",
      expires: recoveryContextExpiresAt,
      httpOnly: true,
      secure: false,
      sameSite: "Strict",
    }]);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: {
        "cache-control": "no-store",
      },
      body: JSON.stringify({ data: { prepared: true } }),
    });
  });
  await page.route("**/v1/invitations/accept", async (route) => {
    attempts += 1;
    submittedBodies.push(route.request().postDataJSON());
    if (attempts === 1) {
      await route.fulfill({
        status: 428,
        contentType: "application/json",
        headers: { "access-control-expose-headers": "x-request-id", "x-request-id": "request-password-policy" },
        body: JSON.stringify({ error: { code: "INVITATION_PASSWORD_REQUIRED", message: "Password policy requires provisioning" } }),
      });
      return;
    }
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      headers: {
        "access-control-expose-headers": "x-request-id",
        "x-request-id": "request-invitation-503",
      },
      body: JSON.stringify({ error: { code: "SERVICE_UNAVAILABLE", message: "Sensitive server detail" } }),
    });
  });
  await page.goto("/es/auth/invitation");
  const token = page.locator("#accept-token");
  await expect(token).toBeEnabled();
  await token.fill("A".repeat(43));
  await page.locator("#accept-email").fill("persona@example.test");
  await page.locator("#accept-name").fill("Cuenta Prueba");
  await page.getByRole("button", { name: "Activar y continuar" }).click();
  await expect(page.getByText("Esta organización conserva una contraseña de respaldo", { exact: true })).toBeVisible();
  await expect(page.locator("#accept-password")).toBeFocused();
  const firstBody = submittedBodies[0] as Record<string, unknown>;
  expect(firstBody).toMatchObject({ token: "A".repeat(43), email: "persona@example.test", displayName: "Cuenta Prueba" });
  expect(firstBody).not.toHaveProperty("recoveryProof");
  expect(firstBody).not.toHaveProperty("password");
  await page.locator("#accept-password").fill("T!empoSeguro8742");
  const responsePromise = page.waitForResponse((response) => (
    response.request().method() === "POST"
    && new URL(response.url()).pathname === "/v1/invitations/accept"
  ));
  const [response] = await Promise.all([
    responsePromise,
    page.getByRole("button", { name: "Activar y continuar" }).click(),
  ]);
  expect(response.status()).toBe(503);
  expect(submittedBodies[1]).toEqual({
    token: "A".repeat(43),
    email: "persona@example.test",
    displayName: "Cuenta Prueba",
    password: "T!empoSeguro8742",
  });
  expect(response.headers()["x-request-id"]).toBe("request-invitation-503");
  await expect(page.getByText(/request-invitation-503/u)).toBeVisible();
  await expect(page.getByText("Sensitive server detail")).toHaveCount(0);
  await expect(page.locator("#accept-password")).toHaveValue("");
  await expect.poll(() => submittedBodies.length).toBe(3);
  expect(submittedBodies[2]).toEqual(submittedBodies[1]);

  // A response can be lost after the server commits. A reload must preserve
  // the API-issued HttpOnly browser context; JavaScript never receives it.
  await page.reload();
  await page.locator("#accept-token").fill("A".repeat(43));
  await page.locator("#accept-email").fill("  PERSONA@example.test  ");
  await page.locator("#accept-name").fill("Cuenta Prueba");
  await page.getByRole("button", { name: "Activar y continuar" }).click();
  await expect.poll(() => submittedBodies.length).toBe(5);
  expect(submittedBodies[3]).toEqual({
    token: "A".repeat(43),
    email: "PERSONA@example.test",
    displayName: "Cuenta Prueba",
  });
  expect(submittedBodies[4]).toEqual(submittedBodies[3]);
  const retained = await page.evaluate(() => ({
    localEntries: Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index)!)
      .map((key) => [key, localStorage.getItem(key)]),
    sessionEntries: Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index)!)
      .map((key) => [key, sessionStorage.getItem(key)]),
  }));
  expect(retained.sessionEntries).toHaveLength(0);
  expect(retained.localEntries).toEqual([[
    "nombramientos.ui-preferences.v1",
    JSON.stringify({ textSize: "standard", contrast: "standard", motion: "system", density: "comfortable" }),
  ]]);
  expect(JSON.stringify(retained)).not.toContain("A".repeat(43));
  expect(JSON.stringify(retained)).not.toMatch(/persona@example\.test/iu);
  expect(await page.evaluate(() => document.cookie)).not.toContain("nom_invitation_recovery");
  const recoveryCookie = (await page.context().cookies()).find(({ name }) =>
    name.startsWith("nom_invitation_recovery_"));
  expect(recoveryCookie).toMatchObject({
    name: recoveryContextCookie,
    value: recoveryContextProof,
    domain: "localhost",
    httpOnly: true,
    path: "/v1/invitations",
    secure: false,
    expires: recoveryContextExpiresAt,
  });
});

test("passwordless invitation acceptance enters the restricted passkey-first security center", async ({ page }) => {
  const expiresAt = new Date(Date.now() + 8 * 60_000).toISOString();
  const session = {
    accepted: true,
    signInRequired: false,
    enrollmentRequired: true,
    tenantId: "40000000-0000-4000-8000-000000000001",
    roles: ["AUDITOR"],
    status: "mfa_enrollment_required",
    authenticated: true,
    user: { id: "30000000-0000-4000-8000-000000000001", displayName: "Persona Invitada", email: "persona@example.test" },
    tenant: { id: "40000000-0000-4000-8000-000000000001", slug: "fixture", name: "Iglesia Fixture", kind: "real", timezone: "America/La_Paz" },
    permissions: [],
    csrfToken: "csrf-invitation-enrollment",
    keyGrant: null,
    expiresAt,
    security: {
      mfaRequired: true,
      mfaEnabled: false,
      enrollmentOnly: true,
      assurance: "enrollment_only",
      aal: 1,
      authMethod: "bootstrap",
      phishingResistant: false,
      recoveryRestricted: false,
      passkeyEnabled: false,
      strongAuthEnabled: false,
      passkeyCount: 0,
      idleExpiresAt: expiresAt,
      risk: { elevated: false, userAgentContextChanged: false, ipContextChanged: false },
    },
  } as const;
  let acceptanceBody: unknown;
  const recoveryContextCookie = `nom_invitation_recovery_${"D".repeat(22)}`;
  await page.route("**/v1/invitations/recovery-context", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    headers: {
      "cache-control": "no-store",
      "set-cookie": `${recoveryContextCookie}=${"S".repeat(43)}; HttpOnly; SameSite=Strict; Path=/v1/invitations; Max-Age=86400`,
    },
    body: JSON.stringify({ data: { prepared: true } }),
  }));
  await page.route("**/v1/invitations/accept", async (route) => {
    acceptanceBody = route.request().postDataJSON();
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": "request-invitation-success" },
      body: JSON.stringify({ data: session, meta: { requestId: "request-invitation-success" } }),
    });
  });
  await page.route("**/v1/session", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    headers: { "cache-control": "no-store" },
    body: JSON.stringify({ data: session }),
  }));

  await page.goto("/es/auth/invitation");
  const invitationToken = "Z".repeat(43);
  await page.locator("#accept-token").fill(invitationToken);
  await page.locator("#accept-email").fill("persona@example.test");
  await page.locator("#accept-name").fill("Persona Invitada");
  await expect(page.locator("#accept-password")).toHaveCount(0);
  await page.getByRole("button", { name: "Activar y continuar" }).click();

  await expect(page).toHaveURL(/\/es\/app\/settings$/u);
  await expect(page.getByRole("heading", { name: "Protege tu cuenta antes de continuar" })).toBeVisible();
  await expect(page.locator(".passkey-primary-flow").getByText("En celular usa Face ID, huella o PIN sin escanear un QR.", { exact: false })).toBeVisible();
  await expect(page.getByText("Aplicación autenticadora (TOTP)", { exact: true })).toBeVisible();
  await expect(page.getByText("Inicia sesión", { exact: true })).toHaveCount(0);
  const acceptedBody = acceptanceBody as Record<string, unknown>;
  expect(acceptedBody).toMatchObject({ token: invitationToken, email: "persona@example.test", displayName: "Persona Invitada" });
  expect(acceptedBody).not.toHaveProperty("recoveryProof");
  const serializedStorage = await page.evaluate(() => JSON.stringify({
    local: Object.fromEntries(Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index)!).map((key) => [key, localStorage.getItem(key)])),
    session: Object.fromEntries(Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index)!).map((key) => [key, sessionStorage.getItem(key)])),
  }));
  expect(serializedStorage).not.toContain(invitationToken);
  expect(serializedStorage).not.toContain("S".repeat(43));
  expect(serializedStorage).not.toContain("csrf-invitation-enrollment");
  expect(page.url()).not.toContain(invitationToken);
  // Next.js 16 may stream metadata after the client transition. Assert the
  // accessible title explicitly so axe audits the settled destination page.
  await expect(page).toHaveTitle("Nombramientos Adventistas");
  const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(accessibility.violations).toEqual([]);
});

test("lost acceptance responses recover only the exact invitation identity and tenant", async ({ page }) => {
  const expiresAt = new Date(Date.now() + 8 * 60_000).toISOString();
  const acceptedSession = invitationEnrollmentSession({
    expiresAt,
    identityId: "30000000-0000-4000-8000-000000000011",
    tenantId: "40000000-0000-4000-8000-000000000011",
  });
  let attempts = 0;
  await page.route("**/v1/invitations/recovery-context", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    headers: {
      "cache-control": "no-store",
      "set-cookie": `nom_invitation_recovery_${"E".repeat(22)}=${"T".repeat(43)}; HttpOnly; SameSite=Strict; Path=/v1/invitations; Max-Age=86400`,
    },
    body: JSON.stringify({ data: { prepared: true } }),
  }));
  await page.route("**/v1/invitations/accept", async (route) => {
    attempts += 1;
    if (attempts === 1) {
      await route.abort("failed");
      return;
    }
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({ data: acceptedSession }),
    });
  });
  await page.route("**/v1/session", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ data: acceptedSession }),
  }));

  await page.goto("/es/auth/invitation");
  await page.locator("#accept-token").fill("L".repeat(43));
  await page.locator("#accept-email").fill("lost@example.test");
  await page.locator("#accept-name").fill("Lost Response");
  await page.getByRole("button", { name: "Activar y continuar" }).click();
  await expect.poll(() => attempts).toBe(2);
  await expect(page).toHaveURL(/\/es\/app\/settings$/u);
});

test("a valid enrollment session for another invitation is a browser conflict and is never installed", async ({ page }) => {
  const expiresAt = new Date(Date.now() + 8 * 60_000).toISOString();
  const acceptedSession = invitationEnrollmentSession({
    expiresAt,
    identityId: "30000000-0000-4000-8000-000000000021",
    tenantId: "40000000-0000-4000-8000-000000000021",
  });
  const otherSession = invitationEnrollmentSession({
    expiresAt,
    identityId: "30000000-0000-4000-8000-000000000022",
    tenantId: "40000000-0000-4000-8000-000000000022",
  });
  let attempts = 0;
  let sessionProbes = 0;
  await page.route("**/v1/invitations/recovery-context", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ data: { prepared: true } }),
  }));
  await page.route("**/v1/invitations/accept", (route) => {
    attempts += 1;
    return route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({ data: acceptedSession }),
    });
  });
  await page.route("**/v1/session", (route) => {
    sessionProbes += 1;
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ data: otherSession }),
    });
  });

  await page.goto("/es/auth/invitation");
  await page.locator("#accept-token").fill("C".repeat(43));
  await page.locator("#accept-email").fill("conflict@example.test");
  await page.locator("#accept-name").fill("Conflict User");
  await page.getByRole("button", { name: "Activar y continuar" }).click();
  await expect.poll(() => attempts).toBe(1);
  await expect.poll(() => sessionProbes).toBe(1);
  await expect(page.getByRole("button", { name: "Activar y continuar" })).toBeEnabled();
  await expect(page).toHaveURL(/\/es\/auth\/invitation$/u);
  await expect(page.locator("#accept-token")).toHaveValue("C".repeat(43));
  await expect(page.locator("#accept-email")).toHaveValue("conflict@example.test");
  expect(attempts).toBe(1);
});

test("platform bootstrap validation is localized, accessible and clears the password", async ({ page }) => {
  const summaries = { es: "Hay 4 errores en el formulario", en: "4 form errors", fr: "4 erreurs dans le formulaire" } as const;
  await page.setViewportSize({ width: 320, height: 720 });
  for (const locale of ["es", "en", "fr"] as const) {
    await page.goto(`/${locale}/auth/platform-bootstrap`);
    await page.locator("#platform-bootstrap-password").fill("short");
    await page.locator('form button[type="submit"]').click();
    await expect(page.locator("form")).toHaveAttribute("novalidate", "");
    const summary = page.locator('[aria-labelledby="platform-bootstrap-error-summary-title"]');
    await expect(summary).toBeFocused();
    await expect(page.locator("#platform-bootstrap-error-summary-title")).toHaveText(summaries[locale]);
    await expect(page.locator("#platform-bootstrap-password")).toHaveValue("");
    for (const field of ["platform-bootstrap-token", "platform-bootstrap-email", "platform-bootstrap-name", "platform-bootstrap-password"]) {
      await expect(page.locator(`#${field}`)).toHaveAttribute("aria-invalid", "true");
      await expect(page.locator(`#${field}`)).toHaveAttribute("aria-describedby", new RegExp(`${field}-(?:error|help)`, "u"));
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  }
});

function invitationEnrollmentSession(input: {
  expiresAt: string;
  identityId: string;
  tenantId: string;
}) {
  return {
    accepted: true,
    signInRequired: false,
    enrollmentRequired: true,
    tenantId: input.tenantId,
    roles: ["AUDITOR"],
    status: "mfa_enrollment_required",
    authenticated: true,
    user: {
      id: input.identityId,
      displayName: "Invitation Recipient",
      email: "recipient@example.test",
    },
    tenant: {
      id: input.tenantId,
      slug: "fixture",
      name: "Fixture",
      kind: "real",
      timezone: "America/La_Paz",
    },
    permissions: [],
    csrfToken: "csrf-invitation-enrollment",
    keyGrant: null,
    expiresAt: input.expiresAt,
    security: {
      mfaRequired: true,
      mfaEnabled: false,
      enrollmentOnly: true,
      assurance: "enrollment_only",
      aal: 1,
      authMethod: "bootstrap",
      phishingResistant: false,
      recoveryRestricted: false,
      passkeyEnabled: false,
      strongAuthEnabled: false,
      passkeyCount: 0,
      idleExpiresAt: input.expiresAt,
      risk: { elevated: false, userAgentContextChanged: false, ipContextChanged: false },
    },
  } as const;
}
