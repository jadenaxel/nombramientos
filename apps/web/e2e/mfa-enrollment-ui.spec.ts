import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { localQaApiRoute } from "./support/local-api-route.ts";

const identityId = "10000000-0000-4000-8000-000000000071";
const tenantId = "d0000000-0000-4000-8000-000000000001";
const enrollmentId = "10000000-0000-4000-8000-000000000072";
const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const recoveryCodes = Array.from({ length: 10 }, (_, index) => `AAAA-AAAA-AAAA-AAA${"ABCDEFGHJK"[index]}`);

test("privileged MFA gate keeps enrollment secrets in memory and exposes localized recovery guidance", async ({ page }, testInfo) => {
  const locale = testInfo.project.name.includes("fr") ? "fr" : testInfo.project.name.includes("en") ? "en" : "es";
  const titles = { es: "Protege tu acceso con MFA", en: "Protect your access with MFA", fr: "Protégez votre accès avec l’AMF" } as const;
  const startLabels = { es: "Configurar autenticador", en: "Set up authenticator", fr: "Configurer l’authentificateur" } as const;
  const confirmLabels = { es: "Confirmar y activar", en: "Confirm and activate", fr: "Confirmer et activer" } as const;
  const recoveryTitles = { es: "Guarda tus códigos de recuperación", en: "Save your recovery codes", fr: "Conservez vos codes de récupération" } as const;
  const resumeTitles = { es: "Continuar verificación", en: "Continue verification", fr: "Continuer la vérification" } as const;
  const authenticatorLinks = { es: "Abrir mi aplicación autenticadora", en: "Open my authenticator app", fr: "Ouvrir mon application d’authentification" } as const;
  const qrLabels = { es: "Código QR local para configurar el autenticador", en: "Locally generated QR code for authenticator setup", fr: "Code QR généré localement pour configurer l’authentificateur" } as const;
  const fallbackLabels = { es: "Aplicación autenticadora (TOTP)", en: "Authenticator app (TOTP)", fr: "Application d’authentification (TOTP)" } as const;
  let csrf = "csrf-enrollment-only";
  let completed = false;

  await page.route(localQaApiRoute(/^\/v1\//u), async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const baseSession = {
      status: completed ? "authenticated" : "mfa_enrollment_required",
      authenticated: true,
      user: { id: identityId, displayName: "Administración Invitada", email: "mfa@example.invalid" },
      tenant: { id: tenantId, slug: "demo", name: "Iglesia Demo", kind: "demo" },
      permissions: completed ? ["role.manage"] : [],
      csrfToken: csrf,
      keyGrant: null,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      security: {
        mfaRequired: true,
        mfaEnabled: completed,
        enrollmentOnly: !completed,
        assurance: completed ? "mfa" : "enrollment_only",
      },
    };
    const json = (data: unknown, status = 200) => route.fulfill({
      status,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": "10000000-0000-4000-8000-000000000073" },
      body: JSON.stringify({ data, meta: { requestId: "10000000-0000-4000-8000-000000000073" } }),
    });
    if (request.method() === "GET" && url.pathname === "/v1/session") return json(baseSession);
    if (request.method() === "POST" && url.pathname === "/v1/auth/mfa/enrollment/start") {
      expect(request.headers()["x-csrf-token"]).toBe(csrf);
      return json({
        enrollmentId,
        secret: seed,
        otpauthUri: `otpauth://totp/Nombramientos%3Ademo?secret=${seed}&issuer=Nombramientos&algorithm=SHA1&digits=6&period=30`,
        expiresAt: new Date(Date.now() + 600_000).toISOString(),
        algorithm: "SHA1",
        digits: 6,
        period: 30,
      }, 201);
    }
    if (request.method() === "POST" && url.pathname === "/v1/auth/mfa/enrollment/confirm") {
      expect(request.headers()["x-csrf-token"]).toBe(csrf);
      expect(request.postDataJSON()).toEqual({ enrollmentId, code: "123456" });
      completed = true;
      csrf = "csrf-mfa-rotated";
      return json({ ...baseSession, status: "authenticated", permissions: ["role.manage"], csrfToken: csrf, security: { ...baseSession.security, mfaEnabled: true, enrollmentOnly: false, assurance: "mfa" }, recoveryCodes });
    }
    if (request.method() === "POST" && url.pathname === "/v1/auth/logout") return json({ loggedOut: true });
    return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: { code: "NOT_FOUND", message: "Not mocked" }, meta: { requestId: "10000000-0000-4000-8000-000000000073" } }) });
  });

  await page.goto(`/${locale}/app/settings`);
  await ensureTotpFallbackOpen(page, fallbackLabels[locale]);
  await expect(page.getByRole("heading", { name: titles[locale] })).toBeVisible();
  await expect(page.getByText(/permissions remain blocked|permisos operativos permanecen bloqueados|autorisations opérationnelles restent bloquées/i)).toBeVisible();
  await page.getByRole("button", { name: startLabels[locale] }).click();
  await expect(page.getByText(seed.match(/.{1,4}/g)!.join(" "))).toBeVisible();
  await expect(page.getByRole("link", { name: authenticatorLinks[locale] })).toHaveAttribute("href", /^otpauth:\/\/totp\//u);
  await expect(page.getByRole("img", { name: qrLabels[locale] })).toBeVisible();
  expect(page.url()).not.toContain(seed);
  await expectOnlyNonsensitivePreferencesInStorage(page, [seed], enrollmentId);

  await page.reload();
  await ensureTotpFallbackOpen(page, fallbackLabels[locale]);
  await expect(page.getByText(resumeTitles[locale], { exact: true })).toBeVisible();
  await expect(page.getByText(seed.match(/.{1,4}/g)!.join(" "))).toHaveCount(0);
  await expectOnlyNonsensitivePreferencesInStorage(page, [seed], enrollmentId);

  await page.locator("#mfa-enrollment-code").fill("123456");
  await page.getByRole("button", { name: confirmLabels[locale] }).click();
  await expect(page.getByRole("heading", { name: recoveryTitles[locale] })).toBeVisible();
  await expect(page.locator("ol[aria-label]").getByRole("listitem")).toHaveCount(10);
  expect(page.url()).not.toContain(seed);
  await expectOnlyNonsensitivePreferencesInStorage(page, [seed, ...recoveryCodes]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(accessibility.violations).toEqual([]);
});

async function ensureTotpFallbackOpen(page: import("@playwright/test").Page, accessibleName: string) {
  const fallback = page.locator("details#totp-fallback");
  await expect(fallback).toBeVisible();
  if (!(await fallback.evaluate((element: HTMLDetailsElement) => element.open))) {
    await fallback.locator("summary").getByText(accessibleName, { exact: true }).click();
  }
  await expect(fallback).toHaveAttribute("open", "");
}

async function expectOnlyNonsensitivePreferencesInStorage(page: import("@playwright/test").Page, forbiddenValues: readonly string[], pendingEnrollmentId?: string) {
  const storage = await page.evaluate(() => ({
    local: Object.fromEntries(Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index)!).map((key) => [key, localStorage.getItem(key)])),
    session: Object.fromEntries(Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index)!).map((key) => [key, sessionStorage.getItem(key)])),
  }));
  expect(Object.keys(storage.local)).toEqual(["nombramientos.ui-preferences.v1"]);
  if (pendingEnrollmentId) {
    expect(Object.keys(storage.session)).toEqual(["nombramientos.mfa-enrollment.v1"]);
    const pending = JSON.parse(storage.session["nombramientos.mfa-enrollment.v1"]!);
    expect(pending.enrollmentId).toBe(pendingEnrollmentId);
    expect(typeof pending.expiresAt).toBe("string");
    expect(Object.keys(pending).sort()).toEqual(["enrollmentId", "expiresAt"]);
  } else expect(storage.session).toEqual({});
  const serialized = JSON.stringify(storage);
  for (const forbidden of forbiddenValues) expect(serialized).not.toContain(forbidden);
}
