import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";

const identityId = "81000000-0000-4000-8000-000000000001";
const tenantId = "81000000-0000-4000-8000-000000000002";
const currentSessionId = "81000000-0000-4000-8000-000000000003";
const otherSessionId = "81000000-0000-4000-8000-000000000004";
const firstCredentialId = "81000000-0000-4000-8000-000000000005";
const secondCredentialId = "81000000-0000-4000-8000-000000000006";

const localized = {
  es: {
    center: "Centro de seguridad", risk: "Verificación adicional de sesión", riskEvidence: "Cambio detectado: Navegador/dispositivo y red",
    replacement: "Reemplazar una llave existente", replacementRequired: "Alcanzaste el máximo de llaves.", replace: "Registrar reemplazo seguro",
    stale: "Por seguridad, tu verificación reciente venció. Vuelve a iniciar sesión con MFA y luego crea tu primera llave de acceso.", reauthenticate: "Volver a iniciar sesión con MFA",
    revoke: "Revocar", revokeTitle: "¿Revocar esta llave de acceso?", confirm: "Confirmar de forma segura",
  },
  en: {
    center: "Security center", risk: "Additional session verification", riskEvidence: "Detected change: Browser/device and network",
    replacement: "Replace an existing passkey", replacementRequired: "You have reached the passkey limit.", replace: "Register secure replacement",
    stale: "For your security, your recent verification expired. Sign in again with MFA, then create your first passkey.", reauthenticate: "Sign in again with MFA",
    revoke: "Revoke", revokeTitle: "Revoke this passkey?", confirm: "Confirm securely",
  },
  fr: {
    center: "Centre de sécurité", risk: "Vérification supplémentaire de la session", riskEvidence: "Changement détecté : Navigateur/appareil et réseau",
    replacement: "Remplacer une clé existante", replacementRequired: "Vous avez atteint la limite de clés.", replace: "Enregistrer le remplacement sécurisé",
    stale: "Pour votre sécurité, votre vérification récente a expiré. Reconnectez-vous avec l’AMF, puis créez votre première clé d’accès.", reauthenticate: "Se reconnecter avec l’AMF",
    revoke: "Révoquer", revokeTitle: "Révoquer cette clé d’accès ?", confirm: "Confirmer en sécurité",
  },
} as const;

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    class SyntheticPublicKeyCredential {
      static isConditionalMediationAvailable = async () => true;
      static isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    }
    Object.defineProperty(window, "PublicKeyCredential", { configurable: true, value: SyntheticPublicKeyCredential });
  });
});

test("risk posture, atomic replacement, stale reauthentication and 320px accessibility remain coherent", async ({ page }, testInfo) => {
  const locale = localeFor(testInfo.project.name);
  const text = localized[locale];
  let registrationBody: unknown;
  await installSecurityApi(page, async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "POST" && path === "/v1/auth/passkeys/registration/options") {
      registrationBody = request.postDataJSON();
      await fail(route, 428, "PASSKEY_ENROLLMENT_REAUTHENTICATION_REQUIRED", "Recent MFA expired");
      return true;
    }
    if (request.method() === "POST" && path === "/v1/auth/logout") {
      await ok(route, { loggedOut: true });
      return true;
    }
    return false;
  });

  await page.goto(`/${locale}/app/settings`);
  await expect(page.getByRole("heading", { name: text.center })).toBeVisible();
  await expect(page.getByText(text.risk, { exact: true })).toBeVisible();
  await expect(page.locator(".security-risk-alert").getByText(text.riskEvidence, { exact: true })).toBeVisible();
  const replacement = page.getByLabel(text.replacement);
  await expect(replacement).toBeVisible();
  await expect(page.locator("#passkey-replacement-help")).toContainText(text.replacementRequired);

  await replacement.focus();
  await page.keyboard.press("ArrowDown");
  await expect(replacement).toHaveValue(firstCredentialId);
  await expect(page.getByRole("button", { name: text.replace })).toBeEnabled();
  await page.getByRole("button", { name: text.replace }).click();
  await expect(page.getByText(text.stale, { exact: false })).toBeVisible();
  expect(registrationBody).toEqual({ replacementCredentialId: firstCredentialId });

  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(accessibility.violations).toEqual([]);

  await page.getByRole("button", { name: text.reauthenticate }).click();
  await expect(page).toHaveURL(new RegExp(`/${locale}/auth/sign-in$`, "u"));
});

test("atomic passkey revocation that closes the current session returns focus safely then signs out", async ({ page }, testInfo) => {
  const locale = localeFor(testInfo.project.name);
  const text = localized[locale];
  await installSecurityApi(page, async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "DELETE" && path === `/v1/auth/passkeys/${firstCredentialId}`) {
      await ok(route, { revoked: true, signedOut: true, sessionsRevoked: 1 });
      return true;
    }
    return false;
  }, 10);

  await page.goto(`/${locale}/app/settings`);
  const credential = page.locator(".credential-list article").filter({ hasText: "Primary laptop" });
  const revoke = credential.getByRole("button", { name: text.revoke });
  await revoke.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: text.revokeTitle })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(revoke).toBeFocused();
  await page.keyboard.press("Enter");
  await page.getByRole("button", { name: text.confirm }).click();
  await expect(page).toHaveURL(new RegExp(`/${locale}/auth/sign-in$`, "u"));
});

async function installSecurityApi(
  page: Page,
  override: (route: Route) => Promise<boolean>,
  maximumPasskeys = 2,
) {
  await page.route("**/v1/**", async (route) => {
    if (await override(route)) return;
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "GET" && path === "/v1/session") return ok(route, session());
    if (request.method() === "GET" && path === "/v1/auth/passkeys") return ok(route, { items: passkeys() });
    if (request.method() === "GET" && path === "/v1/auth/sessions") return ok(route, { items: sessions() });
    if (request.method() === "GET" && path === "/v1/auth/policy") return ok(route, policy(maximumPasskeys));
    if (request.method() === "GET" && path === "/v1/memberships") return ok(route, { items: [], activeTenantId: tenantId });
    return fail(route, 404, "NOT_FOUND", "Synthetic route is not required by this ceremony");
  });
}

function session() {
  return {
    sessionId: currentSessionId, status: "authenticated", authenticated: true,
    user: { id: identityId, displayName: "Security Operator", email: "operator@example.invalid" },
    tenant: { id: tenantId, slug: "security-qa", name: "Security QA", kind: "real", timezone: "America/Santo_Domingo" },
    permissions: ["tenant.settings.manage"], csrfToken: "synthetic-csrf", keyGrant: null,
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    security: { mfaRequired: true, mfaEnabled: true, enrollmentOnly: false, assurance: "mfa", aal: 2, authMethod: "totp", phishingResistant: false, passkeyEnabled: true, passkeyCount: 2, risk: { elevated: true, userAgentContextChanged: true, ipContextChanged: true } },
  };
}

function passkeys() {
  const createdAt = new Date(Date.now() - 86_400_000).toISOString();
  return [
    { id: firstCredentialId, version: 1, name: "Primary laptop", createdAt, lastUsedAt: createdAt, transports: ["internal"], deviceType: "singleDevice", backedUp: false, attachment: "platform", trustLevel: "self", revokedAt: null },
    { id: secondCredentialId, version: 1, name: "Mobile backup", createdAt, lastUsedAt: null, transports: ["hybrid"], deviceType: "multiDevice", backedUp: true, attachment: "platform", trustLevel: "self", revokedAt: null },
  ];
}

function sessions() {
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
  return [
    { id: currentSessionId, current: true, deviceLabel: "Current browser", createdAt: now, lastSeenAt: now, expiresAt, idleExpiresAt: expiresAt, authMethod: "totp", assurance: "mfa", aal: 2, phishingResistant: false, risk: { elevated: true, userAgentContextChanged: true, ipContextChanged: true }, revokedAt: null },
    { id: otherSessionId, current: false, deviceLabel: "Office browser", createdAt: now, lastSeenAt: now, expiresAt, idleExpiresAt: expiresAt, authMethod: "passkey", assurance: "aal2", aal: 2, phishingResistant: true, risk: { elevated: true, userAgentContextChanged: null, ipContextChanged: true }, revokedAt: null },
  ];
}

function policy(maximumPasskeys: number) {
  return {
    policy: {
      baselineVersion: 1, tenantVersion: 1, enforcementMode: "enforce", minimumAal: 2, privilegedMinimumAal: 2,
      requireUserVerification: true, requirePhishingResistantForPrivileged: true, requireDeviceBoundForPrivileged: false, requireAttestationForPrivileged: false,
      allowPassword: true, allowTotpFallback: true, allowRecoveryCodes: true, allowSyncedPasskeys: true,
      minimumPasskeyCount: 1, privilegedMinimumPasskeyCount: 1, maximumPasskeys, maximumActiveSessions: 5,
      idleTimeoutMinutes: 30, absoluteSessionMinutes: 480, stepUpTtlSeconds: 120,
      actionRequirements: { "auth.passkey.revoke": { minAal: 2, phishingResistant: true, stepUpRequired: true } },
    },
    compliance: { enforcementMode: "enforce", sessionMeetsMinimum: true, privilegedSessionReady: true, activePasskeys: 2, minimumPasskeys: 1, privilegedMinimumPasskeys: 1, findings: [] },
  };
}

function localeFor(projectName: string): keyof typeof localized {
  return projectName.endsWith("-en") ? "en" : projectName.endsWith("-fr") ? "fr" : "es";
}

function ok(route: Route, data: unknown) {
  return route.fulfill({ status: 200, contentType: "application/json", headers: { "cache-control": "no-store", "x-request-id": "synthetic-enterprise-auth" }, body: JSON.stringify({ data, meta: { requestId: "synthetic-enterprise-auth" } }) });
}

function fail(route: Route, status: number, code: string, message: string) {
  return route.fulfill({ status, contentType: "application/json", headers: { "cache-control": "no-store", "x-request-id": "synthetic-enterprise-auth" }, body: JSON.stringify({ error: { code, message }, meta: { requestId: "synthetic-enterprise-auth" } }) });
}
