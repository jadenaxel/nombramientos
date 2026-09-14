import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Route } from "@playwright/test";

import { localQaApiRoute } from "./support/local-api-route.ts";

const recoveryId = "94000000-0000-4000-8000-000000000001";
const currentIdentityId = "94000000-0000-4000-8000-000000000002";
const otherRequesterId = "94000000-0000-4000-8000-000000000003";
const tenantId = "94000000-0000-4000-8000-000000000004";
const invitationId = "94000000-0000-4000-8000-000000000005";
const acceptanceId = "94000000-0000-4000-8000-000000000006";
const acceptanceIdentityId = "94000000-0000-4000-8000-000000000007";
const secondRecoveryId = "94000000-0000-4000-8000-000000000008";
const syntheticToken = "R".repeat(43);

const localized = {
  es: {
    publicTitle: "Recupera el onboarding sin debilitar tu cuenta",
    submit: "Verificar y abrir sesión limitada",
    success: "Sesión limitada confirmada",
    totp: "Usar autenticador TOTP",
    console: "Recuperación gobernada del administrador inicial",
    secondAdmin: "Se requiere otro administrador",
    approve: "Aprobar y emitir con llave de acceso",
    oneTime: "Paquete de recuperación · visualización única",
    showToken: "Mostrar código",
  },
  en: {
    publicTitle: "Recover onboarding without weakening your account",
    submit: "Verify and open limited session",
    success: "Limited session confirmed",
    totp: "Use a TOTP authenticator",
    console: "Governed initial-admin recovery",
    secondAdmin: "Another administrator is required",
    approve: "Approve and issue with passkey",
    oneTime: "Recovery package · one-time display",
    showToken: "Show code",
  },
  fr: {
    publicTitle: "Récupérez l’intégration sans affaiblir votre compte",
    submit: "Vérifier et ouvrir la session limitée",
    success: "Session limitée confirmée",
    totp: "Utiliser un authentificateur TOTP",
    console: "Récupération gouvernée de l’administrateur initial",
    secondAdmin: "Un autre administrateur est requis",
    approve: "Approuver et émettre avec une clé d’accès",
    oneTime: "Paquet de récupération · affichage unique",
    showToken: "Afficher le code",
  },
} as const;

test("recovery survives response loss without leaking its bearer and opens the requested MFA path", async ({ page }, testInfo) => {
  const locale = localeFor(testInfo.project.name);
  const text = localized[locale];
  const recoveredSession = initialAdminEnrollmentSession("csrf-recovery-repaired-0001");
  const redeemBodies: Array<Record<string, unknown>> = [];
  const events: string[] = [];
  let bearerAttempts = 0;
  let installed = false;

  await page.route(localQaApiRoute(/^\/v1\//u), async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "GET" && path === "/v1/session") {
      events.push("session");
      return installed
        ? ok(route, recoveredSession)
        : fail(route, 401, "UNAUTHENTICATED", "Synthetic unauthenticated boundary");
    }
    if (request.method() === "POST" && path === "/v1/auth/initial-admin-recovery/prepare-context") {
      events.push("prepare");
      expect(request.postDataJSON()).toEqual({});
      expect(request.headers()["x-csrf-token"]).toBeUndefined();
      return route.fulfill({ status: 204, headers: { "cache-control": "no-store", "x-request-id": "recovery-prepare" } });
    }
    if (request.method() === "POST" && path === "/v1/auth/initial-admin-recovery/redeem") {
      const body = request.postDataJSON() as Record<string, unknown>;
      redeemBodies.push(body);
      events.push(body.token ? "redeem:token" : "redeem:context");
      expect(request.headers()["x-csrf-token"]).toBeUndefined();
      if (body.token) {
        bearerAttempts += 1;
        if (bearerAttempts === 1) return route.abort("failed");
        // The exact retry reaches the server, but this synthetic browser loses
        // its Set-Cookie. The bounded precommit context must repair that race.
        return ok(route, { ...recoveredSession, recovered: true });
      }
      installed = true;
      return ok(route, { ...recoveredSession, recovered: true });
    }
    if (request.method() === "GET" && path === "/v1/auth/passkeys") return ok(route, { items: [] });
    if (request.method() === "GET" && path === "/v1/auth/policy") return ok(route, identityPolicy());
    if (request.method() === "GET" && path === "/v1/auth/sessions") return ok(route, { items: [] });
    if (request.method() === "GET" && path === "/v1/memberships") return ok(route, { items: [], activeTenantId: tenantId });
    return fail(route, 404, "NOT_FOUND", "Synthetic route is not required by this ceremony");
  });

  await page.goto(`/${locale}/auth/onboarding-recovery`);
  await expect(page.locator("html")).toHaveAttribute("lang", locale);
  await expect(page.getByRole("heading", { name: text.publicTitle })).toBeVisible();
  await page.locator("#initial-admin-recovery-id").fill(recoveryId);
  await page.locator("#initial-admin-recovery-token").fill(syntheticToken);
  await page.getByRole("button", { name: text.submit }).click();

  await expect(page.getByRole("heading", { name: text.success })).toBeVisible();
  expect(redeemBodies).toEqual([
    { recoveryId, token: syntheticToken },
    { recoveryId, token: syntheticToken },
    { recoveryId },
  ]);
  expect(events.slice(0, 7)).toEqual([
    "session", "prepare", "redeem:token", "redeem:token", "session", "redeem:context", "session",
  ]);
  expect(page.url()).not.toContain(syntheticToken);
  expect(page.url()).not.toContain(recoveryId);
  const persisted = await page.evaluate(() => JSON.stringify({
    local: Object.fromEntries(Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index)!).map((key) => [key, localStorage.getItem(key)])),
    session: Object.fromEntries(Array.from({ length: sessionStorage.length }, (_, index) => sessionStorage.key(index)!).map((key) => [key, sessionStorage.getItem(key)])),
  }));
  expect(persisted).not.toContain(syntheticToken);
  expect(persisted).not.toContain(recoveryId);
  await expectNoHorizontalOverflow(page);
  const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(accessibility.violations).toEqual([]);

  await page.getByRole("button", { name: text.totp }).click();
  await expect(page).toHaveURL(new RegExp(`/${locale}/app/settings#totp-fallback$`, "u"));
  await expect(page.locator("details#totp-fallback")).toHaveAttribute("open", "");
});

test("the platform queue enforces two-person control and never navigates the approver into the recipient session", async ({ page }, testInfo) => {
  const locale = localeFor(testInfo.project.name);
  const text = localized[locale];
  const expiresAt = future(10);
  let approvalRequest: { body: unknown; headers: Record<string, string> } | undefined;

  await page.route(localQaApiRoute(/^\/v1\//u), async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.pathname === "/v1/session") return ok(route, platformSession());
    if (request.method() === "GET" && url.pathname === "/v1/platform/tenants") {
      return ok(route, {
        items: [],
        worker: { code: "tenant-provisioner", status: "running", healthy: true, startedAt: future(-60), heartbeatAt: new Date().toISOString(), processedCount: 12, lastErrorCode: null },
        contentAccess: false,
        keyAccess: false,
      });
    }
    if (request.method() === "GET" && url.pathname === "/v1/platform/initial-admin-recoveries/candidates") {
      return ok(route, { items: [] });
    }
    if (request.method() === "GET" && url.pathname === "/v1/platform/initial-admin-recoveries") {
      return ok(route, { items: recoveryQueue(), nextCursor: null });
    }
    if (request.method() === "POST" && url.pathname === `/v1/platform/initial-admin-recoveries/${secondRecoveryId}/approve`) {
      approvalRequest = { body: request.postDataJSON(), headers: request.headers() };
      return ok(route, {
        recoveryId: secondRecoveryId,
        version: 2,
        status: "enrollment_pending",
        reused: false,
        delivery: { channel: "local_console", state: "delivered", tokenExpiresAt: expiresAt },
        developmentToken: syntheticToken,
      });
    }
    return fail(route, 404, "NOT_FOUND", "Synthetic route is not required by this ceremony");
  });

  await page.goto(`/${locale}/app/platform`);
  await expect(page.getByRole("heading", { name: text.console })).toBeVisible();
  const ownRequest = page.locator(".recovery-queue-list > article").filter({ hasText: "Own recovery recipient" });
  const otherRequest = page.locator(".recovery-queue-list > article").filter({ hasText: "Second recovery recipient" });
  await expect(ownRequest.getByText(text.secondAdmin, { exact: true })).toBeVisible();
  await expect(ownRequest.getByRole("button", { name: text.approve })).toHaveCount(0);
  await expect(otherRequest.getByRole("button", { name: text.approve })).toBeDisabled();
  await otherRequest.locator(`#recovery-delivery-reference-${secondRecoveryId}`).fill("SD-CASE-882741");
  await expect(otherRequest.getByRole("button", { name: text.approve })).toBeEnabled();
  await otherRequest.getByRole("button", { name: text.approve }).click();

  await expect(page.getByText(text.oneTime, { exact: true })).toBeVisible();
  await expect(page.getByText(syntheticToken, { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: text.showToken }).click();
  await expect(page.getByText(syntheticToken, { exact: true })).toBeVisible();
  await expect(page.locator('a[href*="/auth/onboarding-recovery"]')).toHaveCount(0);
  expect(approvalRequest?.headers["x-csrf-token"]).toBe("csrf-platform-admin-0001");
  expect(approvalRequest?.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/u);
  expect(approvalRequest?.body).toEqual({
    recoveryId: secondRecoveryId,
    expectedVersion: 1,
    source: recoverySource(),
    deliveryChannel: "local_console",
    verifiedChannelReference: "SD-CASE-882741",
  });
  await expectNoHorizontalOverflow(page);
  const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(accessibility.violations).toEqual([]);

  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })));
  await expect(page.getByText(text.oneTime, { exact: true })).toHaveCount(0);
  await expect(page.getByText(syntheticToken, { exact: true })).toHaveCount(0);
});

function localeFor(projectName: string): keyof typeof localized {
  return projectName.endsWith("-fr") ? "fr" : projectName.endsWith("-en") ? "en" : "es";
}

async function expectNoHorizontalOverflow(page: import("@playwright/test").Page) {
  const layout = await page.evaluate(() => ({
    viewportWidth: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
    offenders: [...document.querySelectorAll<HTMLElement>("body *")]
      .map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          element: element.id ? `${element.tagName.toLowerCase()}#${element.id}` : `${element.tagName.toLowerCase()}.${[...element.classList].slice(0, 3).join(".")}`,
          left: Math.round(rect.left * 100) / 100,
          right: Math.round(rect.right * 100) / 100,
          width: Math.round(rect.width * 100) / 100,
        };
      })
      .filter(({ left, right }) => left < -1 || right > window.innerWidth + 1)
      .slice(0, 12),
  }));
  expect(layout.documentWidth, JSON.stringify(layout)).toBeLessThanOrEqual(layout.viewportWidth + 1);
}

function initialAdminEnrollmentSession(csrfToken: string) {
  return {
    authenticated: true,
    status: "mfa_enrollment_required",
    user: { id: acceptanceIdentityId, displayName: "Recovered administrator", email: "recipient@example.invalid" },
    tenant: { id: tenantId, slug: "recovery-fixture", name: "Recovery Fixture", kind: "real", timezone: "America/La_Paz" },
    permissions: [],
    csrfToken,
    keyGrant: null,
    expiresAt: future(10),
    security: {
      mfaRequired: true,
      mfaEnabled: false,
      enrollmentOnly: true,
      assurance: "enrollment_only",
      aal: 1,
      authMethod: "bootstrap",
      phishingResistant: false,
      recoveryRestricted: true,
      passkeyEnabled: false,
      strongAuthEnabled: false,
      passkeyCount: 0,
      idleExpiresAt: future(10),
      risk: { elevated: false, userAgentContextChanged: false, ipContextChanged: false },
    },
  } as const;
}

function platformSession() {
  return {
    authenticated: true,
    status: "authenticated",
    user: { id: currentIdentityId, displayName: "Platform approver", email: "approver@example.invalid" },
    tenant: { id: tenantId, slug: "platform-fixture", name: "Platform Fixture", kind: "real", timezone: "UTC" },
    permissions: ["platform.operation.read", "platform.security.manage"],
    csrfToken: "csrf-platform-admin-0001",
    keyGrant: null,
    expiresAt: future(60),
    security: { mfaRequired: true, mfaEnabled: true, enrollmentOnly: false, assurance: "aal2", aal: 2, authMethod: "passkey", phishingResistant: true, recoveryRestricted: false },
  } as const;
}

function recoverySource() {
  return {
    tenantId,
    invitationId,
    acceptanceId,
    acceptanceIdentityId,
    acceptanceAttempt: 1,
    authorityEpoch: 3,
    invitationVersion: 2,
  } as const;
}

function recoveryQueue() {
  const common = {
    version: 1,
    status: "pending",
    tenantDisplayName: "Recovery Fixture",
    ...recoverySource(),
    recipientEmail: "recipient@example.invalid",
    requesterEmail: "requester@example.invalid",
    approverIdentityId: null,
    approverEmail: null,
    approverDisplayName: null,
    reasonCode: "browser_context_lost",
    deliveryChannel: null,
    deliveryState: "not_started",
    requestedAt: new Date().toISOString(),
    requestExpiresAt: future(60),
    approvedAt: null,
    tokenExpiresAt: null,
    redemptionCount: 0,
    strongFactorFinalizedAt: null,
    revokedAt: null,
    revocationReasonCode: null,
    failureCode: null,
  } as const;
  return [
    { ...common, recoveryId, recipientDisplayName: "Own recovery recipient", requesterIdentityId: currentIdentityId, requesterDisplayName: "Platform approver" },
    { ...common, recoveryId: secondRecoveryId, recipientDisplayName: "Second recovery recipient", requesterIdentityId: otherRequesterId, requesterDisplayName: "Requesting administrator" },
  ];
}

function identityPolicy() {
  return {
    policy: {
      baselineVersion: 1, tenantVersion: 1, enforcementMode: "enforce", minimumAal: 2, privilegedMinimumAal: 2,
      requireUserVerification: true, requirePhishingResistantForPrivileged: true, requireDeviceBoundForPrivileged: false, requireAttestationForPrivileged: false,
      allowPassword: true, allowTotpFallback: true, allowRecoveryCodes: true, allowSyncedPasskeys: true,
      minimumPasskeyCount: 1, privilegedMinimumPasskeyCount: 1, maximumPasskeys: 5, maximumActiveSessions: 5,
      idleTimeoutMinutes: 30, absoluteSessionMinutes: 480, stepUpTtlSeconds: 120, actionRequirements: {},
    },
    compliance: { enforcementMode: "enforce", sessionMeetsMinimum: false, privilegedSessionReady: false, activePasskeys: 0, minimumPasskeys: 1, privilegedMinimumPasskeys: 1, findings: [] },
  };
}

function future(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function ok(route: Route, data: unknown) {
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    headers: { "cache-control": "no-store", "x-request-id": "synthetic-initial-admin-recovery" },
    body: JSON.stringify({ data, meta: { requestId: "synthetic-initial-admin-recovery" } }),
  });
}

function fail(route: Route, status: number, code: string, message: string) {
  return route.fulfill({
    status,
    contentType: "application/json",
    headers: { "cache-control": "no-store", "x-request-id": "synthetic-initial-admin-recovery" },
    body: JSON.stringify({ error: { code, message }, meta: { requestId: "synthetic-initial-admin-recovery" } }),
  });
}
