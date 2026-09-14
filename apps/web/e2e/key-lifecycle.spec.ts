import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import {
  createTenantKeyGrantEnvelope,
  exportTenantDevicePublicKey,
  generateTenantContentKey,
  generateTenantDeviceKeyPair,
  openTenantKeyGrantEnvelope,
} from "@nombramientos/e2ee";

import { resolveLocalQaOrigins } from "../scripts/local-qa-boundary.ts";

const identityId = "10000000-0000-4000-8000-000000000081";
const tenantId = "d0000000-0000-4000-8000-000000000081";
const requestId = "10000000-0000-4000-8000-000000000082";
const apiOrigin = resolveLocalQaOrigins().apiOrigin;

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

test("real-tenant E2EE enrollment is localized and sends public material only", async ({ page }, testInfo) => {
  const requestedLocale = process.env["KEY_LIFECYCLE_TEST_LOCALE"];
  const locale = requestedLocale === "en" || requestedLocale === "fr" || requestedLocale === "es"
    ? requestedLocale
    : testInfo.project.name.includes("fr") ? "fr" : testInfo.project.name.includes("en") ? "en" : "es";
  const title = { es: "Ciclo de vida de la clave de la iglesia", en: "Church key lifecycle", fr: "Cycle de vie de la clé de l’Église" } as const;
  const deviceLabel = { es: "Nombre reconocible del dispositivo", en: "Recognizable device name", fr: "Nom reconnaissable de l’appareil" } as const;
  const register = { es: "Registrar dispositivo", en: "Register device", fr: "Enregistrer l’appareil" } as const;
  const firstAdmin = { es: "Inicialización sin custodia del servidor", en: "Initialization without server custody", fr: "Initialisation sans garde du serveur" } as const;
  const csrf = "csrf-key-lifecycle";
  let registeredDevice: Record<string, unknown> | undefined;
  const state = () => ({
    tenantKind: "real",
    currentGeneration: null,
    generations: [],
    devices: registeredDevice ? [{
      deviceId: registeredDevice.deviceId,
      identityId,
      label: registeredDevice.label,
      wrappingPublicKey: registeredDevice.wrappingPublicKey,
      wrappingKeyFingerprint: (registeredDevice.wrappingPublicKey as { fingerprint: string }).fingerprint,
      status: "pending",
      version: 1,
      registeredAt: new Date().toISOString(),
      activatedAt: null,
      revokedAt: null,
    }] : [],
    ownGrants: [],
    managedGrants: [],
  });

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const json = (data: unknown, status = 200) => route.fulfill({
      status,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": requestId },
      body: JSON.stringify({ data, meta: { requestId } }),
    });
    if (request.method() === "GET" && url.pathname === "/v1/session") return json({
      status: "authenticated",
      authenticated: true,
      user: { id: identityId, displayName: "Initial Administrator", email: "admin@example.invalid" },
      tenant: { id: tenantId, slug: "real-church", name: "Real Church", kind: "real" },
      permissions: ["recovery.activate"],
      csrfToken: csrf,
      keyGrant: null,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      security: { mfaRequired: true, mfaEnabled: true, enrollmentOnly: false, assurance: "mfa" },
    });
    if (request.method() === "GET" && url.pathname === "/v1/key-lifecycle") return json(state());
    if (request.method() === "POST" && url.pathname === "/v1/key-lifecycle/challenges") {
      expect(request.headers()["x-csrf-token"]).toBe(csrf);
      expect(request.headers()["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/u);
      const body = request.postDataJSON() as { operation: string; request: Record<string, unknown> };
      expect(body.operation).toBe("device.register");
      expect(JSON.stringify(body)).not.toMatch(/private|password|passphrase|tenantKey/iu);
      return json({ challengeId: "10000000-0000-4000-8000-000000000083", operation: body.operation, requestHash: `sha256:${"a".repeat(64)}`, status: "pending", expiresAt: new Date(Date.now() + 300_000).toISOString() }, 201);
    }
    if (request.method() === "POST" && url.pathname === "/v1/key-lifecycle/devices") {
      const body = request.postDataJSON() as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(["challengeId", "deviceId", "label", "wrappingPublicKey"]);
      expect(JSON.stringify(body)).not.toMatch(/private|password|passphrase|tenantKey/iu);
      registeredDevice = body;
      return json({ ...body, identityId, status: "pending", version: 1 }, 201);
    }
    if (request.method() === "POST" && url.pathname === "/v1/auth/logout") return json({ loggedOut: true });
    return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: { code: "NOT_FOUND", message: "Not mocked" }, meta: { requestId } }) });
  });

  await page.goto(`/${locale}/app/settings`);
  await expect(page.getByRole("heading", { name: title[locale] })).toBeVisible();
  await expect(page.getByText(/No backdoor|Sin puerta trasera|Sans porte dérobée/u)).toBeVisible();

  if (testInfo.project.name === "desktop-chromium-es") {
    await page.getByLabel(deviceLabel[locale]).fill("Portátil principal");
    await page.getByRole("button", { name: register[locale] }).click();
    await expect(page.getByRole("heading", { name: firstAdmin[locale] })).toBeVisible();
    await expect(page.getByText("Portátil principal")).toBeVisible();
    expect(await page.evaluate(() => ({
      unexpectedLocalKeys: Object.keys(localStorage).filter((key) => key !== "nombramientos.ui-preferences.v1"),
      sessionKeys: Object.keys(sessionStorage),
      serializedLocal: JSON.stringify(localStorage),
    }))).toMatchObject({ unexpectedLocalKeys: [], sessionKeys: [] });
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toMatch(/private|password|passphrase|tenantKey/iu);
    expect(await page.evaluate(async () => new Promise<boolean>((resolve, reject) => {
      const request = indexedDB.open("nombramientos-e2ee-devices");
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const all = request.result.transaction("devices", "readonly").objectStore("devices").getAll();
        all.onerror = () => reject(all.error);
        all.onsuccess = () => resolve(all.result.length === 1 && all.result[0].keyPair.privateKey instanceof CryptoKey);
      };
    }))).toBe(true);
  }

  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const accessibility = await new AxeBuilder({ page }).include("[data-testid='key-lifecycle-view']").withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(accessibility.violations).toEqual([]);
});

test("historical access reaches challenge and cryptographic mutation, recovers from MFA, and remains retryable", async ({ page }, testInfo) => {
  const requestedLocale = process.env["KEY_LIFECYCLE_TEST_LOCALE"];
  const locale = requestedLocale === "en" || requestedLocale === "fr" || requestedLocale === "es"
    ? requestedLocale
    : testInfo.project.name.includes("fr") ? "fr" : testInfo.project.name.includes("en") ? "en" : "es";
  const historicalTitle = {
    es: "Cobertura histórica por dispositivo",
    en: "Historical coverage by device",
    fr: "Couverture historique par appareil",
  } as const;
  const completeHistory = {
    es: "Completar acceso histórico",
    en: "Complete historical access",
    fr: "Compléter l’accès historique",
  } as const;
  const partialCoverage = {
    es: "1 de 2 generaciones retiradas disponibles",
    en: "1 of 2 retired generations available",
    fr: "1 sur 2 générations retirées disponibles",
  } as const;
  const confirmationPrefix = {
    es: "Confirma la huella:",
    en: "Confirm fingerprint:",
    fr: "Confirmez l’empreinte :",
  } as const;
  const partialWarning = {
    es: "El servidor interrumpió la delegación histórica: 1 de 2 generaciones quedaron cubiertas.",
    en: "The server interrupted historical delegation: 1 of 2 generations are covered.",
    fr: "Le serveur a interrompu la délégation historique : 1 génération(s) sur 2 sont couvertes.",
  } as const;
  const mfaWarning = {
    es: "La verificación MFA ya no es reciente. Inicia sesión nuevamente y confirma tu segundo factor.",
    en: "Your MFA verification is no longer recent. Sign in again and confirm your second factor.",
    fr: "Votre vérification AMF n’est plus récente. Reconnectez-vous et confirmez votre second facteur.",
  } as const;
  const mfaAction = {
    es: "Volver a iniciar sesión con MFA",
    en: "Sign in again with MFA",
    fr: "Se reconnecter avec l’AMF",
  } as const;
  const completeCoverage = {
    es: "2 de 2 generaciones retiradas disponibles",
    en: "2 of 2 retired generations available",
    fr: "2 sur 2 générations retirées disponibles",
  } as const;
  const successNotice = {
    es: "El dispositivo recibió las 2 generaciones retiradas.",
    en: "The device received all 2 retired generations.",
    fr: "L’appareil a reçu les 2 générations retirées.",
  } as const;
  const csrf = "csrf-key-history";
  const targetIdentityId = "10000000-0000-4000-8000-000000000091";
  const targetDeviceId = "10000000-0000-4000-8000-000000000092";
  const actorDeviceId = "10000000-0000-4000-8000-000000000098";
  const currentTenantKeyId = "10000000-0000-4000-8000-000000000093";
  const retiredTenantKeyIdA = "10000000-0000-4000-8000-000000000094";
  const retiredTenantKeyIdB = "10000000-0000-4000-8000-000000000095";
  const createdAt = "2026-09-12T12:00:00.000Z";
  const [actorPrivate, targetPrivate] = await Promise.all([
    generateTenantDeviceKeyPair({ tenantId, deviceId: actorDeviceId }),
    generateTenantDeviceKeyPair({ tenantId, deviceId: targetDeviceId }),
  ]);
  const [actorPublic, targetPublic, actorPublicJwk, actorPrivateJwk] = await Promise.all([
    exportTenantDevicePublicKey(actorPrivate),
    exportTenantDevicePublicKey(targetPrivate),
    crypto.subtle.exportKey("jwk", actorPrivate.keyPair.publicKey),
    crypto.subtle.exportKey("jwk", actorPrivate.keyPair.privateKey),
  ]);
  const historicalKey = generateTenantContentKey(retiredTenantKeyIdB);
  const historicalKeyDigest = await sha256Hex(historicalKey.keyBytes);
  const actorHistoricalEnvelope = await createTenantKeyGrantEnvelope({
    tenantId,
    tenantKeyId: retiredTenantKeyIdB,
    generation: 2,
    identityId,
    deviceId: actorDeviceId,
    tenantKey: historicalKey.keyBytes,
    recipient: actorPrivate,
  }).finally(() => historicalKey.keyBytes.fill(0));
  const targetFingerprint = targetPublic.fingerprint;
  const confirmationLabel = `${confirmationPrefix[locale]} ${targetFingerprint.replace(/^sha256:/u, "").slice(-8).toUpperCase()}`;
  let stateReads = 0;
  let grantApprovalChallenges = 0;
  let grantApprovalMutations = 0;
  let delegatedEnvelope: typeof actorHistoricalEnvelope | undefined;

  const envelope = (tenantKeyId: string, generation: number) => ({
    format: "fixture-envelope",
    tenantKeyId,
    generation,
  });
  const grant = (input: {
    grantId: string;
    tenantKeyId: string;
    generation: number;
    status: "active" | "retired";
    identityId?: string;
    deviceId?: string;
    envelope?: typeof actorHistoricalEnvelope;
  }) => {
    const grantEnvelope = input.envelope ?? envelope(input.tenantKeyId, input.generation);
    return {
      ...input,
      identityId: input.identityId ?? targetIdentityId,
      deviceId: input.deviceId ?? targetDeviceId,
      envelope: grantEnvelope,
      envelopeHash: input.envelope?.envelopeHash ?? `sha256:${"e".repeat(64)}`,
      grantKind: "admin_approved",
      version: 1,
      grantedByIdentityId: identityId,
      createdAt,
      retiredAt: input.status === "retired" ? createdAt : null,
      revokedAt: null,
    };
  };
  const actorHistoricalGrant = grant({
    grantId: "10000000-0000-4000-8000-000000000099",
    tenantKeyId: retiredTenantKeyIdB,
    generation: 2,
    status: "retired",
    identityId,
    deviceId: actorDeviceId,
    envelope: actorHistoricalEnvelope,
  });
  const lifecycleState = () => ({
    tenantKind: "real",
    currentGeneration: {
      tenantKeyId: currentTenantKeyId,
      generation: 3,
      status: "active",
      recoveryKeyFingerprint: `sha256:${"d".repeat(64)}`,
      createdAt,
      retiredAt: null,
      lostAt: null,
      activeGrantCount: 1,
    },
    generations: [
      {
        tenantKeyId: currentTenantKeyId,
        generation: 3,
        status: "active",
        recoveryKeyFingerprint: `sha256:${"d".repeat(64)}`,
        createdAt,
        retiredAt: null,
        lostAt: null,
        activeGrantCount: 1,
      },
      {
        tenantKeyId: retiredTenantKeyIdB,
        generation: 2,
        status: "retired",
        recoveryKeyFingerprint: `sha256:${"b".repeat(64)}`,
        createdAt,
        retiredAt: createdAt,
        lostAt: null,
        activeGrantCount: 0,
      },
      {
        tenantKeyId: retiredTenantKeyIdA,
        generation: 1,
        status: "retired",
        recoveryKeyFingerprint: `sha256:${"a".repeat(64)}`,
        createdAt,
        retiredAt: createdAt,
        lostAt: null,
        activeGrantCount: 0,
      },
    ],
    devices: [{
      deviceId: targetDeviceId,
      identityId: targetIdentityId,
      label: "Archive tablet",
      wrappingPublicKey: targetPublic,
      wrappingKeyFingerprint: targetFingerprint,
      status: "active",
      version: 2,
      registeredAt: createdAt,
      activatedAt: createdAt,
      revokedAt: null,
    }, {
      deviceId: actorDeviceId,
      identityId,
      label: "Archive source",
      wrappingPublicKey: actorPublic,
      wrappingKeyFingerprint: actorPublic.fingerprint,
      status: "active",
      version: 1,
      registeredAt: createdAt,
      activatedAt: createdAt,
      revokedAt: null,
    }],
    ownGrants: [actorHistoricalGrant],
    managedGrants: [
      actorHistoricalGrant,
      grant({ grantId: "10000000-0000-4000-8000-000000000096", tenantKeyId: currentTenantKeyId, generation: 3, status: "active" }),
      grant({ grantId: "10000000-0000-4000-8000-000000000097", tenantKeyId: retiredTenantKeyIdA, generation: 1, status: "retired" }),
      ...(delegatedEnvelope ? [grant({
        grantId: "10000000-0000-4000-8000-000000000100",
        tenantKeyId: retiredTenantKeyIdB,
        generation: 2,
        status: "retired",
        envelope: delegatedEnvelope,
      })] : []),
    ],
  });

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const json = (data: unknown, status = 200) => route.fulfill({
      status,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": requestId },
      body: JSON.stringify({ data, meta: { requestId } }),
    });
    const error = (status: number, code: string) => route.fulfill({
      status,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": requestId },
      body: JSON.stringify({ error: { code, message: code }, meta: { requestId } }),
    });
    if (request.method() === "GET" && url.pathname === "/v1/session") return json({
      status: "authenticated",
      authenticated: true,
      user: { id: identityId, displayName: "Key Administrator", email: "admin@example.invalid" },
      tenant: { id: tenantId, slug: "real-church", name: "Real Church", kind: "real", timezone: "America/La_Paz", locale },
      permissions: ["recovery.activate"],
      csrfToken: csrf,
      keyGrant: null,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      security: { mfaRequired: true, mfaEnabled: true, enrollmentOnly: false, assurance: "mfa" },
    });
    if (request.method() === "GET" && url.pathname === "/v1/key-lifecycle") {
      stateReads += 1;
      return json(lifecycleState());
    }
    if (request.method() === "POST" && url.pathname === "/v1/key-lifecycle/challenges") {
      expect(request.headers()["x-csrf-token"]).toBe(csrf);
      expect(request.headers()["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/u);
      const body = request.postDataJSON() as { operation?: string; request?: Record<string, unknown> };
      expect(body.operation).toBe("grant.approve");
      expect(JSON.stringify(body)).not.toMatch(/private|passphrase|tenantKeyBytes/iu);
      grantApprovalChallenges += 1;
      if (grantApprovalChallenges === 2) return error(428, "KEY_LIFECYCLE_STEP_UP_REQUIRED");
      return json({
        challengeId: crypto.randomUUID(),
        operation: body.operation,
        requestHash: `sha256:${"c".repeat(64)}`,
        status: "pending",
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
      }, 201);
    }
    if (request.method() === "POST" && url.pathname === "/v1/key-lifecycle/grants") {
      grantApprovalMutations += 1;
      expect(request.headers()["x-csrf-token"]).toBe(csrf);
      expect(request.headers()["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/u);
      const body = request.postDataJSON() as {
        challengeId: string;
        targetIdentityId: string;
        targetDeviceId: string;
        tenantKeyId: string;
        generation: number;
        envelope: typeof actorHistoricalEnvelope;
      };
      expect(body).toMatchObject({
        targetIdentityId,
        targetDeviceId,
        tenantKeyId: retiredTenantKeyIdB,
        generation: 2,
      });
      const opened = await openTenantKeyGrantEnvelope({
        envelope: body.envelope,
        recipient: targetPrivate,
        expected: {
          tenantId,
          tenantKeyId: retiredTenantKeyIdB,
          generation: 2,
          identityId: targetIdentityId,
          deviceId: targetDeviceId,
        },
      });
      try {
        expect(await sha256Hex(opened.keyBytes)).toBe(historicalKeyDigest);
      } finally {
        opened.keyBytes.fill(0);
      }
      if (grantApprovalMutations === 1) return error(429, "RATE_LIMITED");
      delegatedEnvelope = body.envelope;
      return json({ grantId: "10000000-0000-4000-8000-000000000100", status: "retired" }, 201);
    }
    if (request.method() === "POST" && url.pathname === "/v1/auth/logout") return json({ loggedOut: true });
    return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: { code: "NOT_FOUND", message: "Not mocked" }, meta: { requestId } }) });
  });

  await page.goto(`/${locale}/app/settings`);
  await page.evaluate(async ({
    actorPublicJwk: publicJwk,
    actorPrivateJwk: privateJwk,
    actorDeviceId: localDeviceId,
    actorRecipientId,
    actorFingerprint,
    createdAt: localCreatedAt,
    tenantId: localTenantId,
    identityId: localIdentityId,
  }) => {
    const algorithm = { name: "ECDH", namedCurve: "P-256" };
    const [publicKey, privateKey] = await Promise.all([
      crypto.subtle.importKey("jwk", publicJwk, algorithm, true, []),
      crypto.subtle.importKey("jwk", privateJwk, algorithm, true, ["deriveBits"]),
    ]);
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open("nombramientos-e2ee-devices", 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains("devices")) request.result.createObjectStore("devices");
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction("devices", "readwrite");
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
      transaction.objectStore("devices").put({
        storageVersion: 1,
        tenantId: localTenantId,
        identityId: localIdentityId,
        deviceId: localDeviceId,
        label: "Archive source",
        recipientId: actorRecipientId,
        fingerprint: actorFingerprint,
        publicKey,
        keyPair: { publicKey, privateKey },
        createdAt: localCreatedAt,
      }, `${localTenantId}:${localIdentityId}:${localDeviceId}`);
    });
    database.close();
  }, {
    actorPublicJwk,
    actorPrivateJwk,
    actorDeviceId,
    actorRecipientId: actorPrivate.recipientId,
    actorFingerprint: actorPrivate.fingerprint,
    createdAt,
    tenantId,
    identityId,
  });
  await page.reload();
  const coverage = page.getByTestId("historical-key-coverage");
  await expect(coverage.getByRole("heading", { name: historicalTitle[locale] })).toBeVisible();
  await expect(coverage.getByText(partialCoverage[locale], { exact: true })).toBeVisible();
  await expect(coverage.getByText(/Disponible|Available|Disponible/u, { exact: true })).toHaveCount(1);
  await expect(coverage.getByText(/Pendiente|Pending|En attente/u, { exact: true })).toHaveCount(1);
  expect(grantApprovalChallenges).toBe(0);
  expect(grantApprovalMutations).toBe(0);

  const firstAction = coverage.getByRole("button", { name: completeHistory[locale] });
  await expect(firstAction).toHaveCount(1);
  await firstAction.click();
  await coverage.getByLabel(confirmationLabel, { exact: true }).fill(targetFingerprint.replace(/^sha256:/u, "").slice(-8).toUpperCase());
  await expect(coverage.getByRole("button", { name: completeHistory[locale] })).toHaveCount(2);
  await coverage.getByRole("button", { name: completeHistory[locale] }).last().click();

  await expect(page.locator('[role="alert"]').filter({ hasText: partialWarning[locale] })).toBeVisible();
  await expect(coverage.getByRole("button", { name: completeHistory[locale] })).toHaveCount(1);
  await expect(coverage.getByRole("button", { name: completeHistory[locale] })).toBeEnabled();
  expect(grantApprovalChallenges).toBe(1);
  expect(grantApprovalMutations).toBe(1);

  const readsAfterFirstAttempt = stateReads;
  await coverage.getByRole("button", { name: completeHistory[locale] }).click();
  await coverage.getByLabel(confirmationLabel, { exact: true }).fill(targetFingerprint.replace(/^sha256:/u, "").slice(-8).toUpperCase());
  await coverage.getByRole("button", { name: completeHistory[locale] }).last().click();
  await expect.poll(() => stateReads).toBeGreaterThan(readsAfterFirstAttempt);
  await expect(page.locator('[role="alert"]').filter({ hasText: mfaWarning[locale] })).toBeVisible();
  await expect(page.getByRole("button", { name: mfaAction[locale] })).toBeVisible();
  await expect(coverage.getByRole("button", { name: completeHistory[locale] })).toHaveCount(2);
  await expect(coverage.getByRole("button", { name: completeHistory[locale] }).last()).toBeEnabled();
  expect(grantApprovalChallenges).toBe(2);
  expect(grantApprovalMutations).toBe(1);

  const readsAfterMfaConflict = stateReads;
  await coverage.getByLabel(confirmationLabel, { exact: true }).fill(targetFingerprint.replace(/^sha256:/u, "").slice(-8).toUpperCase());
  await coverage.getByRole("button", { name: completeHistory[locale] }).last().click();
  await expect.poll(() => stateReads).toBeGreaterThan(readsAfterMfaConflict);
  await expect(page.locator('[role="alert"]').filter({ hasText: successNotice[locale] })).toBeVisible();
  await expect(coverage.getByText(completeCoverage[locale], { exact: true })).toBeVisible();
  await expect(coverage.getByRole("button", { name: completeHistory[locale] })).toHaveCount(0);
  expect(grantApprovalChallenges).toBe(3);
  expect(grantApprovalMutations).toBe(2);

  const accessibility = await new AxeBuilder({ page })
    .include("[data-testid='historical-key-coverage']")
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
});
