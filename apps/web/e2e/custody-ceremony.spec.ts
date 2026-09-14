import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import type { CustodyPublicKey } from "../lib/api.ts";
import { signInDemo } from "./support/demo-auth.ts";
import { localQaApiRoute } from "./support/local-api-route.ts";

type CustodyRegistrationPayload = {
  deviceId: string;
  recipientId: string;
  expectedVersion: number;
  suite: CustodyPublicKey["suite"];
  hpkePublicKey: string;
  hpkeFingerprint: string;
  signingAlgorithm: string;
  signingPublicKeySpki: string;
  signingFingerprint: string;
};

type CustodyKeysEnvelope = {
  data: CustodyPublicKey[];
  meta?: { requestId?: string };
};

const syntheticKeyId = "c7000000-0000-4000-8000-000000000001";
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const base64UrlPattern = /^[A-Za-z0-9_-]+$/u;

async function sha256Digest(value: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return `sha256:${Buffer.from(digest).toString("hex")}`;
}

async function browserPersistenceSnapshot(page: Page) {
  return page.evaluate(async () => {
    const databases = typeof indexedDB.databases === "function" ? await indexedDB.databases() : [];
    return {
      local: Object.keys(localStorage).sort().map((key) => [key, localStorage.getItem(key)]),
      session: Object.keys(sessionStorage).sort().map((key) => [key, sessionStorage.getItem(key)]),
      indexedDb: databases
        .map(({ name, version }) => ({ name: name ?? null, version: version ?? null }))
        .sort((left, right) => (left.name ?? "").localeCompare(right.name ?? "")),
      cacheNames: typeof caches === "undefined" ? [] : (await caches.keys()).sort(),
      url: location.href,
    };
  });
}

test("custodian creates, restores and revokes an encrypted device backup without browser persistence", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One browser ceremony is sufficient; custody writes are synthetic and leave Demo unchanged");

  let registrationWrites = 0;
  let revocationWrites = 0;
  let syntheticKey: CustodyPublicKey | undefined;

  await page.route(localQaApiRoute("/v1/custody/keys"), async (route) => {
    const request = route.request();
    if (request.method() === "GET") {
      const response = await route.fetch();
      expect(response.ok()).toBe(true);
      const envelope = structuredClone(await response.json() as CustodyKeysEnvelope);
      expect(Array.isArray(envelope.data)).toBe(true);
      if (syntheticKey) {
        const projected = syntheticKey;
        envelope.data = [...envelope.data.filter((key) => key.keyId !== projected.keyId), projected];
      }
      return route.fulfill({ response, json: envelope });
    }

    expect(request.method()).toBe("POST");
    registrationWrites += 1;
    expect(registrationWrites).toBe(1);
    expect(request.headers()["idempotency-key"]).toMatch(uuidPattern);
    expect(request.headers()["x-csrf-token"]).toBeTruthy();
    const payload = request.postDataJSON() as CustodyRegistrationPayload;
    expect(Object.keys(payload).sort()).toEqual([
      "deviceId",
      "expectedVersion",
      "hpkeFingerprint",
      "hpkePublicKey",
      "recipientId",
      "signingAlgorithm",
      "signingFingerprint",
      "signingPublicKeySpki",
      "suite",
    ]);
    expect(payload.deviceId).toMatch(uuidPattern);
    expect(payload.expectedVersion).toBe(0);
    expect(payload.recipientId).toMatch(new RegExp(`^[0-9a-f-]+:${payload.deviceId}$`, "u"));
    const custodianIdentityId = payload.recipientId.slice(0, -(payload.deviceId.length + 1));
    expect(custodianIdentityId).toMatch(uuidPattern);
    expect(payload.suite).toEqual({
      kem: "DHKEM(P-256, HKDF-SHA256)",
      kemId: 16,
      kdf: "HKDF-SHA256",
      kdfId: 1,
      aead: "AES-256-GCM",
      aeadId: 2,
    });
    expect(payload.hpkePublicKey).toMatch(base64UrlPattern);
    expect(payload.hpkeFingerprint).toMatch(digestPattern);
    expect(payload.signingAlgorithm).toBe("Ed25519");
    expect(payload.signingPublicKeySpki).toMatch(base64UrlPattern);
    expect(payload.signingFingerprint).toMatch(digestPattern);
    expect(JSON.stringify(payload)).not.toMatch(/ciphertext|passphrase|privateKey/iu);

    const hpkeBytes = Uint8Array.from(Buffer.from(payload.hpkePublicKey, "base64url"));
    const signingBytes = Uint8Array.from(Buffer.from(payload.signingPublicKeySpki, "base64url"));
    expect(hpkeBytes).toHaveLength(65);
    await crypto.subtle.importKey("raw", hpkeBytes, { name: "ECDH", namedCurve: "P-256" }, false, []);
    await crypto.subtle.importKey("spki", signingBytes, { name: "Ed25519" }, false, ["verify"]);
    expect(payload.hpkeFingerprint).toBe(await sha256Digest(hpkeBytes));
    expect(payload.signingFingerprint).toBe(await sha256Digest(signingBytes));

    syntheticKey = {
      keyId: syntheticKeyId,
      custodianIdentityId,
      deviceId: payload.deviceId,
      recipientId: payload.recipientId,
      version: 1,
      status: "active",
      suite: payload.suite,
      hpkePublicKey: payload.hpkePublicKey,
      hpkeFingerprint: payload.hpkeFingerprint as `sha256:${string}`,
      signingAlgorithm: "Ed25519",
      signingPublicKeySpki: payload.signingPublicKeySpki,
      signingFingerprint: payload.signingFingerprint as `sha256:${string}`,
      registeredAt: new Date().toISOString(),
      revokedAt: null,
    };
    return route.fulfill({
      status: 201,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": "synthetic-custody-register" },
      body: JSON.stringify({ data: syntheticKey, meta: { requestId: "synthetic-custody-register" } }),
    });
  });

  await page.route(localQaApiRoute(/^\/v1\/custody\/keys\/[^/]+\/revoke$/u), async (route) => {
    const request = route.request();
    expect(request.method()).toBe("POST");
    revocationWrites += 1;
    expect(revocationWrites).toBe(1);
    expect(request.headers()["idempotency-key"]).toMatch(uuidPattern);
    expect(request.headers()["x-csrf-token"]).toBeTruthy();
    if (!syntheticKey) throw new Error("The synthetic custody key must be registered before it can be revoked");
    expect(new URL(request.url()).pathname).toBe(`/v1/custody/keys/${syntheticKey.keyId}/revoke`);
    expect(request.postDataJSON()).toEqual({ expectedVersion: 1, reasonCode: "DEVICE_RETIRED" });

    const revokedAt = new Date().toISOString();
    syntheticKey = { ...syntheticKey, version: 2, status: "revoked", revokedAt };
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": "synthetic-custody-revoke" },
      body: JSON.stringify({
        data: { keyId: syntheticKey.keyId, version: syntheticKey.version, status: syntheticKey.status, revokedAt, affectedFrozenRounds: 0 },
        meta: { requestId: "synthetic-custody-revoke" },
      }),
    });
  });

  await signInDemo(page, "custodian");
  await page.getByRole("link", { name: "Custodia E2EE" }).click();
  await expect(page.getByRole("heading", { name: "Claves y escrutinio independiente" })).toBeVisible();
  const persistenceBaseline = await browserPersistenceSnapshot(page);

  const passphrase = `Demo-custody-${crypto.randomUUID()}!`;
  await page.getByLabel("Contraseña de la copia cifrada").fill(passphrase);
  await page.getByLabel("Confirmar contraseña").fill(passphrase);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Crear, registrar y descargar copia" }).click(),
  ]);
  const backupPath = testInfo.outputPath("custody-backup.json");
  await download.saveAs(backupPath);
  const backup = JSON.parse(readFileSync(backupPath, "utf8")) as {
    format: string;
    version: number;
    tenantId: string;
    deviceId: string;
    recipientId: string;
    createdAt: string;
    kdf: { name: string; hash: string; iterations: number; salt: string };
    cipher: { name: string; keyLength: number; iv: string };
    ciphertext: string;
  };
  if (!syntheticKey) throw new Error("The browser did not register the synthetic custody key before downloading its backup");
  expect(backup.format).toBe("nombramientos.custodian-key-backup");
  expect(backup.version).toBe(1);
  expect(backup.tenantId).toBe("d0000000-0000-4000-8000-000000000001");
  expect(backup.deviceId).toBe(syntheticKey.deviceId);
  expect(backup.recipientId).toBe(syntheticKey.recipientId);
  expect(backup.kdf).toMatchObject({ name: "PBKDF2", hash: "SHA-256", iterations: 600_000 });
  expect(backup.cipher).toMatchObject({ name: "AES-GCM", keyLength: 256 });
  expect(backup.ciphertext.length).toBeGreaterThan(100);
  expect(JSON.stringify(backup)).not.toMatch(/privateKey|privateKeyPkcs8|passphrase/iu);
  await expect(page.getByText("Claves privadas desbloqueadas en memoria")).toBeVisible();

  const persistenceAfterCreation = await browserPersistenceSnapshot(page);
  expect(persistenceAfterCreation).toEqual(persistenceBaseline);
  expect(JSON.stringify(persistenceAfterCreation)).not.toContain(backup.ciphertext);
  expect(JSON.stringify(persistenceAfterCreation)).not.toContain(passphrase);
  expect(JSON.stringify(persistenceAfterCreation)).not.toMatch(/privateKey|privateKeyPkcs8/iu);
  expect(persistenceAfterCreation.url).not.toContain(passphrase);

  // A full document reload destroys the component's in-memory CryptoKey state
  // while retaining only the authenticated HTTP-only session. The projected
  // public key remains available through the isolated GET route.
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Claves y escrutinio independiente" })).toBeVisible();
  const unlockedStatus = page.getByText("Claves privadas desbloqueadas en memoria");
  await expect(unlockedStatus).toHaveCount(0);
  expect(await browserPersistenceSnapshot(page)).toEqual(persistenceBaseline);

  const keyRow = page.locator(".custody-key-list article").filter({ hasText: backup.recipientId });
  await expect(keyRow).toBeVisible();

  await page.getByLabel("Contraseña de la copia cifrada").fill(passphrase);
  await page.getByLabel("Archivo de copia cifrada").setInputFiles(backupPath);
  await page.getByRole("button", { name: "Desbloquear en este dispositivo" }).click();
  await expect(unlockedStatus).toBeVisible();
  expect(await browserPersistenceSnapshot(page)).toEqual(persistenceBaseline);

  await keyRow.getByRole("button", { name: "Revocar" }).click();
  await expect(keyRow.getByText(/Revocada/)).toBeVisible();
  expect(registrationWrites).toBe(1);
  expect(revocationWrites).toBe(1);
  expect(syntheticKey.status).toBe("revoked");
});
