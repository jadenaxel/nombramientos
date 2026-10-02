import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { getMessage } from "@nombramientos/i18n";

import {
  canUnlockTenantGrant,
  unlockTenantGrantForVault,
} from "./key-lifecycle-unlock-policy.ts";

const webRoot = path.resolve(import.meta.dirname, "..");
const lifecycleSource = readFileSync(path.join(webRoot, "components/nombramientos/key-lifecycle-view.tsx"), "utf8");
const clientSource = readFileSync(path.join(webRoot, "lib/key-lifecycle-client.ts"), "utf8");
const historicalDelegationSource = readFileSync(path.join(webRoot, "lib/historical-key-delegation.ts"), "utf8");
const providersSource = readFileSync(path.join(webRoot, "app/providers.tsx"), "utf8");
const shellSource = readFileSync(path.join(webRoot, "components/nombramientos/app-shell.tsx"), "utf8");
const settingsSource = readFileSync(path.join(webRoot, "components/nombramientos/workspace-view.tsx"), "utf8");

test("normaliza la confirmación humana sin usar la clave completa", () => {
  assert.match(clientSource, /replace\(\/\^sha256:\/u, ""\)\.slice\(-8\)\.toUpperCase\(\)/u);
  assert.match(clientSource, /match\(\/\.\{1,4\}\/gu\)\?\.join\(" "\)/u);
});

test("conecta las siete ceremonias mediante challenge y mutación idempotente", () => {
  for (const operation of [
    "device.register", "grant.initialize", "grant.approve", "grant.revoke",
    "key.rotate", "key.recover", "key.declare_lost",
  ]) assert.ok(clientSource.includes(`\"${operation}\"`), `falta ${operation}`);
  for (const endpoint of [
    "/v1/key-lifecycle/challenges", "/v1/key-lifecycle/devices",
    "/v1/key-lifecycle/grants/initialize", "/v1/key-lifecycle/grants",
    "/v1/key-lifecycle/grants/revoke", "/v1/key-lifecycle/rotations",
    "/v1/key-lifecycle/recoveries", "/v1/key-lifecycle/loss-declarations",
  ]) assert.ok(clientSource.includes(endpoint), `falta ${endpoint}`);
  assert.match(clientSource, /challengeIdempotencyKey = idempotencyKey\(\)/u);
  assert.match(clientSource, /mutationIdempotencyKey = idempotencyKey\(\)/u);
  assert.match(clientSource, /retryIdempotent/u);
  assert.match(clientSource, /error\.code\.endsWith\("_UNCERTAIN"\)/u);
});

test("la ceremonia mantiene secretos en cliente y solo persiste objetos CryptoKey", () => {
  assert.match(clientSource, /indexedDB\.open/u);
  assert.match(clientSource, /keyPair: CryptoKeyPair/u);
  assert.doesNotMatch(clientSource, /localStorage|sessionStorage|exportCustodianPrivateKey|privateKeyPkcs8|passphrase:/u);
  assert.match(lifecycleSource, /createEncryptedTenantKeyRecoveryBackup/u);
  assert.match(lifecycleSource, /openEncryptedTenantKeyRecoveryBackup/u);
  assert.match(lifecycleSource, /signTenantKeyRecovery/u);
  assert.match(lifecycleSource, /tenantKey\.fill\(0\)/u);
  assert.doesNotMatch(lifecycleSource, /console\.|error\.message|JSON\.stringify\(parsed\)/u);
});

test("el alta actual y la delegación histórica son acciones explícitas separadas", () => {
  const currentApproval = lifecycleSource.slice(
    lifecycleSource.indexOf("async function approveDevice"),
    lifecycleSource.indexOf("async function completeHistoricalAccess"),
  );
  assert.match(currentApproval, /keyLifecycleApi\.mutate\("grant\.approve"/u);
  assert.doesNotMatch(currentApproval, /delegateHistory/u);
  assert.match(lifecycleSource, /data-testid="historical-key-coverage"/u);
  assert.match(lifecycleSource, /async function completeHistoricalAccess[\s\S]*delegateHistory\(target\)/u);
  assert.match(lifecycleSource, /approvalCode[^\n]*fingerprintConfirmation\(target\.wrappingKeyFingerprint\)/u);
  assert.match(lifecycleSource, /AUTHENTICATION_REQUIRED[\s\S]*auth\.sessionExpired/u);
  assert.match(lifecycleSource, /delegateHistory\(target\)[\s\S]*catch \(error\)[\s\S]*await refresh\(\)\.catch/u);
});

test("desbloquea la actual para escritura y recuerda la retirada sólo para lectura", async () => {
  const tenantId = "10000000-0000-4000-8000-000000000001";
  const currentTenantKeyId = "10000000-0000-4000-8000-000000000002";
  const retiredTenantKeyId = "10000000-0000-4000-8000-000000000003";
  const calls: string[] = [];
  const unlockCurrent = async () => { calls.push("unlock-current"); };
  const rememberHistorical = async () => { calls.push("remember-historical"); };

  await unlockTenantGrantForVault({
    grantStatus: "active",
    grantTenantKeyId: currentTenantKeyId,
    currentTenantKeyId,
    tenantId,
    vaultTenantId: undefined,
    vaultKeyId: undefined,
    keyBytes: new Uint8Array(32),
    unlockCurrent,
    rememberHistorical,
  });
  assert.deepEqual(calls, ["unlock-current"]);

  await unlockTenantGrantForVault({
    grantStatus: "retired",
    grantTenantKeyId: retiredTenantKeyId,
    currentTenantKeyId,
    tenantId,
    vaultTenantId: tenantId,
    vaultKeyId: currentTenantKeyId,
    keyBytes: new Uint8Array(32),
    unlockCurrent,
    rememberHistorical,
  });
  assert.deepEqual(calls, ["unlock-current", "remember-historical"]);

  const retiredWithoutCurrent = {
    grantStatus: "retired",
    grantTenantKeyId: retiredTenantKeyId,
    currentTenantKeyId,
    tenantId,
    vaultTenantId: undefined,
    vaultKeyId: undefined,
  };
  assert.equal(canUnlockTenantGrant(retiredWithoutCurrent), false);
  await assert.rejects(
    unlockTenantGrantForVault({
      ...retiredWithoutCurrent,
      keyBytes: new Uint8Array(32),
      unlockCurrent,
      rememberHistorical,
    }),
    /CLIENT_CRYPTO_ERROR/u,
  );
  assert.deepEqual(calls, ["unlock-current", "remember-historical"]);

  const retiredWithoutDeclaredCurrent = {
    grantStatus: "retired",
    grantTenantKeyId: retiredTenantKeyId,
    currentTenantKeyId: undefined,
    tenantId,
    vaultTenantId: tenantId,
    vaultKeyId: undefined,
  };
  assert.equal(canUnlockTenantGrant(retiredWithoutDeclaredCurrent), false);
  await assert.rejects(
    unlockTenantGrantForVault({
      ...retiredWithoutDeclaredCurrent,
      keyBytes: new Uint8Array(32),
      unlockCurrent,
      rememberHistorical,
    }),
    /CLIENT_CRYPTO_ERROR/u,
  );
  assert.deepEqual(calls, ["unlock-current", "remember-historical"]);
  assert.match(lifecycleSource, /disabled=\{Boolean\(busy\) \|\| !canUnlockTenantGrant\(/u);
});

test("zeroiza cada clave raw aun si falla el vault y el backfill nunca exporta el llavero", () => {
  assert.match(lifecycleSource, /await unlockTenantGrantForVault\(\{[\s\S]*finally \{\s*opened\.keyBytes\.fill\(0\)/u);
  assert.match(lifecycleSource, /await vault\.unlockRaw\(bootstrapDraft\.tenantKey[\s\S]*finally \{\s*bootstrapDraft\.tenantKey\.fill\(0\)/u);
  assert.match(lifecycleSource, /await vault\.unlockRaw\(rotationDraft\.tenantKey[\s\S]*finally \{\s*rotationDraft\.tenantKey\.fill\(0\)/u);
  assert.match(historicalDelegationSource, /withWipedKeyBytes\(opened\.keyBytes/u);
  assert.match(historicalDelegationSource, /await input\.approve/u);
  assert.doesNotMatch(historicalDelegationSource, /rememberRaw|rememberHistorical|unlockRaw|exportKey/u);
  assert.match(providersSource, /importKey\([\s\S]*false,\s*\["decrypt"\]/u);
});

test("Settings y la compuerta de contenido usan el ciclo real para tenants reales", () => {
  assert.match(settingsSource, /<KeyLifecycleView session=\{session\} locale=\{locale\}\/>/u);
  assert.match(shellSource, /session\.tenant\.kind === "real"/u);
  assert.match(shellSource, /<TenantKeyUnlockPanel session=\{session\} locale=\{locale\} \/>/u);
  assert.match(lifecycleSource, /message\(locale, "screen\.keyLifecycleView\.a5f97522f2b3"\)/u);
  assert.deepEqual(
    ["es", "en", "fr"].map((locale) => getMessage(locale as "es" | "en" | "fr", "screen.keyLifecycleView.a5f97522f2b3")),
    ["PRIMER ADMINISTRADOR", "FIRST ADMINISTRATOR", "PREMIER ADMINISTRATEUR"],
  );
});
