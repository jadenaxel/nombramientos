import assert from "node:assert/strict";
import test from "node:test";
import { encryptJson } from "./crypto-client.ts";
import { HistoricalEnvelopeKeyUnavailableError, openJsonEnvelope } from "./historical-envelope.ts";
import { TenantCryptoKeyring } from "./tenant-keyring.ts";

const tenantId = "11111111-1111-4111-8111-111111111111";
const oldKeyId = "22222222-2222-4222-8222-222222222222";
const currentKeyId = "33333333-3333-4333-8333-333333333333";
const aad = { tenantId, memberId: "44444444-4444-4444-8444-444444444444", purpose: "member-display", schemaVersion: 1 };

test("a rotated keyring decrypts historical and current envelopes by their own keyId", async () => {
  const oldKey = await createKey();
  const currentKey = await createKey();
  const oldEnvelope = (await encryptJson(oldKey, oldKeyId, aad, { displayName: "Historical" })).envelope;
  const currentEnvelope = (await encryptJson(currentKey, currentKeyId, aad, { displayName: "Current" })).envelope;
  const keyring = new TenantCryptoKeyring();
  keyring.rememberCurrent(tenantId, oldKeyId, oldKey);
  keyring.rememberCurrent(tenantId, currentKeyId, currentKey);

  assert.deepEqual(await openJsonEnvelope({ resolver: keyringResolver(keyring), tenantId, envelope: oldEnvelope, aad }), { displayName: "Historical" });
  assert.deepEqual(await openJsonEnvelope({ resolver: keyringResolver(keyring), tenantId, envelope: currentEnvelope, aad }), { displayName: "Current" });
});

test("a missing retired grant fails closed without trying the current generation", async () => {
  const oldKey = await createKey();
  const currentKey = await createKey();
  const oldEnvelope = (await encryptJson(oldKey, oldKeyId, aad, { displayName: "Historical" })).envelope;
  const keyring = new TenantCryptoKeyring();
  keyring.rememberCurrent(tenantId, currentKeyId, currentKey);

  await assert.rejects(
    openJsonEnvelope({ resolver: keyringResolver(keyring), tenantId, envelope: oldEnvelope, aad }),
    (error) => error instanceof HistoricalEnvelopeKeyUnavailableError && error.keyId === oldKeyId,
  );
});

async function createKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function keyringResolver(keyring: TenantCryptoKeyring) {
  return { keyFor: (keyId: string, requestedTenantId: string) => keyring.keyFor(requestedTenantId, keyId) };
}
