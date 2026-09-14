import { describe, expect, it } from "vitest";
import {
  createEncryptedTenantKeyRecoveryBackup,
  createTenantKeyGrantEnvelope,
  createTenantKeyRecoveryContext,
  exportTenantDevicePublicKey,
  generateTenantContentKey,
  generateTenantDeviceKeyPair,
  importCustodianPublicKey,
  openEncryptedTenantKeyRecoveryBackup,
  openTenantKeyGrantEnvelope,
  signTenantKeyRecovery,
  verifyTenantKeyGrantEnvelope,
  verifyTenantKeyRecovery,
} from "../src/index.js";

const tenantId = "10000000-0000-4000-8000-000000000001";
const identityId = "10000000-0000-4000-8000-000000000002";
const deviceId = "10000000-0000-4000-8000-000000000003";

describe("client-only tenant key lifecycle", () => {
  it("wraps a random tenant key to a device without exposing plaintext", async () => {
    const device = await generateTenantDeviceKeyPair({ tenantId, deviceId });
    const publicExport = await exportTenantDevicePublicKey(device);
    const publicKey = await importCustodianPublicKey(publicExport);
    const tenantKey = generateTenantContentKey("10000000-0000-4000-8000-000000000004");
    const envelope = await createTenantKeyGrantEnvelope({
      tenantId,
      tenantKeyId: tenantKey.tenantKeyId,
      generation: 1,
      identityId,
      deviceId,
      tenantKey: tenantKey.keyBytes,
      recipient: publicKey,
    });

    expect(JSON.stringify(envelope)).not.toContain(Buffer.from(tenantKey.keyBytes).toString("base64url"));
    expect((await verifyTenantKeyGrantEnvelope(envelope)).envelopeHash).toBe(envelope.envelopeHash);
    const opened = await openTenantKeyGrantEnvelope({
      envelope,
      recipient: device,
      expected: {
        tenantId,
        tenantKeyId: tenantKey.tenantKeyId,
        generation: 1,
        identityId,
        deviceId,
      },
    });
    expect(Buffer.from(opened.keyBytes)).toEqual(Buffer.from(tenantKey.keyBytes));
    await expect(verifyTenantKeyGrantEnvelope({ ...envelope, ciphertext: `${envelope.ciphertext}A` })).rejects.toThrow();
  });

  it("opens a prior-generation grant after a newer tenant key exists", async () => {
    const device = await generateTenantDeviceKeyPair({ tenantId, deviceId });
    const publicKey = await importCustodianPublicKey(await exportTenantDevicePublicKey(device));
    const priorKey = generateTenantContentKey("10000000-0000-4000-8000-000000000014");
    const currentKey = generateTenantContentKey("10000000-0000-4000-8000-000000000015");
    const priorEnvelope = await createTenantKeyGrantEnvelope({
      tenantId,
      tenantKeyId: priorKey.tenantKeyId,
      generation: 1,
      identityId,
      deviceId,
      tenantKey: priorKey.keyBytes,
      recipient: publicKey,
    });
    const currentEnvelope = await createTenantKeyGrantEnvelope({
      tenantId,
      tenantKeyId: currentKey.tenantKeyId,
      generation: 2,
      identityId,
      deviceId,
      tenantKey: currentKey.keyBytes,
      recipient: publicKey,
    });

    const openedCurrent = await openTenantKeyGrantEnvelope({
      envelope: currentEnvelope,
      recipient: device,
      expected: { tenantId, tenantKeyId: currentKey.tenantKeyId, generation: 2, identityId, deviceId },
    });
    const openedPrior = await openTenantKeyGrantEnvelope({
      envelope: priorEnvelope,
      recipient: device,
      expected: { tenantId, tenantKeyId: priorKey.tenantKeyId, generation: 1, identityId, deviceId },
    });

    expect(Buffer.from(openedCurrent.keyBytes)).toEqual(Buffer.from(currentKey.keyBytes));
    expect(Buffer.from(openedPrior.keyBytes)).toEqual(Buffer.from(priorKey.keyBytes));
    expect(openedPrior.tenantKeyId).toBe(priorKey.tenantKeyId);
  });

  it("recovers only with the encrypted offline package and binds a one-time authorization", async () => {
    const tenantKey = generateTenantContentKey("10000000-0000-4000-8000-000000000005");
    const passphrase = "Correct Horse Battery Staple 2026!";
    const prepared = await createEncryptedTenantKeyRecoveryBackup({
      tenantId,
      tenantKeyId: tenantKey.tenantKeyId,
      generation: 1,
      tenantKey: tenantKey.keyBytes,
      passphrase,
      createdAt: "2026-09-11T12:00:00.000Z",
    });
    expect(JSON.stringify(prepared.backup)).not.toContain(passphrase);
    expect(JSON.stringify(prepared.backup)).not.toContain(Buffer.from(tenantKey.keyBytes).toString("base64url"));
    await expect(openEncryptedTenantKeyRecoveryBackup(prepared.backup, "Wrong recovery password!")).rejects.toThrow();

    const recovered = await openEncryptedTenantKeyRecoveryBackup(prepared.backup, passphrase);
    expect(Buffer.from(recovered.tenantKey)).toEqual(Buffer.from(tenantKey.keyBytes));
    const context = createTenantKeyRecoveryContext({
      tenantId,
      tenantKeyId: tenantKey.tenantKeyId,
      generation: 1,
      recoveryNonce: "10000000-0000-4000-8000-000000000006",
      targetIdentityId: identityId,
      targetDeviceId: deviceId,
      targetDeviceFingerprint: `sha256:${"a".repeat(64)}`,
      envelopeHash: `sha256:${"b".repeat(64)}`,
    });
    const authorization = await signTenantKeyRecovery(recovered.recoverySigningKey, context);
    expect(await verifyTenantKeyRecovery(prepared.recoveryPublicKey, authorization)).toBe(true);
    expect(await verifyTenantKeyRecovery(prepared.recoveryPublicKey, {
      ...authorization,
      context: { ...authorization.context, targetDeviceId: "10000000-0000-4000-8000-000000000007" },
    })).toBe(false);
  }, 15_000);
});
