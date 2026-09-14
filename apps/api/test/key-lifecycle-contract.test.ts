import { createECDH, createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  assertGrantEnvelope,
  assertRecoveryAuthorization,
  assertRecoveryPublicKey,
  assertWrappingPublicKey,
  lifecycleChallengeSchema,
  lifecycleIntentRequestHash,
  type TenantKeyGrantEnvelopeInput,
} from "../src/modules/key-lifecycle-contract.js";

const tenantId = "20000000-0000-4000-8000-000000000001";
const identityId = "20000000-0000-4000-8000-000000000002";
const deviceId = "20000000-0000-4000-8000-000000000003";
const tenantKeyId = "20000000-0000-4000-8000-000000000004";

describe("tenant-key HTTP contracts", () => {
  it("accepts only public wrapping material and rejects plaintext/private fields", () => {
    const publicKey = createECDH("prime256v1").generateKeys();
    const descriptor = {
      format: "nombramientos.hpke-public-key" as const,
      version: 1 as const,
      suite: suite(),
      recipientId: `tenant:${tenantId}:device:${deviceId}`,
      fingerprint: digest(publicKey),
      publicKey: publicKey.toString("base64url"),
    };
    expect(() => assertWrappingPublicKey(descriptor, tenantId, deviceId)).not.toThrow();
    expect(lifecycleChallengeSchema.safeParse({
      operation: "device.register",
      request: { deviceId, label: "Primary browser", wrappingPublicKey: descriptor, privateKey: "forbidden" },
    }).success).toBe(false);
    expect(lifecycleChallengeSchema.safeParse({
      operation: "grant.initialize",
      request: { password: "forbidden", deviceId, tenantKeyId },
    }).success).toBe(false);
  });

  it("binds an opaque grant to tenant, generation, identity, device and fingerprint", () => {
    const publicKey = createECDH("prime256v1").generateKeys();
    const fingerprint = digest(publicKey);
    const body = {
      format: "nombramientos.tenant-key-grant" as const,
      version: 1 as const,
      suite: suite(),
      aad: {
        purpose: "nombramientos.tenant-key-grant" as const,
        schemaVersion: 1 as const,
        tenantId,
        tenantKeyId,
        generation: 1,
        identityId,
        deviceId,
        deviceFingerprint: fingerprint,
      },
      recipientId: `tenant:${tenantId}:device:${deviceId}`,
      recipientFingerprint: fingerprint,
      enc: publicKey.toString("base64url"),
      ciphertext: Buffer.alloc(48, 7).toString("base64url"),
    };
    const envelope: TenantKeyGrantEnvelopeInput = {
      ...body,
      envelopeHash: lifecycleIntentRequestHash(body),
    };
    const expected = { tenantId, tenantKeyId, generation: 1, identityId, deviceId, deviceFingerprint: fingerprint };
    expect(() => assertGrantEnvelope(envelope, expected)).not.toThrow();
    expect(() => assertGrantEnvelope(envelope, { ...expected, identityId: "20000000-0000-4000-8000-000000000099" }))
      .toThrow(/exact tenant/i);
    expect(() => assertGrantEnvelope({ ...envelope, ciphertext: Buffer.alloc(48, 8).toString("base64url") }, expected))
      .toThrow(/hash/i);
  });

  it("verifies an Ed25519 recovery signature over the exact one-time context", () => {
    const pair = generateKeyPairSync("ed25519");
    const spki = pair.publicKey.export({ format: "der", type: "spki" });
    const recoveryPublicKey = {
      format: "nombramientos.ed25519-public-key" as const,
      version: 1 as const,
      algorithm: "Ed25519" as const,
      fingerprint: digest(spki),
      publicKeySpki: spki.toString("base64url"),
    };
    assertRecoveryPublicKey(recoveryPublicKey);
    const context = {
      purpose: "nombramientos.tenant-key-recovery" as const,
      schemaVersion: 1 as const,
      tenantId,
      tenantKeyId,
      generation: 1,
      recoveryNonce: "20000000-0000-4000-8000-000000000005",
      targetIdentityId: identityId,
      targetDeviceId: deviceId,
      targetDeviceFingerprint: `sha256:${"a".repeat(64)}` as `sha256:${string}`,
      envelopeHash: `sha256:${"b".repeat(64)}` as `sha256:${string}`,
    };
    const signature = sign(null, Buffer.from(stableJson(context)), pair.privateKey).toString("base64url");
    const authorization = { context, recoveryKeyFingerprint: recoveryPublicKey.fingerprint, signature };
    expect(() => assertRecoveryAuthorization(recoveryPublicKey, authorization, {
      tenantId,
      tenantKeyId,
      generation: 1,
      recoveryNonce: context.recoveryNonce,
      targetIdentityId: identityId,
      targetDeviceId: deviceId,
      targetDeviceFingerprint: context.targetDeviceFingerprint,
      envelopeHash: context.envelopeHash,
    })).not.toThrow();
    expect(() => assertRecoveryAuthorization(recoveryPublicKey, authorization, {
      tenantId,
      tenantKeyId,
      generation: 1,
      recoveryNonce: context.recoveryNonce,
      targetIdentityId: identityId,
      targetDeviceId: "20000000-0000-4000-8000-000000000006",
      targetDeviceFingerprint: context.targetDeviceFingerprint,
      envelopeHash: context.envelopeHash,
    })).toThrow(/exact request/i);
  });
});

function suite() {
  return {
    kem: "DHKEM(P-256, HKDF-SHA256)" as const,
    kemId: 16 as const,
    kdf: "HKDF-SHA256" as const,
    kdfId: 1 as const,
    aead: "AES-256-GCM" as const,
    aeadId: 2 as const,
  };
}

function digest(value: Buffer): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}
