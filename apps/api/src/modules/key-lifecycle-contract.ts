import { createHash, createPublicKey, verify } from "node:crypto";
import { hashKeyLifecycleRequest, type KeyLifecycleOperation } from "@nombramientos/database";
import { z } from "zod";
import { ApiError } from "../lib/errors.js";
import {
  keyGrantRevokeReasonCodeSchema,
  keyLossReasonCodeSchema,
  keyRotationReasonCodeSchema,
} from "../lib/reason-code.js";

const uuid = z.string().uuid();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u)
  .transform((value) => value as `sha256:${string}`);
const base64url = z.string().min(1).max(16_384).regex(/^[A-Za-z0-9_-]+$/u);

export const hpkeSuiteSchema = z.object({
  kem: z.literal("DHKEM(P-256, HKDF-SHA256)"),
  kemId: z.literal(16),
  kdf: z.literal("HKDF-SHA256"),
  kdfId: z.literal(1),
  aead: z.literal("AES-256-GCM"),
  aeadId: z.literal(2),
}).strict();

export const wrappingPublicKeySchema = z.object({
  format: z.literal("nombramientos.hpke-public-key"),
  version: z.literal(1),
  suite: hpkeSuiteSchema,
  recipientId: z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u),
  fingerprint: digest,
  publicKey: base64url,
}).strict();

export const recoveryPublicKeySchema = z.object({
  format: z.literal("nombramientos.ed25519-public-key"),
  version: z.literal(1),
  algorithm: z.literal("Ed25519"),
  fingerprint: digest,
  publicKeySpki: base64url,
}).strict();

export const tenantKeyGrantAadSchema = z.object({
  purpose: z.literal("nombramientos.tenant-key-grant"),
  schemaVersion: z.literal(1),
  tenantId: uuid,
  tenantKeyId: uuid,
  generation: z.number().int().positive(),
  identityId: uuid,
  deviceId: uuid,
  deviceFingerprint: digest,
}).strict();

export const tenantKeyGrantEnvelopeSchema = z.object({
  format: z.literal("nombramientos.tenant-key-grant"),
  version: z.literal(1),
  suite: hpkeSuiteSchema,
  aad: tenantKeyGrantAadSchema,
  recipientId: z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u),
  recipientFingerprint: digest,
  enc: base64url,
  ciphertext: base64url,
  envelopeHash: digest,
}).strict();

export const recoveryContextSchema = z.object({
  purpose: z.literal("nombramientos.tenant-key-recovery"),
  schemaVersion: z.literal(1),
  tenantId: uuid,
  tenantKeyId: uuid,
  generation: z.number().int().positive(),
  recoveryNonce: uuid,
  targetIdentityId: uuid,
  targetDeviceId: uuid,
  targetDeviceFingerprint: digest,
  envelopeHash: digest,
}).strict();

export const recoveryAuthorizationSchema = z.object({
  context: recoveryContextSchema,
  recoveryKeyFingerprint: digest,
  signature: base64url,
}).strict();

export const registerDeviceIntentSchema = z.object({
  deviceId: uuid,
  label: z.string().trim().min(1).max(80),
  wrappingPublicKey: wrappingPublicKeySchema,
}).strict();

export const initializeGrantIntentSchema = z.object({
  deviceId: uuid,
  tenantKeyId: uuid,
  envelope: tenantKeyGrantEnvelopeSchema,
  recoveryPublicKey: recoveryPublicKeySchema,
}).strict();

export const approveGrantIntentSchema = z.object({
  targetIdentityId: uuid,
  targetDeviceId: uuid,
  tenantKeyId: uuid,
  generation: z.number().int().positive(),
  envelope: tenantKeyGrantEnvelopeSchema,
}).strict();

export const revokeGrantIntentSchema = z.object({
  grantId: uuid,
  expectedVersion: z.number().int().positive(),
  reasonCode: keyGrantRevokeReasonCodeSchema,
  confirmLastActiveGrant: z.boolean().default(false),
}).strict();

export const rotationGrantSchema = z.object({
  targetIdentityId: uuid,
  targetDeviceId: uuid,
  envelope: tenantKeyGrantEnvelopeSchema,
}).strict();

export const rotateKeyIntentSchema = z.object({
  expectedTenantKeyId: uuid,
  expectedGeneration: z.number().int().positive(),
  newTenantKeyId: uuid,
  reasonCode: keyRotationReasonCodeSchema,
  recoveryPublicKey: recoveryPublicKeySchema,
  grants: z.array(rotationGrantSchema).min(1).max(100),
}).strict();

export const recoverKeyIntentSchema = z.object({
  tenantKeyId: uuid,
  targetIdentityId: uuid,
  targetDeviceId: uuid,
  envelope: tenantKeyGrantEnvelopeSchema,
  authorization: recoveryAuthorizationSchema,
}).strict();

export const declareKeyLostIntentSchema = z.object({
  tenantKeyId: uuid,
  confirmation: z.literal("PERMANENTLY_LOSE_TENANT_KEY"),
  reasonCode: keyLossReasonCodeSchema,
}).strict();

export const lifecycleChallengeSchema = z.discriminatedUnion("operation", [
  z.object({ operation: z.literal("device.register"), request: registerDeviceIntentSchema }).strict(),
  z.object({ operation: z.literal("grant.initialize"), request: initializeGrantIntentSchema }).strict(),
  z.object({ operation: z.literal("grant.approve"), request: approveGrantIntentSchema }).strict(),
  z.object({ operation: z.literal("grant.revoke"), request: revokeGrantIntentSchema }).strict(),
  z.object({ operation: z.literal("key.rotate"), request: rotateKeyIntentSchema }).strict(),
  z.object({ operation: z.literal("key.recover"), request: recoverKeyIntentSchema }).strict(),
  z.object({ operation: z.literal("key.declare_lost"), request: declareKeyLostIntentSchema }).strict(),
]);

export const challengedRegisterDeviceSchema = registerDeviceIntentSchema.extend({ challengeId: uuid }).strict();
export const challengedInitializeGrantSchema = initializeGrantIntentSchema.extend({ challengeId: uuid }).strict();
export const challengedApproveGrantSchema = approveGrantIntentSchema.extend({ challengeId: uuid }).strict();
export const challengedRevokeGrantSchema = revokeGrantIntentSchema.extend({ challengeId: uuid }).strict();
export const challengedRotateKeySchema = rotateKeyIntentSchema.extend({ challengeId: uuid }).strict();
export const challengedRecoverKeySchema = recoverKeyIntentSchema.extend({ challengeId: uuid }).strict();
export const challengedDeclareKeyLostSchema = declareKeyLostIntentSchema.extend({ challengeId: uuid }).strict();

export type KeyLifecycleIntent = z.infer<typeof lifecycleChallengeSchema>;
export type TenantKeyGrantEnvelopeInput = z.infer<typeof tenantKeyGrantEnvelopeSchema>;
export type RecoveryAuthorizationInput = z.infer<typeof recoveryAuthorizationSchema>;

export function lifecycleIntentRequestHash(value: unknown): `sha256:${string}` {
  return hashKeyLifecycleRequest(value);
}

export function lifecycleOperationNeedsManager(operation: KeyLifecycleOperation): boolean {
  return operation !== "device.register";
}

export function assertWrappingPublicKey(input: z.infer<typeof wrappingPublicKeySchema>, tenantId: string, deviceId: string): void {
  const expectedRecipient = `tenant:${tenantId}:device:${deviceId}`;
  if (input.recipientId !== expectedRecipient) {
    throw invalidCrypto("DEVICE_RECIPIENT_MISMATCH", "Wrapping public key recipient does not match tenant and device");
  }
  const bytes = decodeCanonicalBase64Url(input.publicKey, "wrapping public key");
  if (bytes.byteLength !== 65 || bytes[0] !== 4) {
    throw invalidCrypto("WRAPPING_PUBLIC_KEY_INVALID", "Wrapping public key must be an uncompressed P-256 point");
  }
  const actual = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (actual !== input.fingerprint) {
    throw invalidCrypto("DEVICE_FINGERPRINT_MISMATCH", "Wrapping public-key fingerprint is invalid");
  }
}

export function assertRecoveryPublicKey(input: z.infer<typeof recoveryPublicKeySchema>): void {
  const bytes = decodeCanonicalBase64Url(input.publicKeySpki, "recovery public key");
  if (bytes.byteLength < 40 || bytes.byteLength > 64) {
    throw invalidCrypto("RECOVERY_PUBLIC_KEY_INVALID", "Recovery public key is not a compact Ed25519 SPKI value");
  }
  const actual = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (actual !== input.fingerprint) {
    throw invalidCrypto("RECOVERY_FINGERPRINT_MISMATCH", "Recovery public-key fingerprint is invalid");
  }
  try {
    const key = createPublicKey({ key: bytes, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519") throw new Error("not Ed25519");
  } catch (error) {
    throw new ApiError(400, "RECOVERY_PUBLIC_KEY_INVALID", "Recovery public key is not valid Ed25519 SPKI", error instanceof Error ? error.message : undefined);
  }
}

export function assertGrantEnvelope(
  envelope: TenantKeyGrantEnvelopeInput,
  expected: {
    readonly tenantId: string;
    readonly tenantKeyId: string;
    readonly generation: number;
    readonly identityId: string;
    readonly deviceId: string;
    readonly deviceFingerprint: string;
  },
): void {
  const expectedRecipient = `tenant:${expected.tenantId}:device:${expected.deviceId}`;
  const aad = envelope.aad;
  if (
    aad.tenantId !== expected.tenantId
    || aad.tenantKeyId !== expected.tenantKeyId
    || aad.generation !== expected.generation
    || aad.identityId !== expected.identityId
    || aad.deviceId !== expected.deviceId
    || aad.deviceFingerprint !== expected.deviceFingerprint
    || envelope.recipientId !== expectedRecipient
    || envelope.recipientFingerprint !== expected.deviceFingerprint
  ) {
    throw invalidCrypto("KEY_GRANT_CONTEXT_MISMATCH", "Wrapped grant is not bound to the exact tenant, generation, identity and device");
  }
  const enc = decodeCanonicalBase64Url(envelope.enc, "HPKE encapsulated key");
  const ciphertext = decodeCanonicalBase64Url(envelope.ciphertext, "HPKE ciphertext");
  if (enc.byteLength !== 65 || enc[0] !== 4 || ciphertext.byteLength !== 48) {
    throw invalidCrypto("KEY_GRANT_ENVELOPE_INVALID", "Wrapped grant has invalid P-256 HPKE lengths");
  }
  const { envelopeHash: _claimedHash, ...body } = envelope;
  const actual = lifecycleIntentRequestHash(body);
  if (actual !== envelope.envelopeHash) {
    throw invalidCrypto("KEY_GRANT_HASH_MISMATCH", "Wrapped grant hash does not match its canonical content");
  }
}

export function assertRecoveryAuthorization(
  recoveryPublicKey: z.infer<typeof recoveryPublicKeySchema>,
  authorization: RecoveryAuthorizationInput,
  expected: Omit<z.infer<typeof recoveryContextSchema>, "purpose" | "schemaVersion">,
): void {
  assertRecoveryPublicKey(recoveryPublicKey);
  const context = authorization.context;
  if (
    context.tenantId !== expected.tenantId
    || context.tenantKeyId !== expected.tenantKeyId
    || context.generation !== expected.generation
    || context.recoveryNonce !== expected.recoveryNonce
    || context.targetIdentityId !== expected.targetIdentityId
    || context.targetDeviceId !== expected.targetDeviceId
    || context.targetDeviceFingerprint !== expected.targetDeviceFingerprint
    || context.envelopeHash !== expected.envelopeHash
    || authorization.recoveryKeyFingerprint !== recoveryPublicKey.fingerprint
  ) {
    throw invalidCrypto("RECOVERY_CONTEXT_MISMATCH", "Recovery signature is not bound to the exact request");
  }
  const signature = decodeCanonicalBase64Url(authorization.signature, "recovery signature");
  if (signature.byteLength !== 64) {
    throw invalidCrypto("RECOVERY_SIGNATURE_INVALID", "Recovery signature has an invalid length");
  }
  try {
    const publicKey = createPublicKey({
      key: decodeCanonicalBase64Url(recoveryPublicKey.publicKeySpki, "recovery public key"),
      format: "der",
      type: "spki",
    });
    if (!verify(null, Buffer.from(stableJson(context)), publicKey, signature)) {
      throw invalidCrypto("RECOVERY_SIGNATURE_INVALID", "Recovery signature is invalid");
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(400, "RECOVERY_SIGNATURE_INVALID", "Recovery signature cannot be verified", error instanceof Error ? error.message : undefined);
  }
}

export function requestWithoutChallenge<T extends { readonly challengeId: string }>(input: T): Omit<T, "challengeId"> {
  const { challengeId: _challengeId, ...request } = input;
  return request;
}

function decodeCanonicalBase64Url(value: string, label: string): Buffer {
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.byteLength === 0 || bytes.toString("base64url") !== value) throw new Error("non-canonical base64url");
    return bytes;
  } catch (error) {
    throw new ApiError(400, "KEY_MATERIAL_INVALID", `${label} is not canonical base64url`, error instanceof Error ? error.message : undefined);
  }
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function invalidCrypto(code: string, message: string): ApiError {
  return new ApiError(400, code, message);
}
