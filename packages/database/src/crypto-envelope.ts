import {
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";
import type { EncryptedEnvelope } from "./types.js";

export interface WrappedTenantKey {
  readonly kdf: {
    readonly name: "PBKDF2";
    readonly salt: string;
    readonly iterations: number;
    readonly hash: "SHA-256";
  };
  readonly wrap: {
    readonly algorithm: "AES-GCM";
    readonly iv: string;
    readonly ciphertext: string;
    readonly aad: string;
  };
}

export function sealAesGcmJson(
  value: unknown,
  key: Uint8Array,
  keyId: string,
  context: Readonly<Record<string, unknown>>,
): EncryptedEnvelope {
  requireKey(key);
  const iv = randomBytes(12);
  const aad = Buffer.from(stableJson(context), "utf8");
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return {
    algorithm: "AES-256-GCM",
    keyId,
    nonce: iv.toString("base64url"),
    ciphertext: encrypted.toString("base64url"),
    aad: aad.toString("base64url"),
  };
}

export function wrapTenantKeyWithPassword(
  tenantKey: Uint8Array,
  password: string,
  context: Readonly<Record<string, unknown>>,
): WrappedTenantKey {
  requireKey(tenantKey);
  if (password.length < 16) throw new Error("Bootstrap password must contain at least 16 characters");
  const salt = randomBytes(16);
  const iterations = 310_000;
  const wrappingKey = pbkdf2Sync(password, salt, iterations, 32, "sha256");
  const iv = randomBytes(12);
  const aad = Buffer.from(stableJson(context), "utf8");
  const cipher = createCipheriv("aes-256-gcm", wrappingKey, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([
    cipher.update(tenantKey),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  wrappingKey.fill(0);
  return {
    kdf: {
      name: "PBKDF2",
      salt: salt.toString("base64url"),
      iterations,
      hash: "SHA-256",
    },
    wrap: {
      algorithm: "AES-GCM",
      iv: iv.toString("base64url"),
      ciphertext: encrypted.toString("base64url"),
      aad: aad.toString("base64url"),
    },
  };
}

export function unwrapTenantKeyWithPassword(
  wrapped: WrappedTenantKey,
  password: string,
): Buffer {
  if (
    wrapped.kdf.name !== "PBKDF2" ||
    wrapped.kdf.hash !== "SHA-256" ||
    !Number.isSafeInteger(wrapped.kdf.iterations) ||
    wrapped.kdf.iterations < 100_000 ||
    wrapped.wrap.algorithm !== "AES-GCM"
  ) {
    throw new Error("Unsupported tenant-key wrapping parameters");
  }
  const salt = Buffer.from(wrapped.kdf.salt, "base64url");
  const iv = Buffer.from(wrapped.wrap.iv, "base64url");
  const encrypted = Buffer.from(wrapped.wrap.ciphertext, "base64url");
  if (salt.byteLength < 16 || iv.byteLength !== 12 || encrypted.byteLength !== 48) {
    throw new Error("Invalid tenant-key wrapping payload");
  }
  const ciphertext = encrypted.subarray(0, -16);
  const tag = encrypted.subarray(-16);
  const wrappingKey = pbkdf2Sync(password, salt, wrapped.kdf.iterations, 32, "sha256");
  try {
    const decipher = createDecipheriv("aes-256-gcm", wrappingKey, iv);
    decipher.setAAD(Buffer.from(wrapped.wrap.aad, "base64url"));
    decipher.setAuthTag(tag);
    const tenantKey = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    requireKey(tenantKey);
    return tenantKey;
  } finally {
    wrappingKey.fill(0);
  }
}

export function encryptServerSecret(secret: string, key: Uint8Array): string {
  requireKey(key);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from("nombramientos-auth-secret:v1", "utf8"));
  const encrypted = Buffer.concat([
    cipher.update(secret, "utf8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return `v1.${iv.toString("base64url")}.${encrypted.toString("base64url")}`;
}

export function decryptServerSecret(payload: string, key: Uint8Array): string {
  requireKey(key);
  const [version, ivText, encryptedText] = payload.split(".");
  if (version !== "v1" || !ivText || !encryptedText) throw new Error("Invalid encrypted server secret");
  const encrypted = Buffer.from(encryptedText, "base64url");
  if (encrypted.byteLength < 17) throw new Error("Invalid encrypted server secret length");
  const ciphertext = encrypted.subarray(0, -16);
  const tag = encrypted.subarray(-16);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivText, "base64url"));
  decipher.setAAD(Buffer.from("nombramientos-auth-secret:v1", "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

export function generateSecretKey(): Buffer {
  return randomBytes(32);
}

function requireKey(key: Uint8Array): void {
  if (key.byteLength !== 32) throw new Error("AES-256 key must contain exactly 32 bytes");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}
