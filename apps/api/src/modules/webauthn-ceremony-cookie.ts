import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

export const WEBAUTHN_COOKIE_PREFIX = "nom_webauthn_";

export type WebAuthnCeremonyCookieType = "authentication" | "registration" | "step_up";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const COOKIE_PATH = "/v1/auth/passkeys";
const COOKIE_AAD_DOMAIN = "nombramientos-webauthn-ceremony-cookie";
const MAXIMUM_COOKIE_VALUE_LENGTH = 1_024;
const COOKIE_VERSION = "v1";
const EXPIRY_BYTES = 8;
const TOKEN_BYTES = 32;
const PLAINTEXT_BYTES = EXPIRY_BYTES + TOKEN_BYTES;
const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;

export function webAuthnCeremonyCookieName(ceremonyId: string): string {
  return `${WEBAUTHN_COOKIE_PREFIX}${normalizeCeremonyId(ceremonyId).replaceAll("-", "")}`;
}

export function sealWebAuthnCeremonyCookie(input: {
  readonly ceremonyId: string;
  readonly ceremonyType: WebAuthnCeremonyCookieType;
  readonly ceremonyToken: string;
  readonly expiresAt: Date;
  readonly encryptionKey: Uint8Array;
}): string {
  const ceremonyId = normalizeCeremonyId(input.ceremonyId);
  requireEncryptionKey(input.encryptionKey);
  requireCeremonyType(input.ceremonyType);
  const token = canonicalBase64Url(input.ceremonyToken, TOKEN_BYTES);
  if (!token || !TOKEN_PATTERN.test(input.ceremonyToken)) throw new Error("WebAuthn ceremony token is invalid");
  const expiresAt = input.expiresAt.getTime();
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 0) throw new Error("WebAuthn ceremony expiry is invalid");

  const plaintext = Buffer.alloc(PLAINTEXT_BYTES);
  try {
    plaintext.writeBigUInt64BE(BigInt(expiresAt), 0);
    token.copy(plaintext, EXPIRY_BYTES);
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv("aes-256-gcm", input.encryptionKey, nonce);
    cipher.setAAD(cookieAad(ceremonyId, input.ceremonyType));
    const encrypted = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    return `${COOKIE_VERSION}.${nonce.toString("base64url")}.${encrypted.toString("base64url")}`;
  } finally {
    token.fill(0);
    plaintext.fill(0);
  }
}

export function openWebAuthnCeremonyCookie(input: {
  readonly value: string | undefined;
  readonly ceremonyId: string;
  readonly ceremonyType: WebAuthnCeremonyCookieType;
  readonly encryptionKey: Uint8Array;
  readonly now?: number;
}): string | undefined {
  if (!input.value || input.value.length > MAXIMUM_COOKIE_VALUE_LENGTH) return undefined;
  let plaintext: Buffer | undefined;
  try {
    requireEncryptionKey(input.encryptionKey);
    const ceremonyId = normalizeCeremonyId(input.ceremonyId);
    requireCeremonyType(input.ceremonyType);
    const parts = input.value.split(".");
    if (parts.length !== 3 || parts[0] !== COOKIE_VERSION || !parts[1] || !parts[2]) return undefined;
    const nonce = canonicalBase64Url(parts[1], NONCE_BYTES);
    const encrypted = canonicalBase64Url(parts[2]);
    if (!nonce || !encrypted || encrypted.byteLength !== PLAINTEXT_BYTES + AUTH_TAG_BYTES) return undefined;

    const ciphertext = encrypted.subarray(0, -AUTH_TAG_BYTES);
    const authTag = encrypted.subarray(-AUTH_TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", input.encryptionKey, nonce);
    decipher.setAAD(cookieAad(ceremonyId, input.ceremonyType));
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.byteLength !== PLAINTEXT_BYTES) return undefined;
    const expiry = plaintext.readBigUInt64BE(0);
    const now = input.now ?? Date.now();
    if (!Number.isSafeInteger(now) || now < 0) return undefined;
    if (expiry > BigInt(Number.MAX_SAFE_INTEGER) || Number(expiry) <= now) return undefined;
    const token = plaintext.subarray(EXPIRY_BYTES).toString("base64url");
    if (!TOKEN_PATTERN.test(token)) return undefined;
    return token;
  } catch {
    // Cookie parsing, authentication, correlation, and expiry all fail closed
    // behind the same public ceremony error at the route boundary.
    return undefined;
  } finally {
    plaintext?.fill(0);
  }
}

export function webAuthnCeremonyCookiePath(): string {
  return COOKIE_PATH;
}

function normalizeCeremonyId(value: string): string {
  const normalized = value.toLowerCase();
  if (!UUID_PATTERN.test(normalized)) throw new Error("WebAuthn ceremony identifier is invalid");
  return normalized;
}

function requireEncryptionKey(key: Uint8Array): void {
  if (key.byteLength !== 32) throw new Error("WebAuthn cookie encryption key must contain exactly 32 bytes");
}

function requireCeremonyType(value: string): asserts value is WebAuthnCeremonyCookieType {
  if (!["authentication", "registration", "step_up"].includes(value)) {
    throw new Error("WebAuthn ceremony type is invalid");
  }
}

function canonicalBase64Url(value: string, expectedLength?: number): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) return undefined;
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) return undefined;
  if (expectedLength !== undefined && decoded.byteLength !== expectedLength) return undefined;
  return decoded;
}

function cookieAad(ceremonyId: string, ceremonyType: WebAuthnCeremonyCookieType): Buffer {
  return Buffer.from(`${COOKIE_AAD_DOMAIN}:${COOKIE_VERSION}:${ceremonyId}:${ceremonyType}`, "utf8");
}
