import type { Envelope, KeyGrant } from "./api";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw new Error("El valor cifrado no usa Base64URL canónico.");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (bytesToBase64Url(bytes) !== value) {
    throw new Error("El valor cifrado no usa Base64URL canónico.");
  }
  return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function assertAad(aad: string, expected: Readonly<Record<string, unknown>>, exact = false) {
  const value: unknown = JSON.parse(decoder.decode(base64UrlToBytes(aad)));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("El contexto cifrado no es un objeto válido.");
  }
  const parsed = value as Record<string, unknown>;
  for (const [key, value] of Object.entries(expected)) {
    if (parsed[key] !== value) throw new Error(`El contexto cifrado no coincide (${key}).`);
  }
  if (exact && Object.keys(parsed).length !== Object.keys(expected).length) {
    throw new Error("El contexto cifrado contiene campos inesperados.");
  }
}

export async function unlockTenantKey(password: string, grant: KeyGrant, tenantId: string): Promise<CryptoKey> {
  assertAad(grant.wrap.aad, { tenantId, tenantKeyId: grant.tenantKeyId, purpose: "tenant-key-wrap" });
  const passwordMaterial = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  const wrappingKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: base64UrlToBytes(grant.kdf.salt), iterations: grant.kdf.iterations, hash: grant.kdf.hash },
    passwordMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const rawTenantKey = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(grant.wrap.iv), additionalData: base64UrlToBytes(grant.wrap.aad) },
    wrappingKey,
    base64UrlToBytes(grant.wrap.ciphertext),
  );
  return crypto.subtle.importKey("raw", rawTenantKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function decryptJson<T>(
  key: CryptoKey,
  envelope: Envelope,
  expected?: { keyId?: string; aad?: Readonly<Record<string, unknown>>; exactAad?: boolean },
): Promise<T> {
  if (envelope.algorithm !== "AES-256-GCM") throw new Error("Este dispositivo no admite el formato cifrado recibido.");
  if (expected?.keyId && envelope.keyId !== expected.keyId) throw new Error("La versión de clave no coincide con el contenido.");
  if (expected?.aad) assertAad(envelope.aad, expected.aad, expected.exactAad);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(envelope.nonce), additionalData: base64UrlToBytes(envelope.aad) },
    key,
    base64UrlToBytes(envelope.ciphertext),
  );
  return JSON.parse(decoder.decode(plain)) as T;
}

export async function encryptJson(key: CryptoKey, keyId: string, aad: object, value: unknown): Promise<{ envelope: Envelope; contentHash: string }> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aadBytes = encoder.encode(JSON.stringify(aad));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aadBytes },
    key,
    encoder.encode(JSON.stringify(value)),
  );
  const cipherBytes = new Uint8Array(cipher);
  const envelope: Envelope = {
    algorithm: "AES-256-GCM",
    keyId,
    nonce: bytesToBase64Url(nonce),
    ciphertext: bytesToBase64Url(cipherBytes),
    aad: bytesToBase64Url(aadBytes),
  };
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(JSON.stringify(envelope)));
  return {
    envelope,
    contentHash: `sha256:${Array.from(new Uint8Array(digest)).map((value) => value.toString(16).padStart(2, "0")).join("")}`,
  };
}
