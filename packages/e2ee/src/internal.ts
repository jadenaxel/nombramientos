import { E2eeError, type E2eeErrorCode } from "./errors.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(value);
}

export function decodeUtf8(value: ArrayBufferLike | ArrayBufferView): string {
  try {
    const bytes = ArrayBuffer.isView(value)
      ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
      : new Uint8Array(value);
    return decoder.decode(bytes);
  } catch (error) {
    throw new E2eeError("BALLOT_INVALID", "El payload descifrado no es UTF-8 válido.", {
      cause: error,
    });
  }
}

export function getSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new E2eeError(
      "WEBCRYPTO_UNAVAILABLE",
      "Se requiere Web Cryptography API para operar el sobre HPKE.",
    );
  }
  return subtle;
}

function canonicalizeInner(value: unknown, ancestors: Set<object>): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new E2eeError("INVALID_ENVELOPE", "JSON canónico no admite números no finitos.");
      }
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (ancestors.has(value)) {
        throw new E2eeError("INVALID_ENVELOPE", "JSON canónico no admite referencias cíclicas.");
      }
      ancestors.add(value);
      try {
        if (Array.isArray(value)) {
          return `[${value.map((item) => canonicalizeInner(item, ancestors)).join(",")}]`;
        }

        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) {
          throw new E2eeError(
            "INVALID_ENVELOPE",
            "JSON canónico solo admite objetos JSON simples.",
          );
        }

        const object = value as Record<string, unknown>;
        const properties = Object.keys(object)
          .sort()
          .map((key) => {
            const property = object[key];
            if (property === undefined) {
              throw new E2eeError(
                "INVALID_ENVELOPE",
                "JSON canónico no admite propiedades undefined.",
              );
            }
            return `${JSON.stringify(key)}:${canonicalizeInner(property, ancestors)}`;
          });
        return `{${properties.join(",")}}`;
      } finally {
        ancestors.delete(value);
      }
    }
    default:
      throw new E2eeError(
        "INVALID_ENVELOPE",
        "JSON canónico solo admite valores JSON serializables.",
      );
  }
}

export function canonicalize(value: unknown): string {
  return canonicalizeInner(value, new Set<object>());
}

export async function sha256(value: ArrayBufferLike | ArrayBufferView | string): Promise<string> {
  const source = typeof value === "string" ? utf8(value) : value;
  const view = ArrayBuffer.isView(source)
    ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
    : new Uint8Array(source);
  const input = new Uint8Array(view.byteLength);
  input.set(view);
  const digest = await getSubtleCrypto().digest("SHA-256", input);
  const hexadecimal = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return `sha256:${hexadecimal}`;
}

export function encodeBase64Url(value: ArrayBufferLike | ArrayBufferView): string {
  const bytes = ArrayBuffer.isView(value)
    ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64Url(
  value: unknown,
  label: string,
  code: E2eeErrorCode,
  expectedLength?: number,
): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
    throw new E2eeError(code, `${label} no es base64url canónico.`);
  }

  try {
    const padding = "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0)) as Uint8Array<ArrayBuffer>;
    if (encodeBase64Url(bytes) !== value) {
      throw new Error("non-canonical base64url");
    }
    if (expectedLength !== undefined && bytes.byteLength !== expectedLength) {
      throw new Error("unexpected byte length");
    }
    return bytes;
  } catch (error) {
    throw new E2eeError(code, `${label} no es base64url válido o tiene longitud incorrecta.`, {
      cause: error,
    });
  }
}

export function asRecord(value: unknown, label: string, code: E2eeErrorCode): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new E2eeError(code, `${label} debe ser un objeto.`);
  }
  return value as Record<string, unknown>;
}

export function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
  code: E2eeErrorCode,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new E2eeError(code, `${label} contiene campos ausentes o no permitidos.`);
  }
}

export function isSha256Digest(value: unknown): value is `sha256:${string}` {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
}

export function assertRecipientId(value: unknown, code: E2eeErrorCode = "INVALID_RECIPIENT"): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u.test(value)
  ) {
    throw new E2eeError(
      code,
      "recipientId debe tener entre 1 y 128 caracteres seguros y comenzar con alfanumérico.",
    );
  }
  return value;
}
