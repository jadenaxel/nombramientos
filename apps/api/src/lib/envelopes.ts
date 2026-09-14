import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { ApiError } from "./errors.js";

const base64url = z.string().min(1).regex(/^[A-Za-z0-9_-]+$/);

export const encryptedEnvelopeSchema = z.object({
  algorithm: z.enum(["AES-256-GCM", "XCHACHA20-POLY1305"]),
  keyId: z.string().min(8).max(160),
  nonce: base64url,
  ciphertext: base64url,
  aad: base64url,
}).superRefine((value, context) => {
  const nonceLength = Buffer.from(value.nonce, "base64url").byteLength;
  const expected = value.algorithm === "AES-256-GCM" ? 12 : 24;
  if (nonceLength !== expected) {
    context.addIssue({ code: "custom", path: ["nonce"], message: `Nonce must contain ${expected} bytes` });
  }
  if (Buffer.from(value.ciphertext, "base64url").byteLength < 16) {
    context.addIssue({ code: "custom", path: ["ciphertext"], message: "Ciphertext is too short" });
  }
});

export type EncryptedEnvelopeInput = z.infer<typeof encryptedEnvelopeSchema>;

export function validateEnvelopeContext(
  envelope: EncryptedEnvelopeInput,
  expected: Readonly<Record<string, unknown>>,
  options: { readonly exact?: boolean } = {},
): void {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(envelope.aad, "base64url").toString("utf8"));
  } catch {
    throw new ApiError(400, "ENVELOPE_CONTEXT_INVALID", "Envelope AAD is not valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, "ENVELOPE_CONTEXT_INVALID", "Envelope AAD context is invalid");
  }
  const record = value as Record<string, unknown>;
  if (options.exact) {
    const actualKeys = Object.keys(record).sort();
    const expectedKeys = Object.keys(expected).sort();
    if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
      throw new ApiError(409, "ENVELOPE_CONTEXT_MISMATCH", "Envelope belongs to a different context", {
        field: "aad",
      });
    }
  }
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (!isDeepStrictEqual(record[key], expectedValue)) {
      throw new ApiError(409, "ENVELOPE_CONTEXT_MISMATCH", "Envelope belongs to a different context", { field: key });
    }
  }
}

/**
 * Verifies the client's canonical full-envelope fingerprint. This protects the
 * opaque envelope from accidental corruption without requiring the server to
 * possess, or ever unwrap, the tenant encryption key.
 */
export function validateEnvelopeContentHash(
  envelope: EncryptedEnvelopeInput,
  expected: string,
): void {
  const canonical = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  const actual = `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
  if (actual !== expected) {
    throw new ApiError(400, "CONTENT_HASH_MISMATCH", "Ciphertext hash does not match");
  }
}
