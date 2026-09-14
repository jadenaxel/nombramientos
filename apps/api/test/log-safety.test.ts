import { describe, expect, it } from "vitest";
import { API_LOG_REDACTION_PATHS, API_LOG_SERIALIZERS, safeLogError } from "../src/lib/log-safety.js";

describe("AC-31 API log boundary", () => {
  it("projects an unexpected error to non-sensitive operational metadata only", () => {
    const canary = "AC31_LOG_E2EE_PLAINTEXT_MUST_NOT_ESCAPE";
    const error = Object.assign(new Error(canary, { cause: { envelope: canary } }), {
      name: canary,
      stack: canary,
      code: canary,
      statusCode: 503,
      detail: canary,
      query: canary,
      parameters: [canary],
      body: { privateNote: canary },
      envelope: { ciphertext: canary },
    });

    const projected = safeLogError(error);

    expect(projected).toEqual({ category: "caught-error", statusCode: 503 });
    expect(JSON.stringify(projected)).not.toContain(canary);
  });

  it("does not reflect arbitrary thrown values or invalid status fields", () => {
    const canary = "AC31_NON_ERROR_SECRET";

    expect(safeLogError({ message: canary, statusCode: 200, ciphertext: canary }))
      .toEqual({ category: "non-error-thrown" });
    expect(safeLogError({ message: canary, statusCode: canary }))
      .toEqual({ category: "non-error-thrown" });
  });

  it("sanitizes both conventional Pino error fields before serialization", () => {
    const canary = "AC31_PINO_SERIALIZER_SECRET";
    const error = Object.assign(new Error(canary), { stack: canary, detail: canary });

    expect(API_LOG_SERIALIZERS.err(error)).toEqual({
      type: "Error",
      message: "Sensitive diagnostic suppressed",
      stack: "Sensitive diagnostic suppressed",
      category: "caught-error",
    });
    expect(API_LOG_SERIALIZERS.error(error)).toEqual({
      type: "Error",
      message: "Sensitive diagnostic suppressed",
      stack: "Sensitive diagnostic suppressed",
      category: "caught-error",
    });
    expect(JSON.stringify({
      err: API_LOG_SERIALIZERS.err(error),
      error: API_LOG_SERIALIZERS.error(error),
    })).not.toContain(canary);
  });

  it("redacts full request bodies, E2EE envelopes, ciphertext, and ordinary key material", () => {
    expect(API_LOG_REDACTION_PATHS).toEqual(expect.arrayContaining([
      "req.headers.cookie",
      "req.headers.authorization",
      "req.body",
      "body",
      "*.body",
      "envelope",
      "*.envelope",
      "ciphertext",
      "*.ciphertext",
      "secretMasterKey",
      "*.secretMasterKey",
      "authEncryptionKey",
      "*.authEncryptionKey",
      "backupKey",
      "*.backupKey",
      "keyB64",
      "*.keyB64",
      "privateKey",
      "*.privateKey",
    ]));
  });
});
