export const API_LOG_REDACTION_PATHS = Object.freeze([
  "req.headers.cookie",
  "req.headers.authorization",
  "req.headers.x-csrf-token",
  "req.headers.x-step-up-grant",
  "req.headers.x-device-proof",
  "req.body",
  "request.body",
  "body",
  "*.body",
  "res.headers.set-cookie",
  "password",
  "*.password",
  "code",
  "*.code",
  "token",
  "*.token",
  "grantToken",
  "*.grantToken",
  "acceptanceToken",
  "*.acceptanceToken",
  "secret",
  "*.secret",
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
  "privateKeyB64",
  "*.privateKeyB64",
  "otpauthUri",
  "*.otpauthUri",
  "recoveryCode",
  "*.recoveryCode",
  "recoveryCodes",
  "*.recoveryCodes",
  "envelope",
  "*.envelope",
  "envelopes",
  "*.envelopes",
  "ciphertext",
  "*.ciphertext",
] as const);

export interface SafeLogError {
  readonly category: "caught-error" | "non-error-thrown";
  readonly statusCode?: number;
}

export interface SerializedSafeLogError extends SafeLogError {
  readonly [key: string]: unknown;
  readonly type: "Error";
  readonly message: "Sensitive diagnostic suppressed";
  readonly stack: "Sensitive diagnostic suppressed";
}

/**
 * Deliberately excludes message, stack, cause, query details, and arbitrary error
 * properties: any of those may contain request plaintext or database values.
 */
export function safeLogError(error: unknown): SafeLogError {
  const category = error instanceof Error ? "caught-error" : "non-error-thrown";
  const statusCode = readSafeStatusCode(error);
  return Object.freeze(statusCode === undefined ? { category } : { category, statusCode });
}

export const API_LOG_SERIALIZERS = Object.freeze({
  err: serializeSafeLogError,
  error: serializeSafeLogError,
});

export function serializeSafeLogError(error: unknown): SerializedSafeLogError {
  return Object.freeze({
    type: "Error",
    message: "Sensitive diagnostic suppressed",
    stack: "Sensitive diagnostic suppressed",
    ...safeLogError(error),
  });
}

function readSafeStatusCode(error: unknown): number | undefined {
  if (typeof error !== "object" || error === null || !("statusCode" in error)) return undefined;
  const value = error.statusCode;
  return typeof value === "number" && Number.isInteger(value) && value >= 400 && value <= 599
    ? value
    : undefined;
}
