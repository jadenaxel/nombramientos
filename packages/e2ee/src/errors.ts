export type E2eeErrorCode =
  | "AAD_MISMATCH"
  | "BALLOT_INVALID"
  | "CONTEXT_HASH_MISMATCH"
  | "DECRYPTION_FAILED"
  | "DUPLICATE_RECIPIENT"
  | "ENCRYPTION_FAILED"
  | "ENVELOPE_HASH_MISMATCH"
  | "INVALID_AAD"
  | "INVALID_ENVELOPE"
  | "INVALID_KEY"
  | "INVALID_RECIPIENT"
  | "KEY_BACKUP_DECRYPTION_FAILED"
  | "KEY_BACKUP_INVALID"
  | "KEY_FINGERPRINT_MISMATCH"
  | "KEY_PAIR_MISMATCH"
  | "RECIPIENT_NOT_FOUND"
  | "SIGNATURE_INVALID"
  | "TALLY_INVALID"
  | "WEBCRYPTO_UNAVAILABLE";

export class E2eeError extends Error {
  readonly code: E2eeErrorCode;

  constructor(code: E2eeErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "E2eeError";
    this.code = code;
  }
}
