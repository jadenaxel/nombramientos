export const DOMAIN_ERROR_CODES = [
  "INVALID_STATE_TRANSITION",
  "PERMISSION_DENIED",
  "INVALID_PERMISSION",
  "PERMISSION_ESCALATION",
  "ROUND_NOT_OPEN",
  "ELECTOR_NOT_REQUIRED",
  "INVALID_SELECTION_LIMIT",
  "DUPLICATE_CANDIDATE",
  "CANDIDATE_NOT_ALLOWED",
  "ABSTENTION_WITH_SELECTION",
  "EMPTY_SELECTION",
  "DUPLICATE_RESPONSE",
  "INVALID_RULE",
  "INVALID_METRIC_INPUT",
  "CONSENT_REQUIRED",
  "INVALID_CONGREGATIONAL_DECISION",
  "INVALID_SNAPSHOT",
  "FIXTURE_INVARIANT"
] as const;

export type DomainErrorCode = (typeof DOMAIN_ERROR_CODES)[number];

export class DomainError extends Error {
  public override readonly name = "DomainError";

  public constructor(
    public readonly code: DomainErrorCode,
    message: string,
    public readonly details: Readonly<Record<string, unknown>> = {}
  ) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function invariant(
  condition: unknown,
  code: DomainErrorCode,
  message: string,
  details: Readonly<Record<string, unknown>> = {}
): asserts condition {
  if (!condition) {
    throw new DomainError(code, message, details);
  }
}
