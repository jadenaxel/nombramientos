const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CIVIL_DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;

export interface MemberEligibilityScope {
  /** Null means that no department-specific limitation applies. */
  readonly departmentRestriction: string | null;
  /** Inclusive tenant civil date. Null means that eligibility does not expire automatically. */
  readonly validUntil: string | null;
}

export interface MemberEligibilityContext extends MemberEligibilityScope {
  readonly eligibilityStatus: "eligible" | "ineligible" | "review" | string;
  readonly available: boolean;
  readonly archived: boolean;
  readonly evaluatedOn: string;
  readonly officeDepartmentId: string | null;
  /** False when a referenced department no longer exists or is inactive. */
  readonly restrictionDepartmentActive?: boolean;
}

export const MEMBER_ELIGIBILITY_REASONS = [
  "ELIGIBLE",
  "MEMBER_ARCHIVED",
  "STATUS_NOT_ELIGIBLE",
  "MEMBER_UNAVAILABLE",
  "ELIGIBILITY_EXPIRED",
  "DEPARTMENT_RESTRICTED",
  "INVALID_ELIGIBILITY_SCOPE",
] as const;

export type MemberEligibilityReason = (typeof MEMBER_ELIGIBILITY_REASONS)[number];

export interface MemberEligibilityDecision {
  readonly eligible: boolean;
  readonly reason: MemberEligibilityReason;
}

/**
 * Validates a canonical Gregorian civil date without applying a host timezone.
 * This deliberately accepts only the wire/database YYYY-MM-DD representation.
 */
export function isCanonicalCivilDate(value: string): boolean {
  const match = CIVIL_DATE_PATTERN.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!Number.isSafeInteger(year) || year < 1 || year > 9999
      || !Number.isSafeInteger(month) || month < 1 || month > 12
      || !Number.isSafeInteger(day) || day < 1 || day > 31) return false;
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= (daysInMonth[month - 1] ?? 0);
}

/**
 * Evaluates operational eligibility for one office. It never consumes private
 * notes or ciphertext, and invalid structured data fails closed.
 */
export function evaluateMemberEligibilityForOffice(
  context: MemberEligibilityContext,
): MemberEligibilityDecision {
  if (!isCanonicalCivilDate(context.evaluatedOn)
      || (context.validUntil !== null && !isCanonicalCivilDate(context.validUntil))
      || (context.departmentRestriction !== null && !UUID_PATTERN.test(context.departmentRestriction))
      || (context.officeDepartmentId !== null && !UUID_PATTERN.test(context.officeDepartmentId))) {
    return Object.freeze({ eligible: false, reason: "INVALID_ELIGIBILITY_SCOPE" });
  }
  if (context.archived) return Object.freeze({ eligible: false, reason: "MEMBER_ARCHIVED" });
  if (context.eligibilityStatus !== "eligible") {
    return Object.freeze({ eligible: false, reason: "STATUS_NOT_ELIGIBLE" });
  }
  if (!context.available) return Object.freeze({ eligible: false, reason: "MEMBER_UNAVAILABLE" });
  if (context.validUntil !== null && context.validUntil < context.evaluatedOn) {
    return Object.freeze({ eligible: false, reason: "ELIGIBILITY_EXPIRED" });
  }
  if (context.departmentRestriction !== null
      && (context.restrictionDepartmentActive !== true
        || context.officeDepartmentId !== context.departmentRestriction)) {
    return Object.freeze({ eligible: false, reason: "DEPARTMENT_RESTRICTED" });
  }
  return Object.freeze({ eligible: true, reason: "ELIGIBLE" });
}
