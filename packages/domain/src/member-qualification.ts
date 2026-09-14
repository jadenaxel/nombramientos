export const MEMBER_QUALIFICATION_TYPES = [
  "training",
  "ordination",
  "certification",
  "other",
] as const;

export type MemberQualificationType = (typeof MEMBER_QUALIFICATION_TYPES)[number];

export const MEMBER_QUALIFICATION_STATUSES = [
  "pending",
  "verified",
  "expired",
  "revoked",
] as const;

export type MemberQualificationStatus = (typeof MEMBER_QUALIFICATION_STATUSES)[number];

/**
 * Qualification records are documentary evidence only. They deliberately do
 * not implement or imply a denominational eligibility rule.
 */
export interface MemberQualificationVersion {
  readonly qualificationId: string;
  readonly memberId: string;
  readonly version: number;
  readonly type: MemberQualificationType;
  readonly status: MemberQualificationStatus;
  readonly effectiveOn: string;
  readonly expiresOn: string | null;
  readonly reviewerIdentityId: string;
  readonly recordedAt: string;
}

