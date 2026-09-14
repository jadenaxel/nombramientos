import type { Envelope } from "./api.ts";
import { decryptJson } from "./crypto-client.ts";

export const PRIVATE_NOTE_READ_PERMISSION = "private-note.read" as const;

export type MemberEligibilityReview = {
  readonly schema?: "nombramientos-member-eligibility/v1";
  readonly note?: string;
  readonly departmentRestriction?: string;
  readonly validUntil?: string;
  readonly reviewedByIdentityId?: string;
  readonly reviewedAt?: string;
  readonly legacyVisibleReason?: string;
};

type RevealEligibilityReviewInput = {
  readonly permissions: readonly string[];
  readonly key: CryptoKey;
  readonly keyId?: string;
  readonly tenantId: string;
  readonly memberId: string;
  readonly eligibilityEnvelope?: Envelope;
};

export async function revealMemberEligibilityReview(
  input: RevealEligibilityReviewInput,
): Promise<MemberEligibilityReview | undefined> {
  if (!input.permissions.includes(PRIVATE_NOTE_READ_PERMISSION) || !input.eligibilityEnvelope) return undefined;
  const plaintext = await decryptJson<unknown>(input.key, input.eligibilityEnvelope, {
    keyId: input.keyId,
    aad: {
      tenantId: input.tenantId,
      memberId: input.memberId,
      purpose: "member-eligibility",
      schemaVersion: 1,
    },
    exactAad: true,
  });
  return parseMemberEligibilityReview(plaintext);
}

export function parseMemberEligibilityReview(value: unknown): MemberEligibilityReview {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The encrypted eligibility review has an invalid structure.");
  }
  const record = value as Record<string, unknown>;
  const allowedKeys = new Set([
    "schema",
    "note",
    "departmentRestriction",
    "validUntil",
    "reviewedByIdentityId",
    "reviewedAt",
    "visibleReason",
    "synthetic",
  ]);
  if (Object.keys(record).some((key) => !allowedKeys.has(key))) {
    throw new Error("The encrypted eligibility review contains unexpected fields.");
  }
  if (record["schema"] !== undefined && record["schema"] !== "nombramientos-member-eligibility/v1") {
    throw new Error("The encrypted eligibility review uses an unsupported schema.");
  }
  if (record["synthetic"] !== undefined && typeof record["synthetic"] !== "boolean") {
    throw new Error("The encrypted eligibility review has invalid fixture metadata.");
  }

  const note = optionalString(record, "note", 500);
  const departmentRestriction = optionalString(record, "departmentRestriction", 160);
  const legacyVisibleReason = optionalString(record, "visibleReason", 240);
  const validUntil = optionalString(record, "validUntil", 10);
  if (validUntil && !isCalendarDate(validUntil)) {
    throw new Error("The encrypted eligibility review has an invalid validity date.");
  }
  const reviewedByIdentityId = optionalString(record, "reviewedByIdentityId", 36);
  if (reviewedByIdentityId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(reviewedByIdentityId)) {
    throw new Error("The encrypted eligibility review has an invalid reviewer identifier.");
  }
  const reviewedAt = optionalString(record, "reviewedAt", 40);
  if (reviewedAt && Number.isNaN(Date.parse(reviewedAt))) {
    throw new Error("The encrypted eligibility review has an invalid review timestamp.");
  }

  return {
    ...(record["schema"] === "nombramientos-member-eligibility/v1" ? { schema: record["schema"] } : {}),
    ...(note ? { note } : {}),
    ...(departmentRestriction ? { departmentRestriction } : {}),
    ...(validUntil ? { validUntil } : {}),
    ...(reviewedByIdentityId ? { reviewedByIdentityId } : {}),
    ...(reviewedAt ? { reviewedAt } : {}),
    ...(legacyVisibleReason ? { legacyVisibleReason } : {}),
  };
}

function optionalString(record: Readonly<Record<string, unknown>>, key: string, maximumLength: number): string | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new Error(`The encrypted eligibility review has an invalid ${key} field.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maximumLength) {
    throw new Error(`The encrypted eligibility review has an invalid ${key} field.`);
  }
  return normalized;
}

function isCalendarDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}
