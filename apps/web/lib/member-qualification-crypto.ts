import type {
  Envelope,
  MemberQualificationStatus,
  MemberQualificationType,
} from "./api.ts";
import { decryptJson } from "./crypto-client.ts";

export type QualificationDetails = {
  readonly title?: string;
  readonly issuer?: string;
};

export interface MemberQualificationCryptoContext {
  readonly tenantId: string;
  readonly memberId: string;
  readonly qualificationId: string;
  readonly version: number;
  readonly type: MemberQualificationType;
  readonly status: MemberQualificationStatus;
  readonly effectiveOn: string;
  readonly expiresOn: string | null;
}

export function memberQualificationAad(
  input: MemberQualificationCryptoContext,
): Readonly<Record<string, string | number | null>> {
  return {
    tenantId: input.tenantId,
    memberId: input.memberId,
    qualificationId: input.qualificationId,
    purpose: "member-qualification-details",
    schemaVersion: 1,
    version: input.version,
    type: input.type,
    status: input.status,
    effectiveOn: input.effectiveOn,
    expiresOn: input.expiresOn,
  };
}

export async function openMemberQualificationDetails(input: {
  readonly key: CryptoKey | undefined;
  readonly envelope: Envelope;
  readonly context: MemberQualificationCryptoContext;
}): Promise<QualificationDetails> {
  if (!input.key) throw new Error("QUALIFICATION_KEY_UNAVAILABLE");
  const decrypted = await decryptJson<unknown>(input.key, input.envelope, {
    keyId: input.envelope.keyId,
    aad: memberQualificationAad(input.context),
    exactAad: true,
  });
  return parseQualificationDetails(decrypted);
}

export function parseQualificationDetails(value: unknown): QualificationDetails {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("QUALIFICATION_DETAILS_INVALID");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.some((key) => key !== "title" && key !== "issuer")) {
    throw new Error("QUALIFICATION_DETAILS_INVALID");
  }
  const result: { title?: string; issuer?: string } = {};
  for (const key of ["title", "issuer"] as const) {
    const raw = record[key];
    if (raw === undefined) continue;
    if (typeof raw !== "string") throw new Error("QUALIFICATION_DETAILS_INVALID");
    const normalized = raw.trim();
    if (normalized.length < 1 || normalized.length > 160) {
      throw new Error("QUALIFICATION_DETAILS_INVALID");
    }
    result[key] = normalized;
  }
  return result;
}
