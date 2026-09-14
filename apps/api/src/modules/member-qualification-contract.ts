import {
  MEMBER_QUALIFICATION_STATUSES,
  MEMBER_QUALIFICATION_TYPES,
} from "@nombramientos/database";
import { z } from "zod";
import { encryptedEnvelopeSchema } from "../lib/envelopes.js";

const uuid = z.string().uuid();
const sha256 = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const civilDate = z.string().date();

const qualificationFields = {
  type: z.enum(MEMBER_QUALIFICATION_TYPES),
  status: z.enum(MEMBER_QUALIFICATION_STATUSES),
  effectiveOn: civilDate,
  expiresOn: civilDate.nullable().default(null),
  detailsEnvelope: encryptedEnvelopeSchema.nullable().default(null),
  detailsContentHash: sha256.nullable().default(null),
} as const;

export const memberQualificationCreateSchema = z.object({
  qualificationId: uuid,
  ...qualificationFields,
}).strict().superRefine(validateQualificationFields);

export const memberQualificationRevisionSchema = z.object({
  expectedVersion: z.number().int().positive(),
  ...qualificationFields,
}).strict().superRefine(validateQualificationFields);

type QualificationFields = {
  readonly status: (typeof MEMBER_QUALIFICATION_STATUSES)[number];
  readonly effectiveOn: string;
  readonly expiresOn: string | null;
  readonly detailsEnvelope: z.infer<typeof encryptedEnvelopeSchema> | null;
  readonly detailsContentHash: string | null;
};

function validateQualificationFields(value: QualificationFields, context: z.RefinementCtx): void {
  if (Boolean(value.detailsEnvelope) !== Boolean(value.detailsContentHash)) {
    context.addIssue({
      code: "custom",
      path: [value.detailsEnvelope ? "detailsContentHash" : "detailsEnvelope"],
      message: "detailsEnvelope and detailsContentHash must be supplied together",
    });
  }
  if (value.detailsEnvelope) {
    if (value.detailsEnvelope.algorithm !== "AES-256-GCM") {
      context.addIssue({
        code: "custom",
        path: ["detailsEnvelope", "algorithm"],
        message: "Qualification details require AES-256-GCM",
      });
    }
    if (Buffer.from(value.detailsEnvelope.ciphertext, "base64url").byteLength > 2_048) {
      context.addIssue({
        code: "custom",
        path: ["detailsEnvelope", "ciphertext"],
        message: "Encrypted qualification details are too large",
      });
    }
  }
  if (value.expiresOn && value.expiresOn < value.effectiveOn) {
    context.addIssue({
      code: "custom",
      path: ["expiresOn"],
      message: "Expiration date cannot precede the effective date",
    });
  }
  if (value.status === "expired" && !value.expiresOn) {
    context.addIssue({
      code: "custom",
      path: ["expiresOn"],
      message: "Expired qualifications require an expiration date",
    });
  }
}

export function memberQualificationAadContext(input: {
  readonly tenantId: string;
  readonly memberId: string;
  readonly qualificationId: string;
  readonly version: number;
  readonly type: (typeof MEMBER_QUALIFICATION_TYPES)[number];
  readonly status: (typeof MEMBER_QUALIFICATION_STATUSES)[number];
  readonly effectiveOn: string;
  readonly expiresOn: string | null;
}): Readonly<Record<string, string | number | null>> {
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
