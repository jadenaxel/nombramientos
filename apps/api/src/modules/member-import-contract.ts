import { z } from "zod";
import { encryptedEnvelopeSchema } from "../lib/envelopes.js";

const uuid = z.string().uuid();
const sha256 = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const safeFileName = z.enum(["roster.csv", "roster.xlsx"]);
const safeSheetName = z.string().regex(/^sheet-sha256:[0-9a-f]{64}$/);
const columnIndex = z.number().int().min(0).max(49);

export const memberImportMappingSchema = z.object({
  sourceId: columnIndex.optional(),
  displayName: columnIndex.optional(),
  firstName: columnIndex.optional(),
  lastName: columnIndex.optional(),
  email: columnIndex.optional(),
  membershipStatus: columnIndex.optional(),
  eligible: columnIndex.optional(),
  visibleReason: columnIndex.optional(),
  photoReference: columnIndex.optional(),
}).strict().superRefine((value, context) => {
  if (value.displayName === undefined && (value.firstName === undefined || value.lastName === undefined)) {
    context.addIssue({
      code: "custom",
      message: "Map displayName or both firstName and lastName",
    });
  }
  const values = Object.values(value);
  if (new Set(values).size !== values.length) {
    context.addIssue({ code: "custom", message: "A source column may be mapped only once" });
  }
});

export const memberImportRowSchema = z.object({
  sourceRow: z.number().int().min(2).max(10_001),
  id: uuid,
  shortId: z.string().trim().min(1).max(64).optional(),
  eligible: z.boolean(),
  decision: z.object({
    action: z.enum(["create", "update", "skip"]),
    matchBasis: z.enum(["none", "stable_id", "email", "normalized_name", "user_selected"]),
  }).strict(),
  expectedVersion: z.number().int().positive().optional(),
  displayEnvelope: encryptedEnvelopeSchema.optional(),
  displayContentHash: sha256.optional(),
  contactEnvelope: encryptedEnvelopeSchema.optional(),
  contactContentHash: sha256.optional(),
}).strict().superRefine((value, context) => {
  const actionable = value.decision.action !== "skip";
  if (actionable && (!value.displayEnvelope || !value.displayContentHash)) {
    context.addIssue({ code: "custom", message: "Create and update rows require an encrypted display identity and content hash" });
  }
  if (Boolean(value.contactEnvelope) !== Boolean(value.contactContentHash)) {
    context.addIssue({ code: "custom", message: "contactEnvelope and contactContentHash must be supplied together" });
  }
  if (!actionable && (value.displayEnvelope || value.displayContentHash || value.contactEnvelope || value.contactContentHash)) {
    context.addIssue({ code: "custom", message: "Skipped rows must not send encrypted member content" });
  }
  if (value.decision.action === "update" && value.expectedVersion === undefined) {
    context.addIssue({ code: "custom", path: ["expectedVersion"], message: "Update rows require expectedVersion" });
  }
  if (value.decision.action !== "update" && value.expectedVersion !== undefined) {
    context.addIssue({ code: "custom", path: ["expectedVersion"], message: "Only update rows may send expectedVersion" });
  }
});

export const memberImportPreviewSchema = z.object({
  sourceFingerprint: sha256,
  sourceFileName: safeFileName.optional(),
  sourceSheetName: safeSheetName,
  columnMapping: memberImportMappingSchema,
  rows: z.array(memberImportRowSchema).min(1).max(10_000),
}).strict();

export const memberImportCommitSchema = z.object({
  importId: uuid,
  expectedRevision: z.number().int().positive(),
}).strict();

export type MemberImportPreviewInput = z.infer<typeof memberImportPreviewSchema>;
