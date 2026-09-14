import {
  CANDIDACY_REVIEW_REASON_CODE_BY_STATE,
  ELIGIBILITY_PAUSE_REASON_CODE_BY_RESOLUTION,
  OFFICE_PROCESS_APPLICABILITY_REASON_CODE_BY_ENABLED,
  SESSION_DECISION_CODES_BY_OUTCOME,
} from "@nombramientos/database";
import { z } from "zod";
import {
  assignmentFinalizationReasonCodeSchema,
  assignmentSubstitutionReasonCodeSchema,
  candidacyReviewReasonCodeSchema,
  eligibilityPauseReasonCodeSchema,
  officeProcessApplicabilityReasonCodeSchema,
  roundCloseReasonCodeSchema,
  sessionDecisionCodeSchema,
} from "../lib/reason-code.js";
import { encryptedEnvelopeSchema } from "../lib/envelopes.js";
import { REPORT_TYPES } from "../lib/report-policy.js";
import { ianaTimezoneSchema } from "../lib/timezone.js";

export const workflowUuidSchema = z.string().uuid();
export const workflowVersionSchema = z.number().int().positive();
export const workflowHashSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/);

const localeSchema = z.enum(["es", "en", "fr"]);
const dateSchema = z.string().date();

export const cycleBodySchema = z.object({
  name: z.string().trim().min(2).max(160),
  locale: localeSchema,
  timezone: ianaTimezoneSchema,
  jurisdiction: z.string().trim().min(2).max(160),
  termStart: dateSchema,
  termEnd: dateSchema,
  normativeVersion: z.string().trim().min(1).max(120),
  configuration: z.record(z.unknown()).default({}),
}).strict().superRefine((value, context) => {
  if (value.termEnd < value.termStart) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["termEnd"], message: "termEnd must be on or after termStart" });
  }
});

export const expectedCycleVersionSchema = z.object({
  expectedVersion: workflowVersionSchema,
}).strict();

export const sessionBodySchema = z.object({
  sessionId: workflowUuidSchema,
  expectedCycleVersion: workflowVersionSchema,
  sequence: z.number().int().positive().max(10_000),
  titleEnvelope: encryptedEnvelopeSchema,
  titleContentHash: workflowHashSchema,
  startsAt: z.string().datetime({ offset: true }),
  endsAt: z.string().datetime({ offset: true }),
  locationEnvelope: encryptedEnvelopeSchema.nullable().optional(),
}).strict().superRefine((value, context) => {
  if (Date.parse(value.endsAt) <= Date.parse(value.startsAt)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["endsAt"], message: "endsAt must follow startsAt" });
  }
});

export const sessionTransitionBodySchema = z.object({ expectedVersion: workflowVersionSchema }).strict();

export const sessionUpdateBodySchema = z.object({
  expectedVersion: workflowVersionSchema,
  titleEnvelope: encryptedEnvelopeSchema.optional(),
  titleContentHash: workflowHashSchema.optional(),
  startsAt: z.string().datetime({ offset: true }).optional(),
  endsAt: z.string().datetime({ offset: true }).optional(),
  locationEnvelope: encryptedEnvelopeSchema.nullable().optional(),
}).strict().superRefine((value, context) => {
  if ((value.titleEnvelope === undefined) !== (value.titleContentHash === undefined)) {
    context.addIssue({ code: "custom", path: [value.titleEnvelope === undefined ? "titleEnvelope" : "titleContentHash"], message: "Encrypted title and hash must be supplied together" });
  }
  if (value.titleEnvelope === undefined && value.startsAt === undefined && value.endsAt === undefined && value.locationEnvelope === undefined) {
    context.addIssue({ code: "custom", message: "At least one session field must change" });
  }
  if (value.startsAt && value.endsAt && Date.parse(value.endsAt) <= Date.parse(value.startsAt)) {
    context.addIssue({ code: "custom", path: ["endsAt"], message: "endsAt must follow startsAt" });
  }
});

export const sessionAttendanceBodySchema = z.object({
  expectedVersion: z.number().int().nonnegative(),
  memberId: workflowUuidSchema.nullable().optional(),
  presenceStatus: z.enum(["PRESENT", "REMOTE", "ABSENT", "EXCUSED"]),
  advisory: z.boolean(),
  votingRight: z.boolean(),
  substituteForIdentityId: workflowUuidSchema.nullable().optional(),
}).strict().superRefine((value, context) => {
  if (value.advisory && value.votingRight) context.addIssue({ code: "custom", path: ["votingRight"], message: "Advisors cannot vote" });
  if (["ABSENT", "EXCUSED"].includes(value.presenceStatus) && value.votingRight) {
    context.addIssue({ code: "custom", path: ["votingRight"], message: "Absent participants cannot vote" });
  }
  if (value.substituteForIdentityId && (!["PRESENT", "REMOTE"].includes(value.presenceStatus) || value.advisory)) {
    context.addIssue({ code: "custom", path: ["substituteForIdentityId"], message: "A substitute must be present or remote and cannot be advisory" });
  }
});

export const sessionAgendaCreateBodySchema = z.object({
  expectedSessionVersion: workflowVersionSchema,
  itemId: workflowUuidSchema,
  position: z.number().int().positive().max(10_000),
  titleEnvelope: encryptedEnvelopeSchema,
  titleContentHash: workflowHashSchema,
  processId: workflowUuidSchema.nullable().optional(),
  notesEnvelope: encryptedEnvelopeSchema.nullable().optional(),
}).strict();

export const sessionAgendaOrderBodySchema = z.object({
  expectedSessionVersion: workflowVersionSchema,
  itemIds: z.array(workflowUuidSchema).min(1).max(500),
}).strict().superRefine((value, context) => {
  if (new Set(value.itemIds).size !== value.itemIds.length) {
    context.addIssue({ code: "custom", path: ["itemIds"], message: "Agenda item ids must be unique" });
  }
});

export const sessionDecisionBodySchema = z.object({
  expectedSessionVersion: workflowVersionSchema,
  agendaItemId: workflowUuidSchema,
  decisionCode: sessionDecisionCodeSchema,
  outcome: z.enum(["APPROVED", "REJECTED", "DEFERRED", "RECORDED"]),
  evidenceEnvelope: encryptedEnvelopeSchema.nullable().optional(),
}).strict().superRefine((value, context) => {
  if (!(SESSION_DECISION_CODES_BY_OUTCOME[value.outcome] as readonly string[]).includes(value.decisionCode)) {
    context.addIssue({ code: "custom", path: ["decisionCode"], message: "Decision code must match the selected outcome" });
  }
});

export const sessionListQuerySchema = z.object({
  status: z.enum(["scheduled", "in_progress", "closed", "cancelled"]).optional(),
  sessionId: workflowUuidSchema.optional(),
}).strict();

export const committeeBodySchema = z.object({
  expectedCycleVersion: workflowVersionSchema,
  members: z.array(z.object({
    identityId: workflowUuidSchema,
    memberId: workflowUuidSchema.nullable().optional(),
    displayEnvelope: encryptedEnvelopeSchema,
    roleCode: z.enum(["chair", "pastor", "secretary", "member", "custodian", "advisor"]),
    votingRight: z.boolean(),
    pastoralCapacity: z.boolean(),
  }).strict()).min(2).max(100),
}).strict();

export const electorateBodySchema = z.object({
  expectedCycleVersion: workflowVersionSchema,
  electors: z.array(z.object({
    identityId: workflowUuidSchema,
    canPropose: z.boolean(),
    canVote: z.boolean(),
    recused: z.boolean(),
  }).strict()).min(1).max(500),
}).strict();

export const decisionRuleSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("PLURALITY") }).strict(),
  z.object({
    kind: z.literal("STRICT_MAJORITY"),
    threshold: z.number().min(0.5).max(0.9999999999999999),
    denominator: z.enum(["NON_ABSTAINING_BALLOTS", "ALL_RECEIVED_BALLOTS"]),
  }).strict(),
]);

export const vacancyProcessBodySchema = z.object({
  expectedCycleVersion: workflowVersionSchema,
  officeId: workflowUuidSchema,
  vacancyCount: z.number().int().positive().max(100),
  maxProposalSelections: z.number().int().positive().max(100),
  maxBallotSelections: z.number().int().positive().max(100),
  decisionRule: decisionRuleSchema,
  abstentionRule: z.enum(["EXCLUDED_FROM_CANDIDATE_TOTALS", "INCLUDED_IN_ALL_RECEIVED_DENOMINATOR"]),
  tiebreakPolicy: z.enum(["NEW_BALLOT_ROUND", "DOCUMENTED_HUMAN_RESOLUTION"]),
  quorumRule: z.object({ kind: z.literal("ALL_REQUIRED") }).strict(),
  aggregateAudience: z.enum(["committee", "auditor", "church_after_publication"]),
  agendaOrder: z.number().int().positive().max(10_000),
}).strict();

export const officeProcessApplicabilityBodySchema = z.object({
  expectedCycleVersion: workflowVersionSchema,
  expectedProcessVersion: workflowVersionSchema,
  enabled: z.boolean(),
  reasonCode: officeProcessApplicabilityReasonCodeSchema,
}).strict().superRefine((value, context) => {
  if (value.reasonCode !== OFFICE_PROCESS_APPLICABILITY_REASON_CODE_BY_ENABLED[String(value.enabled) as "true" | "false"]) {
    context.addIssue({ code: "custom", path: ["reasonCode"], message: "Reason code must match the requested applicability state" });
  }
});

export const prepareRoundBodySchema = z.object({
  expectedProcessVersion: workflowVersionSchema,
}).strict();

export const transitionRoundBodySchema = z.object({
  expectedRoundVersion: workflowVersionSchema,
  expectedProcessVersion: workflowVersionSchema,
}).strict();

export const eligibilityPauseResolutionBodySchema = z.object({
  expectedProcessVersion: workflowVersionSchema,
  expectedRoundVersion: workflowVersionSchema.nullable().optional(),
  expectedPauseIds: z.array(workflowUuidSchema).min(1).max(100),
  resolutionCode: z.enum(["ANNUL_AND_RESTART", "RESUME_UNCHANGED", "EXCLUDE_AND_REVIEW", "CLOSE_AFTER_REPLACEMENT"]),
  reasonCode: eligibilityPauseReasonCodeSchema,
  evidenceEnvelope: encryptedEnvelopeSchema,
}).strict().superRefine((value, context) => {
  if (new Set(value.expectedPauseIds).size !== value.expectedPauseIds.length) {
    context.addIssue({ code: "custom", path: ["expectedPauseIds"], message: "Eligibility pause ids must be unique" });
  }
  if (value.reasonCode !== ELIGIBILITY_PAUSE_REASON_CODE_BY_RESOLUTION[value.resolutionCode]) {
    context.addIssue({ code: "custom", path: ["reasonCode"], message: "Reason code must match the selected eligibility resolution" });
  }
});

export const tiebreakRoundBodySchema = z.object({
  expectedProcessVersion: workflowVersionSchema,
  sourceRoundId: workflowUuidSchema,
  expectedAggregateHash: workflowHashSchema,
}).strict();

export const closeWorkflowRoundBodySchema = transitionRoundBodySchema.extend({
  reasonCode: roundCloseReasonCodeSchema,
}).strict();

export const proposalManifestBodySchema = z.object({
  expectedRoundVersion: workflowVersionSchema,
}).strict();

export const proposalAggregateBodySchema = z.object({
  expectedRoundVersion: workflowVersionSchema,
  expectedProcessVersion: workflowVersionSchema,
  manifestId: workflowUuidSchema,
  manifestHash: workflowHashSchema,
  effectiveResponseDenominator: z.number().int().nonnegative(),
  aggregateHash: workflowHashSchema,
  candidates: z.array(z.object({
    memberId: workflowUuidSchema,
    distinctProponentCount: z.number().int().positive(),
  }).strict()).max(10_000),
}).strict().superRefine((value, context) => {
  if ((value.effectiveResponseDenominator === 0) !== (value.candidates.length === 0)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["effectiveResponseDenominator"], message: "effective denominator and candidates are incoherent" });
  }
  value.candidates.forEach((candidate, index) => {
    if (candidate.distinctProponentCount > value.effectiveResponseDenominator) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ["candidates", index, "distinctProponentCount"], message: "support exceeds non-empty responses" });
    }
  });
});

export const candidacyReviewBodySchema = z.object({
  expectedVersion: workflowVersionSchema,
  toState: z.enum(["UNDER_REVIEW", "PRELIMINARY_ACCEPTED", "WITHDRAWN", "EXCLUDED", "INELIGIBLE"]),
  reasonCode: candidacyReviewReasonCodeSchema,
  rationaleEnvelope: encryptedEnvelopeSchema.nullable().optional(),
  restrictedNoteEnvelope: encryptedEnvelopeSchema.nullable().optional(),
}).strict().superRefine((value, context) => {
  if (value.reasonCode !== CANDIDACY_REVIEW_REASON_CODE_BY_STATE[value.toState]) {
    context.addIssue({ code: "custom", path: ["reasonCode"], message: "Reason code must match the candidacy review decision" });
  }
});

export const candidateListBodySchema = z.object({
  expectedProcessVersion: workflowVersionSchema,
  orderedCandidacyIds: z.array(workflowUuidSchema).max(10_000),
}).strict();

export const provisionalAssignmentsBodySchema = z.object({
  roundId: workflowUuidSchema,
  expectedProcessVersion: workflowVersionSchema,
  expectedAggregateHash: workflowHashSchema,
  sessionId: workflowUuidSchema.nullable().optional(),
}).strict();

export const linkedDesignationBodySchema = z.object({
  expectedProcessVersion: workflowVersionSchema,
  baseAssignmentId: workflowUuidSchema,
  evidenceEnvelope: encryptedEnvelopeSchema,
  sessionId: workflowUuidSchema.nullable().optional(),
}).strict();

export const assignmentConsentBodySchema = z.object({
  expectedVersion: workflowVersionSchema,
  status: z.enum(["PENDING", "CONTACTED", "ACCEPTED", "DECLINED", "WITHDRAWN"]),
  envelope: encryptedEnvelopeSchema,
  sessionId: workflowUuidSchema.nullable().optional(),
}).strict();

export const assignmentPresentationBodySchema = z.object({
  expectedVersion: workflowVersionSchema,
  envelope: encryptedEnvelopeSchema,
  sessionId: workflowUuidSchema.nullable().optional(),
}).strict();

export const assignmentCongregationalDecisionBodySchema = z.object({
  expectedVersion: workflowVersionSchema,
  outcome: z.enum(["ELECTED", "RETURNED_TO_COMMITTEE", "NOT_ELECTED", "DEFERRED"]),
  envelope: encryptedEnvelopeSchema,
  sessionId: workflowUuidSchema.nullable().optional(),
}).strict();

export const assignmentActivationBodySchema = z.object({
  expectedVersion: workflowVersionSchema,
  sessionId: workflowUuidSchema.nullable().optional(),
}).strict();

const lifecycleEvidenceSchema = z.object({
  expectedVersion: workflowVersionSchema,
  evidenceEnvelope: encryptedEnvelopeSchema.nullable().optional(),
  sessionId: workflowUuidSchema.nullable().optional(),
}).strict();

export const assignmentFinalizationBodySchema = lifecycleEvidenceSchema.extend({
  reasonCode: assignmentFinalizationReasonCodeSchema,
  openVacancy: z.boolean(),
}).strict().superRefine((value, context) => {
  const expected = value.openVacancy ? "TERM_COMPLETED_OPEN_VACANCY" : "TERM_COMPLETED_NO_VACANCY";
  if (value.reasonCode !== expected) {
    context.addIssue({ code: "custom", path: ["reasonCode"], message: "Reason code must match the vacancy outcome" });
  }
});

export const assignmentSubstitutionBodySchema = lifecycleEvidenceSchema.extend({
  reasonCode: assignmentSubstitutionReasonCodeSchema,
}).strict();

export const workflowReportQuerySchema = z.object({
  reportType: z.enum(REPORT_TYPES),
  audience: z.enum(["committee", "auditor", "church"]),
  cycleId: workflowUuidSchema.optional(),
  sessionId: workflowUuidSchema.optional(),
}).strict();
