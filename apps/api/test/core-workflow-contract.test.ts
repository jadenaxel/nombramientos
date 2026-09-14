import { describe, expect, it } from "vitest";
import {
  assignmentActivationBodySchema,
  assignmentFinalizationBodySchema,
  assignmentPresentationBodySchema,
  assignmentSubstitutionBodySchema,
  candidacyReviewBodySchema,
  candidateListBodySchema,
  committeeBodySchema,
  cycleBodySchema,
  decisionRuleSchema,
  electorateBodySchema,
  eligibilityPauseResolutionBodySchema,
  linkedDesignationBodySchema,
  officeProcessApplicabilityBodySchema,
  provisionalAssignmentsBodySchema,
  proposalAggregateBodySchema,
  proposalManifestBodySchema,
  sessionAgendaCreateBodySchema,
  sessionAgendaOrderBodySchema,
  sessionAttendanceBodySchema,
  sessionBodySchema,
  sessionDecisionBodySchema,
  sessionUpdateBodySchema,
  tiebreakRoundBodySchema,
  vacancyProcessBodySchema,
  workflowReportQuerySchema,
} from "../src/modules/core-workflow-contract.js";
import { requiredReportPermissions } from "../src/lib/report-policy.js";

const ID_A = "11111111-1111-4111-8111-111111111111";
const ID_B = "22222222-2222-4222-8222-222222222222";
const HASH = `sha256:${"a".repeat(64)}`;
const envelope = (identityId: string) => ({
  algorithm: "AES-256-GCM" as const,
  keyId: "tenant-key-v1",
  nonce: Buffer.alloc(12).toString("base64url"),
  ciphertext: Buffer.alloc(32).toString("base64url"),
  aad: Buffer.from(JSON.stringify({ identityId })).toString("base64url"),
});

describe("core workflow HTTP contracts", () => {
  it("requires a coherent cycle term and bounded tenant configuration", () => {
    const valid = {
      name: "Mandato 2029–2030",
      locale: "es",
      timezone: "America/Santo_Domingo",
      jurisdiction: "Unión/Asociación pendiente de validación local",
      termStart: "2029-01-01",
      termEnd: "2030-12-31",
      normativeVersion: "catalog-v1",
      configuration: { parallelRooms: false },
    };
    expect(cycleBodySchema.safeParse(valid).success).toBe(true);
    expect(cycleBodySchema.safeParse({ ...valid, termEnd: "2028-12-31" }).success).toBe(false);
    expect(cycleBodySchema.safeParse({ ...valid, timezone: "America/Not_Real" }).success).toBe(false);
    expect(cycleBodySchema.safeParse({ ...valid, unexpected: true }).success).toBe(false);
  });

  it("keeps committee, electorate, and vacancy configuration explicit", () => {
    expect(committeeBodySchema.safeParse({
      expectedCycleVersion: 2,
      members: [
        { identityId: ID_A, displayEnvelope: envelope(ID_A), roleCode: "chair", votingRight: true, pastoralCapacity: false },
        { identityId: ID_B, displayEnvelope: envelope(ID_B), roleCode: "secretary", votingRight: true, pastoralCapacity: false },
      ],
    }).success).toBe(true);
    expect(electorateBodySchema.safeParse({
      expectedCycleVersion: 3,
      electors: [{ identityId: ID_A, canPropose: true, canVote: true, recused: false }],
    }).success).toBe(true);
    expect(vacancyProcessBodySchema.safeParse({
      expectedCycleVersion: 4,
      officeId: ID_A,
      vacancyCount: 1,
      maxProposalSelections: 3,
      maxBallotSelections: 1,
      decisionRule: { kind: "PLURALITY" },
      abstentionRule: "EXCLUDED_FROM_CANDIDATE_TOTALS",
      tiebreakPolicy: "NEW_BALLOT_ROUND",
      quorumRule: { kind: "ALL_REQUIRED" },
      aggregateAudience: "committee",
      agendaOrder: 1,
    }).success).toBe(true);
  });

  it("binds applicability changes to exact cycle/process versions and a state-specific reason", () => {
    expect(officeProcessApplicabilityBodySchema.safeParse({
      expectedCycleVersion: 7,
      expectedProcessVersion: 3,
      enabled: false,
      reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE",
    }).success).toBe(true);
    expect(officeProcessApplicabilityBodySchema.safeParse({
      expectedCycleVersion: 8,
      expectedProcessVersion: 4,
      enabled: true,
      reasonCode: "CYCLE_STRUCTURE_APPLICABILITY_RESTORED",
    }).success).toBe(true);
    expect(officeProcessApplicabilityBodySchema.safeParse({
      expectedCycleVersion: 8,
      expectedProcessVersion: 4,
      enabled: true,
      reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE",
    }).success).toBe(false);
    expect(officeProcessApplicabilityBodySchema.safeParse({
      expectedCycleVersion: 8,
      expectedProcessVersion: 4,
      enabled: false,
      reasonCode: "PERSONA_TIENE_DIAGNOSTICO",
      note: "free text is never accepted",
    }).success).toBe(false);
  });

  it("accepts only supported decision rules and explicit human review decisions", () => {
    expect(decisionRuleSchema.safeParse({ kind: "PLURALITY" }).success).toBe(true);
    expect(decisionRuleSchema.safeParse({ kind: "STRICT_MAJORITY", threshold: 0.5, denominator: "ALL_RECEIVED_BALLOTS" }).success).toBe(true);
    expect(decisionRuleSchema.safeParse({ kind: "RANDOM_DRAW" }).success).toBe(false);
    expect(candidacyReviewBodySchema.safeParse({
      expectedVersion: 1,
      toState: "UNDER_REVIEW",
      reasonCode: "REVIEW_STARTED",
    }).success).toBe(true);
    expect(candidacyReviewBodySchema.safeParse({
      expectedVersion: 1,
      toState: "CONFIRMED_FOR_BALLOT",
      reasonCode: "SKIP_HUMAN_REVIEW",
    }).success).toBe(false);
  });

  it("rejects duplicate/invalid candidate ids at persistence even when the wire shape is valid", () => {
    expect(candidateListBodySchema.safeParse({ expectedProcessVersion: 4, orderedCandidacyIds: [ID_A, ID_B] }).success).toBe(true);
    expect(provisionalAssignmentsBodySchema.safeParse({
      roundId: ID_A,
      expectedProcessVersion: 8,
      expectedAggregateHash: `sha256:${"a".repeat(64)}`,
    }).success).toBe(true);
    expect(provisionalAssignmentsBodySchema.safeParse({
      roundId: ID_A,
      expectedProcessVersion: 8,
      expectedAggregateHash: "unverified",
    }).success).toBe(false);
  });

  it("requires exact encrypted evidence for eligibility resolution and linked designation", () => {
    expect(eligibilityPauseResolutionBodySchema.safeParse({
      expectedProcessVersion: 4,
      expectedRoundVersion: 3,
      expectedPauseIds: [ID_A, ID_B],
      resolutionCode: "ANNUL_AND_RESTART",
      reasonCode: "ELIGIBILITY_ROUND_RESTARTED",
      evidenceEnvelope: envelope(ID_A),
    }).success).toBe(true);
    expect(eligibilityPauseResolutionBodySchema.safeParse({
      expectedProcessVersion: 4,
      expectedPauseIds: [ID_A, ID_A],
      resolutionCode: "RESUME_UNCHANGED",
      reasonCode: "invalid reason",
      evidenceEnvelope: envelope(ID_A),
    }).success).toBe(false);
    expect(eligibilityPauseResolutionBodySchema.safeParse({
      expectedProcessVersion: 5,
      expectedPauseIds: [ID_A],
      resolutionCode: "CLOSE_AFTER_REPLACEMENT",
      reasonCode: "ELIGIBILITY_REPLACEMENT_COMPLETED",
      evidenceEnvelope: envelope(ID_A),
    }).success).toBe(true);
    expect(linkedDesignationBodySchema.safeParse({
      expectedProcessVersion: 1,
      baseAssignmentId: ID_B,
      evidenceEnvelope: envelope(ID_B),
      sessionId: null,
    }).success).toBe(true);
    expect(linkedDesignationBodySchema.safeParse({
      expectedProcessVersion: 1,
      baseAssignmentId: "not-a-uuid",
      evidenceEnvelope: envelope(ID_B),
      unexpected: true,
    }).success).toBe(false);
  });

  it("binds every tiebreak attempt to a versioned published aggregate", () => {
    expect(tiebreakRoundBodySchema.safeParse({
      expectedProcessVersion: 9,
      sourceRoundId: ID_A,
      expectedAggregateHash: `sha256:${"c".repeat(64)}`,
    }).success).toBe(true);
    expect(tiebreakRoundBodySchema.safeParse({
      expectedProcessVersion: 9,
      sourceRoundId: ID_A,
      expectedAggregateHash: "client-selected-result",
    }).success).toBe(false);
  });

  it("binds proposal consolidation to a closed immutable manifest", () => {
    expect(proposalManifestBodySchema.safeParse({ expectedRoundVersion: 3 }).success).toBe(true);
    expect(proposalAggregateBodySchema.safeParse({
      expectedRoundVersion: 3,
      expectedProcessVersion: 3,
      manifestId: ID_A,
      manifestHash: `sha256:${"a".repeat(64)}`,
      effectiveResponseDenominator: 1,
      aggregateHash: `sha256:${"b".repeat(64)}`,
      candidates: [{ memberId: ID_B, distinctProponentCount: 1 }],
    }).success).toBe(true);
    expect(proposalAggregateBodySchema.safeParse({
      expectedRoundVersion: 3,
      expectedProcessVersion: 3,
      manifestId: ID_A,
      manifestHash: `sha256:${"a".repeat(64)}`,
      effectiveResponseDenominator: 0,
      aggregateHash: `sha256:${"b".repeat(64)}`,
      candidates: [],
    }).success).toBe(true);
    expect(proposalAggregateBodySchema.safeParse({
      expectedRoundVersion: 3,
      expectedProcessVersion: 3,
      manifestId: ID_A,
      manifestHash: `sha256:${"a".repeat(64)}`,
      effectiveResponseDenominator: 6,
      aggregateHash: `sha256:${"b".repeat(64)}`,
      candidates: [{ memberId: ID_B, distinctProponentCount: 7 }],
    }).success).toBe(false);
    expect(proposalAggregateBodySchema.safeParse({
      expectedRoundVersion: 3,
      expectedProcessVersion: 3,
      aggregateHash: `sha256:${"b".repeat(64)}`,
      candidates: [],
    }).success).toBe(false);
  });

  it("keeps assignment lifecycle mutations explicit and versioned", () => {
    expect(assignmentPresentationBodySchema.safeParse({ expectedVersion: 3, envelope: envelope(ID_A) }).success).toBe(true);
    expect(assignmentActivationBodySchema.safeParse({ expectedVersion: 5 }).success).toBe(true);
    expect(assignmentFinalizationBodySchema.safeParse({
      expectedVersion: 6,
      reasonCode: "TERM_COMPLETED_NO_VACANCY",
      openVacancy: false,
    }).success).toBe(true);
    expect(assignmentSubstitutionBodySchema.safeParse({
      expectedVersion: 6,
      reasonCode: "ASSIGNMENT_REPLACED",
      evidenceEnvelope: envelope(ID_B),
    }).success).toBe(true);
    expect(assignmentSubstitutionBodySchema.safeParse({
      expectedVersion: 6,
      reasonCode: "free text is forbidden",
    }).success).toBe(false);
  });

  it("validates workflow report scope and preserves report-specific permission requirements", () => {
    expect(workflowReportQuerySchema.safeParse({ reportType: "office_round", audience: "committee", cycleId: ID_A }).success).toBe(true);
    expect(workflowReportQuerySchema.safeParse({ reportType: "session_minutes", audience: "committee", cycleId: ID_A, sessionId: ID_B }).success).toBe(true);
    expect(workflowReportQuerySchema.safeParse({ reportType: "office_round", audience: "church" }).success).toBe(true);
    expect(() => requiredReportPermissions("office_round", "church")).toThrow(/not available/i);
    expect(requiredReportPermissions("committee_participation", "committee")).toEqual(["member.read", "participation.nominal.read"]);
    expect(workflowReportQuerySchema.safeParse({ reportType: "invented", audience: "committee" }).success).toBe(false);
  });

  it("keeps session preparation, attendance, agenda and decisions strict and versioned", () => {
    expect(sessionBodySchema.safeParse({
      sessionId: ID_A,
      expectedCycleVersion: 1,
      sequence: 1,
      titleEnvelope: envelope(ID_A),
      titleContentHash: HASH,
      startsAt: "2030-10-01T18:00:00-04:00",
      endsAt: "2030-10-01T20:00:00-04:00",
    }).success).toBe(true);
    expect(sessionBodySchema.safeParse({
      sessionId: ID_A,
      expectedCycleVersion: 1,
      sequence: 1,
      title: "El servidor no acepta títulos claros",
      startsAt: "2030-10-01T18:00:00-04:00",
      endsAt: "2030-10-01T20:00:00-04:00",
    }).success).toBe(false);
    expect(sessionUpdateBodySchema.safeParse({ expectedVersion: 1 }).success).toBe(false);
    expect(sessionUpdateBodySchema.safeParse({ expectedVersion: 1, titleEnvelope: envelope(ID_A), titleContentHash: HASH }).success).toBe(true);
    expect(sessionUpdateBodySchema.safeParse({ expectedVersion: 1, titleEnvelope: envelope(ID_A) }).success).toBe(false);
    expect(sessionUpdateBodySchema.safeParse({ expectedVersion: 1, title: "Sesión revisada" }).success).toBe(false);
    expect(sessionAttendanceBodySchema.safeParse({
      expectedVersion: 0,
      presenceStatus: "PRESENT",
      advisory: false,
      votingRight: true,
      substituteForIdentityId: ID_B,
    }).success).toBe(true);
    expect(sessionAttendanceBodySchema.safeParse({
      expectedVersion: 0,
      presenceStatus: "ABSENT",
      advisory: false,
      votingRight: true,
    }).success).toBe(false);
    expect(sessionAgendaCreateBodySchema.safeParse({ expectedSessionVersion: 2, itemId: ID_B, position: 1, titleEnvelope: envelope(ID_B), titleContentHash: HASH }).success).toBe(true);
    expect(sessionAgendaCreateBodySchema.safeParse({ expectedSessionVersion: 2, itemId: ID_B, position: 1, title: "Apertura" }).success).toBe(false);
    expect(sessionAgendaOrderBodySchema.safeParse({ expectedSessionVersion: 3, itemIds: [ID_A, ID_A] }).success).toBe(false);
    expect(sessionDecisionBodySchema.safeParse({
      expectedSessionVersion: 4,
      agendaItemId: ID_A,
      decisionCode: "RESOLUTION",
      outcome: "APPROVED",
    }).success).toBe(true);
  });
});
