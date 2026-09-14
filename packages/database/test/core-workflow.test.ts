import { describe, expect, it } from "vitest";
import {
  assertCandidacyTransition,
  ballotRulesHash,
  buildWorkflowCycleMetrics,
  candidateSetHash,
  canonicalWorkflowJson,
  classifyWorkflowReportSensitiveProjection,
  electorateHash,
  normalizeProposalAggregate,
  planEligibilityPauseResolution,
  projectWorkflowReportSnapshot,
  workflowSha256,
} from "../src/core-workflow.js";

const ROUND_ID = "11111111-1111-4111-8111-111111111111";
const MEMBER_A = "22222222-2222-4222-8222-222222222221";
const MEMBER_B = "22222222-2222-4222-8222-222222222222";
const MEMBER_C = "22222222-2222-4222-8222-222222222223";
const MANIFEST_HASH = `sha256:${"a".repeat(64)}`;

describe("core workflow invariants", () => {
  it("uses the dashboard coverage formula and handles a zero vacancy denominator", () => {
    expect(buildWorkflowCycleMetrics({ membersTotal: 7, eligibleReference: 7, vacanciesTotal: 0, recommended: 0, accepted: 0, congregationallyElected: 0 }))
      .toMatchObject({ vacanciesTotal: 0, coveragePercent: null });
    expect(buildWorkflowCycleMetrics({ membersTotal: 7, eligibleReference: 7, vacanciesTotal: 3, recommended: 2, accepted: 1, congregationallyElected: 1 }))
      .toMatchObject({ vacanciesTotal: 3, recommended: 2, coveragePercent: 66.67 });
  });

  it("canonicalizes proposal aggregates without elector-to-preference records", () => {
    const aggregate = normalizeProposalAggregate({
      sourceRoundId: ROUND_ID,
      sourceManifestHash: MANIFEST_HASH,
      completedResponses: 7,
      electorateDenominator: 7,
      effectiveResponseDenominator: 6,
      maxProposalSelections: 2,
      candidates: [
        { memberId: MEMBER_C, distinctProponentCount: 2 },
        { memberId: MEMBER_B, distinctProponentCount: 3 },
        { memberId: MEMBER_A, distinctProponentCount: 4 },
      ],
    });
    expect(aggregate.candidates).toEqual([
      { memberId: MEMBER_A, distinctProponentCount: 4 },
      { memberId: MEMBER_B, distinctProponentCount: 3 },
      { memberId: MEMBER_C, distinctProponentCount: 2 },
    ]);
    expect(aggregate.completedResponses).toBe(7);
    expect(aggregate.electorateDenominator).toBe(7);
    expect(aggregate.effectiveResponseDenominator).toBe(6);
    expect(canonicalWorkflowJson(aggregate)).not.toContain("identityId");
    expect(workflowSha256(aggregate)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("represents an all-abstention proposal set as a non-applicable support denominator", () => {
    expect(normalizeProposalAggregate({
      sourceRoundId: ROUND_ID,
      sourceManifestHash: MANIFEST_HASH,
      completedResponses: 7,
      electorateDenominator: 7,
      effectiveResponseDenominator: 0,
      maxProposalSelections: 2,
      candidates: [],
    })).toMatchObject({
      completedResponses: 7,
      electorateDenominator: 7,
      effectiveResponseDenominator: 0,
      candidates: [],
    });
  });

  it("rejects duplicates, impossible counts and incomplete participation", () => {
    const base = {
      sourceRoundId: ROUND_ID,
      sourceManifestHash: MANIFEST_HASH,
      completedResponses: 5,
      electorateDenominator: 5,
      effectiveResponseDenominator: 5,
      maxProposalSelections: 1,
    } as const;
    expect(() => normalizeProposalAggregate({
      ...base,
      candidates: [
        { memberId: MEMBER_A, distinctProponentCount: 3 },
        { memberId: MEMBER_A, distinctProponentCount: 2 },
      ],
    })).toThrow(/once/i);
    expect(() => normalizeProposalAggregate({
      ...base,
      candidates: [
        { memberId: MEMBER_A, distinctProponentCount: 4 },
        { memberId: MEMBER_B, distinctProponentCount: 4 },
      ],
    })).toThrow(/exceed/i);
    expect(() => normalizeProposalAggregate({
      ...base,
      completedResponses: 4,
      candidates: [],
    })).toThrow(/every frozen elector/i);
  });

  it("enforces the human-review candidacy state machine", () => {
    expect(() => assertCandidacyTransition("PROPOSED", "UNDER_REVIEW")).not.toThrow();
    expect(() => assertCandidacyTransition("UNDER_REVIEW", "CONFIRMED_FOR_BALLOT")).not.toThrow();
    expect(() => assertCandidacyTransition("PROPOSED", "CONFIRMED_FOR_BALLOT")).toThrow(/cannot transition/i);
    expect(() => assertCandidacyTransition("EXCLUDED", "UNDER_REVIEW")).toThrow(/cannot transition/i);
  });

  it("hashes candidate sets independent of visible order and rejects ambiguity", () => {
    const first = candidateSetHash([
      { candidateId: MEMBER_A, memberId: MEMBER_B },
      { candidateId: MEMBER_B, memberId: MEMBER_A },
    ]);
    const second = candidateSetHash([
      { candidateId: MEMBER_B, memberId: MEMBER_A },
      { candidateId: MEMBER_A, memberId: MEMBER_B },
    ]);
    expect(first).toBe(second);
    expect(first).toBe(workflowSha256({ candidateIds: [MEMBER_A, MEMBER_B] }));
    expect(ballotRulesHash(2)).toBe(workflowSha256({
      allowAbstention: true,
      maxSelections: 2,
      minSelections: 1,
    }));
    expect(() => candidateSetHash([
      { candidateId: MEMBER_A, memberId: MEMBER_A },
      { candidateId: MEMBER_A, memberId: MEMBER_B },
    ])).toThrow(/unique/i);
  });

  it("freezes electorate capabilities and recusals into a deterministic digest", () => {
    const left = electorateHash([
      { identityId: MEMBER_A, canSubmit: true, recused: false },
      { identityId: MEMBER_B, canSubmit: false, recused: true },
    ]);
    const right = electorateHash([
      { identityId: MEMBER_B, canSubmit: false, recused: true },
      { identityId: MEMBER_A, canSubmit: true, recused: false },
    ]);
    expect(left).toBe(right);
  });

  it("plans eligibility-pause recovery without ever reopening a round that accepted responses", () => {
    expect(planEligibilityPauseResolution({
      resolutionCode: "ANNUL_AND_RESTART",
      previousProcessPhase: "VOTACION_ABIERTA",
      previousRoundPhase: "VOTACION_ABIERTA",
      affectedMembersEligible: false,
      affectedCandidacyCount: 1,
    })).toEqual({ annulRound: true, prepareProposalRound: true, processPhase: "CONFIGURADO", roundPhase: null });
    expect(() => planEligibilityPauseResolution({
      resolutionCode: "RESUME_UNCHANGED",
      previousProcessPhase: "PROPUESTAS_ABIERTAS",
      previousRoundPhase: "PROPUESTAS_ABIERTAS",
      affectedMembersEligible: true,
      affectedCandidacyCount: 0,
    })).toThrow(expect.objectContaining({ code: "OPEN_ROUND_REQUIRES_ANNULMENT" }));
    expect(planEligibilityPauseResolution({
      resolutionCode: "RESUME_UNCHANGED",
      previousProcessPhase: "DEPURACION",
      previousRoundPhase: null,
      affectedMembersEligible: true,
      affectedCandidacyCount: 1,
    })).toEqual({ annulRound: false, prepareProposalRound: false, processPhase: "DEPURACION", roundPhase: null });
  });

  it("requires an ineligible affected candidacy before returning a paused process to review", () => {
    expect(planEligibilityPauseResolution({
      resolutionCode: "EXCLUDE_AND_REVIEW",
      previousProcessPhase: "LISTA_CONFIRMADA",
      previousRoundPhase: "LISTA_CONFIRMADA",
      affectedMembersEligible: false,
      affectedCandidacyCount: 1,
    })).toEqual({ annulRound: true, prepareProposalRound: false, processPhase: "DEPURACION", roundPhase: null });
    expect(() => planEligibilityPauseResolution({
      resolutionCode: "EXCLUDE_AND_REVIEW",
      previousProcessPhase: "LISTA_CONFIRMADA",
      previousRoundPhase: "LISTA_CONFIRMADA",
      affectedMembersEligible: false,
      affectedCandidacyCount: 0,
    })).toThrow(expect.objectContaining({ code: "CANDIDACY_REVIEW_UNAVAILABLE" }));
  });

  it("closes an assignment-stage eligibility pause only after an audited replacement exists", () => {
    expect(planEligibilityPauseResolution({
      resolutionCode: "CLOSE_AFTER_REPLACEMENT",
      previousProcessPhase: "RESULTADO_INTERNO",
      previousRoundPhase: null,
      affectedMembersEligible: false,
      affectedCandidacyCount: 1,
      replacementProcessAvailable: true,
    })).toEqual({ annulRound: false, prepareProposalRound: false, processPhase: "CERRADO", roundPhase: null });
    expect(() => planEligibilityPauseResolution({
      resolutionCode: "CLOSE_AFTER_REPLACEMENT",
      previousProcessPhase: "RESULTADO_INTERNO",
      previousRoundPhase: null,
      affectedMembersEligible: false,
      affectedCandidacyCount: 1,
      replacementProcessAvailable: false,
    })).toThrow(expect.objectContaining({ code: "ASSIGNMENT_REPLACEMENT_REQUIRED" }));
    expect(() => planEligibilityPauseResolution({
      resolutionCode: "CLOSE_AFTER_REPLACEMENT",
      previousProcessPhase: "VOTACION_ABIERTA",
      previousRoundPhase: "VOTACION_ABIERTA",
      affectedMembersEligible: false,
      affectedCandidacyCount: 1,
      replacementProcessAvailable: true,
    })).toThrow(expect.objectContaining({ code: "ROUND_RESOLUTION_REQUIRED" }));
  });

  it("redacts internal counts, eligibility, nominal identities and reasons from church reports", () => {
    const snapshot = {
      processes: [{ id: "process", phase: "RESULTADO_INTERNO", maxProposalSelections: 3, decisionRule: { kind: "PLURALITY" }, proposalAggregate: { effectiveResponseDenominator: 6 } }],
      candidacies: [{ id: "candidate", distinctProponentCount: 4, eligibilityStatus: "eligible" }],
      candidacyReviews: [{ candidacyId: "candidate", toState: "INELIGIBLE" }],
      publishedAggregates: [{ aggregate: { abstentions: 1, candidates: [{ votes: 4 }] } }],
      eligibleMembers: [{ memberId: MEMBER_A, eligibilityStatus: "eligible" }],
      committee: [{ identityId: "nominal-secret" }],
      participation: [{ identityId: "nominal-secret", status: "received" }],
      assignments: [{ id: "assignment", state: "ELEGIDA_POR_IGLESIA", memberSnapshot: { displayEnvelope: "ciphertext" }, sourceAggregateHash: MANIFEST_HASH }],
      transitions: [{ assignmentId: "assignment", action: "CONGREGATIONAL_DECISION_RECORDED", reasonCode: "PRIVATE_REASON", actorIdentityId: "nominal-secret" }],
    };
    const projected = projectWorkflowReportSnapshot(snapshot, "church", {
      reportType: "office_round",
      permissions: ["aggregate.read", "member.read", "candidate.review", "consent.record", "audit.read"],
      includeNominalParticipation: true,
    });
    expect(projected["candidacies"]).toEqual([]);
    expect(projected["publishedAggregates"]).toEqual([]);
    expect(projected["eligibleMembers"]).toEqual([]);
    expect(projected["committee"]).toEqual([]);
    expect(projected["participation"]).toEqual([]);
    expect(projected["assignments"]).toEqual([expect.objectContaining({ state: "ELEGIDA_POR_IGLESIA", memberSnapshot: { displayEnvelope: "ciphertext" } })]);
    const serialized = JSON.stringify(projected);
    expect(serialized).not.toContain("nominal-secret");
    expect(serialized).not.toContain("PRIVATE_REASON");
    expect(serialized).not.toContain("effectiveResponseDenominator");
    expect(serialized).not.toContain("abstentions");
    expect(serialized).not.toContain("eligibilityStatus");
  });

  it("includes nominal participation only for an explicitly authorized report projection", () => {
    const snapshot = { processes: [], assignments: [], transitions: [], committee: [{ identityId: MEMBER_A }], participation: [{ identityId: MEMBER_A, status: "received" }] };
    expect(projectWorkflowReportSnapshot(snapshot, "committee", {
      reportType: "committee_participation",
      permissions: ["member.read", "participation.nominal.read"],
      includeNominalParticipation: false,
    })).toMatchObject({ committee: [], participation: [], redactions: expect.arrayContaining(["nominal_participation"]) });
    expect(projectWorkflowReportSnapshot(snapshot, "auditor", {
      reportType: "committee_participation",
      permissions: ["member.read", "participation.nominal.read"],
      includeNominalParticipation: true,
    })).toMatchObject({ committee: [{ identityId: MEMBER_A }], participation: [{ identityId: MEMBER_A, status: "received" }] });
  });

  it("keeps member snapshots out of church session minutes while retaining public assignment state", () => {
    const projected = projectWorkflowReportSnapshot({
      assignments: [{
        id: "assignment",
        memberId: MEMBER_A,
        memberSnapshot: { displayEnvelope: "ciphertext", photoSnapshot: "encrypted-photo" },
        state: "VIGENTE",
      }],
    }, "church", {
      reportType: "session_minutes",
      permissions: ["member.read"],
      includeNominalParticipation: false,
    });
    expect(projected["assignments"]).toEqual([{ id: "assignment", state: "VIGENTE" }]);
    expect(JSON.stringify(projected)).not.toMatch(/memberId|memberSnapshot|displayEnvelope|photoSnapshot/u);
  });

  it("keeps minutes title envelopes internal and gives church reports metadata-only session labels", () => {
    const snapshot = {
      sessions: [{
        id: "session-a", sequence: 1, titleEnvelope: { ciphertext: "session-title-ciphertext" },
        titleVersion: 2, legacyTitleUnavailable: false, startsAt: "2030-01-01T18:00:00Z",
        endsAt: "2030-01-01T20:00:00Z", status: "closed", version: 7,
      }],
      sessionMinutes: {
        id: "session-a", cycleId: "cycle-a", sequence: 1,
        titleEnvelope: { ciphertext: "session-title-ciphertext" }, titleVersion: 2,
        legacyTitleUnavailable: false, startsAt: "2030-01-01T18:00:00Z",
        endsAt: "2030-01-01T20:00:00Z", status: "closed", version: 7,
        attendance: [],
        agendaItems: [{
          id: "agenda-a", position: 1, titleEnvelope: { ciphertext: "agenda-title-ciphertext" },
          titleVersion: 1, legacyTitleUnavailable: false, processId: null, status: "decided",
          version: 2, createdAt: "2030-01-01T18:00:00Z", updatedAt: "2030-01-01T19:00:00Z",
          decision: { id: "decision-a", decisionCode: "INFORMATION_NOTED", outcome: "RECORDED", createdAt: "2030-01-01T19:00:00Z" },
        }],
      },
    };
    const internal = projectWorkflowReportSnapshot(snapshot, "committee", {
      reportType: "session_minutes",
      permissions: ["aggregate.read"],
      includeNominalParticipation: false,
    });
    expect(internal).toMatchObject({
      sessions: [{ titleEnvelope: { ciphertext: "session-title-ciphertext" }, titleVersion: 2 }],
      sessionMinutes: {
        titleEnvelope: { ciphertext: "session-title-ciphertext" },
        agendaItems: [{ titleEnvelope: { ciphertext: "agenda-title-ciphertext" }, titleVersion: 1 }],
      },
    });
    const church = projectWorkflowReportSnapshot(snapshot, "church", {
      reportType: "session_minutes",
      permissions: ["aggregate.read"],
      includeNominalParticipation: false,
    });
    expect(church).toMatchObject({
      sessions: [{ id: "session-a", sequence: 1, status: "closed" }],
      sessionMinutes: { id: "session-a", sequence: 1, agendaItems: [{ id: "agenda-a", position: 1, status: "decided" }] },
    });
    expect(JSON.stringify(church)).not.toMatch(/titleEnvelope|titleVersion|session-title-ciphertext|agenda-title-ciphertext/u);
  });

  it("projects a minimum aggregate reader through explicit allowlists without candidate, member, consent, or actor data", () => {
    const snapshot = {
      schemaVersion: 1,
      cycle: { id: "cycle", status: "active", secret: "must-not-pass" },
      processes: [{ id: "process", phase: "DEPURACION", proposalAggregate: { completedResponses: 7 } }],
      rounds: [{ id: "round", phase: "CERRADO", candidateSetHash: MANIFEST_HASH }],
      candidacies: [{ id: "candidate", memberId: MEMBER_A, displayEnvelope: { ciphertext: "member-secret" }, distinctProponentCount: 4 }],
      candidacyReviews: [{ id: "review", candidacyId: "candidate", toState: "INELIGIBLE" }],
      publishedAggregates: [{ manifestId: "manifest", aggregateHash: MANIFEST_HASH, aggregate: { abstentions: 1 } }],
      assignments: [{ id: "assignment", memberId: MEMBER_A, memberSnapshot: { displayEnvelope: "member-secret" }, consentStatus: "ACCEPTED", sourceAggregateHash: MANIFEST_HASH, state: "VIGENTE" }],
      transitions: [{ id: "transition", assignmentId: "assignment", action: "TERM_ACTIVATED", actorIdentityId: MEMBER_B, reasonCode: "PASTORAL_SECRET" }],
    };
    const officeRound = projectWorkflowReportSnapshot(snapshot, "committee", {
      reportType: "office_round",
      permissions: ["aggregate.read"],
      includeNominalParticipation: false,
    });
    expect(officeRound).toMatchObject({ candidacies: [], candidacyReviews: [], publishedAggregates: [expect.objectContaining({ aggregateHash: MANIFEST_HASH })] });
    const history = projectWorkflowReportSnapshot(snapshot, "committee", {
      reportType: "cycle_history",
      permissions: ["aggregate.read"],
      includeNominalParticipation: false,
    });
    expect(history["assignments"]).toEqual([expect.objectContaining({ id: "assignment", state: "VIGENTE" })]);
    expect(history["transitions"]).toEqual([expect.objectContaining({ id: "transition", action: "TERM_ACTIVATED" })]);
    const serialized = JSON.stringify({ officeRound, history });
    expect(serialized).not.toMatch(/memberId|memberSnapshot|displayEnvelope|consentStatus|actorIdentityId|PASTORAL_SECRET|must-not-pass/u);
  });

  it("projects cycle-scoped metrics and organization without leaking internal church recommendations", () => {
    const snapshot = {
      metrics: {
        membersTotal: 7,
        eligibleReference: 7,
        vacanciesTotal: 2,
        recommended: 2,
        accepted: 1,
        congregationallyElected: 1,
        coveragePercent: 100,
        secret: "must-not-pass",
      },
      organization: [
        {
          id: "elected",
          vacancyId: "vacancy-a",
          officeId: "office-a",
          departmentId: "department-a",
          officeName: "Secretaría",
          departmentName: "Administración",
          officeNames: { es: "Secretaría" },
          departmentNames: { es: "Administración" },
          status: "elected",
          processState: "VIGENTE",
          memberId: MEMBER_A,
          memberSnapshot: { displayEnvelope: "elected-ciphertext" },
        },
        {
          id: "accepted",
          vacancyId: "vacancy-b",
          officeId: "office-b",
          departmentId: "department-a",
          officeName: "Tesorería",
          departmentName: "Administración",
          officeNames: { es: "Tesorería" },
          departmentNames: { es: "Administración" },
          status: "accepted",
          processState: "ACEPTADA",
          memberId: MEMBER_B,
          memberSnapshot: { displayEnvelope: "accepted-ciphertext" },
        },
      ],
    };
    const internal = projectWorkflowReportSnapshot(snapshot, "committee", {
      reportType: "general_recommendations",
      permissions: ["aggregate.read", "organigram.read"],
      includeNominalParticipation: false,
    });
    expect(internal).toMatchObject({
      metrics: { vacanciesTotal: 2, recommended: 2, accepted: 1, congregationallyElected: 1, coveragePercent: 100 },
      organization: [
        expect.objectContaining({ status: "elected", memberId: MEMBER_A, memberSnapshot: { displayEnvelope: "elected-ciphertext" } }),
        expect.objectContaining({ status: "accepted", memberId: MEMBER_B, memberSnapshot: { displayEnvelope: "accepted-ciphertext" } }),
      ],
    });
    const church = projectWorkflowReportSnapshot(snapshot, "church", {
      reportType: "general_recommendations",
      permissions: ["aggregate.read", "organigram.read"],
      includeNominalParticipation: false,
    });
    expect(church).toMatchObject({
      metrics: { vacanciesTotal: 2, congregationallyElected: 1 },
      organization: [
        expect.objectContaining({ status: "elected", memberId: MEMBER_A, memberSnapshot: { displayEnvelope: "elected-ciphertext" } }),
        expect.objectContaining({ status: "vacant" }),
      ],
    });
    const churchSerialized = JSON.stringify(church);
    expect(churchSerialized).not.toMatch(/accepted-ciphertext|ACEPTADA|recommended|coveragePercent|membersTotal|eligibleReference|must-not-pass/u);
    expect(projectWorkflowReportSnapshot(snapshot, "committee", {
      reportType: "general_recommendations",
      permissions: ["aggregate.read"],
      includeNominalParticipation: false,
    })["organization"]).toEqual([]);
    expect(projectWorkflowReportSnapshot(snapshot, "committee", {
      reportType: "roster_import_incidents",
      permissions: ["member.read", "member.import"],
      includeNominalParticipation: false,
    })["metrics"]).toBeNull();
  });

  it("classifies only report data that was actually materialized as sensitive", () => {
    expect(classifyWorkflowReportSensitiveProjection({
      metrics: null,
      organization: [],
      sessions: [],
      processes: [],
      redactions: ["member_pii"],
    }, "committee")).toBeNull();
    expect(classifyWorkflowReportSensitiveProjection({
      metrics: { vacanciesTotal: 0, recommended: 0 },
      organization: [],
    }, "committee")).toBe("internal");
    expect(classifyWorkflowReportSensitiveProjection({
      metrics: { vacanciesTotal: 1, congregationallyElected: 0 },
      organization: [{ officeId: "office-a", status: "vacant" }],
    }, "church")).toBeNull();
    expect(classifyWorkflowReportSensitiveProjection({
      metrics: { vacanciesTotal: 1, congregationallyElected: 1 },
      organization: [{
        officeId: "office-a",
        status: "elected",
        memberId: MEMBER_A,
        memberSnapshot: { displayEnvelope: "opaque" },
      }],
    }, "church")).toBe("congregational-personal");
  });
});
