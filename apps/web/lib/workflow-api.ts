import { apiRequest, type Envelope, type Locale } from "./api.ts";
import type { StoredPhotoRecord } from "./photo-client.ts";
export {
  buildProposalAggregate,
  canonicalWorkflowJson,
  proposalEnvelopeContentHash,
  verifyProposalManifest,
  workflowHash,
  type ProposalAggregate,
  type ProposalSubmissionPlaintext,
  type VerifiableProposalManifest,
} from "./workflow-aggregate.ts";

export type WorkflowCycleSummary = {
  id: string;
  name: string;
  status: "draft" | "active" | "closed" | "archived";
  locale: Locale;
  timezone: string;
  jurisdiction: string;
  termStart: string;
  termEnd: string;
  normativeVersion: string;
  version: number;
  clonedFromCycleId: string | null;
  createdAt: string;
  updatedAt: string;
  activatedAt: string | null;
  closedAt: string | null;
  archivedAt: string | null;
  readiness: { processes: number; sessions: number; committeeMembers: number; electors: number };
};

export type WorkflowProcess = {
  id: string;
  office_id: string;
  canonical_code: string;
  names: Record<Locale, string>;
  appointment_mechanism: string;
  catalog_metadata: { linkedBaseOfficeCode?: string } & Record<string, unknown>;
  phase: string;
  vacancy_count: number;
  max_proposal_selections: number;
  max_ballot_selections: number;
  decision_rule: { kind: "PLURALITY" } | { kind: "STRICT_MAJORITY"; threshold: number; denominator: "NON_ABSTAINING_BALLOTS" | "ALL_RECEIVED_BALLOTS" };
  abstention_rule: "EXCLUDED_FROM_CANDIDATE_TOTALS" | "INCLUDED_IN_ALL_RECEIVED_DENOMINATOR";
  tiebreak_policy: "NEW_BALLOT_ROUND" | "DOCUMENTED_HUMAN_RESOLUTION";
  quorum_rule: { kind: "ALL_REQUIRED" };
  aggregate_audience: "committee" | "auditor" | "church_after_publication";
  agenda_order: number;
  procedure_sequence: number;
  source_process_id: string | null;
  replacement_for_assignment_id: string | null;
  reused_vacancy_id: string | null;
  enabled: boolean;
  version: number;
};

export type ProcessApplicabilityResult = {
  cycleId: string;
  officeId: string;
  baseProcessId: string;
  affectedProcessIds: string[];
  enabled: boolean;
  reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE" | "CYCLE_STRUCTURE_APPLICABILITY_RESTORED";
  changed: boolean;
  cycleVersion: number;
  processVersions: Array<{ processId: string; version: number }>;
  updatedAt: string;
};

export type WorkflowRound = {
  id: string;
  process_id: string;
  workflow_stage: "proposal" | "ballot" | "tiebreak";
  workflow_attempt: number;
  phase: string;
  submission_kind: "proposal" | "vote";
  version: number;
  opened_at: string | null;
  closed_at: string | null;
  candidate_set_hash: `sha256:${string}`;
  rules_hash: `sha256:${string}`;
  configuration_hash: `sha256:${string}`;
  electorate_hash: `sha256:${string}`;
};

export type WorkflowEligibilityPause = {
  id: string;
  processId: string;
  roundId: string | null;
  memberId: string;
  memberVersion: number;
  previousProcessPhase: string;
  previousRoundPhase: string | null;
  reasonCode: "MEMBER_ELIGIBILITY_CHANGED" | "MEMBER_ARCHIVED";
  createdAt: string;
  resolutionId: string | null;
  resolutionCode: "ANNUL_AND_RESTART" | "RESUME_UNCHANGED" | "EXCLUDE_AND_REVIEW" | "CLOSE_AFTER_REPLACEMENT" | null;
  resolutionReasonCode: string | null;
  resolvedByIdentityId: string | null;
  replacementRoundId: string | null;
  replacementProcessId: string | null;
  resolutionProcessPhase: string | null;
  resolvedAt: string | null;
};

export type WorkflowAssignment = {
  id: string;
  vacancy_id: string;
  member_id: string;
  office_id: string;
  process_id: string;
  state: string;
  version: number;
  effective: boolean;
  consent_status: string | null;
  congregational_outcome: string | null;
  member_snapshot: { memberId: string; displayEnvelope?: Envelope | null; displayEnvelopeRedacted?: boolean; photo?: StoredPhotoRecord } | null;
  office_snapshot: { canonicalCode?: string; names?: Record<Locale, string> } | null;
  presented_at: string | null;
  started_at: string | null;
  ended_at: string | null;
  created_at: string;
  updated_at: string;
};

export type CycleWorkflow = {
  cycle: WorkflowCycleSummary;
  sessions: Array<{
    id: string; sequence: number; title_envelope: Envelope | null; title_envelope_version: number;
    legacy_title_unavailable: boolean; starts_at: string; ends_at: string; status: string; version: number;
  }>;
  processes: WorkflowProcess[];
  committee: Array<{
    identity_id: string; member_id: string | null; display_envelope: Envelope; role_code: string;
    voting_right: boolean; pastoral_capacity: boolean; status: string;
  }>;
  electorate: Array<{ identity_id: string; can_propose: boolean; can_vote: boolean; recused: boolean; version: number }>;
  rounds: WorkflowRound[];
  assignments: WorkflowAssignment[];
  eligibilityPauses: WorkflowEligibilityPause[];
};

export type CommitteeCandidate = {
  identityId: string;
  displayName: string;
  email: string;
  membershipStatus: "active";
};

export type WorkflowSessionStatus = "scheduled" | "in_progress" | "closed" | "cancelled";
export type WorkflowSessionRecord = {
  id: string;
  cycleId: string;
  sequence: number;
  titleEnvelope: Envelope | null;
  titleVersion: number;
  legacyTitleUnavailable: boolean;
  startsAt: string;
  endsAt: string;
  status: WorkflowSessionStatus;
  locationEnvelope: Envelope | null;
  version: number;
  actualStartedAt: string | null;
  actualClosedAt: string | null;
  createdAt: string;
  updatedAt: string;
  attendanceCount?: number;
  agendaCount?: number;
  decisionCount?: number;
};

export type WorkflowSessionAttendance = {
  identityId: string;
  memberId: string | null;
  displayEnvelope: Envelope | null;
  photoSnapshot: StoredPhotoRecord | null;
  presenceStatus: "PRESENT" | "REMOTE" | "ABSENT" | "EXCUSED";
  advisory: boolean;
  votingRight: boolean;
  substituteForIdentityId: string | null;
  version: number;
  recordedByIdentityId: string;
  createdAt: string;
  updatedAt: string;
};

export type WorkflowSessionAgendaItem = {
  id: string;
  position: number;
  titleEnvelope: Envelope | null;
  titleVersion: number;
  legacyTitleUnavailable: boolean;
  processId: string | null;
  notesEnvelope: Envelope | null;
  status: "pending" | "in_progress" | "decided" | "deferred";
  version: number;
  createdByIdentityId: string;
  createdAt: string;
  updatedAt: string;
  decision: WorkflowSessionDecision | null;
};

export type WorkflowSessionDecision = {
  id: string;
  agendaItemId?: string;
  decisionCode: string;
  outcome: "APPROVED" | "REJECTED" | "DEFERRED" | "RECORDED";
  evidenceEnvelope: Envelope | null;
  recordedByIdentityId: string;
  createdAt: string;
};

export type WorkflowSessionDetail = WorkflowSessionRecord & {
  attendance: WorkflowSessionAttendance[];
  agendaItems: WorkflowSessionAgendaItem[];
};

export type ProposalManifest = {
  manifestId: string;
  manifestHash: `sha256:${string}`;
  schemaVersion: 1;
  tenantId: string;
  roundId: string;
  roundVersion: number;
  candidateSetHash: `sha256:${string}`;
  rulesHash: `sha256:${string}`;
  configurationHash: `sha256:${string}`;
  electorateHash: `sha256:${string}`;
  candidateIds: string[];
  entryCount: number;
  createdAt: string;
  entries: Array<{ position: number; receiptId: string; contentHash: `sha256:${string}`; submissionRoundVersion: number; envelope: Envelope }>;
};

export type ReviewBoard = {
  process: {
    id: string; cycleId: string; phase: string; version: number; sourceProposalAggregateHash: string | null;
    participation: { completedResponses: number; electorateDenominator: number; effectiveResponseDenominator: number } | null;
  };
  office: { id: string; canonicalCode: string; names: Record<Locale, string>; appointmentMechanism: string };
  candidates: Array<{
    id: string; memberId: string; displayEnvelope: Envelope | null; photoSnapshot: StoredPhotoRecord | null;
    state: string; distinctProponentCount: number; electorateDenominator: number; supportDenominator: number;
    supportPercent: number | null; available: boolean; alreadyAssignedCount: number; version: number; updatedAt: string;
    reviews: Array<Record<string, unknown>>;
  }>;
  reviews: Array<Record<string, unknown>>;
};

export type AssignmentHistory = {
  assignment: Record<string, unknown> & { id: string; state: string; version: number; memberSnapshot: unknown; officeSnapshot: unknown };
  transitions: Array<{ id: string; sessionId: string | null; fromState: string | null; toState: string; action: string; reasonCode: string | null; assignmentVersion: number; occurredAt: string }>;
  replacementProcesses: Array<{ processId: string; phase: string; procedureSequence: number; reusedVacancyId: string; createdAt: string }>;
};

export type ProvisionalAssignmentOutcome = {
  assignmentId: string;
  vacancyId: string;
  candidateId: string;
  state: "PROPUESTA_INTERNA";
  independent: boolean;
  linkedToAssignmentId?: string;
  workload: { independent_count: number; nominal_count: number };
  warning: boolean;
  independentLoadWarning: boolean;
};

export type ProvisionalAssignmentsResult = {
  processId: string;
  roundId: string;
  aggregateHash: string;
  assignments: ProvisionalAssignmentOutcome[];
  phase: string;
  processVersion: number;
  roundVersion: number;
};

export type WorkflowReportSnapshot = {
  schemaVersion: 1;
  reportType: string;
  audience: "committee" | "auditor" | "church";
  generatedAt: string;
  cycleOptions: Array<{ id: string; name: string; status: string; locale: Locale; timezone: string; jurisdiction: string; termStart: string; termEnd: string; normativeVersion: string; version: number }>;
  cycle: { id: string; name: string; status: string; locale: Locale; timezone: string; jurisdiction: string; termStart: string; termEnd: string; normativeVersion: string; version: number } | null;
  metrics: null | {
    membersTotal?: number; eligibleReference?: number; vacanciesTotal: number;
    recommended?: number; accepted?: number; congregationallyElected: number; coveragePercent?: number | null;
  };
  organization: Array<{
    id: string; vacancyId: string; officeId: string; departmentId: string; ordinal?: number;
    officeName: string; departmentName: string; officeNames: Partial<Record<Locale, string>>;
    departmentNames: Partial<Record<Locale, string>>; status: string; processState?: string | null;
    effective?: boolean | null; memberId?: string; memberSnapshot?: { memberId?: string; displayEnvelope?: Envelope | null; displayEnvelopeRedacted?: boolean; photo?: StoredPhotoRecord } | null;
    linkedToId?: string | null;
  }>;
  sessions: Array<{
    id: string; sequence: number; titleEnvelope?: Envelope | null; titleVersion?: number;
    legacyTitleUnavailable?: boolean; startsAt: string; endsAt: string; status: string; version: number;
  }>;
  sessionMinutes: null | {
    id: string; cycleId: string; sequence: number; titleEnvelope?: Envelope | null; titleVersion?: number;
    legacyTitleUnavailable?: boolean; startsAt: string; endsAt: string;
    status: string; version: number; actualStartedAt: string | null; actualClosedAt: string | null;
    attendance: Array<{
      identityId: string; memberId: string | null; presenceStatus: "PRESENT" | "REMOTE" | "ABSENT" | "EXCUSED";
      displayEnvelope: Envelope | null; photoSnapshot: StoredPhotoRecord | null;
      advisory: boolean; votingRight: boolean; substituteForIdentityId: string | null;
    }>;
    agendaItems: Array<{
      id: string; position: number; titleEnvelope?: Envelope | null; titleVersion?: number;
      legacyTitleUnavailable?: boolean; notesEnvelope?: Envelope | null; processId: string | null; status: string; version: number;
      createdAt: string; updatedAt: string;
      decision: null | { id: string; decisionCode: string; outcome: "APPROVED" | "REJECTED" | "DEFERRED" | "RECORDED"; evidenceEnvelope?: Envelope | null; createdAt: string };
    }>;
  };
  departments: Array<{ id: string; canonicalCode: string; names: Record<Locale, string> }>;
  offices: Array<{ id: string; departmentId: string; canonicalCode: string; names: Record<Locale, string>; appointmentMechanism: string; version: number }>;
  processes: Array<Record<string, unknown> & { id: string; officeId: string; departmentId: string; phase: string; vacancyCount: number; agendaOrder: number; procedureSequence: number; proposalAggregate?: { completedResponses: number; electorateDenominator: number; effectiveResponseDenominator: number } | null }>;
  rounds: Array<Record<string, unknown> & { id: string; processId: string; workflowStage: string; phase: string; submissionKind: string; version: number }>;
  candidacies: Array<Record<string, unknown> & { id: string; processId: string; memberId: string; displayEnvelope: Envelope | null; photoSnapshot: StoredPhotoRecord | null; state: string; distinctProponentCount: number; electorateDenominator: number; supportDenominator: number }>;
  candidacyReviews: Array<Record<string, unknown> & { id: string; candidacyId: string; fromState: string; toState: string; decidedAt: string }>;
  publishedAggregates: Array<Record<string, unknown> & { manifestId: string; roundId: string; aggregateHash: string; aggregate: { receivedBallots: number; nonAbstainingBallots: number; abstentions: number; rule: Record<string, unknown>; decision: Record<string, unknown>; candidates: Array<{ candidateId: string; votes: number }> }; version: number; publishedAt: string }>;
  assignments: Array<Record<string, unknown> & { id: string; vacancyId: string; memberId: string; officeId: string; processId: string | null; state: string; memberSnapshot: { memberId: string; displayEnvelope?: Envelope | null; displayEnvelopeRedacted?: boolean; photo?: StoredPhotoRecord } | null; officeSnapshot: Record<string, unknown> | null }>;
  transitions: Array<Record<string, unknown> & { id: string; assignmentId: string; fromState: string | null; toState: string; action: string; occurredAt: string }>;
  eligibleMembers: Array<Record<string, unknown> & { memberId: string; displayEnvelope: Envelope | null; photoSnapshot: StoredPhotoRecord | null; eligibilityStatus: string; available: boolean; consideredCount: number; assignedCount: number }>;
  committee: Array<Record<string, unknown> & { identityId: string; memberId: string | null; displayEnvelope: Envelope; roleCode: string; votingRight: boolean; pastoralCapacity: boolean; status: string }>;
  participation: Array<Record<string, unknown> & { roundId: string; submissionKind: string; identityId: string; canSubmit: boolean; recused: boolean; status: string; receivedAt: string | null }>;
  redactions: string[];
};

type CycleInput = {
  name: string; locale: Locale; timezone: string; jurisdiction: string; termStart: string; termEnd: string;
  normativeVersion: string; configuration: Record<string, unknown>;
};

function resource(segment: string): string {
  return encodeURIComponent(segment);
}

function mutation<T>(path: string, method: "POST" | "PUT" | "PATCH", body: unknown, logicalIdempotencyKey?: string): Promise<T> {
  return apiRequest<T>(path, {
    method,
    body: JSON.stringify(body),
    idempotent: true,
    ...(logicalIdempotencyKey ? { idempotencyKey: logicalIdempotencyKey } : {}),
  });
}

export const workflowApi = {
  cycles: () => apiRequest<{ items: WorkflowCycleSummary[] }>("/v1/cycles"),
  workflow: (cycleId: string) => apiRequest<CycleWorkflow>(`/v1/cycles/${resource(cycleId)}/workflow`),
  createCycle: (body: CycleInput, key?: string) => mutation<WorkflowCycleSummary>("/v1/cycles", "POST", body, key),
  cloneCycle: (sourceCycleId: string, body: CycleInput, key?: string) => mutation<WorkflowCycleSummary>(`/v1/cycles/${resource(sourceCycleId)}/clone`, "POST", body, key),
  activateCycle: (cycleId: string, expectedVersion: number) => mutation<Record<string, unknown>>(`/v1/cycles/${resource(cycleId)}/activate`, "POST", { expectedVersion }),
  closeCycle: (cycleId: string, expectedVersion: number) => mutation<Record<string, unknown>>(`/v1/cycles/${resource(cycleId)}/close`, "POST", { expectedVersion }),
  archiveCycle: (cycleId: string, expectedVersion: number) => mutation<Record<string, unknown>>(`/v1/cycles/${resource(cycleId)}/archive`, "POST", { expectedVersion }),
  addSession: (cycleId: string, body: object) => mutation<Record<string, unknown>>(`/v1/cycles/${resource(cycleId)}/sessions`, "POST", body),
  sessions: (cycleId: string) => apiRequest<{ items: WorkflowSessionRecord[] }>(`/v1/cycles/${resource(cycleId)}/sessions`),
  session: (sessionId: string) => apiRequest<WorkflowSessionDetail>(`/v1/sessions/${resource(sessionId)}`),
  updateSession: (sessionId: string, body: object) => mutation<WorkflowSessionRecord>(`/v1/sessions/${resource(sessionId)}`, "PATCH", body),
  startSession: (sessionId: string, expectedVersion: number) => mutation<WorkflowSessionRecord>(`/v1/sessions/${resource(sessionId)}/start`, "POST", { expectedVersion }),
  closeSession: (sessionId: string, expectedVersion: number) => mutation<WorkflowSessionRecord>(`/v1/sessions/${resource(sessionId)}/close`, "POST", { expectedVersion }),
  upsertSessionAttendance: (sessionId: string, identityId: string, body: object) => mutation<Record<string, unknown>>(`/v1/sessions/${resource(sessionId)}/attendance/${resource(identityId)}`, "PUT", body),
  addSessionAgendaItem: (sessionId: string, body: object) => mutation<Record<string, unknown>>(`/v1/sessions/${resource(sessionId)}/agenda`, "POST", body),
  reorderSessionAgenda: (sessionId: string, body: object) => mutation<Record<string, unknown>>(`/v1/sessions/${resource(sessionId)}/agenda/order`, "PUT", body),
  recordSessionDecision: (sessionId: string, body: object) => mutation<Record<string, unknown>>(`/v1/sessions/${resource(sessionId)}/decisions`, "POST", body),
  configureCommittee: (cycleId: string, body: object) => mutation<Record<string, unknown>>(`/v1/cycles/${resource(cycleId)}/committee`, "PUT", body),
  committeeCandidates: (cycleId: string) => apiRequest<{ items: CommitteeCandidate[] }>(`/v1/cycles/${resource(cycleId)}/committee-candidates`),
  configureElectorate: (cycleId: string, body: object) => mutation<Record<string, unknown>>(`/v1/cycles/${resource(cycleId)}/electorate`, "PUT", body),
  configureVacancy: (cycleId: string, body: object) => mutation<Record<string, unknown>>(`/v1/cycles/${resource(cycleId)}/vacancy-processes`, "POST", body),
  setProcessApplicability: (processId: string, body: { expectedCycleVersion: number; expectedProcessVersion: number; enabled: boolean; reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE" | "CYCLE_STRUCTURE_APPLICABILITY_RESTORED" }) => mutation<ProcessApplicabilityResult>(`/v1/office-processes/${resource(processId)}/applicability`, "PUT", body),
  prepareProposalRound: (processId: string, expectedProcessVersion: number) => mutation<Record<string, unknown>>(`/v1/office-processes/${resource(processId)}/proposal-rounds`, "POST", { expectedProcessVersion }),
  resolveEligibilityPause: (processId: string, body: object) => mutation<Record<string, unknown>>(`/v1/office-processes/${resource(processId)}/eligibility-pause/resolve`, "POST", body),
  openProposalRound: (roundId: string, expectedRoundVersion: number, expectedProcessVersion: number) => mutation<Record<string, unknown>>(`/v1/proposal-rounds/${resource(roundId)}/open`, "POST", { expectedRoundVersion, expectedProcessVersion }),
  closeProposalRound: (roundId: string, expectedRoundVersion: number, expectedProcessVersion: number) => mutation<Record<string, unknown>>(`/v1/proposal-rounds/${resource(roundId)}/close`, "POST", { expectedRoundVersion, expectedProcessVersion, reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED" }),
  createProposalManifest: async (roundId: string, expectedRoundVersion: number): Promise<ProposalManifest> => {
    const path = `/v1/proposal-rounds/${resource(roundId)}/manifest`;
    // Creation returns immutable receipt metadata, not the encrypted entries.
    // Retrieve the complete manifest before any local verification/decryption.
    await mutation<Record<string, unknown>>(path, "POST", { expectedRoundVersion });
    return apiRequest<ProposalManifest>(path);
  },
  proposalManifest: (roundId: string) => apiRequest<ProposalManifest>(`/v1/proposal-rounds/${resource(roundId)}/manifest`),
  consolidateProposals: (roundId: string, body: object) => mutation<Record<string, unknown>>(`/v1/proposal-rounds/${resource(roundId)}/aggregate`, "POST", body),
  reviewBoard: (processId: string) => apiRequest<ReviewBoard>(`/v1/office-processes/${resource(processId)}/review-board`),
  reviewCandidacy: (processId: string, candidacyId: string, body: object) => mutation<Record<string, unknown>>(`/v1/office-processes/${resource(processId)}/candidacies/${resource(candidacyId)}/reviews`, "POST", body),
  confirmCandidateList: (processId: string, body: object) => mutation<Record<string, unknown>>(`/v1/office-processes/${resource(processId)}/candidate-lists`, "POST", body),
  prepareBallotRound: (processId: string, expectedProcessVersion: number) => mutation<Record<string, unknown>>(`/v1/office-processes/${resource(processId)}/ballot-rounds`, "POST", { expectedProcessVersion }),
  prepareTiebreakRound: (processId: string, expectedProcessVersion: number, sourceRoundId: string, expectedAggregateHash: string) => mutation<Record<string, unknown>>(`/v1/office-processes/${resource(processId)}/tiebreak-rounds`, "POST", { expectedProcessVersion, sourceRoundId, expectedAggregateHash }),
  openBallotRound: (roundId: string, expectedRoundVersion: number, expectedProcessVersion: number) => mutation<Record<string, unknown>>(`/v1/ballot-rounds/${resource(roundId)}/open`, "POST", { expectedRoundVersion, expectedProcessVersion }),
  closeBallotRound: (roundId: string, expectedRoundVersion: number, expectedProcessVersion: number) => mutation<Record<string, unknown>>(`/v1/ballot-rounds/${resource(roundId)}/close`, "POST", { expectedRoundVersion, expectedProcessVersion, reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED" }),
  createProvisionalAssignments: (processId: string, roundId: string, expectedProcessVersion: number, expectedAggregateHash: string) => mutation<ProvisionalAssignmentsResult>(`/v1/office-processes/${resource(processId)}/provisional-assignments`, "POST", { roundId, expectedProcessVersion, expectedAggregateHash }),
  createLinkedDesignation: (processId: string, body: object) => mutation<Record<string, unknown>>(`/v1/office-processes/${resource(processId)}/linked-designations`, "POST", body),
  recordConsent: (assignmentId: string, body: object) => mutation<Record<string, unknown>>(`/v1/assignments/${resource(assignmentId)}/consent`, "POST", body),
  presentAssignment: (assignmentId: string, body: object) => mutation<Record<string, unknown>>(`/v1/assignments/${resource(assignmentId)}/presentation`, "POST", body),
  congregationalDecision: (assignmentId: string, body: object) => mutation<Record<string, unknown>>(`/v1/assignments/${resource(assignmentId)}/congregational-decision`, "POST", body),
  activateAssignment: (assignmentId: string, expectedVersion: number, sessionId?: string) => mutation<Record<string, unknown>>(`/v1/assignments/${resource(assignmentId)}/activate`, "POST", { expectedVersion, ...(sessionId ? { sessionId } : {}) }),
  finalizeAssignment: (assignmentId: string, body: object) => mutation<Record<string, unknown>>(`/v1/assignments/${resource(assignmentId)}/finalize`, "POST", body),
  substituteAssignment: (assignmentId: string, body: object) => mutation<Record<string, unknown>>(`/v1/assignments/${resource(assignmentId)}/substitute`, "POST", body),
  assignmentHistory: (assignmentId: string) => apiRequest<AssignmentHistory>(`/v1/assignments/${resource(assignmentId)}/history`),
  reportSnapshot: (reportType: string, audience: "committee" | "auditor" | "church", cycleId?: string, sessionId?: string) => {
    const query = new URLSearchParams({ reportType, audience });
    if (cycleId) query.set("cycleId", cycleId);
    if (sessionId) query.set("sessionId", sessionId);
    return apiRequest<WorkflowReportSnapshot>(`/v1/reports/workflow-snapshot?${query.toString()}`);
  },
};
