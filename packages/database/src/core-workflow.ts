import { createHash } from "node:crypto";
import { DataConflictError } from "./tenant-store.js";

export type CandidacyState =
  | "PROPOSED"
  | "UNDER_REVIEW"
  | "PRELIMINARY_ACCEPTED"
  | "CONFIRMED_FOR_BALLOT"
  | "WITHDRAWN"
  | "EXCLUDED"
  | "INELIGIBLE";

export interface ProposalAggregateCandidate {
  readonly memberId: string;
  readonly distinctProponentCount: number;
}

export interface NormalizedProposalAggregate {
  readonly schemaVersion: 1;
  readonly sourceRoundId: string;
  readonly sourceManifestHash: string;
  readonly completedResponses: number;
  readonly electorateDenominator: number;
  readonly effectiveResponseDenominator: number;
  readonly candidates: readonly ProposalAggregateCandidate[];
}

export type WorkflowReportAudience = "committee" | "auditor" | "church";

export interface WorkflowReportProjectionContext {
  readonly reportType: string;
  readonly permissions: ReadonlySet<string> | readonly string[];
  readonly includeNominalParticipation: boolean;
}

export type EligibilityPauseResolutionCode =
  | "ANNUL_AND_RESTART"
  | "RESUME_UNCHANGED"
  | "EXCLUDE_AND_REVIEW"
  | "CLOSE_AFTER_REPLACEMENT";

export interface EligibilityPauseResolutionPlan {
  readonly annulRound: boolean;
  readonly prepareProposalRound: boolean;
  readonly processPhase: string;
  readonly roundPhase: string | null;
}

const OPEN_SUBMISSION_PHASES = new Set(["PROPUESTAS_ABIERTAS", "VOTACION_ABIERTA"]);

/**
 * Produces the only admissible recovery plan for an eligibility pause. In
 * particular, a round that accepted submissions is never resumed and no
 * frozen candidate/elector snapshot is edited in place.
 */
export function planEligibilityPauseResolution(input: {
  readonly resolutionCode: EligibilityPauseResolutionCode;
  readonly previousProcessPhase: string;
  readonly previousRoundPhase: string | null;
  readonly affectedMembersEligible: boolean;
  readonly affectedCandidacyCount: number;
  readonly replacementProcessAvailable?: boolean;
}): EligibilityPauseResolutionPlan {
  if (!input.previousProcessPhase || input.previousProcessPhase === "PAUSADO") {
    throw new DataConflictError("ELIGIBILITY_PAUSE_INVALID", "Eligibility pause is missing its recoverable process phase");
  }
  if (!Number.isSafeInteger(input.affectedCandidacyCount) || input.affectedCandidacyCount < 0) {
    throw new DataConflictError("ELIGIBILITY_PAUSE_INVALID", "Affected candidacy count is invalid");
  }
  if (input.resolutionCode === "ANNUL_AND_RESTART") {
    return {
      annulRound: input.previousRoundPhase !== null,
      prepareProposalRound: true,
      processPhase: "CONFIGURADO",
      roundPhase: null,
    };
  }
  if (input.resolutionCode === "RESUME_UNCHANGED") {
    if (!input.affectedMembersEligible) {
      throw new DataConflictError("ELIGIBILITY_NOT_RESTORED", "Every affected member must be eligible and available before an unchanged resume");
    }
    if (input.previousRoundPhase && OPEN_SUBMISSION_PHASES.has(input.previousRoundPhase)) {
      throw new DataConflictError("OPEN_ROUND_REQUIRES_ANNULMENT", "A round that accepted submissions cannot be resumed after an eligibility change");
    }
    return {
      annulRound: false,
      prepareProposalRound: false,
      processPhase: input.previousProcessPhase,
      roundPhase: input.previousRoundPhase,
    };
  }
  if (input.resolutionCode === "CLOSE_AFTER_REPLACEMENT") {
    if (input.previousRoundPhase !== null) {
      throw new DataConflictError("ROUND_RESOLUTION_REQUIRED", "A paused round must be resolved before closing an assignment lifecycle");
    }
    if (!input.replacementProcessAvailable) {
      throw new DataConflictError("ASSIGNMENT_REPLACEMENT_REQUIRED", "Close-after-replacement requires an audited replacement process");
    }
    return {
      annulRound: false,
      prepareProposalRound: false,
      processPhase: "CERRADO",
      roundPhase: null,
    };
  }
  if (input.affectedMembersEligible) {
    throw new DataConflictError("ELIGIBILITY_STILL_VALID", "Exclude-and-review requires an affected member who remains unavailable or ineligible");
  }
  if (input.affectedCandidacyCount === 0) {
    throw new DataConflictError("CANDIDACY_REVIEW_UNAVAILABLE", "No affected candidacy is available for documented exclusion");
  }
  return {
    annulRound: input.previousRoundPhase !== null,
    prepareProposalRound: false,
    processPhase: "DEPURACION",
    roundPhase: null,
  };
}

export function buildWorkflowCycleMetrics(input: {
  readonly membersTotal: number;
  readonly eligibleReference: number;
  readonly vacanciesTotal: number;
  readonly recommended: number;
  readonly accepted: number;
  readonly congregationallyElected: number;
}): Record<string, number | null> {
  return {
    ...input,
    coveragePercent: input.vacanciesTotal === 0
      ? null
      : Number(((input.recommended / input.vacanciesTotal) * 100).toFixed(2)),
  };
}

/**
 * Applies the server-side audience boundary to an already preference-free
 * workflow snapshot. Ballot/proposal envelopes are never accepted by this
 * projection; church reports additionally lose every internal count,
 * candidacy/eligibility view, nominal roster and reason code.
 */
export function projectWorkflowReportSnapshot(
  snapshot: Readonly<Record<string, unknown>>,
  audience: WorkflowReportAudience,
  context: WorkflowReportProjectionContext,
): Record<string, unknown> {
  const permissions = context.permissions instanceof Set
    ? context.permissions
    : new Set(context.permissions);
  const internalAudience = audience !== "church";
  const canReadMembers = permissions.has("member.read");
  const canReviewCandidates = canReadMembers && permissions.has("candidate.review") && internalAudience;
  const canReadAggregates = permissions.has("aggregate.read") && internalAudience;
  const canReadConsent = canReadMembers && permissions.has("consent.record") && internalAudience;
  const canReadAuditActors = permissions.has("audit.read") && internalAudience;
  const canReadReasons = (permissions.has("private-note.read") || permissions.has("audit.read")) && internalAudience;
  const canReadOrganization = permissions.has("organigram.read") && internalAudience;
  const canReadPublicOrganization = permissions.has("organigram.read") && audience === "church";
  const canReadNominalParticipation = context.reportType === "committee_participation"
    && context.includeNominalParticipation
    && canReadMembers
    && permissions.has("participation.nominal.read")
    && internalAudience;
  const scope = WORKFLOW_REPORT_COLLECTIONS[context.reportType] ?? EMPTY_WORKFLOW_REPORT_COLLECTIONS;
  const redact = new Set<string>();
  if (!canReadMembers) redact.add("member_pii");
  if (!canReviewCandidates) redact.add("candidate_dossiers");
  if (!canReadConsent) redact.add("consent_dossiers");
  if (!canReadAggregates) redact.add("aggregate_evidence");
  if (!canReadAuditActors) redact.add("audit_actors");
  if (!canReadReasons) redact.add("reasons_and_notes");
  if (!canReadNominalParticipation) redact.add("nominal_participation");
  if (audience === "church") {
    redact.add("internal_counts");
    redact.add("candidacies");
    redact.add("eligibility");
  }

  const processes = scope.has("processes")
    ? records(snapshot["processes"]).map((process) => pickWorkflowFields(process, internalAudience
        ? PROCESS_FIELDS
        : PUBLIC_PROCESS_FIELDS))
    : [];
  const rounds = scope.has("rounds")
    ? records(snapshot["rounds"]).map((round) => pickWorkflowFields(round, canReadAggregates ? ROUND_FIELDS : PUBLIC_ROUND_FIELDS))
    : [];
  const assignments = scope.has("assignments")
    ? records(snapshot["assignments"]).map((assignment) => {
        const fields = new Set(ASSIGNMENT_FIELDS);
        if (canReadMembers && (internalAudience || context.reportType !== "session_minutes")) {
          fields.add("memberId");
          fields.add("memberSnapshot");
        }
        if (canReadConsent) fields.add("consentStatus");
        if (canReadAggregates) {
          fields.add("sourceManifestId");
          fields.add("sourceAggregateHash");
          fields.add("sourceCandidateId");
        }
        return pickWorkflowFields(assignment, fields);
      })
    : [];
  const transitions = scope.has("transitions")
    ? records(snapshot["transitions"]).map((transition) => {
        const fields = new Set(TRANSITION_FIELDS);
        if (canReadReasons) fields.add("reasonCode");
        if (canReadAuditActors) fields.add("actorIdentityId");
        return pickWorkflowFields(transition, fields);
      })
    : [];
  const rawSessionMinutes = context.reportType === "session_minutes" ? record(snapshot["sessionMinutes"]) : null;
  const sessionMinutes = rawSessionMinutes ? {
    ...pickWorkflowFields(rawSessionMinutes, internalAudience ? SESSION_MINUTES_FIELDS : PUBLIC_SESSION_MINUTES_FIELDS),
    attendance: canReadMembers && internalAudience
      ? records(rawSessionMinutes["attendance"]).map((entry) => pickWorkflowFields(entry, ATTENDANCE_FIELDS))
      : [],
    agendaItems: records(rawSessionMinutes["agendaItems"]).map((item) => {
      const decision = record(item["decision"]);
      return {
        ...pickWorkflowFields(item, internalAudience ? AGENDA_ITEM_FIELDS : PUBLIC_AGENDA_ITEM_FIELDS),
        decision: decision ? pickWorkflowFields(decision, SESSION_DECISION_FIELDS) : null,
      };
    }),
  } : null;
  const metrics = record(snapshot["metrics"]);
  const organization = scope.has("organization") && (canReadOrganization || canReadPublicOrganization)
    ? records(snapshot["organization"]).map((item) => {
        const status = typeof item["status"] === "string" ? item["status"] : "vacant";
        if (audience === "church" && (status === "recommended" || status === "accepted")) {
          return { ...pickWorkflowFields(item, PUBLIC_ORGANIZATION_FIELDS), status: "vacant" };
        }
        const fields = new Set(internalAudience ? ORGANIZATION_FIELDS : PUBLIC_ORGANIZATION_FIELDS);
        if (internalAudience || status === "elected") {
          fields.add("memberId");
          fields.add("memberSnapshot");
        }
        return pickWorkflowFields(item, fields);
      })
    : [];
  return {
    schemaVersion: snapshot["schemaVersion"],
    reportType: context.reportType,
    audience,
    generatedAt: snapshot["generatedAt"],
    cycleOptions: records(snapshot["cycleOptions"]).map((cycle) => pickWorkflowFields(cycle, CYCLE_FIELDS)),
    cycle: record(snapshot["cycle"]) ? pickWorkflowFields(record(snapshot["cycle"])!, CYCLE_FIELDS) : null,
    metrics: metrics && permissions.has("aggregate.read")
      ? pickWorkflowFields(metrics, internalAudience ? METRIC_FIELDS : PUBLIC_METRIC_FIELDS)
      : null,
    organization,
    sessions: scope.has("sessions")
      ? records(snapshot["sessions"]).map((session) => pickWorkflowFields(session, internalAudience ? SESSION_FIELDS : PUBLIC_SESSION_FIELDS))
      : [],
    sessionMinutes,
    departments: scope.has("departments") ? records(snapshot["departments"]).map((department) => pickWorkflowFields(department, DEPARTMENT_FIELDS)) : [],
    offices: scope.has("offices") ? records(snapshot["offices"]).map((office) => pickWorkflowFields(office, OFFICE_FIELDS)) : [],
    processes,
    rounds,
    candidacies: scope.has("candidacies") && canReviewCandidates
      ? records(snapshot["candidacies"]).map((candidate) => pickWorkflowFields(candidate, CANDIDACY_FIELDS))
      : [],
    candidacyReviews: scope.has("candidacyReviews") && canReviewCandidates
      ? records(snapshot["candidacyReviews"]).map((review) => pickWorkflowFields(review, CANDIDACY_REVIEW_FIELDS))
      : [],
    publishedAggregates: scope.has("publishedAggregates") && canReadAggregates
      ? records(snapshot["publishedAggregates"]).map((aggregate) => pickWorkflowFields(aggregate, PUBLISHED_AGGREGATE_FIELDS))
      : [],
    assignments,
    transitions,
    eligibleMembers: scope.has("eligibleMembers") && canReadMembers && internalAudience
      ? records(snapshot["eligibleMembers"]).map((member) => pickWorkflowFields(member, ELIGIBLE_MEMBER_FIELDS))
      : [],
    committee: canReadNominalParticipation
      ? records(snapshot["committee"]).map((membership) => pickWorkflowFields(membership, COMMITTEE_FIELDS))
      : [],
    participation: canReadNominalParticipation
      ? records(snapshot["participation"]).map((entry) => pickWorkflowFields(entry, PARTICIPATION_FIELDS))
      : [],
    redactions: [...redact].sort(),
  };
}

export type WorkflowReportSensitivityClassification = "internal" | "congregational-personal";

/**
 * Classifies the response after server-side projection.  This deliberately
 * works from the materialized response rather than the caller's permissions:
 * an empty/fully redacted report does not create a sensitive-read event merely
 * because the principal could have seen more data.
 */
export function classifyWorkflowReportSensitiveProjection(
  snapshot: Readonly<Record<string, unknown>>,
  audience: WorkflowReportAudience,
): WorkflowReportSensitivityClassification | null {
  if (audience !== "church") {
    return INTERNAL_REPORT_DATA_KEYS.some((key) => isMaterialized(snapshot[key]))
      ? "internal"
      : null;
  }
  return containsCongregationalPersonalData(snapshot)
    ? "congregational-personal"
    : null;
}

const INTERNAL_REPORT_DATA_KEYS = [
  "metrics",
  "organization",
  "sessions",
  "sessionMinutes",
  "departments",
  "offices",
  "processes",
  "rounds",
  "candidacies",
  "candidacyReviews",
  "publishedAggregates",
  "assignments",
  "transitions",
  "eligibleMembers",
  "committee",
  "participation",
] as const;

const CONGREGATIONAL_PERSONAL_KEYS = new Set([
  "memberId",
  "memberSnapshot",
  "displayEnvelope",
  "photoSnapshot",
  "titleEnvelope",
  "locationEnvelope",
]);

function isMaterialized(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

function containsCongregationalPersonalData(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsCongregationalPersonalData);
  if (value === null || typeof value !== "object") return false;
  for (const [key, child] of Object.entries(value as Readonly<Record<string, unknown>>)) {
    if (CONGREGATIONAL_PERSONAL_KEYS.has(key) && isMaterialized(child)) return true;
    if (containsCongregationalPersonalData(child)) return true;
  }
  return false;
}

const CYCLE_FIELDS = new Set(["id", "name", "status", "locale", "timezone", "jurisdiction", "termStart", "termEnd", "normativeVersion", "version", "activatedAt", "closedAt", "archivedAt"]);
const METRIC_FIELDS = new Set(["membersTotal", "eligibleReference", "vacanciesTotal", "recommended", "accepted", "congregationallyElected", "coveragePercent"]);
const PUBLIC_METRIC_FIELDS = new Set(["vacanciesTotal", "congregationallyElected"]);
const PUBLIC_ORGANIZATION_FIELDS = new Set(["id", "vacancyId", "officeId", "departmentId", "officeName", "departmentName", "officeNames", "departmentNames", "status", "linkedToId"]);
const ORGANIZATION_FIELDS = new Set([...PUBLIC_ORGANIZATION_FIELDS, "processState", "effective", "ordinal"]);
const PUBLIC_SESSION_FIELDS = new Set(["id", "sequence", "startsAt", "endsAt", "status", "version"]);
const SESSION_FIELDS = new Set([...PUBLIC_SESSION_FIELDS, "titleEnvelope", "titleVersion", "legacyTitleUnavailable"]);
const PUBLIC_SESSION_MINUTES_FIELDS = new Set([...PUBLIC_SESSION_FIELDS, "cycleId", "actualStartedAt", "actualClosedAt"]);
const SESSION_MINUTES_FIELDS = new Set([...SESSION_FIELDS, "cycleId", "actualStartedAt", "actualClosedAt"]);
const ATTENDANCE_FIELDS = new Set(["identityId", "memberId", "displayEnvelope", "photoSnapshot", "presenceStatus", "advisory", "votingRight", "substituteForIdentityId"]);
const PUBLIC_AGENDA_ITEM_FIELDS = new Set(["id", "position", "processId", "status", "version", "createdAt", "updatedAt"]);
const AGENDA_ITEM_FIELDS = new Set([...PUBLIC_AGENDA_ITEM_FIELDS, "titleEnvelope", "titleVersion", "legacyTitleUnavailable"]);
const SESSION_DECISION_FIELDS = new Set(["id", "decisionCode", "outcome", "createdAt"]);
const DEPARTMENT_FIELDS = new Set(["id", "canonicalCode", "names"]);
const OFFICE_FIELDS = new Set(["id", "departmentId", "canonicalCode", "names", "appointmentMechanism", "version"]);
const PUBLIC_PROCESS_FIELDS = new Set(["id", "officeId", "departmentId", "phase", "vacancyCount", "agendaOrder", "procedureSequence", "sourceProcessId", "replacementForAssignmentId", "reusedVacancyId", "enabled", "version"]);
const PROCESS_FIELDS = new Set([...PUBLIC_PROCESS_FIELDS, "maxProposalSelections", "maxBallotSelections", "decisionRule", "abstentionRule", "tiebreakPolicy", "quorumRule", "aggregateAudience", "proposalAggregate"]);
const PUBLIC_ROUND_FIELDS = new Set(["id", "processId", "workflowStage", "workflowAttempt", "phase", "submissionKind", "version", "openedAt", "closedAt"]);
const ROUND_FIELDS = new Set([...PUBLIC_ROUND_FIELDS, "candidateSetHash", "rulesHash"]);
const CANDIDACY_FIELDS = new Set(["id", "processId", "memberId", "displayEnvelope", "photoSnapshot", "state", "distinctProponentCount", "electorateDenominator", "supportDenominator", "availableSnapshot", "departmentRestriction", "validUntil", "eligibilityEvaluatedOn", "eligibilityEffective", "alreadyAssignedCount", "version", "updatedAt"]);
const CANDIDACY_REVIEW_FIELDS = new Set(["id", "candidacyId", "fromState", "toState", "decidedAt"]);
const PUBLISHED_AGGREGATE_FIELDS = new Set(["manifestId", "roundId", "aggregateHash", "aggregate", "version", "publishedAt"]);
const ASSIGNMENT_FIELDS = new Set(["id", "vacancyId", "officeId", "processId", "state", "version", "effective", "congregationalOutcome", "officeSnapshot", "presentedAt", "startedAt", "endedAt", "createdAt", "updatedAt"]);
const TRANSITION_FIELDS = new Set(["id", "assignmentId", "sessionId", "fromState", "toState", "action", "assignmentVersion", "occurredAt"]);
const ELIGIBLE_MEMBER_FIELDS = new Set(["memberId", "memberVersion", "displayEnvelope", "eligibilityStatus", "available", "departmentRestriction", "validUntil", "eligibilityEvaluatedOn", "eligibilityEffective", "photoSnapshot", "consideredCount", "assignedCount"]);
const COMMITTEE_FIELDS = new Set(["identityId", "memberId", "displayEnvelope", "roleCode", "votingRight", "pastoralCapacity", "status", "joinedAt"]);
const PARTICIPATION_FIELDS = new Set(["roundId", "submissionKind", "identityId", "canSubmit", "recused", "status", "receivedAt"]);

const WORKFLOW_REPORT_COLLECTIONS: Readonly<Record<string, ReadonlySet<string>>> = {
  cycle_summary: new Set(["sessions", "processes", "rounds", "assignments"]),
  general_recommendations: new Set(["departments", "offices", "processes", "assignments", "organization"]),
  elected_board: new Set(["departments", "offices", "assignments", "organization"]),
  department: new Set(["departments", "offices", "processes", "assignments", "organization"]),
  office_round: new Set(["departments", "offices", "processes", "rounds", "candidacies", "candidacyReviews", "publishedAggregates", "assignments"]),
  committee_participation: new Set(["rounds", "committee", "participation"]),
  responsibility_distribution: new Set(["departments", "offices", "assignments", "organization"]),
  unconsidered_unassigned: new Set(["departments", "offices", "candidacies", "assignments", "eligibleMembers"]),
  progress: new Set(["sessions", "departments", "offices", "processes", "rounds", "assignments", "organization"]),
  session_minutes: new Set(["sessions", "departments", "offices", "processes", "rounds", "publishedAggregates", "assignments", "transitions"]),
  cycle_history: new Set(["sessions", "departments", "offices", "processes", "rounds", "assignments", "transitions"]),
  audit_integrity: new Set(["processes", "rounds", "assignments", "transitions"]),
  roster_import_incidents: new Set(),
};
const EMPTY_WORKFLOW_REPORT_COLLECTIONS: ReadonlySet<string> = new Set();

function records(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value)
    ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item))
    : [];
}

function record(value: unknown): Record<string, unknown> | null {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function pickWorkflowFields(value: Readonly<Record<string, unknown>>, fields: ReadonlySet<string>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => fields.has(key)));
}

const CANDIDACY_TRANSITIONS: Readonly<Record<CandidacyState, readonly CandidacyState[]>> = {
  PROPOSED: ["UNDER_REVIEW", "WITHDRAWN", "INELIGIBLE"],
  UNDER_REVIEW: ["PRELIMINARY_ACCEPTED", "CONFIRMED_FOR_BALLOT", "WITHDRAWN", "EXCLUDED", "INELIGIBLE"],
  PRELIMINARY_ACCEPTED: ["CONFIRMED_FOR_BALLOT", "WITHDRAWN", "INELIGIBLE"],
  CONFIRMED_FOR_BALLOT: ["WITHDRAWN", "INELIGIBLE"],
  WITHDRAWN: [],
  EXCLUDED: [],
  INELIGIBLE: [],
};

export function canonicalWorkflowJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalWorkflowJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalWorkflowJson(record[key])}`)
    .join(",")}}`;
}

export function workflowSha256(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalWorkflowJson(value), "utf8").digest("hex")}`;
}

export function normalizeProposalAggregate(input: {
  readonly sourceRoundId: string;
  readonly sourceManifestHash: string;
  readonly completedResponses: number;
  readonly electorateDenominator: number;
  readonly effectiveResponseDenominator: number;
  readonly maxProposalSelections: number;
  readonly candidates: readonly ProposalAggregateCandidate[];
}): NormalizedProposalAggregate {
  if (!/^sha256:[0-9a-f]{64}$/u.test(input.sourceManifestHash)) {
    throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Source proposal manifest hash is invalid");
  }
  if (!Number.isSafeInteger(input.completedResponses) || input.completedResponses < 0) {
    throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Completed response count is invalid");
  }
  if (!Number.isSafeInteger(input.electorateDenominator) || input.electorateDenominator <= 0) {
    throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Electorate denominator is invalid");
  }
  if (input.completedResponses !== input.electorateDenominator) {
    throw new DataConflictError("PARTICIPATION_INCOMPLETE", "Proposal consolidation requires every frozen elector response");
  }
  if (
    !Number.isSafeInteger(input.effectiveResponseDenominator)
    || input.effectiveResponseDenominator < 0
    || input.effectiveResponseDenominator > input.completedResponses
  ) {
    throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Effective non-empty response denominator is invalid");
  }
  if (!Number.isSafeInteger(input.maxProposalSelections) || input.maxProposalSelections <= 0) {
    throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Proposal selection limit is invalid");
  }

  const candidates = [...input.candidates]
    .map((candidate) => ({
      memberId: candidate.memberId,
      distinctProponentCount: candidate.distinctProponentCount,
    }))
    .sort((left, right) => compareIdentifiers(left.memberId, right.memberId));
  if (new Set(candidates.map(({ memberId }) => memberId)).size !== candidates.length) {
    throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Each proposed member must appear once");
  }
  for (const candidate of candidates) {
    if (
      !Number.isSafeInteger(candidate.distinctProponentCount)
      || candidate.distinctProponentCount <= 0
      || candidate.distinctProponentCount > input.effectiveResponseDenominator
    ) {
      throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Distinct proponent count is outside the frozen electorate");
    }
  }
  const totalCandidateSelections = candidates.reduce(
    (total, candidate) => total + candidate.distinctProponentCount,
    0,
  );
  if (
    totalCandidateSelections < input.effectiveResponseDenominator
    || totalCandidateSelections > input.effectiveResponseDenominator * input.maxProposalSelections
  ) {
    throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Aggregate proposal selections exceed the frozen limit");
  }
  if ((input.effectiveResponseDenominator === 0) !== (candidates.length === 0)) {
    throw new DataConflictError("PROPOSAL_AGGREGATE_INVALID", "Empty and non-empty response evidence is incoherent");
  }
  return {
    schemaVersion: 1,
    sourceRoundId: input.sourceRoundId,
    sourceManifestHash: input.sourceManifestHash,
    completedResponses: input.completedResponses,
    electorateDenominator: input.electorateDenominator,
    effectiveResponseDenominator: input.effectiveResponseDenominator,
    candidates,
  };
}

export function assertCandidacyTransition(from: CandidacyState, to: CandidacyState): void {
  if (from === to || !CANDIDACY_TRANSITIONS[from].includes(to)) {
    throw new DataConflictError(
      "INVALID_STATE_TRANSITION",
      `Candidacy cannot transition from ${from} to ${to}`,
    );
  }
}

export function candidateSetHash(
  candidates: readonly { readonly candidateId: string; readonly memberId: string }[],
): string {
  const normalized = [...candidates]
    .map(({ candidateId, memberId }) => ({ candidateId, memberId }))
    .sort((left, right) => compareIdentifiers(left.candidateId, right.candidateId));
  if (
    new Set(normalized.map(({ candidateId }) => candidateId)).size !== normalized.length
    || new Set(normalized.map(({ memberId }) => memberId)).size !== normalized.length
  ) {
    throw new DataConflictError("CANDIDATE_SET_INVALID", "Candidate and member identifiers must be unique");
  }
  // This byte representation is deliberately identical to
  // @nombramientos/e2ee#hashCandidateSet. Member ids are validated above but
  // never enter the ballot hash; candidate ids are the semantic ballot values.
  return workflowSha256({ candidateIds: normalized.map(({ candidateId }) => candidateId) });
}

export function ballotRulesHash(maxSelections: number): string {
  if (!Number.isSafeInteger(maxSelections) || maxSelections <= 0) {
    throw new DataConflictError("BALLOT_RULES_INVALID", "Ballot maxSelections must be a positive safe integer");
  }
  // Keep in exact lockstep with @nombramientos/e2ee#hashBallotRules.
  return workflowSha256({ allowAbstention: true, maxSelections, minSelections: 1 });
}

export function electorateHash(
  electors: readonly {
    readonly identityId: string;
    readonly canSubmit: boolean;
    readonly recused: boolean;
  }[],
): string {
  const normalized = [...electors]
    .map(({ identityId, canSubmit, recused }) => ({ identityId, canSubmit, recused }))
    .sort((left, right) => compareIdentifiers(left.identityId, right.identityId));
  if (new Set(normalized.map(({ identityId }) => identityId)).size !== normalized.length) {
    throw new DataConflictError("ELECTORATE_INVALID", "Elector identities must be unique");
  }
  return workflowSha256({ schemaVersion: 1, electors: normalized });
}

function compareIdentifiers(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
