import { invariant } from "./errors.js";
import {
  validateFinalResponse,
  type FinalResponse
} from "./submissions.js";

export interface EffectiveBallot {
  readonly electorId: string;
  readonly response: FinalResponse;
}

export interface CandidateTally {
  readonly candidateId: string;
  readonly votes: number;
  readonly shareOfNonAbstaining: number | null;
  readonly percentageOfNonAbstaining: number | null;
}

export interface ElectionTally {
  readonly receivedBallots: number;
  readonly nonAbstainingBallots: number;
  readonly abstentions: number;
  readonly maxSelections: number;
  readonly candidates: readonly CandidateTally[];
}

function compareIdentifiers(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function tallyBallots(
  candidateIds: readonly string[],
  maxSelections: number,
  ballots: readonly EffectiveBallot[]
): ElectionTally {
  invariant(
    Number.isSafeInteger(maxSelections) && maxSelections > 0,
    "INVALID_SELECTION_LIMIT",
    "El máximo de selecciones debe ser un entero positivo.",
    { maxSelections }
  );
  const allowedCandidates = new Set(candidateIds);
  invariant(
    allowedCandidates.size === candidateIds.length,
    "INVALID_SNAPSHOT",
    "El snapshot de candidatos contiene identificadores repetidos."
  );

  const counts = new Map<string, number>(
    candidateIds.map((candidateId) => [candidateId, 0])
  );
  const seenElectors = new Set<string>();
  let abstentions = 0;
  let nonAbstainingBallots = 0;

  for (const ballot of ballots) {
    invariant(
      !seenElectors.has(ballot.electorId),
      "DUPLICATE_RESPONSE",
      "El escrutinio recibió más de una boleta efectiva del mismo elector.",
      { electorId: ballot.electorId }
    );
    seenElectors.add(ballot.electorId);

    const response = validateFinalResponse(
      ballot.response,
      allowedCandidates,
      maxSelections
    );
    if (response.kind === "ABSTENTION") {
      abstentions += 1;
      continue;
    }

    nonAbstainingBallots += 1;
    for (const candidateId of response.candidateIds) {
      counts.set(candidateId, (counts.get(candidateId) ?? 0) + 1);
    }
  }

  const candidates = [...counts.entries()]
    .sort(([left], [right]) => compareIdentifiers(left, right))
    .map(([candidateId, votes]) => {
      const share =
        nonAbstainingBallots === 0 ? null : votes / nonAbstainingBallots;
      return Object.freeze({
        candidateId,
        votes,
        shareOfNonAbstaining: share,
        percentageOfNonAbstaining: share === null ? null : share * 100
      });
    });

  return Object.freeze({
    receivedBallots: ballots.length,
    nonAbstainingBallots,
    abstentions,
    maxSelections,
    candidates: Object.freeze(candidates)
  });
}

export const DECISION_DENOMINATORS = [
  "NON_ABSTAINING_BALLOTS",
  "ALL_RECEIVED_BALLOTS"
] as const;

export type DecisionDenominator = (typeof DECISION_DENOMINATORS)[number];

export type InternalDecisionRule =
  | Readonly<{ kind: "PLURALITY" }>
  | Readonly<{
      kind: "STRICT_MAJORITY";
      threshold?: number;
      denominator?: DecisionDenominator;
    }>;

export const INTERNAL_DECISION_STATUSES = [
  "SELECTED",
  "PARTIAL_SELECTION",
  "TIEBREAK_REQUIRED",
  "NO_SELECTION"
] as const;

export type InternalDecisionStatus =
  (typeof INTERNAL_DECISION_STATUSES)[number];

export const INTERNAL_DECISION_REASONS = [
  "TOP_K",
  "CUTOFF_TIE",
  "NO_VALID_CANDIDATE_VOTES",
  "THRESHOLD_NOT_MET",
  "INSUFFICIENT_QUALIFIED_CANDIDATES"
] as const;

export type InternalDecisionReason =
  (typeof INTERNAL_DECISION_REASONS)[number];

export interface InternalDecision {
  readonly status: InternalDecisionStatus;
  readonly reason: InternalDecisionReason;
  readonly selectedCandidateIds: readonly string[];
  readonly tiebreakCandidateIds: readonly string[];
  readonly unfilledSeats: number;
}

function thresholdFor(rule: InternalDecisionRule): number | null {
  if (rule.kind === "PLURALITY") {
    return null;
  }
  const threshold = rule.threshold ?? 0.5;
  invariant(
    Number.isFinite(threshold) && threshold >= 0 && threshold < 1,
    "INVALID_RULE",
    "El umbral debe ser mayor o igual a cero y menor que uno.",
    { threshold }
  );
  return threshold;
}

export function evaluateInternalDecision(
  tally: ElectionTally,
  seats: number,
  rule: InternalDecisionRule
): InternalDecision {
  invariant(
    Number.isSafeInteger(seats) && seats > 0,
    "INVALID_RULE",
    "El número de plazas debe ser un entero positivo.",
    { seats }
  );
  const threshold = thresholdFor(rule);
  const decisionDenominator =
    rule.kind === "STRICT_MAJORITY" &&
    rule.denominator === "ALL_RECEIVED_BALLOTS"
      ? tally.receivedBallots
      : tally.nonAbstainingBallots;
  const ranked = [...tally.candidates].sort(
    (left, right) =>
      right.votes - left.votes ||
      compareIdentifiers(left.candidateId, right.candidateId)
  );
  const positive = ranked.filter((candidate) => candidate.votes > 0);

  if (positive.length === 0 || decisionDenominator === 0) {
    return Object.freeze({
      status: "NO_SELECTION",
      reason: "NO_VALID_CANDIDATE_VOTES",
      selectedCandidateIds: Object.freeze([]),
      tiebreakCandidateIds: Object.freeze([]),
      unfilledSeats: seats
    });
  }

  const qualified = positive.filter((candidate) => {
    if (threshold === null) {
      return true;
    }
    return candidate.votes / decisionDenominator > threshold;
  });

  if (qualified.length === 0) {
    return Object.freeze({
      status: "NO_SELECTION",
      reason: "THRESHOLD_NOT_MET",
      selectedCandidateIds: Object.freeze([]),
      tiebreakCandidateIds: Object.freeze([]),
      unfilledSeats: seats
    });
  }

  if (qualified.length <= seats) {
    const selectedCandidateIds = qualified.map(
      (candidate) => candidate.candidateId
    );
    const unfilledSeats = seats - qualified.length;
    return Object.freeze({
      status: unfilledSeats === 0 ? "SELECTED" : "PARTIAL_SELECTION",
      reason:
        unfilledSeats === 0 ? "TOP_K" : "INSUFFICIENT_QUALIFIED_CANDIDATES",
      selectedCandidateIds: Object.freeze(selectedCandidateIds),
      tiebreakCandidateIds: Object.freeze([]),
      unfilledSeats
    });
  }

  const cutoffCandidate = qualified[seats - 1];
  invariant(
    cutoffCandidate !== undefined,
    "INVALID_RULE",
    "No se pudo determinar el límite de plazas."
  );
  const cutoffVotes = cutoffCandidate.votes;
  const selectedAboveCutoff = qualified.filter(
    (candidate) => candidate.votes > cutoffVotes
  );
  const atCutoff = qualified.filter(
    (candidate) => candidate.votes === cutoffVotes
  );
  const remainingSeats = seats - selectedAboveCutoff.length;

  if (atCutoff.length > remainingSeats) {
    return Object.freeze({
      status: "TIEBREAK_REQUIRED",
      reason: "CUTOFF_TIE",
      selectedCandidateIds: Object.freeze(
        selectedAboveCutoff.map((candidate) => candidate.candidateId)
      ),
      tiebreakCandidateIds: Object.freeze(
        atCutoff.map((candidate) => candidate.candidateId).sort(compareIdentifiers)
      ),
      unfilledSeats: remainingSeats
    });
  }

  return Object.freeze({
    status: "SELECTED",
    reason: "TOP_K",
    selectedCandidateIds: Object.freeze(
      [...selectedAboveCutoff, ...atCutoff].map(
        (candidate) => candidate.candidateId
      )
    ),
    tiebreakCandidateIds: Object.freeze([]),
    unfilledSeats: 0
  });
}
