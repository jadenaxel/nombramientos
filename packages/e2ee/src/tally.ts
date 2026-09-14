import {
  evaluateInternalDecision,
  tallyBallots,
  type InternalDecision,
  type InternalDecisionRule,
} from "@nombramientos/domain";
import { validateBallotPayload, validateBallotRules, type BallotPayload } from "./ballot.js";
import { E2eeError } from "./errors.js";
import { canonicalize, sha256 } from "./internal.js";

export type CanonicalTallyDecisionRule =
  | Readonly<{ kind: "PLURALITY" }>
  | Readonly<{
      kind: "STRICT_MAJORITY";
      threshold: number;
      denominator: "NON_ABSTAINING_BALLOTS" | "ALL_RECEIVED_BALLOTS";
    }>;

export interface CanonicalTallyCandidate {
  readonly candidateId: string;
  readonly votes: number;
}

export interface CanonicalTallyAggregate {
  readonly schemaVersion: 1;
  readonly receivedBallots: number;
  readonly nonAbstainingBallots: number;
  readonly abstentions: number;
  readonly maxSelections: number;
  readonly candidates: readonly CanonicalTallyCandidate[];
  readonly rule: CanonicalTallyDecisionRule;
  readonly decision: InternalDecision;
}

export function normalizeTallyDecisionRule(value: unknown): CanonicalTallyDecisionRule {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new E2eeError("TALLY_INVALID", "La regla de decisión del escrutinio no es válida.");
  }
  const input = value as Record<string, unknown>;
  if (input["kind"] === "PLURALITY" && Object.keys(input).length === 1) {
    return Object.freeze({ kind: "PLURALITY" });
  }
  if (input["kind"] !== "STRICT_MAJORITY") {
    throw new E2eeError("TALLY_INVALID", "La regla de decisión del escrutinio no es soportada.");
  }
  const allowed = new Set(["kind", "threshold", "denominator"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    throw new E2eeError("TALLY_INVALID", "La regla de decisión contiene propiedades no permitidas.");
  }
  const threshold = input["threshold"] ?? 0.5;
  const denominator = input["denominator"] ?? "NON_ABSTAINING_BALLOTS";
  if (typeof threshold !== "number" || !Number.isFinite(threshold) || threshold < 0 || threshold >= 1) {
    throw new E2eeError("TALLY_INVALID", "El umbral debe estar entre cero incluido y uno excluido.");
  }
  if (denominator !== "NON_ABSTAINING_BALLOTS" && denominator !== "ALL_RECEIVED_BALLOTS") {
    throw new E2eeError("TALLY_INVALID", "El denominador de la regla de decisión no es válido.");
  }
  return Object.freeze({ kind: "STRICT_MAJORITY", threshold, denominator });
}

export function createTallyAggregate(input: {
  readonly candidateIds: readonly string[];
  readonly minSelections: number;
  readonly maxSelections: number;
  readonly allowAbstention: boolean;
  readonly vacancies: number;
  readonly rule: unknown;
  readonly ballots: readonly unknown[];
}): CanonicalTallyAggregate {
  if (!Number.isSafeInteger(input.vacancies) || input.vacancies <= 0) {
    throw new E2eeError("TALLY_INVALID", "El número de plazas del escrutinio debe ser positivo.");
  }
  const rules = validateBallotRules({
    candidateIds: input.candidateIds,
    minSelections: input.minSelections,
    maxSelections: input.maxSelections,
    allowAbstention: input.allowAbstention,
  });
  const ballots = input.ballots.map((value) => validateBallotPayload(value, rules));
  const tally = tallyBallots(
    rules.candidateIds,
    rules.maxSelections,
    ballots.map((ballot: BallotPayload, index) => ({
      // El recibo opaco/posición del manifiesto sirve solamente para proteger la
      // unicidad durante este cálculo; nunca relaciona identidad con preferencia.
      electorId: `manifest-entry-${index + 1}`,
      response: ballot.abstain
        ? { kind: "ABSTENTION" as const }
        : { kind: "SELECTION" as const, candidateIds: ballot.selections },
    })),
  );
  const rule = normalizeTallyDecisionRule(input.rule);
  const decision = evaluateInternalDecision(tally, input.vacancies, rule as InternalDecisionRule);
  const candidates = tally.candidates
    .map(({ candidateId, votes }) => Object.freeze({ candidateId, votes }))
    .sort((left, right) => left.candidateId < right.candidateId ? -1 : left.candidateId > right.candidateId ? 1 : 0);
  return Object.freeze({
    schemaVersion: 1,
    receivedBallots: tally.receivedBallots,
    nonAbstainingBallots: tally.nonAbstainingBallots,
    abstentions: tally.abstentions,
    maxSelections: tally.maxSelections,
    candidates: Object.freeze(candidates),
    rule,
    decision,
  });
}

export async function computeTallyAggregateHash(
  aggregate: CanonicalTallyAggregate,
): Promise<`sha256:${string}`> {
  return (await sha256(canonicalize(aggregate))) as `sha256:${string}`;
}
