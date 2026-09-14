import {
  evaluateInternalDecision,
  type ElectionTally,
  type InternalDecisionRule,
} from "@nombramientos/domain";
import { z } from "zod";
import { CustodyError, canonicalCustodyJson, custodySha256 } from "./custody-crypto.js";

const candidateSchema = z.object({
  candidateId: z.string().uuid(),
  votes: z.number().int().min(0),
}).strict();

const decisionSchema = z.object({
  status: z.enum(["SELECTED", "PARTIAL_SELECTION", "TIEBREAK_REQUIRED", "NO_SELECTION"]),
  reason: z.enum([
    "TOP_K",
    "CUTOFF_TIE",
    "NO_VALID_CANDIDATE_VOTES",
    "THRESHOLD_NOT_MET",
    "INSUFFICIENT_QUALIFIED_CANDIDATES",
  ]),
  selectedCandidateIds: z.array(z.string().uuid()),
  tiebreakCandidateIds: z.array(z.string().uuid()),
  unfilledSeats: z.number().int().min(0),
}).strict();

const ruleSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("PLURALITY") }).strict(),
  z.object({
    kind: z.literal("STRICT_MAJORITY"),
    threshold: z.number().min(0).max(0.9999999999999999),
    denominator: z.enum(["NON_ABSTAINING_BALLOTS", "ALL_RECEIVED_BALLOTS"]),
  }).strict(),
]);

const tallyAggregateSchema = z.object({
  schemaVersion: z.literal(1),
  receivedBallots: z.number().int().min(0),
  nonAbstainingBallots: z.number().int().min(0),
  abstentions: z.number().int().min(0),
  maxSelections: z.number().int().positive(),
  candidates: z.array(candidateSchema),
  rule: ruleSchema,
  decision: decisionSchema,
}).strict();

export type TallyAggregate = z.infer<typeof tallyAggregateSchema>;

export interface TallyAggregateContext {
  readonly candidateIds: readonly string[];
  readonly receivedBallots: number;
  readonly maxSelections: number;
  readonly vacancies: number;
  readonly decisionRule: unknown;
}

export interface ValidatedTallyAggregate {
  readonly aggregate: TallyAggregate;
  readonly aggregateHash: string;
}

/**
 * Validates the custodian-produced clear aggregate without accepting any
 * candidate, total, decision, or hash on trust. Individual ballots remain
 * opaque to the server; two frozen custodians must independently attest the
 * same resulting canonical aggregate.
 */
export function validateTallyAggregate(
  input: unknown,
  context: TallyAggregateContext,
): ValidatedTallyAggregate {
  const parsed = tallyAggregateSchema.safeParse(input);
  if (!parsed.success) {
    throw invalidAggregate("Tally aggregate does not match the canonical schema");
  }
  const aggregate = parsed.data;
  assertContext(context);
  const expectedRule = ruleSchema.safeParse(context.decisionRule);
  if (!expectedRule.success) {
    throw invalidAggregate("Frozen round decision rule is invalid");
  }
  if (canonicalCustodyJson(aggregate.rule) !== canonicalCustodyJson(expectedRule.data)) {
    throw invalidAggregate("Aggregate rule differs from the decision rule frozen for the round");
  }

  const expectedCandidates = [...context.candidateIds].sort(compareIdentifiers);
  if (new Set(expectedCandidates).size !== expectedCandidates.length) {
    throw invalidAggregate("Candidate snapshot contains duplicate identifiers");
  }
  const actualCandidates = aggregate.candidates.map(({ candidateId }) => candidateId);
  if (!sameArray(actualCandidates, expectedCandidates)) {
    throw invalidAggregate("Aggregate candidates must exactly match the eligible snapshot in identifier order");
  }
  if (aggregate.receivedBallots !== context.receivedBallots) {
    throw invalidAggregate("Aggregate receivedBallots must equal the fixed manifest entry count");
  }
  if (aggregate.maxSelections !== context.maxSelections) {
    throw invalidAggregate("Aggregate maxSelections differs from the frozen round");
  }
  if (aggregate.nonAbstainingBallots + aggregate.abstentions !== aggregate.receivedBallots) {
    throw invalidAggregate("Non-abstaining ballots plus abstentions must equal received ballots");
  }
  if (aggregate.candidates.some(({ votes }) => votes > aggregate.nonAbstainingBallots)) {
    throw invalidAggregate("A candidate cannot receive more votes than non-abstaining ballots");
  }
  const selectionCount = aggregate.candidates.reduce((total, { votes }) => total + votes, 0);
  const minimumSelections = aggregate.nonAbstainingBallots;
  const maximumSelections = aggregate.nonAbstainingBallots * aggregate.maxSelections;
  if (selectionCount < minimumSelections || selectionCount > maximumSelections) {
    throw invalidAggregate("Candidate vote total is incompatible with ballot cardinality");
  }

  const tally: ElectionTally = {
    receivedBallots: aggregate.receivedBallots,
    nonAbstainingBallots: aggregate.nonAbstainingBallots,
    abstentions: aggregate.abstentions,
    maxSelections: aggregate.maxSelections,
    candidates: aggregate.candidates.map(({ candidateId, votes }) => {
      const share = aggregate.nonAbstainingBallots === 0
        ? null
        : votes / aggregate.nonAbstainingBallots;
      return {
        candidateId,
        votes,
        shareOfNonAbstaining: share,
        percentageOfNonAbstaining: share === null ? null : share * 100,
      };
    }),
  };
  const expectedDecision = evaluateInternalDecision(
    tally,
    context.vacancies,
    aggregate.rule as InternalDecisionRule,
  );
  if (canonicalCustodyJson(aggregate.decision) !== canonicalCustodyJson(expectedDecision)) {
    throw invalidAggregate("Aggregate decision does not follow the supplied validated rule and tally");
  }

  return {
    aggregate,
    aggregateHash: custodySha256(canonicalCustodyJson(aggregate)),
  };
}

function assertContext(context: TallyAggregateContext): void {
  if (
    !Number.isSafeInteger(context.receivedBallots)
    || context.receivedBallots < 0
    || !Number.isSafeInteger(context.maxSelections)
    || context.maxSelections <= 0
    || !Number.isSafeInteger(context.vacancies)
    || context.vacancies <= 0
  ) {
    throw invalidAggregate("Tally validation context is invalid");
  }
}

function sameArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function compareIdentifiers(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function invalidAggregate(message: string): CustodyError {
  return new CustodyError(400, "INVALID_TALLY_AGGREGATE", message);
}
