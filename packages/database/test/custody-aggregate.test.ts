import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { validateTallyAggregate } from "../src/custody-aggregate.js";

const candidates = [randomUUID(), randomUUID(), randomUUID()].sort();
const context = {
  candidateIds: candidates,
  receivedBallots: 7,
  maxSelections: 2,
  vacancies: 2,
  decisionRule: { kind: "PLURALITY" },
} as const;

function validAggregate() {
  const first = candidates[0]!;
  const second = candidates[1]!;
  const third = candidates[2]!;
  return {
    schemaVersion: 1 as const,
    receivedBallots: 7,
    nonAbstainingBallots: 6,
    abstentions: 1,
    maxSelections: 2,
    candidates: [
      { candidateId: first, votes: 4 },
      { candidateId: second, votes: 3 },
      { candidateId: third, votes: 1 },
    ],
    rule: { kind: "PLURALITY" as const },
    decision: {
      status: "SELECTED" as const,
      reason: "TOP_K" as const,
      selectedCandidateIds: [first, second],
      tiebreakCandidateIds: [] as string[],
      unfilledSeats: 0,
    },
  };
}

describe("canonical custodian tally aggregate", () => {
  it("calculates one stable server hash only after validating totals, candidates, rule and decision", () => {
    const first = validateTallyAggregate(validAggregate(), context);
    const second = validateTallyAggregate(structuredClone(validAggregate()), context);
    expect(first.aggregateHash).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(second).toEqual(first);
  });

  it("rejects candidates outside, missing from, duplicated in, or out of order against the snapshot", () => {
    for (const candidateList of [
      validAggregate().candidates.slice(1),
      [...validAggregate().candidates, { candidateId: randomUUID(), votes: 0 }],
      [validAggregate().candidates[1]!, validAggregate().candidates[0]!, validAggregate().candidates[2]!],
      [validAggregate().candidates[0]!, validAggregate().candidates[0]!, validAggregate().candidates[2]!],
    ]) {
      expect(() => validateTallyAggregate({ ...validAggregate(), candidates: candidateList }, context))
        .toThrowError(expect.objectContaining({ code: "INVALID_TALLY_AGGREGATE" }));
    }
  });

  it("rejects impossible received, abstention and selection totals", () => {
    for (const aggregate of [
      { ...validAggregate(), receivedBallots: 6 },
      { ...validAggregate(), abstentions: 2 },
      {
        ...validAggregate(),
        candidates: validAggregate().candidates.map((candidate) => ({ ...candidate, votes: 7 })),
      },
    ]) {
      expect(() => validateTallyAggregate(aggregate, context))
        .toThrowError(expect.objectContaining({ code: "INVALID_TALLY_AGGREGATE" }));
    }
  });

  it("recomputes the decision and rejects forged selected, tie and unfilled fields", () => {
    const forged = validAggregate();
    forged.decision.selectedCandidateIds = [candidates[2]!];
    expect(() => validateTallyAggregate(forged, context))
      .toThrowError(expect.objectContaining({ code: "INVALID_TALLY_AGGREGATE" }));

    const tied = {
      ...validAggregate(),
      candidates: candidates.map((candidateId, index) => ({ candidateId, votes: index === 0 ? 4 : 3 })),
      decision: {
        status: "TIEBREAK_REQUIRED",
        reason: "CUTOFF_TIE",
        selectedCandidateIds: [candidates[0]!],
        tiebreakCandidateIds: [candidates[1]!, candidates[2]!],
        unfilledSeats: 1,
      },
    };
    expect(validateTallyAggregate(tied, context).aggregate.decision.status).toBe("TIEBREAK_REQUIRED");
    expect(() => validateTallyAggregate({
      ...tied,
      decision: { ...tied.decision, tiebreakCandidateIds: [candidates[2]!, candidates[1]!] },
    }, context)).toThrowError(expect.objectContaining({ code: "INVALID_TALLY_AGGREGATE" }));
  });

  it("rejects a client-selected rule that differs from the rule frozen by the round", () => {
    const changedRule = {
      ...validAggregate(),
      rule: {
        kind: "STRICT_MAJORITY",
        threshold: 0.5,
        denominator: "NON_ABSTAINING_BALLOTS",
      },
    };
    expect(() => validateTallyAggregate(changedRule, context))
      .toThrowError(expect.objectContaining({ code: "INVALID_TALLY_AGGREGATE" }));
  });
});
