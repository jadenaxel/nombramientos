import { describe, expect, it } from "vitest";
import {
  assertScenarioIntegrity,
  type ScenarioIntegrity,
} from "../scripts/real-browser-stack-guards.js";

const LOWER_CANDIDATE_ID = "10000000-0000-4000-8000-000000000001";
const HIGHER_CANDIDATE_ID = "f0000000-0000-4000-8000-000000000002";

describe("real browser-stack scenario integrity contract", () => {
  it.each([
    {
      label: "selected candidate was generated first in canonical order",
      fixtureOrder: [LOWER_CANDIDATE_ID, HIGHER_CANDIDATE_ID] as const,
      canonicalCandidates: [
        { candidateId: LOWER_CANDIDATE_ID, votes: 1 },
        { candidateId: HIGHER_CANDIDATE_ID, votes: 0 },
      ],
    },
    {
      label: "selected candidate was generated first in reverse canonical order",
      fixtureOrder: [HIGHER_CANDIDATE_ID, LOWER_CANDIDATE_ID] as const,
      canonicalCandidates: [
        { candidateId: LOWER_CANDIDATE_ID, votes: 0 },
        { candidateId: HIGHER_CANDIDATE_ID, votes: 1 },
      ],
    },
  ])("accepts a canonical aggregate when $label", ({ fixtureOrder, canonicalCandidates }) => {
    expect(() => assertScenarioIntegrity(
      scenarioIntegrity(canonicalCandidates, fixtureOrder[0]),
      fixtureOrder,
    )).not.toThrow();
  });

  it("still requires the selected candidate to own the single vote", () => {
    const row = scenarioIntegrity([
      { candidateId: LOWER_CANDIDATE_ID, votes: 1 },
      { candidateId: HIGHER_CANDIDATE_ID, votes: 0 },
    ], HIGHER_CANDIDATE_ID);
    expectScenarioCode(
      () => assertScenarioIntegrity(row, [HIGHER_CANDIDATE_ID, LOWER_CANDIDATE_ID]),
      "SCN_CANDS",
    );
  });

  it("attaches bounded stable codes without removing the safe human diagnostic", () => {
    expectScenarioCode(
      () => assertScenarioIntegrity({ ...scenarioIntegrity([
        { candidateId: LOWER_CANDIDATE_ID, votes: 1 },
        { candidateId: HIGHER_CANDIDATE_ID, votes: 0 },
      ], LOWER_CANDIDATE_ID), vote_receipts: 1 }, [LOWER_CANDIDATE_ID, HIGHER_CANDIDATE_ID]),
      "SCN_COUNT",
      "vote_receipts",
    );
  });
});

function scenarioIntegrity(
  candidates: readonly { readonly candidateId: string; readonly votes: number }[],
  selectedCandidateId: string,
): ScenarioIntegrity {
  return {
    import_jobs: 1,
    completed_import_jobs: 1,
    member_rows: 3,
    updated_member_version: 2,
    created_homonym_rows: 1,
    skipped_member_rows: 0,
    import_idempotency_records: 2,
    vote_submissions: 2,
    vote_receipts: 2,
    distinct_vote_electors: 2,
    vote_idempotency_records: 2,
    custody_sets: 1,
    custodian_snapshots: 2,
    manifests: 1,
    manifest_entries: 2,
    attestations: 2,
    published_manifests: 1,
    round_version: 4,
    round_phase: "RESULTADO_INTERNO",
    aggregate: {
      schemaVersion: 1,
      receivedBallots: 2,
      nonAbstainingBallots: 1,
      abstentions: 1,
      maxSelections: 1,
      candidates,
      rule: { kind: "PLURALITY" },
      decision: {
        status: "SELECTED",
        reason: "TOP_K",
        selectedCandidateIds: [selectedCandidateId],
        tiebreakCandidateIds: [],
        unfilledSeats: 0,
      },
    },
  };
}

function expectScenarioCode(action: () => void, code: string, messagePart?: string): void {
  try {
    action();
    throw new Error("Expected scenario integrity assertion to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    expect((error as Error & { readonly code?: string }).code).toBe(code);
    if (messagePart) expect((error as Error).message).toContain(messagePart);
  }
}
