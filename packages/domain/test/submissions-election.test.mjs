import test from "node:test";
import assert from "node:assert/strict";

import {
  DomainError,
  PERMISSIONS,
  consolidateProposals,
  createDemoReferenceFixture,
  evaluateInternalDecision,
  tallyBallots,
  validateBallotSubmission,
  validateProposalSubmission
} from "../dist/index.js";

function hasDomainCode(code) {
  return (error) => error instanceof DomainError && error.code === code;
}

const proposalPolicy = {
  roundId: "proposal-round",
  roundVersion: 1,
  processState: "PROPUESTAS_ABIERTAS",
  requiredElectorIds: ["E01", "E02"],
  allowedCandidateIds: ["A", "B", "C"],
  maxSelections: 3
};

test("proponer menos del máximo y abstenerse son respuestas finales válidas", () => {
  const actor = {
    electorId: "E01",
    permissions: new Set([PERMISSIONS.PROPOSAL_SUBMIT])
  };
  const selected = validateProposalSubmission(proposalPolicy, actor, {
    kind: "SELECTION",
    candidateIds: ["A", "B"]
  });
  const abstained = validateProposalSubmission(proposalPolicy, actor, {
    kind: "ABSTENTION"
  });
  assert.deepEqual(selected.response.candidateIds, ["A", "B"]);
  assert.equal(abstained.response.kind, "ABSTENTION");
});

test("permiso de envío no sustituye pertenecer al padrón congelado", () => {
  assert.throws(
    () =>
      validateProposalSubmission(
        proposalPolicy,
        {
          electorId: "E99",
          permissions: new Set([PERMISSIONS.PROPOSAL_SUBMIT])
        },
        { kind: "SELECTION", candidateIds: ["A"] }
      ),
    hasDomainCode("ELECTOR_NOT_REQUIRED")
  );
});

test("fase, duplicados, candidato externo y abstención combinada se rechazan", () => {
  const actor = {
    electorId: "E01",
    permissions: new Set([PERMISSIONS.PROPOSAL_SUBMIT])
  };
  assert.throws(
    () =>
      validateProposalSubmission(
        { ...proposalPolicy, processState: "DEPURACION" },
        actor,
        { kind: "SELECTION", candidateIds: ["A"] }
      ),
    hasDomainCode("ROUND_NOT_OPEN")
  );
  assert.throws(
    () =>
      validateProposalSubmission(proposalPolicy, actor, {
        kind: "SELECTION",
        candidateIds: ["A", "A"]
      }),
    hasDomainCode("DUPLICATE_CANDIDATE")
  );
  assert.throws(
    () =>
      validateProposalSubmission(proposalPolicy, actor, {
        kind: "SELECTION",
        candidateIds: ["X"]
      }),
    hasDomainCode("CANDIDATE_NOT_ALLOWED")
  );
  assert.throws(
    () =>
      validateProposalSubmission(proposalPolicy, actor, {
        kind: "ABSTENTION",
        candidateIds: ["A"]
      }),
    hasDomainCode("ABSTENTION_WITH_SELECTION")
  );
});

test("cinco proponentes producen un candidato con cinco apoyos", () => {
  const submissions = Array.from({ length: 5 }, (_, index) => ({
    electorId: `E${index + 1}`,
    response: { kind: "SELECTION", candidateIds: ["A"] }
  }));
  const aggregate = consolidateProposals(submissions);
  assert.equal(aggregate.candidates.length, 1);
  assert.equal(aggregate.candidates[0].candidateId, "A");
  assert.equal(aggregate.candidates[0].proponentCount, 5);
  assert.equal(aggregate.candidates[0].supportPercentage, 100);
});

test("la consolidación no tolera dos respuestas efectivas del mismo elector", () => {
  assert.throws(
    () =>
      consolidateProposals([
        {
          electorId: "E01",
          response: { kind: "SELECTION", candidateIds: ["A"] }
        },
        { electorId: "E01", response: { kind: "ABSTENTION" } }
      ]),
    hasDomainCode("DUPLICATE_RESPONSE")
  );
});

test("la boleta exige su propio permiso, fase y límite congelado", () => {
  const ballotPolicy = {
    ...proposalPolicy,
    processState: "VOTACION_ABIERTA",
    maxSelections: 1
  };
  assert.doesNotThrow(() =>
    validateBallotSubmission(
      ballotPolicy,
      {
        electorId: "E01",
        permissions: new Set([PERMISSIONS.BALLOT_SUBMIT])
      },
      { kind: "SELECTION", candidateIds: ["A"] }
    )
  );
  assert.throws(
    () =>
      validateBallotSubmission(
        ballotPolicy,
        {
          electorId: "E01",
          permissions: new Set([PERMISSIONS.BALLOT_SUBMIT])
        },
        { kind: "SELECTION", candidateIds: ["A", "B"] }
      ),
    hasDomainCode("INVALID_SELECTION_LIMIT")
  );
});

test("el escrutinio de referencia produce 3/2/1 y una abstención", () => {
  const fixture = createDemoReferenceFixture();
  const round = fixture.rounds[0];
  const tally = tallyBallots(
    round.candidateIds,
    round.maxBallotSelections,
    round.ballots
  );
  assert.equal(tally.receivedBallots, 7);
  assert.equal(tally.nonAbstainingBallots, 6);
  assert.equal(tally.abstentions, 1);
  assert.deepEqual(
    Object.fromEntries(tally.candidates.map((candidate) => [candidate.candidateId, candidate.votes])),
    { M001: 3, M002: 2, M003: 1 }
  );
});

test("50 % gana por pluralidad pero no supera la mayoría estricta", () => {
  const tally = tallyBallots(
    ["A", "B", "C"],
    1,
    [
      { electorId: "E1", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E2", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E3", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E4", response: { kind: "SELECTION", candidateIds: ["B"] } },
      { electorId: "E5", response: { kind: "SELECTION", candidateIds: ["B"] } },
      { electorId: "E6", response: { kind: "SELECTION", candidateIds: ["C"] } },
      { electorId: "E7", response: { kind: "ABSTENTION" } }
    ]
  );
  assert.deepEqual(
    evaluateInternalDecision(tally, 1, { kind: "PLURALITY" }),
    {
      status: "SELECTED",
      reason: "TOP_K",
      selectedCandidateIds: ["A"],
      tiebreakCandidateIds: [],
      unfilledSeats: 0
    }
  );
  assert.equal(
    evaluateInternalDecision(tally, 1, { kind: "STRICT_MAJORITY" }).status,
    "NO_SELECTION"
  );
});

test("la mayoría puede usar el denominador de abstenciones configurado", () => {
  const tally = tallyBallots(
    ["A", "B"],
    1,
    [
      { electorId: "E1", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E2", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E3", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E4", response: { kind: "SELECTION", candidateIds: ["B"] } },
      { electorId: "E5", response: { kind: "ABSTENTION" } },
      { electorId: "E6", response: { kind: "ABSTENTION" } }
    ]
  );
  assert.equal(
    evaluateInternalDecision(tally, 1, {
      kind: "STRICT_MAJORITY",
      denominator: "NON_ABSTAINING_BALLOTS"
    }).status,
    "SELECTED"
  );
  assert.equal(
    evaluateInternalDecision(tally, 1, {
      kind: "STRICT_MAJORITY",
      denominator: "ALL_RECEIVED_BALLOTS"
    }).status,
    "NO_SELECTION"
  );
});

test("un empate en el cupo crea desempate solo entre afectados", () => {
  const tally = tallyBallots(
    ["A", "B", "C"],
    1,
    [
      { electorId: "E1", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E2", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E3", response: { kind: "SELECTION", candidateIds: ["B"] } },
      { electorId: "E4", response: { kind: "SELECTION", candidateIds: ["B"] } },
      { electorId: "E5", response: { kind: "SELECTION", candidateIds: ["C"] } }
    ]
  );
  const decision = evaluateInternalDecision(tally, 1, { kind: "PLURALITY" });
  assert.equal(decision.status, "TIEBREAK_REQUIRED");
  assert.deepEqual(decision.tiebreakCandidateIds, ["A", "B"]);
  assert.deepEqual(decision.selectedCandidateIds, []);
});

test("múltiples plazas seleccionan top K y detectan empate en el último cupo", () => {
  const selectedTally = tallyBallots(
    ["A", "B", "C"],
    2,
    [
      { electorId: "E1", response: { kind: "SELECTION", candidateIds: ["A", "B"] } },
      { electorId: "E2", response: { kind: "SELECTION", candidateIds: ["A", "B"] } },
      { electorId: "E3", response: { kind: "SELECTION", candidateIds: ["A", "C"] } }
    ]
  );
  assert.deepEqual(
    evaluateInternalDecision(selectedTally, 2, { kind: "PLURALITY" })
      .selectedCandidateIds,
    ["A", "B"]
  );

  const tiedTally = tallyBallots(
    ["A", "B", "C"],
    2,
    [
      { electorId: "E1", response: { kind: "SELECTION", candidateIds: ["A", "B"] } },
      { electorId: "E2", response: { kind: "SELECTION", candidateIds: ["A", "C"] } }
    ]
  );
  const tied = evaluateInternalDecision(tiedTally, 2, { kind: "PLURALITY" });
  assert.equal(tied.status, "TIEBREAK_REQUIRED");
  assert.deepEqual(tied.selectedCandidateIds, ["A"]);
  assert.deepEqual(tied.tiebreakCandidateIds, ["B", "C"]);
  assert.equal(tied.unfilledSeats, 1);
});

test("cero votos no selecciona ni siquiera a un candidato único", () => {
  const empty = tallyBallots(
    ["A"],
    1,
    [{ electorId: "E1", response: { kind: "ABSTENTION" } }]
  );
  assert.equal(
    evaluateInternalDecision(empty, 1, { kind: "PLURALITY" }).status,
    "NO_SELECTION"
  );

  const positive = tallyBallots(
    ["A"],
    1,
    [{ electorId: "E1", response: { kind: "SELECTION", candidateIds: ["A"] } }]
  );
  assert.equal(
    evaluateInternalDecision(positive, 1, { kind: "PLURALITY" }).status,
    "SELECTED"
  );
});

test("menos candidatos calificados que plazas deja cupos pendientes", () => {
  const tally = tallyBallots(
    ["A", "B", "C"],
    3,
    [
      { electorId: "E1", response: { kind: "SELECTION", candidateIds: ["A"] } },
      { electorId: "E2", response: { kind: "SELECTION", candidateIds: ["A"] } }
    ]
  );
  const decision = evaluateInternalDecision(tally, 3, { kind: "PLURALITY" });
  assert.equal(decision.status, "PARTIAL_SELECTION");
  assert.deepEqual(decision.selectedCandidateIds, ["A"]);
  assert.equal(decision.unfilledSeats, 2);
});
