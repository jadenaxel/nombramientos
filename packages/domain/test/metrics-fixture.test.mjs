import test from "node:test";
import assert from "node:assert/strict";

import {
  DEMO_REFERENCE_EXPECTED,
  analyzeDemoReferenceFixture,
  calculateCycleMetrics,
  calculateParticipation,
  createDemoReferenceFixture,
  evaluateInternalDecision,
  percentageForDisplay,
  ratioMetric,
  tallyBallots
} from "../dist/index.js";

test("el fixture tiene 180 miembros, 150 elegibles y homónimos distintos", () => {
  const fixture = createDemoReferenceFixture();
  assert.equal(fixture.members.length, 180);
  assert.equal(fixture.eligibleReferenceIds.length, 150);
  const homonyms = fixture.members.filter(
    (member) => member.displayName === "Alex Rivera"
  );
  assert.equal(homonyms.length, 2);
  assert.notEqual(homonyms[0].memberId, homonyms[1].memberId);
  assert.equal(fixture.historicalCycles.length, 2);
});

test("las propuestas de referencia derivan 4/3/2 sobre seis proponentes", () => {
  const analysis = analyzeDemoReferenceFixture();
  const byCandidate = Object.fromEntries(
    analysis.proposal.candidates.map((candidate) => [
      candidate.candidateId,
      {
        count: candidate.proponentCount,
        percentage: Math.round(candidate.supportPercentage * 100) / 100
      }
    ])
  );
  assert.equal(analysis.proposal.responseCount, 7);
  assert.equal(analysis.proposal.nonEmptyProposerCount, 6);
  assert.equal(analysis.proposal.abstentionCount, 1);
  assert.equal(analysis.proposalParticipationPercentage, 100);
  assert.deepEqual(byCandidate, {
    M001: { count: 4, percentage: 66.67 },
    M002: { count: 3, percentage: 50 },
    M003: { count: 2, percentage: 33.33 }
  });
});

test("las boletas derivan 3/2/1 y 50/33,33/16,67", () => {
  const analysis = analyzeDemoReferenceFixture();
  assert.deepEqual(
    Object.fromEntries(
      analysis.tally.candidates.map((candidate) => [
        candidate.candidateId,
        {
          votes: candidate.votes,
          percentage:
            Math.round(candidate.percentageOfNonAbstaining * 100) / 100
        }
      ])
    ),
    {
      M001: { votes: 3, percentage: 50 },
      M002: { votes: 2, percentage: 33.33 },
      M003: { votes: 1, percentage: 16.67 }
    }
  );
  assert.equal(analysis.plurality.status, "SELECTED");
  assert.equal(analysis.strictMajority.status, "NO_SELECTION");
});

test("cobertura, aceptación y elección usan las 40 vacantes como denominador", () => {
  const { metrics } = analyzeDemoReferenceFixture();
  assert.deepEqual(
    [
      metrics.vacancies.recommended.numerator,
      percentageForDisplay(metrics.vacancies.recommended),
      metrics.vacancies.accepted.numerator,
      percentageForDisplay(metrics.vacancies.accepted),
      metrics.vacancies.electedByChurch.numerator,
      percentageForDisplay(metrics.vacancies.electedByChurch)
    ],
    [20, 50, 15, 37.5, 10, 25]
  );
});

test("42 consideradas dejan 108 no consideradas; 16 recomendadas dejan 134 sin recomendación", () => {
  const { metrics } = analyzeDemoReferenceFixture();
  assert.equal(metrics.people.considered.numerator, 42);
  assert.equal(metrics.people.notConsidered.numerator, 108);
  assert.equal(percentageForDisplay(metrics.people.notConsidered), 72);
  assert.equal(metrics.people.withRecommendation.numerator, 16);
  assert.equal(metrics.people.withoutRecommendation.numerator, 134);
  assert.equal(
    percentageForDisplay(metrics.people.withoutRecommendation),
    89.33
  );
});

test("la carga independiente es 134/13/2/1 y genera tres alertas", () => {
  const { metrics } = analyzeDemoReferenceFixture();
  assert.deepEqual(
    {
      responsibilities: metrics.load.independentResponsibilities,
      zero: metrics.load.zero,
      one: metrics.load.one,
      two: metrics.load.two,
      threeOrMore: metrics.load.threeOrMore,
      alerts: metrics.load.concentratedPersonIds
    },
    {
      responsibilities: 20,
      zero: 134,
      one: 13,
      two: 2,
      threeOrMore: 1,
      alerts: ["M001", "M002", "M003"]
    }
  );
});

test("una función de primer anciano vinculada no infla la carga independiente", () => {
  const fixture = createDemoReferenceFixture();
  const metrics = calculateCycleMetrics({
    eligibleReferenceIds: ["M020"],
    proposedCandidateIds: [],
    vacancies: [],
    responsibilities: fixture.scenarios.firstElderResponsibilities
  });
  assert.equal(metrics.load.nominalResponsibilities, 2);
  assert.equal(metrics.load.independentResponsibilities, 1);
  assert.equal(metrics.load.one, 1);
  assert.equal(metrics.load.concentratedPersonIds.length, 0);
});

test("denominador cero devuelve No aplica, nunca NaN o 100 %", () => {
  const metric = ratioMetric(0, 0);
  assert.equal(metric.applicable, false);
  assert.equal(metric.ratio, null);
  assert.equal(metric.percentage, null);
  assert.equal(percentageForDisplay(metric), null);
});

test("borrador, ausencia y recusación no cuentan; abstención final sí", () => {
  const participation = calculateParticipation(
    ["E01", "E02", "E03", "E04", "E05"],
    [
      { electorId: "E01", status: "DRAFT" },
      { electorId: "E02", status: "FINAL_SELECTION" },
      { electorId: "E03", status: "FINAL_ABSTENTION" },
      { electorId: "E04", status: "ABSENT" },
      { electorId: "E05", status: "RECUSED" }
    ]
  );
  assert.equal(participation.response.numerator, 2);
  assert.equal(participation.response.denominator, 5);
  assert.deepEqual(participation.pendingElectorIds, ["E01", "E04", "E05"]);
});

test("los escenarios adicionales prueban empate simple y empate de cupo múltiple", () => {
  const fixture = createDemoReferenceFixture();
  const tie = fixture.scenarios.tie;
  const tieDecision = evaluateInternalDecision(
    tallyBallots(tie.candidateIds, 1, tie.ballots),
    1,
    { kind: "PLURALITY" }
  );
  assert.equal(tieDecision.status, "TIEBREAK_REQUIRED");

  const multiple = fixture.scenarios.multipleSeatCutoffTie;
  const multipleDecision = evaluateInternalDecision(
    tallyBallots(multiple.candidateIds, 2, multiple.ballots),
    multiple.seats,
    { kind: "PLURALITY" }
  );
  assert.equal(multipleDecision.status, "TIEBREAK_REQUIRED");
  assert.equal(multipleDecision.tiebreakCandidateIds.length, 4);
  assert.equal(multipleDecision.unfilledSeats, 2);
});

test("las expectativas publicadas coinciden con el análisis, no con tarjetas fijas", () => {
  const { metrics } = analyzeDemoReferenceFixture();
  assert.equal(
    metrics.vacancies.applicable,
    DEMO_REFERENCE_EXPECTED.applicableVacancies
  );
  assert.equal(
    metrics.load.independentResponsibilities,
    DEMO_REFERENCE_EXPECTED.independentResponsibilities
  );
  assert.equal(
    metrics.load.concentratedPersonIds.length,
    DEMO_REFERENCE_EXPECTED.concentrationAlerts
  );
});
