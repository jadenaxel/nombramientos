import {
  evaluateInternalDecision,
  tallyBallots,
  type EffectiveBallot,
  type InternalDecision
} from "./election.js";
import { invariant } from "./errors.js";
import {
  calculateCycleMetrics,
  calculateParticipation,
  percentageForDisplay,
  type CycleMetrics,
  type Responsibility,
  type VacancyProgress
} from "./metrics.js";
import {
  consolidateProposals,
  type EffectiveProposalSubmission,
  type FinalResponse,
  type ProposalConsolidation,
  type SelectionResponse
} from "./submissions.js";
import type { AssignmentState } from "./states.js";

function numericRange(first: number, last: number): readonly number[] {
  return Object.freeze(
    Array.from({ length: last - first + 1 }, (_, index) => first + index)
  );
}

function paddedId(prefix: string, value: number, width = 3): string {
  return `${prefix}${String(value).padStart(width, "0")}`;
}

function memberId(value: number): string {
  return paddedId("M", value);
}

function vacancyId(value: number): string {
  return paddedId("V", value, 2);
}

function departmentId(value: number): string {
  return paddedId("D", value, 2);
}

function selection(...candidateIds: string[]): SelectionResponse {
  return Object.freeze({
    kind: "SELECTION",
    candidateIds: Object.freeze(candidateIds)
  });
}

const ABSTENTION: FinalResponse = Object.freeze({ kind: "ABSTENTION" });

function itemAt<T>(values: readonly T[], index: number, label: string): T {
  const value = values[index];
  invariant(
    value !== undefined,
    "FIXTURE_INVARIANT",
    `No existe ${label} en el índice ${index}.`,
    { index, label }
  );
  return value;
}

export interface DemoMember {
  readonly memberId: string;
  readonly displayName: string;
  readonly eligibleInReferenceSnapshot: boolean;
  readonly visibleEligibilityReason: string | null;
  readonly photoAssetId: string | null;
}

export interface DemoCommitteeMember {
  readonly electorId: string;
  readonly memberId: string;
  readonly committeeRole: "CHAIR_PASTOR" | "SECRETARY" | "MEMBER";
  readonly requiredToRespond: true;
}

export interface DemoRound {
  readonly roundId: string;
  readonly vacancyId: string;
  readonly candidateIds: readonly string[];
  readonly maxProposalSelections: number;
  readonly maxBallotSelections: number;
  readonly proposalSubmissions: readonly EffectiveProposalSubmission[];
  readonly ballots: readonly EffectiveBallot[];
}

export interface DemoVacancy extends VacancyProgress {
  readonly departmentId: string;
}

export interface HistoricalCycleScenario {
  readonly cycleId: string;
  readonly termLabel: string;
  readonly scenario: "TIE" | "DECLINED_ASSIGNMENT";
  readonly assignmentState: AssignmentState | null;
}

export interface DemoScenarios {
  readonly tie: {
    readonly candidateIds: readonly string[];
    readonly ballots: readonly EffectiveBallot[];
  };
  readonly multipleSeatCutoffTie: {
    readonly seats: number;
    readonly candidateIds: readonly string[];
    readonly ballots: readonly EffectiveBallot[];
  };
  readonly firstElderResponsibilities: readonly Responsibility[];
}

export interface DemoReferenceFixture {
  readonly tenantId: "tenant-demo";
  readonly tenantLabel: "Iglesia Demostración";
  readonly cycleId: "cycle-reference";
  readonly members: readonly DemoMember[];
  readonly eligibleReferenceIds: readonly string[];
  readonly committee: readonly DemoCommitteeMember[];
  readonly vacancies: readonly DemoVacancy[];
  readonly responsibilities: readonly Responsibility[];
  readonly rounds: readonly DemoRound[];
  readonly historicalCycles: readonly HistoricalCycleScenario[];
  readonly scenarios: DemoScenarios;
}

function recommendedPersonForVacancy(index: number): string {
  invariant(
    index >= 1 && index <= 20,
    "FIXTURE_INVARIANT",
    "Solo las primeras veinte vacantes tienen recomendación.",
    { index }
  );
  if (index <= 3) {
    return memberId(1);
  }
  if (index <= 5) {
    return memberId(2);
  }
  if (index <= 7) {
    return memberId(3);
  }
  return memberId(index - 4);
}

function createReferenceRound(
  index: number,
  electorIds: readonly string[]
): DemoRound {
  const [e1, e2, e3, e4, e5, e6, e7] = numericRange(0, 6).map(
    (position) => itemAt(electorIds, position, "elector")
  );
  invariant(
    e1 !== undefined &&
      e2 !== undefined &&
      e3 !== undefined &&
      e4 !== undefined &&
      e5 !== undefined &&
      e6 !== undefined &&
      e7 !== undefined,
    "FIXTURE_INVARIANT",
    "La ronda de referencia requiere siete electores."
  );

  if (index === 1) {
    const candidates = Object.freeze([memberId(1), memberId(2), memberId(3)]);
    return Object.freeze({
      roundId: "round-v01",
      vacancyId: vacancyId(1),
      candidateIds: candidates,
      maxProposalSelections: 3,
      maxBallotSelections: 1,
      proposalSubmissions: Object.freeze([
        { electorId: e1, response: selection(candidates[0]!) },
        { electorId: e2, response: selection(candidates[0]!) },
        {
          electorId: e3,
          response: selection(candidates[0]!, candidates[1]!)
        },
        {
          electorId: e4,
          response: selection(candidates[0]!, candidates[2]!)
        },
        {
          electorId: e5,
          response: selection(candidates[1]!, candidates[2]!)
        },
        { electorId: e6, response: selection(candidates[1]!) },
        { electorId: e7, response: ABSTENTION }
      ]),
      ballots: Object.freeze([
        { electorId: e1, response: selection(candidates[0]!) },
        { electorId: e2, response: selection(candidates[0]!) },
        { electorId: e3, response: selection(candidates[0]!) },
        { electorId: e4, response: selection(candidates[1]!) },
        { electorId: e5, response: selection(candidates[1]!) },
        { electorId: e6, response: selection(candidates[2]!) },
        { electorId: e7, response: ABSTENTION }
      ])
    });
  }

  const winner = recommendedPersonForVacancy(index);
  let otherCandidates: readonly string[];
  if (index <= 14) {
    const firstNewMember = 4 + (index - 2) * 3;
    otherCandidates = Object.freeze([
      memberId(firstNewMember),
      memberId(firstNewMember + 1),
      memberId(firstNewMember + 2)
    ]);
  } else {
    otherCandidates = Object.freeze([memberId(40), memberId(41)]);
  }

  const other1 = itemAt(otherCandidates, 0, "primer candidato alterno");
  const other2 = itemAt(otherCandidates, 1, "segundo candidato alterno");
  const other3 = otherCandidates[2] ?? other2;
  const candidates = Object.freeze(
    [...new Set([winner, ...otherCandidates])].sort()
  );
  const proposalSubmissions: readonly EffectiveProposalSubmission[] =
    index <= 14
      ? Object.freeze([
          { electorId: e1, response: selection(other1) },
          { electorId: e2, response: selection(other2) },
          { electorId: e3, response: selection(other3) },
          { electorId: e4, response: selection(winner) },
          { electorId: e5, response: selection(other1, other2) },
          { electorId: e6, response: selection(winner, other3) },
          { electorId: e7, response: ABSTENTION }
        ])
      : Object.freeze([
          { electorId: e1, response: selection(winner) },
          { electorId: e2, response: selection(other1) },
          { electorId: e3, response: selection(other2) },
          { electorId: e4, response: selection(winner) },
          { electorId: e5, response: selection(winner, other1) },
          { electorId: e6, response: selection(winner, other2) },
          { electorId: e7, response: ABSTENTION }
        ]);

  return Object.freeze({
    roundId: `round-${vacancyId(index).toLowerCase()}`,
    vacancyId: vacancyId(index),
    candidateIds: candidates,
    maxProposalSelections: 3,
    maxBallotSelections: 1,
    proposalSubmissions,
    ballots: Object.freeze([
      { electorId: e1, response: selection(winner) },
      { electorId: e2, response: selection(winner) },
      { electorId: e3, response: selection(winner) },
      { electorId: e4, response: selection(winner) },
      { electorId: e5, response: selection(other1) },
      { electorId: e6, response: selection(other2) },
      { electorId: e7, response: ABSTENTION }
    ])
  });
}

function createScenarios(electorIds: readonly string[]): DemoScenarios {
  const electors = numericRange(0, 6).map((position) =>
    itemAt(electorIds, position, "elector de escenario")
  );
  const tieCandidates = Object.freeze([memberId(43), memberId(44)]);
  const multipleCandidates = Object.freeze([
    memberId(46),
    memberId(47),
    memberId(48),
    memberId(49)
  ]);

  return Object.freeze({
    tie: Object.freeze({
      candidateIds: tieCandidates,
      ballots: Object.freeze([
        { electorId: electors[0]!, response: selection(tieCandidates[0]!) },
        { electorId: electors[1]!, response: selection(tieCandidates[0]!) },
        { electorId: electors[2]!, response: selection(tieCandidates[0]!) },
        { electorId: electors[3]!, response: selection(tieCandidates[1]!) },
        { electorId: electors[4]!, response: selection(tieCandidates[1]!) },
        { electorId: electors[5]!, response: selection(tieCandidates[1]!) },
        { electorId: electors[6]!, response: ABSTENTION }
      ])
    }),
    multipleSeatCutoffTie: Object.freeze({
      seats: 2,
      candidateIds: multipleCandidates,
      ballots: Object.freeze([
        {
          electorId: electors[0]!,
          response: selection(multipleCandidates[0]!, multipleCandidates[1]!)
        },
        {
          electorId: electors[1]!,
          response: selection(multipleCandidates[0]!, multipleCandidates[2]!)
        },
        {
          electorId: electors[2]!,
          response: selection(multipleCandidates[1]!, multipleCandidates[2]!)
        },
        {
          electorId: electors[3]!,
          response: selection(multipleCandidates[0]!, multipleCandidates[3]!)
        },
        {
          electorId: electors[4]!,
          response: selection(multipleCandidates[1]!, multipleCandidates[3]!)
        },
        {
          electorId: electors[5]!,
          response: selection(multipleCandidates[2]!, multipleCandidates[3]!)
        },
        { electorId: electors[6]!, response: ABSTENTION }
      ])
    }),
    firstElderResponsibilities: Object.freeze([
      {
        responsibilityId: "elder-base",
        personId: memberId(20),
        independent: true,
        linkedToResponsibilityId: null
      },
      {
        responsibilityId: "first-elder-linked",
        personId: memberId(20),
        independent: false,
        linkedToResponsibilityId: "elder-base"
      }
    ])
  });
}

export function createDemoReferenceFixture(): DemoReferenceFixture {
  const members: readonly DemoMember[] = Object.freeze(
    numericRange(1, 180).map((index) => {
      const eligible = index <= 150;
      return Object.freeze({
        memberId: memberId(index),
        displayName:
          index === 50 || index === 51
            ? "Alex Rivera"
            : `Miembro Demo ${String(index).padStart(3, "0")}`,
        eligibleInReferenceSnapshot: eligible,
        visibleEligibilityReason: eligible
          ? null
          : "No disponible para servir durante este ciclo de demostración.",
        photoAssetId: index % 12 === 0 ? `photo-demo-${index}` : null
      });
    })
  );
  const eligibleReferenceIds = Object.freeze(
    members
      .filter((member) => member.eligibleInReferenceSnapshot)
      .map((member) => member.memberId)
  );
  const committee: readonly DemoCommitteeMember[] = Object.freeze(
    numericRange(1, 7).map((index) =>
      Object.freeze({
        electorId: paddedId("E", index, 2),
        memberId: memberId(100 + index),
        committeeRole:
          index === 1
            ? ("CHAIR_PASTOR" as const)
            : index === 2
              ? ("SECRETARY" as const)
              : ("MEMBER" as const),
        requiredToRespond: true as const
      })
    )
  );
  const electorIds = Object.freeze(
    committee.map((member) => member.electorId)
  );
  const vacancies: readonly DemoVacancy[] = Object.freeze(
    numericRange(1, 40).map((index) => {
      const recommended = index <= 20;
      return Object.freeze({
        vacancyId: vacancyId(index),
        departmentId: departmentId(Math.ceil(index / 5)),
        applicable: true,
        recommendationPersonId: recommended
          ? recommendedPersonForVacancy(index)
          : null,
        accepted: index <= 15,
        electedByChurch: index <= 10,
        current: false
      });
    })
  );
  const responsibilities: readonly Responsibility[] = Object.freeze(
    vacancies
      .filter((vacancy) => vacancy.recommendationPersonId !== null)
      .map((vacancy) =>
        Object.freeze({
          responsibilityId: `responsibility-${vacancy.vacancyId.toLowerCase()}`,
          personId: vacancy.recommendationPersonId as string,
          independent: true,
          linkedToResponsibilityId: null
        })
      )
  );
  const rounds = Object.freeze(
    numericRange(1, 20).map((index) =>
      createReferenceRound(index, electorIds)
    )
  );

  return Object.freeze({
    tenantId: "tenant-demo",
    tenantLabel: "Iglesia Demostración",
    cycleId: "cycle-reference",
    members,
    eligibleReferenceIds,
    committee,
    vacancies,
    responsibilities,
    rounds,
    historicalCycles: Object.freeze([
      Object.freeze({
        cycleId: "cycle-historical-tie",
        termLabel: "2023-2024",
        scenario: "TIE" as const,
        assignmentState: null
      }),
      Object.freeze({
        cycleId: "cycle-historical-declined",
        termLabel: "2025-2026",
        scenario: "DECLINED_ASSIGNMENT" as const,
        assignmentState: "DECLINADA" as const
      })
    ]),
    scenarios: createScenarios(electorIds)
  });
}

export interface DemoReferenceAnalysis {
  readonly proposal: ProposalConsolidation;
  readonly proposalParticipationPercentage: number | null;
  readonly tally: ReturnType<typeof tallyBallots>;
  readonly plurality: InternalDecision;
  readonly strictMajority: InternalDecision;
  readonly metrics: CycleMetrics;
}

export function analyzeDemoReferenceFixture(
  fixture: DemoReferenceFixture = createDemoReferenceFixture()
): DemoReferenceAnalysis {
  const firstRound = fixture.rounds.find(
    (round) => round.vacancyId === vacancyId(1)
  );
  invariant(
    firstRound !== undefined,
    "FIXTURE_INVARIANT",
    "Falta la ronda V01 del fixture de referencia."
  );
  const proposal = consolidateProposals(firstRound.proposalSubmissions);
  const tally = tallyBallots(
    firstRound.candidateIds,
    firstRound.maxBallotSelections,
    firstRound.ballots
  );
  const proposedCandidateIds = fixture.rounds.flatMap((round) =>
    round.proposalSubmissions.flatMap((submission) =>
      submission.response.kind === "SELECTION"
        ? submission.response.candidateIds
        : []
    )
  );
  const participation = calculateParticipation(
    fixture.committee.map((member) => member.electorId),
    firstRound.proposalSubmissions.map((submission) => ({
      electorId: submission.electorId,
      status:
        submission.response.kind === "ABSTENTION"
          ? ("FINAL_ABSTENTION" as const)
          : ("FINAL_SELECTION" as const)
    }))
  );

  return Object.freeze({
    proposal,
    proposalParticipationPercentage: percentageForDisplay(
      participation.response
    ),
    tally,
    plurality: evaluateInternalDecision(tally, 1, { kind: "PLURALITY" }),
    strictMajority: evaluateInternalDecision(tally, 1, {
      kind: "STRICT_MAJORITY"
    }),
    metrics: calculateCycleMetrics({
      eligibleReferenceIds: fixture.eligibleReferenceIds,
      proposedCandidateIds,
      vacancies: fixture.vacancies,
      responsibilities: fixture.responsibilities
    })
  });
}

export const DEMO_REFERENCE_EXPECTED = Object.freeze({
  members: 180,
  eligible: 150,
  requiredElectors: 7,
  proposalResponses: 7,
  nonEmptyProposers: 6,
  proposalAbstentions: 1,
  proposalCounts: Object.freeze({ M001: 4, M002: 3, M003: 2 }),
  proposalPercentages: Object.freeze({
    M001: 66.67,
    M002: 50,
    M003: 33.33
  }),
  receivedBallots: 7,
  nonAbstainingBallots: 6,
  ballotAbstentions: 1,
  ballotCounts: Object.freeze({ M001: 3, M002: 2, M003: 1 }),
  ballotPercentages: Object.freeze({ M001: 50, M002: 33.33, M003: 16.67 }),
  applicableVacancies: 40,
  recommendedVacancies: 20,
  acceptedVacancies: 15,
  electedVacancies: 10,
  consideredPeople: 42,
  notConsideredPeople: 108,
  uniqueRecommendedPeople: 16,
  withoutRecommendationPeople: 134,
  independentResponsibilities: 20,
  loadZero: 134,
  loadOne: 13,
  loadTwo: 2,
  loadThreeOrMore: 1,
  concentrationAlerts: 3
});

export function assertDemoReferenceFixture(
  fixture: DemoReferenceFixture = createDemoReferenceFixture()
): void {
  const analysis = analyzeDemoReferenceFixture(fixture);
  const expected = DEMO_REFERENCE_EXPECTED;
  const candidateProposal = new Map(
    analysis.proposal.candidates.map((candidate) => [candidate.candidateId, candidate])
  );
  const candidateTally = new Map(
    analysis.tally.candidates.map((candidate) => [candidate.candidateId, candidate])
  );
  const checks: readonly [string, number | string, number | string][] = [
    ["members", fixture.members.length, expected.members],
    ["eligible", fixture.eligibleReferenceIds.length, expected.eligible],
    ["requiredElectors", fixture.committee.length, expected.requiredElectors],
    ["proposalResponses", analysis.proposal.responseCount, expected.proposalResponses],
    [
      "nonEmptyProposers",
      analysis.proposal.nonEmptyProposerCount,
      expected.nonEmptyProposers
    ],
    ["receivedBallots", analysis.tally.receivedBallots, expected.receivedBallots],
    [
      "nonAbstainingBallots",
      analysis.tally.nonAbstainingBallots,
      expected.nonAbstainingBallots
    ],
    [
      "M001 proposal count",
      candidateProposal.get("M001")?.proponentCount ?? -1,
      expected.proposalCounts.M001
    ],
    [
      "M002 proposal count",
      candidateProposal.get("M002")?.proponentCount ?? -1,
      expected.proposalCounts.M002
    ],
    [
      "M003 proposal count",
      candidateProposal.get("M003")?.proponentCount ?? -1,
      expected.proposalCounts.M003
    ],
    [
      "M001 ballot count",
      candidateTally.get("M001")?.votes ?? -1,
      expected.ballotCounts.M001
    ],
    [
      "recommendedVacancies",
      analysis.metrics.vacancies.recommended.numerator,
      expected.recommendedVacancies
    ],
    [
      "acceptedVacancies",
      analysis.metrics.vacancies.accepted.numerator,
      expected.acceptedVacancies
    ],
    [
      "electedVacancies",
      analysis.metrics.vacancies.electedByChurch.numerator,
      expected.electedVacancies
    ],
    [
      "consideredPeople",
      analysis.metrics.people.considered.numerator,
      expected.consideredPeople
    ],
    [
      "notConsideredPeople",
      analysis.metrics.people.notConsidered.numerator,
      expected.notConsideredPeople
    ],
    [
      "withoutRecommendationPeople",
      analysis.metrics.people.withoutRecommendation.numerator,
      expected.withoutRecommendationPeople
    ],
    [
      "independentResponsibilities",
      analysis.metrics.load.independentResponsibilities,
      expected.independentResponsibilities
    ],
    [
      "concentrationAlerts",
      analysis.metrics.load.concentratedPersonIds.length,
      expected.concentrationAlerts
    ],
    ["plurality", analysis.plurality.status, "SELECTED"],
    ["strictMajority", analysis.strictMajority.status, "NO_SELECTION"]
  ];

  for (const [label, actual, wanted] of checks) {
    invariant(
      actual === wanted,
      "FIXTURE_INVARIANT",
      `El fixture no satisface ${label}.`,
      { label, actual, expected: wanted }
    );
  }
}
