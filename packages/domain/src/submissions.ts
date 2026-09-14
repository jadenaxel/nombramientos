import { invariant } from "./errors.js";
import {
  assertPermission,
  PERMISSIONS,
  type Permission
} from "./permissions.js";
import type { OfficeProcessState } from "./states.js";

export interface SelectionResponse {
  readonly kind: "SELECTION";
  readonly candidateIds: readonly string[];
}

export interface AbstentionResponse {
  readonly kind: "ABSTENTION";
}

export type FinalResponse = SelectionResponse | AbstentionResponse;

export interface SubmissionActor {
  readonly electorId: string;
  readonly permissions: ReadonlySet<Permission> | readonly Permission[];
}

export interface SubmissionRoundPolicy {
  readonly roundId: string;
  readonly roundVersion: number;
  readonly processState: OfficeProcessState;
  readonly requiredElectorIds: readonly string[];
  readonly allowedCandidateIds: readonly string[];
  readonly maxSelections: number;
}

export interface ValidatedFinalSubmission {
  readonly roundId: string;
  readonly roundVersion: number;
  readonly electorId: string;
  readonly response: FinalResponse;
}

function uniqueSet(
  values: readonly string[],
  label: string
): ReadonlySet<string> {
  const set = new Set(values);
  invariant(
    set.size === values.length,
    "INVALID_SNAPSHOT",
    `El snapshot contiene ${label} repetidos.`,
    { label }
  );
  return set;
}

function validatePolicy(policy: SubmissionRoundPolicy): {
  readonly electors: ReadonlySet<string>;
  readonly candidates: ReadonlySet<string>;
} {
  invariant(
    policy.roundId.length > 0 &&
      Number.isSafeInteger(policy.roundVersion) &&
      policy.roundVersion > 0,
    "INVALID_SNAPSHOT",
    "La ronda necesita identificador y versión positiva.",
    { roundId: policy.roundId, roundVersion: policy.roundVersion }
  );
  invariant(
    Number.isSafeInteger(policy.maxSelections) && policy.maxSelections > 0,
    "INVALID_SELECTION_LIMIT",
    "El máximo de selecciones debe ser un entero positivo.",
    { maxSelections: policy.maxSelections }
  );

  return {
    electors: uniqueSet(policy.requiredElectorIds, "electores"),
    candidates: uniqueSet(policy.allowedCandidateIds, "candidatos")
  };
}

export function validateFinalResponse(
  response: FinalResponse,
  allowedCandidateIds: ReadonlySet<string>,
  maxSelections: number
): FinalResponse {
  if (response.kind === "ABSTENTION") {
    const unsafeResponse = response as AbstentionResponse & {
      readonly candidateIds?: unknown;
    };
    invariant(
      unsafeResponse.candidateIds === undefined ||
        (Array.isArray(unsafeResponse.candidateIds) &&
          unsafeResponse.candidateIds.length === 0),
      "ABSTENTION_WITH_SELECTION",
      "Una abstención no puede incluir candidatos."
    );
    return Object.freeze({ kind: "ABSTENTION" });
  }

  invariant(
    Array.isArray(response.candidateIds) && response.candidateIds.length > 0,
    "EMPTY_SELECTION",
    "Una respuesta de selección debe incluir al menos un candidato."
  );
  invariant(
    response.candidateIds.length <= maxSelections,
    "INVALID_SELECTION_LIMIT",
    "La selección excede el máximo congelado de la ronda.",
    { selected: response.candidateIds.length, maxSelections }
  );

  const uniqueCandidates = new Set(response.candidateIds);
  invariant(
    uniqueCandidates.size === response.candidateIds.length,
    "DUPLICATE_CANDIDATE",
    "Una misma persona no puede seleccionarse dos veces en la boleta."
  );

  for (const candidateId of response.candidateIds) {
    invariant(
      allowedCandidateIds.has(candidateId),
      "CANDIDATE_NOT_ALLOWED",
      "La selección contiene un candidato fuera del snapshot congelado.",
      { candidateId }
    );
  }

  return Object.freeze({
    kind: "SELECTION",
    candidateIds: Object.freeze([...response.candidateIds])
  });
}

function validateSubmission(
  policy: SubmissionRoundPolicy,
  actor: SubmissionActor,
  response: FinalResponse,
  expectedState: OfficeProcessState,
  requiredPermission: Permission
): ValidatedFinalSubmission {
  assertPermission(actor.permissions, requiredPermission);
  invariant(
    policy.processState === expectedState,
    "ROUND_NOT_OPEN",
    `La ronda no está abierta para ${requiredPermission}.`,
    { expectedState, actualState: policy.processState }
  );

  const snapshot = validatePolicy(policy);
  invariant(
    snapshot.electors.has(actor.electorId),
    "ELECTOR_NOT_REQUIRED",
    "El actor no pertenece al padrón requerido congelado de la ronda.",
    { electorId: actor.electorId, roundId: policy.roundId }
  );

  return Object.freeze({
    roundId: policy.roundId,
    roundVersion: policy.roundVersion,
    electorId: actor.electorId,
    response: validateFinalResponse(
      response,
      snapshot.candidates,
      policy.maxSelections
    )
  });
}

export function validateProposalSubmission(
  policy: SubmissionRoundPolicy,
  actor: SubmissionActor,
  response: FinalResponse
): ValidatedFinalSubmission {
  return validateSubmission(
    policy,
    actor,
    response,
    "PROPUESTAS_ABIERTAS",
    PERMISSIONS.PROPOSAL_SUBMIT
  );
}

export function validateBallotSubmission(
  policy: SubmissionRoundPolicy,
  actor: SubmissionActor,
  response: FinalResponse
): ValidatedFinalSubmission {
  return validateSubmission(
    policy,
    actor,
    response,
    "VOTACION_ABIERTA",
    PERMISSIONS.BALLOT_SUBMIT
  );
}

export interface EffectiveProposalSubmission {
  readonly electorId: string;
  readonly response: FinalResponse;
}

export interface CandidateProposalAggregate {
  readonly candidateId: string;
  readonly proponentCount: number;
  readonly supportRatio: number | null;
  readonly supportPercentage: number | null;
}

export interface ProposalConsolidation {
  readonly responseCount: number;
  readonly nonEmptyProposerCount: number;
  readonly abstentionCount: number;
  readonly candidates: readonly CandidateProposalAggregate[];
}

function compareIdentifiers(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/**
 * Consolida únicamente las respuestas finales efectivas. La capa de persistencia
 * debe resolver versiones e idempotencia antes de invocar esta función.
 */
export function consolidateProposals(
  submissions: readonly EffectiveProposalSubmission[]
): ProposalConsolidation {
  const seenElectors = new Set<string>();
  const proponentsByCandidate = new Map<string, Set<string>>();
  let abstentionCount = 0;
  let nonEmptyProposerCount = 0;

  for (const submission of submissions) {
    invariant(
      !seenElectors.has(submission.electorId),
      "DUPLICATE_RESPONSE",
      "La consolidación recibió más de una respuesta efectiva del mismo elector.",
      { electorId: submission.electorId }
    );
    seenElectors.add(submission.electorId);

    if (submission.response.kind === "ABSTENTION") {
      abstentionCount += 1;
      continue;
    }

    invariant(
      submission.response.candidateIds.length > 0,
      "EMPTY_SELECTION",
      "Una propuesta efectiva no puede estar vacía."
    );
    const uniqueCandidates = new Set(submission.response.candidateIds);
    invariant(
      uniqueCandidates.size === submission.response.candidateIds.length,
      "DUPLICATE_CANDIDATE",
      "Una propuesta contiene el mismo candidato más de una vez.",
      { electorId: submission.electorId }
    );
    nonEmptyProposerCount += 1;

    for (const candidateId of uniqueCandidates) {
      const proponents = proponentsByCandidate.get(candidateId) ?? new Set<string>();
      proponents.add(submission.electorId);
      proponentsByCandidate.set(candidateId, proponents);
    }
  }

  const candidates = [...proponentsByCandidate.entries()]
    .sort(([left], [right]) => compareIdentifiers(left, right))
    .map(([candidateId, proponents]) => {
      const supportRatio =
        nonEmptyProposerCount === 0
          ? null
          : proponents.size / nonEmptyProposerCount;
      return Object.freeze({
        candidateId,
        proponentCount: proponents.size,
        supportRatio,
        supportPercentage: supportRatio === null ? null : supportRatio * 100
      });
    });

  return Object.freeze({
    responseCount: submissions.length,
    nonEmptyProposerCount,
    abstentionCount,
    candidates: Object.freeze(candidates)
  });
}
