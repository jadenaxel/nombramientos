import { DomainError, invariant } from "./errors.js";

export const OFFICE_PROCESS_STATES = [
  "PENDIENTE",
  "CONFIGURADO",
  "PROPUESTAS_ABIERTAS",
  "PROPUESTAS_CERRADAS",
  "DEPURACION",
  "LISTA_CONFIRMADA",
  "VOTACION_ABIERTA",
  "VOTACION_CERRADA",
  "ESCRUTINIO",
  "RESULTADO_INTERNO",
  "RECOMENDACION_CONFIRMADA",
  "CERRADO",
  "PAUSADO",
  "SIN_CANDIDATOS",
  "DESEMPATE_PENDIENTE",
  "ANULADO",
  "VACANTE_PENDIENTE"
] as const;

export type OfficeProcessState = (typeof OFFICE_PROCESS_STATES)[number];

const STANDARD_OFFICE_TRANSITIONS: Readonly<
  Record<OfficeProcessState, readonly OfficeProcessState[]>
> = {
  PENDIENTE: ["CONFIGURADO", "ANULADO"],
  CONFIGURADO: ["PROPUESTAS_ABIERTAS", "VACANTE_PENDIENTE", "ANULADO"],
  PROPUESTAS_ABIERTAS: ["PROPUESTAS_CERRADAS", "ANULADO"],
  PROPUESTAS_CERRADAS: ["DEPURACION", "ANULADO"],
  DEPURACION: ["LISTA_CONFIRMADA", "SIN_CANDIDATOS", "ANULADO"],
  LISTA_CONFIRMADA: ["VOTACION_ABIERTA", "ANULADO"],
  VOTACION_ABIERTA: ["VOTACION_CERRADA", "ANULADO"],
  VOTACION_CERRADA: ["ESCRUTINIO", "ANULADO"],
  ESCRUTINIO: [
    "RESULTADO_INTERNO",
    "DESEMPATE_PENDIENTE",
    "VACANTE_PENDIENTE",
    "ANULADO"
  ],
  RESULTADO_INTERNO: [
    "RECOMENDACION_CONFIRMADA",
    "VACANTE_PENDIENTE",
    "ANULADO"
  ],
  RECOMENDACION_CONFIRMADA: ["CERRADO", "VACANTE_PENDIENTE", "ANULADO"],
  CERRADO: [],
  PAUSADO: [],
  SIN_CANDIDATOS: ["PROPUESTAS_ABIERTAS", "VACANTE_PENDIENTE", "ANULADO"],
  DESEMPATE_PENDIENTE: ["VOTACION_ABIERTA", "VACANTE_PENDIENTE", "ANULADO"],
  ANULADO: [],
  VACANTE_PENDIENTE: ["CONFIGURADO", "PROPUESTAS_ABIERTAS", "CERRADO", "ANULADO"]
};

const PAUSABLE_OFFICE_STATES = new Set<OfficeProcessState>([
  "PROPUESTAS_ABIERTAS",
  "PROPUESTAS_CERRADAS",
  "DEPURACION",
  "LISTA_CONFIRMADA",
  "VOTACION_ABIERTA",
  "VOTACION_CERRADA",
  "ESCRUTINIO",
  "RESULTADO_INTERNO",
  "SIN_CANDIDATOS",
  "DESEMPATE_PENDIENTE",
  "VACANTE_PENDIENTE"
]);

export interface OfficeTransitionContext {
  /** Obligatorio al salir de PAUSADO; impide reanudar en una fase diferente. */
  readonly pausedFrom?: OfficeProcessState;
}

export function canTransitionOfficeProcess(
  from: OfficeProcessState,
  to: OfficeProcessState,
  context: OfficeTransitionContext = {}
): boolean {
  if (from === to) {
    return false;
  }

  if (to === "PAUSADO") {
    return PAUSABLE_OFFICE_STATES.has(from);
  }

  if (from === "PAUSADO") {
    return context.pausedFrom === to && PAUSABLE_OFFICE_STATES.has(to);
  }

  return STANDARD_OFFICE_TRANSITIONS[from].includes(to);
}

export function assertOfficeProcessTransition(
  from: OfficeProcessState,
  to: OfficeProcessState,
  context: OfficeTransitionContext = {}
): void {
  if (!canTransitionOfficeProcess(from, to, context)) {
    throw new DomainError(
      "INVALID_STATE_TRANSITION",
      `No se permite cambiar el proceso de ${from} a ${to}.`,
      { from, to, pausedFrom: context.pausedFrom ?? null }
    );
  }
}

export const ROUND_STATES = [
  "DRAFT",
  "FROZEN",
  "OPEN",
  "CLOSED",
  "COUNTING",
  "VERIFIED",
  "PUBLISHED",
  "PAUSED",
  "INCIDENT",
  "ANNULLED"
] as const;

export type RoundState = (typeof ROUND_STATES)[number];

const ROUND_TRANSITIONS: Readonly<Record<RoundState, readonly RoundState[]>> = {
  DRAFT: ["FROZEN", "ANNULLED"],
  FROZEN: ["OPEN", "ANNULLED"],
  OPEN: ["CLOSED", "PAUSED", "ANNULLED"],
  CLOSED: ["COUNTING", "INCIDENT", "ANNULLED"],
  COUNTING: ["VERIFIED", "INCIDENT", "ANNULLED"],
  VERIFIED: ["PUBLISHED", "INCIDENT", "ANNULLED"],
  PUBLISHED: [],
  PAUSED: ["OPEN", "ANNULLED"],
  INCIDENT: ["COUNTING", "ANNULLED"],
  ANNULLED: []
};

export function assertRoundTransition(from: RoundState, to: RoundState): void {
  invariant(
    from !== to && ROUND_TRANSITIONS[from].includes(to),
    "INVALID_STATE_TRANSITION",
    `No se permite cambiar la ronda de ${from} a ${to}.`,
    { from, to }
  );
}

export const ASSIGNMENT_STATES = [
  "PROPUESTA_INTERNA",
  "ACEPTACION_PENDIENTE",
  "ACEPTADA",
  "PRESENTADA_A_IGLESIA",
  "ELEGIDA_POR_IGLESIA",
  "VIGENTE",
  "FINALIZADA",
  "DECLINADA",
  "DEVUELTA_A_COMISION",
  "RETIRADA",
  "SUSTITUIDA"
] as const;

export type AssignmentState = (typeof ASSIGNMENT_STATES)[number];

const ASSIGNMENT_TRANSITIONS: Readonly<
  Record<AssignmentState, readonly AssignmentState[]>
> = {
  PROPUESTA_INTERNA: ["ACEPTACION_PENDIENTE", "RETIRADA"],
  ACEPTACION_PENDIENTE: ["ACEPTADA", "DECLINADA", "RETIRADA"],
  ACEPTADA: ["PRESENTADA_A_IGLESIA", "DECLINADA", "RETIRADA"],
  PRESENTADA_A_IGLESIA: [
    "ELEGIDA_POR_IGLESIA",
    "DEVUELTA_A_COMISION",
    "RETIRADA"
  ],
  ELEGIDA_POR_IGLESIA: ["VIGENTE", "SUSTITUIDA"],
  VIGENTE: ["FINALIZADA", "SUSTITUIDA"],
  FINALIZADA: [],
  DECLINADA: [],
  DEVUELTA_A_COMISION: [],
  RETIRADA: [],
  SUSTITUIDA: []
};

export function assertAssignmentTransition(
  from: AssignmentState,
  to: AssignmentState
): void {
  invariant(
    from !== to && ASSIGNMENT_TRANSITIONS[from].includes(to),
    "INVALID_STATE_TRANSITION",
    `No se permite cambiar la asignación de ${from} a ${to}.`,
    { from, to }
  );
}

export const CANDIDACY_STATES = [
  "PROPOSED",
  "UNDER_REVIEW",
  "PRELIMINARY_ACCEPTED",
  "CONFIRMED_FOR_BALLOT",
  "WITHDRAWN",
  "EXCLUDED",
  "INELIGIBLE"
] as const;

export type CandidacyState = (typeof CANDIDACY_STATES)[number];

const CANDIDACY_TRANSITIONS: Readonly<
  Record<CandidacyState, readonly CandidacyState[]>
> = {
  PROPOSED: ["UNDER_REVIEW", "WITHDRAWN", "INELIGIBLE"],
  UNDER_REVIEW: [
    "PRELIMINARY_ACCEPTED",
    "CONFIRMED_FOR_BALLOT",
    "WITHDRAWN",
    "EXCLUDED",
    "INELIGIBLE"
  ],
  PRELIMINARY_ACCEPTED: [
    "CONFIRMED_FOR_BALLOT",
    "WITHDRAWN",
    "INELIGIBLE"
  ],
  CONFIRMED_FOR_BALLOT: ["WITHDRAWN", "INELIGIBLE"],
  WITHDRAWN: [],
  EXCLUDED: [],
  INELIGIBLE: []
};

export function assertCandidacyTransition(
  from: CandidacyState,
  to: CandidacyState
): void {
  invariant(
    from !== to && CANDIDACY_TRANSITIONS[from].includes(to),
    "INVALID_STATE_TRANSITION",
    `No se permite cambiar la candidatura de ${from} a ${to}.`,
    { from, to }
  );
}

export const CONSENT_STATUSES = [
  "PENDING",
  "CONTACTED",
  "ACCEPTED",
  "DECLINED",
  "WITHDRAWN"
] as const;

export type ConsentStatus = (typeof CONSENT_STATUSES)[number];

export function assertEligibleForFormalReport(consent: ConsentStatus): void {
  invariant(
    consent === "ACCEPTED",
    "CONSENT_REQUIRED",
    "La recomendación no puede incorporarse al informe formal sin aceptación.",
    { consent }
  );
}

export const CONGREGATIONAL_OUTCOMES = [
  "ELECTED",
  "RETURNED_TO_COMMITTEE",
  "NOT_ELECTED",
  "DEFERRED"
] as const;

export type CongregationalOutcome = (typeof CONGREGATIONAL_OUTCOMES)[number];

export function assignmentStateAfterCongregationalDecision(
  current: AssignmentState,
  outcome: CongregationalOutcome
): AssignmentState {
  invariant(
    current === "PRESENTADA_A_IGLESIA",
    "INVALID_CONGREGATIONAL_DECISION",
    "La decisión congregacional solo aplica a una asignación presentada.",
    { current, outcome }
  );

  switch (outcome) {
    case "ELECTED":
      return "ELEGIDA_POR_IGLESIA";
    case "RETURNED_TO_COMMITTEE":
    case "NOT_ELECTED":
      return "DEVUELTA_A_COMISION";
    case "DEFERRED":
      return "PRESENTADA_A_IGLESIA";
  }
}
