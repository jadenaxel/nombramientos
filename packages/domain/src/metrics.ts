import { invariant } from "./errors.js";

export interface RatioMetric {
  readonly numerator: number;
  readonly denominator: number;
  readonly ratio: number | null;
  readonly percentage: number | null;
  readonly applicable: boolean;
}

export function ratioMetric(numerator: number, denominator: number): RatioMetric {
  invariant(
    Number.isSafeInteger(numerator) && numerator >= 0,
    "INVALID_METRIC_INPUT",
    "El numerador debe ser un entero no negativo.",
    { numerator }
  );
  invariant(
    Number.isSafeInteger(denominator) && denominator >= 0,
    "INVALID_METRIC_INPUT",
    "El denominador debe ser un entero no negativo.",
    { denominator }
  );
  invariant(
    numerator <= denominator,
    "INVALID_METRIC_INPUT",
    "El numerador no puede exceder el denominador de esta métrica.",
    { numerator, denominator }
  );

  if (denominator === 0) {
    return Object.freeze({
      numerator,
      denominator,
      ratio: null,
      percentage: null,
      applicable: false
    });
  }

  const ratio = numerator / denominator;
  return Object.freeze({
    numerator,
    denominator,
    ratio,
    percentage: ratio * 100,
    applicable: true
  });
}

export function percentageForDisplay(
  metric: RatioMetric,
  fractionDigits = 2
): number | null {
  invariant(
    Number.isSafeInteger(fractionDigits) &&
      fractionDigits >= 0 &&
      fractionDigits <= 10,
    "INVALID_METRIC_INPUT",
    "La precisión debe ser un entero entre 0 y 10.",
    { fractionDigits }
  );
  if (metric.percentage === null) {
    return null;
  }
  const factor = 10 ** fractionDigits;
  return Math.round((metric.percentage + Number.EPSILON) * factor) / factor;
}

export type ParticipationStatus =
  | "DRAFT"
  | "FINAL_SELECTION"
  | "FINAL_ABSTENTION"
  | "ABSENT"
  | "RECUSED";

export interface ParticipationRecord {
  readonly electorId: string;
  readonly status: ParticipationStatus;
}

export interface ParticipationMetric {
  readonly response: RatioMetric;
  readonly completedElectorIds: readonly string[];
  readonly pendingElectorIds: readonly string[];
}

function compareIdentifiers(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertUnique(values: readonly string[], label: string): Set<string> {
  const set = new Set(values);
  invariant(
    set.size === values.length,
    "INVALID_METRIC_INPUT",
    `Hay ${label} repetidos.`,
    { label }
  );
  return set;
}

export function calculateParticipation(
  requiredElectorIds: readonly string[],
  records: readonly ParticipationRecord[]
): ParticipationMetric {
  const required = assertUnique(requiredElectorIds, "electores requeridos");
  const finalByElector = new Set<string>();

  for (const record of records) {
    if (
      record.status === "DRAFT" ||
      record.status === "ABSENT" ||
      record.status === "RECUSED"
    ) {
      continue;
    }
    invariant(
      required.has(record.electorId),
      "INVALID_METRIC_INPUT",
      "Una respuesta final no pertenece al padrón requerido.",
      { electorId: record.electorId }
    );
    invariant(
      !finalByElector.has(record.electorId),
      "DUPLICATE_RESPONSE",
      "Hay más de una respuesta final por elector.",
      { electorId: record.electorId }
    );
    finalByElector.add(record.electorId);
  }

  const completedElectorIds = [...finalByElector].sort(compareIdentifiers);
  const pendingElectorIds = [...required]
    .filter((electorId) => !finalByElector.has(electorId))
    .sort(compareIdentifiers);

  return Object.freeze({
    response: ratioMetric(finalByElector.size, required.size),
    completedElectorIds: Object.freeze(completedElectorIds),
    pendingElectorIds: Object.freeze(pendingElectorIds)
  });
}

export interface VacancyProgress {
  readonly vacancyId: string;
  readonly applicable: boolean;
  readonly recommendationPersonId: string | null;
  readonly accepted: boolean;
  readonly electedByChurch: boolean;
  readonly current: boolean;
}

export interface Responsibility {
  readonly responsibilityId: string;
  readonly personId: string;
  readonly independent: boolean;
  readonly linkedToResponsibilityId: string | null;
}

export interface CycleMetricsInput {
  readonly eligibleReferenceIds: readonly string[];
  /** Unión de candidatos en propuestas válidas de rondas no anuladas. */
  readonly proposedCandidateIds: readonly string[];
  readonly vacancies: readonly VacancyProgress[];
  readonly responsibilities: readonly Responsibility[];
}

export interface CycleMetrics {
  readonly vacancies: {
    readonly applicable: number;
    readonly recommended: RatioMetric;
    readonly accepted: RatioMetric;
    readonly electedByChurch: RatioMetric;
    readonly current: RatioMetric;
  };
  readonly people: {
    readonly eligibleReference: number;
    readonly considered: RatioMetric;
    readonly notConsidered: RatioMetric;
    readonly withRecommendation: RatioMetric;
    readonly withoutRecommendation: RatioMetric;
  };
  readonly load: {
    readonly nominalResponsibilities: number;
    readonly independentResponsibilities: number;
    readonly zero: number;
    readonly one: number;
    readonly two: number;
    readonly threeOrMore: number;
    readonly concentratedPersonIds: readonly string[];
  };
}

export function calculateCycleMetrics(input: CycleMetricsInput): CycleMetrics {
  const eligible = assertUnique(
    input.eligibleReferenceIds,
    "personas elegibles de referencia"
  );
  const proposed = new Set(input.proposedCandidateIds);
  for (const personId of proposed) {
    invariant(
      eligible.has(personId),
      "INVALID_METRIC_INPUT",
      "Una persona considerada no pertenece al universo elegible de referencia.",
      { personId }
    );
  }

  assertUnique(
    input.vacancies.map((vacancy) => vacancy.vacancyId),
    "vacantes"
  );
  const applicableVacancies = input.vacancies.filter(
    (vacancy) => vacancy.applicable
  );
  const recommendations = applicableVacancies.filter(
    (vacancy) => vacancy.recommendationPersonId !== null
  );

  for (const vacancy of input.vacancies) {
    invariant(
      vacancy.applicable ||
        (!vacancy.accepted &&
          !vacancy.electedByChurch &&
          !vacancy.current &&
          vacancy.recommendationPersonId === null),
      "INVALID_METRIC_INPUT",
      "Una vacante no aplicable no puede aportar resultados al ciclo.",
      { vacancyId: vacancy.vacancyId }
    );
    invariant(
      !vacancy.accepted || vacancy.recommendationPersonId !== null,
      "INVALID_METRIC_INPUT",
      "Una aceptación requiere recomendación previa.",
      { vacancyId: vacancy.vacancyId }
    );
    invariant(
      !vacancy.electedByChurch || vacancy.accepted,
      "INVALID_METRIC_INPUT",
      "Una elección por la iglesia requiere aceptación previa.",
      { vacancyId: vacancy.vacancyId }
    );
    invariant(
      !vacancy.current || vacancy.electedByChurch,
      "INVALID_METRIC_INPUT",
      "Una asignación vigente requiere elección por la iglesia.",
      { vacancyId: vacancy.vacancyId }
    );
    if (vacancy.recommendationPersonId !== null) {
      invariant(
        eligible.has(vacancy.recommendationPersonId),
        "INVALID_METRIC_INPUT",
        "La recomendación no pertenece al universo elegible.",
        {
          vacancyId: vacancy.vacancyId,
          personId: vacancy.recommendationPersonId
        }
      );
    }
  }

  assertUnique(
    input.responsibilities.map(
      (responsibility) => responsibility.responsibilityId
    ),
    "responsabilidades"
  );
  const responsibilityIds = new Set(
    input.responsibilities.map(
      (responsibility) => responsibility.responsibilityId
    )
  );
  const independentLoad = new Map<string, number>();
  for (const responsibility of input.responsibilities) {
    invariant(
      eligible.has(responsibility.personId),
      "INVALID_METRIC_INPUT",
      "Una responsabilidad pertenece a una persona fuera del universo elegible.",
      { personId: responsibility.personId }
    );
    invariant(
      responsibility.independent
        ? responsibility.linkedToResponsibilityId === null
        : responsibility.linkedToResponsibilityId !== null &&
            responsibilityIds.has(responsibility.linkedToResponsibilityId),
      "INVALID_METRIC_INPUT",
      "La relación entre responsabilidad nominal y vinculada es inconsistente.",
      { responsibilityId: responsibility.responsibilityId }
    );
    if (responsibility.independent) {
      independentLoad.set(
        responsibility.personId,
        (independentLoad.get(responsibility.personId) ?? 0) + 1
      );
    }
  }

  const recommendedPeople = new Set(
    recommendations.map((vacancy) => vacancy.recommendationPersonId as string)
  );
  let zero = 0;
  let one = 0;
  let two = 0;
  let threeOrMore = 0;
  const concentratedPersonIds: string[] = [];

  for (const personId of eligible) {
    const count = independentLoad.get(personId) ?? 0;
    if (count === 0) {
      zero += 1;
    } else if (count === 1) {
      one += 1;
    } else if (count === 2) {
      two += 1;
      concentratedPersonIds.push(personId);
    } else {
      threeOrMore += 1;
      concentratedPersonIds.push(personId);
    }
  }

  const denominator = applicableVacancies.length;
  const eligibleDenominator = eligible.size;
  const consideredCount = proposed.size;
  const acceptedCount = applicableVacancies.filter(
    (vacancy) => vacancy.accepted
  ).length;
  const electedCount = applicableVacancies.filter(
    (vacancy) => vacancy.electedByChurch
  ).length;
  const currentCount = applicableVacancies.filter(
    (vacancy) => vacancy.current
  ).length;

  return Object.freeze({
    vacancies: Object.freeze({
      applicable: denominator,
      recommended: ratioMetric(recommendations.length, denominator),
      accepted: ratioMetric(acceptedCount, denominator),
      electedByChurch: ratioMetric(electedCount, denominator),
      current: ratioMetric(currentCount, denominator)
    }),
    people: Object.freeze({
      eligibleReference: eligibleDenominator,
      considered: ratioMetric(consideredCount, eligibleDenominator),
      notConsidered: ratioMetric(
        eligibleDenominator - consideredCount,
        eligibleDenominator
      ),
      withRecommendation: ratioMetric(
        recommendedPeople.size,
        eligibleDenominator
      ),
      withoutRecommendation: ratioMetric(
        eligibleDenominator - recommendedPeople.size,
        eligibleDenominator
      )
    }),
    load: Object.freeze({
      nominalResponsibilities: input.responsibilities.length,
      independentResponsibilities: input.responsibilities.filter(
        (responsibility) => responsibility.independent
      ).length,
      zero,
      one,
      two,
      threeOrMore,
      concentratedPersonIds: Object.freeze(
        concentratedPersonIds.sort(compareIdentifiers)
      )
    })
  });
}
