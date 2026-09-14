import type { DashboardData, Locale, OrganizationRecord } from "./api.ts";
import { organizationWorkload } from "./organization-model.ts";

function localizedName(names: Partial<Record<Locale, string>> | undefined, locale: Locale, fallback: string): string {
  return names?.[locale]?.trim() || names?.es?.trim() || names?.en?.trim() || names?.fr?.trim() || fallback;
}

export function analyticsPercent(value: number, denominator: number): number | null {
  if (denominator <= 0) return null;
  return Number(((value / denominator) * 100).toFixed(2));
}

export function roundParticipationRows(data: DashboardData, locale: Locale) {
  return (data.analytics?.roundParticipation ?? []).map((round) => ({
    ...round,
    office: localizedName(round.officeNames, locale, round.officeName),
    pending: Math.max(0, round.required - round.received),
    percent: analyticsPercent(round.received, round.required),
  }));
}

export function departmentProgressRows(
  data: DashboardData,
  locale: Locale,
  uncategorizedLabel: string,
) {
  return (data.analytics?.departments ?? []).map((department) => ({
    ...department,
    department: department.departmentName
      ? localizedName(department.departmentNames ?? undefined, locale, department.departmentName)
      : uncategorizedLabel,
    pending: Math.max(0, department.vacanciesTotal - department.recommended),
  }));
}

export function sessionEvolutionRows(data: DashboardData) {
  return (data.analytics?.sessions ?? []).map((session) => ({
    ...session,
    completionPercent: analyticsPercent(session.decisions, session.agendaItems),
  }));
}

export function responsibilityDistributionRows(
  items: readonly OrganizationRecord[],
  eligibleReference: number,
) {
  const summaries = [...organizationWorkload(items).values()];
  const peopleWithIndependentLoad = summaries.filter((summary) => summary.independent > 0).length;
  const bins = [
    { key: "zero" as const, minimum: 0, maximum: 0 },
    { key: "one" as const, minimum: 1, maximum: 1 },
    { key: "two" as const, minimum: 2, maximum: 2 },
    { key: "threePlus" as const, minimum: 3, maximum: Number.POSITIVE_INFINITY },
  ];
  return bins.map((bin) => {
    const people = bin.key === "zero"
      ? Math.max(0, eligibleReference - peopleWithIndependentLoad)
      : summaries.filter((summary) => summary.independent >= bin.minimum && summary.independent <= bin.maximum).length;
    const linkedFunctions = summaries
      .filter((summary) => summary.independent >= bin.minimum && summary.independent <= bin.maximum)
      .reduce((total, summary) => total + summary.linked, 0);
    return {
      key: bin.key,
      value: people,
      linkedFunctions,
      denominator: eligibleReference,
      percent: analyticsPercent(people, eligibleReference),
    };
  });
}
