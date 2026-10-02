export type OrganizationStage = "proposal" | "elected";

export type OrganizationItemModel = {
  readonly id: string;
  readonly memberId?: string;
  readonly officeName: string;
  readonly departmentName: string;
  readonly departmentId?: string;
  readonly status: string;
  readonly linkedToId?: string;
  readonly independent?: boolean;
  readonly displayName?: string;
};

export type OrganizationFilters = {
  readonly query: string;
  readonly department: string;
  readonly status: string;
};

export type ResponsibilitySummary = {
  readonly total: number;
  readonly independent: number;
  readonly linked: number;
  readonly responsibilities: readonly {
    readonly assignmentId: string;
    readonly officeName: string;
    readonly departmentName: string;
    readonly status: string;
    readonly linked: boolean;
  }[];
};

export type OrganizationDirectoryInsights = {
  readonly people: number;
  readonly departments: number;
  readonly appointments: number;
  readonly leadership: number;
  readonly multiRolePeople: number;
};

function searchable(value: string): string {
  return value.normalize("NFKD").replace(/[\u0300-\u036f]/gu, "").toLocaleLowerCase();
}

function responsibilityPriority(officeName: string): number {
  const value = searchable(officeName);
  if (value.startsWith("primer anciano")) return 0;
  if (value.startsWith("direccion") || value === "secretaria" || value === "tesoreria") return 1;
  if (value.startsWith("subdireccion")) return 2;
  if (value.startsWith("coordinacion") || value.startsWith("responsable")) return 3;
  if (value.startsWith("secretaria de") || value.startsWith("asistencia") || value.startsWith("asociado")) return 4;
  return 5;
}

export function filterOrganizationItems<T extends OrganizationItemModel>(
  items: readonly T[],
  filters: OrganizationFilters,
): readonly T[] {
  const query = searchable(filters.query.trim());
  return items.filter((item) => {
    if (filters.department !== "all" && item.departmentId !== filters.department && item.departmentName !== filters.department) return false;
    if (filters.status !== "all" && item.status !== filters.status) return false;
    if (!query) return true;
    return searchable(`${item.displayName ?? ""} ${item.officeName} ${item.departmentName}`).includes(query);
  });
}

export function groupOrganizationByDepartment<T extends OrganizationItemModel>(
  items: readonly T[],
  locale: string,
): readonly (readonly [string, readonly T[]])[] {
  const grouped = new Map<string, T[]>();
  for (const item of items) grouped.set(item.departmentName, [...(grouped.get(item.departmentName) ?? []), item]);
  return [...grouped.entries()]
    .map(([department, assignments]) => [
      department,
      [...assignments].sort((left, right) =>
        responsibilityPriority(left.officeName) - responsibilityPriority(right.officeName)
        || left.officeName.localeCompare(right.officeName, locale)
        || (left.displayName ?? "").localeCompare(right.displayName ?? "", locale)),
    ] as const)
    .sort(([left], [right]) => left.localeCompare(right, locale));
}

export function organizationWorkload(
  items: readonly OrganizationItemModel[],
): ReadonlyMap<string, ResponsibilitySummary> {
  const grouped = new Map<string, OrganizationItemModel[]>();
  for (const item of items) {
    if (!item.memberId) continue;
    grouped.set(item.memberId, [...(grouped.get(item.memberId) ?? []), item]);
  }
  return new Map([...grouped.entries()].map(([memberId, responsibilities]) => {
    const entries = responsibilities.map((item) => ({
      assignmentId: item.id,
      officeName: item.officeName,
      departmentName: item.departmentName,
      status: item.status,
      linked: item.independent === false || Boolean(item.linkedToId),
    }));
    const linked = entries.filter((entry) => entry.linked).length;
    return [memberId, {
      total: entries.length,
      independent: entries.length - linked,
      linked,
      responsibilities: entries,
    }] as const;
  }));
}

export function organizationTotals(items: readonly OrganizationItemModel[]): {
  readonly total: number;
  readonly occupied: number;
  readonly elected: number;
  readonly recommended: number;
  readonly independent: number;
  readonly linked: number;
} {
  return items.reduce((total, item) => ({
    total: total.total + 1,
    occupied: total.occupied + (item.memberId ? 1 : 0),
    elected: total.elected + (item.status === "elected" ? 1 : 0),
    recommended: total.recommended + (["recommended", "accepted"].includes(item.status) ? 1 : 0),
    independent: total.independent + (item.memberId && item.independent !== false && !item.linkedToId ? 1 : 0),
    linked: total.linked + (item.memberId && (item.independent === false || Boolean(item.linkedToId)) ? 1 : 0),
  }), { total: 0, occupied: 0, elected: 0, recommended: 0, independent: 0, linked: 0 });
}

export function organizationDirectoryInsights(
  items: readonly OrganizationItemModel[],
): OrganizationDirectoryInsights {
  const people = new Set(items.flatMap((item) => item.memberId ? [item.memberId] : []));
  const departments = new Set(items.map((item) => item.departmentId ?? item.departmentName));
  const workload = organizationWorkload(items);
  return {
    people: people.size,
    departments: departments.size,
    appointments: items.filter((item) => Boolean(item.memberId)).length,
    leadership: items.filter((item) => responsibilityPriority(item.officeName) <= 2).length,
    multiRolePeople: [...workload.values()].filter((summary) => summary.total > 1).length,
  };
}

export function organizationReportQuery(input: {
  readonly cycleId?: string;
  readonly departmentId?: string;
  readonly stage: OrganizationStage;
}): string {
  const parameters = new URLSearchParams({ reportType: "department_organization", organizationStage: input.stage });
  if (input.cycleId) parameters.set("cycleId", input.cycleId);
  if (input.departmentId) parameters.set("department", input.departmentId);
  return parameters.toString();
}
