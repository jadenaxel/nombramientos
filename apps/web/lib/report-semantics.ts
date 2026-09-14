export type ReportOrganizationRecord = {
  readonly id: string;
  readonly vacancyId: string;
  readonly departmentId: string;
  readonly officeId: string;
  readonly status: string;
  readonly memberId?: string;
  readonly memberSnapshot?: unknown;
  readonly displayName?: string;
  readonly shortId?: string;
  readonly linkedToId?: string | null;
};

export type OrganizationFilters = {
  readonly departmentId: string;
  readonly officeId: string;
  readonly memberId: string;
  readonly state: string;
};

/**
 * Applies report filters only against immutable identifiers from the cycle
 * snapshot. Translated or subsequently renamed labels are presentation data.
 */
export function filterOrganizationByStableIds<T extends ReportOrganizationRecord>(
  items: readonly T[],
  filters: OrganizationFilters,
): readonly T[] {
  return items.filter((item) =>
    (filters.departmentId === "all" || item.departmentId === filters.departmentId)
    && (filters.officeId === "all" || item.officeId === filters.officeId)
    && (filters.memberId === "all" || item.memberId === filters.memberId)
    && (filters.state === "all"
      || (filters.state === "proposal" && ["recommended", "accepted", "elected"].includes(item.status))
      || item.status === filters.state));
}

/**
 * A board proposal remains historically true after a later election, but its
 * preliminary export must never relabel that earlier stage as congregational.
 */
export function projectOrganizationStage<T extends ReportOrganizationRecord>(
  items: readonly T[],
  stage: string,
): readonly T[] {
  if (stage === "elected") return items.filter((item) => item.status === "elected");
  if (stage !== "proposal") return items;
  return items
    .filter((item) => ["recommended", "accepted", "elected"].includes(item.status))
    .map((item) => ({ ...item, status: item.status === "recommended" ? "recommended" : "accepted" }));
}

/**
 * Church-facing snapshots must never recover preliminary identities. The API
 * already projects this boundary; repeating it in the client is intentional
 * defence in depth for locally generated files.
 */
export function organizationForReportAudience<T extends ReportOrganizationRecord>(
  items: readonly T[],
  audience: "committee" | "auditor" | "church",
): readonly T[] {
  if (audience !== "church") return items;
  return items.map((item) => ["recommended", "accepted"].includes(item.status)
    ? {
        ...item,
        status: "vacant",
        memberId: undefined,
        memberSnapshot: undefined,
        displayName: undefined,
        shortId: undefined,
      }
    : item);
}

export type CountRatio = {
  readonly count: number;
  readonly denominator: number;
  readonly percent: number | null;
};

export function countRatio(count: number, denominator: number): CountRatio {
  return {
    count,
    denominator,
    percent: denominator === 0 ? null : Number(((count / denominator) * 100).toFixed(2)),
  };
}

export type CommitteeParticipationEntry = {
  readonly roundId: string;
  readonly identityId: string;
  readonly canSubmit: boolean;
  readonly recused: boolean;
  readonly status: string;
};

export type CommitteeAttendanceSession = {
  readonly sessionId: string;
  readonly attendance: readonly {
    readonly identityId: string;
    readonly presenceStatus: "PRESENT" | "REMOTE" | "ABSENT" | "EXCUSED";
  }[];
};

export type CommitteeParticipationSummary = {
  readonly steps: CountRatio;
  readonly pendingSteps: number;
  readonly recusedSteps: number;
  readonly notRequiredSteps: number;
  readonly attendance: CountRatio;
  readonly absentSessions: number;
  readonly excusedSessions: number;
  readonly unrecordedSessions: number;
};

/** Counts completion and attendance only. Candidate selections never enter. */
export function summarizeCommitteeParticipation(
  identityId: string,
  participation: readonly CommitteeParticipationEntry[],
  attendanceSessions: readonly CommitteeAttendanceSession[],
): CommitteeParticipationSummary {
  const identitySteps = participation.filter((entry) => entry.identityId === identityId);
  const required = identitySteps.filter((entry) => entry.canSubmit && !entry.recused);
  const received = required.filter((entry) => entry.status === "received").length;
  const recusedSteps = identitySteps.filter((entry) => entry.recused || entry.status === "recused").length;
  const notRequiredSteps = identitySteps.filter((entry) => !entry.canSubmit && !entry.recused).length;
  const attendance = attendanceSessions.flatMap((session) =>
    session.attendance.filter((entry) => entry.identityId === identityId));
  const attended = attendance.filter((entry) => entry.presenceStatus === "PRESENT" || entry.presenceStatus === "REMOTE").length;
  return {
    steps: countRatio(received, required.length),
    pendingSteps: required.length - received,
    recusedSteps,
    notRequiredSteps,
    attendance: countRatio(attended, attendanceSessions.length),
    absentSessions: attendance.filter((entry) => entry.presenceStatus === "ABSENT").length,
    excusedSessions: attendance.filter((entry) => entry.presenceStatus === "EXCUSED").length,
    unrecordedSessions: Math.max(0, attendanceSessions.length - attendance.length),
  };
}

export type ResponsibilityGroup<T extends ReportOrganizationRecord> = {
  readonly memberId: string;
  readonly displayName?: string;
  readonly count: number;
  readonly responsibilities: readonly T[];
};

/**
 * Identity is always memberId. Names and short IDs are mutable/non-unique and
 * are therefore labels only; linked nominal functions do not inflate load.
 */
export function groupIndependentResponsibilities<T extends ReportOrganizationRecord>(
  items: readonly T[],
): readonly ResponsibilityGroup<T>[] {
  const groups = new Map<string, { displayName?: string; responsibilities: T[] }>();
  for (const item of items) {
    if (!item.memberId || item.linkedToId) continue;
    const current = groups.get(item.memberId) ?? { responsibilities: [] };
    current.displayName ??= item.displayName;
    current.responsibilities.push(item);
    groups.set(item.memberId, current);
  }
  return [...groups.entries()].map(([memberId, value]) => ({
    memberId,
    displayName: value.displayName,
    count: value.responsibilities.length,
    responsibilities: value.responsibilities,
  }));
}

export type EligibleReportMember = {
  readonly memberId: string;
  readonly eligibilityStatus: string;
  readonly consideredCount: number;
  readonly assignedCount: number;
};

export type AssignmentForEligibilityReport = {
  readonly memberId: string;
  readonly state: string;
};

const ELECTED_ASSIGNMENT_STATES = new Set([
  "ELEGIDA_POR_IGLESIA",
  "VIGENTE",
  "FINALIZADA",
  "SUSTITUIDA",
]);

export function classifyEligiblePeople(
  members: readonly EligibleReportMember[],
  assignments: readonly AssignmentForEligibilityReport[],
  memberId: string,
): {
  readonly unconsidered: readonly EligibleReportMember[];
  readonly withoutRecommendation: readonly EligibleReportMember[];
  readonly withoutElectedOffice: readonly EligibleReportMember[];
} {
  const eligible = members.filter((member) => member.eligibilityStatus === "eligible"
    && (memberId === "all" || member.memberId === memberId));
  const recommendedMemberIds = new Set(assignments.map((assignment) => assignment.memberId));
  const electedMemberIds = new Set(assignments
    .filter((assignment) => ELECTED_ASSIGNMENT_STATES.has(assignment.state))
    .map((assignment) => assignment.memberId));
  return {
    unconsidered: eligible.filter((member) => member.consideredCount === 0),
    withoutRecommendation: eligible.filter((member) => !recommendedMemberIds.has(member.memberId)),
    withoutElectedOffice: eligible.filter((member) => !electedMemberIds.has(member.memberId)),
  };
}

export type ComparableCycleSnapshot = {
  readonly cycle: null | {
    readonly id: string;
    readonly name: string;
    readonly termStart: string;
    readonly termEnd: string;
    readonly status: string;
    readonly version: number;
  };
  readonly metrics: null | {
    readonly vacanciesTotal: number;
    readonly recommended?: number;
    readonly accepted?: number;
    readonly congregationallyElected: number;
  };
};

export type CycleComparison = {
  readonly cycle: NonNullable<ComparableCycleSnapshot["cycle"]>;
  readonly metrics: NonNullable<ComparableCycleSnapshot["metrics"]> & { readonly coveragePercent: number | null };
  readonly previousCycleName?: string;
  readonly deltas?: {
    readonly vacanciesTotal: number;
    readonly recommended?: number;
    readonly accepted?: number;
    readonly congregationallyElected: number;
    readonly coveragePercent: number | null;
  };
};

function comparableCoverage(metrics: NonNullable<ComparableCycleSnapshot["metrics"]>): number | null {
  const numerator = metrics.recommended ?? metrics.congregationallyElected;
  return countRatio(numerator, metrics.vacanciesTotal).percent;
}

export function compareCycleSnapshots(
  snapshots: readonly ComparableCycleSnapshot[],
  cycleId: string,
  term: string,
): readonly CycleComparison[] {
  const unique = new Map<string, ComparableCycleSnapshot>();
  for (const snapshot of snapshots) if (snapshot.cycle && snapshot.metrics) unique.set(snapshot.cycle.id, snapshot);
  const ordered = [...unique.values()]
    .filter((snapshot) => snapshot.cycle
      && (cycleId === "all" || snapshot.cycle.id === cycleId)
      && (term === "all" || `${snapshot.cycle.termStart}—${snapshot.cycle.termEnd}` === term))
    .sort((left, right) => right.cycle!.termStart.localeCompare(left.cycle!.termStart)
      || right.cycle!.termEnd.localeCompare(left.cycle!.termEnd)
      || left.cycle!.id.localeCompare(right.cycle!.id));
  return ordered.map((snapshot, index) => {
    const cycle = snapshot.cycle!;
    const metrics = snapshot.metrics!;
    const coveragePercent = comparableCoverage(metrics);
    const previous = ordered[index + 1];
    if (!previous?.cycle || !previous.metrics) return { cycle, metrics: { ...metrics, coveragePercent } };
    const previousCoverage = comparableCoverage(previous.metrics);
    return {
      cycle,
      metrics: { ...metrics, coveragePercent },
      previousCycleName: previous.cycle.name,
      deltas: {
        vacanciesTotal: metrics.vacanciesTotal - previous.metrics.vacanciesTotal,
        ...(metrics.recommended !== undefined && previous.metrics.recommended !== undefined
          ? { recommended: metrics.recommended - previous.metrics.recommended }
          : {}),
        ...(metrics.accepted !== undefined && previous.metrics.accepted !== undefined
          ? { accepted: metrics.accepted - previous.metrics.accepted }
          : {}),
        congregationallyElected: metrics.congregationallyElected - previous.metrics.congregationallyElected,
        coveragePercent: coveragePercent === null || previousCoverage === null
          ? null
          : Number((coveragePercent - previousCoverage).toFixed(2)),
      },
    };
  });
}
