import { ApiError } from "./errors.js";

export const REPORT_TYPES = [
  "cycle_summary",
  "general_recommendations",
  "elected_board",
  "department",
  "office_round",
  "committee_participation",
  "responsibility_distribution",
  "unconsidered_unassigned",
  "progress",
  "session_minutes",
  "cycle_history",
  "audit_integrity",
  "roster_import_incidents",
] as const;

export type ReportType = (typeof REPORT_TYPES)[number];
export type ReportAudience = "committee" | "auditor" | "church";
export type ReportScope = `${ReportType}:${ReportAudience}`;

type ReportPolicy = {
  readonly audiences: readonly ReportAudience[];
  readonly permissions: readonly string[];
};

const ORGANIZATION_PERMISSIONS = ["aggregate.read", "organigram.read"] as const;

export const REPORT_POLICIES: Readonly<Record<ReportType, ReportPolicy>> = {
  cycle_summary: { audiences: ["committee", "auditor", "church"], permissions: ["aggregate.read"] },
  general_recommendations: { audiences: ["committee", "auditor", "church"], permissions: ORGANIZATION_PERMISSIONS },
  elected_board: { audiences: ["committee", "auditor", "church"], permissions: ORGANIZATION_PERMISSIONS },
  department: { audiences: ["committee", "auditor", "church"], permissions: ORGANIZATION_PERMISSIONS },
  office_round: { audiences: ["committee", "auditor"], permissions: ["aggregate.read"] },
  committee_participation: { audiences: ["committee", "auditor"], permissions: ["member.read", "participation.nominal.read"] },
  responsibility_distribution: { audiences: ["committee", "auditor"], permissions: ORGANIZATION_PERMISSIONS },
  unconsidered_unassigned: { audiences: ["committee", "auditor"], permissions: ["member.read", ...ORGANIZATION_PERMISSIONS] },
  progress: { audiences: ["committee", "auditor", "church"], permissions: ORGANIZATION_PERMISSIONS },
  session_minutes: { audiences: ["committee", "auditor", "church"], permissions: ["aggregate.read"] },
  cycle_history: { audiences: ["committee", "auditor", "church"], permissions: ["aggregate.read"] },
  audit_integrity: { audiences: ["committee", "auditor"], permissions: ["audit.read"] },
  roster_import_incidents: { audiences: ["committee"], permissions: ["member.read", "member.import"] },
};

export function requiredReportPermissions(reportType: ReportType, audience: ReportAudience): readonly string[] {
  const policy = REPORT_POLICIES[reportType];
  if (!policy.audiences.includes(audience)) {
    throw new ApiError(400, "REPORT_AUDIENCE_INVALID", "The requested report is not available for that audience");
  }
  return policy.permissions;
}

export function accessibleReportTypes(permissions: ReadonlySet<string>): readonly ReportType[] {
  return REPORT_TYPES.filter((reportType) =>
    REPORT_POLICIES[reportType].permissions.every((permission) => permissions.has(permission)));
}

/**
 * Returns the exact type/audience pairs the current principal may read. Keeping
 * the audience in the database predicate prevents a type-only authorization
 * decision from becoming a cross-audience IDOR when policies diverge.
 */
export function accessibleReportScopes(permissions: ReadonlySet<string>): readonly ReportScope[] {
  return REPORT_TYPES.flatMap((reportType) => {
    const policy = REPORT_POLICIES[reportType];
    if (!policy.permissions.every((permission) => permissions.has(permission))) return [];
    return policy.audiences.map((audience) => `${reportType}:${audience}` as const);
  });
}

export function canAccessReport(
  permissions: ReadonlySet<string>,
  reportType: string,
  audience: string,
): reportType is ReportType {
  if (!REPORT_TYPES.includes(reportType as ReportType)) return false;
  if (!(["committee", "auditor", "church"] as const).includes(audience as ReportAudience)) return false;
  const policy = REPORT_POLICIES[reportType as ReportType];
  return policy.audiences.includes(audience as ReportAudience)
    && policy.permissions.every((permission) => permissions.has(permission));
}
