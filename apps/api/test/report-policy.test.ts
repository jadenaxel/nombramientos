import { describe, expect, it } from "vitest";
import {
  accessibleReportScopes,
  accessibleReportTypes,
  canAccessReport,
  REPORT_POLICIES,
  REPORT_TYPES,
  requiredReportPermissions,
} from "../src/lib/report-policy.js";

describe("report policy", () => {
  it("defines the twelve required institutional reports plus the operational summary", () => {
    expect(REPORT_TYPES).toHaveLength(13);
    expect(new Set(REPORT_TYPES)).toHaveLength(13);
    expect(REPORT_TYPES.filter((value) => value !== "cycle_summary")).toHaveLength(12);
  });

  it("keeps roster and import incidents restricted to committee administrators", () => {
    expect(REPORT_POLICIES.roster_import_incidents.audiences).toEqual(["committee"]);
    expect(requiredReportPermissions("roster_import_incidents", "committee")).toEqual(["member.read", "member.import"]);
  });

  it("requires audit permission for the integrity report", () => {
    expect(requiredReportPermissions("audit_integrity", "auditor")).toEqual(["audit.read"]);
  });

  it("rejects internal round detail for the church audience", () => {
    expect(() => requiredReportPermissions("office_round", "church")).toThrowError(expect.objectContaining({
      statusCode: 400,
      code: "REPORT_AUDIENCE_INVALID",
    }));
  });

  it("filters persisted report metadata by the caller's underlying data permissions", () => {
    const auditor = accessibleReportTypes(new Set(["aggregate.read", "organigram.read", "audit.read"]));
    expect(auditor).toContain("audit_integrity");
    expect(auditor).not.toContain("committee_participation");
    expect(auditor).not.toContain("roster_import_incidents");

    const committeeMember = accessibleReportTypes(new Set(["aggregate.read", "organigram.read", "member.read"]));
    expect(committeeMember).not.toContain("audit_integrity");
    expect(committeeMember).not.toContain("committee_participation");
    expect(committeeMember).not.toContain("roster_import_incidents");
  });

  it("reevaluates exact type/audience scopes when permissions change", () => {
    const permissions = new Set(["member.read", "member.import"]);
    expect(accessibleReportScopes(permissions)).toContain("roster_import_incidents:committee");
    expect(accessibleReportScopes(permissions)).not.toContain("roster_import_incidents:auditor");
    expect(canAccessReport(permissions, "roster_import_incidents", "committee")).toBe(true);
    permissions.delete("member.import");
    expect(canAccessReport(permissions, "roster_import_incidents", "committee")).toBe(false);
    expect(canAccessReport(new Set(["aggregate.read"]), "office_round", "church")).toBe(false);
  });
});
