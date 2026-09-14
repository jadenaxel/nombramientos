import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const workspaceRoot = path.resolve(import.meta.dirname, "..", "..", "..");
const document = JSON.parse(readFileSync(path.join(workspaceRoot, "docs", "api", "openapi.json"), "utf8")) as {
  paths: Record<string, Record<string, Record<string, unknown>>>;
};

describe("sensitive GET audit contract", () => {
  it("publishes stable action codes exactly where sensitive envelopes or report data are materialized", () => {
    for (const memberPath of ["/v1/members", "/v1/members/manage"]) {
      expect(document.paths[memberPath]?.["get"]?.["x-conditional-audit-actions"]).toEqual({
        "contactEnvelope materialized": "member.contact.read",
        "eligibilityEnvelope materialized": "member.private-note.read",
      });
    }
    expect(document.paths["/v1/members/{memberId}/photo"]?.["get"]?.["x-audit-action"])
      .toBe("member.photo.read");
    expect(document.paths["/v1/office-processes/{processId}/review-board"]?.["get"]?.["x-conditional-audit-actions"])
      .toEqual({
        "photoSnapshot or rationaleEnvelope materialized": "candidacy.review-material.read",
        "restrictedNoteEnvelope materialized": "candidacy.private-note.read",
      });
    expect(document.paths["/v1/reports/workflow-snapshot"]?.["get"]?.["x-conditional-audit-actions"])
      .toEqual({ "sensitive projected response materialized": "workflow-report.snapshot.read" });
    expect(document.paths["/v1/reports/{reportId}/artifact"]?.["get"]?.["x-audit-action"])
      .toBe("report.downloaded");
  });

  it("does not claim audit events for ordinary metadata and configuration reads", () => {
    for (const route of ["/v1/dashboard", "/v1/catalog", "/v1/reports", "/v1/members/{memberId}/photo/write-context"]) {
      expect(document.paths[route]?.["get"]).not.toHaveProperty("x-audit-action");
      expect(document.paths[route]?.["get"]).not.toHaveProperty("x-conditional-audit-actions");
    }
  });
});
