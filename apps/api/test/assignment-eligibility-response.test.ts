import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { throwIfAssignmentEligibilityPaused } from "../src/lib/assignment-eligibility.js";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("post-commit assignment eligibility conflicts", () => {
  it("maps the committed discriminated pause to a stable non-sensitive 409", () => {
    const pause = {
      eligibilityPaused: true,
      code: "ASSIGNMENT_ELIGIBILITY_PAUSED",
      assignmentId: "11111111-1111-4111-8111-111111111111",
      memberId: "22222222-2222-4222-8222-222222222222",
      processId: "33333333-3333-4333-8333-333333333333",
      roundId: "44444444-4444-4444-8444-444444444444",
      pauseIds: ["55555555-5555-4555-8555-555555555555"],
      processVersion: 9,
      roundVersion: 7,
      message: "Assignment eligibility changed; resolve the persisted workflow pause before advancing",
    } as const;
    expect(() => throwIfAssignmentEligibilityPaused(pause)).toThrowError(expect.objectContaining({
      statusCode: 409,
      code: "ASSIGNMENT_ELIGIBILITY_PAUSED",
      details: {
        eligibilityPaused: true,
        assignmentId: pause.assignmentId,
        processId: pause.processId,
        roundId: pause.roundId,
        pauseIds: pause.pauseIds,
        processVersion: 9,
        roundVersion: 7,
      },
    }));
    try {
      throwIfAssignmentEligibilityPaused(pause);
    } catch (error) {
      expect(JSON.stringify(error)).not.toContain(pause.memberId);
    }
  });

  it("is a no-op for a completed assignment transition", () => {
    expect(() => throwIfAssignmentEligibilityPaused({ id: "assignment", state: "ACEPTADA", version: 3 }))
      .not.toThrow();
  });

  it("translates only after the database transaction returns on all advancing routes", () => {
    const coreRoutes = readFileSync(path.join(appRoot, "src/modules/core-workflow-routes.ts"), "utf8");
    const tenantRoutes = readFileSync(path.join(appRoot, "src/modules/tenant-routes.ts"), "utf8");
    for (const source of [coreRoutes, tenantRoutes]) {
      expect(source).toMatch(/withCoreWorkflowPrincipal[\s\S]*throwIfAssignmentEligibilityPaused\(result\)/u);
    }
    expect(coreRoutes.match(/throwIfAssignmentEligibilityPaused\(result\)/gu)?.length).toBe(2);
    expect(tenantRoutes.match(/throwIfAssignmentEligibilityPaused\(result\)/gu)?.length).toBe(2);
  });

  it("documents the durable, non-sensitive 409 on every advancing assignment endpoint", () => {
    const contract = JSON.parse(readFileSync(path.resolve(appRoot, "../../docs/api/openapi.json"), "utf8")) as {
      paths: Record<string, { post?: { responses?: Record<string, { $ref?: string }> } }>;
      components: { responses: Record<string, unknown>; schemas: Record<string, unknown> };
    };
    for (const route of [
      "/v1/assignments/{assignmentId}/consent",
      "/v1/assignments/{assignmentId}/congregational-decision",
      "/v1/assignments/{assignmentId}/presentation",
      "/v1/assignments/{assignmentId}/activate",
    ]) {
      expect(contract.paths[route]?.post?.responses?.["409"]).toEqual({
        $ref: "#/components/responses/AssignmentEligibilityPaused",
      });
    }
    expect(contract.components.responses["AssignmentEligibilityPaused"]).toBeDefined();
    const schema = JSON.stringify(contract.components.schemas["AssignmentEligibilityPausedErrorResponse"]);
    expect(schema).toContain("ASSIGNMENT_ELIGIBILITY_PAUSED");
    expect(schema).not.toContain("memberId");
  });
});
