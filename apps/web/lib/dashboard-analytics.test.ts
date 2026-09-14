import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { DashboardData, OrganizationRecord } from "./api.ts";
import {
  analyticsPercent,
  departmentProgressRows,
  responsibilityDistributionRows,
  roundParticipationRows,
  sessionEvolutionRows,
} from "./dashboard-analytics.ts";

const dashboard: DashboardData = {
  tenant: { id: "tenant", name: "Iglesia", kind: "demo" },
  cycle: { id: "cycle", name: "2030", status: "active", termStart: "2030-01-01", termEnd: "2030-12-31", version: 4, updatedAt: "2030-02-02T00:00:00Z" },
  metrics: { membersTotal: 10, eligibleReference: 8, vacanciesTotal: 4, recommended: 3, accepted: 2, congregationallyElected: 1, coveragePercent: 75 },
  activeRound: null,
  analytics: {
    roundParticipation: [{ roundId: "round", kind: "proposal", officeName: "Tesorería", officeNames: { en: "Treasury" }, phase: "PROPUESTAS_CERRADAS", version: 3, required: 8, received: 6, recordedAt: "2030-02-02T00:00:00Z" }],
    departments: [{ departmentId: "department", departmentName: "Administración", departmentNames: { en: "Administration" }, vacanciesTotal: 4, recommended: 3, accepted: 2, elected: 1, coveragePercent: 75 }],
    sessions: [{ sessionId: "session", sequence: 1, status: "closed", version: 2, startsAt: "2030-02-01T00:00:00Z", updatedAt: "2030-02-02T00:00:00Z", agendaItems: 4, decisions: 3 }],
  },
  updatedAt: "2030-02-02T00:00:00Z",
};

describe("dashboard analytics projections", () => {
  it("preserves each frozen electorate denominator instead of summing unlike rounds", () => {
    assert.deepEqual(roundParticipationRows(dashboard, "en"), [{
      ...dashboard.analytics.roundParticipation[0],
      office: "Treasury",
      pending: 2,
      percent: 75,
    }]);
    assert.equal(analyticsPercent(0, 0), null);
  });

  it("keeps department vacancy stages cumulative and exposes the unfilled remainder", () => {
    assert.deepEqual(departmentProgressRows(dashboard, "en", "Uncategorized"), [{
      ...dashboard.analytics.departments[0],
      department: "Administration",
      pending: 1,
    }]);
  });

  it("uses agenda items as the explicit session-decision denominator", () => {
    assert.deepEqual(sessionEvolutionRows(dashboard), [{
      ...dashboard.analytics.sessions[0],
      completionPercent: 75,
    }]);
  });

  it("groups people by independent workload without inflating it with linked nominal functions", () => {
    const items: OrganizationRecord[] = [
      { id: "base", memberId: "member", officeName: "Elder", departmentName: "Elders", status: "accepted", independent: true },
      { id: "linked", memberId: "member", officeName: "First elder", departmentName: "Elders", status: "accepted", independent: false, linkedToId: "base" },
      { id: "second", memberId: "other", officeName: "Treasurer", departmentName: "Administration", status: "recommended", independent: true },
      { id: "third", memberId: "other", officeName: "Secretary", departmentName: "Administration", status: "recommended", independent: true },
    ];
    assert.deepEqual(responsibilityDistributionRows(items, 8), [
      { key: "zero", value: 6, linkedFunctions: 0, denominator: 8, percent: 75 },
      { key: "one", value: 1, linkedFunctions: 1, denominator: 8, percent: 12.5 },
      { key: "two", value: 1, linkedFunctions: 0, denominator: 8, percent: 12.5 },
      { key: "threePlus", value: 0, linkedFunctions: 0, denominator: 8, percent: 0 },
    ]);
    assert.ok(responsibilityDistributionRows(items, 0).every((row) => row.percent === null));
  });
});
