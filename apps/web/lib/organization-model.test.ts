import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  filterOrganizationItems,
  groupOrganizationByDepartment,
  organizationDirectoryInsights,
  organizationReportQuery,
  organizationTotals,
  organizationWorkload,
  type OrganizationItemModel,
} from "./organization-model.ts";

const items: readonly OrganizationItemModel[] = [
  { id: "a-linked", memberId: "member-1", officeName: "Primer anciano", departmentName: "Ancianos", departmentId: "department-elders", status: "elected", linkedToId: "a-base", independent: false, displayName: "Andrés Núñez" },
  { id: "a-base", memberId: "member-1", officeName: "Anciano", departmentName: "Ancianos", departmentId: "department-elders", status: "elected", independent: true, displayName: "Andrés Núñez" },
  { id: "a-load", memberId: "member-1", officeName: "Director de Música", departmentName: "Música", departmentId: "department-music", status: "accepted", independent: true, displayName: "Andrés Núñez" },
  { id: "vacant", officeName: "Secretaría", departmentName: "Secretaría", departmentId: "department-secretariat", status: "vacant" },
];

describe("organization view model", () => {
  it("searches decrypted labels accent-insensitively and applies department IDs", () => {
    assert.deepEqual(filterOrganizationItems(items, { query: "andres nunez", department: "department-music", status: "all" }).map(({ id }) => id), ["a-load"]);
    assert.deepEqual(filterOrganizationItems(items, { query: "", department: "all", status: "elected" }).map(({ id }) => id), ["a-linked", "a-base"]);
  });

  it("groups and sorts the accessible hierarchy without changing the records", () => {
    const grouped = groupOrganizationByDepartment(items, "es");
    assert.deepEqual(grouped.map(([department]) => department), ["Ancianos", "Música", "Secretaría"]);
    assert.deepEqual(grouped[0]?.[1].map(({ id }) => id), ["a-linked", "a-base"]);
  });

  it("prioritizes leadership and derives directory-grade insights without counting names", () => {
    const unordered: readonly OrganizationItemModel[] = [
      { id: "helper", memberId: "person-2", officeName: "Colaboración de Jóvenes", departmentName: "Jóvenes", departmentId: "youth", status: "elected", displayName: "Sara" },
      { id: "director", memberId: "person-1", officeName: "Dirección de Jóvenes", departmentName: "Jóvenes", departmentId: "youth", status: "elected", displayName: "Luis" },
      { id: "assistant", memberId: "person-1", officeName: "Subdirección de Jóvenes", departmentName: "Jóvenes", departmentId: "youth", status: "elected", displayName: "Luis" },
    ];
    assert.deepEqual(groupOrganizationByDepartment(unordered, "es")[0]?.[1].map(({ id }) => id), ["director", "assistant", "helper"]);
    assert.deepEqual(organizationDirectoryInsights(unordered), {
      people: 2,
      departments: 1,
      appointments: 3,
      leadership: 2,
      multiRolePeople: 1,
    });
  });

  it("separates independent workload from linked nominal functions", () => {
    const summary = organizationWorkload(items).get("member-1");
    assert.deepEqual(summary, {
      total: 3,
      independent: 2,
      linked: 1,
      responsibilities: [
        { assignmentId: "a-linked", officeName: "Primer anciano", departmentName: "Ancianos", status: "elected", linked: true },
        { assignmentId: "a-base", officeName: "Anciano", departmentName: "Ancianos", status: "elected", linked: false },
        { assignmentId: "a-load", officeName: "Director de Música", departmentName: "Música", status: "accepted", linked: false },
      ],
    });
    assert.deepEqual(organizationTotals(items), { total: 4, occupied: 3, elected: 2, recommended: 1, independent: 2, linked: 1 });
  });

  it("deep-links an authorized export to the report center with scoped IDs", () => {
    assert.equal(
      organizationReportQuery({ cycleId: "cycle/a", departmentId: "department&music", stage: "proposal" }),
      "reportType=department_organization&organizationStage=proposal&cycleId=cycle%2Fa&department=department%26music",
    );
  });
});
