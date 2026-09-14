import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateMemberEligibilityForOffice,
  isCanonicalCivilDate,
} from "../dist/member-eligibility.js";

const treasury = "10000000-0000-4000-8000-000000000001";
const youth = "20000000-0000-4000-8000-000000000002";
const base = {
  eligibilityStatus: "eligible",
  available: true,
  archived: false,
  departmentRestriction: null,
  validUntil: null,
  evaluatedOn: "2026-09-12",
  officeDepartmentId: treasury,
};

test("canonical civil dates reject normalization and impossible days", () => {
  assert.equal(isCanonicalCivilDate("2028-02-29"), true);
  assert.equal(isCanonicalCivilDate("0001-01-01"), true);
  assert.equal(isCanonicalCivilDate("2027-02-29"), false);
  assert.equal(isCanonicalCivilDate("2026-9-12"), false);
  assert.equal(isCanonicalCivilDate("2026-09-12T00:00:00Z"), false);
});

test("null scope is unrestricted and validUntil is inclusive", () => {
  assert.deepEqual(evaluateMemberEligibilityForOffice(base), { eligible: true, reason: "ELIGIBLE" });
  assert.deepEqual(evaluateMemberEligibilityForOffice({ ...base, validUntil: "2026-09-12" }), {
    eligible: true,
    reason: "ELIGIBLE",
  });
  assert.deepEqual(evaluateMemberEligibilityForOffice({ ...base, validUntil: "2026-09-11" }), {
    eligible: false,
    reason: "ELIGIBILITY_EXPIRED",
  });
});

test("a department restriction allows only the exact active department", () => {
  assert.deepEqual(evaluateMemberEligibilityForOffice({
    ...base,
    departmentRestriction: treasury,
    restrictionDepartmentActive: true,
  }), { eligible: true, reason: "ELIGIBLE" });
  assert.deepEqual(evaluateMemberEligibilityForOffice({
    ...base,
    departmentRestriction: youth,
    restrictionDepartmentActive: true,
  }), { eligible: false, reason: "DEPARTMENT_RESTRICTED" });
  assert.deepEqual(evaluateMemberEligibilityForOffice({
    ...base,
    departmentRestriction: treasury,
    restrictionDepartmentActive: false,
  }), { eligible: false, reason: "DEPARTMENT_RESTRICTED" });
});

test("invalid structured scope and base ineligibility fail closed", () => {
  assert.deepEqual(evaluateMemberEligibilityForOffice({ ...base, evaluatedOn: "bad-date" }), {
    eligible: false,
    reason: "INVALID_ELIGIBILITY_SCOPE",
  });
  assert.deepEqual(evaluateMemberEligibilityForOffice({ ...base, eligibilityStatus: "review" }), {
    eligible: false,
    reason: "STATUS_NOT_ELIGIBLE",
  });
  assert.deepEqual(evaluateMemberEligibilityForOffice({ ...base, archived: true }), {
    eligible: false,
    reason: "MEMBER_ARCHIVED",
  });
});
