import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migration = readFileSync(path.join(packageRoot, "migrations/tenant/030_member_eligibility_scope.sql"), "utf8");
const policyMigration = readFileSync(path.join(packageRoot, "migrations/tenant/031_member_eligibility_policy_guards.sql"), "utf8");
const tenantStore = readFileSync(path.join(packageRoot, "src/tenant-store.ts"), "utf8");
const workflowStore = readFileSync(path.join(packageRoot, "src/core-workflow-store.ts"), "utf8");
const custodyStore = readFileSync(path.join(packageRoot, "src/custody-store.ts"), "utf8");
const eligibilityGuard = readFileSync(path.join(packageRoot, "src/member-eligibility-guard.ts"), "utf8");
const seed = readFileSync(path.join(packageRoot, "scripts/seed-demo.ts"), "utf8");
const persistentIntegration = readFileSync(path.join(packageRoot, "test/integration.test.ts"), "utf8");

describe("structured member eligibility persistence", () => {
  it("adds operational fields in the new tenant migration without using private rationale", () => {
    expect(migration).toMatch(/ALTER TABLE members[\s\S]*eligibility_department_id uuid[\s\S]*eligibility_valid_until date/u);
    expect(migration).toMatch(/Null means unrestricted/u);
    expect(migration).toMatch(/Inclusive tenant civil date/u);
    expect(migration).toMatch(/ALTER TABLE cycle_member_snapshots[\s\S]*eligibility_effective boolean/u);
    expect(migration).toMatch(/ALTER TABLE candidate_snapshots[\s\S]*member_version_snapshot/u);
    expect(migration.match(/eligibility_effective(?:_snapshot)? SET DEFAULT false/gu)?.length).toBe(4);
    expect(policyMigration).toMatch(/eligibility_evaluated_on DROP DEFAULT/gu);
    expect(policyMigration).toMatch(/eligibility_effective(?:_snapshot)? DROP DEFAULT/gu);
    expect(policyMigration).toMatch(/DROP INDEX IF EXISTS member_eligibility_one_active_pause_per_process/u);
    expect(policyMigration).toMatch(/member_eligibility_one_active_pause_per_process_member[\s\S]*process_id, member_id/u);
    expect(migration).toMatch(/CREATE OR REPLACE FUNCTION preserve_candidacy_evidence/u);
    expect(migration).toMatch(/NEW\.display_envelope_snapshot,NEW\.photo_snapshot[\s\S]*OLD\.display_envelope_snapshot,OLD\.photo_snapshot/u);
    expect(migration).toMatch(/DISABLE TRIGGER candidate_list_entries_immutable[\s\S]*ENABLE TRIGGER candidate_list_entries_immutable/u);
    expect(migration).not.toMatch(/ADD COLUMN (?:note|rationale_envelope|restricted_note_envelope)/iu);
  });

  it("persists, versions, projects, and pauses scope changes", () => {
    expect(tenantStore).toMatch(/eligibility_department_id = CASE WHEN \$13::boolean/u);
    expect(tenantStore).toMatch(/eligibility_valid_until = CASE WHEN \$15::boolean/u);
    expect(tenantStore).toMatch(/version = version \+ 1/u);
    expect(tenantStore).toMatch(/scopeMutation \|\| !currentlyEffective/u);
    expect(tenantStore).toMatch(/"CONFIGURADO", "PROPUESTAS_ABIERTAS"/u);
    expect(tenantStore).toMatch(/assertRoundCandidatesCurrentlyEligible\(input\.roundId, round\.office_id\)/u);
    expect(tenantStore).toMatch(/member\.import\.updated/u);
    expect(tenantStore).toMatch(/eligibilityMutation[\s\S]*pauseAffectedMemberWorkflows/u);
    expect(tenantStore).toMatch(/workflow\.pause\.extended/u);
  });

  it("enforces current and frozen scope at every office-specific decision boundary", () => {
    expect(eligibilityGuard).toMatch(/requireRoundCandidatesOperationallyEligible/u);
    expect(eligibilityGuard).toMatch(/evaluateMemberEligibilityForOffice/u);
    expect(eligibilityGuard).toMatch(/snapshot_evaluated_on > context\.evaluated_on/u);
    expect(eligibilityGuard).toMatch(/pg_advisory_xact_lock_shared/u);
    expect(eligibilityGuard).toMatch(/pg_advisory_xact_lock\(/u);
    expect(eligibilityGuard).toMatch(
      /requireRoundCandidatesOperationallyEligible[\s\S]*?acquireMemberEligibilityPolicySharedLock\(client\)[\s\S]*?FOR SHARE OF member/u,
    );
    expect(eligibilityGuard).not.toMatch(/FOR SHARE OF snapshot/u);
    expect(workflowStore).toMatch(/assertRoundCandidatesEligible\(round\.id, process\.office_id\)/u);
    expect(workflowStore).toMatch(/requireMembersEligibleForOffice\([\s\S]*"PROPOSED_MEMBER_INELIGIBLE"/u);
    expect(workflowStore).toMatch(/requireMembersEligibleForOffice\([\s\S]*"SELECTED_MEMBER_INELIGIBLE"/u);
    expect(workflowStore).toMatch(/eligibility_effective_snapshot/u);
  });

  it("guards every custody materialization point and assignment transition", () => {
    for (const operation of ["submitBallot", "createManifest", "attestManifest", "publishAggregate"]) {
      expect(custodyStore).toMatch(new RegExp(`public async ${operation}\\([\\s\\S]*?requireOperationalCandidateEligibility`, "u"));
    }
    for (const operation of ["recordAssignmentConsent", "presentAssignment", "recordCongregationalDecision", "activateAssignment"]) {
      expect(workflowStore).toMatch(new RegExp(`public async ${operation}\\([\\s\\S]*?ensureAssignmentMayAdvance`, "u"));
    }
    expect(workflowStore).toMatch(/eligibilityPaused: true/u);
    expect(workflowStore).toMatch(/pauseAssignmentForEligibility/u);
    expect(workflowStore).toMatch(/member_eligibility_workflow_pauses/u);
    expect(workflowStore).not.toMatch(/terminal source process cannot be reopened/u);
  });

  it("rejects eligibility-affecting tenant and catalog mutations under the exclusive policy lock", () => {
    expect(tenantStore).toMatch(/assertTenantTimezoneMutationSafe/u);
    expect(tenantStore).toMatch(/TENANT_TIMEZONE_ELIGIBILITY_ACTIVE/u);
    expect(tenantStore).toMatch(/assertDepartmentDeactivationSafe/u);
    expect(tenantStore).toMatch(/CATALOG_DEPARTMENT_ELIGIBILITY_IN_USE/u);
    expect(tenantStore).toMatch(/assertOfficeEligibilityMutationSafe/u);
    expect(tenantStore).toMatch(/CATALOG_OFFICE_ELIGIBILITY_IN_USE/u);
    expect(tenantStore).toMatch(/assignment\.member_snapshot->'eligibility'->>'validUntil'/u);
    expect(tenantStore).toMatch(/acquireMemberEligibilityPolicyExclusiveLock/u);
  });

  it("never applies migrations from the persistent integration suite", () => {
    expect(persistentIntegration).toMatch(/inspectMigrationPlan/u);
    expect(persistentIntegration).toMatch(/Persistent tenant database has pending migrations/u);
    expect(persistentIntegration).not.toMatch(/runMigrations/u);
  });

  it("keeps import defaults and demo snapshots explicit and unrestricted", () => {
    expect(tenantStore).toMatch(/newly imported members are[\s\S]*explicitly unrestricted/u);
    expect(tenantStore).toMatch(/eligibility_department_id,eligibility_valid_until[\s\S]*NULL,NULL/u);
    expect(seed).toMatch(/eligibility_department_id_snapshot,eligibility_valid_until_snapshot,eligibility_evaluated_on,eligibility_effective/u);
    expect(seed).toMatch(/seedAssignmentEvidence/u);
    expect(seed).toMatch(/memberVersion: evidence\.member_version[\s\S]*departmentRestriction:[\s\S]*evaluatedOn:[\s\S]*effective:/u);
    expect(seed).toMatch(/officeSnapshot[\s\S]*departmentId: evidence\.office_department_id/u);
  });
});
