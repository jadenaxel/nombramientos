import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const source = await readFile(new URL("../scripts/seed-demo.ts", import.meta.url), "utf8");

function functionSource(name: string, nextName: string): string {
  const start = source.indexOf(`async function ${name}`);
  const end = source.indexOf(`async function ${nextName}`, start + 1);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("demo seed member/contact boundary", () => {
  it("repairs the deterministic demo with display-only member and snapshot envelopes", () => {
    const members = functionSource("seedMembers", "seedCycles");
    const snapshots = functionSource("seedCycleMemberSnapshot", "seedCommittee");
    const assignments = functionSource("seedAssignments", "seedReferenceRounds");

    expect(members).toContain('purpose: "member-display"');
    expect(members).not.toContain('purpose: "member-contact"');
    expect(members).toContain("profile_envelope=NULL");
    expect(members).toContain("contact_envelope=NULL,contact_content_hash=NULL");
    expect(snapshots).toContain("profile_envelope=NULL,display_envelope=EXCLUDED.display_envelope");
    expect(snapshots).toContain("legacy_profile_redacted=false");
    expect(assignments).toContain("const { memberSnapshot, officeSnapshot } = await seedAssignmentEvidence");
    expect(assignments).toContain("member_snapshot,office_snapshot,cycle_id,office_id");
    expect(source).toContain("memberVersion: evidence.member_version");
    expect(source).toContain("departmentRestriction: evidence.eligibility_department_id");
    expect(source).toContain("departmentId: evidence.office_department_id");
    expect(assignments).not.toContain("profileEnvelope");
    expect(assignments).not.toContain("contactEnvelope");
  });

  it("requires the repaired split fixture before taking the manifest fast path", () => {
    const completeness = functionSource("isCompleteDemoFixture", "prepareDemoAccessFile");

    expect(source).toContain("await isCompleteDemoFixture(tenantPool, memberCount > fixture.members.length)");
    expect(source).toContain("memberCount !== fixture.members.length && !referenceFixtureComplete");
    expect(completeness).toContain("allowAdditionalMembers");
    expect(completeness).toContain("row.split_members === 180");
    expect(completeness).toContain("row.contact_free_members === 180");
    expect(completeness).toContain("row.split_cycle_snapshots === 180");
    expect(completeness).toContain("row.missing_candidate_displays === 0");
    expect(completeness).toContain("row.assignment_display_snapshots === 20");
    expect(completeness).toContain("a.member_snapshot->'eligibility' ?& ARRAY['departmentRestriction','validUntil','evaluatedOn','effective']");
    expect(completeness).toContain("a.office_snapshot ?& ARRAY['officeId','departmentId','canonicalCode','names']");
    expect(completeness).toContain("row.expired_seed_reports === 3");
    expect(completeness).toContain("NOT (a.member_snapshot ?| ARRAY['profileEnvelope','contactEnvelope'])");
  });

  it("omits absent optional fixture fields instead of encrypting null values", () => {
    const memberSeed = functionSource("seedMembers", "seedCycleMemberSnapshot");
    expect(source).toContain("const SEED_VERSION = 5");
    expect(memberSeed).toContain("const visibleReason = member.visibleEligibilityReason?.trim()");
    expect(memberSeed).toContain("...(visibleReason ? { visibleReason } : {})");
    expect(memberSeed).not.toContain("visibleReason: member.visibleEligibilityReason");
    expect(memberSeed).not.toContain("photoAssetId: member.photoAssetId");
  });

  it("keeps synthetic report placeholders expired and devoid of invalid artifact bytes", () => {
    const reports = functionSource("seedReports", "seedAuditHistory");

    expect(reports).toContain("'expired'");
    expect(reports).toContain("artifact_envelope=NULL");
    expect(reports).toContain("artifact_bytes=NULL");
    expect(reports).toContain("artifact_manifest=NULL");
    expect(reports).toContain("plaintext_bytes=NULL");
    expect(reports).not.toContain("state='ready'");
  });

  it("limits provenance-trigger relaxation to the guarded repair transaction", () => {
    const disable = source.indexOf("ALTER TABLE assignments DISABLE TRIGGER assignments_preserve_provenance");
    const repair = source.indexOf("await seedAssignments", disable);
    const enable = source.indexOf("ALTER TABLE assignments ENABLE TRIGGER assignments_preserve_provenance", repair);
    const reports = source.indexOf("await seedReports", enable);

    expect(disable).toBeGreaterThan(source.indexOf("assertSyntheticSeedTarget"));
    expect(repair).toBeGreaterThan(disable);
    expect(enable).toBeGreaterThan(repair);
    expect(reports).toBeGreaterThan(enable);
  });
});
