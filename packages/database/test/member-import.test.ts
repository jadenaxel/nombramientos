import { describe, expect, it } from "vitest";
import { evaluateMemberImportPlan, type MemberImportRow } from "../src/member-import.js";

const existing = [
  { id: "d2000000-0000-4000-8000-000000000001", stableCode: "OZA-001", version: 3 },
] as const;

function row(overrides: Partial<MemberImportRow> = {}): MemberImportRow {
  return {
    sourceRow: 2,
    id: "d2000000-0000-4000-8000-000000000002",
    shortId: "OZA-002",
    eligible: true,
    decision: { action: "create", matchBasis: "none" },
    displayEnvelope: {
      algorithm: "AES-256-GCM",
      keyId: "tenant-key-v1",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
      aad: "e30",
    },
    displayContentHash: `sha256:${"0".repeat(64)}`,
    ...overrides,
  };
}

describe("member import planning", () => {
  it("keeps an explicit create decision for a name/email suggestion opaque to the server", () => {
    const result = evaluateMemberImportPlan([
      row({ decision: { action: "create", matchBasis: "normalized_name" } }),
    ], existing);
    expect(result).toMatchObject({ counts: { create: 1, update: 0, skip: 0, errors: 0 } });
    expect(result.rows[0]).toEqual({ sourceRow: 2, action: "create", status: "ready", codes: [] });
  });

  it("rejects stale updates and targets selected by a mismatched stable id", () => {
    const result = evaluateMemberImportPlan([
      row({
        id: existing[0].id,
        expectedVersion: 2,
        shortId: "OTHER",
        decision: { action: "update", matchBasis: "user_selected" },
      }),
    ], existing);
    expect(result.rows[0]?.codes).toEqual(["VERSION_CONFLICT", "STABLE_ID_MISMATCH"]);
  });

  it("fails closed when an import targets a quarantined legacy profile", () => {
    const result = evaluateMemberImportPlan([
      row({
        id: existing[0].id,
        expectedVersion: existing[0].version,
        shortId: existing[0].stableCode,
        decision: { action: "update", matchBasis: "stable_id" },
      }),
    ], [{ ...existing[0], profileMigrationRequired: true }]);
    expect(result.rows[0]?.codes).toEqual(["LEGACY_PROFILE_MIGRATION_REQUIRED"]);
  });

  it("detects duplicate source rows, target ids and stable ids within one plan", () => {
    const result = evaluateMemberImportPlan([
      row(),
      row({ shortId: " oza-002 " }),
    ], []);
    expect(result.counts.errors).toBe(2);
    expect(result.rows[0]?.codes).toEqual(expect.arrayContaining([
      "DUPLICATE_SOURCE_ROW",
      "DUPLICATE_TARGET",
      "DUPLICATE_STABLE_ID",
    ]));
  });

  it("preserves an explicit skip without requiring an existing target", () => {
    const encrypted = row({ decision: { action: "skip", matchBasis: "none" } });
    const { displayEnvelope: _envelope, displayContentHash: _hash, ...skipped } = encrypted;
    const result = evaluateMemberImportPlan([skipped], []);
    expect(result).toMatchObject({ counts: { create: 0, update: 0, skip: 1, errors: 0 } });
  });
});
