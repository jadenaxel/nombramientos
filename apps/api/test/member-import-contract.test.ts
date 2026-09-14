import { describe, expect, it } from "vitest";
import {
  memberImportCommitSchema,
  memberImportMappingSchema,
  memberImportPreviewSchema,
  memberImportRowSchema,
} from "../src/modules/member-import-contract.js";

const envelope = {
  algorithm: "AES-256-GCM" as const,
  keyId: "tenant-key-v1",
  nonce: Buffer.alloc(12).toString("base64url"),
  ciphertext: Buffer.alloc(32).toString("base64url"),
  aad: Buffer.from(JSON.stringify({
    tenantId: "d0000000-0000-4000-8000-000000000001",
    memberId: "d2000000-0000-4000-8000-000000000001",
    purpose: "member-display",
    schemaVersion: 1,
  })).toString("base64url"),
};

const hash = `sha256:${"0".repeat(64)}`;

describe("member import HTTP contract", () => {
  it("requires an explicit action and encrypted content for creates and updates", () => {
    expect(memberImportRowSchema.safeParse({
      sourceRow: 2,
      id: "d2000000-0000-4000-8000-000000000001",
      eligible: true,
      decision: { action: "create", matchBasis: "normalized_name" },
      displayEnvelope: envelope,
      displayContentHash: hash,
    }).success).toBe(true);
    expect(memberImportRowSchema.safeParse({
      sourceRow: 2,
      id: "d2000000-0000-4000-8000-000000000001",
      eligible: true,
      decision: { action: "create", matchBasis: "none" },
    }).success).toBe(false);
  });

  it("allows skipped error rows without leaking clear profile content", () => {
    expect(memberImportRowSchema.safeParse({
      sourceRow: 3,
      id: "d2000000-0000-4000-8000-000000000003",
      eligible: false,
      decision: { action: "skip", matchBasis: "none" },
    }).success).toBe(true);
    expect(memberImportRowSchema.safeParse({
      sourceRow: 3,
      id: "d2000000-0000-4000-8000-000000000003",
      eligible: false,
      decision: { action: "skip", matchBasis: "none" },
      displayEnvelope: envelope,
      displayContentHash: hash,
    }).success).toBe(false);
    expect(memberImportRowSchema.safeParse({
      sourceRow: 3,
      id: "d2000000-0000-4000-8000-000000000003",
      eligible: false,
      decision: { action: "skip", matchBasis: "none" },
      displayName: "Clear text must never reach this contract",
    }).success).toBe(false);
  });

  it("requires a non-ambiguous column mapping and a selected sheet", () => {
    expect(memberImportMappingSchema.safeParse({ displayName: 1, email: 1 }).success).toBe(false);
    expect(memberImportPreviewSchema.safeParse({
      sourceFingerprint: hash,
      sourceFileName: "roster.csv",
      sourceSheetName: `sheet-sha256:${"d".repeat(64)}`,
      columnMapping: { firstName: 0, lastName: 1 },
      rows: [{
        sourceRow: 2,
        id: "d2000000-0000-4000-8000-000000000003",
        eligible: false,
        decision: { action: "skip", matchBasis: "none" },
      }],
    }).success).toBe(true);
  });

  it("rejects path-like file names and unmapped names", () => {
    expect(memberImportPreviewSchema.safeParse({
      sourceFingerprint: hash,
      sourceFileName: "../padron.csv",
      sourceSheetName: `sheet-sha256:${"d".repeat(64)}`,
      columnMapping: { email: 1 },
      rows: [{
        sourceRow: 2,
        id: "d2000000-0000-4000-8000-000000000003",
        eligible: false,
        decision: { action: "skip", matchBasis: "none" },
      }],
    }).success).toBe(false);
  });

  it("requires the preview revision when committing", () => {
    const importId = "d2000000-0000-4000-8000-000000000004";
    expect(memberImportCommitSchema.safeParse({ importId, expectedRevision: 2 }).success).toBe(true);
    expect(memberImportCommitSchema.safeParse({ importId }).success).toBe(false);
    expect(memberImportCommitSchema.safeParse({ importId, expectedRevision: 0 }).success).toBe(false);
  });

  it("rejects the row maximum plus one before persistence", () => {
    const row = {
      sourceRow: 2,
      id: "d2000000-0000-4000-8000-000000000003",
      eligible: false,
      decision: { action: "skip" as const, matchBasis: "none" as const },
    };
    expect(memberImportPreviewSchema.safeParse({
      sourceFingerprint: hash,
      sourceFileName: "roster.csv",
      sourceSheetName: `sheet-sha256:${"d".repeat(64)}`,
      columnMapping: { displayName: 0 },
      rows: Array.from({ length: 10_001 }, () => row),
    }).success).toBe(false);
  });
});
