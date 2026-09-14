import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  memberQualificationAadContext,
  memberQualificationCreateSchema,
  memberQualificationRevisionSchema,
} from "../src/modules/member-qualification-contract.js";

const memberId = "11111111-1111-4111-8111-111111111111";
const qualificationId = "22222222-2222-4222-8222-222222222222";

function envelope(ciphertextBytes = 48) {
  return {
    algorithm: "AES-256-GCM" as const,
    keyId: "tenant-key-v1",
    nonce: Buffer.alloc(12).toString("base64url"),
    ciphertext: Buffer.alloc(ciphertextBytes).toString("base64url"),
    aad: Buffer.from("{}").toString("base64url"),
  };
}

function createFixture() {
  return {
    qualificationId,
    type: "ordination" as const,
    status: "verified" as const,
    effectiveOn: "2026-09-12",
    expiresOn: null,
    detailsEnvelope: envelope(),
    detailsContentHash: `sha256:${"a".repeat(64)}`,
  };
}

describe("member qualification API contract", () => {
  it("accepts only closed types/statuses, civil dates and paired bounded ciphertext", () => {
    expect(memberQualificationCreateSchema.safeParse(createFixture()).success).toBe(true);
    expect(memberQualificationCreateSchema.safeParse({ ...createFixture(), type: "elected" }).success).toBe(false);
    expect(memberQualificationCreateSchema.safeParse({ ...createFixture(), status: "automatic" }).success).toBe(false);
    expect(memberQualificationCreateSchema.safeParse({ ...createFixture(), effectiveOn: "2026-02-30" }).success).toBe(false);
    expect(memberQualificationCreateSchema.safeParse({ ...createFixture(), expiresOn: "2026-01-01" }).success).toBe(false);
    expect(memberQualificationCreateSchema.safeParse({ ...createFixture(), detailsContentHash: null }).success).toBe(false);
    expect(memberQualificationCreateSchema.safeParse({
      ...createFixture(), detailsEnvelope: envelope(2_049),
    }).success).toBe(false);
  });

  it("requires explicit expiration for expired state and rejects clear title/issuer fields", () => {
    expect(memberQualificationCreateSchema.safeParse({
      ...createFixture(), status: "expired", expiresOn: null,
    }).success).toBe(false);
    expect(memberQualificationCreateSchema.safeParse({
      ...createFixture(), title: "Ordination", issuer: "Institution",
    }).success).toBe(false);
    const { qualificationId: _qualificationId, ...revision } = createFixture();
    expect(memberQualificationRevisionSchema.safeParse({
      ...revision, expectedVersion: 1,
    }).success).toBe(true);
    expect(memberQualificationRevisionSchema.safeParse({
      ...revision, expectedVersion: 0,
    }).success).toBe(false);
  });

  it("binds all public metadata and the independent purpose into exact AAD", () => {
    expect(memberQualificationAadContext({
      tenantId: memberId,
      memberId,
      qualificationId,
      version: 3,
      type: "certification",
      status: "pending",
      effectiveOn: "2026-09-12",
      expiresOn: "2027-09-12",
    })).toEqual({
      tenantId: memberId,
      memberId,
      qualificationId,
      purpose: "member-qualification-details",
      schemaVersion: 1,
      version: 3,
      type: "certification",
      status: "pending",
      effectiveOn: "2026-09-12",
      expiresOn: "2027-09-12",
    });
  });

  it("documents lifecycle-gated writes and historical generation reads", () => {
    const openapi = readFileSync(new URL("../../../docs/api/openapi.json", import.meta.url), "utf8");
    expect(openapi).toContain("current active E2EE generation and an active lifecycle grant on an active device");
    expect(openapi).toContain("retain retired generation keys in session memory to read immutable history");
    expect(openapi).toContain("Missing or invalid decrypted details degrade to unavailable");
  });
});
