import { describe, expect, it } from "vitest";
import { photoAadContext, photoArchiveSchema, photoPutSchema } from "../src/modules/photo-contract.js";

const memberId = "11111111-1111-4111-8111-111111111111";
const photoId = "22222222-2222-4222-8222-222222222222";

function fixture() {
  return {
    photoId,
    expectedVersion: 0,
    version: 1,
    mediaType: "image/jpeg" as const,
    width: 512,
    height: 512,
    plaintextBytes: 128,
    envelope: {
      algorithm: "AES-256-GCM" as const,
      keyId: "tenant-key-v1",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: Buffer.alloc(144).toString("base64url"),
      aad: Buffer.from("{}").toString("base64url"),
    },
    contentHash: `sha256:${"a".repeat(64)}`,
  };
}

describe("photo API contract", () => {
  it("accepts only a bounded square JPEG ciphertext with exact AEAD overhead", () => {
    expect(photoPutSchema.safeParse(fixture()).success).toBe(true);
    expect(photoPutSchema.safeParse({ ...fixture(), height: 500 }).success).toBe(false);
    expect(photoPutSchema.safeParse({ ...fixture(), mediaType: "image/png" }).success).toBe(false);
    expect(photoPutSchema.safeParse({ ...fixture(), plaintextBytes: 127 }).success).toBe(false);
    expect(photoPutSchema.safeParse({ ...fixture(), version: 0 }).success).toBe(false);
    expect(photoPutSchema.safeParse({
      ...fixture(),
      envelope: { ...fixture().envelope, ciphertext: Buffer.alloc(143).toString("base64url") },
    }).success).toBe(false);
  });

  it("rejects cleartext metadata fields and weak archive preconditions", () => {
    expect(photoPutSchema.safeParse({ ...fixture(), originalFilename: "person.jpg" }).success).toBe(false);
    expect(photoPutSchema.safeParse({ ...fixture(), exif: { GPSLatitude: 18.4 } }).success).toBe(false);
    expect(photoArchiveSchema.safeParse({ expectedVersion: 0 }).success).toBe(false);
    expect(photoArchiveSchema.safeParse({ expectedVersion: 1, reason: "name.jpg" }).success).toBe(false);
  });

  it("binds tenant, object, version and normalized dimensions in exact AAD", () => {
    expect(photoAadContext({
      tenantId: memberId,
      memberId,
      photoId,
      version: 3,
      mediaType: "image/jpeg",
      width: 512,
      height: 512,
      plaintextBytes: 42_000,
    })).toEqual({
      tenantId: memberId,
      memberId,
      photoId,
      purpose: "member-photo",
      schemaVersion: 1,
      version: 3,
      mediaType: "image/jpeg",
      width: 512,
      height: 512,
      plaintextBytes: 42_000,
    });
  });
});
