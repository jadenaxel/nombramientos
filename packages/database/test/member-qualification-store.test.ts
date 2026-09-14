import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  MEMBER_QUALIFICATION_STATUSES,
  MEMBER_QUALIFICATION_TYPES,
  MemberQualificationStoreError,
} from "../src/member-qualification-store.js";

const migration032 = readFileSync(
  new URL("../migrations/tenant/032_member_qualification_versions.sql", import.meta.url),
  "utf8",
);
const migration033 = readFileSync(
  new URL("../migrations/tenant/033_member_qualification_envelope_shape.sql", import.meta.url),
  "utf8",
);
const store = readFileSync(new URL("../src/member-qualification-store.ts", import.meta.url), "utf8");

describe("independent member qualification storage contract", () => {
  it("closes the public type/status vocabularies", () => {
    expect(MEMBER_QUALIFICATION_TYPES).toEqual(["training", "ordination", "certification", "other"]);
    expect(MEMBER_QUALIFICATION_STATUSES).toEqual(["pending", "verified", "expired", "revoked"]);
  });

  it("uses append-only linear versions with civil dates and encrypted optional details", () => {
    expect(migration032).toContain("CREATE TABLE member_qualification_versions");
    expect(migration032).toContain("PRIMARY KEY (qualification_id, version)");
    expect(migration032).toContain("UNIQUE (qualification_id, version, member_id)");
    expect(migration032).toContain("FOREIGN KEY (qualification_id, supersedes_version, member_id)");
    expect(migration032).toContain("REFERENCES member_qualification_versions(qualification_id, version, member_id)");
    expect(migration032).toContain("supersedes_version = version - 1");
    expect(migration032).toContain("effective_on date NOT NULL");
    expect(migration032).toContain("details_envelope jsonb");
    expect(migration033).toContain("member_qualification_details_envelope_shape");
    expect(migration033).toContain("details_envelope = jsonb_build_object(");
    expect(migration033).toContain("jsonb_typeof(details_envelope -> 'algorithm') = 'string'");
    expect(migration033).toContain("details_envelope ->> 'algorithm' = 'AES-256-GCM'");
    expect(migration033).toContain("details_envelope ->> 'nonce' ~ '^[A-Za-z0-9_-]{16}$'");
    expect(migration032).toContain("BEFORE UPDATE OR DELETE");
    expect(migration032).toContain("BEFORE TRUNCATE");
    expect(migration032).toContain("eligibility or election");
  });

  it("preserves immutable migration 032 and applies envelope hardening incrementally", () => {
    expect(createHash("sha256").update(migration032).digest("hex"))
      .toBe("0726a8dc837508c7dc0295ff1faba1ba8d6d049ef1824e4167a1a47d15cdca4c");
    expect(migration032).not.toContain("member_qualification_details_envelope_shape");
    expect(migration033).toContain("ALTER TABLE member_qualification_versions");
    expect(migration033).toContain("ADD CONSTRAINT member_qualification_details_envelope_shape");
  });

  it("does not update election or eligibility entities and keeps narrative out of event metadata", () => {
    expect(store).not.toMatch(/UPDATE\s+(?:members|candidacies|assignments|rounds|office_processes)/u);
    expect(store).not.toContain("eligibility_status");
    expect(store).not.toContain("title");
    expect(store).not.toContain("issuer");
    expect(store).not.toMatch(/payload[^;]*(?:details_envelope|ciphertext|nonce)/su);
    const metadataProjection = store.match(/function toEventMetadata[\s\S]*?\n\}/u)?.[0] ?? "";
    expect(metadataProjection).not.toMatch(/memberId|qualification_type|status|effective_on|expires_on|hasDetails/u);
    expect(metadataProjection).toMatch(/qualificationId[\s\S]*version[\s\S]*eligibilityInference/u);
  });

  it("delegates same-transaction content-key checks to the common lifecycle guard", () => {
    expect(store).toContain("assertWritableTenantContentKey");
    expect(store).toMatch(/await assertWritableTenantContentKey\(this\.client,[\s\S]*?identityId,[\s\S]*?envelopes: \[envelope\]/u);
    expect(store).toContain("error instanceof ContentKeyWriteGuardError");
    expect(store).toContain("new MemberQualificationStoreError(error.statusCode, error.code, error.message)");
    expect(store).not.toContain("FROM e2ee_key_generations generation");
    expect(store).not.toContain("FROM device_key_grants");
  });

  it("serializes revisions on the mutable member row without locking append-only versions", () => {
    const revision = store.match(/public async revise[\s\S]*?private async recordChange/u)?.[0] ?? "";
    expect(revision).toContain("FROM member_qualification_versions");
    expect(revision).not.toMatch(/FROM member_qualification_versions[\s\S]*?FOR UPDATE/u);
    expect(store).toContain('writeLock ? "FOR UPDATE" : ""');
    expect(store).not.toContain('writeLock ? "FOR SHARE" : ""');
  });

  it("exposes neutral typed conflicts", () => {
    expect(new MemberQualificationStoreError(409, "QUALIFICATION_VERSION_CONFLICT", "stale"))
      .toMatchObject({ statusCode: 409, code: "QUALIFICATION_VERSION_CONFLICT", message: "stale" });
  });

  it("persists the actual created response status for idempotent POST replays", () => {
    expect(store).toContain("SET response_status=201,response_body=$4");
  });
});
