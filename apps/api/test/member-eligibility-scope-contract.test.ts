import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { memberCreateSchema, memberUpdateSchema } from "../src/modules/tenant-routes.js";

const envelope = {
  algorithm: "AES-256-GCM" as const,
  keyId: "tenant-key-v1",
  nonce: Buffer.alloc(12).toString("base64url"),
  ciphertext: Buffer.alloc(32).toString("base64url"),
  aad: Buffer.from("{}").toString("base64url"),
};

describe("member operational eligibility scope contract", () => {
  it("accepts exact department UUIDs and nullable inclusive civil dates", () => {
    const parsed = memberCreateSchema.parse({
      id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      eligible: true,
      displayEnvelope: envelope,
      displayContentHash: `sha256:${"a".repeat(64)}`,
      departmentRestriction: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      validUntil: "2028-02-29",
    });
    expect(parsed.departmentRestriction).toBe("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    expect(parsed.validUntil).toBe("2028-02-29");
    expect(memberUpdateSchema.parse({ expectedVersion: 3, departmentRestriction: null, validUntil: null }))
      .toMatchObject({ departmentRestriction: null, validUntil: null });
  });

  it("fails closed for non-UUID scope and non-civil or impossible dates", () => {
    expect(memberUpdateSchema.safeParse({ expectedVersion: 1, departmentRestriction: "Treasury" }).success).toBe(false);
    expect(memberUpdateSchema.safeParse({ expectedVersion: 1, validUntil: "2027-02-29" }).success).toBe(false);
    expect(memberUpdateSchema.safeParse({ expectedVersion: 1, validUntil: "2028-2-9" }).success).toBe(false);
  });

  it("documents null semantics and the eligibility permission boundary", () => {
    const apiRoot = path.resolve(import.meta.dirname, "..");
    const document = JSON.parse(readFileSync(path.resolve(apiRoot, "../../docs/api/openapi.json"), "utf8")) as {
      paths: Record<string, Record<string, Record<string, unknown>>>;
      components: { schemas: Record<string, { properties?: Record<string, Record<string, unknown>> }> };
    };
    const create = document.components.schemas["MemberCreateRequest"]?.properties ?? {};
    const update = document.components.schemas["MemberUpdateRequest"]?.properties ?? {};
    expect(create).toHaveProperty("departmentRestriction");
    expect(create).toHaveProperty("validUntil");
    expect(update).toHaveProperty("departmentRestriction");
    expect(update).toHaveProperty("validUntil");
    expect(String(create["departmentRestriction"]?.["description"])).toMatch(/null.*unrestrict/i);
    expect(String(create["validUntil"]?.["description"])).toMatch(/inclusive.*tenant civil date/i);
    expect(document.paths["/v1/members/{memberId}"]?.["patch"]?.["x-conditional-permissions"])
      .toMatchObject({
        "eligibilityStatus, available, eligibilityEnvelope, departmentRestriction, or validUntil": "member.eligibility.manage",
      });
  });
});
