import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const apiRoot = path.resolve(import.meta.dirname, "..");
const workspaceRoot = path.resolve(apiRoot, "..", "..");
const document = JSON.parse(readFileSync(path.join(workspaceRoot, "docs", "api", "openapi.json"), "utf8")) as {
  paths: Record<string, Record<string, Record<string, unknown>>>;
  components: { schemas: Record<string, Record<string, unknown>> };
};

describe("member display/contact boundary contract", () => {
  it("documents separate display and contact envelopes without the retired profile payload", () => {
    const create = document.components.schemas["MemberCreateRequest"] as { properties: Record<string, unknown>; required: string[] };
    const update = document.components.schemas["MemberUpdateRequest"] as { properties: Record<string, unknown> };
    const row = document.components.schemas["MemberImportRow"] as { properties: Record<string, unknown> };

    expect(create.required).toEqual(expect.arrayContaining(["displayEnvelope", "displayContentHash"]));
    expect(create.properties).toHaveProperty("contactEnvelope");
    expect(update.properties).toHaveProperty("resolveLegacyProfile");
    expect(row.properties).toHaveProperty("contactContentHash");
    expect(JSON.stringify({ create, update, row })).not.toMatch(/profileEnvelope|profileContentHash|"contentHash"/u);
  });

  it("declares contact permission as conditional rather than broadening member.read", () => {
    expect(document.paths["/v1/members"]?.["get"]?.["x-required-permissions"]).toEqual(["member.read"]);
    expect(document.paths["/v1/members"]?.["get"]?.["x-optional-permissions"]).toContain("member.contact.read");
    expect(document.paths["/v1/members"]?.["post"]?.["x-conditional-permissions"]).toEqual({ contactEnvelope: "member.contact.manage" });
    expect(document.paths["/v1/members/{memberId}"]?.["patch"]?.["x-conditional-permissions"])
      .toMatchObject({ "contactEnvelope or resolveLegacyProfile": "member.contact.manage" });
  });
});

