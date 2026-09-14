import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const document = JSON.parse(
  readFileSync(path.join(workspaceRoot, "docs", "api", "openapi.json"), "utf8"),
) as OpenApiDocument;

describe("member import OpenAPI contract", () => {
  it("publishes only the reviewed preview and commit mutations", () => {
    expect(document.paths["/v1/members/import"]).toBeUndefined();
    expect(document.paths["/v1/members/import/preview"]?.post?.operationId).toBe("previewMemberImport");
    expect(document.paths["/v1/members/import/commit"]?.post?.operationId).toBe("commitMemberImport");
  });

  it("requires explicit row decisions and optimistic commit concurrency", () => {
    expect(document.components.schemas["MemberImportDecision"]?.properties?.["action"]?.enum).toEqual([
      "create",
      "update",
      "skip",
    ]);
    expect(document.components.schemas["MemberImportRow"]?.required).toEqual(
      expect.arrayContaining(["sourceRow", "id", "eligible", "decision"]),
    );
    expect(document.components.schemas["MemberImportCommitRequest"]?.required).toEqual([
      "importId",
      "expectedRevision",
    ]);
  });
});

interface OpenApiOperation {
  readonly operationId?: string;
}

interface OpenApiSchema {
  readonly required?: readonly string[];
  readonly properties?: Readonly<Record<string, { readonly enum?: readonly string[] }>>;
}

interface OpenApiDocument {
  readonly paths: Readonly<Record<string, { readonly post?: OpenApiOperation } | undefined>>;
  readonly components: {
    readonly schemas: Readonly<Record<string, OpenApiSchema | undefined>>;
  };
}
