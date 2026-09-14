import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const tenantRoutes = readFileSync(new URL("../src/modules/tenant-routes.ts", import.meta.url), "utf8");
const photoRoutes = readFileSync(new URL("../src/modules/photo-routes.ts", import.meta.url), "utf8");
const server = readFileSync(new URL("../src/server.ts", import.meta.url), "utf8");

describe("tenant content-key HTTP error boundary", () => {
  it("does not use a legacy grant preflight outside the write transaction", () => {
    expect(tenantRoutes).not.toContain("requireCurrentTenantKey");
    expect(tenantRoutes).not.toMatch(/tenant\.getKeyGrant\(/u);
    expect(photoRoutes).not.toMatch(/getKeyGrant|requireCurrentTenantKey/u);
  });

  it("preserves stable 409 codes if a store lets the common guard error escape", () => {
    expect(server).toContain("ContentKeyWriteGuardError");
    expect(server).toMatch(/error instanceof ContentKeyWriteGuardError[\s\S]*?status\(error\.statusCode\)[\s\S]*?code: error\.code/u);
  });
});
