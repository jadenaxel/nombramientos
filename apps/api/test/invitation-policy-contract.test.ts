import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const service = readFileSync(path.join(packageRoot, "src", "modules", "invitation-service.ts"), "utf8");

describe("invitation policy-conflict API mapping", () => {
  it("returns typed policy outcomes without serializing password material", () => {
    expect(service).toContain('error.code === "POLICY_CONFLICT"');
    expect(service).toContain('"INVITATION_POLICY_CONFLICT"');
    expect(service).toContain('error.code === "PASSWORD_REQUIRED"');
    expect(service).toContain('"INVITATION_PASSWORD_REQUIRED"');
    expect(service).toContain("disabledPasswordHash");
    expect(service).not.toMatch(/return\s*\{[^}]*passwordHash/su);
  });
});
