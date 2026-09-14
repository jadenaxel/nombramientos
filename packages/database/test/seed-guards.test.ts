import { describe, expect, it } from "vitest";
import { assertSyntheticSeedTarget } from "../src/seed-guards.js";

const demo = {
  databaseName: "nom_t_d0000000000040008000000000000001",
  tenantId: "d0000000-0000-4000-8000-000000000001",
  kind: "demo",
} as const;

describe("synthetic seed target guard", () => {
  it("accepts only the deterministic demo database with matching tenant settings", () => {
    expect(() => assertSyntheticSeedTarget(demo, demo)).not.toThrow();
  });

  it("refuses a control-plane mapping redirected to the empty Ozama tenant", () => {
    expect(() => assertSyntheticSeedTarget(demo, {
      databaseName: "nom_t_0a2a0000000040008000000000000001",
      tenantId: "0a2a0000-0000-4000-8000-000000000001",
      kind: "real",
    })).toThrow(/refusing all writes/i);
  });

  it("refuses a correctly named database whose internal tenant identity is inconsistent", () => {
    expect(() => assertSyntheticSeedTarget(demo, {
      databaseName: demo.databaseName,
      tenantId: "0a2a0000-0000-4000-8000-000000000001",
      kind: "real",
    })).toThrow(/refusing all writes/i);
  });
});

