import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("federated source-session compatibility migration", () => {
  const migration = readFileSync(path.resolve(import.meta.dirname, "../migrations/control/031_gestionchurch_independent_source_sessions.sql"), "utf8");
  const operation = readFileSync(path.resolve(import.meta.dirname, "../scripts/apply-independent-source-session-migration.mjs"), "utf8");
  it("serializes a subject and revokes only after authority/context changes", () => {
    expect(migration).toContain("pg_advisory_xact_lock");
    expect(migration).toContain("previous_role_fingerprint IS DISTINCT FROM p_role_fingerprint");
    expect(migration).toContain("previous_identity_status IS DISTINCT FROM ''active''");
    expect(migration).toContain("previous_membership_status IS DISTINCT FROM ''active''");
  });
  it("fails closed if the previous function cannot be patched and keeps its privilege boundary", () => {
    expect(migration).toContain("RAISE EXCEPTION");
    expect(migration).toContain("REVOKE ALL ON FUNCTION");
    expect(migration).not.toMatch(/GRANT .* TO PUBLIC|UPDATE tenants|DROP TABLE/iu);
  });
  it("targeted application requires an exact pending plan and private rollback before the official runner", () => {
    expect(operation).toContain('assert.equal(plan.pending.length, 1)');
    expect(operation).toContain('assert.equal(plan.pending[0]?.name, target)');
    expect(operation).toContain('expectedPendingMigrations: plan.pending');
    expect(operation).toContain('"/inheritance:r"');
    expect(operation).toContain('flag: "wx", mode: 0o600');
    expect(operation.indexOf('writeFile(rollbackPath')).toBeLessThan(operation.indexOf('await runMigrations'));
    expect(operation).not.toMatch(/console\.(?:log|error)\([^\n]*(?:definition|ddl|admin\.href)/u);
  });
});
