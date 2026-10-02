import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import { constrainPersistentResolverPool, PersistentReadOnlyPool, PERSISTENT_READ_ONLY_OPTIONS } from "./persistent-read-only-fixture.js";

describe("persistent integration test safety boundary", () => {
  it("forces startup read-only and refuses URL or config option overrides", async () => {
    const pool = new PersistentReadOnlyPool({ connectionString: "postgres://user:password@127.0.0.1:55432/readonly", max: 1 });
    expect(pool.options.options).toBe(PERSISTENT_READ_ONLY_OPTIONS);
    await pool.end();
    expect(() => new PersistentReadOnlyPool({ options: "-c default_transaction_read_only=off" })).toThrow();
    expect(() => new PersistentReadOnlyPool({ connectionString: "postgres://user:password@127.0.0.1:55432/readonly?options=unsafe" })).toThrow();
  });

  it("guards resolver pools before any connection and refuses retroactive installation", async () => {
    const pool = new Pool({ max: 1 });
    constrainPersistentResolverPool(pool);
    expect(pool.options.options).toBe(PERSISTENT_READ_ONLY_OPTIONS);
    expect(() => constrainPersistentResolverPool({ totalCount: 1 } as Pool)).toThrow();
    await pool.end();
  });

  it("keeps installed-tenant integration source free of DML, migration execution and store mutators", () => {
    const source = readFileSync(new URL("./integration.test.ts", import.meta.url), "utf8");
    expect(source).toContain('import { PersistentReadOnlyPool as Pool, constrainPersistentResolverPool }');
    expect(source).not.toMatch(/\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|TRUNCATE\s+|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+DATABASE)\b/iu);
    expect(source).not.toMatch(/query\(["']BEGIN["']\)|runMigrations\(|\.previewImport\(|\.commitImport\(/u);
    expect(source).toContain('constrainPersistentResolverPool(await resolver.getPool(context.tenantId))');
    expect(source).toContain("current_setting('transaction_read_only')='on'");
  });
});
