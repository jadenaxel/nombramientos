import { EventEmitter } from "node:events";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  closePoolOwnerAndConfirmDrained,
  dropEphemeralDatabase,
  dropEphemeralRole,
} from "./ephemeral-postgres-cleanup.js";

class FakePool extends EventEmitter {
  public totalCount: number;
  public idleCount: number;
  public waitingCount = 0;
  public readonly queries: Array<{ text: string; values: readonly unknown[] | undefined }> = [];
  readonly #responses: unknown[];
  readonly #deferRemoval: boolean;

  public constructor(totalCount: number, responses: readonly unknown[] = [], deferRemoval = false) {
    super();
    this.totalCount = totalCount;
    this.idleCount = totalCount;
    this.#responses = [...responses];
    this.#deferRemoval = deferRemoval;
  }

  public async end(): Promise<void> {
    const clients = this.totalCount;
    const remove = (): void => {
      for (let index = 0; index < clients; index += 1) this.emit("remove");
      this.totalCount = 0;
      this.idleCount = 0;
    };
    if (this.#deferRemoval) setTimeout(remove, 5);
    else remove();
  }

  public async query(text: string, values?: readonly unknown[]): Promise<unknown> {
    this.queries.push({ text, values });
    const response = this.#responses.shift();
    if (response === undefined) throw new Error("Unexpected fake PostgreSQL query");
    return response;
  }
}

const asPool = (pool: FakePool): Pool => pool as unknown as Pool;

describe("ephemeral PostgreSQL cleanup contract", () => {
  it("attests every real pool-client removal event before accepting shutdown", async () => {
    const pool = new FakePool(2);
    await expect(closePoolOwnerAndConfirmDrained(
      [{ pool: asPool(pool), label: "fixture pool" }],
      async () => pool.end(),
      "fixture owner close",
    )).resolves.toBeUndefined();
    expect(pool.listenerCount("remove")).toBe(0);
  });

  it("waits when pool.end resolves before deferred remove callbacks arrive", async () => {
    const pool = new FakePool(2, [], true);
    await expect(closePoolOwnerAndConfirmDrained(
      [{ pool: asPool(pool), label: "deferred pool" }],
      async () => pool.end(),
      "deferred owner close",
    )).resolves.toBeUndefined();
    expect(pool.totalCount).toBe(0);
    expect(pool.listenerCount("remove")).toBe(0);
  });

  it("fails closed when an owner reports success without removing its clients", async () => {
    const pool = new FakePool(1);
    await expect(closePoolOwnerAndConfirmDrained(
      [{ pool: asPool(pool), label: "leaked pool" }],
      async () => undefined,
      "leaked owner close",
      25,
    )).rejects.toThrow("did not drain cleanly");
    expect(pool.listenerCount("remove")).toBe(0);
  });

  it("waits for zero pg_stat_activity, drops without FORCE, and verifies absence", async () => {
    const databaseName = "nom_ephemeral_0123456789abcdef";
    const pool = new FakePool(0, [
      { rows: [{ current_database: "postgres" }] },
      { rows: [{ count: 1 }] },
      { rows: [{ count: 0 }] },
      { rows: [{ sql: `DROP DATABASE IF EXISTS ${databaseName}` }] },
      { rows: [] },
      { rows: [{ count: 0 }] },
    ]);
    await dropEphemeralDatabase(asPool(pool), databaseName, {
      pattern: /^nom_ephemeral_[0-9a-f]{16}$/u,
      label: "test database",
      drainTimeoutMs: 1_000,
      pollIntervalMs: 1,
    });
    const statements = pool.queries.map(({ text }) => text);
    expect(statements).toContain("SELECT count(*)::int AS count FROM pg_stat_activity WHERE datname=$1");
    expect(statements.join("\n")).not.toMatch(/WITH\s*\(\s*FORCE\s*\)|pg_terminate_backend/iu);
    expect(statements.at(-1)).toBe("SELECT count(*)::int AS count FROM pg_database WHERE datname=$1");
  });

  it("rejects a name outside the exact database guard before issuing SQL", async () => {
    const pool = new FakePool(0);
    await expect(dropEphemeralDatabase(asPool(pool), "nombramientos_control", {
      pattern: /^nom_ephemeral_[0-9a-f]{16}$/u,
      label: "test database",
    })).rejects.toThrow("exact test database boundary");
    expect(pool.queries).toHaveLength(0);
  });

  it("drops an exact ephemeral role and verifies its absence", async () => {
    const pool = new FakePool(0, [
      { rows: [{ sql: "DROP ROLE IF EXISTS nom_ephemeral_role_01234567" }] },
      { rows: [] },
      { rows: [{ count: 0 }] },
    ]);
    await dropEphemeralRole(asPool(pool), "nom_ephemeral_role_01234567", {
      pattern: /^nom_ephemeral_role_[0-9a-f]{8}$/u,
      label: "test role",
    });
    expect(pool.queries.map(({ text }) => text).join("\n")).not.toMatch(/DROP\s+ROLE\s+nombramientos_/iu);
  });

  it("never evaluates stateful identifier guards", async () => {
    const pool = new FakePool(0);
    await expect(dropEphemeralRole(asPool(pool), "nom_ephemeral_role_01234567", {
      pattern: /^nom_ephemeral_role_[0-9a-f]{8}$/gu,
      label: "test role",
    })).rejects.toThrow("stateful identifier policy");
    expect(pool.queries).toHaveLength(0);
  });
});
