import { EventEmitter } from "node:events";
import type { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import {
  cleanupTemporaryDatabases,
  endPoolAndWaitForClients,
} from "./live-database-cleanup.js";

type QueryResponse = { readonly rows: readonly Record<string, unknown>[] };

function fakePool(options: {
  readonly clients?: number;
  readonly query?: (text: string, values: readonly unknown[]) => QueryResponse | Promise<QueryResponse>;
  readonly onEnd?: () => void | Promise<void>;
} = {}): { readonly pool: Pool; readonly queries: string[]; readonly state: { ended: boolean; removed: number } } {
  const emitter = new EventEmitter();
  const queries: string[] = [];
  const state = { ended: false, removed: 0 };
  const raw = {
    totalCount: options.clients ?? 1,
    on: emitter.on.bind(emitter),
    off: emitter.off.bind(emitter),
    query: async (text: string, values: readonly unknown[] = []): Promise<QueryResponse> => {
      queries.push(text);
      return options.query ? await options.query(text, values) : { rows: [] };
    },
    end: async (): Promise<void> => {
      state.ended = true;
      await options.onEnd?.();
      const clients = raw.totalCount;
      setImmediate(() => {
        for (let index = 0; index < clients; index += 1) {
          state.removed += 1;
          raw.totalCount -= 1;
          emitter.emit("remove");
        }
      });
    },
  };
  return { pool: raw as unknown as Pool, queries, state };
}

describe("live database cleanup fail-closed contract", () => {
  it("waits for every delayed pg-pool remove event even when end resolves first", async () => {
    const fixture = fakePool({ clients: 2 });

    await endPoolAndWaitForClients(fixture.pool, "delayed fixture");

    expect(fixture.state).toEqual({ ended: true, removed: 2 });
  });

  it("rejects protected and unknown namespaces before issuing SQL", async () => {
    for (const databaseName of ["nombramientos_control", "unguarded_scratch_database"] as const) {
      const target = fakePool();
      const maintenance = fakePool();

      await expect(cleanupTemporaryDatabases({
        maintenancePool: maintenance.pool,
        targets: [{
          databaseName,
          databasePools: [target.pool],
          assertSafeDatabaseName: () => undefined,
        }],
        label: "Guard contract",
      })).rejects.toThrow(/name guard/u);

      expect(maintenance.queries).toEqual([]);
      expect(target.state.ended).toBe(true);
      expect(maintenance.state.ended).toBe(true);
    }
  });

  it("attests zero activity, uses ordinary DROP without FORCE, and verifies absence", async () => {
    const databaseName = `nom_access_test_${"a".repeat(24)}`;
    const target = fakePool({ clients: 2 });
    const maintenance = fakePool({
      query: (text, values) => {
        if (!text.startsWith("DROP DATABASE")) expect(values).toEqual([databaseName]);
        if (text.includes("pg_stat_activity")) return { rows: [{ count: 0 }] };
        if (text.startsWith("SELECT format")) return { rows: [{ sql: `DROP DATABASE IF EXISTS ${databaseName}` }] };
        if (text.startsWith("DROP DATABASE")) return { rows: [] };
        if (text.includes("pg_database")) return { rows: [{ count: 0 }] };
        throw new Error(`Unexpected cleanup SQL: ${text}`);
      },
    });

    await cleanupTemporaryDatabases({
      maintenancePool: maintenance.pool,
      targets: [{
        databaseName,
        databasePools: [target.pool],
        assertSafeDatabaseName: (candidate) => {
          if (!/^nom_access_test_[0-9a-f]{24}$/u.test(candidate)) throw new Error("unsafe test name");
        },
      }],
      label: "Ordinary drop contract",
    });

    expect(maintenance.queries[0]).toContain("pg_stat_activity");
    expect(maintenance.queries).toContain(`DROP DATABASE IF EXISTS ${databaseName}`);
    expect(maintenance.queries.join("\n")).not.toContain("FORCE");
    expect(maintenance.queries.at(-1)).toContain("pg_database");
    expect(target.state.removed).toBe(2);
    expect(maintenance.state.removed).toBe(1);
  });

  it("waits for pg_stat_activity to converge to zero before the ordinary drop", async () => {
    const databaseName = `nom_key_lifecycle_${"c".repeat(20)}`;
    const target = fakePool();
    let activityAttempts = 0;
    const maintenance = fakePool({
      query: (text) => {
        if (text.includes("pg_stat_activity")) {
          activityAttempts += 1;
          return { rows: [{ count: activityAttempts < 3 ? 1 : 0 }] };
        }
        if (text.startsWith("SELECT format")) return { rows: [{ sql: `DROP DATABASE IF EXISTS ${databaseName}` }] };
        if (text.startsWith("DROP DATABASE")) return { rows: [] };
        if (text.includes("pg_database")) return { rows: [{ count: 0 }] };
        throw new Error(`Unexpected cleanup SQL: ${text}`);
      },
    });

    await cleanupTemporaryDatabases({
      maintenancePool: maintenance.pool,
      targets: [{ databaseName, databasePools: [target.pool], assertSafeDatabaseName: () => undefined }],
      label: "Delayed activity convergence contract",
    });

    expect(activityAttempts).toBe(3);
    const dropIndex = maintenance.queries.findIndex((sql) => sql.startsWith("DROP DATABASE"));
    const finalAttestationIndex = maintenance.queries.findLastIndex((sql) => sql.includes("pg_stat_activity"));
    expect(dropIndex).toBeGreaterThan(finalAttestationIndex);
    expect(maintenance.queries.join("\n")).not.toMatch(/FORCE|pg_terminate_backend/u);
  });

  it("fails closed after bounded retries while pg_stat_activity remains active", async () => {
    vi.useFakeTimers();
    try {
      const databaseName = `nom_key_lifecycle_${"d".repeat(20)}`;
      const target = fakePool();
      const maintenance = fakePool({
        query: (text) => {
          if (text.includes("pg_stat_activity")) return { rows: [{ count: 1 }] };
          if (text.includes("pg_database")) return { rows: [{ count: 1 }] };
          throw new Error(`DROP must not execute while a connection survives: ${text}`);
        },
      });

      const settled = cleanupTemporaryDatabases({
        maintenancePool: maintenance.pool,
        targets: [{ databaseName, databasePools: [target.pool], assertSafeDatabaseName: () => undefined }],
        label: "Persistent activity convergence contract",
      }).then(
        () => ({ error: undefined }),
        (error: unknown) => ({ error }),
      );
      await vi.runAllTimersAsync();
      const { error } = await settled;

      expect(error).toBeInstanceOf(AggregateError);
      const failures = (error as AggregateError).errors as Error[];
      expect(failures).toHaveLength(2);
      expect(failures[0]?.message).toContain("zero-connection attestation");
      expect((failures[0]?.cause as Error | undefined)?.message).toMatch(/still has 1 active PostgreSQL connection/u);
      expect(failures[1]?.message).toContain("post-drop absence verification");
      expect(maintenance.queries.filter((sql) => sql.includes("pg_stat_activity")).length).toBeGreaterThan(1);
      expect(maintenance.queries.some((sql) => sql.startsWith("DROP DATABASE"))).toBe(false);
      expect(maintenance.state.ended).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("retries SQLSTATE 55006 only after a fresh zero-connection attestation", async () => {
    const databaseName = `nom_key_lifecycle_${"e".repeat(20)}`;
    const target = fakePool();
    const activityCounts = [0, 1, 0];
    let dropAttempts = 0;
    const maintenance = fakePool({
      query: (text) => {
        if (text.includes("pg_stat_activity")) return { rows: [{ count: activityCounts.shift() ?? 0 }] };
        if (text.startsWith("SELECT format")) return { rows: [{ sql: `DROP DATABASE IF EXISTS ${databaseName}` }] };
        if (text.startsWith("DROP DATABASE")) {
          dropAttempts += 1;
          if (dropAttempts === 1) {
            throw Object.assign(new Error("database is being accessed by other users"), { code: "55006" });
          }
          return { rows: [] };
        }
        if (text.includes("pg_database")) return { rows: [{ count: 0 }] };
        throw new Error(`Unexpected cleanup SQL: ${text}`);
      },
    });

    await cleanupTemporaryDatabases({
      maintenancePool: maintenance.pool,
      targets: [{ databaseName, databasePools: [target.pool], assertSafeDatabaseName: () => undefined }],
      label: "Transient object-in-use contract",
    });

    expect(dropAttempts).toBe(2);
    expect(maintenance.queries.filter((sql) => sql.includes("pg_stat_activity"))).toHaveLength(3);
    const firstDrop = maintenance.queries.findIndex((sql) => sql.startsWith("DROP DATABASE"));
    const secondDrop = maintenance.queries.findLastIndex((sql) => sql.startsWith("DROP DATABASE"));
    expect(maintenance.queries.slice(firstDrop + 1, secondDrop).some((sql) => sql.includes("pg_stat_activity"))).toBe(true);
    expect(maintenance.queries.join("\n")).not.toMatch(/FORCE|pg_terminate_backend/u);
  });

  it("does not retry an ordinary DROP failure outside SQLSTATE 55006", async () => {
    const databaseName = `nom_access_test_${"b".repeat(24)}`;
    const target = fakePool();
    let dropAttempts = 0;
    const maintenance = fakePool({
      query: (text) => {
        if (text.includes("pg_stat_activity")) return { rows: [{ count: 0 }] };
        if (text.startsWith("SELECT format")) return { rows: [{ sql: `DROP DATABASE IF EXISTS ${databaseName}` }] };
        if (text.startsWith("DROP DATABASE")) {
          dropAttempts += 1;
          throw Object.assign(new Error("permission denied"), { code: "42501" });
        }
        if (text.includes("pg_database")) return { rows: [{ count: 1 }] };
        throw new Error(`Unexpected cleanup SQL: ${text}`);
      },
    });

    await expect(cleanupTemporaryDatabases({
      maintenancePool: maintenance.pool,
      targets: [{ databaseName, databasePools: [target.pool], assertSafeDatabaseName: () => undefined }],
      label: "Non-retriable drop contract",
    })).rejects.toBeInstanceOf(AggregateError);

    expect(dropAttempts).toBe(1);
    expect(maintenance.queries.filter((sql) => sql.includes("pg_stat_activity"))).toHaveLength(1);
    expect(maintenance.state.ended).toBe(true);
  });
});
