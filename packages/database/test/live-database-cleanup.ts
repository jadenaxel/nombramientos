import type { Pool } from "pg";

const POOL_DRAIN_TIMEOUT_MS = 10_000;
const DATABASE_CONNECTION_DRAIN_TIMEOUT_MS = 5_000;
const DATABASE_CONNECTION_DRAIN_RETRY_MS = 25;
const DATABASE_IDENTIFIER = /^[a-z][a-z0-9_]{0,62}$/u;
const PROTECTED_DATABASE_NAMES = new Set([
  "postgres",
  "template0",
  "template1",
  "nombramientos_control",
  "nom_t_d0000000000040008000000000000001",
  "nom_t_0a2a0000000040008000000000000001",
]);
const TEMPORARY_DATABASE_NAMESPACES = [
  /^nom_access_test_[0-9a-f]{24}$/u,
  /^nom_catalog_reconcile_[0-9a-f]{24}$/u,
  /^nom_control_test_[0-9a-f]{24}$/u,
  /^nom_custody_test_[0-9a-f]{24}$/u,
  /^nom_enterprise_auth_[0-9a-f]{24}$/u,
  /^nom_enterprise_invariants_[0-9a-f]{20}$/u,
  /^nom_init_admin_recovery_[0-9a-f]{16}$/u,
  /^nom_inv_pwd_upgrade_[0-9a-f]{20}$/u,
  /^nom_inv_reconcile_[0-9a-f]{20}$/u,
  /^nom_key_lifecycle_[0-9a-f]{20}$/u,
  /^nom_legacy_(?:control|tenant)_[0-9a-f]{18}$/u,
  /^nom_maintenance_pre024_[0-9a-f]{16}$/u,
  /^nom_photo_test_[ab]_[0-9a-f]{32}$/u,
  /^nom_qual_test_[0-9a-f]{24}$/u,
  /^nom_reason_upgrade_[0-9a-f]{24}$/u,
  /^nom_test_catalog_[0-9a-f]{12}$/u,
  /^nom_test_eligibility_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$/u,
  /^nom_test_organization_[0-9a-f]{12}$/u,
  /^nom_t_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$/u,
  /^nom_workflow_test_[0-9a-f]{8}_[0-9a-f]{4}_4[0-9a-f]{3}_[89ab][0-9a-f]{3}_[0-9a-f]{12}$/u,
] as const;

export interface TemporaryDatabaseCleanupTarget {
  readonly databaseName: string;
  readonly databasePools: readonly Pool[];
  readonly assertSafeDatabaseName: (databaseName: string) => void;
  readonly label?: string;
}

export interface TemporaryDatabaseCleanupOptions {
  readonly maintenancePool: Pool;
  readonly targets: readonly TemporaryDatabaseCleanupTarget[];
  readonly label: string;
}

/**
 * Ends a pg-pool and proves that every client which existed at shutdown emitted
 * pg-pool's real `remove` event. A bounded timeout turns leaked checked-out
 * clients into a deterministic failure instead of leaving a live suite hung.
 */
export async function endPoolAndWaitForClients(pool: Pool, label: string): Promise<void> {
  const expectedRemovals = pool.totalCount;
  let removed = 0;
  let resolveDrained: (() => void) | undefined;
  const drained = new Promise<void>((resolve) => {
    resolveDrained = resolve;
  });
  if (expectedRemovals === 0) resolveDrained?.();

  const onRemove = (): void => {
    removed += 1;
    if (removed >= expectedRemovals) resolveDrained?.();
  };
  pool.on("remove", onRemove);

  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      reject(new Error(`${label} did not emit ${expectedRemovals} pg-pool remove event(s) within ${POOL_DRAIN_TIMEOUT_MS}ms`));
    }, POOL_DRAIN_TIMEOUT_MS);
    timeout.unref();
  });

  try {
    await Promise.race([
      Promise.all([pool.end(), drained]),
      timedOut,
    ]);
    if (removed !== expectedRemovals || pool.totalCount !== 0) {
      throw new Error(`${label} did not drain exactly: expected ${expectedRemovals}, observed ${removed}, remaining ${pool.totalCount}`);
    }
  } finally {
    if (timeout) clearTimeout(timeout);
    pool.off("remove", onRemove);
  }
}

/**
 * Fail-closed teardown for UUID-scoped live-test databases. It never terminates
 * foreign backends and never uses PostgreSQL's FORCE option: all test pools must
 * drain first, pg_stat_activity must attest zero sessions, and absence is
 * verified after the ordinary DROP DATABASE statement. The maintenance pool is
 * always closed last, with every teardown failure retained.
 */
export async function cleanupTemporaryDatabases(options: TemporaryDatabaseCleanupOptions): Promise<void> {
  const failures: Error[] = [];
  const safeTargets = new Set<TemporaryDatabaseCleanupTarget>();
  const recordFailure = (stage: string, error: unknown): void => {
    failures.push(new Error(`${options.label} cleanup failed during ${stage}`, { cause: error }));
  };

  try {
    for (const target of options.targets) {
      try {
        assertGenericTemporaryDatabaseName(target.databaseName);
        target.assertSafeDatabaseName(target.databaseName);
        safeTargets.add(target);
      } catch (error) {
        recordFailure(`${target.label ?? target.databaseName} name guard`, error);
      }
    }

    const pools = [...new Set(options.targets.flatMap(({ databasePools }) => databasePools))];
    for (const [index, pool] of pools.entries()) {
      try {
        await endPoolAndWaitForClients(pool, `${options.label} database pool ${index + 1}`);
      } catch (error) {
        recordFailure(`database pool ${index + 1} shutdown`, error);
      }
    }

    for (const target of options.targets) {
      if (!safeTargets.has(target)) continue;
      const targetLabel = target.label ?? target.databaseName;
      let connectionCountIsZero = false;
      const connectionDrainDeadline = Date.now() + DATABASE_CONNECTION_DRAIN_TIMEOUT_MS;
      try {
        await waitForZeroDatabaseConnections(
          options.maintenancePool,
          target.databaseName,
          targetLabel,
          connectionDrainDeadline,
        );
        connectionCountIsZero = true;
      } catch (error) {
        recordFailure(`${targetLabel} zero-connection attestation`, error);
      }

      if (connectionCountIsZero) {
        try {
          const formatted = await options.maintenancePool.query<{ sql: string }>(
            "SELECT format('DROP DATABASE IF EXISTS %I', $1::text) AS sql",
            [target.databaseName],
          );
          const sql = formatted.rows[0]?.sql;
          if (!sql) throw new Error("PostgreSQL did not format the DROP DATABASE statement");
          await dropDatabaseWithInUseRetry(
            options.maintenancePool,
            target.databaseName,
            targetLabel,
            sql,
            connectionDrainDeadline,
          );
        } catch (error) {
          recordFailure(`${targetLabel} ordinary database drop`, error);
        }
      }

      try {
        const remaining = await options.maintenancePool.query<{ count: number }>(
          "SELECT count(*)::int AS count FROM pg_database WHERE datname=$1",
          [target.databaseName],
        );
        if (remaining.rows[0]?.count !== 0) {
          throw new Error(`${targetLabel} still exists after cleanup`);
        }
      } catch (error) {
        recordFailure(`${targetLabel} post-drop absence verification`, error);
      }
    }
  } finally {
    try {
      await endPoolAndWaitForClients(options.maintenancePool, `${options.label} maintenance pool`);
    } catch (error) {
      recordFailure("maintenance pool shutdown", error);
    }
  }

  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(failures, `${options.label} cleanup failed closed with ${failures.length} errors`);
  }
}

async function waitForZeroDatabaseConnections(
  maintenancePool: Pool,
  databaseName: string,
  label: string,
  deadline: number,
): Promise<void> {
  let attempts = 0;
  while (true) {
    attempts += 1;
    const connections = await maintenancePool.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM pg_stat_activity WHERE datname=$1",
      [databaseName],
    );
    const count = connections.rows[0]?.count;
    if (count === 0) return;
    if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 0) {
      throw new Error(`${label} returned an invalid pg_stat_activity connection count: ${String(count)}`);
    }

    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      throw new Error(
        `${label} still has ${count} active PostgreSQL connection(s) after ${attempts} attestation attempt(s)`,
      );
    }
    await waitForRetry(Math.min(DATABASE_CONNECTION_DRAIN_RETRY_MS, remainingMs));
  }
}

async function dropDatabaseWithInUseRetry(
  maintenancePool: Pool,
  databaseName: string,
  label: string,
  sql: string,
  deadline: number,
): Promise<void> {
  let attempts = 0;
  while (true) {
    attempts += 1;
    try {
      await maintenancePool.query(sql);
      return;
    } catch (error) {
      if (!hasPostgresErrorCode(error, "55006")) throw error;

      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        throw new Error(`${label} remained in use after ${attempts} ordinary DROP DATABASE attempt(s)`, { cause: error });
      }
      await waitForRetry(Math.min(DATABASE_CONNECTION_DRAIN_RETRY_MS, remainingMs));
      await waitForZeroDatabaseConnections(maintenancePool, databaseName, label, deadline);
    }
  }
}

function hasPostgresErrorCode(error: unknown, code: string): boolean {
  return typeof error === "object"
    && error !== null
    && "code" in error
    && (error as { readonly code?: unknown }).code === code;
}

function waitForRetry(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}

export async function cleanupAfterFailure(
  primaryError: unknown,
  cleanup: () => Promise<void>,
  label: string,
): Promise<never> {
  try {
    await cleanup();
  } catch (cleanupError) {
    throw new AggregateError([primaryError, cleanupError], `${label} failed and its teardown also failed`);
  }
  throw primaryError;
}

export async function runWithCleanup<T>(
  work: () => Promise<T>,
  cleanup: () => Promise<void>,
  label: string,
): Promise<T> {
  let primaryError: unknown;
  try {
    return await work();
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      await cleanup();
    } catch (cleanupError) {
      if (primaryError !== undefined) {
        throw new AggregateError([primaryError, cleanupError], `${label} failed and its teardown also failed`);
      }
      throw cleanupError;
    }
  }
}

function assertGenericTemporaryDatabaseName(databaseName: string): void {
  if (
    !DATABASE_IDENTIFIER.test(databaseName)
    || PROTECTED_DATABASE_NAMES.has(databaseName)
    || !TEMPORARY_DATABASE_NAMESPACES.some((pattern) => pattern.test(databaseName))
  ) {
    throw new Error("Refusing to clean up an invalid or protected PostgreSQL database name");
  }
}
