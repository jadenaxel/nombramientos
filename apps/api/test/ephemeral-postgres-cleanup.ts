import type { Pool } from "pg";

const defaultDrainTimeoutMs = 10_000;
const defaultPollIntervalMs = 25;

export interface PoolDrainTarget {
  readonly pool: Pool;
  readonly label: string;
}

export interface EphemeralIdentifierPolicy {
  readonly pattern: RegExp;
  readonly label: string;
}

export interface DatabaseDropOptions extends EphemeralIdentifierPolicy {
  readonly drainTimeoutMs?: number;
  readonly pollIntervalMs?: number;
}

interface PoolDrainTracker extends PoolDrainTarget {
  readonly expectedRemovals: number;
  readonly drained: Promise<void>;
  readonly onRemove: () => void;
  removed: number;
}

/**
 * Closes an owner that may own one or more pg pools and proves that every
 * client which existed at the shutdown boundary emitted pg's `remove` event.
 * This detects pool owners that resolve shutdown while retaining live clients.
 */
export async function closePoolOwnerAndConfirmDrained(
  targets: readonly PoolDrainTarget[],
  closeOwner: () => Promise<unknown>,
  operationLabel: string,
  timeoutMs = defaultDrainTimeoutMs,
): Promise<void> {
  if (targets.length === 0) throw new Error(`${operationLabel} has no pools to attest`);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new Error(`${operationLabel} timeout is outside the test safety boundary`);
  }
  const unique = new Set(targets.map(({ pool }) => pool));
  if (unique.size !== targets.length) throw new Error(`${operationLabel} contains a duplicate pool`);

  const trackers: PoolDrainTracker[] = targets.map((target) => {
    let resolveDrained: (() => void) | undefined;
    const drained = new Promise<void>((resolve) => {
      resolveDrained = resolve;
    });
    const tracker: PoolDrainTracker = {
      ...target,
      expectedRemovals: target.pool.totalCount,
      drained,
      removed: 0,
      onRemove: () => {
        tracker.removed += 1;
        if (tracker.removed === tracker.expectedRemovals) resolveDrained?.();
      },
    };
    if (tracker.expectedRemovals === 0) resolveDrained?.();
    target.pool.on("remove", tracker.onRemove);
    return tracker;
  });
  const failures: Error[] = [];
  try {
    try {
      await withTimeout((async () => {
        await closeOwner();
        await Promise.all(trackers.map(async ({ drained }) => drained));
      })(), timeoutMs, `${operationLabel} timed out while draining PostgreSQL clients`);
    } catch (error) {
      failures.push(cleanupStageError(operationLabel, error));
    }

    for (const tracker of trackers) {
      if (
        tracker.pool.totalCount !== 0
        || tracker.pool.idleCount !== 0
        || tracker.pool.waitingCount !== 0
      ) {
        failures.push(new Error(`${tracker.label} retained PostgreSQL clients after shutdown`));
      }
      if (tracker.removed !== tracker.expectedRemovals) {
        failures.push(new Error(
          `${tracker.label} removal attestation failed (${tracker.removed}/${tracker.expectedRemovals})`,
        ));
      }
    }
  } finally {
    for (const tracker of trackers) tracker.pool.off("remove", tracker.onRemove);
  }

  if (failures.length > 0) {
    throw new AggregateError(failures, `${operationLabel} did not drain cleanly`);
  }
}

export async function endPoolAndConfirmDrained(
  pool: Pool,
  label: string,
  timeoutMs = defaultDrainTimeoutMs,
): Promise<void> {
  await closePoolOwnerAndConfirmDrained([{ pool, label }], async () => pool.end(), label, timeoutMs);
}

/** Waits for PostgreSQL's authoritative connection inventory to reach zero. */
export async function waitForDatabaseConnectionsToDrain(
  maintenance: Pool,
  databaseName: string,
  options: DatabaseDropOptions,
): Promise<void> {
  assertEphemeralIdentifier(databaseName, options);
  const timeoutMs = options.drainTimeoutMs ?? defaultDrainTimeoutMs;
  const pollIntervalMs = options.pollIntervalMs ?? defaultPollIntervalMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 60_000) {
    throw new Error("Ephemeral database drain timeout is outside the test safety boundary");
  }
  if (!Number.isInteger(pollIntervalMs) || pollIntervalMs < 1 || pollIntervalMs > 1_000) {
    throw new Error("Ephemeral database drain poll interval is outside the test safety boundary");
  }

  const deadline = Date.now() + timeoutMs;
  while (true) {
    const active = await maintenance.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM pg_stat_activity WHERE datname=$1",
      [databaseName],
    );
    const count = active.rows[0]?.count;
    if (count === 0) return;
    if (typeof count !== "number" || !Number.isInteger(count) || count < 0) {
      throw new Error(`${options.label} connection inventory is unavailable`);
    }
    if (Date.now() >= deadline) {
      throw new Error(`${options.label} still has ${count} PostgreSQL connection(s) after pool shutdown`);
    }
    await delay(pollIntervalMs);
  }
}

/**
 * Drops only an exact, caller-guarded ephemeral database. It never terminates
 * sessions and never uses FORCE: any leaked client makes teardown fail closed.
 */
export async function dropEphemeralDatabase(
  maintenance: Pool,
  databaseName: string,
  options: DatabaseDropOptions,
): Promise<void> {
  assertEphemeralIdentifier(databaseName, options);
  const target = await maintenance.query<{ current_database: string }>(
    "SELECT current_database()::text AS current_database",
  );
  if (target.rows[0]?.current_database === databaseName) {
    throw new Error(`Refusing to drop ${options.label} through a connection to itself`);
  }

  await waitForDatabaseConnectionsToDrain(maintenance, databaseName, options);
  await executeFormatted(
    maintenance,
    "SELECT format('DROP DATABASE IF EXISTS %I', $1::text) AS sql",
    [databaseName],
    options.label,
  );
  const remaining = await maintenance.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM pg_database WHERE datname=$1",
    [databaseName],
  );
  if (remaining.rows[0]?.count !== 0) {
    throw new Error(`${options.label} survived DROP DATABASE`);
  }
}

export async function dropEphemeralRole(
  maintenance: Pool,
  roleName: string,
  policy: EphemeralIdentifierPolicy,
): Promise<void> {
  assertEphemeralIdentifier(roleName, policy);
  await executeFormatted(
    maintenance,
    "SELECT format('DROP ROLE IF EXISTS %I', $1::text) AS sql",
    [roleName],
    policy.label,
  );
  const remaining = await maintenance.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM pg_roles WHERE rolname=$1",
    [roleName],
  );
  if (remaining.rows[0]?.count !== 0) throw new Error(`${policy.label} survived DROP ROLE`);
}

export async function collectCleanupFailure(
  failures: Error[],
  label: string,
  work: () => Promise<unknown> | undefined,
): Promise<void> {
  try {
    await work();
  } catch (error) {
    failures.push(cleanupStageError(label, error));
  }
}

export function cleanupStageError(label: string, error: unknown): Error {
  const code = typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
  return new Error(`${label} failed${code ? ` (${code})` : ""}`);
}

function assertEphemeralIdentifier(name: string, policy: EphemeralIdentifierPolicy): void {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(name)) {
    throw new Error(`Refusing an invalid PostgreSQL identifier for ${policy.label}`);
  }
  if (policy.pattern.global || policy.pattern.sticky) {
    throw new Error(`Refusing a stateful identifier policy for ${policy.label}`);
  }
  if (!policy.pattern.test(name)) {
    throw new Error(`Refusing cleanup outside the exact ${policy.label} boundary`);
  }
}

async function executeFormatted(
  pool: Pool,
  query: string,
  values: readonly unknown[],
  label: string,
): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error(`PostgreSQL did not format the ${label} cleanup statement`);
  await pool.query(sql);
}

async function withTimeout<T>(work: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    timer.unref();
  });
  try {
    return await Promise.race([work, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    timer.unref();
  });
}
