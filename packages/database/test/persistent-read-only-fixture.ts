import { Pool as PgPool, type PoolConfig } from "pg";

export const PERSISTENT_READ_ONLY_OPTIONS = "-c default_transaction_read_only=on";

/** Test-only: even a SELECT calling a mutating function must fail at PostgreSQL. */
export class PersistentReadOnlyPool extends PgPool {
  public constructor(config: PoolConfig) {
    if (config.options !== undefined || (config.connectionString && new URL(config.connectionString).search)) {
      throw new Error("Persistent test connections cannot override read-only startup options");
    }
    super({ ...config, options: PERSISTENT_READ_ONLY_OPTIONS });
  }
}

/** A resolver creates its own Pool; install the same guard before its first connection. */
export function constrainPersistentResolverPool(pool: PgPool): void {
  if (pool.totalCount !== 0) {
    throw new Error("Read-only resolver guard must be installed before any connection");
  }
  pool.options.options = PERSISTENT_READ_ONLY_OPTIONS;
}
