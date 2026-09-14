import { Pool, type PoolClient, type PoolConfig } from "pg";
import { z } from "zod";
import { sslForMode } from "./config.js";
import type {
  ResolvedTenantCredential,
  SecretProvider,
  TenantCredentialRecord,
  TenantExecutionContext,
  TenantWork,
} from "./types.js";

const uuid = z.string().uuid();

interface PoolEntry {
  readonly credentialVersion: number;
  readonly pool: Pool;
  lastUsedAt: number;
}

export class TenantPoolResolver {
  readonly #entries = new Map<string, PoolEntry>();

  public constructor(
    private readonly resolveRecord: (tenantId: string) => Promise<TenantCredentialRecord>,
    private readonly secrets: SecretProvider,
    private readonly maxPerTenant = 3,
    private readonly idleMs = 60_000,
  ) {}

  public async withTenant<T>(
    context: TenantExecutionContext,
    work: TenantWork<T>,
  ): Promise<T> {
    uuid.parse(context.tenantId);
    uuid.parse(context.identityId);
    uuid.parse(context.sessionId);
    const pool = await this.getPool(context.tenantId);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await setLocalContext(client, context);
      const result = await work(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
      void this.pruneIdle();
    }
  }

  public async getPool(tenantId: string): Promise<Pool> {
    uuid.parse(tenantId);
    const record = await this.resolveRecord(tenantId);
    if (record.tenantId !== tenantId) {
      throw new Error("Tenant credential resolution returned a mismatched tenant");
    }
    assertLocalTenantCredentialRoute(record);

    const existing = this.#entries.get(tenantId);
    if (existing && existing.credentialVersion === record.credentialVersion) {
      existing.lastUsedAt = Date.now();
      return existing.pool;
    }
    if (existing) {
      this.#entries.delete(tenantId);
      await existing.pool.end();
    }

    const resolved: ResolvedTenantCredential = {
      tenantId: record.tenantId,
      host: record.host,
      port: record.port,
      database: record.database,
      user: record.user,
      password: await this.secrets.getSecret(record.secretReference),
      credentialVersion: record.credentialVersion,
      sslMode: record.sslMode,
    };
    const pool = new Pool(poolConfig(resolved, this.maxPerTenant));
    pool.on("error", () => {
      // The caller's structured logger owns diagnostic detail. Never log credentials here.
      this.#entries.delete(tenantId);
    });
    this.#entries.set(tenantId, {
      credentialVersion: record.credentialVersion,
      pool,
      lastUsedAt: Date.now(),
    });
    return pool;
  }

  public async close(): Promise<void> {
    const entries = [...this.#entries.values()];
    this.#entries.clear();
    await Promise.allSettled(entries.map(({ pool }) => pool.end()));
  }

  public async evict(tenantId: string): Promise<void> {
    uuid.parse(tenantId);
    const entry = this.#entries.get(tenantId);
    if (!entry) return;
    this.#entries.delete(tenantId);
    await entry.pool.end();
  }

  private async pruneIdle(): Promise<void> {
    const threshold = Date.now() - this.idleMs;
    const expired = [...this.#entries.entries()].filter(
      ([, entry]) => entry.lastUsedAt < threshold,
    );
    for (const [tenantId, entry] of expired) {
      this.#entries.delete(tenantId);
      await entry.pool.end().catch(() => undefined);
    }
  }
}

/** One-shot connection for a control-plane-authorized invitation saga. */
export async function withResolvedTenantCredential<T>(
  record: TenantCredentialRecord,
  secrets: SecretProvider,
  context: TenantExecutionContext,
  work: TenantWork<T>,
): Promise<T> {
  uuid.parse(context.tenantId);
  uuid.parse(context.identityId);
  uuid.parse(context.sessionId);
  if (record.tenantId !== context.tenantId) {
    throw new Error("Invitation saga credential does not match its tenant context");
  }
  assertLocalTenantCredentialRoute(record);
  const resolved: ResolvedTenantCredential = {
    tenantId: record.tenantId,
    host: record.host,
    port: record.port,
    database: record.database,
    user: record.user,
    password: await secrets.getSecret(record.secretReference),
    credentialVersion: record.credentialVersion,
    sslMode: record.sslMode,
  };
  const pool = new Pool(poolConfig(resolved, 1));
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await setLocalContext(client, context);
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

async function setLocalContext(
  client: PoolClient,
  context: TenantExecutionContext,
): Promise<void> {
  await client.query(
    `SELECT
       set_config('app.tenant_id', $1, true),
       set_config('app.identity_id', $2, true),
       set_config('app.session_id', $3, true),
       set_config('app.request_id', $4, true)`,
    [context.tenantId, context.identityId, context.sessionId, context.requestId],
  );
}

function poolConfig(
  credential: ResolvedTenantCredential,
  max: number,
): PoolConfig {
  return {
    host: credential.host,
    port: credential.port,
    database: credential.database,
    user: credential.user,
    password: credential.password,
    application_name: `nombramientos-tenant-${credential.tenantId.slice(0, 8)}`,
    max,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
    allowExitOnIdle: true,
    ssl: sslForMode(credential.sslMode),
  };
}

export function assertLocalTenantCredentialRoute(record: TenantCredentialRecord): void {
  const suffix = record.tenantId.replaceAll("-", "");
  if (
    !/^[0-9a-f]{32}$/u.test(suffix)
    || record.host !== "127.0.0.1"
    || record.port !== 55_432
    || record.database !== `nom_t_${suffix}`
    || record.user !== `nom_r_${suffix}`
    || !Number.isInteger(record.credentialVersion)
    || record.credentialVersion < 1
    || record.secretReference !== `tenant-db/${record.tenantId}/runtime/v${record.credentialVersion}`
    || record.sslMode !== "disable"
  ) {
    throw new Error("Tenant credential route does not match the protected local deterministic contract");
  }
}
