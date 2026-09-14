import type { PoolClient } from "pg";
import { computeTenantAuditEventHashV2, type TenantAuditEventRecord } from "./audit-anchors.js";

export interface TenantAuditEventDatabaseRow {
  readonly sequence: string;
  readonly id: string;
  readonly occurred_at: Date;
  readonly hash_version: 1 | 2;
  readonly actor_identity_id: string | null;
  readonly action: string;
  readonly entity_type: string | null;
  readonly entity_id: string | null;
  readonly result: "success" | "denied" | "failure";
  readonly request_id: string | null;
  readonly metadata: Record<string, unknown>;
  readonly previous_hash: string | null;
  readonly event_hash: string;
}

/** Keeps every hash-version field when a PostgreSQL audit row crosses into a verifier. */
export function tenantAuditEventRecordFromRow(event: TenantAuditEventDatabaseRow): TenantAuditEventRecord {
  if (!(event.occurred_at instanceof Date) || !Number.isFinite(event.occurred_at.getTime())) {
    throw new Error("Audit event has an invalid PostgreSQL timestamp");
  }
  return {
    sequence: event.sequence,
    id: event.id,
    occurredAt: event.occurred_at.toISOString(),
    hashVersion: event.hash_version,
    actorIdentityId: event.actor_identity_id,
    action: event.action,
    entityType: event.entity_type,
    entityId: event.entity_id,
    result: event.result,
    requestId: event.request_id,
    metadata: event.metadata,
    previousHash: event.previous_hash,
    eventHash: event.event_hash,
  };
}

export interface AppendTenantAuditEventInput {
  readonly action: string;
  readonly entityType: string;
  readonly entityId: string;
  readonly result: "success" | "denied" | "failure";
  readonly metadata: Readonly<Record<string, unknown>>;
}

/**
 * Appends the current tenant audit format while retaining verification support
 * for pre-migration v1 rows. Sequence values may contain rollback gaps, so the
 * value itself is bound into the v2 digest instead of assuming contiguity.
 */
export async function appendTenantAuditEventV2(
  client: PoolClient,
  input: AppendTenantAuditEventInput,
): Promise<void> {
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('tenant_audit_chain', 0))");
  const previous = await client.query<{ event_hash: string }>(
    "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
  );
  const previousHash = previous.rows[0]?.event_hash ?? null;
  const context = await client.query<{ identity_id: string; request_id: string }>(
    `SELECT current_setting('app.identity_id') AS identity_id,
            current_setting('app.request_id') AS request_id`,
  );
  const actor = context.rows[0];
  const reserved = await client.query<{ sequence: string; id: string; occurred_at: Date }>(
    `SELECT nextval(pg_get_serial_sequence('audit_events','sequence'))::text AS sequence,
            gen_random_uuid()::text AS id,clock_timestamp() AS occurred_at`,
  );
  const identity = reserved.rows[0];
  if (!identity) throw new Error("Audit event identity reservation failed");
  const actorIdentityId = actor?.identity_id ?? null;
  const requestId = actor?.request_id ?? null;
  const occurredAt = identity.occurred_at.toISOString();
  const eventHash = computeTenantAuditEventHashV2({
    id: identity.id,
    sequence: identity.sequence,
    occurredAt,
    actorIdentityId,
    action: input.action,
    entityType: input.entityType,
    entityId: input.entityId,
    result: input.result,
    requestId,
    metadata: input.metadata,
    previousHash,
  });
  await client.query(
    `INSERT INTO audit_events(
       sequence,id,occurred_at,actor_identity_id,action,entity_type,entity_id,result,
       request_id,metadata,previous_hash,event_hash,hash_version
     ) OVERRIDING SYSTEM VALUE
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,2)`,
    [
      identity.sequence,
      identity.id,
      occurredAt,
      actorIdentityId,
      input.action,
      input.entityType,
      input.entityId,
      input.result,
      requestId,
      input.metadata,
      previousHash,
      eventHash,
    ],
  );
}
