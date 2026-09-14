import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { verifyTenantAuditEventChain, type TenantAuditEventRecord } from "../src/audit-anchors.js";

const DEMO_TENANT_ID = "d0000000-0000-4000-8000-000000000001";
const DEMO_IDENTITY_ID = "d1000000-0000-4000-8000-000000000001";
const OZAMA_TENANT_ID = "0a2a0000-0000-4000-8000-000000000001";
const DEMO_DATABASE_NAME = "nom_t_d0000000000040008000000000000001";
const OZAMA_DATABASE_NAME = "nom_t_0a2a0000000040008000000000000001";
const moduleParent = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const databasePackageRoot = path.basename(moduleParent).toLowerCase() === "dist"
  ? path.dirname(moduleParent)
  : moduleParent;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_SEED_AUDIT_LIVE"] === "true";
const liveConfig = requireLive ? discoverLiveConfig() : undefined;
const liveReady = Boolean(requireLive && liveConfig && await canReach(liveConfig));

if (requireLive && !liveReady) {
  throw new Error("Seed audit live validation requires the isolated loopback PostgreSQL cluster on port 55432");
}

const live = liveReady ? describe : describe.skip;

live("demo seed v5 append-only audit history on isolated PostgreSQL", () => {
  it("writes a canonical synthetic chain once and never mutates Ozama", async () => {
    const config = liveConfig!;
    const control = new Pool({ connectionString: config.controlUrl, max: 1, connectionTimeoutMillis: 2_000 });
    const demo = new Pool({ connectionString: config.demoUrl, max: 1, connectionTimeoutMillis: 2_000 });
    const ozama = new Pool({ connectionString: config.ozamaUrl, max: 1, connectionTimeoutMillis: 2_000 });
    try {
      const ozamaBeforeFirstSeed = await databaseFingerprint(ozama);
      const ozamaControlBeforeFirstSeed = await controlOzamaFingerprint(control);
      expect(await auditCount(ozama)).toBe(0);

      await runDemoSeed(config.adminUrl);

      const auditRows = await loadAuditChain(demo);
      const verification = verifyTenantAuditEventChain(auditRows);
      expect(verification.valid).toBe(true);
      expect(auditRows.length).toBeGreaterThanOrEqual(3);

      const activeCycle = await demo.query<{ id: string }>(
        "SELECT id FROM election_cycles WHERE status='active' ORDER BY created_at DESC LIMIT 1",
      );
      const cycleId = activeCycle.rows[0]?.id;
      expect(typeof cycleId).toBe("string");
      const expectedSeedEvents = [
        {
          id: fixtureUuid("audit:tenant-ready"),
          actorIdentityId: DEMO_IDENTITY_ID,
          action: "demo.tenant.ready",
          entityType: "tenant",
          entityId: DEMO_TENANT_ID,
          result: "success",
          requestId: null,
          metadata: { synthetic: true, setupState: "ready", seedVersion: 4 },
        },
        {
          id: fixtureUuid("audit:cycle-seeded"),
          actorIdentityId: DEMO_IDENTITY_ID,
          action: "demo.cycle.seeded",
          entityType: "cycle",
          entityId: cycleId,
          result: "success",
          requestId: null,
          metadata: { synthetic: true, vacancies: 40, recommended: 20, accepted: 15, elected: 10 },
        },
        {
          id: fixtureUuid("audit:reference-rounds"),
          actorIdentityId: DEMO_IDENTITY_ID,
          action: "demo.reference-rounds.seeded",
          entityType: "cycle",
          entityId: cycleId,
          result: "success",
          requestId: null,
          metadata: { synthetic: true, completedRounds: 20, frozenSubmissions: 280 },
        },
        {
          id: fixtureUuid("audit:member-envelope-optionals-repaired:v5"),
          actorIdentityId: DEMO_IDENTITY_ID,
          action: "demo.member-envelopes.repaired",
          entityType: "tenant",
          entityId: DEMO_TENANT_ID,
          result: "success",
          requestId: null,
          metadata: { synthetic: true, repairVersion: 5, affectedMembers: 180, optionalNullsOmitted: true },
        },
      ] as const;
      const actualSeedEvents = auditRows
        .filter((event) => expectedSeedEvents.some((expected) => expected.id === event.id))
        .map(({ id, actorIdentityId, action, entityType, entityId, result, requestId, metadata }) => ({
          id,
          actorIdentityId,
          action,
          entityType,
          entityId,
          result,
          requestId,
          metadata,
        }));
      expect(actualSeedEvents.length).toBe(4);
      expect(isDeepStrictEqual(actualSeedEvents, expectedSeedEvents)).toBe(true);

      expect(await databaseFingerprint(ozama)).toEqual(ozamaBeforeFirstSeed);
      expect(await controlOzamaFingerprint(control)).toEqual(ozamaControlBeforeFirstSeed);
      expect(await auditCount(ozama)).toBe(0);

      const demoBeforeRerun = await databaseFingerprint(demo);
      const ozamaBeforeRerun = await databaseFingerprint(ozama);
      const ozamaControlBeforeRerun = await controlOzamaFingerprint(control);

      await runDemoSeed(config.adminUrl);

      expect(await databaseFingerprint(demo)).toEqual(demoBeforeRerun);
      expect(await databaseFingerprint(ozama)).toEqual(ozamaBeforeRerun);
      expect(await controlOzamaFingerprint(control)).toEqual(ozamaControlBeforeRerun);
      expect(await auditCount(ozama)).toBe(0);
    } finally {
      await Promise.allSettled([control.end(), demo.end(), ozama.end()]);
    }
  }, 180_000);
});

interface LiveConfig {
  readonly adminUrl: string;
  readonly controlUrl: string;
  readonly demoUrl: string;
  readonly ozamaUrl: string;
}

interface AuditRow extends TenantAuditEventRecord {
  readonly id: string;
}

interface DatabaseFingerprint {
  readonly tables: readonly {
    readonly table: string;
    readonly rowCount: string;
    readonly digest: string;
  }[];
  readonly sequences: readonly {
    readonly sequence: string;
    readonly lastValue: string | null;
  }[];
}

function discoverLiveConfig(): LiveConfig | undefined {
  let configured = process.env["TEST_SEED_DATABASE_ADMIN_URL"] ?? process.env["DATABASE_ADMIN_URL"];
  if (!configured) {
    try {
      const install = JSON.parse(readFileSync(path.join(databasePackageRoot, ".local", "install.json"), "utf8")) as {
        DATABASE_ADMIN_URL?: string;
      };
      configured = install.DATABASE_ADMIN_URL;
    } catch (error) {
      if (isUnavailableFile(error)) return undefined;
      throw error;
    }
  }
  if (!configured) return undefined;
  let admin: URL;
  try {
    admin = assertWorkspacePostgresUrl(configured, "nom_admin", "postgres");
  } catch {
    return undefined;
  }
  return {
    adminUrl: admin.toString(),
    controlUrl: withDatabase(admin, "nombramientos_control"),
    demoUrl: withDatabase(admin, DEMO_DATABASE_NAME),
    ozamaUrl: withDatabase(admin, OZAMA_DATABASE_NAME),
  };
}

async function canReach(config: LiveConfig): Promise<boolean> {
  const pools = [config.controlUrl, config.demoUrl, config.ozamaUrl]
    .map((connectionString) => new Pool({ connectionString, max: 1, connectionTimeoutMillis: 2_000 }));
  try {
    await Promise.all(pools.map((pool) => pool.query("SELECT 1")));
    return true;
  } catch {
    return false;
  } finally {
    await Promise.allSettled(pools.map((pool) => pool.end()));
  }
}

async function runDemoSeed(adminUrl: string): Promise<void> {
  const tsxEntryPoint = path.join(databasePackageRoot, "node_modules", "tsx", "dist", "cli.mjs");
  const seedEntryPoint = path.join(databasePackageRoot, "scripts", "seed-demo.ts");
  await new Promise<void>((resolve, reject) => {
    const child = spawn(process.execPath, [tsxEntryPoint, seedEntryPoint], {
      cwd: databasePackageRoot,
      env: { ...process.env, DATABASE_ADMIN_URL: adminUrl },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    child.stdout.resume();
    child.stderr.resume();
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("Demo seed timed out; child output was suppressed"));
    }, 120_000);
    child.once("error", () => {
      clearTimeout(timeout);
      reject(new Error("Demo seed process could not start; child output was suppressed"));
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      if (code === 0) resolve();
      else reject(new Error(`Demo seed failed (${signal ?? `exit-${String(code)}`}); child output was suppressed`));
    });
  });
}

async function loadAuditChain(pool: Pool): Promise<AuditRow[]> {
  const result = await pool.query<{
    id: string;
    sequence: string;
    occurred_at: Date;
    hash_version: 1 | 2;
    actor_identity_id: string | null;
    action: string;
    entity_type: string | null;
    entity_id: string | null;
    result: "success" | "denied" | "failure";
    request_id: string | null;
    metadata: Record<string, unknown>;
    previous_hash: string | null;
    event_hash: string;
  }>(
    `SELECT id,sequence::text,occurred_at,hash_version,actor_identity_id,action,entity_type,entity_id,result,
            request_id,metadata,previous_hash,event_hash
       FROM audit_events ORDER BY audit_events.sequence`,
  );
  return result.rows.map((event) => ({
    id: event.id,
    sequence: event.sequence,
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
  }));
}

async function auditCount(pool: Pool): Promise<number> {
  const result = await pool.query<{ count: number }>("SELECT count(*)::int AS count FROM audit_events");
  return result.rows[0]?.count ?? -1;
}

async function databaseFingerprint(pool: Pool): Promise<DatabaseFingerprint> {
  const relations = await pool.query<{ table_name: string }>(
    `SELECT c.relname AS table_name
       FROM pg_class c
       JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind='r'
      ORDER BY c.relname`,
  );
  const tables = [];
  for (const relation of relations.rows) {
    const tableName = relation.table_name;
    const fingerprint = await pool.query<{ row_count: string; digest: string }>(
      `SELECT count(*)::text AS row_count,
              md5(COALESCE(string_agg(row_hash, ',' ORDER BY row_hash), '')) AS digest
         FROM (SELECT md5(to_jsonb(source_row)::text) AS row_hash
                 FROM public.${quoteIdentifier(tableName)} AS source_row) AS row_fingerprints`,
    );
    const row = fingerprint.rows[0];
    if (!row) throw new Error("Database fingerprint query returned no aggregate row");
    tables.push({ table: tableName, rowCount: row.row_count, digest: row.digest });
  }
  const sequenceResult = await pool.query<{ sequence: string; last_value: string | null }>(
    `SELECT sequencename AS sequence,last_value::text
       FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename`,
  );
  return {
    tables,
    sequences: sequenceResult.rows.map((row) => ({ sequence: row.sequence, lastValue: row.last_value })),
  };
}

async function controlOzamaFingerprint(pool: Pool): Promise<{ readonly rowCount: string; readonly digest: string }> {
  const result = await pool.query<{ row_count: string; digest: string }>(
    `WITH ozama_identities AS (
       SELECT identity_id FROM tenant_memberships WHERE tenant_id=$1
     ), relevant AS (
       SELECT 'tenants' AS source,to_jsonb(t) AS value FROM tenants t WHERE id=$1
       UNION ALL SELECT 'provisioning_jobs',to_jsonb(j) FROM provisioning_jobs j WHERE tenant_id=$1
       UNION ALL SELECT 'tenant_memberships',to_jsonb(m) FROM tenant_memberships m WHERE tenant_id=$1
       UNION ALL SELECT 'platform_identities',to_jsonb(i) FROM platform_identities i WHERE id IN (SELECT identity_id FROM ozama_identities)
       UNION ALL SELECT 'platform_role_bindings',to_jsonb(r) FROM platform_role_bindings r WHERE identity_id IN (SELECT identity_id FROM ozama_identities)
       UNION ALL SELECT 'auth_sessions',to_jsonb(s) FROM auth_sessions s WHERE active_tenant_id=$1 OR identity_id IN (SELECT identity_id FROM ozama_identities)
       UNION ALL SELECT 'mfa_challenges',to_jsonb(m) FROM mfa_challenges m WHERE tenant_id=$1 OR identity_id IN (SELECT identity_id FROM ozama_identities)
       UNION ALL SELECT 'platform_audit_events',to_jsonb(a) FROM platform_audit_events a WHERE tenant_id=$1 OR actor_identity_id IN (SELECT identity_id FROM ozama_identities)
       UNION ALL SELECT 'tenant_invitations',to_jsonb(i) FROM tenant_invitations i WHERE tenant_id=$1
     ), row_fingerprints AS (
       SELECT md5(source || ':' || value::text) AS row_hash FROM relevant
     )
     SELECT count(*)::text AS row_count,
            md5(COALESCE(string_agg(row_hash, ',' ORDER BY row_hash), '')) AS digest
       FROM row_fingerprints`,
    [OZAMA_TENANT_ID],
  );
  const row = result.rows[0];
  if (!row) throw new Error("Ozama control fingerprint query returned no aggregate row");
  return { rowCount: row.row_count, digest: row.digest };
}

function withDatabase(admin: URL, database: string): string {
  const value = new URL(admin);
  value.pathname = `/${database}`;
  return value.toString();
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function fixtureUuid(label: string): string {
  const raw = createHash("sha256").update(`nombramientos-demo:${label}`).digest("hex").slice(0, 32).split("");
  raw[12] = "4";
  raw[16] = "8";
  const hex = raw.join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isUnavailableFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error
    && (error.code === "ENOENT" || error.code === "EACCES" || error.code === "EPERM");
}
