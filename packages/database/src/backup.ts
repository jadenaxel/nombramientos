import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import type { PoolClient } from "pg";
import { z } from "zod";

const sha256Schema = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const tableInvariantSchema = z.object({
  name: z.string().min(1),
  rows: z.number().int().nonnegative(),
  sha256: sha256Schema,
});
const sequenceInvariantSchema = z.object({
  name: z.string().min(1),
  lastValue: z.string(),
  isCalled: z.boolean(),
});

export const tenantInvariantSchema = z.object({
  tenantId: z.string().uuid(),
  tenantKind: z.enum(["demo", "real"]),
  catalogVersion: z.string().min(1),
  schemaMigrations: z.array(z.object({ name: z.string().min(1), checksum: z.string().min(1) })),
  tables: z.array(tableInvariantSchema),
  sequences: z.array(sequenceInvariantSchema),
  auditHead: z.object({ sequence: z.string(), eventHash: z.string().min(1) }).nullable(),
  outboxHeadSequence: z.string().nullable(),
});

export type TenantInvariant = z.infer<typeof tenantInvariantSchema>;

const backupCoreSchema = z.object({
  backupId: z.string().uuid(),
  tenantId: z.string().uuid(),
  tenantKind: z.enum(["demo", "real"]),
  sourceDatabase: z.string().regex(/^nom_t_[0-9a-f]{32}$/),
  credentialVersion: z.number().int().positive(),
  runtimeSecretReference: z.string().min(1),
  recoveryPointAt: z.string().datetime({ offset: true }),
  backupCompletedAt: z.string().datetime({ offset: true }),
  postgresServerVersion: z.string().min(1),
  pgDumpVersion: z.string().min(1),
  encryptionKeyId: z.string().uuid(),
  invariant: tenantInvariantSchema,
  invariantSha256: sha256Schema,
  dump: z.object({
    format: z.literal("pg_dump-custom"),
    bytes: z.number().int().positive(),
    sha256: sha256Schema,
  }),
}).superRefine((core, context) => {
  const suffix = core.tenantId.replaceAll("-", "");
  if (core.sourceDatabase !== `nom_t_${suffix}`) {
    context.addIssue({ code: "custom", message: "Backup source database must match its tenant id" });
  }
  if (core.runtimeSecretReference !== `tenant-db/${core.tenantId}/runtime/v${core.credentialVersion}`) {
    context.addIssue({ code: "custom", message: "Backup secret reference must match its tenant and credential version" });
  }
  if (core.invariant.tenantId !== core.tenantId || core.invariant.tenantKind !== core.tenantKind) {
    context.addIssue({ code: "custom", message: "Backup invariant must match its tenant identity" });
  }
  if (Date.parse(core.backupCompletedAt) < Date.parse(core.recoveryPointAt)) {
    context.addIssue({ code: "custom", message: "Backup completion cannot precede its recovery point" });
  }
});

export const backupManifestSchema = z.object({
  format: z.literal("nombramientos-tenant-backup"),
  version: z.literal(1),
  core: backupCoreSchema,
  encryption: z.object({
    algorithm: z.literal("AES-256-GCM"),
    nonce: z.string().min(1),
    tag: z.string().min(1),
    aadSha256: sha256Schema,
  }),
  payload: z.object({
    file: z.literal("database.dump.aesgcm"),
    bytes: z.number().int().positive(),
    sha256: sha256Schema,
  }),
});

export type BackupCore = z.infer<typeof backupCoreSchema>;
export type BackupManifest = z.infer<typeof backupManifestSchema>;

export const backupKeyInventorySchema = z.object({
  version: z.literal(1),
  activeKeyId: z.string().uuid(),
  keys: z.array(z.object({
    id: z.string().uuid(),
    createdAt: z.string().datetime({ offset: true }),
    status: z.enum(["active", "retired"]),
    keyB64: z.string().min(1),
  })).min(1),
}).superRefine((inventory, context) => {
  const ids = new Set(inventory.keys.map(({ id }) => id));
  if (ids.size !== inventory.keys.length) {
    context.addIssue({ code: "custom", message: "Backup key ids must be unique" });
  }
  const active = inventory.keys.filter(({ status }) => status === "active");
  if (active.length !== 1 || active[0]?.id !== inventory.activeKeyId) {
    context.addIssue({ code: "custom", message: "Backup key inventory must have one matching active key" });
  }
  for (const key of inventory.keys) {
    if (!isCanonicalBase64Url(key.keyB64, 32)) {
      context.addIssue({ code: "custom", message: "Every backup key must encode exactly 32 bytes" });
    }
  }
});

export type BackupKeyInventory = z.infer<typeof backupKeyInventorySchema>;

export async function captureTenantInvariant(client: PoolClient): Promise<TenantInvariant> {
  await client.query("SET LOCAL TIME ZONE 'UTC'");
  const settings = await client.query<{
    tenant_id: string;
    kind: "demo" | "real";
    catalog_version: string;
  }>("SELECT tenant_id::text,kind,catalog_version FROM tenant_settings WHERE singleton=true");
  const tenant = settings.rows[0];
  if (!tenant) throw new Error("Tenant settings are missing from backup source");

  const migrations = await client.query<{ name: string; checksum: string }>(
    "SELECT name,checksum FROM schema_migrations ORDER BY name",
  );
  const tableNames = await client.query<{ name: string }>(
    `SELECT tablename AS name FROM pg_catalog.pg_tables
      WHERE schemaname='public' ORDER BY tablename`,
  );
  const tables: TenantInvariant["tables"][number][] = [];
  for (const { name } of tableNames.rows) {
    const result = await client.query<{ row_value: string }>(
      `SELECT to_jsonb(source)::text AS row_value
         FROM ${quoteIdentifier(name)} source
        ORDER BY to_jsonb(source)::text`,
    );
    const hash = createHash("sha256");
    for (const row of result.rows) {
      const value = row.row_value;
      hash.update(String(Buffer.byteLength(value, "utf8"))).update(":").update(value).update("\n");
    }
    tables.push({ name, rows: result.rowCount ?? result.rows.length, sha256: `sha256:${hash.digest("hex")}` });
  }

  const sequenceNames = await client.query<{ name: string }>(
    `SELECT sequencename AS name FROM pg_catalog.pg_sequences
      WHERE schemaname='public' ORDER BY sequencename`,
  );
  const sequences: TenantInvariant["sequences"][number][] = [];
  for (const { name } of sequenceNames.rows) {
    const result = await client.query<{ last_value: string; is_called: boolean }>(
      `SELECT last_value::text,is_called FROM ${quoteIdentifier(name)}`,
    );
    const sequence = result.rows[0];
    if (!sequence) throw new Error(`Sequence state is unavailable: ${name}`);
    sequences.push({ name, lastValue: sequence.last_value, isCalled: sequence.is_called });
  }

  const tableSet = new Set(tableNames.rows.map(({ name }) => name));
  const auditHead = tableSet.has("audit_events")
    ? await client.query<{ sequence: string; event_hash: string }>(
        "SELECT sequence::text,event_hash FROM audit_events ORDER BY audit_events.sequence DESC LIMIT 1",
      )
    : null;
  const outboxHead = tableSet.has("outbox_events")
    ? await client.query<{ sequence: string }>(
        "SELECT sequence::text FROM outbox_events ORDER BY outbox_events.sequence DESC LIMIT 1",
      )
    : null;

  return tenantInvariantSchema.parse({
    tenantId: tenant.tenant_id,
    tenantKind: tenant.kind,
    catalogVersion: tenant.catalog_version,
    schemaMigrations: migrations.rows,
    tables,
    sequences,
    auditHead: auditHead?.rows[0]
      ? { sequence: auditHead.rows[0].sequence, eventHash: auditHead.rows[0].event_hash }
      : null,
    outboxHeadSequence: outboxHead?.rows[0]?.sequence ?? null,
  });
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Canonical JSON accepts JSON-compatible values only");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

export function sha256(value: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export async function hashFile(filePath: string): Promise<{ bytes: number; sha256: string }> {
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(filePath)) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += value.byteLength;
    hash.update(value);
  }
  return { bytes, sha256: `sha256:${hash.digest("hex")}` };
}

export async function encryptBackupPayload(inputPath: string, outputPath: string, key: Uint8Array, core: BackupCore): Promise<{
  nonce: string;
  tag: string;
  aadSha256: string;
}> {
  if (key.byteLength !== 32) throw new Error("Backup encryption key must be exactly 32 bytes");
  const nonce = randomBytes(12);
  const aad = Buffer.from(canonicalJson(backupCoreSchema.parse(core)), "utf8");
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  await pipeline(
    createReadStream(inputPath),
    cipher,
    createWriteStream(outputPath, { flags: "wx", mode: 0o600 }),
  );
  return {
    nonce: nonce.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    aadSha256: sha256(aad),
  };
}

export async function decryptBackupPayload(
  inputPath: string,
  outputPath: string,
  key: Uint8Array,
  manifest: BackupManifest,
): Promise<void> {
  const parsed = verifyBackupManifest(manifest);
  if (key.byteLength !== 32) throw new Error("Backup decryption key must be exactly 32 bytes");
  const aad = Buffer.from(canonicalJson(parsed.core), "utf8");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(parsed.encryption.nonce, "base64url"),
  );
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(parsed.encryption.tag, "base64url"));
  try {
    await pipeline(
      createReadStream(inputPath),
      decipher,
      createWriteStream(outputPath, { flags: "wx", mode: 0o600 }),
    );
  } catch (error) {
    await rm(outputPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

export function verifyBackupManifest(value: unknown): BackupManifest {
  const manifest = backupManifestSchema.parse(value);
  if (!isCanonicalBase64Url(manifest.encryption.nonce, 12)) {
    throw new Error("Backup manifest nonce must be 96 bits");
  }
  if (!isCanonicalBase64Url(manifest.encryption.tag, 16)) {
    throw new Error("Backup manifest authentication tag must be 128 bits");
  }
  if (manifest.core.invariantSha256 !== sha256(canonicalJson(manifest.core.invariant))) {
    throw new Error("Backup invariant checksum does not match its manifest");
  }
  if (manifest.encryption.aadSha256 !== sha256(canonicalJson(manifest.core))) {
    throw new Error("Backup authenticated-header checksum does not match its manifest");
  }
  return manifest;
}

export async function readBackupManifest(filePath: string): Promise<BackupManifest> {
  return verifyBackupManifest(JSON.parse(await readFile(filePath, "utf8")) as unknown);
}

export function compareTenantInvariants(expected: TenantInvariant, actual: TenantInvariant): readonly string[] {
  const expectedValue = tenantInvariantSchema.parse(expected);
  const actualValue = tenantInvariantSchema.parse(actual);
  if (canonicalJson(expectedValue) === canonicalJson(actualValue)) return [];
  const differences: string[] = [];
  if (expectedValue.tenantId !== actualValue.tenantId) differences.push("tenantId");
  if (expectedValue.tenantKind !== actualValue.tenantKind) differences.push("tenantKind");
  if (expectedValue.catalogVersion !== actualValue.catalogVersion) differences.push("catalogVersion");
  if (canonicalJson(expectedValue.schemaMigrations) !== canonicalJson(actualValue.schemaMigrations)) differences.push("schemaMigrations");
  if (canonicalJson(expectedValue.tables) !== canonicalJson(actualValue.tables)) differences.push("tables");
  if (canonicalJson(expectedValue.sequences) !== canonicalJson(actualValue.sequences)) differences.push("sequences");
  if (canonicalJson(expectedValue.auditHead) !== canonicalJson(actualValue.auditHead)) differences.push("auditHead");
  if (expectedValue.outboxHeadSequence !== actualValue.outboxHeadSequence) differences.push("outboxHeadSequence");
  return differences;
}

export function scratchDatabaseName(tenantId: string, backupId: string): string {
  const tenantPrefix = z.string().uuid().parse(tenantId).replaceAll("-", "").slice(0, 8);
  const backupPrefix = z.string().uuid().parse(backupId).replaceAll("-", "").slice(0, 8);
  return `nom_restore_${tenantPrefix}_${backupPrefix}`;
}

export function assertScratchDatabaseName(name: string, registeredTenantDatabases: readonly string[]): void {
  if (!/^nom_restore_[0-9a-f]{8}_[0-9a-f]{8}$/.test(name)) {
    throw new Error("Restore target must use the guarded nom_restore_<tenant>_<backup> name");
  }
  if (registeredTenantDatabases.includes(name) || /^nom_t_[0-9a-f]{32}$/.test(name)) {
    throw new Error("Restore target cannot be a registered tenant database");
  }
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function isCanonicalBase64Url(value: string, expectedBytes: number): boolean {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.byteLength === expectedBytes && decoded.toString("base64url") === value;
}
