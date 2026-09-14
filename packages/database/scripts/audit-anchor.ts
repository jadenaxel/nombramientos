import { constants as fsConstants } from "node:fs";
import {
  chmod,
  copyFile,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  unlink,
} from "node:fs/promises";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import path from "node:path";
import { Pool, type PoolClient } from "pg";
import { z } from "zod";
import {
  appendLocalAuditEvidence,
  assertIsolatedAuditAdminUrl,
  createLocalAuditLedger,
  createLocalAuditReceipt,
  ledgerGenerationFilename,
  LOCAL_AUDIT_STORAGE_ASSURANCE,
  parseLocalAuditLedger,
  parseLocalAuditReceipt,
  receiptGenerationFilename,
  verifyLocalAuditLedger,
  type LocalAuditLedger,
  type LocalAuditReceipt,
} from "../src/audit-anchor-ledger.js";
import {
  createSignedAuditAnchor,
  createSignedAuditCheckpoint,
  verifyTenantAuditEventChain,
  type AnchoredAuditTrailVerification,
  type AuditPublicKeyRing,
  type TenantAuditEventRecord,
} from "../src/audit-anchors.js";
import { tenantAuditEventRecordFromRow } from "../src/audit-event-chain.js";
import { resolveDatabasePackageRoot } from "./script-config.js";

const STREAM_ID = "tenant-audit";
const TENANT_ID = z.string().uuid();
const installSchema = z.object({
  version: z.literal(1),
  DATABASE_ADMIN_URL: z.string().url(),
}).passthrough();
const tenantRouteSchema = z.object({
  id: z.string().uuid(),
  kind: z.enum(["demo", "real"]),
  database_name: z.string().min(1),
  database_host: z.string().min(1),
  database_port: z.coerce.number().int(),
  status: z.literal("active"),
}).strict();
const auditRowSchema = z.object({
  sequence: z.string().regex(/^[1-9][0-9]*$/),
  id: z.string().uuid(),
  occurred_at: z.date(),
  hash_version: z.union([z.literal(1), z.literal(2)]),
  actor_identity_id: z.string().uuid().nullable(),
  action: z.string().min(1),
  entity_type: z.string().nullable(),
  entity_id: z.string().nullable(),
  result: z.enum(["success", "denied", "failure"]),
  request_id: z.string().uuid().nullable(),
  metadata: z.record(z.string(), z.unknown()),
  previous_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  event_hash: z.string().regex(/^[0-9a-f]{64}$/),
}).strict();

const signingKeySchema = z.object({
  id: z.string().uuid(),
  purpose: z.enum(["checkpoint", "anchor"]),
  algorithm: z.literal("Ed25519"),
  status: z.enum(["active", "retired"]),
  createdAt: z.string().datetime({ offset: true }),
  privateKeyPkcs8Pem: z.string().startsWith("-----BEGIN PRIVATE KEY-----"),
  publicKeySpkiPem: z.string().startsWith("-----BEGIN PUBLIC KEY-----"),
}).strict();
const signingInventorySchema = z.object({
  format: z.literal("nombramientos-local-audit-signing-keys"),
  version: z.literal(1),
  storageAssurance: z.literal(LOCAL_AUDIT_STORAGE_ASSURANCE),
  checkpointActiveKeyId: z.string().uuid(),
  anchorActiveKeyId: z.string().uuid(),
  keys: z.array(signingKeySchema).min(2),
}).strict().superRefine((inventory, context) => {
  const ids = new Set<string>();
  for (const key of inventory.keys) {
    if (ids.has(key.id)) context.addIssue({ code: "custom", message: "Signing inventory contains duplicate key ids" });
    ids.add(key.id);
  }
  const activeCheckpoints = inventory.keys.filter((key) => key.purpose === "checkpoint" && key.status === "active");
  const activeAnchors = inventory.keys.filter((key) => key.purpose === "anchor" && key.status === "active");
  if (activeCheckpoints.length !== 1 || activeCheckpoints[0]?.id !== inventory.checkpointActiveKeyId) {
    context.addIssue({ code: "custom", message: "Signing inventory must identify exactly one active checkpoint key" });
  }
  if (activeAnchors.length !== 1 || activeAnchors[0]?.id !== inventory.anchorActiveKeyId) {
    context.addIssue({ code: "custom", message: "Signing inventory must identify exactly one active anchor key" });
  }
  if (inventory.checkpointActiveKeyId === inventory.anchorActiveKeyId) {
    context.addIssue({ code: "custom", message: "Checkpoint and anchor signing keys must be distinct" });
  }
});

type SigningInventory = z.infer<typeof signingInventorySchema>;

interface ToolOptions {
  readonly action: "configure" | "checkpoint" | "verify" | "drill";
  readonly tenantId?: string;
}

interface LocalAuditContext {
  readonly packageRoot: string;
  readonly localRoot: string;
  readonly auditRoot: string;
  readonly ledgersRoot: string;
  readonly receiptsRoot: string;
  readonly workRoot: string;
  readonly locksRoot: string;
  readonly signingInventoryPath: string;
  readonly adminUrl: URL;
}

interface LoadedSigningKeys {
  readonly inventory: SigningInventory;
  readonly checkpointPrivateKey: KeyObject;
  readonly anchorPrivateKey: KeyObject;
  readonly checkpointPublicKeys: AuditPublicKeyRing;
  readonly anchorPublicKeys: AuditPublicKeyRing;
}

interface TenantAuditSnapshot {
  readonly tenantId: string;
  readonly tenantKind: "demo" | "real";
  readonly databaseName: string;
  readonly events: readonly TenantAuditEventRecord[];
  readonly postgresVersion: string;
  readonly transactionReadOnly: true;
}

interface StoredEvidence {
  readonly ledger: LocalAuditLedger;
  readonly receipt: LocalAuditReceipt;
  readonly ledgerPath: string;
  readonly receiptPath: string;
}

async function main(): Promise<void> {
  const options = parseArguments(process.argv.slice(2));
  const context = await loadContext();
  if (options.action === "configure") {
    const keys = await loadSigningKeys(context, true);
    emit({
      action: "configure",
      status: "ready",
      storageAssurance: LOCAL_AUDIT_STORAGE_ASSURANCE,
      checkpointSigningKeyId: keys.inventory.checkpointActiveKeyId,
      anchorSigningKeyId: keys.inventory.anchorActiveKeyId,
      secretMaterialPrinted: false,
    });
    return;
  }

  const tenantId = options.tenantId;
  if (!tenantId) throw new Error("--tenant-id is required for every tenant audit action");
  const keys = await loadSigningKeys(context, options.action === "checkpoint");
  const lockPath = path.join(context.locksRoot, `${tenantId}.lock`);
  await withExclusiveLock(lockPath, context.locksRoot, async () => {
    const snapshot = await readTenantAuditSnapshot(context.adminUrl, tenantId);
    if (options.action === "checkpoint") {
      await checkpointTenant(context, snapshot, keys);
    } else if (options.action === "verify") {
      await verifyTenant(context, snapshot, keys);
    } else {
      await drillTenant(context, snapshot, keys);
    }
  });
}

function parseArguments(values: readonly string[]): ToolOptions {
  let action: ToolOptions["action"] | undefined;
  let tenantId: string | undefined;
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    const value = values[index + 1];
    if (key === "--action" && value && ["configure", "checkpoint", "verify", "drill"].includes(value)) {
      action = value as ToolOptions["action"];
      index += 1;
    } else if (key === "--tenant-id" && value) {
      tenantId = TENANT_ID.parse(value);
      index += 1;
    } else {
      throw new Error(`Unsupported audit-anchor argument: ${key ?? "missing"}`);
    }
  }
  if (!action) throw new Error("--action must be configure, checkpoint, verify, or drill");
  if (action === "configure" && tenantId) throw new Error("configure does not accept --tenant-id");
  return { action, ...(tenantId ? { tenantId } : {}) };
}

async function loadContext(): Promise<LocalAuditContext> {
  const packageRoot = path.resolve(resolveDatabasePackageRoot(import.meta.url));
  const localRoot = path.join(packageRoot, ".local");
  await requirePlainDirectory(localRoot, ".local directory");
  const resolvedLocalRoot = await realpath(localRoot);
  const installPath = path.join(resolvedLocalRoot, "install.json");
  const install = installSchema.parse(await readJsonFile(installPath, resolvedLocalRoot, "local install configuration"));
  const adminUrl = assertIsolatedAuditAdminUrl(install.DATABASE_ADMIN_URL);
  const auditRoot = await ensureDirectory(path.join(resolvedLocalRoot, "audit-anchors"), resolvedLocalRoot);
  const [ledgersRoot, receiptsRoot, workRoot, locksRoot] = await Promise.all([
    ensureDirectory(path.join(auditRoot, "ledgers"), auditRoot),
    ensureDirectory(path.join(auditRoot, "receipts"), auditRoot),
    ensureDirectory(path.join(auditRoot, "work"), auditRoot),
    ensureDirectory(path.join(auditRoot, "locks"), auditRoot),
  ]);
  return {
    packageRoot,
    localRoot: resolvedLocalRoot,
    auditRoot,
    ledgersRoot,
    receiptsRoot,
    workRoot,
    locksRoot,
    signingInventoryPath: path.join(resolvedLocalRoot, "audit-signing-keys.json"),
    adminUrl,
  };
}

async function loadSigningKeys(context: LocalAuditContext, allowCreate: boolean): Promise<LoadedSigningKeys> {
  const lockPath = path.join(context.locksRoot, "signing-inventory.lock");
  return withExclusiveLock(lockPath, context.locksRoot, async () => {
    let raw: unknown;
    try {
      raw = await readJsonFile(context.signingInventoryPath, context.localRoot, "audit signing inventory");
    } catch (error) {
      if (!isMissingFile(error)) throw error;
      if (!allowCreate) {
        throw new Error("Audit signing inventory is missing; run configure or checkpoint explicitly first");
      }
      const inventory = createSigningInventory();
      await writeImmutableJson(context.signingInventoryPath, inventory, context.localRoot);
      raw = inventory;
    }
    return materializeSigningKeys(signingInventorySchema.parse(raw));
  });
}

function createSigningInventory(): SigningInventory {
  const checkpoint = generateKeyPairSync("ed25519");
  const anchor = generateKeyPairSync("ed25519");
  const checkpointId = randomUUID();
  const anchorId = randomUUID();
  const createdAt = new Date().toISOString();
  return signingInventorySchema.parse({
    format: "nombramientos-local-audit-signing-keys",
    version: 1,
    storageAssurance: LOCAL_AUDIT_STORAGE_ASSURANCE,
    checkpointActiveKeyId: checkpointId,
    anchorActiveKeyId: anchorId,
    keys: [
      {
        id: checkpointId,
        purpose: "checkpoint",
        algorithm: "Ed25519",
        status: "active",
        createdAt,
        privateKeyPkcs8Pem: checkpoint.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        publicKeySpkiPem: checkpoint.publicKey.export({ type: "spki", format: "pem" }).toString(),
      },
      {
        id: anchorId,
        purpose: "anchor",
        algorithm: "Ed25519",
        status: "active",
        createdAt,
        privateKeyPkcs8Pem: anchor.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        publicKeySpkiPem: anchor.publicKey.export({ type: "spki", format: "pem" }).toString(),
      },
    ],
  });
}

function materializeSigningKeys(inventory: SigningInventory): LoadedSigningKeys {
  const checkpointPublicKeys = new Map<string, KeyObject>();
  const anchorPublicKeys = new Map<string, KeyObject>();
  let checkpointPrivateKey: KeyObject | undefined;
  let anchorPrivateKey: KeyObject | undefined;
  for (const record of inventory.keys) {
    const privateKey = createPrivateKey(record.privateKeyPkcs8Pem);
    const publicKey = createPublicKey(record.publicKeySpkiPem);
    if (privateKey.asymmetricKeyType !== "ed25519" || publicKey.asymmetricKeyType !== "ed25519") {
      throw new Error("Audit signing inventory contains a non-Ed25519 key");
    }
    const derived = createPublicKey(privateKey).export({ type: "spki", format: "der" });
    const declared = publicKey.export({ type: "spki", format: "der" });
    if (derived.byteLength !== declared.byteLength || !timingSafeEqual(derived, declared)) {
      throw new Error("Audit signing inventory public/private key pair does not match");
    }
    if (record.purpose === "checkpoint") checkpointPublicKeys.set(record.id, publicKey);
    else anchorPublicKeys.set(record.id, publicKey);
    if (record.id === inventory.checkpointActiveKeyId) checkpointPrivateKey = privateKey;
    if (record.id === inventory.anchorActiveKeyId) anchorPrivateKey = privateKey;
  }
  if (!checkpointPrivateKey || !anchorPrivateKey) throw new Error("Active audit signing private keys are unavailable");
  return { inventory, checkpointPrivateKey, anchorPrivateKey, checkpointPublicKeys, anchorPublicKeys };
}

async function readTenantAuditSnapshot(adminUrl: URL, tenantId: string): Promise<TenantAuditSnapshot> {
  const controlUrl = new URL(adminUrl);
  controlUrl.pathname = "/nombramientos_control";
  const control = createAdminPool(controlUrl, "nombramientos-audit-anchor-control");
  let route: z.infer<typeof tenantRouteSchema>;
  try {
    route = await inReadOnlyTransaction(control, async (client) => {
      const result = await client.query(
        `SELECT id::text,kind,database_name::text,database_host,database_port,status
           FROM tenants WHERE id=$1 AND status='active'`,
        [tenantId],
      );
      const row = result.rows[0];
      if (!row) throw new Error("Active tenant audit route was not found");
      return tenantRouteSchema.parse(row);
    });
  } finally {
    await control.end();
  }

  const suffix = tenantId.replaceAll("-", "");
  if (route.database_name !== `nom_t_${suffix}`) {
    throw new Error("Tenant audit route does not match its deterministic database boundary");
  }
  if (route.database_host !== "127.0.0.1" || route.database_port !== 55432) {
    throw new Error("Tenant audit route is outside isolated loopback PostgreSQL port 55432");
  }

  const tenantUrl = new URL(adminUrl);
  tenantUrl.pathname = `/${route.database_name}`;
  const tenant = createAdminPool(tenantUrl, "nombramientos-audit-anchor-tenant-readonly");
  try {
    return await inReadOnlyTransaction(tenant, async (client) => {
      const runtime = await client.query<{
        current_user: string;
        current_database: string;
        transaction_read_only: string;
        server_version: string;
      }>(
        `SELECT current_user,current_database(),
                current_setting('transaction_read_only') AS transaction_read_only,
                current_setting('server_version') AS server_version`,
      );
      const state = runtime.rows[0];
      if (
        !state ||
        state.current_user !== decodeURIComponent(adminUrl.username) ||
        state.current_database !== route.database_name ||
        state.transaction_read_only !== "on" ||
        !state.server_version.startsWith("18.")
      ) {
        throw new Error("Tenant audit snapshot did not establish the expected PostgreSQL 18 read-only boundary");
      }
      const settings = await client.query<{ tenant_id: string; kind: "demo" | "real" }>(
        "SELECT tenant_id::text,kind FROM tenant_settings WHERE singleton=true",
      );
      const setting = settings.rows[0];
      if (!setting || setting.tenant_id !== tenantId || setting.kind !== route.kind) {
        throw new Error("Tenant settings do not match the selected control-plane route");
      }
      const result = await client.query(
        `SELECT sequence::text,id::text,occurred_at,hash_version,actor_identity_id::text,action,entity_type,entity_id,result,
                request_id::text,metadata,previous_hash,event_hash
           FROM audit_events ORDER BY audit_events.sequence`,
      );
      const events = result.rows.map((raw): TenantAuditEventRecord => {
        const row = auditRowSchema.parse(raw);
        return tenantAuditEventRecordFromRow(row);
      });
      const chain = verifyTenantAuditEventChain(events);
      if (!chain.valid) throw new Error(`Current database audit chain failed verification: ${chain.code}: ${chain.message}`);
      return {
        tenantId,
        tenantKind: route.kind,
        databaseName: route.database_name,
        events,
        postgresVersion: state.server_version,
        transactionReadOnly: true,
      };
    });
  } finally {
    await tenant.end();
  }
}

async function inReadOnlyTransaction<T>(pool: Pool, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const mode = await client.query<{ transaction_read_only: string }>(
      "SELECT current_setting('transaction_read_only') AS transaction_read_only",
    );
    if (mode.rows[0]?.transaction_read_only !== "on") throw new Error("PostgreSQL refused the read-only transaction mode");
    const value = await operation(client);
    await client.query("COMMIT");
    return value;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function createAdminPool(url: URL, applicationName: string): Pool {
  return new Pool({
    host: url.hostname,
    port: Number(url.port),
    database: decodeURIComponent(url.pathname.replace(/^\//u, "")),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    ssl: false,
    application_name: applicationName,
    max: 1,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 1_000,
  });
}

async function checkpointTenant(
  context: LocalAuditContext,
  snapshot: TenantAuditSnapshot,
  keys: LoadedSigningKeys,
): Promise<void> {
  const existing = await loadLatestEvidence(context, snapshot.tenantId);
  if (existing) verifyExistingPrefix(snapshot.events, existing, keys);
  const previousCheckpoint = existing?.ledger.checkpoints.at(-1) ?? null;
  const previousAnchor = existing?.ledger.anchors.at(-1) ?? null;
  if (previousCheckpoint?.lastSequence === snapshot.events.at(-1)?.sequence) {
    const verified = verifyStoredEvidence(snapshot.events, existing!, keys);
    requireVerified(verified, "Existing current audit evidence");
    emitCheckpointResult("current", snapshot, existing!);
    return;
  }

  const checkpoint = createSignedAuditCheckpoint({
    tenantId: snapshot.tenantId,
    streamId: STREAM_ID,
    checkpointId: randomUUID(),
    capturedAt: new Date().toISOString(),
    events: snapshot.events,
    previousCheckpoint,
    signingKeyId: keys.inventory.checkpointActiveKeyId,
    privateKey: keys.checkpointPrivateKey,
  });
  const anchor = createSignedAuditAnchor({
    checkpoint,
    anchorId: randomUUID(),
    anchoredAt: new Date().toISOString(),
    previousAnchor,
    signingKeyId: keys.inventory.anchorActiveKeyId,
    privateKey: keys.anchorPrivateKey,
  });
  const ledger = appendLocalAuditEvidence(
    existing?.ledger ?? createLocalAuditLedger(snapshot.tenantId, STREAM_ID),
    checkpoint,
    anchor,
  );
  const ledgerFile = ledgerGenerationFilename(anchor);
  const receipt = createLocalAuditReceipt(anchor, ledgerFile, new Date().toISOString());
  requireVerified(verifyLocalAuditLedger({
    events: snapshot.events,
    ledger,
    receipt,
    checkpointPublicKeys: keys.checkpointPublicKeys,
    anchorPublicKeys: keys.anchorPublicKeys,
  }), "New audit evidence");

  const { ledgerDirectory, receiptDirectory } = await ensureTenantDirectories(context, snapshot.tenantId);
  const ledgerPath = path.join(ledgerDirectory, ledgerFile);
  const receiptPath = path.join(receiptDirectory, receiptGenerationFilename(receipt));
  let ledgerWritten = false;
  let receiptWritten = false;
  try {
    await writeImmutableJson(ledgerPath, ledger, ledgerDirectory);
    ledgerWritten = true;
    await writeImmutableJson(receiptPath, receipt, receiptDirectory);
    receiptWritten = true;
  } finally {
    if (!receiptWritten && ledgerWritten) await removeExactFile(ledgerPath, ledgerDirectory);
  }

  const persisted = await loadLatestEvidence(context, snapshot.tenantId);
  if (!persisted) throw new Error("Persisted audit evidence is unavailable after append");
  requireVerified(verifyStoredEvidence(snapshot.events, persisted, keys), "Persisted audit evidence");
  emitCheckpointResult("completed", snapshot, persisted);
}

function emitCheckpointResult(status: "completed" | "current", snapshot: TenantAuditSnapshot, evidence: StoredEvidence): void {
  emit({
    action: "checkpoint",
    status,
    tenantId: snapshot.tenantId,
    tenantKind: snapshot.tenantKind,
    eventCount: snapshot.events.length,
    checkpointCount: evidence.ledger.checkpoints.length,
    anchorSequence: evidence.receipt.anchorSequence,
    receipt: {
      tenantId: evidence.receipt.tenantId,
      streamId: evidence.receipt.streamId,
      anchorSequence: evidence.receipt.anchorSequence,
      checkpointHash: evidence.receipt.checkpointHash,
      anchorHash: evidence.receipt.anchorHash,
      storageAssurance: evidence.receipt.storageAssurance,
    },
    transactionReadOnly: snapshot.transactionReadOnly,
    postgresMajor: snapshot.postgresVersion.split(".")[0],
    secretMaterialPrinted: false,
  });
}

async function verifyTenant(
  context: LocalAuditContext,
  snapshot: TenantAuditSnapshot,
  keys: LoadedSigningKeys,
): Promise<void> {
  const evidence = await loadLatestEvidence(context, snapshot.tenantId);
  if (!evidence) throw new Error("No local audit checkpoint exists for the requested tenant");
  const result = verifyStoredEvidence(snapshot.events, evidence, keys);
  requireVerified(result, "Audit ledger verification");
  emit({
    action: "verify",
    status: "passed",
    tenantId: snapshot.tenantId,
    eventCount: result.valid ? result.eventCount : "unavailable",
    checkpointCount: evidence.ledger.checkpoints.length,
    anchorCount: evidence.ledger.anchors.length,
    anchorSequence: evidence.receipt.anchorSequence,
    latestAnchorHash: evidence.receipt.anchorHash,
    transactionReadOnly: snapshot.transactionReadOnly,
    storageAssurance: evidence.receipt.storageAssurance,
    secretMaterialPrinted: false,
  });
}

async function drillTenant(
  context: LocalAuditContext,
  snapshot: TenantAuditSnapshot,
  keys: LoadedSigningKeys,
): Promise<void> {
  const evidence = await loadLatestEvidence(context, snapshot.tenantId);
  if (!evidence) throw new Error("A checkpoint is required before running the audit evidence drill");
  requireVerified(verifyStoredEvidence(snapshot.events, evidence, keys), "Audit drill baseline");
  if (snapshot.events.length < 3) throw new Error("Audit drill requires at least three anchored events");

  const temporaryDirectory = await mkdtemp(path.join(context.workRoot, "audit-drill-"));
  await assertResolvedWithin(context.workRoot, temporaryDirectory, "audit drill directory");
  const copiedLedgerPath = path.join(temporaryDirectory, "ledger.json");
  const copiedReceiptPath = path.join(temporaryDirectory, "receipt.json");
  let cases: Record<string, { detected: true; code: string }> | undefined;
  try {
    await copyFile(evidence.ledgerPath, copiedLedgerPath, fsConstants.COPYFILE_EXCL);
    await copyFile(evidence.receiptPath, copiedReceiptPath, fsConstants.COPYFILE_EXCL);
    await Promise.all([chmod(copiedLedgerPath, 0o600), chmod(copiedReceiptPath, 0o600)]);
    const copiedLedger = parseLocalAuditLedger(JSON.parse(await readFile(copiedLedgerPath, "utf8")) as unknown);
    const copiedReceipt = parseLocalAuditReceipt(JSON.parse(await readFile(copiedReceiptPath, "utf8")) as unknown);
    cases = {};

    const altered = [...snapshot.events];
    const alteredIndex = Math.floor(altered.length / 2);
    altered[alteredIndex] = {
      ...altered[alteredIndex]!,
      metadata: { ...altered[alteredIndex]!.metadata, auditDrillMutation: "altered" },
    };
    cases["alteration"] = requireDetected(
      verifyCopied(altered, copiedLedger, copiedReceipt, keys),
      "alteration",
    );

    const deleted = snapshot.events.filter((_, index) => index !== 1);
    cases["intermediateDeletion"] = requireDetected(
      verifyCopied(deleted, copiedLedger, copiedReceipt, keys),
      "intermediate deletion",
    );

    cases["truncation"] = requireDetected(
      verifyCopied(snapshot.events.slice(0, -1), copiedLedger, copiedReceipt, keys),
      "truncation",
    );

    const reordered = [...snapshot.events];
    [reordered[1], reordered[2]] = [reordered[2]!, reordered[1]!];
    cases["reordering"] = requireDetected(
      verifyCopied(reordered, copiedLedger, copiedReceipt, keys),
      "reordering",
    );

    cases["rollback"] = runRollbackDrill(snapshot.events, copiedLedger, copiedReceipt, keys);
  } finally {
    await removeExactDirectory(temporaryDirectory, context.workRoot);
  }
  if (!cases) throw new Error("Audit drill did not produce detection evidence");
  emit({
    action: "drill",
    status: "passed",
    tenantId: snapshot.tenantId,
    baselineVerified: true,
    temporaryEvidenceCopied: true,
    cases,
    databaseWrites: 0,
    transactionReadOnly: snapshot.transactionReadOnly,
    storageAssurance: LOCAL_AUDIT_STORAGE_ASSURANCE,
    secretMaterialPrinted: false,
    temporaryEvidenceRemoved: true,
  });
}

function runRollbackDrill(
  events: readonly TenantAuditEventRecord[],
  ledger: LocalAuditLedger,
  receipt: LocalAuditReceipt,
  keys: LoadedSigningKeys,
): { detected: true; code: string } {
  if (ledger.checkpoints.length >= 2) {
    const oldLedger = parseLocalAuditLedger({
      ...ledger,
      checkpoints: ledger.checkpoints.slice(0, -1),
      anchors: ledger.anchors.slice(0, -1),
    });
    const oldCoverage = Number(BigInt(oldLedger.checkpoints.at(-1)!.eventCount));
    return requireDetected(
      verifyCopied(events.slice(0, oldCoverage), oldLedger, receipt, keys),
      "rollback",
    );
  }

  const split = Math.max(1, Math.floor(events.length / 2));
  const ephemeralCheckpointKeys = generateKeyPairSync("ed25519");
  const ephemeralAnchorKeys = generateKeyPairSync("ed25519");
  const checkpointKeyId = randomUUID();
  const anchorKeyId = randomUUID();
  const checkpointOne = createSignedAuditCheckpoint({
    tenantId: ledger.tenantId,
    streamId: ledger.streamId,
    checkpointId: randomUUID(),
    capturedAt: "2026-09-11T00:00:00.000Z",
    events: events.slice(0, split),
    signingKeyId: checkpointKeyId,
    privateKey: ephemeralCheckpointKeys.privateKey,
  });
  const anchorOne = createSignedAuditAnchor({
    checkpoint: checkpointOne,
    anchorId: randomUUID(),
    anchoredAt: "2026-09-11T00:00:01.000Z",
    signingKeyId: anchorKeyId,
    privateKey: ephemeralAnchorKeys.privateKey,
  });
  const checkpointTwo = createSignedAuditCheckpoint({
    tenantId: ledger.tenantId,
    streamId: ledger.streamId,
    checkpointId: randomUUID(),
    capturedAt: "2026-09-11T00:00:02.000Z",
    events,
    previousCheckpoint: checkpointOne,
    signingKeyId: checkpointKeyId,
    privateKey: ephemeralCheckpointKeys.privateKey,
  });
  const anchorTwo = createSignedAuditAnchor({
    checkpoint: checkpointTwo,
    anchorId: randomUUID(),
    anchoredAt: "2026-09-11T00:00:03.000Z",
    previousAnchor: anchorOne,
    signingKeyId: anchorKeyId,
    privateKey: ephemeralAnchorKeys.privateKey,
  });
  const oldLedger = appendLocalAuditEvidence(
    createLocalAuditLedger(ledger.tenantId, ledger.streamId),
    checkpointOne,
    anchorOne,
  );
  const currentLedger = appendLocalAuditEvidence(oldLedger, checkpointTwo, anchorTwo);
  const laterReceipt = createLocalAuditReceipt(
    anchorTwo,
    ledgerGenerationFilename(anchorTwo),
    "2026-09-11T00:00:04.000Z",
  );
  const result = verifyLocalAuditLedger({
    events: events.slice(0, split),
    ledger: oldLedger,
    receipt: laterReceipt,
    checkpointPublicKeys: new Map([[checkpointKeyId, ephemeralCheckpointKeys.publicKey]]),
    anchorPublicKeys: new Map([[anchorKeyId, ephemeralAnchorKeys.publicKey]]),
  });
  // Keep the current generation reachable during the drill so both sides of
  // the rollback comparison are constructed and type-checked.
  if (currentLedger.anchors.length !== 2) throw new Error("Synthetic rollback drill did not create a later anchor");
  return requireDetected(result, "rollback");
}

function verifyCopied(
  events: readonly TenantAuditEventRecord[],
  ledger: LocalAuditLedger,
  receipt: LocalAuditReceipt,
  keys: LoadedSigningKeys,
): AnchoredAuditTrailVerification {
  return verifyLocalAuditLedger({
    events,
    ledger,
    receipt,
    checkpointPublicKeys: keys.checkpointPublicKeys,
    anchorPublicKeys: keys.anchorPublicKeys,
  });
}

function verifyStoredEvidence(
  events: readonly TenantAuditEventRecord[],
  evidence: StoredEvidence,
  keys: LoadedSigningKeys,
): AnchoredAuditTrailVerification {
  return verifyCopied(events, evidence.ledger, evidence.receipt, keys);
}

function verifyExistingPrefix(
  events: readonly TenantAuditEventRecord[],
  evidence: StoredEvidence,
  keys: LoadedSigningKeys,
): void {
  const eventCount = BigInt(evidence.ledger.checkpoints.at(-1)!.eventCount);
  if (eventCount > BigInt(events.length)) {
    throw new Error("Database audit history is shorter than the independently retained checkpoint");
  }
  const result = verifyStoredEvidence(events.slice(0, Number(eventCount)), evidence, keys);
  requireVerified(result, "Existing audit evidence prefix");
}

function requireVerified(result: AnchoredAuditTrailVerification, label: string): void {
  if (!result.valid) throw new Error(`${label} failed safely: ${result.code}`);
}

function requireDetected(
  result: AnchoredAuditTrailVerification,
  label: string,
): { detected: true; code: string } {
  if (result.valid) throw new Error(`Audit drill failed to detect ${label}`);
  return { detected: true, code: result.code };
}

async function loadLatestEvidence(context: LocalAuditContext, tenantId: string): Promise<StoredEvidence | null> {
  const receiptDirectory = path.join(context.receiptsRoot, tenantId);
  const ledgerDirectory = path.join(context.ledgersRoot, tenantId);
  if (!(await isDirectory(receiptDirectory))) {
    if (await pathExists(ledgerDirectory)) {
      if (!(await isDirectory(ledgerDirectory)) || (await readdir(ledgerDirectory)).length > 0) {
        throw new Error("Audit ledger exists without its independent receipt directory");
      }
    }
    return null;
  }
  await assertResolvedWithin(context.receiptsRoot, receiptDirectory, "tenant receipt directory");
  if (!(await isDirectory(ledgerDirectory))) throw new Error("Audit receipt exists without its ledger directory");
  await assertResolvedWithin(context.ledgersRoot, ledgerDirectory, "tenant ledger directory");

  const receiptEntries = await readdir(receiptDirectory, { withFileTypes: true });
  if (receiptEntries.length === 0) {
    if ((await readdir(ledgerDirectory)).length === 0) return null;
    throw new Error("Tenant receipt directory is empty while ledger artifacts remain");
  }
  const receipts: Array<{ file: string; value: LocalAuditReceipt }> = [];
  for (const entry of receiptEntries) {
    if (!entry.isFile() || !/^receipt-[0-9]{20,}-[0-9a-f]{64}\.json$/.test(entry.name)) {
      throw new Error("Tenant receipt directory contains an unexpected entry");
    }
    const receiptPath = path.join(receiptDirectory, entry.name);
    const value = parseLocalAuditReceipt(await readJsonFile(receiptPath, receiptDirectory, "audit receipt"));
    if (receiptGenerationFilename(value) !== entry.name || value.tenantId !== tenantId || value.streamId !== STREAM_ID) {
      throw new Error("Audit receipt filename or tenant boundary is invalid");
    }
    receipts.push({ file: receiptPath, value });
  }
  receipts.sort((left, right) => compareDecimal(left.value.anchorSequence, right.value.anchorSequence));
  for (const [index, entry] of receipts.entries()) {
    if (BigInt(entry.value.anchorSequence) !== BigInt(index + 1)) {
      throw new Error("Independent audit receipt sequence contains a gap or duplicate");
    }
  }

  const ledgerEntries = await readdir(ledgerDirectory, { withFileTypes: true });
  const ledgerNames = new Set<string>();
  for (const entry of ledgerEntries) {
    if (!entry.isFile() || !/^ledger-[0-9]{20,}-[0-9a-f]{64}\.json$/.test(entry.name)) {
      throw new Error("Tenant ledger directory contains an unexpected entry");
    }
    ledgerNames.add(entry.name);
  }
  const expectedLedgerNames = new Set(receipts.map(({ value }) => value.ledgerFile));
  if (
    ledgerNames.size !== expectedLedgerNames.size ||
    [...ledgerNames].some((name) => !expectedLedgerNames.has(name))
  ) {
    throw new Error("Immutable ledger generations do not match the independent receipt inventory");
  }

  const latestReceipt = receipts.at(-1)!;
  const ledgerPath = path.join(ledgerDirectory, latestReceipt.value.ledgerFile);
  const ledger = parseLocalAuditLedger(await readJsonFile(ledgerPath, ledgerDirectory, "audit ledger"));
  if (
    ledger.tenantId !== tenantId ||
    ledger.streamId !== STREAM_ID ||
    ledger.checkpoints.length !== receipts.length ||
    ledgerGenerationFilename(ledger.anchors.at(-1)!) !== latestReceipt.value.ledgerFile
  ) {
    throw new Error("Latest immutable ledger generation does not match its receipt inventory");
  }
  return {
    ledger,
    receipt: latestReceipt.value,
    ledgerPath,
    receiptPath: latestReceipt.file,
  };
}

async function ensureTenantDirectories(context: LocalAuditContext, tenantId: string): Promise<{
  ledgerDirectory: string;
  receiptDirectory: string;
}> {
  return {
    ledgerDirectory: await ensureDirectory(path.join(context.ledgersRoot, tenantId), context.ledgersRoot),
    receiptDirectory: await ensureDirectory(path.join(context.receiptsRoot, tenantId), context.receiptsRoot),
  };
}

async function readJsonFile(filePath: string, root: string, label: string): Promise<unknown> {
  const info = await lstat(filePath);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`);
  await assertResolvedWithin(root, filePath, label);
  return JSON.parse(await readFile(filePath, "utf8")) as unknown;
}

async function writeImmutableJson(filePath: string, value: unknown, root: string): Promise<void> {
  const directory = path.dirname(filePath);
  await assertResolvedWithin(root, directory, "artifact directory");
  assertLexicallyWithin(root, filePath, "artifact file");
  if (await pathExists(filePath)) throw new Error("Refusing to overwrite an immutable local audit artifact");
  const temporary = path.join(directory, `.${path.basename(filePath)}.${randomUUID()}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(value)}\n`, { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = undefined;
    await chmod(temporary, 0o600);
    await link(temporary, filePath);
    await chmod(filePath, 0o600);
  } finally {
    await handle?.close().catch(() => undefined);
    await removeExactFile(temporary, directory).catch((error: unknown) => {
      if (!isMissingFile(error)) throw error;
    });
  }
}

async function withExclusiveLock<T>(lockPath: string, root: string, operation: () => Promise<T>): Promise<T> {
  assertLexicallyWithin(root, lockPath, "lock file");
  let acquired = false;
  try {
    const handle = await open(lockPath, "wx", 0o600);
    acquired = true;
    try {
      await handle.writeFile(`${JSON.stringify({ pid: process.pid, acquiredAt: new Date().toISOString() })}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (acquired) await removeExactFile(lockPath, root).catch(() => undefined);
    if (isAlreadyExists(error)) throw new Error("Audit operation lock already exists; inspect a possible stale operation before retrying");
    throw error;
  }
  try {
    return await operation();
  } finally {
    await removeExactFile(lockPath, root);
  }
}

async function ensureDirectory(directory: string, root: string): Promise<string> {
  assertLexicallyWithin(root, directory, "local audit directory");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Local audit path must be a regular directory");
  const resolved = await realpath(directory);
  await assertResolvedWithin(root, resolved, "local audit directory");
  await chmod(resolved, 0o700);
  return resolved;
}

async function requirePlainDirectory(directory: string, label: string): Promise<void> {
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${label} must be a regular directory`);
}

async function assertResolvedWithin(root: string, value: string, label: string): Promise<void> {
  const [resolvedRoot, resolvedValue] = await Promise.all([realpath(root), realpath(value)]);
  const samePath = process.platform === "win32"
    ? resolvedRoot.toLowerCase() === resolvedValue.toLowerCase()
    : resolvedRoot === resolvedValue;
  if (!samePath && !isWithin(resolvedRoot, resolvedValue)) {
    throw new Error(`${label} must remain inside the protected .local boundary`);
  }
}

function assertLexicallyWithin(root: string, value: string, label: string): void {
  const resolvedRoot = path.resolve(root);
  const resolvedValue = path.resolve(value);
  if (!isWithin(resolvedRoot, resolvedValue)) throw new Error(`${label} must remain inside the protected .local boundary`);
}

function isWithin(root: string, value: string): boolean {
  const normalizedRoot = process.platform === "win32" ? root.toLowerCase() : root;
  const normalizedValue = process.platform === "win32" ? value.toLowerCase() : value;
  return normalizedValue.startsWith(`${normalizedRoot}${path.sep}`) && normalizedValue !== normalizedRoot;
}

async function removeExactFile(filePath: string, root: string): Promise<void> {
  assertLexicallyWithin(root, filePath, "cleanup file");
  let info;
  try {
    info = await lstat(filePath);
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  if (info.isDirectory()) throw new Error("Refusing file cleanup for a directory");
  await unlink(filePath);
}

async function removeExactDirectory(directory: string, root: string): Promise<void> {
  const resolvedDirectory = await realpath(directory);
  const resolvedRoot = await realpath(root);
  if (
    !isWithin(resolvedRoot, resolvedDirectory) ||
    !path.basename(resolvedDirectory).startsWith("audit-drill-")
  ) {
    throw new Error("Refusing to remove a path outside the exact audit drill work boundary");
  }
  await rm(resolvedDirectory, { recursive: true, force: true });
}

async function isDirectory(value: string): Promise<boolean> {
  try {
    const info = await lstat(value);
    return info.isDirectory() && !info.isSymbolicLink();
  } catch (error) {
    if (isMissingFile(error)) return false;
    throw error;
  }
}

async function pathExists(value: string): Promise<boolean> {
  try {
    await lstat(value);
    return true;
  } catch (error) {
    if (isMissingFile(error)) return false;
    throw error;
  }
}

function compareDecimal(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function emit(value: Readonly<Record<string, unknown>>): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function safeErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) return "unknown safe failure";
  return error.message
    .replace(/postgres(?:ql)?:\/\/[^@\s]+@/gi, "postgresql://[redacted]@")
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[redacted key]")
    .replace(/PGPASSWORD=[^\s]+/gi, "PGPASSWORD=[redacted]");
}

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function isAlreadyExists(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST";
}

void main().catch((error: unknown) => {
  process.stderr.write(`Tenant audit anchor operation failed: ${safeErrorMessage(error)}\n`);
  process.exitCode = 1;
});
