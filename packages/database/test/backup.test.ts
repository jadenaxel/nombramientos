import { randomBytes, randomUUID } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertScratchDatabaseName,
  backupKeyInventorySchema,
  backupManifestSchema,
  canonicalJson,
  compareTenantInvariants,
  decryptBackupPayload,
  encryptBackupPayload,
  hashFile,
  scratchDatabaseName,
  sha256,
  verifyBackupManifest,
  type BackupCore,
  type BackupManifest,
  type TenantInvariant,
} from "../src/backup.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("authenticated tenant backups", () => {
  it("encrypts and restores a dump with a 256-bit key and authenticated manifest core", async () => {
    const directory = await temporaryDirectory();
    const plaintext = path.join(directory, "source.dump");
    const encrypted = path.join(directory, "source.dump.aesgcm");
    const restored = path.join(directory, "restored.dump");
    const source = Buffer.concat([Buffer.from("PGDMP test fixture\n", "utf8"), randomBytes(8_192)]);
    await writeFile(plaintext, source);
    const key = randomBytes(32);
    const core = backupCore();
    const encryption = await encryptBackupPayload(plaintext, encrypted, key, core);
    const payload = await hashFile(encrypted);
    const manifest = backupManifestSchema.parse({
      format: "nombramientos-tenant-backup",
      version: 1,
      core,
      encryption: { algorithm: "AES-256-GCM", ...encryption },
      payload: { file: "database.dump.aesgcm", ...payload },
    });

    expect(Buffer.from(manifest.encryption.nonce, "base64url")).toHaveLength(12);
    expect(Buffer.from(manifest.encryption.tag, "base64url")).toHaveLength(16);
    expect(await readFile(encrypted)).not.toEqual(source);
    await decryptBackupPayload(encrypted, restored, key, manifest);
    expect(await readFile(restored)).toEqual(source);
  });

  it("rejects ciphertext tampering without returning unauthenticated plaintext", async () => {
    const directory = await temporaryDirectory();
    const plaintext = path.join(directory, "source.dump");
    const encrypted = path.join(directory, "source.dump.aesgcm");
    const restored = path.join(directory, "restored.dump");
    await writeFile(plaintext, randomBytes(4_096));
    const key = randomBytes(32);
    const core = backupCore();
    const encryption = await encryptBackupPayload(plaintext, encrypted, key, core);
    const encryptedBytes = await readFile(encrypted);
    encryptedBytes[0] = (encryptedBytes[0] ?? 0) ^ 0xff;
    await writeFile(encrypted, encryptedBytes);
    const payload = await hashFile(encrypted);
    const manifest = backupManifestSchema.parse({
      format: "nombramientos-tenant-backup",
      version: 1,
      core,
      encryption: { algorithm: "AES-256-GCM", ...encryption },
      payload: { file: "database.dump.aesgcm", ...payload },
    });

    await expect(decryptBackupPayload(encrypted, restored, key, manifest)).rejects.toThrow();
    await expect(access(restored)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("detects manifest-core tampering before decryption", () => {
    const core = backupCore();
    const manifest = manifestFor(core);
    const tampered: BackupManifest = {
      ...manifest,
      core: { ...manifest.core, pgDumpVersion: "pg_dump (PostgreSQL) 18.99" },
    };
    expect(() => verifyBackupManifest(tampered)).toThrow(/authenticated-header checksum/i);
  });

  it("rejects a manifest that crosses its tenant database boundary", () => {
    const core = backupCore();
    expect(() => backupManifestSchema.parse({
      ...manifestFor(core),
      core: {
        ...core,
        sourceDatabase: "nom_t_0a2a0000000040008000000000000001",
      },
    })).toThrow(/source database/i);
  });

  it("requires exactly one 256-bit active key while retaining retired restore keys", () => {
    const retiredId = randomUUID();
    const activeId = randomUUID();
    expect(backupKeyInventorySchema.parse({
      version: 1,
      activeKeyId: activeId,
      keys: [
        { id: retiredId, createdAt: new Date().toISOString(), status: "retired", keyB64: randomBytes(32).toString("base64url") },
        { id: activeId, createdAt: new Date().toISOString(), status: "active", keyB64: randomBytes(32).toString("base64url") },
      ],
    }).keys).toHaveLength(2);
    expect(() => backupKeyInventorySchema.parse({
      version: 1,
      activeKeyId: activeId,
      keys: [
        { id: activeId, createdAt: new Date().toISOString(), status: "active", keyB64: randomBytes(16).toString("base64url") },
      ],
    })).toThrow(/32 bytes/i);
  });
});

describe("isolated restore guards", () => {
  it("derives only a guarded scratch name and refuses tenant databases", () => {
    const tenantId = "d0000000-0000-4000-8000-000000000001";
    const backupId = "b0000000-0000-4000-8000-000000000001";
    const scratch = scratchDatabaseName(tenantId, backupId);
    expect(scratch).toBe("nom_restore_d0000000_b0000000");
    expect(() => assertScratchDatabaseName(scratch, [])).not.toThrow();
    expect(() => assertScratchDatabaseName("nom_t_d0000000000040008000000000000001", [])).toThrow(/guarded/i);
    expect(() => assertScratchDatabaseName(scratch, [scratch])).toThrow(/registered tenant/i);
    expect(() => assertScratchDatabaseName("postgres", [])).toThrow(/guarded/i);
  });

  it("reports the exact invariant families that differ", () => {
    const expected = invariant();
    const actual: TenantInvariant = {
      ...expected,
      tables: expected.tables.map((table) => ({ ...table, rows: table.rows + 1 })),
      outboxHeadSequence: "8",
    };
    expect(compareTenantInvariants(expected, actual)).toEqual(["tables", "outboxHeadSequence"]);
    expect(compareTenantInvariants(expected, structuredClone(expected))).toEqual([]);
  });

  it("canonicalizes object keys for stable authenticated checksums", () => {
    expect(canonicalJson({ z: 1, a: { y: 2, b: 3 } })).toBe('{"a":{"b":3,"y":2},"z":1}');
  });
});

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "nom-backup-test-"));
  temporaryDirectories.push(directory);
  return directory;
}

function invariant(): TenantInvariant {
  return {
    tenantId: "d0000000-0000-4000-8000-000000000001",
    tenantKind: "demo",
    catalogVersion: "2026.09",
    schemaMigrations: [{ name: "001_tenant.sql", checksum: "sha256:test" }],
    tables: [{ name: "members", rows: 16, sha256: `sha256:${"1".repeat(64)}` }],
    sequences: [{ name: "audit_events_sequence_seq", lastValue: "7", isCalled: true }],
    auditHead: { sequence: "7", eventHash: `sha256:${"2".repeat(64)}` },
    outboxHeadSequence: "7",
  };
}

function backupCore(): BackupCore {
  const value = invariant();
  return {
    backupId: randomUUID(),
    tenantId: value.tenantId,
    tenantKind: value.tenantKind,
    sourceDatabase: "nom_t_d0000000000040008000000000000001",
    credentialVersion: 1,
    runtimeSecretReference: "tenant-db/d0000000-0000-4000-8000-000000000001/runtime/v1",
    recoveryPointAt: new Date().toISOString(),
    backupCompletedAt: new Date().toISOString(),
    postgresServerVersion: "18.6",
    pgDumpVersion: "pg_dump (PostgreSQL) 18.6",
    encryptionKeyId: randomUUID(),
    invariant: value,
    invariantSha256: sha256(canonicalJson(value)),
    dump: { format: "pg_dump-custom", bytes: 8_192, sha256: `sha256:${"3".repeat(64)}` },
  };
}

function manifestFor(core: BackupCore): BackupManifest {
  return backupManifestSchema.parse({
    format: "nombramientos-tenant-backup",
    version: 1,
    core,
    encryption: {
      algorithm: "AES-256-GCM",
      nonce: randomBytes(12).toString("base64url"),
      tag: randomBytes(16).toString("base64url"),
      aadSha256: sha256(canonicalJson(core)),
    },
    payload: {
      file: "database.dump.aesgcm",
      bytes: 1,
      sha256: `sha256:${"4".repeat(64)}`,
    },
  });
}
