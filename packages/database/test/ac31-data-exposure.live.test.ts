import { spawn } from "node:child_process";
import { createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool, type PoolClient } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  backupKeyInventorySchema,
  backupManifestSchema,
  canonicalJson,
  captureTenantInvariant,
  decryptBackupPayload,
  encryptBackupPayload,
  hashFile,
  sha256,
  type BackupCore,
} from "../src/backup.js";
import { generateSecretKey, sealAesGcmJson } from "../src/crypto-envelope.js";
import { runMigrations } from "../src/migrations.js";
import type { EncryptedEnvelope } from "../src/types.js";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const localRoot = path.join(packageRoot, ".local");
const installFile = path.join(localRoot, "install.json");
const installation = discoverInstallation();
const reachable = installation ? await canReachWorkspace(installation.adminUrl) : false;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";

if (requireLive && !reachable) {
  throw new Error("AC-31 live inspection requires PostgreSQL 18 on isolated loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface Installation {
  readonly adminUrl: string;
  readonly postgresBin: string;
  readonly secretMasterKey: Buffer;
  readonly authEncryptionKey: Buffer;
  readonly backupKey: Buffer;
  readonly backupKeyId: string;
}

interface ExposureFixture {
  readonly admin: Pool;
  readonly tenant: Pool;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly tenantContentKey: Buffer;
  readonly workDirectory: string;
  readonly canaries: Readonly<Record<string, string>>;
  readonly envelopes: readonly EncryptedEnvelope[];
  readonly visible: Readonly<Record<string, string | number | boolean>>;
}

let fixture: ExposureFixture | undefined;

live("AC-31 backend dump, backup object, ordinary-secret, and tool-log boundary", () => {
  beforeAll(async () => {
    if (!installation) throw new Error("Protected local installation metadata is unavailable");
    fixture = await createExposureFixture(installation);
  }, 60_000);

  afterAll(async () => {
    try {
      if (fixture) await cleanupFixture(fixture);
    } finally {
      installation?.secretMasterKey.fill(0);
      installation?.authEncryptionKey.fill(0);
      installation?.backupKey.fill(0);
    }
  }, 60_000);

  it("keeps declared E2EE plaintext opaque after a real custom pg_dump and outer-backup decryption while enumerating visible metadata", async () => {
    const current = requireFixture();
    if (!installation) throw new Error("Protected local installation metadata is unavailable");

    const plaintextDump = path.join(current.workDirectory, "database.dump");
    const restoredDump = path.join(current.workDirectory, "restored.dump");
    const inspectableSql = path.join(current.workDirectory, "restored-data.sql");
    const artifactDirectory = path.join(current.workDirectory, "backup-object");
    const encryptedDump = path.join(artifactDirectory, "database.dump.aesgcm");
    await mkdir(artifactDirectory, { recursive: false });

    const dumpRun = await runProcess(
      pgToolPath(installation.postgresBin, "pg_dump"),
      [
        "--host", new URL(installation.adminUrl).hostname,
        "--port", String(WORKSPACE_PORT),
        "--username", decodeURIComponent(new URL(installation.adminUrl).username),
        "--dbname", current.databaseName,
        "--format=custom",
        "--compress=zstd:level=6",
        "--no-owner",
        "--no-privileges",
        "--file", plaintextDump,
      ],
      decodeURIComponent(new URL(installation.adminUrl).password),
    );
    expect(dumpRun.code).toBe(0);

    const invariant = await captureInvariant(current.tenant);
    const dump = await hashFile(plaintextDump);
    const now = new Date().toISOString();
    const core: BackupCore = {
      backupId: randomUUID(),
      tenantId: current.tenantId,
      tenantKind: "real",
      sourceDatabase: current.databaseName,
      credentialVersion: 1,
      runtimeSecretReference: `tenant-db/${current.tenantId}/runtime/v1`,
      recoveryPointAt: now,
      backupCompletedAt: now,
      postgresServerVersion: "18.local-test",
      pgDumpVersion: "pg_dump (PostgreSQL) 18.local-test",
      encryptionKeyId: installation.backupKeyId,
      invariant,
      invariantSha256: sha256(canonicalJson(invariant)),
      dump: { format: "pg_dump-custom", ...dump },
    };
    const encryption = await encryptBackupPayload(plaintextDump, encryptedDump, installation.backupKey, core);
    const encrypted = await hashFile(encryptedDump);
    const manifest = backupManifestSchema.parse({
      format: "nombramientos-tenant-backup",
      version: 1,
      core,
      encryption: { algorithm: "AES-256-GCM", ...encryption },
      payload: { file: "database.dump.aesgcm", ...encrypted },
    });
    const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
    await writeFile(path.join(artifactDirectory, "manifest.json"), manifestText, "utf8");
    await writeFile(path.join(artifactDirectory, "manifest.sha256"), `${sha256(manifestText)}\n`, "utf8");
    await unlink(plaintextDump);

    expect((await readdir(artifactDirectory)).sort()).toEqual([
      "database.dump.aesgcm",
      "manifest.json",
      "manifest.sha256",
    ]);
    await assertSensitiveValuesAbsent(await readFile(encryptedDump), current.canaries, installation);
    await assertSensitiveValuesAbsent(Buffer.from(manifestText, "utf8"), current.canaries, installation);

    await decryptBackupPayload(encryptedDump, restoredDump, installation.backupKey, manifest);
    const restoreRun = await runProcess(
      pgToolPath(installation.postgresBin, "pg_restore"),
      [
        "--data-only",
        "--no-owner",
        "--no-privileges",
        "--file", inspectableSql,
        restoredDump,
      ],
      undefined,
    );
    expect(restoreRun.code).toBe(0);
    const dumpText = await readFile(inspectableSql, "utf8");

    for (const secret of Object.values(current.canaries)) expect(dumpText).not.toContain(secret);
    expect(dumpText).not.toContain(current.tenantContentKey.toString("base64url"));
    for (const secret of ordinarySecretTextRepresentations(installation)) expect(dumpText).not.toContain(secret);

    for (const [metadata, value] of Object.entries(current.visible)) {
      expect(
        dumpText.includes(String(value)),
        `expected dump-visible metadata: ${metadata}`,
      ).toBe(true);
    }
    for (const envelope of current.envelopes) {
      expect(dumpText).toContain(envelope.keyId);
      expect(dumpText).toContain(envelope.ciphertext);
    }

    const toolLog = `${dumpRun.stdout}\n${dumpRun.stderr}\n${restoreRun.stdout}\n${restoreRun.stderr}`;
    for (const secret of Object.values(current.canaries)) expect(toolLog).not.toContain(secret);
    for (const secret of ordinarySecretTextRepresentations(installation)) expect(toolLog).not.toContain(secret);

    const ordinaryKeys = [installation.secretMasterKey, installation.authEncryptionKey, installation.backupKey];
    for (const envelope of current.envelopes) {
      for (const ordinaryKey of ordinaryKeys) expect(() => openEnvelope(envelope, ordinaryKey)).toThrow();
    }
    const tenantDecryptedValues = current.envelopes.map((encryptedEnvelope) => openEnvelope(
      encryptedEnvelope,
      current.tenantContentKey,
    ));
    expect(tenantDecryptedValues).toEqual(expect.arrayContaining([
      ...Object.entries(current.canaries)
        .filter(([name]) => name !== "sessionTitle" && name !== "agendaTitle")
        .map(([, value]) => expect.objectContaining({ value })),
      expect.objectContaining({ title: current.canaries["sessionTitle"] }),
      expect.objectContaining({ title: current.canaries["agendaTitle"] }),
    ]));

    expect({
      backup: {
        tenantId: manifest.core.tenantId,
        tenantKind: manifest.core.tenantKind,
        sourceDatabase: manifest.core.sourceDatabase,
        credentialVersion: manifest.core.credentialVersion,
        runtimeSecretReference: manifest.core.runtimeSecretReference,
        recoveryPointAt: manifest.core.recoveryPointAt,
        backupCompletedAt: manifest.core.backupCompletedAt,
        postgresServerVersion: manifest.core.postgresServerVersion,
        pgDumpVersion: manifest.core.pgDumpVersion,
        encryptionKeyId: manifest.core.encryptionKeyId,
      },
      databaseInventory: {
        catalogVersion: manifest.core.invariant.catalogVersion,
        migrationNamesChecksums: manifest.core.invariant.schemaMigrations.length,
        tableNamesCountsHashes: manifest.core.invariant.tables.length,
        sequenceNamesValues: manifest.core.invariant.sequences.length,
        auditHead: manifest.core.invariant.auditHead,
        outboxHeadSequence: manifest.core.invariant.outboxHeadSequence,
      },
      payload: {
        plaintextBytesAndHash: manifest.core.dump,
        ciphertextBytesAndHash: { bytes: manifest.payload.bytes, sha256: manifest.payload.sha256 },
        algorithmNonceTagAndAadHash: manifest.encryption,
      },
    }).toEqual(expect.objectContaining({
      backup: expect.objectContaining({ tenantId: current.tenantId, tenantKind: "real", sourceDatabase: current.databaseName }),
      databaseInventory: expect.objectContaining({ catalogVersion: "ac31-evidence-v1" }),
      payload: expect.objectContaining({
        plaintextBytesAndHash: expect.objectContaining({ format: "pg_dump-custom", bytes: expect.any(Number), sha256: expect.stringMatching(/^sha256:/u) }),
        ciphertextBytesAndHash: expect.objectContaining({ bytes: expect.any(Number), sha256: expect.stringMatching(/^sha256:/u) }),
        algorithmNonceTagAndAadHash: expect.objectContaining({ algorithm: "AES-256-GCM" }),
      }),
    }));
  }, 60_000);
});

async function createExposureFixture(currentInstallation: Installation): Promise<ExposureFixture> {
  const tenantId = randomUUID();
  const databaseName = `nom_t_${tenantId.replaceAll("-", "")}`;
  const admin = new Pool({ connectionString: currentInstallation.adminUrl, max: 1, connectionTimeoutMillis: 5_000 });
  let tenant: Pool | undefined;
  let workDirectory: string | undefined;
  let tenantContentKey: Buffer | undefined;
  try {
    assertAc31DatabaseName(databaseName);
    const exists = await admin.query("SELECT 1 FROM pg_database WHERE datname=$1", [databaseName]);
    if (exists.rowCount !== 0) {
      throw new Error("Random AC-31 database name already exists; refusing to reuse it");
    }
    const create = await admin.query<{ sql: string }>(
      "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L',$1::text,'UTF8') AS sql",
      [databaseName],
    );
    const createSql = create.rows[0]?.sql;
    if (!createSql) throw new Error("PostgreSQL did not format the AC-31 database statement");
    await admin.query(createSql);

    const tenantUrl = new URL(currentInstallation.adminUrl);
    tenantUrl.pathname = `/${databaseName}`;
    tenant = new Pool({ connectionString: tenantUrl.toString(), max: 2, connectionTimeoutMillis: 5_000 });
    workDirectory = await mkdtemp(path.join(os.tmpdir(), "nom-ac31-evidence-"));
    tenantContentKey = generateSecretKey();
    await runMigrations(tenant, { scope: "tenant", directory: path.join(packageRoot, "migrations", "tenant") });
    const memberId = randomUUID();
    const actorIdentityId = randomUUID();
    const departmentId = randomUUID();
    const officeId = randomUUID();
    const cycleId = randomUUID();
    const proposalRoundId = randomUUID();
    const voteRoundId = randomUUID();
    const proposalSubmissionId = randomUUID();
    const voteSubmissionId = randomUUID();
    const proposalReceiptId = randomUUID();
    const voteReceiptId = randomUUID();
    const reportId = randomUUID();
    const sessionId = randomUUID();
    const agendaItemId = randomUUID();
    const stableCode = `AC31-${randomBytes(6).toString("hex").toUpperCase()}`;
    const canaries = {
      display: `AC31_DISPLAY_${randomUUID()}`,
      contact: `AC31_CONTACT_${randomUUID()}`,
      eligibility: `AC31_ELIGIBILITY_${randomUUID()}`,
      privateNote: `AC31_PRIVATE_NOTE_${randomUUID()}`,
      proposal: `AC31_PROPOSAL_SELECTION_${randomUUID()}`,
      ballot: `AC31_BALLOT_SELECTION_${randomUUID()}`,
      photo: `AC31_PHOTO_BYTES_${randomUUID()}`,
      report: `AC31_REPORT_BODY_${randomUUID()}`,
      minutes: `AC31_MINUTES_${randomUUID()}`,
      sessionTitle: `AC31_SESSION_TITLE_${randomUUID()}`,
      agendaTitle: `AC31_AGENDA_TITLE_${randomUUID()}`,
    } as const;
    const tenantKeyId = `tenant-key-${randomUUID()}`;
    const displayEnvelope = sealAesGcmJson(
      { value: canaries.display },
      tenantContentKey,
      tenantKeyId,
      { tenantId, memberId, purpose: "member-display", schemaVersion: 1 },
    );
    const contactEnvelope = sealAesGcmJson(
      { value: canaries.contact },
      tenantContentKey,
      tenantKeyId,
      { tenantId, memberId, purpose: "member-contact", schemaVersion: 1 },
    );
    const eligibilityEnvelope = envelope(canaries.eligibility, "member-eligibility", tenantId, tenantContentKey, tenantKeyId);
    const privateNoteEnvelope = envelope(canaries.privateNote, "private-note", tenantId, tenantContentKey, tenantKeyId);
    const proposalEnvelope = envelope(canaries.proposal, "proposal", tenantId, tenantContentKey, tenantKeyId);
    const ballotEnvelope = envelope(canaries.ballot, "ballot", tenantId, tenantContentKey, tenantKeyId);
    const photoEnvelope = sealAesGcmJson(
      { value: canaries.photo, padding: "x".repeat(256) },
      tenantContentKey,
      tenantKeyId,
      { tenantId, purpose: "member-photo", version: 1 },
    );
    const reportEnvelope = envelope(canaries.report, "report-artifact", tenantId, tenantContentKey, tenantKeyId);
    const minutesEnvelope = envelope(canaries.minutes, "session-minutes", tenantId, tenantContentKey, tenantKeyId);
    const sessionTitleEnvelope = sealAesGcmJson(
      { schema: "nombramientos-session-title/v1", title: canaries.sessionTitle },
      tenantContentKey,
      tenantKeyId,
      { tenantId, cycleId, sessionId, purpose: "session-title", schemaVersion: 1, titleVersion: 1 },
    );
    const agendaTitleEnvelope = sealAesGcmJson(
      { schema: "nombramientos-session-agenda-title/v1", title: canaries.agendaTitle },
      tenantContentKey,
      tenantKeyId,
      { tenantId, sessionId, agendaItemId, purpose: "session-agenda-title", schemaVersion: 1, titleVersion: 1 },
    );
    const envelopes = [
      displayEnvelope,
      contactEnvelope,
      eligibilityEnvelope,
      privateNoteEnvelope,
      proposalEnvelope,
      ballotEnvelope,
      photoEnvelope,
      reportEnvelope,
      minutesEnvelope,
      sessionTitleEnvelope,
      agendaTitleEnvelope,
    ] as const;

    await tenant.query(
      `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state,catalog_version)
       VALUES ($1,'AC-31 operational fixture','real','America/La_Paz','es','ready','ac31-evidence-v1')`,
      [tenantId],
    );
    await tenant.query(
      `INSERT INTO members(
         id,stable_code,display_envelope,display_content_hash,contact_envelope,contact_content_hash,
         eligibility_envelope,eligibility_status,available
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,'review',true)`,
      [
        memberId,
        stableCode,
        displayEnvelope,
        envelopeHash(displayEnvelope),
        contactEnvelope,
        envelopeHash(contactEnvelope),
        eligibilityEnvelope,
      ],
    );
    await tenant.query(
      "INSERT INTO departments(id,canonical_code,names) VALUES ($1,'AC31_DEPARTMENT',$2)",
      [departmentId, { es: "Departamento operativo AC-31", en: "AC-31 operational department", fr: "Département opérationnel AC-31" }],
    );
    await tenant.query(
      `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality)
       VALUES ($1,$2,'AC31_OFFICE',$3,'church_election_after_nominating_report',1)`,
      [officeId, departmentId, { es: "Cargo operativo AC-31", en: "AC-31 operational office", fr: "Fonction opérationnelle AC-31" }],
    );
    await tenant.query(
      `INSERT INTO election_cycles(id,name,status,locale,timezone,term_start,term_end,normative_version,created_by_identity_id)
       VALUES ($1,'Ciclo operativo AC-31','active','es','America/La_Paz','2042-01-01','2042-12-31','ac31-v1',$2)`,
      [cycleId, actorIdentityId],
    );
    await tenant.query(
      `INSERT INTO rounds(
         id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,candidate_set_hash,rules_hash,
         max_proposal_selections,max_ballot_selections,workflow_stage,opened_at
       ) VALUES
         ($1,$3,$4,'CERRADO','proposal',1,1,$5,$6,1,1,'proposal',clock_timestamp()),
         ($2,$3,$4,'VOTACION_ABIERTA','vote',1,1,$7,$8,1,1,'ballot',clock_timestamp())`,
      [
        proposalRoundId,
        voteRoundId,
        cycleId,
        officeId,
        sha256(`proposal-candidates:${memberId}`),
        sha256("proposal-rules"),
        sha256(`ballot-candidates:${memberId}`),
        sha256("ballot-rules"),
      ],
    );
    for (const roundId of [proposalRoundId, voteRoundId]) {
      await tenant.query(
        "INSERT INTO round_elector_snapshots(round_id,identity_id,can_submit,recused) VALUES ($1,$2,true,false)",
        [roundId, actorIdentityId],
      );
      await tenant.query(
        `INSERT INTO candidate_snapshots(
           round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
           member_version_snapshot,eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
           eligibility_evaluated_on,eligibility_effective
         ) SELECT $1,$2,member.id,$4,true,1,0,member.version,
                  member.eligibility_department_id,member.eligibility_valid_until,
                  (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
             FROM members member CROSS JOIN tenant_settings settings
            WHERE member.id=$3 AND settings.singleton=true`,
        [roundId, randomUUID(), memberId, displayEnvelope],
      );
    }
    const proposalHash = envelopeHash(proposalEnvelope);
    const ballotHash = envelopeHash(ballotEnvelope);
    await tenant.query(
      `INSERT INTO encrypted_submissions(id,round_id,elector_identity_id,kind,envelope,content_hash,round_version)
       VALUES ($1,$2,$3,'proposal',$4,$5,1),($6,$7,$3,'vote',$8,$9,1)`,
      [proposalSubmissionId, proposalRoundId, actorIdentityId, proposalEnvelope, proposalHash, voteSubmissionId, voteRoundId, ballotEnvelope, ballotHash],
    );
    await tenant.query(
      `INSERT INTO participation_receipts(id,submission_id,round_id,elector_identity_id,kind,content_hash,received_at)
       SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,'proposal',$5,received_at
         FROM encrypted_submissions WHERE id=$2::uuid`,
      [proposalReceiptId, proposalSubmissionId, proposalRoundId, actorIdentityId, proposalHash],
    );
    await tenant.query(
      `INSERT INTO participation_receipts(id,submission_id,round_id,elector_identity_id,kind,content_hash,received_at)
       SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,'vote',$5,received_at
         FROM encrypted_submissions WHERE id=$2::uuid`,
      [voteReceiptId, voteSubmissionId, voteRoundId, actorIdentityId, ballotHash],
    );
    const photoPlaintextBytes = Buffer.from(JSON.stringify({ value: canaries.photo, padding: "x".repeat(256) }), "utf8").byteLength;
    const photoCipherBytes = Buffer.from(photoEnvelope.ciphertext, "base64url").byteLength;
    expect(photoCipherBytes).toBe(photoPlaintextBytes + 16);
    await tenant.query(
      `INSERT INTO member_photo_assets(
         id,member_id,version,media_type,width,height,plaintext_bytes,cipher_bytes,envelope,content_hash,created_by_identity_id
       ) VALUES ($1,$2,1,'image/jpeg',128,128,$3,$4,$5,$6,$7)`,
      [randomUUID(), memberId, photoPlaintextBytes, photoCipherBytes, photoEnvelope, envelopeHash(photoEnvelope), actorIdentityId],
    );
    await tenant.query(
      `INSERT INTO cycle_sessions(
         id,cycle_id,sequence,title_envelope,title_envelope_version,starts_at,ends_at,status,created_by_identity_id
       ) VALUES ($1,$2,1,$3,1,'2042-06-01T18:00:00Z','2042-06-01T20:00:00Z','closed',$4)`,
      [sessionId, cycleId, sessionTitleEnvelope, actorIdentityId],
    );
    await tenant.query(
      `INSERT INTO session_agenda_items(
         id,session_id,position,title_envelope,title_envelope_version,notes_envelope,status,created_by_identity_id
       ) VALUES ($1,$2,1,$3,1,$4,'decided',$5)`,
      [agendaItemId, sessionId, agendaTitleEnvelope, privateNoteEnvelope, actorIdentityId],
    );
    await tenant.query(
      `INSERT INTO session_decisions(id,session_id,agenda_item_id,decision_code,outcome,evidence_envelope,recorded_by_identity_id)
       VALUES ($1,$2,$3,'INFORMATION_NOTED','RECORDED',$4,$5)`,
      [randomUUID(), sessionId, agendaItemId, minutesEnvelope, actorIdentityId],
    );
    const reportArtifactHash = envelopeHash(reportEnvelope);
    const reportCiphertextHash = sha256(Buffer.from(reportEnvelope.ciphertext, "base64url"));
    const reportPlaintextBytes = Buffer.byteLength(JSON.stringify({ value: canaries.report }), "utf8");
    await tenant.query(
      `INSERT INTO report_versions(
         id,report_type,audience,locale,format,filters,artifact_envelope,artifact_bytes,artifact_sha256,
         filename,media_type,state,requested_by_identity_id,ready_at,artifact_manifest,plaintext_bytes,
         ciphertext_sha256,version
       ) VALUES ($1,'cycle_summary','committee','es','pdf',$2,$3,NULL,$4,
                 'ac31-report.pdf','application/pdf','ready',$5,clock_timestamp(),$6,$7,$8,1)`,
      [
        reportId,
        { cycleId },
        reportEnvelope,
        reportArtifactHash,
        actorIdentityId,
        { rowCount: 1, generatedAt: "2042-06-01T20:00:00.000Z", snapshotSha256: sha256("ac31-snapshot") },
        reportPlaintextBytes,
        reportCiphertextHash,
      ],
    );

    return {
      admin,
      tenant,
      databaseName,
      tenantId,
      tenantContentKey,
      workDirectory,
      canaries,
      envelopes,
      visible: {
        tenantId,
        memberId,
        stableCode,
        eligibilityStatus: "review",
        actorIdentityId,
        cycleId,
        cycleStatus: "active",
        proposalRoundId,
        voteRoundId,
        proposalKind: "proposal",
        voteKind: "vote",
        proposalReceiptId,
        voteReceiptId,
        reportId,
        reportType: "cycle_summary",
        reportAudience: "committee",
        reportLocale: "es",
        reportFormat: "pdf",
        reportState: "ready",
        reportFilename: "ac31-report.pdf",
        photoMediaType: "image/jpeg",
        photoWidth: 128,
        photoHeight: 128,
        photoPlaintextBytes,
        reportPlaintextBytes,
      },
    };
  } catch (error) {
    tenantContentKey?.fill(0);
    return cleanupAfterFailure(
      error,
      () => cleanupExposureResources(admin, tenant, databaseName, workDirectory),
      "AC-31 fixture setup",
    );
  }
}

function envelope(
  secret: string,
  purpose: string,
  tenantId: string,
  key: Uint8Array,
  keyId: string,
): EncryptedEnvelope {
  return sealAesGcmJson({ value: secret }, key, keyId, { tenantId, purpose, version: 1 });
}

function envelopeHash(value: EncryptedEnvelope): string {
  return sha256(JSON.stringify({
    algorithm: value.algorithm,
    keyId: value.keyId,
    nonce: value.nonce,
    ciphertext: value.ciphertext,
    aad: value.aad,
  }));
}

function openEnvelope(value: EncryptedEnvelope, key: Uint8Array): unknown {
  const encrypted = Buffer.from(value.ciphertext, "base64url");
  const ciphertext = encrypted.subarray(0, -16);
  const tag = encrypted.subarray(-16);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(value.nonce, "base64url"));
  decipher.setAAD(Buffer.from(value.aad, "base64url"));
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8")) as unknown;
}

async function assertSensitiveValuesAbsent(
  content: Buffer,
  canaries: Readonly<Record<string, string>>,
  currentInstallation: Installation,
): Promise<void> {
  const text = content.toString("latin1");
  for (const secret of Object.values(canaries)) expect(text).not.toContain(secret);
  for (const secret of ordinarySecretTextRepresentations(currentInstallation)) expect(text).not.toContain(secret);
  for (const key of ordinaryKeyBuffers(currentInstallation)) expect(content.includes(key)).toBe(false);
}

function ordinarySecretTextRepresentations(currentInstallation: Installation): readonly string[] {
  const password = decodeURIComponent(new URL(currentInstallation.adminUrl).password);
  return [
    password,
    ...ordinaryKeyBuffers(currentInstallation).flatMap((key) => [
      key.toString("base64"),
      key.toString("base64url"),
      key.toString("hex"),
    ]),
  ].filter((value) => value.length > 0);
}

function ordinaryKeyBuffers(currentInstallation: Installation): readonly Buffer[] {
  return [
    currentInstallation.secretMasterKey,
    currentInstallation.authEncryptionKey,
    currentInstallation.backupKey,
  ];
}

async function captureInvariant(pool: Pool) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const invariant = await captureTenantInvariant(client);
    await client.query("COMMIT");
    return invariant;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function cleanupFixture(current: ExposureFixture): Promise<void> {
  current.tenantContentKey.fill(0);
  await cleanupExposureResources(
    current.admin,
    current.tenant,
    current.databaseName,
    current.workDirectory,
  );
}

async function cleanupExposureResources(
  admin: Pool,
  tenant: Pool | undefined,
  databaseName: string,
  workDirectory: string | undefined,
): Promise<void> {
  const failures: Error[] = [];
  try {
    await cleanupTemporaryDatabases({
      maintenancePool: admin,
      targets: [{
        databaseName,
        databasePools: tenant ? [tenant] : [],
        assertSafeDatabaseName: assertAc31DatabaseName,
      }],
      label: "Temporary AC-31 evidence database",
    });
  } catch (error) {
    failures.push(new Error("AC-31 cleanup failed for its temporary database", { cause: error }));
  }
  if (workDirectory) {
    try {
      await rm(workDirectory, { recursive: true, force: true });
    } catch (error) {
      failures.push(new Error("AC-31 cleanup failed for its temporary evidence directory", { cause: error }));
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(failures, `AC-31 cleanup failed closed with ${failures.length} errors`);
  }
}

function assertAc31DatabaseName(databaseName: string): void {
  if (!/^nom_t_[0-9a-f]{32}$/u.test(databaseName)) {
    throw new Error("Refusing to clean up a non-AC-31 tenant database name");
  }
}

function discoverInstallation(): Installation | undefined {
  if (!existsSync(installFile)) return undefined;
  const parsed = JSON.parse(readFileSync(installFile, "utf8")) as {
    DATABASE_ADMIN_URL?: string;
    POSTGRES_BIN?: string;
    DATABASE_SECRET_MASTER_KEY_B64?: string;
    AUTH_ENCRYPTION_KEY_B64?: string;
    DATABASE_BACKUP_KEY_FILE?: string;
  };
  if (!parsed.DATABASE_ADMIN_URL || !parsed.POSTGRES_BIN || !parsed.DATABASE_SECRET_MASTER_KEY_B64
    || !parsed.AUTH_ENCRYPTION_KEY_B64 || !parsed.DATABASE_BACKUP_KEY_FILE) return undefined;
  const admin = assertWorkspacePostgresUrl(parsed.DATABASE_ADMIN_URL, "nom_admin", "postgres");
  const backupKeyFile = path.resolve(parsed.DATABASE_BACKUP_KEY_FILE);
  if (!backupKeyFile.startsWith(`${path.resolve(localRoot)}${path.sep}`)) return undefined;
  const inventory = backupKeyInventorySchema.parse(JSON.parse(readFileSync(backupKeyFile, "utf8")) as unknown);
  const activeKey = inventory.keys.find(({ id }) => id === inventory.activeKeyId);
  if (!activeKey) return undefined;
  const secretMasterKey = Buffer.from(parsed.DATABASE_SECRET_MASTER_KEY_B64, "base64url");
  const authEncryptionKey = Buffer.from(parsed.AUTH_ENCRYPTION_KEY_B64, "base64url");
  const backupKey = Buffer.from(activeKey.keyB64, "base64url");
  if ([secretMasterKey, authEncryptionKey, backupKey].some((key) => key.byteLength !== 32)) return undefined;
  return {
    adminUrl: admin.toString(),
    postgresBin: path.resolve(parsed.POSTGRES_BIN),
    secretMasterKey,
    authEncryptionKey,
    backupKey,
    backupKeyId: activeKey.id,
  };
}

async function canReachWorkspace(connectionString: string): Promise<boolean> {
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_500 });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === WORKSPACE_PORT;
  } catch {
    return false;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

function requireFixture(): ExposureFixture {
  if (!fixture) throw new Error("AC-31 exposure fixture is unavailable");
  return fixture;
}

function pgToolPath(postgresBin: string, tool: "pg_dump" | "pg_restore"): string {
  return path.join(postgresBin, process.platform === "win32" ? `${tool}.exe` : tool);
}

async function runProcess(
  executable: string,
  args: readonly string[],
  password: string | undefined,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      windowsHide: true,
      shell: false,
      env: { ...process.env, PGCONNECT_TIMEOUT: "5", ...(password ? { PGPASSWORD: password } : {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
}
