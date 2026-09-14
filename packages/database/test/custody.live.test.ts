import {
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool, type PoolClient } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import {
  CUSTODY_HPKE_SUITE,
  CUSTODY_SIGNING_ALGORITHM,
  buildTallyAttestationContext,
  canonicalCustodyJson,
  custodySha256,
  hashCanonicalCustodyJson,
  type CustodianKeyMaterial,
} from "../src/custody-crypto.js";
import { CustodyStore } from "../src/custody-store.js";
import { runMigrations } from "../src/migrations.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Custody live tests require the local PostgreSQL 18 workspace cluster on 127.0.0.1:55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface KeyFixture {
  readonly identityId: string;
  readonly deviceId: string;
  readonly material: CustodianKeyMaterial;
  readonly signingPrivateKey: KeyObject;
  keyId?: string;
}

interface LiveFixture {
  readonly cluster: Pool;
  readonly tenant: Pool;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly officeId: string;
  readonly first: KeyFixture;
  readonly second: KeyFixture;
}

let fixture: LiveFixture | undefined;

live("E2EE custody PostgreSQL workflow", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 30_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 30_000);

  it("registers/fixes two custodians, stores an HPKE ballot, attests twice and publishes without elector identity", async () => {
    const current = requireFixture();
    const firstRegistrationId = randomUUID();
    const firstRegistration = await withStore(current.tenant, current.first.identityId, (store) =>
      store.registerKey({
        ...current.first.material,
        identityId: current.first.identityId,
        deviceId: current.first.deviceId,
        expectedVersion: 0,
        idempotencyKey: firstRegistrationId,
      }),
    );
    const replay = await withStore(current.tenant, current.first.identityId, (store) =>
      store.registerKey({
        ...current.first.material,
        identityId: current.first.identityId,
        deviceId: current.first.deviceId,
        expectedVersion: 0,
        idempotencyKey: firstRegistrationId,
      }),
    );
    expect(replay).toEqual(firstRegistration);
    current.first.keyId = stringField(firstRegistration, "keyId");

    const secondRegistration = await withStore(current.tenant, current.second.identityId, (store) =>
      store.registerKey({
        ...current.second.material,
        identityId: current.second.identityId,
        deviceId: current.second.deviceId,
        expectedVersion: 0,
        idempotencyKey: randomUUID(),
      }),
    );
    current.second.keyId = stringField(secondRegistration, "keyId");

    const workflow = await prepareManifest(current, "matching");
    const downloaded = await withStore(current.tenant, current.first.identityId, (store) =>
      store.downloadManifest(workflow.roundId, current.first.identityId),
    );
    expect(downloaded).not.toBeNull();
    expect(JSON.stringify(downloaded)).not.toContain(workflow.electorId);
    expect(JSON.stringify(downloaded)).not.toContain("privateKey");
    await expect(withStore(current.tenant, randomUUID(), (store) =>
      store.downloadManifest(workflow.roundId, randomUUID()),
    )).resolves.toBeNull();

    const aggregate = aggregateFixture(workflow.candidateIds, 0);
    const aggregateHash = custodySha256(canonicalCustodyJson(aggregate));
    const firstAttestation = await attest(current, workflow, current.first, 1, aggregate);
    expect(firstAttestation["state"]).toBe("awaiting_attestations");
    const secondAttestation = await attest(current, workflow, current.second, 2, aggregate);
    expect(secondAttestation["state"]).toBe("publishable");
    expect(secondAttestation["version"]).toBe(3);

    const publication = await withStore(current.tenant, current.first.identityId, (store) =>
      store.publishAggregate({
        identityId: current.first.identityId,
        idempotencyKey: randomUUID(),
        roundId: workflow.roundId,
        expectedRoundVersion: 3,
        expectedManifestVersion: 3,
      }),
    );
    expect(publication).toMatchObject({ state: "published", aggregateHash, aggregate, roundVersion: 4, version: 4 });
    await expect(withStore(current.tenant, randomUUID(), (store) =>
      store.getPublishedAggregate(workflow.roundId),
    )).resolves.toMatchObject({ aggregateHash, aggregate, state: "published" });

    const evidence = await current.tenant.query<{
      manifest_entries: number;
      attestations: number;
      manifest_identity_columns: number;
      private_key_columns: number;
      phase: string;
    }>(
      `SELECT
         (SELECT count(*)::int FROM tally_manifest_entries entry
           JOIN tally_manifests manifest ON manifest.id=entry.manifest_id WHERE manifest.round_id=$1) AS manifest_entries,
         (SELECT count(*)::int FROM custodian_attestations attestation
           JOIN tally_manifests manifest ON manifest.id=attestation.manifest_id WHERE manifest.round_id=$1) AS attestations,
         (SELECT count(*)::int FROM information_schema.columns
           WHERE table_schema='public' AND table_name='tally_manifest_entries'
             AND column_name LIKE '%identity%') AS manifest_identity_columns,
         (SELECT count(*)::int FROM information_schema.columns
           WHERE table_schema='public' AND table_name IN ('custodian_device_keys','round_custodian_key_snapshots')
             AND column_name LIKE '%private%') AS private_key_columns,
         (SELECT phase FROM rounds WHERE id=$1) AS phase`,
      [workflow.roundId],
    );
    expect(evidence.rows[0]).toEqual({
      manifest_entries: 1,
      attestations: 2,
      manifest_identity_columns: 0,
      private_key_columns: 0,
      phase: "RESULTADO_INTERNO",
    });
  }, 30_000);

  it("persists a genuine two-custodian discrepancy and blocks publication", async () => {
    const current = requireFixture();
    const workflow = await prepareManifest(current, "disputed");
    const firstAggregate = aggregateFixture(workflow.candidateIds, 0);
    const secondAggregate = aggregateFixture(workflow.candidateIds, 1);
    await attest(current, workflow, current.first, 1, firstAggregate);
    const disagreement = await attest(current, workflow, current.second, 2, secondAggregate);
    expect(disagreement).toMatchObject({ state: "disputed", version: 3 });
    await expect(withStore(current.tenant, current.first.identityId, (store) =>
      store.publishAggregate({
        identityId: current.first.identityId,
        idempotencyKey: randomUUID(),
        roundId: workflow.roundId,
        expectedRoundVersion: 3,
        expectedManifestVersion: 3,
      }),
    )).rejects.toMatchObject({ code: "AGGREGATE_NOT_PUBLISHABLE" });
  }, 30_000);

  it("blocks tally after a frozen private key is lost and its public registration is revoked", async () => {
    const current = requireFixture();
    const workflow = await prepareManifest(current, "lost-key");
    const secondKeyId = requireKeyId(current.second);
    await expect(withStore(current.tenant, current.second.identityId, (store) =>
      store.revokeKey({
        identityId: current.second.identityId,
        idempotencyKey: randomUUID(),
        keyId: secondKeyId,
        expectedVersion: 1,
        reasonCode: "private key lost while visiting a named person",
      }),
    )).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await withStore(current.tenant, current.second.identityId, (store) =>
      store.revokeKey({
        identityId: current.second.identityId,
        idempotencyKey: randomUUID(),
        keyId: secondKeyId,
        expectedVersion: 1,
        reasonCode: "VERIFIED_KEY_LOSS",
      }),
    );
    const storedReason = await current.tenant.query<{ revocation_reason: string }>(
      "SELECT revocation_reason FROM custodian_device_keys WHERE id=$1",
      [secondKeyId],
    );
    expect(storedReason.rows[0]?.revocation_reason).toBe("VERIFIED_KEY_LOSS");
    await expect(withStore(current.tenant, current.first.identityId, (store) =>
      store.attestManifest({
        identityId: current.first.identityId,
        idempotencyKey: randomUUID(),
        roundId: workflow.roundId,
        expectedManifestVersion: 1,
        aggregate: aggregateFixture(workflow.candidateIds, 0),
        signature: randomBytes(64).toString("base64url"),
      }),
    )).rejects.toMatchObject({ code: "CUSTODY_KEY_UNAVAILABLE" });
  }, 30_000);
});

async function prepareManifest(current: LiveFixture, label: string): Promise<{
  readonly roundId: string;
  readonly electorId: string;
  readonly manifestId: string;
  readonly manifestHash: string;
  readonly candidateIds: readonly [string, string];
}> {
  const roundId = randomUUID();
  const electorId = randomUUID();
  const cycleId = randomUUID();
  const candidateSetHash = custodySha256(`${label}:candidates`);
  const rulesHash = custodySha256(`${label}:rules`);
  const candidateIds = [randomUUID(), randomUUID()] as const;
  await current.tenant.query(
    `INSERT INTO election_cycles(
       id,name,status,locale,timezone,term_start,term_end,normative_version,eligible_reference_count
     ) VALUES ($1,$2,'draft','es','America/La_Paz','2026-01-01','2026-12-31','test',1)`,
    [cycleId, `Custody ${label}`],
  );
  await current.tenant.query(
    `INSERT INTO rounds(
       id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,
       candidate_set_hash,rules_hash,version,opened_at
     ) VALUES ($1,$2,$3,'VOTACION_ABIERTA','vote',1,1,$4,$5,1,clock_timestamp())`,
    [roundId, cycleId, current.officeId, candidateSetHash, rulesHash],
  );
  for (const [index, candidateId] of candidateIds.entries()) {
    const memberId = randomUUID();
    const displayEnvelope = {
      algorithm: "AES-256-GCM",
      keyId: "custody-display-fixture-key",
      nonce: randomBytes(12).toString("base64url"),
      ciphertext: randomBytes(32).toString("base64url"),
      aad: Buffer.from(JSON.stringify({
        tenantId: current.tenantId,
        memberId,
        purpose: "member-display",
        schemaVersion: 1,
      })).toString("base64url"),
    };
    await current.tenant.query(
      `INSERT INTO members(id,stable_code,display_envelope,display_content_hash) VALUES ($1,$2,$3,$4)`,
      [memberId, `CUSTODY-${label}-${index}`, displayEnvelope, custodySha256(JSON.stringify(displayEnvelope))],
    );
    await current.tenant.query(
      `INSERT INTO candidate_snapshots(
         round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
         member_version_snapshot,eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
         eligibility_evaluated_on,eligibility_effective
       ) SELECT $1,$2,member.id,$4,true,$5,0,member.version,
                member.eligibility_department_id,member.eligibility_valid_until,
                (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
           FROM members member CROSS JOIN tenant_settings settings
          WHERE member.id=$3 AND settings.singleton=true`,
      [roundId, candidateId, memberId, displayEnvelope, index + 1],
    );
  }
  await current.tenant.query(
    `INSERT INTO round_elector_snapshots(round_id,identity_id,can_submit,recused)
     VALUES ($1,$2,true,false)`,
    [roundId, electorId],
  );
  await withStore(current.tenant, current.first.identityId, (store) =>
    store.freezeRound({
      identityId: current.first.identityId,
      idempotencyKey: randomUUID(),
      roundId,
      expectedRoundVersion: 1,
      keyIds: [requireKeyId(current.first), requireKeyId(current.second)],
    }),
  );
  const publicRecipients = await withStore(current.tenant, electorId, (store) =>
    store.getBallotRecipients(roundId, electorId, current.tenantId),
  );
  expect(publicRecipients).toMatchObject({
    roundId,
    roundVersion: 1,
    custodyVersion: 1,
    suite: CUSTODY_HPKE_SUITE,
  });
  expect(canonicalCustodyJson(publicRecipients)).not.toContain("signing");
  expect(canonicalCustodyJson(publicRecipients)).not.toContain("custodianIdentityId");
  await expect(withStore(current.tenant, randomUUID(), (store) =>
    store.getBallotRecipients(roundId, randomUUID(), current.tenantId),
  )).rejects.toMatchObject({ statusCode: 403, code: "NOT_AN_ELECTOR" });
  await expect(withStore(current.tenant, electorId, (store) =>
    store.getBallotRecipients(roundId, electorId, randomUUID()),
  )).rejects.toMatchObject({ statusCode: 403, code: "CUSTODY_TENANT_MISMATCH" });
  const envelope = ballotEnvelope({
    tenantId: current.tenantId,
    cycleId,
    roundId,
    roundVersion: 1,
    candidateSetHash,
    rulesHash,
    keys: [current.first.material, current.second.material],
  });
  await withStore(current.tenant, electorId, (store) =>
    store.submitBallot({
      identityId: electorId,
      idempotencyKey: randomUUID(),
      roundId,
      expectedVersion: 1,
      envelope: envelope.value,
      contentHash: envelope.contentHash,
    }),
  );
  await current.tenant.query(
    "UPDATE rounds SET phase='VOTACION_CERRADA',version=2,closed_at=clock_timestamp() WHERE id=$1",
    [roundId],
  );
  const manifest = await withStore(current.tenant, current.first.identityId, (store) =>
    store.createManifest({
      identityId: current.first.identityId,
      idempotencyKey: randomUUID(),
      roundId,
      expectedRoundVersion: 2,
      expectedCustodyVersion: 1,
    }),
  );
  expect(manifest).toMatchObject({ state: "awaiting_attestations", version: 1, roundVersion: 3, entryCount: 1 });
  return {
    roundId,
    electorId,
    manifestId: stringField(manifest, "manifestId"),
    manifestHash: stringField(manifest, "manifestHash"),
    candidateIds,
  };
}

async function attest(
  current: LiveFixture,
  workflow: { readonly roundId: string; readonly manifestId: string; readonly manifestHash: string },
  key: KeyFixture,
  expectedManifestVersion: number,
  aggregate: ReturnType<typeof aggregateFixture>,
): Promise<Record<string, unknown>> {
  const aggregateHash = custodySha256(canonicalCustodyJson(aggregate));
  const context = buildTallyAttestationContext({
    tenantId: current.tenantId,
    roundId: workflow.roundId,
    manifestId: workflow.manifestId,
    manifestHash: workflow.manifestHash,
    aggregateHash,
  });
  const signature = sign(
    null,
    Buffer.from(canonicalCustodyJson(context), "utf8"),
    key.signingPrivateKey,
  ).toString("base64url");
  return withStore(current.tenant, key.identityId, (store) => store.attestManifest({
    identityId: key.identityId,
    idempotencyKey: randomUUID(),
    roundId: workflow.roundId,
    expectedManifestVersion,
    aggregate,
    signature,
  }));
}

function aggregateFixture(
  candidateIds: readonly [string, string],
  selectedIndex: 0 | 1,
) {
  const sorted = [...candidateIds].sort();
  const selected = candidateIds[selectedIndex];
  return {
    schemaVersion: 1 as const,
    receivedBallots: 1,
    nonAbstainingBallots: 1,
    abstentions: 0,
    maxSelections: 1,
    candidates: sorted.map((candidateId) => ({ candidateId, votes: candidateId === selected ? 1 : 0 })),
    rule: { kind: "PLURALITY" as const },
    decision: {
      status: "SELECTED" as const,
      reason: "TOP_K" as const,
      selectedCandidateIds: [selected],
      tiebreakCandidateIds: [],
      unfilledSeats: 0,
    },
  };
}

function ballotEnvelope(input: {
  readonly tenantId: string;
  readonly cycleId: string;
  readonly roundId: string;
  readonly roundVersion: number;
  readonly candidateSetHash: string;
  readonly rulesHash: string;
  readonly keys: readonly CustodianKeyMaterial[];
}): { readonly value: Record<string, unknown>; readonly contentHash: string } {
  const body = {
    format: "nombramientos.hpke-ballot-envelope",
    version: 1,
    suite: CUSTODY_HPKE_SUITE,
    aad: {
      tenantId: input.tenantId,
      cycleId: input.cycleId,
      roundId: input.roundId,
      purpose: "nombramientos.ballot.selections",
      schemaVersion: 1,
      roundVersion: input.roundVersion,
      candidateSetHash: input.candidateSetHash,
      rulesHash: input.rulesHash,
    },
    recipients: input.keys
      .map((key) => ({
        recipientId: key.recipientId,
        fingerprint: key.hpkeFingerprint,
        enc: randomBytes(65).toString("base64url"),
        ciphertext: randomBytes(64).toString("base64url"),
      }))
      .sort((left, right) => left.recipientId < right.recipientId ? -1 : 1),
  };
  const value = { ...body, envelopeHash: hashCanonicalCustodyJson(body) };
  return { value, contentHash: hashCanonicalCustodyJson(value) };
}

async function createFixture(databaseAdminUrl: string): Promise<LiveFixture> {
  const suffix = randomBytes(12).toString("hex");
  const databaseName = `nom_custody_test_${suffix}`;
  const tenantId = randomUUID();
  const officeId = randomUUID();
  const cluster = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    application_name: "nombramientos-custody-live-cluster",
    max: 1,
  });
  const tenant = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, databaseName),
    application_name: "nombramientos-custody-live-tenant",
    max: 4,
  });
  try {
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [databaseName]);
    await runMigrations(tenant, {
      scope: "tenant",
      directory: path.join(packageRoot, "migrations", "tenant"),
    });
    const departmentId = randomUUID();
    await tenant.query(
      `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state)
       VALUES ($1,'Custody live temporary tenant','demo','America/La_Paz','es','ready')`,
      [tenantId],
    );
    await tenant.query(
      "INSERT INTO departments(id,canonical_code,names) VALUES ($1,'CUSTODY_TEST',$2)",
      [departmentId, { es: "Custody test" }],
    );
    await tenant.query(
      `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality)
       VALUES ($1,$2,'CUSTODY_TEST_OFFICE',$3,'committee',1)`,
      [officeId, departmentId, { es: "Custody test office" }],
    );
    return {
      cluster,
      tenant,
      databaseName,
      tenantId,
      officeId,
      first: keyFixture(randomUUID(), "custodian-a"),
      second: keyFixture(randomUUID(), "custodian-b"),
    };
  } catch (error) {
    return cleanupAfterFailure(error, () => cleanupCustodyDatabase(cluster, tenant, databaseName), "Custody fixture setup");
  }
}

function keyFixture(identityId: string, recipientId: string): KeyFixture {
  const hpke = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = hpke.publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Error("P-256 fixture export failed");
  const hpkeBytes = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]);
  const signing = generateKeyPairSync("ed25519");
  const signingSpki = signing.publicKey.export({ format: "der", type: "spki" });
  return {
    identityId,
    deviceId: randomUUID(),
    signingPrivateKey: signing.privateKey,
    material: {
      recipientId,
      suite: CUSTODY_HPKE_SUITE,
      hpkePublicKey: hpkeBytes.toString("base64url"),
      hpkeFingerprint: custodySha256(hpkeBytes),
      signingAlgorithm: CUSTODY_SIGNING_ALGORITHM,
      signingPublicKeySpki: signingSpki.toString("base64url"),
      signingFingerprint: custodySha256(signingSpki),
    },
  };
}

async function withStore<T>(
  pool: Pool,
  identityId: string,
  work: (store: CustodyStore) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, identityId);
    const result = await work(new CustodyStore(client));
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function setContext(client: PoolClient, identityId: string): Promise<void> {
  await client.query(
    `SELECT set_config('app.identity_id',$1,true),set_config('app.session_id',$2,true),
            set_config('app.request_id',$3,true)`,
    [identityId, randomUUID(), randomUUID()],
  );
}

async function cleanupFixture(current: LiveFixture): Promise<void> {
  await cleanupCustodyDatabase(current.cluster, current.tenant, current.databaseName);
}

async function cleanupCustodyDatabase(cluster: Pool, tenant: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [tenant], assertSafeDatabaseName: assertCustodyDatabaseName }],
    label: "Temporary custody database",
  });
}

function assertCustodyDatabaseName(databaseName: string): void {
  if (!/^nom_custody_test_[0-9a-f]{24}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-custody-test database");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the custody test statement");
  await pool.query(sql);
}

function requireFixture(): LiveFixture {
  if (!fixture) throw new Error("Custody live fixture is unavailable");
  return fixture;
}

function requireKeyId(key: KeyFixture): string {
  if (!key.keyId) throw new Error("Custodian fixture has no registered key id");
  return key.keyId;
}

function stringField(value: Record<string, unknown>, field: string): string {
  const item = value[field];
  if (typeof item !== "string") throw new Error(`Expected ${field} in custody response`);
  return item;
}

function discoverAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (parsed && typeof parsed === "object" && "DATABASE_ADMIN_URL" in parsed) {
        const configured = parsed.DATABASE_ADMIN_URL;
        if (typeof configured === "string") candidate = configured;
      }
    }
    if (!candidate) return undefined;
    return assertWorkspacePostgresUrl(candidate, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReachWorkspace(databaseAdminUrl: string): Promise<boolean> {
  const pool = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    connectionTimeoutMillis: 1_500,
    max: 1,
  });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === WORKSPACE_PORT;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)) throw new Error("Invalid local database name");
  const url = new URL(databaseAdminUrl);
  if (!isLoopback(url.hostname) || Number(url.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Custody tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}
