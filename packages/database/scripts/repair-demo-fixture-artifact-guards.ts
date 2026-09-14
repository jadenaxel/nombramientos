import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import { assertDemoReferenceFixture, createDemoReferenceFixture } from "@nombramientos/domain";

import { DEMO_ACCESS_PROFILE_DEFINITIONS, DEMO_ACCESS_TENANT_ID } from "../src/demo-access.js";
import { assertSyntheticSeedTarget } from "../src/seed-guards.js";
import type { EncryptedEnvelope } from "../src/types.js";
import { assertWorkspacePostgresUrl } from "./script-config.js";

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const HEX_SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;

export const DEMO_FIXTURE_REPAIR_DATABASE = `nom_t_${DEMO_ACCESS_TENANT_ID.replaceAll("-", "")}`;
export const DEMO_FIXTURE_REPAIR_AUTHORIZATION = "AUTORIZO_REPARAR_FIXTURE_DEMO_EF271FE4_ECEF_181_A_180";
export const DEMO_FIXTURE_REPAIR_TARGET = Object.freeze({
  memberId: "ef271fe4-ecef-4b9c-bad1-4c4e9ab14dbc",
  stableCode: "MEM-EF271FE4-ECE",
  createdAt: "2026-09-12T02:40:11.390Z",
  auditSequence: "183",
  sourceRequestId: "76d16e30-2b7a-4959-9a02-740e177e36c1",
  outboxSequence: "100",
  outboxId: "02afac91-e930-4394-9779-c549b671fb83",
  idempotencyOperation: "member.create",
  idempotencyKey: "44a75658-f487-4b97-8a40-65f38c97761c",
  actorIdentityId: DEMO_ACCESS_PROFILE_DEFINITIONS.administrator.identityId,
});

const fixture = createDemoReferenceFixture();
assertDemoReferenceFixture(fixture);

export const DEMO_FIXTURE_REFERENCE_STABLE_CODES = Object.freeze(fixture.members.map(({ memberId }) => memberId));
export const DEMO_FIXTURE_EXPIRED_REPORT_IDS = Object.freeze([
  "report:cycle-coverage",
  "report:responsibility-load",
  "report:participation-summary",
].map(fixtureUuid));
export const DEMO_FIXTURE_MEMBER_FOREIGN_KEYS = Object.freeze([
  "assignments.member_id",
  "candidate_list_entries.member_id",
  "candidate_snapshots.member_id",
  "candidacies.member_id",
  "committee_memberships.member_id",
  "cycle_member_snapshots.member_id",
  "member_eligibility_workflow_pauses.member_id",
  "member_photo_assets.member_id",
  "session_attendance.member_id",
]);
export const DEMO_FIXTURE_MANIFEST = Object.freeze({
  seedId: "demo-reference",
  version: 5,
  fixtureHash: `sha256:${createHash("sha256").update(JSON.stringify(fixture)).digest("hex")}`,
  metadata: Object.freeze({
    members: 180,
    eligible: 150,
    referenceRounds: 20,
    frozenReferenceSubmissions: 280,
    vacancies: 40,
    recommended: 20,
    accepted: 15,
    elected: 10,
    independentResponsibilities: 20,
    uniqueRecommendedPeople: 16,
  }),
});

export type DemoFixtureRepairMode = "check" | "apply";

export interface DemoFixtureRepairCommand {
  readonly mode: DemoFixtureRepairMode;
}

export interface DemoRepairMemberRow {
  readonly id: string;
  readonly stable_code: string;
  readonly created_at: Date;
  readonly updated_at: Date;
  readonly version: number;
  readonly archived_at: Date | null;
  readonly profile_envelope: unknown;
  readonly display_envelope: unknown;
  readonly display_content_hash: string | null;
  readonly contact_envelope: unknown;
  readonly contact_content_hash: string | null;
  readonly profile_migration_required: boolean;
  readonly eligibility_envelope: unknown;
  readonly eligibility_status: string;
  readonly available: boolean;
}

export interface DemoRepairAuditRow {
  readonly sequence: string;
  readonly id: string;
  readonly occurred_at: Date;
  readonly hash_version: number;
  readonly actor_identity_id: string | null;
  readonly action: string;
  readonly entity_type: string | null;
  readonly entity_id: string | null;
  readonly result: string;
  readonly request_id: string | null;
  readonly metadata: unknown;
  readonly previous_hash: string | null;
  readonly event_hash: string;
}

export interface DemoRepairOutboxRow {
  readonly sequence: string;
  readonly id: string;
  readonly audience: string;
  readonly event_type: string;
  readonly aggregate_type: string;
  readonly aggregate_id: string | null;
  readonly payload: unknown;
  readonly occurred_at: Date;
  readonly published_at: Date | null;
}

export interface DemoRepairIdempotencyRow {
  readonly identity_id: string;
  readonly operation: string;
  readonly idempotency_key: string;
  readonly request_hash: string;
  readonly response_status: number | null;
  readonly response_body: unknown;
  readonly created_at: Date;
  readonly expires_at: Date;
}

export interface DemoFixtureSemanticSnapshot {
  readonly members: string;
  readonly active_members: string;
  readonly eligible: string;
  readonly vacancies: string;
  readonly recommended: string;
  readonly accepted: string;
  readonly elected: string;
  readonly responsibilities: string;
  readonly responsible_people: string;
  readonly cycles: string;
  readonly reference_rounds: string;
  readonly seeded_submissions: string;
  readonly split_members: string;
  readonly contact_free_members: string;
  readonly split_cycle_snapshots: string;
  readonly missing_candidate_displays: string;
  readonly assignment_display_snapshots: string;
  readonly expired_seed_reports: string;
  readonly active_cycle_reference_eligible: string;
}

export interface DemoFixtureManifestRow {
  readonly seed_id: string;
  readonly version: number;
  readonly fixture_hash: string;
  readonly metadata: unknown;
  readonly completed_at: Date;
}

export interface ForeignKeyReferenceCount {
  readonly table_name: string;
  readonly column_name: string;
  readonly count: string;
}

export interface OfflineObservation {
  readonly serviceStateFilePresent: boolean;
  readonly listeningPorts: readonly number[];
  readonly unexpectedDatabaseSessions: readonly Readonly<{
    pid: number;
    database: string;
    applicationName: string;
  }>[];
  readonly workerLeaseAcquired: boolean;
}

export function parseDemoFixtureRepairArguments(args: readonly string[]): DemoFixtureRepairCommand {
  if (args.length === 0 || (args.length === 1 && args[0] === "--check")) return { mode: "check" };
  if (
    args.length === 2
    && args[0] === "--apply"
    && args[1] === `--authorization=${DEMO_FIXTURE_REPAIR_AUTHORIZATION}`
  ) return { mode: "apply" };
  fail(
    `arguments are invalid; use --check, or --apply --authorization=${DEMO_FIXTURE_REPAIR_AUTHORIZATION}`,
  );
}

export function assertDemoFixtureRepairAdminUrl(value: string): URL {
  try {
    return assertWorkspacePostgresUrl(value, "nom_admin", "postgres");
  } catch {
    fail("DATABASE_ADMIN_URL must be the exact workspace administrator endpoint without URL options");
  }
}

export function assertDemoFixtureRepairControlUrl(value: string | undefined): URL {
  try {
    return assertWorkspacePostgresUrl(value ?? "", "nom_control", "nombramientos_control");
  } catch {
    fail("DATABASE_CONTROL_URL must be the exact workspace control endpoint without URL options");
  }
}

export function assertDemoControlTarget(row: Readonly<Record<string, unknown>>): void {
  assertSyntheticSeedTarget(
    { databaseName: DEMO_FIXTURE_REPAIR_DATABASE, tenantId: DEMO_ACCESS_TENANT_ID, kind: "demo" },
    {
      databaseName: requireString(row["database_name"], "control database_name"),
      tenantId: requireString(row["id"], "control tenant id"),
      kind: requireString(row["kind"], "control tenant kind"),
    },
  );
  if (row["slug"] !== "iglesia-demostracion" || row["status"] !== "active") {
    fail("control-plane Demo tenant is not the exact active fixture tenant");
  }
  if (row["database_host"] !== "127.0.0.1" || Number(row["database_port"]) !== 55432) {
    fail("control-plane Demo tenant is outside the exact workspace PostgreSQL route");
  }
  if (row["ssl_mode"] !== "disable") fail("control-plane Demo tenant has an unexpected SSL mode");
  if (
    row["control_database"] !== "nombramientos_control"
    || row["current_user"] !== "nom_admin"
    || row["server_address"] !== "127.0.0.1"
    || Number(row["server_port"]) !== 55432
  ) fail("control connection is not the exact isolated administrator endpoint");
}

export function assertDemoTenantTarget(row: Readonly<Record<string, unknown>>): void {
  assertSyntheticSeedTarget(
    { databaseName: DEMO_FIXTURE_REPAIR_DATABASE, tenantId: DEMO_ACCESS_TENANT_ID, kind: "demo" },
    {
      databaseName: requireString(row["database_name"], "tenant current_database"),
      tenantId: requireString(row["tenant_id"], "tenant_settings tenant_id"),
      kind: requireString(row["kind"], "tenant_settings kind"),
    },
  );
  if (row["setup_state"] !== "ready") fail("Demo tenant setup_state is not ready");
  if (
    row["current_user"] !== "nom_admin"
    || row["server_address"] !== "127.0.0.1"
    || Number(row["server_port"]) !== 55432
  ) fail("tenant connection is not the exact isolated administrator endpoint");
}

export function assertOfflineForDemoFixtureRepair(observation: OfflineObservation): void {
  if (observation.serviceStateFilePresent) {
    fail("local services state still exists; stop API, web and worker with stop-local.ps1 -KeepDatabase");
  }
  if (observation.listeningPorts.length > 0) {
    fail(`local service ports are listening (${observation.listeningPorts.join(",")})`);
  }
  if (!observation.workerLeaseAcquired) fail("the provisioning worker still owns its database lease");
  if (observation.unexpectedDatabaseSessions.length > 0) {
    const summary = observation.unexpectedDatabaseSessions
      .map(({ pid, database, applicationName }) => `${pid}:${database}:${applicationName || "unnamed"}`)
      .join(",");
    fail(`unexpected application database sessions remain (${summary})`);
  }
}

export function assertExactRepairEvidence(input: {
  readonly member: DemoRepairMemberRow;
  readonly audit: DemoRepairAuditRow;
  readonly outbox: DemoRepairOutboxRow;
  readonly idempotency: DemoRepairIdempotencyRow;
}): void {
  const { member, audit, outbox, idempotency } = input;
  if (
    member.id !== DEMO_FIXTURE_REPAIR_TARGET.memberId
    || member.stable_code !== DEMO_FIXTURE_REPAIR_TARGET.stableCode
    || iso(member.created_at, "member.created_at") !== DEMO_FIXTURE_REPAIR_TARGET.createdAt
    || member.version !== 1
    || member.archived_at !== null
    || member.profile_envelope !== null
    || member.contact_envelope !== null
    || member.contact_content_hash !== null
    || member.profile_migration_required
    || member.eligibility_envelope !== null
    || member.eligibility_status !== "eligible"
    || !member.available
  ) fail("exact accidental member structure did not match");
  if (iso(member.updated_at, "member.updated_at") < DEMO_FIXTURE_REPAIR_TARGET.createdAt) {
    fail("accidental member timestamps are inconsistent");
  }

  const displayEnvelope = assertDisplayEnvelope(member.display_envelope);
  const expectedDisplayHash = encryptedEnvelopeHash(displayEnvelope);
  if (member.display_content_hash !== expectedDisplayHash) fail("member display_content_hash did not match its envelope");

  if (
    audit.sequence !== DEMO_FIXTURE_REPAIR_TARGET.auditSequence
    || !UUID_PATTERN.test(audit.id)
    || audit.hash_version !== 2
    || audit.actor_identity_id !== DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId
    || audit.action !== "member.created"
    || audit.entity_type !== "member"
    || audit.entity_id !== DEMO_FIXTURE_REPAIR_TARGET.memberId
    || audit.result !== "success"
    || audit.request_id !== DEMO_FIXTURE_REPAIR_TARGET.sourceRequestId
    || !isDeepStrictEqual(audit.metadata, { eligibilityStatus: "eligible", available: true, version: 1 })
    || (audit.previous_hash !== null && !HEX_SHA256_PATTERN.test(audit.previous_hash))
    || !HEX_SHA256_PATTERN.test(audit.event_hash)
  ) fail("exact source audit evidence did not match");

  if (
    outbox.sequence !== DEMO_FIXTURE_REPAIR_TARGET.outboxSequence
    || outbox.id !== DEMO_FIXTURE_REPAIR_TARGET.outboxId
    || outbox.audience !== "tenant.authorized"
    || outbox.event_type !== "member.changed"
    || outbox.aggregate_type !== "member"
    || outbox.aggregate_id !== DEMO_FIXTURE_REPAIR_TARGET.memberId
    || !isDeepStrictEqual(outbox.payload, { memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId, version: 1 })
    || outbox.published_at !== null
  ) fail("exact original outbox evidence did not match");

  const expectedResponse = {
    id: DEMO_FIXTURE_REPAIR_TARGET.memberId,
    shortId: DEMO_FIXTURE_REPAIR_TARGET.stableCode,
    displayEnvelope,
    profileMigrationRequired: false,
    eligible: true,
    eligibilityStatus: "eligible",
    available: true,
    archived: false,
    archivedAt: null,
    currentResponsibilities: 0,
    version: 1,
    createdAt: DEMO_FIXTURE_REPAIR_TARGET.createdAt,
  };
  const expectedRequestHash = hashCanonical({
    identityId: DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId,
    idempotencyKey: DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey,
    memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId,
    stableCode: DEMO_FIXTURE_REPAIR_TARGET.stableCode,
    displayEnvelope,
    displayContentHash: expectedDisplayHash,
    eligibilityStatus: "eligible",
    available: true,
  });
  if (
    idempotency.identity_id !== DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId
    || idempotency.operation !== DEMO_FIXTURE_REPAIR_TARGET.idempotencyOperation
    || idempotency.idempotency_key !== DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey
    || !HEX_SHA256_PATTERN.test(idempotency.request_hash)
    || idempotency.request_hash !== expectedRequestHash
    || idempotency.response_status !== 200
    || !isDeepStrictEqual(idempotency.response_body, expectedResponse)
  ) fail("exact original idempotency evidence did not match");

  const idempotencyCreated = time(idempotency.created_at, "idempotency.created_at");
  const memberCreated = time(member.created_at, "member.created_at");
  const outboxOccurred = time(outbox.occurred_at, "outbox.occurred_at");
  const auditOccurred = time(audit.occurred_at, "audit.occurred_at");
  const expires = time(idempotency.expires_at, "idempotency.expires_at");
  if (idempotencyCreated > memberCreated || memberCreated > outboxOccurred || outboxOccurred > auditOccurred) {
    fail("source evidence timestamps are not in creation order");
  }
  if (Math.abs(expires - idempotencyCreated - 86_400_000) > 1_000) {
    fail("idempotency expiry is not the original 24-hour window");
  }
}

export function assertPreservedOperationalEvidence(input: {
  readonly originalOutbox: DemoRepairOutboxRow;
  readonly observedOutbox: DemoRepairOutboxRow;
  readonly originalIdempotency: DemoRepairIdempotencyRow;
  readonly observedIdempotency: DemoRepairIdempotencyRow;
}): void {
  if (!isDeepStrictEqual(input.observedOutbox, input.originalOutbox)) {
    fail("original outbox evidence changed during repair");
  }
  if (!isDeepStrictEqual(input.observedIdempotency, input.originalIdempotency)) {
    fail("original idempotency evidence changed during repair");
  }
}

export function assertCompensatingOutboxEvent(row: DemoRepairOutboxRow): void {
  if (
    BigInt(row.sequence) <= BigInt(DEMO_FIXTURE_REPAIR_TARGET.outboxSequence)
    || !UUID_PATTERN.test(row.id)
    || row.audience !== "tenant.authorized"
    || row.event_type !== "member.changed"
    || row.aggregate_type !== "member"
    || row.aggregate_id !== DEMO_FIXTURE_REPAIR_TARGET.memberId
    || !isDeepStrictEqual(row.payload, { memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId, version: 1 })
    || row.published_at !== null
  ) fail("compensating outbox event did not match the existing member.changed consumer contract");
  time(row.occurred_at, "compensating outbox occurred_at");
}

export function assertCompensatingAuditEvent(input: {
  readonly row: DemoRepairAuditRow;
  readonly requestId: string;
  readonly previousHash: string;
  readonly compensatingOutbox: DemoRepairOutboxRow;
}): void {
  const { row, requestId, previousHash, compensatingOutbox } = input;
  if (
    !UUID_PATTERN.test(row.id)
    || row.hash_version !== 2
    || row.actor_identity_id !== DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId
    || row.action !== "test.fixture.repaired"
    || row.entity_type !== "member"
    || row.entity_id !== DEMO_FIXTURE_REPAIR_TARGET.memberId
    || row.result !== "success"
    || row.request_id !== requestId
    || row.previous_hash !== previousHash
    || !HEX_SHA256_PATTERN.test(row.event_hash)
    || !isDeepStrictEqual(row.metadata, {
      reasonCode: "E2E_SERVICE_WORKER_MOCK_BYPASS",
      sourceAuditSequence: DEMO_FIXTURE_REPAIR_TARGET.auditSequence,
      sourceRequestId: DEMO_FIXTURE_REPAIR_TARGET.sourceRequestId,
      preservedOutboxId: DEMO_FIXTURE_REPAIR_TARGET.outboxId,
      preservedIdempotencyKey: DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey,
      compensatingOutboxId: compensatingOutbox.id,
      compensatingOutboxSequence: compensatingOutbox.sequence,
      expectedFixtureMembers: 180,
      expectedEligibleMembers: 150,
    })
  ) fail("compensating audit event did not match the exact repair contract");
  time(row.occurred_at, "compensating audit occurred_at");
}

export function assertForeignKeyReferencesAbsent(references: readonly ForeignKeyReferenceCount[]): void {
  if (references.length !== DEMO_FIXTURE_MEMBER_FOREIGN_KEYS.length) {
    fail(`expected ${DEMO_FIXTURE_MEMBER_FOREIGN_KEYS.length} member foreign keys, found ${references.length}`);
  }
  const unique = new Set<string>();
  for (const reference of references) {
    if (!/^[a-z_]+$/u.test(reference.table_name) || !/^[a-z_]+$/u.test(reference.column_name)) {
      fail("foreign-key metadata contains an unsafe identifier");
    }
    const key = `${reference.table_name}.${reference.column_name}`;
    if (unique.has(key)) fail(`duplicate member foreign-key projection (${key})`);
    unique.add(key);
    if (reference.count !== "0") fail(`${key} contains a reference to the accidental member`);
  }
  if (!isDeepStrictEqual([...unique].sort(), [...DEMO_FIXTURE_MEMBER_FOREIGN_KEYS].sort())) {
    fail("member foreign-key schema did not match the reviewed migration set");
  }
}

export function assertDemoFixtureManifest(row: DemoFixtureManifestRow): void {
  if (
    row.seed_id !== DEMO_FIXTURE_MANIFEST.seedId
    || row.version !== DEMO_FIXTURE_MANIFEST.version
    || !SHA256_PATTERN.test(row.fixture_hash)
    || row.fixture_hash !== DEMO_FIXTURE_MANIFEST.fixtureHash
    || !isDeepStrictEqual(row.metadata, DEMO_FIXTURE_MANIFEST.metadata)
  ) fail("complete Demo seed manifest did not match version, hash and metadata");
  time(row.completed_at, "seed manifest completed_at");
}

export function assertReferenceStableCodes(codes: readonly string[]): void {
  const actual = [...codes].sort();
  const expected = [...DEMO_FIXTURE_REFERENCE_STABLE_CODES].sort();
  if (!isDeepStrictEqual(actual, expected)) fail("the 180 reference member stable codes are incomplete or ambiguous");
}

export function assertDemoFixtureSemanticSnapshot(
  snapshot: DemoFixtureSemanticSnapshot,
  stage: "before" | "after",
): void {
  const exact = stage === "before"
    ? { members: "181", active_members: "181", eligible: "151", split_members: "181", contact_free_members: "181" }
    : { members: "180", active_members: "180", eligible: "150", split_members: "180", contact_free_members: "180" };
  for (const [key, expected] of Object.entries(exact)) {
    if (snapshot[key as keyof DemoFixtureSemanticSnapshot] !== expected) {
      fail(`Demo ${stage} invariant ${key} did not equal ${expected}`);
    }
  }
  const invariant: Readonly<Record<keyof Omit<DemoFixtureSemanticSnapshot,
    "members" | "active_members" | "eligible" | "split_members" | "contact_free_members">, string>> = {
    vacancies: "40",
    recommended: "20",
    accepted: "15",
    elected: "10",
    responsibilities: "20",
    responsible_people: "16",
    cycles: "3",
    reference_rounds: "20",
    seeded_submissions: "294",
    split_cycle_snapshots: "180",
    missing_candidate_displays: "0",
    assignment_display_snapshots: "20",
    expired_seed_reports: "3",
    active_cycle_reference_eligible: "150",
  };
  for (const [key, minimum] of Object.entries(invariant)) {
    const actual = BigInt(snapshot[key as keyof DemoFixtureSemanticSnapshot]);
    const expected = BigInt(minimum);
    const permitsAdditionalHistory = key === "cycles" || key === "reference_rounds" || key === "seeded_submissions";
    if (permitsAdditionalHistory ? actual < expected : actual !== expected) {
      fail(`Demo ${stage} invariant ${key} did not ${permitsAdditionalHistory ? "reach" : "equal"} ${minimum}`);
    }
  }
}

export function encryptedEnvelopeHash(envelope: EncryptedEnvelope): string {
  const canonical = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

export function hashCanonical(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function assertDisplayEnvelope(value: unknown): EncryptedEnvelope {
  if (!isRecord(value)) fail("member display envelope is not an object");
  const keys = Object.keys(value).sort();
  const expectedKeys = ["aad", "algorithm", "ciphertext", "keyId", "nonce"];
  if (!isDeepStrictEqual(keys, expectedKeys)) fail("member display envelope fields did not match the exact contract");
  const algorithm = value["algorithm"];
  const keyId = value["keyId"];
  const nonce = value["nonce"];
  const ciphertext = value["ciphertext"];
  const aad = value["aad"];
  if (
    algorithm !== "AES-256-GCM"
    || typeof keyId !== "string" || keyId.length < 8 || keyId.length > 160
    || typeof nonce !== "string" || !BASE64URL_PATTERN.test(nonce) || Buffer.from(nonce, "base64url").byteLength !== 12
    || typeof ciphertext !== "string" || !BASE64URL_PATTERN.test(ciphertext) || Buffer.from(ciphertext, "base64url").byteLength < 16
    || typeof aad !== "string" || !BASE64URL_PATTERN.test(aad)
  ) fail("member display envelope encoding did not match the browser AES-GCM contract");
  let aadValue: unknown;
  try {
    aadValue = JSON.parse(Buffer.from(aad, "base64url").toString("utf8"));
  } catch {
    fail("member display envelope AAD is not JSON");
  }
  if (!isDeepStrictEqual(aadValue, {
    tenantId: DEMO_ACCESS_TENANT_ID,
    memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId,
    purpose: "member-display",
    schemaVersion: 1,
  })) fail("member display envelope AAD did not match the exact Demo member context");
  return { algorithm, keyId, nonce, ciphertext, aad };
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) fail("canonical JSON contains an unsupported value");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) fail(`${label} is unavailable`);
  return value;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fixtureUuid(label: string): string {
  const raw = createHash("sha256").update(`nombramientos-demo:${label}`).digest("hex").slice(0, 32).split("");
  raw[12] = "4";
  raw[16] = "8";
  const hex = raw.join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function iso(value: Date, label: string): string {
  return new Date(time(value, label)).toISOString();
}

function time(value: Date, label: string): number {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail(`${label} is invalid`);
  return value.getTime();
}

function fail(message: string): never {
  throw new Error(`Fixture repair refused: ${message}`);
}
