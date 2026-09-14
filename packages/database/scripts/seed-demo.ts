import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  assertDemoReferenceFixture,
  createDemoReferenceFixture,
  evaluateMemberEligibilityForOffice,
} from "@nombramientos/domain";
import { hash, verify } from "argon2";
import * as OTPAuth from "otpauth";
import { Pool, type PoolClient } from "pg";
import { z } from "zod";
import {
  decryptServerSecret,
  encryptServerSecret,
  generateSecretKey,
  sealAesGcmJson,
  unwrapTenantKeyWithPassword,
  wrapTenantKeyWithPassword,
  type WrappedTenantKey,
} from "../src/crypto-envelope.js";
import {
  accessProfile,
  buildDemoAccessFileV2,
  demoAccessPublicManifest,
  DEMO_ACCESS_PROFILE_CODES,
  DEMO_ACCESS_PROFILE_DEFINITIONS,
  DEMO_ACCESS_TENANT_ID,
  parseDemoAccessFile,
  type DemoAccessFile,
  type DemoAccessFileV2,
  type DemoAccessProfileCode,
} from "../src/demo-access.js";
import { computeTenantAuditEventHash, verifyTenantAuditEventChain } from "../src/audit-anchors.js";
import { tenantAuditEventRecordFromRow, type TenantAuditEventDatabaseRow } from "../src/audit-event-chain.js";
import type { EncryptedEnvelope } from "../src/types.js";
import { assertSyntheticSeedTarget } from "../src/seed-guards.js";
import {
  loadLocalScriptValues,
  localScriptEnvironment,
  requireMasterKey,
  resolveDatabasePackageRoot,
  withoutDatabase,
} from "./script-config.js";

const DEMO_TENANT_ID = DEMO_ACCESS_TENANT_ID;
const DEMO_IDENTITY_ID = DEMO_ACCESS_PROFILE_DEFINITIONS.administrator.identityId;
const SEED_ID = "demo-reference";
const SEED_VERSION = 5;
const ACCESS_SEED_ID = "demo-access-profiles";
const ACCESS_SEED_VERSION = 1;
const INITIAL_AUDIT_SEED_VERSION = 4;
const MEMBER_ENVELOPE_REPAIR_VERSION = 5;
const DEMO_DATABASE_NAME = `nom_t_${DEMO_TENANT_ID.replaceAll("-", "")}`;

const environment = localScriptEnvironment.extend({
  AUTH_ENCRYPTION_KEY_B64: z.string(),
  DEMO_INITIAL_PASSWORD: z.string().min(16).optional(),
}).parse(loadLocalScriptValues());
const authEncryptionKey = Buffer.from(environment.AUTH_ENCRYPTION_KEY_B64, "base64url");
if (authEncryptionKey.byteLength !== 32) throw new Error("AUTH_ENCRYPTION_KEY_B64 must encode 32 bytes");

const fixture = createDemoReferenceFixture();
assertDemoReferenceFixture(fixture);
const fixtureHash = `sha256:${createHash("sha256").update(JSON.stringify(fixture)).digest("hex")}`;
const packageRoot = resolveDatabasePackageRoot(import.meta.url);
requireMasterKey(environment.DATABASE_SECRET_MASTER_KEY_B64);
const controlUrl = withoutDatabase(environment.DATABASE_ADMIN_URL, "nombramientos_control");
const control = new Pool({ connectionString: controlUrl, application_name: "nombramientos-demo-seed-control", max: 1 });

const tenantRecord = await control.query<{ database_name: string }>(
  "SELECT database_name FROM tenants WHERE id=$1 AND kind='demo' AND status='active'",
  [DEMO_TENANT_ID],
);
const tenant = tenantRecord.rows[0];
if (!tenant) throw new Error("Provision the demo tenant before seeding it");
assertSyntheticSeedTarget(
  { databaseName: DEMO_DATABASE_NAME, tenantId: DEMO_TENANT_ID, kind: "demo" },
  { databaseName: tenant.database_name, tenantId: DEMO_TENANT_ID, kind: "demo" },
);
const adminUrl = new URL(environment.DATABASE_ADMIN_URL);
adminUrl.pathname = `/${tenant.database_name}`;
const tenantPool = new Pool({ connectionString: adminUrl.toString(), application_name: "nombramientos-demo-seed", max: 1 });

let tenantKey: Buffer | undefined;
try {
  const targetResult = await tenantPool.query<{
    database_name: string;
    tenant_id: string;
    kind: string;
  }>(
    `SELECT current_database() AS database_name, tenant_id, kind
       FROM tenant_settings
      WHERE singleton = true`,
  );
  const target = targetResult.rows[0];
  if (!target) throw new Error("Synthetic seed target has no tenant settings row; refusing all writes");
  assertSyntheticSeedTarget(
    { databaseName: DEMO_DATABASE_NAME, tenantId: DEMO_TENANT_ID, kind: "demo" },
    { databaseName: target.database_name, tenantId: target.tenant_id, kind: target.kind },
  );
  const [countResult, manifestResult] = await Promise.all([
    tenantPool.query<{ count: number }>("SELECT count(*)::int AS count FROM members"),
    tenantPool.query<{ version: number; fixture_hash: string }>(
      "SELECT version,fixture_hash FROM seed_manifests WHERE seed_id=$1",
      [SEED_ID],
    ),
  ]);
  const memberCount = countResult.rows[0]?.count ?? 0;
  const manifest = manifestResult.rows[0];
  const referenceFixtureComplete = manifest?.version === SEED_VERSION
    && manifest.fixture_hash === fixtureHash
    && await isCompleteDemoFixture(tenantPool, memberCount > fixture.members.length);
  if (memberCount !== 0 && memberCount !== fixture.members.length && !referenceFixtureComplete) {
    throw new Error("Partial demo member seed detected; refusing an ambiguous repair");
  }

  const storedAccess = await readStoredDemoAccess(packageRoot);
  const preparedAccess = await prepareDemoAccessFile(
    control,
    storedAccess,
    environment.DEMO_INITIAL_PASSWORD,
  );
  if (preparedAccess.fileChanged) await writeDemoAccessFile(packageRoot, preparedAccess.access);
  const controlProfilesChanged = await ensureDemoControlProfiles(control, preparedAccess.access);
  const administratorAccess = preparedAccess.access.profiles.administrator;
  const grantResult = await tenantPool.query<{
    tenant_key_id: string;
    kdf: WrappedTenantKey["kdf"];
    wrap: WrappedTenantKey["wrap"];
  }>(
    `SELECT tenant_key_id,kdf,wrap FROM device_key_grants
      WHERE identity_id=$1 AND status='active'
      ORDER BY created_at DESC LIMIT 1`,
    [DEMO_IDENTITY_ID],
  );
  const storedGrant = grantResult.rows[0];
  let tenantKeyId: string;
  if (storedGrant) {
    tenantKeyId = storedGrant.tenant_key_id;
    tenantKey = unwrapTenantKeyWithPassword(
      { kdf: storedGrant.kdf, wrap: storedGrant.wrap },
      administratorAccess.password,
    );
  } else {
    if (memberCount !== 0) {
      throw new Error("Demo content exists without an active administrator key grant; automatic key replacement is refused");
    }
    tenantKey = generateSecretKey();
    tenantKeyId = randomUUID();
  }
  const tenantProfilesChanged = await ensureDemoTenantProfiles(
    tenantPool,
    preparedAccess.access,
    tenantKey,
    tenantKeyId,
  );
  const accessProfilesChanged = preparedAccess.fileChanged || controlProfilesChanged || tenantProfilesChanged;

  if (
    referenceFixtureComplete
  ) {
    const auditHistoryChanged = await ensureDemoAuditHistory(tenantPool);
    process.stdout.write(accessProfilesChanged
      ? "Demo fixture was already complete; its isolated access profiles were reconciled without changing the reference fixture.\n"
      : auditHistoryChanged
        ? "Demo seed was already complete and its synthetic audit history was appended; no credential, key, or reference fixture row was changed.\n"
        : "Demo seed is already complete; no credential, key, or fixture row was changed.\n");
    process.exitCode = 0;
  } else {

    const client = await tenantPool.connect();
    try {
      await client.query("BEGIN");
      const members = await seedMembers(client, tenantKey, tenantKeyId, memberCount > 0);
      const cycles = await seedCycles(client);
      const offices = await electableOfficeIds(client);
      const vacancies = await seedCurrentVacancies(client, cycles.current, offices);
      await seedCycleMemberSnapshot(client, cycles.current, members);
      const electors = await seedCommittee(client, cycles.current, members, tenantKey, tenantKeyId);
      // Migration 025 deliberately redacts legacy combined assignment
      // snapshots. This transaction is already guarded to the canonical demo
      // tenant, so temporarily relax provenance only while rebuilding the
      // deterministic synthetic evidence from display-only envelopes.
      await client.query("ALTER TABLE assignments DISABLE TRIGGER assignments_preserve_provenance");
      await seedAssignments(client, vacancies, members, tenantKey, tenantKeyId);
      await seedReferenceRounds(client, cycles.current, vacancies, members, electors, tenantKey, tenantKeyId);
      await seedActiveRound(client, cycles.current, offices, members);
      await seedHistoricalScenarios(
        client,
        cycles.historicalTie,
        cycles.historicalDeclined,
        offices,
        members,
        electors,
        tenantKey,
        tenantKeyId,
      );
      await client.query("ALTER TABLE assignments ENABLE TRIGGER assignments_preserve_provenance");
      await seedReports(client, cycles.current);
      await seedAuditHistory(client, cycles.current);
      await client.query(
        `INSERT INTO seed_manifests(seed_id,version,fixture_hash,metadata)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT(seed_id) DO UPDATE SET
           version=EXCLUDED.version,fixture_hash=EXCLUDED.fixture_hash,
           metadata=EXCLUDED.metadata,completed_at=clock_timestamp()`,
        [SEED_ID, SEED_VERSION, fixtureHash, {
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
        }],
      );
      await client.query("UPDATE tenant_settings SET setup_state='ready',updated_at=clock_timestamp() WHERE singleton=true");
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
    process.stdout.write("Demo seeded with the complete encrypted reference fixture and isolated access profiles; no credential was printed.\n");
  }
} finally {
  tenantKey?.fill(0);
  authEncryptionKey.fill(0);
  await Promise.allSettled([tenantPool.end(), control.end()]);
}

type DemoFixture = ReturnType<typeof createDemoReferenceFixture>;
type DemoRound = DemoFixture["rounds"][number];
type DemoResponse = DemoRound["ballots"][number]["response"];

interface SeedMember {
  readonly id: string;
  readonly stableCode: string;
  readonly displayEnvelope: EncryptedEnvelope;
  readonly eligibilityEnvelope: EncryptedEnvelope;
  readonly eligible: boolean;
}

interface SeedVacancy {
  readonly id: string;
  readonly officeId: string;
  readonly cycleId: string;
}

async function seedMembers(
  client: PoolClient,
  key: Buffer,
  keyId: string,
  replaceEnvelopes: boolean,
): Promise<ReadonlyMap<string, SeedMember>> {
  const result = new Map<string, SeedMember>();
  for (const member of fixture.members) {
    const stableCode = member.memberId;
    const existing = await client.query<{ id: string; profile_migration_required: boolean }>("SELECT id,profile_migration_required FROM members WHERE stable_code IN ($1,$2)", [stableCode, `DEMO-${member.memberId.slice(1).padStart(4, "0")}`]);
    const memberId = existing.rows[0]?.id ?? fixtureUuid(`member:${member.memberId}`);
    const visibleReason = member.visibleEligibilityReason?.trim();
    const photoAssetId = member.photoAssetId?.trim();
    const displayEnvelope = sealAesGcmJson(
      {
        displayName: member.displayName,
        synthetic: true,
        ...(photoAssetId ? { photoAssetId } : {}),
        ...(visibleReason ? { visibleReason } : {}),
      },
      key,
      keyId,
      { tenantId: DEMO_TENANT_ID, memberId, purpose: "member-display", schemaVersion: 1 },
    );
    const eligibilityEnvelope = sealAesGcmJson(
      { synthetic: true, ...(visibleReason ? { visibleReason } : {}) },
      key,
      keyId,
      { tenantId: DEMO_TENANT_ID, memberId, purpose: "member-eligibility", schemaVersion: 1 },
    );
    if (existing.rowCount === 0) {
      await client.query(
         `INSERT INTO members(
            id,stable_code,profile_envelope,display_envelope,display_content_hash,
            profile_migration_required,eligibility_envelope,eligibility_status,available,
            eligibility_department_id,eligibility_valid_until
          ) VALUES ($1,$2,NULL,$3,$4,false,$5,$6,$7,NULL,NULL)`,
        [memberId, stableCode, displayEnvelope, hashEnvelope(displayEnvelope), eligibilityEnvelope, member.eligibleInReferenceSnapshot ? "eligible" : "ineligible", member.eligibleInReferenceSnapshot],
      );
    } else if (replaceEnvelopes || existing.rows[0]?.profile_migration_required) {
      await client.query(
         `UPDATE members SET stable_code=$2,profile_envelope=NULL,display_envelope=$3,display_content_hash=$4,
            contact_envelope=NULL,contact_content_hash=NULL,profile_migration_required=false,eligibility_envelope=$5,
            eligibility_status=$6,available=$7,eligibility_department_id=NULL,eligibility_valid_until=NULL,
            updated_at=clock_timestamp() WHERE id=$1`,
        [memberId, stableCode, displayEnvelope, hashEnvelope(displayEnvelope), eligibilityEnvelope, member.eligibleInReferenceSnapshot ? "eligible" : "ineligible", member.eligibleInReferenceSnapshot],
      );
    }
    result.set(member.memberId, {
      id: memberId,
      stableCode,
      displayEnvelope,
      eligibilityEnvelope,
      eligible: member.eligibleInReferenceSnapshot,
    });
  }
  return result;
}

async function seedCycles(client: PoolClient): Promise<{ current: string; historicalTie: string; historicalDeclined: string }> {
  return {
    current: await ensureCycle(client, fixtureUuid("cycle:current"), "Ciclo demo 2027-2028", "active", "2027-01-01", "2028-12-31", "working-2026-09", 150),
    historicalTie: await ensureCycle(client, fixtureUuid("cycle:historical-tie"), "Ciclo demo 2023-2024", "archived", "2023-01-01", "2024-12-31", "historical-demo-v1", 145),
    historicalDeclined: await ensureCycle(client, fixtureUuid("cycle:historical-declined"), "Ciclo demo 2025-2026", "closed", "2025-01-01", "2026-12-31", "historical-demo-v2", 148),
  };
}

async function ensureCycle(
  client: PoolClient,
  wantedId: string,
  name: string,
  status: "active" | "closed" | "archived",
  termStart: string,
  termEnd: string,
  normativeVersion: string,
  eligible: number,
): Promise<string> {
  const existing = await client.query<{ id: string }>("SELECT id FROM election_cycles WHERE name=$1 ORDER BY created_at LIMIT 1", [name]);
  const id = existing.rows[0]?.id ?? wantedId;
  if (existing.rowCount === 0) {
    await client.query(
      `INSERT INTO election_cycles(id,name,status,locale,timezone,term_start,term_end,normative_version,eligible_reference_count)
       VALUES ($1,$2,$3,'es','America/Santo_Domingo',$4,$5,$6,$7)`,
      [id, name, status, termStart, termEnd, normativeVersion, eligible],
    );
  } else {
    await client.query(
      "UPDATE election_cycles SET status=$2,term_start=$3,term_end=$4,normative_version=$5,eligible_reference_count=$6 WHERE id=$1",
      [id, status, termStart, termEnd, normativeVersion, eligible],
    );
  }
  return id;
}

async function electableOfficeIds(client: PoolClient): Promise<readonly string[]> {
  const result = await client.query<{ id: string }>(
    `SELECT id FROM offices WHERE active
      AND appointment_mechanism NOT IN ('conference_appointment','ex_officio')
      ORDER BY canonical_code LIMIT 40`,
  );
  if (result.rows.length < 40) throw new Error("The versioned catalog must expose at least 40 electable offices");
  return result.rows.map(({ id }) => id);
}

async function seedCurrentVacancies(
  client: PoolClient,
  cycleId: string,
  officeIds: readonly string[],
): Promise<ReadonlyMap<string, SeedVacancy>> {
  const result = new Map<string, SeedVacancy>();
  for (let index = 0; index < fixture.vacancies.length; index += 1) {
    const source = fixture.vacancies[index];
    const officeId = officeIds[index];
    if (!source || !officeId) throw new Error("Reference vacancy/catalog mapping is incomplete");
    const status = source.electedByChurch ? "elected" : source.accepted ? "accepted" : source.recommendationPersonId ? "recommended" : "pending";
    const existing = await client.query<{ id: string }>("SELECT id FROM vacancies WHERE cycle_id=$1 AND office_id=$2 AND ordinal=1", [cycleId, officeId]);
    const id = existing.rows[0]?.id ?? fixtureUuid(`vacancy:${source.vacancyId}`);
    if (existing.rowCount === 0) {
      await client.query("INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status) VALUES ($1,$2,$3,1,$4)", [id, cycleId, officeId, status]);
    } else {
      await client.query("UPDATE vacancies SET status=$2 WHERE id=$1", [id, status]);
    }
    result.set(source.vacancyId, { id, officeId, cycleId });
  }
  return result;
}

async function seedCycleMemberSnapshot(client: PoolClient, cycleId: string, members: ReadonlyMap<string, SeedMember>): Promise<void> {
  for (const member of members.values()) {
    const memberVersion = await client.query<{ version: number }>("SELECT version FROM members WHERE id=$1", [member.id]);
    await client.query(
      `INSERT INTO cycle_member_snapshots(
         cycle_id,member_id,member_version,eligibility_status,available,profile_envelope,display_envelope,eligibility_envelope,
         eligibility_department_id_snapshot,eligibility_valid_until_snapshot,eligibility_evaluated_on,eligibility_effective
       ) VALUES ($1,$2,$3,$4,$5,NULL,$6,$7,NULL,NULL,
         (SELECT (clock_timestamp() AT TIME ZONE timezone)::date FROM tenant_settings WHERE singleton=true),$5)
       ON CONFLICT(cycle_id,member_id) DO UPDATE SET
         member_version=EXCLUDED.member_version,eligibility_status=EXCLUDED.eligibility_status,
         available=EXCLUDED.available,profile_envelope=NULL,display_envelope=EXCLUDED.display_envelope,
         legacy_profile_redacted=false,eligibility_envelope=EXCLUDED.eligibility_envelope,
         eligibility_department_id_snapshot=NULL,eligibility_valid_until_snapshot=NULL,
         eligibility_evaluated_on=EXCLUDED.eligibility_evaluated_on,
         eligibility_effective=EXCLUDED.eligibility_effective`,
      [cycleId, member.id, memberVersion.rows[0]?.version ?? 1, member.eligible ? "eligible" : "ineligible", member.eligible, member.displayEnvelope, member.eligibilityEnvelope],
    );
  }
}

async function seedCommittee(
  client: PoolClient,
  cycleId: string,
  members: ReadonlyMap<string, SeedMember>,
  key: Buffer,
  keyId: string,
): Promise<ReadonlyMap<string, string>> {
  const existing = await client.query<{ identity_id: string }>(
    "SELECT identity_id FROM committee_memberships WHERE cycle_id=$1 ORDER BY (identity_id=$2) DESC,joined_at,id",
    [cycleId, DEMO_IDENTITY_ID],
  );
  if (existing.rows.length !== 0 && existing.rows.length !== fixture.committee.length) throw new Error("Partial demo committee seed detected");
  const identities = existing.rows.length === fixture.committee.length
    ? existing.rows.map(({ identity_id }) => identity_id)
    : fixture.committee.map((_, index) => index === 0 ? DEMO_IDENTITY_ID : fixtureUuid(`committee-identity:${index + 1}`));
  const result = new Map<string, string>();
  for (let index = 0; index < fixture.committee.length; index += 1) {
    const source = fixture.committee[index];
    const identityId = identities[index];
    if (!source || !identityId) throw new Error("Reference committee mapping is incomplete");
    const member = members.get(source.memberId);
    if (!member) throw new Error(`Reference committee member is missing: ${source.memberId}`);
    const displayName = index === 0 ? "Presidente/Pastor de demostración" : index === 1 ? "Secretaría de demostración" : `Integrante sintético ${index + 1}`;
    const displayEnvelope = sealAesGcmJson(
      { displayName },
      key,
      keyId,
      { tenantId: DEMO_TENANT_ID, cycleId, identityId, purpose: "committee-display", schemaVersion: 1 },
    );
    await client.query(
      `INSERT INTO committee_memberships(
         id,cycle_id,identity_id,member_id,display_envelope,role_code,pastoral_capacity,voting_right,status
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,true,'active')
       ON CONFLICT(cycle_id,identity_id) DO UPDATE SET
         member_id=EXCLUDED.member_id,display_envelope=EXCLUDED.display_envelope,
         role_code=EXCLUDED.role_code,pastoral_capacity=EXCLUDED.pastoral_capacity,
         voting_right=true,status='active'`,
      [fixtureUuid(`committee-membership:${source.electorId}`), cycleId, identityId, member.id, displayEnvelope, index === 0 ? "chair" : index === 1 ? "secretary" : "member", index === 0],
    );
    result.set(source.electorId, identityId);
  }
  return result;
}

async function seedAssignmentEvidence(
  client: PoolClient,
  member: SeedMember,
  officeId: string,
): Promise<{ memberSnapshot: Record<string, unknown>; officeSnapshot: Record<string, unknown> }> {
  const result = await client.query<{
    member_version: number;
    eligibility_status: string;
    available: boolean;
    archived: boolean;
    eligibility_department_id: string | null;
    eligibility_valid_until: string | null;
    evaluated_on: string;
    office_department_id: string;
    office_active: boolean;
    office_canonical_code: string;
    office_names: Record<string, string>;
    office_version: number;
    office_department_active: boolean;
    restriction_department_active: boolean | null;
    catalog_version: string;
  }>(
    `SELECT member.version AS member_version,member.eligibility_status,member.available,
            member.archived_at IS NOT NULL AS archived,member.eligibility_department_id,
            to_char(member.eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until,
            to_char((clock_timestamp() AT TIME ZONE settings.timezone)::date,'YYYY-MM-DD') AS evaluated_on,
            office.department_id AS office_department_id,office.active AS office_active,
            office.canonical_code AS office_canonical_code,office.names AS office_names,
            office.version AS office_version,department.active AS office_department_active,
            restriction.active AS restriction_department_active,settings.catalog_version
       FROM members member
       JOIN offices office ON office.id=$2
       JOIN departments department ON department.id=office.department_id
       CROSS JOIN tenant_settings settings
       LEFT JOIN departments restriction ON restriction.id=member.eligibility_department_id
      WHERE member.id=$1 AND settings.singleton=true`,
    [member.id, officeId],
  );
  const evidence = result.rows[0];
  if (!evidence) throw new Error("Demo assignment eligibility evidence is unavailable");
  const decision = evaluateMemberEligibilityForOffice({
    eligibilityStatus: evidence.eligibility_status,
    available: evidence.available,
    archived: evidence.archived,
    departmentRestriction: evidence.eligibility_department_id,
    validUntil: evidence.eligibility_valid_until,
    evaluatedOn: evidence.evaluated_on,
    officeDepartmentId: evidence.office_department_id,
    ...(evidence.eligibility_department_id === null ? {} : {
      restrictionDepartmentActive: evidence.restriction_department_active === true,
    }),
  });
  return {
    memberSnapshot: {
      memberId: member.id,
      memberVersion: evidence.member_version,
      displayEnvelope: member.displayEnvelope,
      eligibility: {
        departmentRestriction: evidence.eligibility_department_id,
        validUntil: evidence.eligibility_valid_until,
        evaluatedOn: evidence.evaluated_on,
        effective: evidence.office_active && evidence.office_department_active && decision.eligible,
      },
    },
    officeSnapshot: {
      officeId,
      departmentId: evidence.office_department_id,
      canonicalCode: evidence.office_canonical_code,
      names: evidence.office_names,
      officeVersion: evidence.office_version,
      catalogVersion: evidence.catalog_version,
    },
  };
}

async function seedAssignments(
  client: PoolClient,
  vacancies: ReadonlyMap<string, SeedVacancy>,
  members: ReadonlyMap<string, SeedMember>,
  key: Buffer,
  keyId: string,
): Promise<void> {
  for (const source of fixture.vacancies.filter((vacancy) => vacancy.recommendationPersonId !== null)) {
    const vacancy = vacancies.get(source.vacancyId);
    const member = members.get(source.recommendationPersonId ?? "");
    if (!vacancy || !member) throw new Error(`Assignment mapping is incomplete: ${source.vacancyId}`);
    const wantedId = fixtureUuid(`assignment:${source.vacancyId}`);
    const existing = await client.query<{ id: string }>("SELECT id FROM assignments WHERE vacancy_id=$1 AND effective", [vacancy.id]);
    const assignmentId = existing.rows[0]?.id ?? wantedId;
    const state = source.electedByChurch ? "ELEGIDA_POR_IGLESIA" : source.accepted ? "ACEPTADA" : "PROPUESTA_INTERNA";
    const consentStatus = source.accepted ? "ACCEPTED" : null;
    const consentEnvelope = source.accepted
      ? sealAesGcmJson({ decision: "ACCEPTED", synthetic: true }, key, keyId, { tenantId: DEMO_TENANT_ID, assignmentId, purpose: "assignment-consent", schemaVersion: 1 })
      : null;
    const congregationalDecision = source.electedByChurch
      ? sealAesGcmJson({ outcome: "ELECTED", synthetic: true }, key, keyId, { tenantId: DEMO_TENANT_ID, assignmentId, purpose: "congregational-decision", schemaVersion: 1 })
      : null;
    const { memberSnapshot, officeSnapshot } = await seedAssignmentEvidence(client, member, vacancy.officeId);
    if (existing.rowCount === 0) {
      await client.query(
        `INSERT INTO assignments(
           id,vacancy_id,member_id,state,effective,consent_status,congregational_outcome,
           consent_envelope,congregational_decision,independent,member_snapshot,office_snapshot,cycle_id,office_id
         ) VALUES ($1,$2,$3,$4,true,$5,$6,$7,$8,true,$9,$10,$11,$12)`,
        [
          assignmentId, vacancy.id, member.id, state, consentStatus,
          source.electedByChurch ? "ELECTED" : null, consentEnvelope, congregationalDecision,
          memberSnapshot, officeSnapshot, vacancy.cycleId, vacancy.officeId,
        ],
      );
    } else {
      await client.query(
        `UPDATE assignments SET member_id=$2,state=$3,consent_status=$4,congregational_outcome=$5,
           consent_envelope=$6,congregational_decision=$7,independent=true,
           linked_to_assignment_id=NULL,member_snapshot=$8,office_snapshot=$9,cycle_id=$10,office_id=$11,
           updated_at=clock_timestamp() WHERE id=$1`,
        [
          assignmentId, member.id, state, consentStatus,
          source.electedByChurch ? "ELECTED" : null, consentEnvelope, congregationalDecision,
          memberSnapshot, officeSnapshot, vacancy.cycleId, vacancy.officeId,
        ],
      );
    }
  }
}

async function seedReferenceRounds(
  client: PoolClient,
  cycleId: string,
  vacancies: ReadonlyMap<string, SeedVacancy>,
  members: ReadonlyMap<string, SeedMember>,
  electors: ReadonlyMap<string, string>,
  key: Buffer,
  keyId: string,
): Promise<void> {
  for (const source of fixture.rounds) {
    const vacancy = vacancies.get(source.vacancyId);
    if (!vacancy) throw new Error(`Round vacancy is missing: ${source.vacancyId}`);
    await seedClosedRound(client, {
      seedLabel: `reference:${source.roundId}`,
      cycleId,
      officeId: vacancy.officeId,
      vacancyId: vacancy.id,
      vacancies: 1,
      maxProposalSelections: source.maxProposalSelections,
      maxBallotSelections: source.maxBallotSelections,
      candidateMemberCodes: source.candidateIds,
      responseSets: [
        { kind: "proposal", responses: source.proposalSubmissions },
        { kind: "vote", responses: source.ballots },
      ],
      members,
      electors,
      key,
      keyId,
    });
  }
}

async function seedClosedRound(client: PoolClient, input: {
  seedLabel: string;
  cycleId: string;
  officeId: string;
  vacancyId?: string;
  phase?: "CERRADO" | "DESEMPATE_PENDIENTE";
  vacancies: number;
  maxProposalSelections: number;
  maxBallotSelections: number;
  candidateMemberCodes: readonly string[];
  responseSets: readonly {
    kind: "proposal" | "vote";
    responses: readonly { readonly electorId: string; readonly response: DemoResponse }[];
  }[];
  members: ReadonlyMap<string, SeedMember>;
  electors: ReadonlyMap<string, string>;
  key: Buffer;
  keyId: string;
}): Promise<void> {
  const roundId = fixtureUuid(`round:${input.seedLabel}`);
  const candidateSetHash = `sha256:${createHash("sha256").update(input.candidateMemberCodes.join("|")).digest("hex")}`;
  const rulesHash = `sha256:${createHash("sha256").update(`${input.vacancies}|${input.maxProposalSelections}|${input.maxBallotSelections}|demo-v1`).digest("hex")}`;
  await client.query(
    `INSERT INTO rounds(
       id,cycle_id,office_id,vacancy_id,phase,submission_kind,vacancies,max_selections,
       max_proposal_selections,max_ballot_selections,candidate_set_hash,rules_hash,version,opened_at,closed_at
     ) VALUES ($1,$2,$3,$4,$5,'vote',$6,$7,$8,$7,$9,$10,1,clock_timestamp()-interval '30 days',clock_timestamp()-interval '29 days')
     ON CONFLICT(id) DO UPDATE SET
       phase=EXCLUDED.phase,vacancy_id=EXCLUDED.vacancy_id,
       max_selections=EXCLUDED.max_selections,
       max_proposal_selections=EXCLUDED.max_proposal_selections,
       max_ballot_selections=EXCLUDED.max_ballot_selections,
       candidate_set_hash=EXCLUDED.candidate_set_hash,rules_hash=EXCLUDED.rules_hash`,
    [roundId, input.cycleId, input.officeId, input.vacancyId ?? null, input.phase ?? "CERRADO", input.vacancies, input.maxBallotSelections, input.maxProposalSelections, candidateSetHash, rulesHash],
  );
  const candidateIds = new Map<string, string>();
  for (let index = 0; index < input.candidateMemberCodes.length; index += 1) {
    const memberCode = input.candidateMemberCodes[index];
    const member = memberCode ? input.members.get(memberCode) : undefined;
    if (!member || !memberCode) throw new Error(`Round candidate is missing: ${memberCode ?? "unknown"}`);
    const candidateId = fixtureUuid(`candidate:${input.seedLabel}:${memberCode}`);
    candidateIds.set(memberCode, candidateId);
    await client.query(
      `INSERT INTO candidate_snapshots(
         round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
         eligibility_department_id_snapshot,eligibility_valid_until_snapshot,eligibility_evaluated_on,eligibility_effective
       ) VALUES ($1,$2,$3,$4,true,$5,0,NULL,NULL,
         (SELECT (clock_timestamp() AT TIME ZONE timezone)::date FROM tenant_settings WHERE singleton=true),true)
       ON CONFLICT(round_id,candidate_id) DO UPDATE SET
         display_envelope=EXCLUDED.display_envelope,eligible=true,visible_order=EXCLUDED.visible_order,
         eligibility_department_id_snapshot=NULL,eligibility_valid_until_snapshot=NULL,
         eligibility_evaluated_on=EXCLUDED.eligibility_evaluated_on,eligibility_effective=true`,
      [roundId, candidateId, member.id, member.displayEnvelope, index],
    );
  }
  for (const set of input.responseSets) {
    for (const source of set.responses) {
      const identityId = input.electors.get(source.electorId);
      if (!identityId) throw new Error(`Reference elector is missing: ${source.electorId}`);
      await client.query(
        `INSERT INTO round_elector_snapshots(round_id,identity_id,can_submit,recused)
         VALUES ($1,$2,true,false) ON CONFLICT(round_id,identity_id) DO NOTHING`,
        [roundId, identityId],
      );
      const encryptedResponse = source.response.kind === "ABSTENTION"
        ? { schema: "nombramientos-submission/v1", abstain: true, selections: [] }
        : {
            schema: "nombramientos-submission/v1",
            abstain: false,
            selections: source.response.candidateIds.map((memberCode) => {
              const candidateId = candidateIds.get(memberCode);
              if (!candidateId) throw new Error(`Response candidate is outside the round: ${memberCode}`);
              return candidateId;
            }),
          };
      const envelope = sealAesGcmJson(encryptedResponse, input.key, input.keyId, {
        tenantId: DEMO_TENANT_ID,
        cycleId: input.cycleId,
        roundId,
        purpose: set.kind,
        schemaVersion: 1,
        roundVersion: 1,
        candidateSetHash,
        rulesHash,
      });
      const contentHash = hashEnvelope(envelope);
      const submissionId = fixtureUuid(`submission:${input.seedLabel}:${set.kind}:${source.electorId}`);
      await client.query(
        `INSERT INTO encrypted_submissions(id,round_id,elector_identity_id,kind,envelope,content_hash,round_version)
         VALUES ($1,$2,$3,$4,$5,$6,1)
         ON CONFLICT(round_id,elector_identity_id,kind) DO NOTHING`,
        [submissionId, roundId, identityId, set.kind, envelope, contentHash],
      );
      await client.query(
        `INSERT INTO participation_receipts(id,submission_id,round_id,elector_identity_id,kind,content_hash,received_at)
         SELECT $1,s.id,s.round_id,s.elector_identity_id,s.kind,s.content_hash,s.received_at
           FROM encrypted_submissions s WHERE s.round_id=$2 AND s.elector_identity_id=$3 AND s.kind=$4
         ON CONFLICT(round_id,elector_identity_id,kind) DO NOTHING`,
        [fixtureUuid(`receipt:${input.seedLabel}:${set.kind}:${source.electorId}`), roundId, identityId, set.kind],
      );
    }
  }
}

async function seedActiveRound(
  client: PoolClient,
  cycleId: string,
  officeIds: readonly string[],
  members: ReadonlyMap<string, SeedMember>,
): Promise<void> {
  const activeResult = await client.query<{ id: string }>(
    `SELECT id FROM rounds WHERE cycle_id=$1 AND phase IN (
      'PROPUESTAS_ABIERTAS','PROPUESTAS_CERRADAS','DEPURACION','LISTA_CONFIRMADA',
      'VOTACION_ABIERTA','VOTACION_CERRADA','ESCRUTINIO','RESULTADO_INTERNO',
      'RECOMENDACION_CONFIRMADA','PAUSADO'
    ) ORDER BY created_at DESC LIMIT 1`,
    [cycleId],
  );
  const officeId = officeIds[20];
  if (!officeId) throw new Error("Catalog does not contain an office for the active demo round");
  const roundId = activeResult.rows[0]?.id ?? fixtureUuid("round:active-proposal");
  // An open round must never contain a base-ineligible candidate; keep the
  // synthetic demo usable under the same fail-closed rule as real tenants.
  const activeMemberCodes = ["M001", "M002", "M003"] as const;
  const candidateSetHash = `sha256:${createHash("sha256").update(activeMemberCodes.join("|")).digest("hex")}`;
  const rulesHash = `sha256:${createHash("sha256").update("proposal|1|3|demo-active-v1").digest("hex")}`;
  if (activeResult.rowCount === 0) {
    await client.query(
      `INSERT INTO rounds(
         id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,
         max_proposal_selections,max_ballot_selections,candidate_set_hash,rules_hash,opened_at
       ) VALUES ($1,$2,$3,'PROPUESTAS_ABIERTAS','proposal',1,3,3,1,$4,$5,clock_timestamp())`,
      [roundId, cycleId, officeId, candidateSetHash, rulesHash],
    );
  }
  const submissionCount = await client.query<{ count: number }>("SELECT count(*)::int AS count FROM encrypted_submissions WHERE round_id=$1", [roundId]);
  if ((submissionCount.rows[0]?.count ?? 0) === 0) {
    await client.query(
      "UPDATE rounds SET candidate_set_hash=$2,rules_hash=$3 WHERE id=$1",
      [roundId, candidateSetHash, rulesHash],
    );
    await client.query("DELETE FROM candidate_snapshots WHERE round_id=$1", [roundId]);
    await client.query("DELETE FROM round_elector_snapshots WHERE round_id=$1", [roundId]);
    await client.query("INSERT INTO round_elector_snapshots(round_id,identity_id) VALUES ($1,$2)", [roundId, DEMO_IDENTITY_ID]);
    for (const [index, memberCode] of activeMemberCodes.entries()) {
      const member = members.get(memberCode);
      if (!member) throw new Error(`Active candidate is missing: ${memberCode}`);
      await client.query(
        `INSERT INTO candidate_snapshots(
           round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
           eligibility_department_id_snapshot,eligibility_valid_until_snapshot,eligibility_evaluated_on,eligibility_effective
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL,
           (SELECT (clock_timestamp() AT TIME ZONE timezone)::date FROM tenant_settings WHERE singleton=true),$5)`,
        [
          roundId,
          fixtureUuid(`candidate:active:${memberCode}`),
          member.id,
          member.displayEnvelope,
          member.eligible,
          index,
          memberCode === "M001" ? 3 : memberCode === "M002" ? 2 : 0,
        ],
      );
    }
  }
}

async function seedHistoricalScenarios(
  client: PoolClient,
  tieCycleId: string,
  declinedCycleId: string,
  officeIds: readonly string[],
  members: ReadonlyMap<string, SeedMember>,
  electors: ReadonlyMap<string, string>,
  key: Buffer,
  keyId: string,
): Promise<void> {
  const [tieOffice, multipleOffice, declinedOffice, elderOffice, linkedOffice] = officeIds;
  if (!tieOffice || !multipleOffice || !declinedOffice || !elderOffice || !linkedOffice) throw new Error("Historical scenario catalog mapping is incomplete");
  await seedClosedRound(client, {
    seedLabel: "historical:tie",
    phase: "DESEMPATE_PENDIENTE",
    cycleId: tieCycleId,
    officeId: tieOffice,
    vacancies: 1,
    maxProposalSelections: 3,
    maxBallotSelections: 1,
    candidateMemberCodes: fixture.scenarios.tie.candidateIds,
    responseSets: [{ kind: "vote", responses: fixture.scenarios.tie.ballots }],
    members,
    electors,
    key,
    keyId,
  });
  await seedClosedRound(client, {
    seedLabel: "historical:multiple-seat-cutoff-tie",
    phase: "DESEMPATE_PENDIENTE",
    cycleId: tieCycleId,
    officeId: multipleOffice,
    vacancies: fixture.scenarios.multipleSeatCutoffTie.seats,
    maxProposalSelections: 3,
    maxBallotSelections: fixture.scenarios.multipleSeatCutoffTie.seats,
    candidateMemberCodes: fixture.scenarios.multipleSeatCutoffTie.candidateIds,
    responseSets: [{ kind: "vote", responses: fixture.scenarios.multipleSeatCutoffTie.ballots }],
    members,
    electors,
    key,
    keyId,
  });

  const declinedVacancy = await ensureHistoricalVacancy(client, declinedCycleId, declinedOffice, "recommended", "declined");
  const declinedMember = members.get("M045");
  if (!declinedMember) throw new Error("Historical declined member is missing");
  const declinedAssignmentId = fixtureUuid("assignment:historical-declined");
  const declinedEnvelope = sealAesGcmJson(
    { decision: "DECLINED", synthetic: true },
    key,
    keyId,
    { tenantId: DEMO_TENANT_ID, assignmentId: declinedAssignmentId, purpose: "assignment-consent", schemaVersion: 1 },
  );
  const declinedEvidence = await seedAssignmentEvidence(client, declinedMember, declinedOffice);
  await client.query(
    `INSERT INTO assignments(id,vacancy_id,member_id,state,effective,consent_status,consent_envelope,independent,member_snapshot,office_snapshot,cycle_id,office_id)
     VALUES ($1,$2,$3,'DECLINADA',false,'DECLINED',$4,true,$5,$6,$7,$8)
     ON CONFLICT(id) DO UPDATE SET state='DECLINADA',effective=false,consent_status='DECLINED',
       consent_envelope=EXCLUDED.consent_envelope,member_snapshot=EXCLUDED.member_snapshot,office_snapshot=EXCLUDED.office_snapshot,
       cycle_id=EXCLUDED.cycle_id,office_id=EXCLUDED.office_id`,
    [declinedAssignmentId, declinedVacancy, declinedMember.id, declinedEnvelope,
      declinedEvidence.memberSnapshot, declinedEvidence.officeSnapshot, declinedCycleId, declinedOffice],
  );

  const elderMember = members.get("M020");
  if (!elderMember) throw new Error("First-elder scenario member is missing");
  const baseVacancy = await ensureHistoricalVacancy(client, tieCycleId, elderOffice, "accepted", "elder-base");
  const linkedVacancy = await ensureHistoricalVacancy(client, tieCycleId, linkedOffice, "accepted", "first-elder-linked");
  const baseAssignmentId = fixtureUuid("assignment:elder-base");
  const linkedAssignmentId = fixtureUuid("assignment:first-elder-linked");
  const baseEvidence = await seedAssignmentEvidence(client, elderMember, elderOffice);
  const linkedEvidence = await seedAssignmentEvidence(client, elderMember, linkedOffice);
  await client.query(
    `INSERT INTO assignments(id,vacancy_id,member_id,state,effective,consent_status,independent,member_snapshot,office_snapshot,cycle_id,office_id)
     VALUES ($1,$2,$3,'FINALIZADA',false,'ACCEPTED',true,$4,$5,$6,$7)
     ON CONFLICT(id) DO UPDATE SET state='FINALIZADA',effective=false,independent=true,
       linked_to_assignment_id=NULL,member_snapshot=EXCLUDED.member_snapshot,office_snapshot=EXCLUDED.office_snapshot,
       cycle_id=EXCLUDED.cycle_id,office_id=EXCLUDED.office_id`,
    [baseAssignmentId, baseVacancy, elderMember.id,
      baseEvidence.memberSnapshot, baseEvidence.officeSnapshot, tieCycleId, elderOffice],
  );
  await client.query(
    `INSERT INTO assignments(id,vacancy_id,member_id,state,effective,consent_status,independent,linked_to_assignment_id,member_snapshot,office_snapshot,cycle_id,office_id)
     VALUES ($1,$2,$3,'FINALIZADA',false,'ACCEPTED',false,$4,$5,$6,$7,$8)
     ON CONFLICT(id) DO UPDATE SET state='FINALIZADA',effective=false,independent=false,
       linked_to_assignment_id=EXCLUDED.linked_to_assignment_id,member_snapshot=EXCLUDED.member_snapshot,office_snapshot=EXCLUDED.office_snapshot,
       cycle_id=EXCLUDED.cycle_id,office_id=EXCLUDED.office_id`,
    [linkedAssignmentId, linkedVacancy, elderMember.id, baseAssignmentId,
      linkedEvidence.memberSnapshot, linkedEvidence.officeSnapshot, tieCycleId, linkedOffice],
  );
}

async function ensureHistoricalVacancy(
  client: PoolClient,
  cycleId: string,
  officeId: string,
  status: "recommended" | "accepted",
  label: string,
): Promise<string> {
  await client.query(
    `INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status) VALUES ($1,$2,$3,1,$4)
     ON CONFLICT(cycle_id,office_id,ordinal) DO UPDATE SET status=EXCLUDED.status`,
    [fixtureUuid(`vacancy:historical:${label}`), cycleId, officeId, status],
  );
  const result = await client.query<{ id: string }>("SELECT id FROM vacancies WHERE cycle_id=$1 AND office_id=$2 AND ordinal=1", [cycleId, officeId]);
  const id = result.rows[0]?.id;
  if (!id) throw new Error("Historical vacancy was not persisted");
  return id;
}

async function seedReports(client: PoolClient, cycleId: string): Promise<void> {
  const reports = [
    { seedKey: "cycle-coverage", type: "progress", format: "pdf", filename: "demo-cobertura-ciclo.pdf" },
    { seedKey: "responsibility-load", type: "responsibility_distribution", format: "xlsx", filename: "demo-carga-responsabilidades.xlsx" },
    { seedKey: "participation-summary", type: "committee_participation", format: "csv", filename: "demo-participacion.csv" },
  ] as const;
  for (const report of reports) {
    const reportId = fixtureUuid(`report:${report.seedKey}`);
    const artifactBody = {
      synthetic: true,
      cycleId,
      metrics: report.type === "progress"
        ? { applicable: 40, recommended: 20, accepted: 15, elected: 10 }
        : report.type === "responsibility_distribution"
          ? { independentResponsibilities: 20, uniquePeople: 16, concentrationAlerts: 3 }
          : { frozenElectors: 7, completeReferenceRounds: 20 },
    };
    const snapshotSha256 = `sha256:${createHash("sha256").update(JSON.stringify(artifactBody)).digest("hex")}`;
    // Do not label encrypted JSON as PDF/XLSX/CSV. Historical synthetic
    // placeholders stay visibly expired; the browser can issue a fresh,
    // format-valid E2EE artifact from the display-only snapshot.
    await client.query(
      `INSERT INTO report_versions(
         id,report_type,audience,locale,format,filters,artifact_envelope,artifact_bytes,artifact_sha256,
         ciphertext_sha256,artifact_manifest,plaintext_bytes,filename,media_type,state,
         requested_by_identity_id,ready_at,failed_at,error_code,version
       ) VALUES ($1,$2,'committee','es',$3,$4,NULL,NULL,NULL,NULL,NULL,NULL,$5,$6,'expired',$7,NULL,NULL,NULL,1)
       ON CONFLICT(id) DO UPDATE SET
         report_type=EXCLUDED.report_type,
         audience=EXCLUDED.audience,
         locale=EXCLUDED.locale,
         format=EXCLUDED.format,
         filters=EXCLUDED.filters,
         artifact_envelope=NULL,
         artifact_bytes=NULL,
         artifact_sha256=NULL,
         ciphertext_sha256=NULL,
         artifact_manifest=NULL,
         plaintext_bytes=NULL,
         filename=EXCLUDED.filename,
         media_type=EXCLUDED.media_type,
         state='expired',
         requested_by_identity_id=EXCLUDED.requested_by_identity_id,
         ready_at=NULL,
         failed_at=NULL,
         error_code=NULL`,
      [
        reportId, report.type, report.format, { cycleId, synthetic: true, snapshotSha256 }, report.filename,
        mediaTypeFor(report.format), DEMO_IDENTITY_ID,
      ],
    );
  }
}

async function seedAuditHistory(client: PoolClient, cycleId: string): Promise<boolean> {
  const baselineEvents = [
    {
      id: fixtureUuid("audit:tenant-ready"),
      action: "demo.tenant.ready",
      entityType: "tenant",
      entityId: DEMO_TENANT_ID,
      metadata: { synthetic: true, setupState: "ready", seedVersion: INITIAL_AUDIT_SEED_VERSION },
    },
    {
      id: fixtureUuid("audit:cycle-seeded"),
      action: "demo.cycle.seeded",
      entityType: "cycle",
      entityId: cycleId,
      metadata: { synthetic: true, vacancies: 40, recommended: 20, accepted: 15, elected: 10 },
    },
    {
      id: fixtureUuid("audit:reference-rounds"),
      action: "demo.reference-rounds.seeded",
      entityType: "cycle",
      entityId: cycleId,
      metadata: { synthetic: true, completedRounds: 20, frozenSubmissions: 280 },
    },
  ] as const;
  const repairEvents = [
    {
      id: fixtureUuid("audit:member-envelope-optionals-repaired:v5"),
      action: "demo.member-envelopes.repaired",
      entityType: "tenant",
      entityId: DEMO_TENANT_ID,
      metadata: {
        synthetic: true,
        repairVersion: MEMBER_ENVELOPE_REPAIR_VERSION,
        affectedMembers: fixture.members.length,
        optionalNullsOmitted: true,
      },
    },
  ] as const;
  const events = [...baselineEvents, ...repairEvents];

  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('tenant_audit_chain', 0))");
  const chain = await client.query<TenantAuditEventDatabaseRow>(
    `SELECT id::text,sequence::text,occurred_at,hash_version,actor_identity_id,action,entity_type,entity_id,result,
            request_id,metadata,previous_hash,event_hash
       FROM audit_events ORDER BY audit_events.sequence`,
  );
  if (chain.rows.length > 0) {
    const verification = verifyTenantAuditEventChain(chain.rows.map(tenantAuditEventRecordFromRow));
    if (!verification.valid) {
      throw new Error(`Existing demo audit chain is invalid (${verification.code}); refusing to append seed events`);
    }
  }

  const existingSeedEvents = new Map(chain.rows
    .filter((event) => events.some((seedEvent) => seedEvent.id === event.id))
    .map((event) => [event.id, event]));
  const existingBaselineCount = baselineEvents.filter((event) => existingSeedEvents.has(event.id)).length;
  const existingRepairCount = repairEvents.filter((event) => existingSeedEvents.has(event.id)).length;
  if (existingBaselineCount > 0 && existingBaselineCount !== baselineEvents.length) {
    throw new Error("Partial demo audit baseline detected; refusing an ambiguous repair");
  }
  if (existingRepairCount > 0 && existingBaselineCount !== baselineEvents.length) {
    throw new Error("Demo repair evidence exists without its complete audit baseline; refusing all writes");
  }
  for (const event of events) {
    const stored = existingSeedEvents.get(event.id);
    if (stored && (
      stored.actor_identity_id !== DEMO_IDENTITY_ID
      || stored.action !== event.action
      || stored.entity_type !== event.entityType
      || stored.entity_id !== event.entityId
      || stored.result !== "success"
      || stored.request_id !== null
      || !isDeepStrictEqual(stored.metadata, event.metadata)
    )) {
      throw new Error("Existing demo audit seed does not match the deterministic fixture; refusing all writes");
    }
  }

  const pendingEvents = existingBaselineCount === 0
    ? events
    : repairEvents.filter((event) => !existingSeedEvents.has(event.id));
  if (pendingEvents.length === 0) return false;

  let previousHash: string | null = chain.rows.at(-1)?.event_hash ?? null;
  for (const event of pendingEvents) {
    const eventHash = computeTenantAuditEventHash({
      actorIdentityId: DEMO_IDENTITY_ID,
      previousHash,
      action: event.action,
      entityType: event.entityType,
      entityId: event.entityId,
      result: "success",
      metadata: event.metadata,
      requestId: null,
    });
    await client.query(
      `INSERT INTO audit_events(
         id,actor_identity_id,action,entity_type,entity_id,result,request_id,
         metadata,previous_hash,event_hash
       ) VALUES ($1,$2,$3,$4,$5,'success',NULL,$6,$7,$8)`,
      [event.id, DEMO_IDENTITY_ID, event.action, event.entityType, event.entityId, event.metadata, previousHash, eventHash],
    );
    previousHash = eventHash;
  }
  return true;
}

async function ensureDemoAuditHistory(pool: Pool): Promise<boolean> {
  const cycle = await pool.query<{ id: string }>(
    "SELECT id FROM election_cycles WHERE status='active' ORDER BY created_at DESC LIMIT 1",
  );
  const cycleId = cycle.rows[0]?.id;
  if (!cycleId) throw new Error("Complete demo fixture has no active cycle; refusing audit history repair");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const changed = await seedAuditHistory(client, cycleId);
    await client.query("COMMIT");
    return changed;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function isCompleteDemoFixture(
  pool: Pool,
  allowAdditionalMembers = false,
): Promise<boolean> {
  const result = await pool.query<{
    members: number;
    eligible: number;
    vacancies: number;
    recommended: number;
    accepted: number;
    elected: number;
    responsibilities: number;
    responsible_people: number;
    cycles: number;
    reference_rounds: number;
    seeded_submissions: number;
    split_members: number;
    contact_free_members: number;
    split_cycle_snapshots: number;
    missing_candidate_displays: number;
    assignment_display_snapshots: number;
    expired_seed_reports: number;
  }>(`
    WITH current_cycle AS (SELECT id FROM election_cycles WHERE status='active' LIMIT 1)
    SELECT
      (SELECT count(*)::int FROM members) AS members,
      (SELECT count(*)::int FROM members WHERE eligibility_status='eligible' AND available) AS eligible,
      (SELECT count(*)::int FROM vacancies WHERE cycle_id=(SELECT id FROM current_cycle)) AS vacancies,
      (SELECT count(*)::int FROM vacancies WHERE cycle_id=(SELECT id FROM current_cycle) AND status IN ('recommended','accepted','elected')) AS recommended,
      (SELECT count(*)::int FROM vacancies WHERE cycle_id=(SELECT id FROM current_cycle) AND status IN ('accepted','elected')) AS accepted,
      (SELECT count(*)::int FROM vacancies WHERE cycle_id=(SELECT id FROM current_cycle) AND status='elected') AS elected,
      (SELECT count(*)::int FROM assignments a JOIN vacancies v ON v.id=a.vacancy_id
        WHERE v.cycle_id=(SELECT id FROM current_cycle) AND a.effective AND a.independent) AS responsibilities,
      (SELECT count(DISTINCT a.member_id)::int FROM assignments a JOIN vacancies v ON v.id=a.vacancy_id
        WHERE v.cycle_id=(SELECT id FROM current_cycle) AND a.effective AND a.independent) AS responsible_people,
      (SELECT count(*)::int FROM election_cycles) AS cycles,
      (SELECT count(*)::int FROM rounds WHERE cycle_id=(SELECT id FROM current_cycle) AND phase='CERRADO') AS reference_rounds,
      (SELECT count(*)::int FROM encrypted_submissions) AS seeded_submissions,
      (SELECT count(*)::int FROM members
        WHERE NOT profile_migration_required AND profile_envelope IS NULL
          AND display_envelope IS NOT NULL AND display_content_hash IS NOT NULL) AS split_members,
      (SELECT count(*)::int FROM members WHERE contact_envelope IS NULL AND contact_content_hash IS NULL) AS contact_free_members,
      (SELECT count(*)::int FROM cycle_member_snapshots
        WHERE cycle_id=(SELECT id FROM current_cycle) AND profile_envelope IS NULL
          AND display_envelope IS NOT NULL AND NOT legacy_profile_redacted) AS split_cycle_snapshots,
      (SELECT count(*)::int FROM candidate_snapshots WHERE display_envelope IS NULL) AS missing_candidate_displays,
      (SELECT count(*)::int FROM assignments a JOIN vacancies v ON v.id=a.vacancy_id
        WHERE v.cycle_id=(SELECT id FROM current_cycle) AND a.effective AND a.independent
          AND a.member_snapshot->'displayEnvelope' IS NOT NULL
          AND a.member_snapshot ? 'memberVersion'
          AND a.member_snapshot->'eligibility' ?& ARRAY['departmentRestriction','validUntil','evaluatedOn','effective']
          AND a.office_snapshot ?& ARRAY['officeId','departmentId','canonicalCode','names']
          AND NOT (a.member_snapshot ?| ARRAY['profileEnvelope','contactEnvelope'])) AS assignment_display_snapshots,
      (SELECT count(*)::int FROM report_versions
        WHERE id=ANY(ARRAY[
          '${fixtureUuid("report:cycle-coverage")}'::uuid,
          '${fixtureUuid("report:responsibility-load")}'::uuid,
          '${fixtureUuid("report:participation-summary")}'::uuid
        ]) AND state='expired' AND artifact_envelope IS NULL AND artifact_bytes IS NULL
          AND artifact_sha256 IS NULL AND ciphertext_sha256 IS NULL
          AND artifact_manifest IS NULL AND plaintext_bytes IS NULL) AS expired_seed_reports
  `);
  const row = result.rows[0];
  const memberCountMatches = row && (allowAdditionalMembers ? row.members >= 180 : row.members === 180);
  const eligibleCountMatches = row && (allowAdditionalMembers ? row.eligible >= 150 : row.eligible === 150);
  const splitMemberCountMatches = row && (allowAdditionalMembers ? row.split_members >= 180 : row.split_members === 180);
  const contactFreeCountMatches = row && (allowAdditionalMembers ? row.contact_free_members >= 180 : row.contact_free_members === 180);
  const snapshotCountMatches = row && (allowAdditionalMembers ? row.split_cycle_snapshots >= 180 : row.split_cycle_snapshots === 180);
  return Boolean(row
    && memberCountMatches
    && eligibleCountMatches
    && row.vacancies === 40
    && row.recommended === 20
    && row.accepted === 15
    && row.elected === 10
    && row.responsibilities === 20
    && row.responsible_people === 16
    && row.cycles >= 3
    && row.reference_rounds >= 20
    && row.seeded_submissions >= 294
    && splitMemberCountMatches
    && contactFreeCountMatches
    && snapshotCountMatches
    && row.missing_candidate_displays === 0
    && row.assignment_display_snapshots === 20
    && row.expired_seed_reports === 3);
}

async function prepareDemoAccessFile(
  controlPool: Pool,
  stored: DemoAccessFile | null,
  configuredAdministratorPassword: string | undefined,
): Promise<{ readonly access: DemoAccessFileV2; readonly fileChanged: boolean }> {
  const credentials = {} as Record<DemoAccessProfileCode, {
    password: string;
    totpEnrollmentUri: string;
  }>;

  for (const code of DEMO_ACCESS_PROFILE_CODES) {
    const storedProfile = stored ? accessProfile(stored, code) : null;
    if (storedProfile) {
      if (
        code === "administrator"
        && configuredAdministratorPassword
        && configuredAdministratorPassword !== storedProfile.password
      ) {
        throw new Error("Configured Demo administrator password does not match the protected access file");
      }
      credentials[code] = {
        password: storedProfile.password,
        totpEnrollmentUri: storedProfile.totpEnrollmentUri,
      };
      continue;
    }

    const definition = DEMO_ACCESS_PROFILE_DEFINITIONS[code];
    const identity = await controlPool.query<{
      password_hash: string;
      totp_secret_ciphertext: string | null;
    }>(
      "SELECT password_hash,totp_secret_ciphertext FROM platform_identities WHERE id=$1",
      [definition.identityId],
    );
    if (identity.rowCount === 1) {
      if (code !== "administrator" || !configuredAdministratorPassword) {
        throw new Error(`Demo ${code} identity exists without recoverable protected access material`);
      }
      const row = identity.rows[0]!;
      if (!row.totp_secret_ciphertext) {
        throw new Error("Existing Demo administrator has no enrolled TOTP secret");
      }
      credentials[code] = {
        password: configuredAdministratorPassword,
        totpEnrollmentUri: createDemoTotp(definition.email, decryptServerSecret(
          row.totp_secret_ciphertext,
          authEncryptionKey,
        )).toString(),
      };
      continue;
    }
    credentials[code] = createDemoCredential(
      definition.email,
      code === "administrator" ? configuredAdministratorPassword : undefined,
    );
  }

  return {
    access: buildDemoAccessFileV2(credentials),
    fileChanged: stored?.version !== 2,
  };
}

async function ensureDemoControlProfiles(
  controlPool: Pool,
  access: DemoAccessFileV2,
): Promise<boolean> {
  let changed = false;
  await controlPool.query("BEGIN");
  try {
    for (const code of DEMO_ACCESS_PROFILE_CODES) {
      const profile = access.profiles[code];
      const normalizedEmail = profile.email.normalize("NFKC").toLocaleLowerCase("en-US");
      const existing = await controlPool.query<{
        email: string;
        normalized_email: string;
        display_name: string;
        password_hash: string;
        mfa_enabled: boolean;
        mfa_required: boolean;
        totp_secret_ciphertext: string | null;
        status: string;
      }>(
        `SELECT email,normalized_email,display_name,password_hash,mfa_enabled,mfa_required,
                totp_secret_ciphertext,status
           FROM platform_identities WHERE id=$1 FOR UPDATE`,
        [profile.identityId],
      );
      const identity = existing.rows[0];
      if (identity) {
        const passwordMatches = await verify(identity.password_hash, profile.password).catch(() => false);
        const storedTotpSecret = identity.totp_secret_ciphertext
          ? decryptServerSecret(identity.totp_secret_ciphertext, authEncryptionKey)
          : null;
        if (
          identity.email !== profile.email
          || identity.normalized_email !== normalizedEmail
          || identity.display_name !== profile.displayName
          || identity.status !== "active"
          || !identity.mfa_enabled
          || !passwordMatches
          || storedTotpSecret !== totpSecretFromUri(profile.totpEnrollmentUri)
        ) {
          throw new Error(`Existing Demo ${code} identity does not match its protected access profile`);
        }
        if (!identity.mfa_required) {
          await controlPool.query(
            "UPDATE platform_identities SET mfa_required=true,updated_at=clock_timestamp() WHERE id=$1",
            [profile.identityId],
          );
          changed = true;
        }
      } else {
        const passwordHash = await hash(profile.password, {
          type: 2,
          memoryCost: 65_536,
          timeCost: 3,
          parallelism: 1,
        });
        const encryptedTotp = encryptServerSecret(
          totpSecretFromUri(profile.totpEnrollmentUri),
          authEncryptionKey,
        );
        await controlPool.query(
          `INSERT INTO platform_identities(
             id,email,normalized_email,display_name,password_hash,mfa_enabled,mfa_required,
             totp_secret_ciphertext,mfa_enrolled_at,status
           ) VALUES ($1,$2,$3,$4,$5,true,true,$6,clock_timestamp(),'active')`,
          [profile.identityId, profile.email, normalizedEmail, profile.displayName, passwordHash, encryptedTotp],
        );
        changed = true;
      }

      const foreignMembership = await controlPool.query(
        `SELECT 1 FROM tenant_memberships
          WHERE identity_id=$1 AND tenant_id<>$2 AND status='active' LIMIT 1`,
        [profile.identityId, DEMO_TENANT_ID],
      );
      if (foreignMembership.rowCount !== 0) {
        throw new Error(`Demo ${code} identity is unexpectedly active in another tenant`);
      }
      const membership = await controlPool.query(
        `INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default)
         VALUES ($1,$2,'active',true)
         ON CONFLICT(tenant_id,identity_id) DO UPDATE SET
           status='active',is_default=true,revoked_at=NULL
         WHERE tenant_memberships.status<>'active'
            OR NOT tenant_memberships.is_default
            OR tenant_memberships.revoked_at IS NOT NULL`,
        [DEMO_TENANT_ID, profile.identityId],
      );
      changed = changed || membership.rowCount === 1;
    }
    await controlPool.query("COMMIT");
    return changed;
  } catch (error) {
    await controlPool.query("ROLLBACK").catch(() => undefined);
    throw error;
  }
}

async function ensureDemoTenantProfiles(
  pool: Pool,
  access: DemoAccessFileV2,
  contentKey: Buffer,
  tenantKeyId: string,
): Promise<boolean> {
  const client = await pool.connect();
  let changed = false;
  try {
    await client.query("BEGIN");
    const requiredRoleCodes = [...new Set(DEMO_ACCESS_PROFILE_CODES.flatMap(
      (code) => [...DEMO_ACCESS_PROFILE_DEFINITIONS[code].roleCodes],
    ))].sort();
    const roles = await client.query<{ id: string; code: string }>(
      "SELECT id::text,code FROM roles WHERE system_role AND code=ANY($1::text[]) ORDER BY code",
      [requiredRoleCodes],
    );
    if (roles.rowCount !== requiredRoleCodes.length) {
      throw new Error("One or more required Demo system roles are unavailable");
    }
    const roleIds = new Map(roles.rows.map((role) => [role.code, role.id]));

    // Establish every replacement binding first. Revoking the legacy tally
    // binding from the administrator later in this same transaction can never
    // leave the Demo without its dedicated custodian.
    for (const code of DEMO_ACCESS_PROFILE_CODES) {
      const profile = access.profiles[code];
      for (const roleCode of profile.roleCodes) {
        const roleId = roleIds.get(roleCode);
        if (!roleId) throw new Error(`Demo role is unavailable: ${roleCode}`);
        const binding = await client.query(
          `INSERT INTO role_bindings(identity_id,role_id,granted_by_identity_id)
           VALUES ($1,$2,$3)
           ON CONFLICT(identity_id,role_id) DO UPDATE SET
             granted_at=clock_timestamp(),granted_by_identity_id=EXCLUDED.granted_by_identity_id,
             revoked_at=NULL,version=role_bindings.version+1,updated_at=clock_timestamp()
           WHERE role_bindings.revoked_at IS NOT NULL`,
          [
            profile.identityId,
            roleId,
            code === "administrator" ? null : DEMO_IDENTITY_ID,
          ],
        );
        changed = changed || binding.rowCount === 1;
      }
    }
    for (const code of DEMO_ACCESS_PROFILE_CODES) {
      const profile = access.profiles[code];
      const revoked = await client.query(
        `UPDATE role_bindings binding
            SET revoked_at=clock_timestamp(),version=binding.version+1,updated_at=clock_timestamp()
           FROM roles role
          WHERE binding.role_id=role.id
            AND binding.identity_id=$1
            AND binding.revoked_at IS NULL
            AND role.system_role
            AND NOT (role.code=ANY($2::text[]))`,
        [profile.identityId, profile.roleCodes],
      );
      changed = changed || (revoked.rowCount ?? 0) > 0;
    }

    for (const code of DEMO_ACCESS_PROFILE_CODES) {
      const profile = access.profiles[code];
      const activeGrants = await client.query<{
        tenant_key_id: string;
        kdf: WrappedTenantKey["kdf"];
        wrap: WrappedTenantKey["wrap"];
      }>(
        `SELECT tenant_key_id,kdf,wrap FROM device_key_grants
          WHERE identity_id=$1 AND status='active'
          ORDER BY created_at DESC,id DESC`,
        [profile.identityId],
      );
      if (!profile.tenantContentKey) {
        if (activeGrants.rowCount !== 0) {
          throw new Error(`Demo ${code} must not receive the general tenant content key`);
        }
        continue;
      }
      if (activeGrants.rowCount === 0) {
        const deviceId = randomUUID();
        const wrapped = wrapTenantKeyWithPassword(contentKey, profile.password, {
          identityId: profile.identityId,
          purpose: "tenant-key-wrap",
          tenantId: DEMO_TENANT_ID,
          tenantKeyId,
          version: 1,
        });
        await client.query(
          `INSERT INTO device_key_grants(identity_id,device_id,version,tenant_key_id,kdf,wrap)
           VALUES ($1,$2,1,$3,$4,$5)`,
          [profile.identityId, deviceId, tenantKeyId, wrapped.kdf, wrapped.wrap],
        );
        changed = true;
        continue;
      }
      if (activeGrants.rowCount !== 1) {
        throw new Error(`Demo ${code} has an ambiguous active tenant content-key grant set`);
      }
      const grant = activeGrants.rows[0]!;
      const expectedContext = {
        identityId: profile.identityId,
        purpose: "tenant-key-wrap",
        tenantId: DEMO_TENANT_ID,
        tenantKeyId,
        version: 1,
      };
      const actualContext: unknown = JSON.parse(Buffer.from(grant.wrap.aad, "base64url").toString("utf8"));
      const unwrapped = unwrapTenantKeyWithPassword({ kdf: grant.kdf, wrap: grant.wrap }, profile.password);
      try {
        if (
          grant.tenant_key_id !== tenantKeyId
          || !isDeepStrictEqual(actualContext, expectedContext)
          || unwrapped.byteLength !== contentKey.byteLength
          || !timingSafeEqual(unwrapped, contentKey)
        ) {
          throw new Error(`Demo ${code} tenant content-key grant is inconsistent`);
        }
      } finally {
        unwrapped.fill(0);
      }
    }

    const publicManifest = demoAccessPublicManifest();
    const accessFixtureHash = `sha256:${createHash("sha256").update(JSON.stringify(publicManifest)).digest("hex")}`;
    const metadata = {
      profiles: publicManifest.map(({ profile, roleCodes, tenantContentKey }) => ({
        profile,
        roleCodes,
        tenantContentKey,
      })),
    };
    const manifestInsert = await client.query(
      `INSERT INTO seed_manifests(seed_id,version,fixture_hash,metadata)
       VALUES ($1,$2,$3,$4) ON CONFLICT(seed_id) DO NOTHING`,
      [ACCESS_SEED_ID, ACCESS_SEED_VERSION, accessFixtureHash, metadata],
    );
    changed = changed || manifestInsert.rowCount === 1;
    const manifest = await client.query<{ version: number; fixture_hash: string; metadata: unknown }>(
      "SELECT version,fixture_hash,metadata FROM seed_manifests WHERE seed_id=$1",
      [ACCESS_SEED_ID],
    );
    const storedManifest = manifest.rows[0];
    if (
      !storedManifest
      || storedManifest.version !== ACCESS_SEED_VERSION
      || storedManifest.fixture_hash !== accessFixtureHash
      || !isDeepStrictEqual(storedManifest.metadata, metadata)
    ) {
      throw new Error("Existing Demo access-profile manifest does not match the fixed non-secret definition");
    }
    await client.query("COMMIT");
    return changed;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function createDemoCredential(
  email: string,
  configuredPassword?: string,
): { readonly password: string; readonly totpEnrollmentUri: string } {
  const password = configuredPassword ?? randomBytes(24).toString("base64url");
  if (password.length < 16) throw new Error("Demo passwords must contain at least 16 characters");
  const secret = new OTPAuth.Secret({ size: 20 });
  return { password, totpEnrollmentUri: createDemoTotp(email, secret.base32).toString() };
}

function createDemoTotp(email: string, secret: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    issuer: "Nombramientos Adventistas — Demostración",
    label: email,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
}

function totpSecretFromUri(enrollmentUri: string): string {
  const secret = new URL(enrollmentUri).searchParams.get("secret");
  if (!secret) throw new Error("Demo access material is missing its TOTP secret");
  return secret;
}

function hashEnvelope(envelope: EncryptedEnvelope): string {
  const canonicalEnvelope = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  return `sha256:${createHash("sha256").update(canonicalEnvelope, "utf8").digest("hex")}`;
}

function fixtureUuid(label: string): string {
  const raw = createHash("sha256").update(`nombramientos-demo:${label}`).digest("hex").slice(0, 32).split("");
  raw[12] = "4";
  raw[16] = "8";
  const hex = raw.join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function mediaTypeFor(format: "pdf" | "xlsx" | "csv"): string {
  if (format === "pdf") return "application/pdf";
  if (format === "xlsx") return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
  return "text/csv; charset=utf-8";
}

async function readStoredDemoAccess(root: string): Promise<DemoAccessFile | null> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path.join(root, ".local", "demo-access.json"), "utf8"));
    return parseDemoAccessFile(parsed);
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") return null;
    throw new Error("The protected Demo access file is malformed and will not be replaced automatically", { cause: error });
  }
}

async function writeDemoAccessFile(root: string, access: DemoAccessFileV2): Promise<void> {
  const localRoot = path.join(root, ".local");
  const destination = path.join(localRoot, "demo-access.json");
  const temporary = `${destination}.${process.pid}.tmp`;
  await mkdir(localRoot, { recursive: true });
  try {
    await writeFile(temporary, `${JSON.stringify(access)}\n`, { encoding: "utf8", mode: 0o600 });
    await chmod(temporary, 0o600).catch(() => undefined);
    await rename(temporary, destination);
    await chmod(destination, 0o600).catch(() => undefined);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}
