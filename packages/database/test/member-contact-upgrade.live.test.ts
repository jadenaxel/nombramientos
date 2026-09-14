import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/migrations.js";
import { TenantStore } from "../src/tenant-store.js";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReach(adminUrl) : false;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";

if (requireLive && !reachable) {
  throw new Error("Member-contact upgrade test requires PostgreSQL 18 on isolated loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

live("member display/contact migration 025 upgrade", () => {
  it("quarantines the live legacy profile and physically redacts every derived combined envelope", async () => {
    if (!adminUrl) throw new Error("Local administrator URL is unavailable");
    const suffix = randomUUID().replaceAll("-", "");
    const databaseName = `nom_t_${suffix}`;
    const admin = new Pool({ connectionString: adminUrl, max: 1, connectionTimeoutMillis: 5_000 });
    let migrationDirectory: string | undefined;
    let tenant: Pool | undefined;
    await runWithCleanup(async () => {
      migrationDirectory = await mkdtemp(path.join(os.tmpdir(), "nom-member-contact-upgrade-"));
      await createDatabase(admin, databaseName);
      const tenantUrl = new URL(adminUrl);
      tenantUrl.pathname = `/${databaseName}`;
      tenant = new Pool({ connectionString: tenantUrl.toString(), max: 1, connectionTimeoutMillis: 5_000 });

      const fullMigrationDirectory = path.join(packageRoot, "migrations", "tenant");
      for (const file of await readdir(fullMigrationDirectory)) {
        if (/^\d+_.+\.sql$/u.test(file) && file.localeCompare("025_member_contact_boundary.sql") < 0) {
          await copyFile(path.join(fullMigrationDirectory, file), path.join(migrationDirectory, file));
        }
      }
      const preBoundary = await runMigrations(tenant, { scope: "tenant", directory: migrationDirectory });
      expect(preBoundary.at(-1)).toBe("024_session_title_envelopes.sql");

      const tenantId = randomUUID();
      const memberId = randomUUID();
      const cycleId = randomUUID();
      const departmentId = randomUUID();
      const officeId = randomUUID();
      const vacancyId = randomUUID();
      const assignmentId = randomUUID();
      const roundId = randomUUID();
      const reportId = randomUUID();
      const actorIdentityId = randomUUID();
      const legacyCiphertext = randomBytes(40).toString("base64url");
      const legacyEnvelope = {
        algorithm: "AES-256-GCM",
        keyId: `legacy-key-${suffix}`,
        nonce: randomBytes(12).toString("base64url"),
        ciphertext: legacyCiphertext,
        aad: Buffer.from(JSON.stringify({ tenantId, memberId, purpose: "member-profile", schemaVersion: 1 })).toString("base64url"),
      } as const;

      await tenant.query(
        `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state)
         VALUES ($1,'Upgrade scratch','real','America/La_Paz','es','ready')`,
        [tenantId],
      );
      await tenant.query(
        `INSERT INTO members(id,stable_code,profile_envelope,eligibility_status,available)
         VALUES ($1,'UPGRADE-LEGACY',$2,'eligible',true)`,
        [memberId, legacyEnvelope],
      );
      await tenant.query(
        `INSERT INTO election_cycles(
           id,name,status,locale,timezone,term_start,term_end,normative_version,created_by_identity_id
         ) VALUES ($1,'Upgrade cycle','active','es','America/La_Paz','2044-01-01','2044-12-31','upgrade-v1',$2)`,
        [cycleId, actorIdentityId],
      );
      await tenant.query(
        `INSERT INTO cycle_member_snapshots(
           cycle_id,member_id,member_version,eligibility_status,available,profile_envelope
         ) VALUES ($1,$2,1,'eligible',true,$3)`,
        [cycleId, memberId, legacyEnvelope],
      );
      await tenant.query(
        "INSERT INTO departments(id,canonical_code,names) VALUES ($1,'UPGRADE_DEPT',$2)",
        [departmentId, { es: "Upgrade", en: "Upgrade", fr: "Upgrade" }],
      );
      await tenant.query(
        `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality)
         VALUES ($1,$2,'UPGRADE_OFFICE',$3,'church_election',1)`,
        [officeId, departmentId, { es: "Upgrade", en: "Upgrade", fr: "Upgrade" }],
      );
      await tenant.query(
        "INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status) VALUES ($1,$2,$3,1,'recommended')",
        [vacancyId, cycleId, officeId],
      );
      await tenant.query(
        `INSERT INTO assignments(
           id,vacancy_id,member_id,state,effective,independent,cycle_id,office_id,member_snapshot
         ) VALUES ($1,$2,$3,'PROPUESTA_INTERNA',true,true,$4,$5,$6)`,
        [assignmentId, vacancyId, memberId, cycleId, officeId, { memberId, displayEnvelope: legacyEnvelope }],
      );
      await tenant.query(
        `INSERT INTO rounds(
           id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,candidate_set_hash,rules_hash,
           max_proposal_selections,max_ballot_selections,workflow_stage
         ) VALUES ($1,$2,$3,'CERRADO','vote',1,1,$4,$5,1,1,'ballot')`,
        [roundId, cycleId, officeId, `sha256:${"1".repeat(64)}`, `sha256:${"2".repeat(64)}`],
      );
      await tenant.query(
        `INSERT INTO candidate_snapshots(
           round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count
         ) VALUES ($1,$2,$3,$4,true,1,0)`,
        [roundId, randomUUID(), memberId, legacyEnvelope],
      );
      await tenant.query(
        `INSERT INTO report_versions(
           id,report_type,audience,locale,format,filters,artifact_envelope,state,requested_by_identity_id,
           filename,media_type
         ) VALUES ($1,'cycle_summary','committee','es','pdf','{}'::jsonb,$2,'pending',$3,'legacy.pdf','application/pdf')`,
        [reportId, legacyEnvelope, actorIdentityId],
      );

      const applied = await runMigrations(tenant, {
        scope: "tenant",
        directory: fullMigrationDirectory,
      });
      expect(applied).toContain("025_member_contact_boundary.sql");

      const member = await tenant.query<{
        profile_envelope: typeof legacyEnvelope | null;
        display_envelope: unknown;
        contact_envelope: unknown;
        profile_migration_required: boolean;
      }>(
        `SELECT profile_envelope,display_envelope,contact_envelope,profile_migration_required
           FROM members WHERE id=$1`,
        [memberId],
      );
      expect(member.rows[0]).toMatchObject({
        profile_envelope: legacyEnvelope,
        display_envelope: null,
        contact_envelope: null,
        profile_migration_required: true,
      });

      const client = await tenant.connect();
      try {
        const projection = await new TenantStore(client).listMembers(10, undefined, false, false, false);
        expect(JSON.stringify(projection)).not.toContain(legacyCiphertext);
        expect(projection).toMatchObject({
          items: [expect.objectContaining({ displayEnvelope: null, profileMigrationRequired: true })],
        });
      } finally {
        client.release();
      }

      const derived = await tenant.query<{
        cycle_profile: unknown; cycle_display: unknown; cycle_redacted: boolean;
        candidate_display: unknown; assignment_snapshot: Record<string, unknown>;
        report_state: string; report_artifact: unknown;
      }>(
        `SELECT snapshot.profile_envelope AS cycle_profile,snapshot.display_envelope AS cycle_display,
                snapshot.legacy_profile_redacted AS cycle_redacted,
                candidate.display_envelope AS candidate_display,
                assignment.member_snapshot AS assignment_snapshot,
                report.state AS report_state,report.artifact_envelope AS report_artifact
           FROM cycle_member_snapshots snapshot
           JOIN candidate_snapshots candidate ON candidate.round_id=$2
           JOIN assignments assignment ON assignment.id=$3
           JOIN report_versions report ON report.id=$4
          WHERE snapshot.cycle_id=$1 AND snapshot.member_id=$5`,
        [cycleId, roundId, assignmentId, reportId, memberId],
      );
      expect(derived.rows[0]).toMatchObject({
        cycle_profile: null,
        cycle_display: null,
        cycle_redacted: true,
        candidate_display: null,
        assignment_snapshot: { memberId, displayEnvelopeRedacted: true },
        report_state: "expired",
        report_artifact: null,
      });
      expect(JSON.stringify(derived.rows[0])).not.toContain(legacyCiphertext);

      const grants = await tenant.query<{ role_code: string; grants: number }>(
        `SELECT role.code AS role_code,count(*)::int AS grants
           FROM role_permissions granted JOIN roles role ON role.id=granted.role_id
          WHERE granted.permission_code IN ('member.contact.read','member.contact.manage')
          GROUP BY role.code ORDER BY role.code`,
      );
      expect(grants.rows).toEqual([{ role_code: "CHURCH_ADMIN", grants: 2 }]);

      await expect(tenant.query(
        "INSERT INTO members(id,stable_code,eligibility_status,available) VALUES ($1,'INVALID-NO-DISPLAY','eligible',true)",
        [randomUUID()],
      )).rejects.toMatchObject({ code: "23514" });

      const displayEnvelope = { ...legacyEnvelope, aad: Buffer.from(JSON.stringify({ tenantId, memberId, purpose: "member-display", schemaVersion: 1 })).toString("base64url") };
      await tenant.query(
        `UPDATE members SET profile_envelope=NULL,display_envelope=$2,display_content_hash=$3,
                contact_envelope=NULL,contact_content_hash=NULL,profile_migration_required=false
          WHERE id=$1`,
        [memberId, displayEnvelope, `sha256:${"a".repeat(64)}`],
      );
      const resolved = await tenant.query(
        `SELECT profile_envelope,display_envelope,contact_envelope,profile_migration_required
           FROM members WHERE id=$1`,
        [memberId],
      );
      expect(resolved.rows[0]).toMatchObject({
        profile_envelope: null,
        display_envelope: displayEnvelope,
        contact_envelope: null,
        profile_migration_required: false,
      });
    }, () => cleanupMemberContactUpgradeResources(admin, tenant, databaseName, migrationDirectory),
    "Member-contact upgrade live test");
  }, 60_000);
});

function discoverAdminUrl(): string | undefined {
  if (!existsSync(installFile)) return undefined;
  const value = JSON.parse(readFileSync(installFile, "utf8")) as { DATABASE_ADMIN_URL?: string };
  if (!value.DATABASE_ADMIN_URL) return undefined;
  try {
    return assertWorkspacePostgresUrl(value.DATABASE_ADMIN_URL, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReach(connectionString: string): Promise<boolean> {
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_500 });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === 55_432;
  } catch {
    return false;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

async function createDatabase(admin: Pool, databaseName: string): Promise<void> {
  assertMemberContactUpgradeDatabaseName(databaseName);
  const formatted = await admin.query<{ sql: string }>(
    "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L',$1::text,'UTF8') AS sql",
    [databaseName],
  );
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the scratch database statement");
  await admin.query(sql);
}

async function cleanupMemberContactUpgradeResources(
  admin: Pool,
  tenant: Pool | undefined,
  databaseName: string,
  migrationDirectory: string | undefined,
): Promise<void> {
  const failures: Error[] = [];
  try {
    await cleanupTemporaryDatabases({
      maintenancePool: admin,
      targets: [{
        databaseName,
        databasePools: tenant ? [tenant] : [],
        assertSafeDatabaseName: assertMemberContactUpgradeDatabaseName,
      }],
      label: "Temporary member-contact upgrade database",
    });
  } catch (error) {
    failures.push(new Error("Member-contact upgrade cleanup failed for its temporary database", { cause: error }));
  }
  if (migrationDirectory) {
    try {
      await rm(migrationDirectory, { recursive: true, force: true });
    } catch (error) {
      failures.push(new Error("Member-contact upgrade cleanup failed for its temporary migration directory", { cause: error }));
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(failures, `Member-contact upgrade cleanup failed closed with ${failures.length} errors`);
  }
}

function assertMemberContactUpgradeDatabaseName(databaseName: string): void {
  if (!/^nom_t_[0-9a-f]{32}$/u.test(databaseName)) {
    throw new Error("Refusing to clean up a non-member-contact-upgrade scratch database");
  }
}
