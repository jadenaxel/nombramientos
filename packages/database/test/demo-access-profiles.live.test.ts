import { timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { unwrapTenantKeyWithPassword, type WrappedTenantKey } from "../src/crypto-envelope.js";
import {
  DEMO_ACCESS_PROFILE_CODES,
  DEMO_ACCESS_PROFILE_DEFINITIONS,
  parseDemoAccessFile,
} from "../src/demo-access.js";
import { assertWorkspacePostgresUrl, withoutDatabase } from "../scripts/script-config.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const accessFile = path.join(packageRoot, ".local", "demo-access.json");
const required = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const ready = Boolean(adminUrl && existsSync(accessFile) && await canReachLocalPostgres(adminUrl));
if (required && !ready) throw new Error("Demo access-profile integration requires the isolated local PostgreSQL installation");
const live = ready ? describe : describe.skip;

live("isolated Demo access profiles", () => {
  it("persists exact MFA identities, memberships, roles and explicitly separated content-key grants", async () => {
    if (!adminUrl) throw new Error("The exact workspace administrator URL is unavailable");
    const access = parseDemoAccessFile(JSON.parse(readFileSync(accessFile, "utf8")));
    expect(access.version).toBe(2);
    if (access.version !== 2) throw new Error("Demo access file has not been upgraded to version 2");

    const control = new Pool({ connectionString: withoutDatabase(adminUrl, "nombramientos_control"), max: 1 });
    const demo = new Pool({ connectionString: withoutDatabase(adminUrl, "nom_t_d0000000000040008000000000000001"), max: 1 });
    const ozama = new Pool({ connectionString: withoutDatabase(adminUrl, "nom_t_0a2a0000000040008000000000000001"), max: 1 });
    const identityIds = DEMO_ACCESS_PROFILE_CODES.map((code) => access.profiles[code].identityId);
    const openedKeys: Buffer[] = [];
    try {
      const identities = await control.query<{
        id: string;
        mfa_enabled: boolean;
        mfa_required: boolean;
        status: string;
        membership_status: string;
        is_default: boolean;
      }>(
        `SELECT identity.id::text,identity.mfa_enabled,identity.mfa_required,identity.status,
                membership.status AS membership_status,membership.is_default
           FROM platform_identities identity
           JOIN tenant_memberships membership ON membership.identity_id=identity.id
          WHERE identity.id=ANY($1::uuid[]) AND membership.tenant_id=$2
          ORDER BY identity.id`,
        [identityIds, "d0000000-0000-4000-8000-000000000001"],
      );
      expect(identities.rows).toHaveLength(5);
      expect(identities.rows.every((identity) =>
        identity.mfa_enabled
        && identity.mfa_required
        && identity.status === "active"
        && identity.membership_status === "active"
        && identity.is_default)).toBe(true);

      const bindings = await demo.query<{ identity_id: string; role_codes: string[] }>(
        `SELECT binding.identity_id::text,array_agg(role.code ORDER BY role.code)::text[] AS role_codes
           FROM role_bindings binding JOIN roles role ON role.id=binding.role_id
          WHERE binding.identity_id=ANY($1::uuid[]) AND binding.revoked_at IS NULL AND role.system_role
          GROUP BY binding.identity_id ORDER BY binding.identity_id`,
        [identityIds],
      );
      const bindingsByIdentity = new Map(bindings.rows.map((binding) => [binding.identity_id, binding.role_codes]));
      for (const code of DEMO_ACCESS_PROFILE_CODES) {
        const definition = DEMO_ACCESS_PROFILE_DEFINITIONS[code];
        expect(bindingsByIdentity.get(definition.identityId)).toEqual([...definition.roleCodes].sort());
      }

      const grants = await demo.query<{
        identity_id: string;
        tenant_key_id: string;
        kdf: WrappedTenantKey["kdf"];
        wrap: WrappedTenantKey["wrap"];
      }>(
        `SELECT identity_id::text,tenant_key_id,kdf,wrap FROM device_key_grants
          WHERE identity_id=ANY($1::uuid[]) AND status='active' ORDER BY identity_id`,
        [identityIds],
      );
      expect(grants.rows).toHaveLength(4);
      expect(grants.rows.some(({ identity_id }) =>
        identity_id === DEMO_ACCESS_PROFILE_DEFINITIONS.custodian.identityId)).toBe(false);
      const referenceKeyId = grants.rows[0]?.tenant_key_id;
      expect(referenceKeyId).toBeTruthy();
      for (const grant of grants.rows) {
        expect(grant.tenant_key_id).toBe(referenceKeyId);
        const profile = DEMO_ACCESS_PROFILE_CODES.find((code) =>
          access.profiles[code].identityId === grant.identity_id);
        if (!profile) throw new Error("Unexpected Demo key grant identity");
        openedKeys.push(unwrapTenantKeyWithPassword(
          { kdf: grant.kdf, wrap: grant.wrap },
          access.profiles[profile].password,
        ));
      }
      const referenceKey = openedKeys[0];
      if (!referenceKey) throw new Error("Demo tenant content key was unavailable");
      expect(openedKeys.every((candidate) =>
        candidate.byteLength === referenceKey.byteLength && timingSafeEqual(candidate, referenceKey))).toBe(true);

      const manifest = await demo.query<{ metadata_text: string }>(
        "SELECT metadata::text AS metadata_text FROM seed_manifests WHERE seed_id='demo-access-profiles' AND version=1",
      );
      expect(manifest.rows).toHaveLength(1);
      expect(manifest.rows[0]!.metadata_text).not.toMatch(
        /"(?:password|totpEnrollmentUri|totpSecret|secret|email)"\s*:|@nombramientos\.local/i,
      );

      const ozamaLeak = await ozama.query<{ bindings: number; grants: number }>(
        `SELECT
           (SELECT count(*)::int FROM role_bindings WHERE identity_id=ANY($1::uuid[])) AS bindings,
           (SELECT count(*)::int FROM device_key_grants WHERE identity_id=ANY($1::uuid[])) AS grants`,
        [identityIds],
      );
      expect(ozamaLeak.rows[0]).toEqual({ bindings: 0, grants: 0 });
    } finally {
      for (const key of openedKeys) key.fill(0);
      await Promise.allSettled([control.end(), demo.end(), ozama.end()]);
    }
  }, 30_000);
});

function discoverAdminUrl(): string | undefined {
  if (!existsSync(installFile)) return undefined;
  try {
    const install = JSON.parse(readFileSync(installFile, "utf8")) as { DATABASE_ADMIN_URL?: string };
    if (!install.DATABASE_ADMIN_URL) return undefined;
    return assertWorkspacePostgresUrl(install.DATABASE_ADMIN_URL, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReachLocalPostgres(connectionString: string): Promise<boolean> {
  try {
    const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_000 });
    try {
      const result = await pool.query<{ port: number }>("SELECT current_setting('port')::int AS port");
      return result.rows[0]?.port === 55_432;
    } finally {
      await pool.end();
    }
  } catch {
    return false;
  }
}
