import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { inspectMigrationPlan, runMigrations } from "../dist/src/migrations.js";

// Targeted, explicitly authorized operational migration. Never sync/provision,
// reconcile role grants, or change runtime passwords like the general CLI does.
const packageRoot = path.resolve(import.meta.dirname, "..");
const directory = path.join(packageRoot, "migrations/control");
const target = "031_gestionchurch_independent_source_sessions.sql";
const mode = process.argv[2];
assert.ok(["--check", "--apply"].includes(mode) && process.argv.length === 3);
let pool;
try {
  const install = JSON.parse(await readFile(path.join(packageRoot, ".local/install.json"), "utf8"));
  const admin = new URL(install.DATABASE_ADMIN_URL);
  assert.ok(admin.protocol === "postgresql:" && admin.hostname === "127.0.0.1" && admin.port === "55432"
    && decodeURIComponent(admin.username) === "nom_admin" && admin.pathname === "/postgres" && !admin.search && !admin.hash);
  admin.pathname = "/nombramientos_control";
  pool = new Pool({ connectionString: admin.href, max: 1, connectionTimeoutMillis: 5_000 });
  const plan = await inspectMigrationPlan(pool, { scope: "control", directory });
  console.log(JSON.stringify({ appliedCount: plan.applied.length, appliedHead: plan.applied.at(-1)?.name, pending: plan.pending.map((item) => item.name) }));
  if (mode === "--apply") {
    assert.equal(plan.applied.length, 30);
    assert.equal(plan.applied.at(-1)?.name, "030_gestionchurch_session_binding.sql");
    assert.equal(plan.pending.length, 1);
    assert.equal(plan.pending[0]?.name, target);
    const prior = await pool.query("SELECT pg_get_functiondef('sync_gestionchurch_federated_identity(uuid,text,text,text,text,text,text[],text,text)'::regprocedure) definition");
    const ddl = prior.rows[0]?.definition;
    assert.ok(typeof ddl === "string" && ddl.includes("CREATE OR REPLACE FUNCTION"));
    const rollbackPath = path.join(packageRoot, ".local", `independent-session-function-before-${randomUUID()}.sql`);
    const bytes = `${ddl};\n`;
    await writeFile(rollbackPath, bytes, { flag: "wx", mode: 0o600 });
    if (process.platform === "win32") {
      const currentUser = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true });
      const sid = currentUser.match(/S-1-\d+(?:-\d+)+/u)?.[0];
      assert.ok(sid);
      execFileSync("icacls.exe", [rollbackPath, "/inheritance:r", "/grant:r", `*${sid}:(R,W)`], { stdio: "pipe", windowsHide: true });
    }
    const before = await pool.query("SELECT (SELECT count(*) FROM platform_identities)::text identities,(SELECT count(*) FROM tenant_memberships)::text memberships,(SELECT count(*) FROM auth_sessions)::text sessions,(SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL)::text revoked");
    const applied = await runMigrations(pool, { scope: "control", directory, expectedPendingMigrations: plan.pending });
    assert.deepEqual(applied, [target]);
    const after = await pool.query("SELECT (SELECT count(*) FROM platform_identities)::text identities,(SELECT count(*) FROM tenant_memberships)::text memberships,(SELECT count(*) FROM auth_sessions)::text sessions,(SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL)::text revoked");
    assert.deepEqual(after.rows, before.rows, "Migration must not change identities, memberships or sessions");
    const verified = await inspectMigrationPlan(pool, { scope: "control", directory });
    assert.equal(verified.pending.length, 0);
    assert.equal(verified.applied.length, 31);
    const current = await pool.query("SELECT pg_get_functiondef('sync_gestionchurch_federated_identity(uuid,text,text,text,text,text,text[],text,text)'::regprocedure) definition");
    assert.ok(current.rows[0]?.definition.includes("previous_role_fingerprint IS DISTINCT FROM p_role_fingerprint"));
    console.log(JSON.stringify({ applied, verifiedCount: verified.applied.length, head: verified.applied.at(-1)?.name, pendingCount: 0, businessRowCountsUnchanged: true, rollbackFile: path.relative(packageRoot, rollbackPath).replaceAll("\\", "/"), rollbackSha256: createHash("sha256").update(bytes).digest("hex") }));
  }
} catch (error) {
  // PostgreSQL detail/messages can contain query arguments. Never echo them.
  console.error(JSON.stringify({ pass: false, operation: "guarded-independent-session-migration", code: typeof error?.code === "string" && /^[A-Z0-9_]{3,40}$/u.test(error.code) ? error.code : "GUARD_OR_DATABASE_FAILURE" }));
  process.exitCode = 1;
} finally {
  await pool?.end();
}
