import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { Socket } from "node:net";
import path from "node:path";
import { Pool } from "pg";
import { inspectMigrationPlan, runMigrations } from "../dist/src/migrations.js";
import { resolveTenantMaintenanceRoute } from "../dist/src/tenant-maintenance-policy.js";

// Only the two additive, reviewed routine/constraint patches. No general CLI,
// provisioning, sync, password/grant reconciliation, or business-row mutation.
const packageRoot = path.resolve(import.meta.dirname, "..");
const mode = process.argv[2];
assert.ok(["--check", "--apply"].includes(mode) && process.argv.length === 3);
const targetControl = "032_gestionchurch_explicit_operational_roles.sql";
const targetTenant = "038_gestionchurch_explicit_custodian_role.sql";
const identitySignature = "sync_gestionchurch_federated_identity(uuid,text,text,text,text,text,text[],text,text)";
const rolesSignature = "sync_gestionchurch_federated_roles(uuid,text[])";
const constraintName = "platform_identities_gestionchurch_federation_complete";
const pools = [];
let stage = "configuration";
const appliedScopes = [];
try {
  const install = JSON.parse(await readFile(path.join(packageRoot, ".local/install.json"), "utf8"));
  const admin = new URL(install.DATABASE_ADMIN_URL);
  assert.ok(admin.protocol === "postgresql:" && admin.hostname === "127.0.0.1" && admin.port === "55432"
    && decodeURIComponent(admin.username) === "nom_admin" && admin.pathname === "/postgres" && !admin.search && !admin.hash);
  const poolFor = (database) => {
    const url = new URL(admin.href); url.pathname = `/${database}`;
    const pool = new Pool({ connectionString: url.href, max: 1, connectionTimeoutMillis: 5_000 });
    pools.push(pool); return pool;
  };
  const control = poolFor("nombramientos_control");
  const entries = [{ scope: "control", pool: control, signature: identitySignature, target: targetControl, count: 31, head: "031_gestionchurch_independent_source_sessions.sql", database: "nombramientos_control" }];
  const tenants = await control.query("SELECT id::text FROM tenants ORDER BY id");
  for (const row of tenants.rows) {
    assert.match(row.id, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u);
    const route = await resolveTenantMaintenanceRoute(control, row.id);
    const suffix = row.id.replaceAll("-", "");
    assert.equal(route.databaseHost, "127.0.0.1"); assert.equal(route.databasePort, 55432);
    assert.equal(route.databaseName, `nom_t_${suffix}`); assert.equal(route.runtimeRole, `nom_r_${suffix}`);
    const pool = poolFor(route.databaseName);
    const settings = await pool.query("SELECT tenant_id::text,kind,setup_state,current_database() database FROM tenant_settings WHERE singleton=true");
    assert.equal(settings.rowCount, 1);
    assert.equal(settings.rows[0].tenant_id, route.id); assert.equal(settings.rows[0].kind, route.kind);
    assert.equal(settings.rows[0].database, route.databaseName);
    assert.ok(["not_started", "ready"].includes(settings.rows[0].setup_state), "Do not overlap in-progress onboarding");
    entries.push({ scope: "tenant", pool, signature: rolesSignature, target: targetTenant, count: 39, head: "037_gestionchurch_federation.sql", database: route.databaseName, tenantId: route.id, executionRole: `nom_o_${suffix}` });
  }
  stage = "all-ledger-preflight";
  for (const entry of entries) {
    entry.directory = path.join(packageRoot, "migrations", entry.scope);
    entry.plan = await inspectMigrationPlan(entry.pool, { scope: entry.scope, directory: entry.directory });
    console.log(JSON.stringify({ scope: entry.scope, ...(entry.tenantId ? { tenantId: entry.tenantId } : {}), appliedCount: entry.plan.applied.length, appliedHead: entry.plan.applied.at(-1)?.name, pending: entry.plan.pending.map((item) => item.name) }));
    if (mode !== "--apply") continue;
    assert.equal(entry.plan.applied.length, entry.count);
    assert.equal(entry.plan.applied.at(-1)?.name, entry.head);
    assert.equal(entry.plan.pending.length, 1);
    assert.equal(entry.plan.pending[0]?.name, entry.target);
    entry.routine = await routineSnapshot(entry.pool, entry.signature);
    assert.equal(entry.routine.security_definer, true);
    assert.deepEqual(entry.routine.configuration, ["search_path=pg_catalog"]);
    assert.equal(entry.routine.owner, entry.executionRole ?? "nom_admin");
    entry.beforeCounts = await tableCounts(entry.pool);
  }
  if (mode === "--apply") {
    stage = "stopped-module-gate";
    assert.equal(await isListening(3300), false, "Nom web must remain stopped during scoped migration");
    assert.equal(await isListening(4100), false, "Nom API must remain stopped during scoped migration");
    const existingConstraint = await control.query("SELECT pg_get_constraintdef(oid) definition,convalidated FROM pg_constraint WHERE conrelid='public.platform_identities'::regclass AND conname=$1", [constraintName]);
    assert.equal(existingConstraint.rowCount, 1); assert.equal(existingConstraint.rows[0].convalidated, true);
    assert.ok(existingConstraint.rows[0].definition.includes("12"));
    stage = "private-rollback-snapshots";
    const runId = randomUUID();
    for (const entry of entries) {
      const bytes = `${entry.routine.definition};\n${entry.scope === "control" ? `ALTER TABLE public.platform_identities DROP CONSTRAINT ${constraintName};\nALTER TABLE public.platform_identities ADD CONSTRAINT ${constraintName} ${existingConstraint.rows[0].definition};\n` : ""}`;
      entry.rollbackPath = path.join(packageRoot, ".local", `explicit-roles-before-${runId}-${entry.tenantId ?? "control"}.sql`);
      await writeFile(entry.rollbackPath, bytes, { flag: "wx", mode: 0o600 });
      restrictPrivateFile(entry.rollbackPath);
      entry.rollbackSha256 = createHash("sha256").update(bytes).digest("hex");
    }
    stage = "official-scoped-migrations";
    for (const entry of entries) {
      const applied = await runMigrations(entry.pool, { scope: entry.scope, directory: entry.directory, expectedPendingMigrations: entry.plan.pending, ...(entry.executionRole ? { executionRole: entry.executionRole } : {}) });
      assert.deepEqual(applied, [entry.target]);
      appliedScopes.push({ scope: entry.scope, ...(entry.tenantId ? { tenantId: entry.tenantId } : {}), migration: entry.target });
      assert.deepEqual(await tableCounts(entry.pool), entry.beforeCounts, "All non-ledger public table row counts must remain unchanged");
      const current = await routineSnapshot(entry.pool, entry.signature);
      for (const property of ["owner", "acl", "security_definer", "configuration"]) assert.deepEqual(current[property], entry.routine[property]);
      assert.ok(current.definition.includes(entry.scope === "control" ? "NOMINATIONS_BALLOT_CUSTODIAN" : "TALLY_CUSTODIAN"));
      const verified = await inspectMigrationPlan(entry.pool, { scope: entry.scope, directory: entry.directory });
      assert.equal(verified.pending.length, 0); assert.equal(verified.applied.length, entry.count + 1);
      assert.equal(verified.applied.at(-1)?.name, entry.target);
      console.log(JSON.stringify({ scope: entry.scope, ...(entry.tenantId ? { tenantId: entry.tenantId } : {}), applied, verifiedCount: verified.applied.length, head: entry.target, pendingCount: 0, allBusinessRowCountsUnchanged: true, routinePrivilegesUnchanged: true, rollbackFile: path.relative(packageRoot, entry.rollbackPath).replaceAll("\\", "/"), rollbackSha256: entry.rollbackSha256 }));
    }
    console.log(JSON.stringify({ pass: true, operation: "guarded-explicit-operational-role-migrations", appliedScopes: appliedScopes.length }));
  }
} catch (error) {
  // Never echo DB messages, query arguments, URLs, definitions, or rollback SQL.
  console.error(JSON.stringify({ pass: false, operation: "guarded-explicit-operational-role-migrations", stage, appliedScopes, code: typeof error?.code === "string" && /^[A-Z0-9_]{3,40}$/u.test(error.code) ? error.code : "GUARD_OR_DATABASE_FAILURE" }));
  process.exitCode = 1;
} finally {
  await Promise.all(pools.map((pool) => pool.end()));
}

async function routineSnapshot(pool, signature) {
  const result = await pool.query("SELECT pg_get_functiondef(oid) definition,proowner::regrole::text owner,proacl::text acl,prosecdef security_definer,proconfig configuration FROM pg_proc WHERE oid=$1::regprocedure", [signature]);
  assert.equal(result.rowCount, 1); return result.rows[0];
}
async function tableCounts(pool) {
  const tables = await pool.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'schema_migrations' ORDER BY tablename");
  const counts = [];
  for (const { tablename } of tables.rows) {
    assert.match(tablename, /^[a-z][a-z0-9_]{0,62}$/u);
    const result = await pool.query(`SELECT count(*)::text count FROM public."${tablename}"`);
    counts.push([tablename, result.rows[0].count]);
  }
  return counts;
}
function restrictPrivateFile(filename) {
  if (process.platform !== "win32") return;
  const currentUser = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true });
  const sid = currentUser.match(/S-1-\d+(?:-\d+)+/u)?.[0]; assert.ok(sid);
  execFileSync("icacls.exe", [filename, "/inheritance:r", "/grant:r", `*${sid}:(R,W)`], { stdio: "pipe", windowsHide: true });
}
async function isListening(port) {
  return new Promise((resolve, reject) => {
    const socket = new Socket(); socket.setTimeout(2_000);
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("timeout", () => { socket.destroy(); reject(new Error("Indeterminate module listener state")); });
    socket.once("error", (error) => { socket.destroy(); if (error.code === "ECONNREFUSED") resolve(false); else reject(new Error("Indeterminate module listener state")); });
    socket.connect(port, "127.0.0.1");
  });
}
