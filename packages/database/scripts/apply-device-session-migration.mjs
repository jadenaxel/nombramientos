import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Socket } from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';
import { inspectMigrationPlan, runMigrations } from '../dist/src/migrations.js';
import { resolveTenantMaintenanceRoute } from '../dist/src/tenant-maintenance-policy.js';
import { TENANT_RUNTIME_GRANT_CONTRACT } from '../dist/src/runtime-grant-contract.js';

// Deliberately local and narrow: no general migrations, seeds, identity sync,
// key conversion, role reassignment, password rotation or broad grant repair.
export const TARGET = '039_device_bound_http_sessions.sql';
export const TABLES = Object.freeze(['e2ee_http_challenges', 'e2ee_http_devices', 'e2ee_http_session_bindings']);
export const LOCAL_TENANTS = Object.freeze([
  '0a2a0000-0000-4000-8000-000000000001',
  '699b078c-4361-45f4-b23a-0c7752bb1969',
  'd0000000-0000-4000-8000-000000000001',
]);
export function assertTargetPlan(plan) {
  const original = plan.applied.length === 40 && plan.applied.at(-1)?.name === '038_gestionchurch_explicit_custodian_role.sql';
  const completed = plan.applied.length === 41 && plan.applied.at(-1)?.name === TARGET && plan.pending.length === 0;
  assert.ok(completed || (original && plan.pending.length === 1 && plan.pending[0]?.name === TARGET));
  return completed;
}
export function assertLocalRoute(route) {
  assert.ok(LOCAL_TENANTS.includes(route.id));
  const suffix = route.id.replaceAll('-', '');
  assert.equal(route.databaseHost, '127.0.0.1'); assert.equal(route.databasePort, 55432);
  assert.equal(route.databaseName, `nom_t_${suffix}`); assert.equal(route.runtimeRole, `nom_r_${suffix}`);
  return `nom_o_${suffix}`;
}
export function assertExpirationCleanupAuthority(metadata, owner) {
  assert.equal(metadata.owner, owner);
  assert.equal(metadata.owner_can_login, false);
  assert.equal(metadata.prosecdef, true);
  assert.deepEqual(metadata.proconfig, ['search_path=pg_catalog']);
  assert.equal(metadata.public_execute, false);
  assert.equal(metadata.runtime_execute, false);
  assert.equal(metadata.tgenabled, 'O');
  // AFTER INSERT FOR EACH STATEMENT: no row-level or callable maintenance API.
  assert.equal(metadata.tgtype, 4);
  assert.equal(metadata.index_owner, owner);
  assert.equal(metadata.index_valid, true);
}

async function main() {
  const mode = process.argv[2];
  assert.ok(['--check', '--apply'].includes(mode) && process.argv.length === 3);
  const packageRoot = path.resolve(import.meta.dirname, '..');
  const directory = path.join(packageRoot, 'migrations/tenant');
  const pools = []; const appliedTenants = []; let stage = 'configuration';
  try {
    const install = JSON.parse(await readFile(path.join(packageRoot, '.local/install.json'), 'utf8'));
    const admin = new URL(install.DATABASE_ADMIN_URL);
    assert.ok(admin.protocol === 'postgresql:' && admin.hostname === '127.0.0.1' && admin.port === '55432'
      && decodeURIComponent(admin.username) === 'nom_admin' && admin.pathname === '/postgres' && !admin.search && !admin.hash);
    const poolFor = (database) => {
      const url = new URL(admin.href); url.pathname = `/${database}`;
      const pool = new Pool({ connectionString: url.href, max: 1, connectionTimeoutMillis: 5_000 });
      pools.push(pool); return pool;
    };
    const control = poolFor('nombramientos_control');
    stage = 'all-tenant-preflight';
    assert.deepEqual((await control.query('SELECT id::text FROM tenants ORDER BY id')).rows.map(({ id }) => id), LOCAL_TENANTS);
    const controlPlan = await inspectMigrationPlan(control, { scope: 'control', directory: path.join(packageRoot, 'migrations/control') });
    assert.equal(controlPlan.applied.length, 32); assert.equal(controlPlan.pending.length, 0);
    const controlBefore = await snapshot(control);
    const entries = [];
    for (const tenantId of LOCAL_TENANTS) {
      const route = await resolveTenantMaintenanceRoute(control, tenantId);
      const owner = assertLocalRoute(route); const pool = poolFor(route.databaseName);
      const settings = (await pool.query('SELECT tenant_id::text,kind,setup_state FROM tenant_settings WHERE singleton=true')).rows;
      assert.equal(settings.length, 1); assert.equal(settings[0].tenant_id, tenantId); assert.equal(settings[0].kind, route.kind);
      assert.ok(['not_started', 'ready'].includes(settings[0].setup_state));
      const plan = await inspectMigrationPlan(pool, { scope: 'tenant', directory });
      const completed = assertTargetPlan(plan);
      const before = await snapshot(pool);
      entries.push({ tenantId, route, owner, pool, plan, completed, before });
      console.log(JSON.stringify({ tenantId, appliedCount: plan.applied.length, head: plan.applied.at(-1)?.name,
        pending: plan.pending.map(({ name }) => name), alreadyApplied: completed }));
    }
    if (mode === '--check') return;
    stage = 'stopped-module-gate';
    assert.equal(await isListening(3300), false); assert.equal(await isListening(4100), false);
    for (const entry of entries) {
      stage = 'scoped-tenant-migration';
      const applied = entry.completed ? [] : await runMigrations(entry.pool, { scope: 'tenant', directory,
        expectedPendingMigrations: entry.plan.pending, executionRole: entry.owner });
      assert.deepEqual(applied, entry.completed ? [] : [TARGET]);
      appliedTenants.push(entry.tenantId);
      stage = 'new-table-only-runtime-grants';
      const client = await entry.pool.connect();
      try {
        await client.query('BEGIN');
        for (const table of TABLES) {
          const privileges = TENANT_RUNTIME_GRANT_CONTRACT.tables[table];
          assert.deepEqual(privileges, table === 'e2ee_http_devices' ? ['INSERT', 'SELECT'] : ['INSERT', 'SELECT', 'UPDATE']);
          await client.query(`GRANT ${privileges.join(',')} ON public.${table} TO ${entry.route.runtimeRole}`);
        }
        await client.query('COMMIT');
      } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
      stage = 'preservation-and-privilege-verification';
      const after = await snapshot(entry.pool);
      // On a resumable already-applied run, only the three new table ACLs may differ.
      const originalOnly = (items) => items.filter(([name]) => !TABLES.includes(name));
      assert.deepEqual(originalOnly(after.rows), originalOnly(entry.before.rows));
      assert.deepEqual(originalOnly(after.relations), originalOnly(entry.before.relations));
      const oldFunctionNames = new Set(entry.before.functions.map(([name]) => name));
      assert.deepEqual(after.functions.filter(([name]) => oldFunctionNames.has(name)), entry.before.functions);
      assert.deepEqual(after.database, entry.before.database);
      const objects = await entry.pool.query("SELECT relname,relowner::regrole::text owner FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY($1::text[]) ORDER BY relname", [TABLES]);
      assert.equal(objects.rowCount, 3); assert.ok(objects.rows.every(({ owner }) => owner === entry.owner));
      for (const table of TABLES) {
        const result = await entry.pool.query("SELECT p,has_table_privilege($1::text,$2::text,p) allowed FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p", [entry.route.runtimeRole, `public.${table}`]);
        assert.deepEqual(result.rows.filter(({ allowed }) => allowed).map(({ p }) => p).sort(), [...TENANT_RUNTIME_GRANT_CONTRACT.tables[table]].sort());
        assert.equal((await entry.pool.query("SELECT count(*)::int n FROM information_schema.role_table_grants WHERE table_schema='public' AND table_name=$1 AND grantee='PUBLIC'", [table])).rows[0].n, 0);
      }
      const trigger = (await entry.pool.query("SELECT p.proowner::regrole::text owner,p.prosecdef,t.tgenabled,EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') public_execute FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgname='e2ee_http_device_revocation' AND t.tgrelid='public.e2ee_key_devices'::regclass")).rows;
      assert.equal(trigger.length, 1); assert.equal(trigger[0].owner, entry.owner); assert.equal(trigger[0].prosecdef, false); assert.equal(trigger[0].tgenabled, 'O');
      assert.equal(trigger[0].public_execute, false);
      const expiration = (await entry.pool.query(`SELECT p.proowner::regrole::text owner,
        r.rolcanlogin owner_can_login,p.prosecdef,p.proconfig,t.tgenabled,t.tgtype,
        EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE a.grantee=0 AND a.privilege_type='EXECUTE') public_execute,
        has_function_privilege($1::text,p.oid,'EXECUTE') runtime_execute,
        i.relowner::regrole::text index_owner,x.indisvalid index_valid
        FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_roles r ON r.oid=p.proowner
        JOIN pg_class i ON i.oid='public.e2ee_http_challenges_expiration'::regclass
        JOIN pg_index x ON x.indexrelid=i.oid
        WHERE t.tgname='e2ee_http_challenge_expiration'
          AND t.tgrelid='public.e2ee_http_challenges'::regclass
          AND p.oid='public.prune_expired_e2ee_http_challenges()'::regprocedure`, [entry.route.runtimeRole])).rows;
      assert.equal(expiration.length, 1);
      assertExpirationCleanupAuthority(expiration[0], entry.owner);
      const verified = await inspectMigrationPlan(entry.pool, { scope: 'tenant', directory });
      assert.equal(assertTargetPlan(verified), true);
      console.log(JSON.stringify({ tenantId: entry.tenantId, applied, verifiedCount: 41, pendingCount: 0,
        businessRowsAndExistingPrivilegesUnchanged: true, newTablePrivilegesVerified: true,
        boundedExpirationCleanupAuthorityVerified: true,
        preservationSha256: createHash('sha256').update(JSON.stringify(originalOnly(after.rows))).digest('hex') }));
    }
    assert.deepEqual(await snapshot(control), controlBefore);
    console.log(JSON.stringify({ pass: true, operation: 'guarded-device-session-migration', tenants: entries.length, controlUnchanged: true }));
  } catch (error) {
    // Never echo DB messages, URLs, query arguments or private business rows.
    console.error(JSON.stringify({ pass: false, operation: 'guarded-device-session-migration', stage, appliedTenants,
      code: typeof error?.code === 'string' && /^[A-Z0-9_]{3,40}$/u.test(error.code) ? error.code : 'GUARD_OR_DATABASE_FAILURE' }));
    process.exitCode = 1;
  } finally { await Promise.all(pools.map((pool) => pool.end())); }
}
async function snapshot(pool) {
  const tables = (await pool.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'schema_migrations' ORDER BY tablename")).rows;
  const rows = [];
  for (const { tablename } of tables) {
    assert.match(tablename, /^[a-z][a-z0-9_]{0,62}$/u);
    const result = await pool.query(`SELECT count(*)::text n,md5(COALESCE(string_agg(h,'' ORDER BY h),'')) digest FROM (SELECT md5(row_to_json(r)::text) h FROM public."${tablename}" r) s`);
    rows.push([tablename, result.rows[0].n, result.rows[0].digest]);
  }
  const relations = (await pool.query("SELECT c.relname,c.relowner::regrole::text owner,c.relacl::text acl,(SELECT COALESCE(jsonb_agg(jsonb_build_array(a.attname,a.attacl::text) ORDER BY a.attnum),'[]'::jsonb) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) columns FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','S') ORDER BY c.relname")).rows.map((r) => [r.relname, r.owner, r.acl, r.columns]);
  const functions = (await pool.query("SELECT p.oid::regprocedure::text name,p.proowner::regrole::text owner,p.proacl::text acl,p.prosecdef,p.proconfig,md5(pg_get_functiondef(p.oid)) digest FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.prokind='f' ORDER BY name")).rows.map((r) => [r.name, r.owner, r.acl, r.prosecdef, r.proconfig, r.digest]);
  const database = (await pool.query('SELECT datdba::regrole::text owner,datacl::text acl FROM pg_database WHERE datname=current_database()')).rows;
  return { rows, relations, functions, database };
}
async function isListening(port) {
  return new Promise((resolve, reject) => {
    const socket = new Socket(); socket.setTimeout(2_000);
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Indeterminate module state')); });
    socket.once('error', (error) => { socket.destroy(); if (error.code === 'ECONNREFUSED') resolve(false); else reject(new Error('Indeterminate module state')); });
    socket.connect(port, '127.0.0.1');
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) await main();
