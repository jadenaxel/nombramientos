import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { catalogPackage2025 } from "@nombramientos/catalog";
import { EncryptedFileSecretProvider, TenantProvisioner } from "../dist/src/index.js";

const packageRoot = path.resolve(import.meta.dirname, "..");
const localRoot = path.join(packageRoot, ".local");
const args = process.argv.slice(2);
const mode = args[0]?.startsWith("--") ? args[0] : "--check";
const input = mode === args[0] ? args[1] : args[0];
assert.ok(["--check", "--create", "--cleanup"].includes(mode) && typeof input === "string" && args.length === (mode === args[0] ? 2 : 1));
const pools = [];
let stage = "configuration", provisioner, masterKey;
try {
  const install = JSON.parse(await readFile(path.join(localRoot, "install.json"), "utf8"));
  const admin = new URL(install.DATABASE_ADMIN_URL);
  assert.ok(admin.protocol === "postgresql:" && admin.hostname === "127.0.0.1" && admin.port === "55432" && admin.pathname === "/postgres" && decodeURIComponent(admin.username) === "nom_admin" && !admin.search && !admin.hash);
  const poolFor = (database, user = admin.username, password = admin.password) => {
    const url = new URL(admin.href); url.pathname = `/${database}`; url.username = user; url.password = password;
    const pool = new Pool({ connectionString: url.href, max: 1, connectionTimeoutMillis: 5_000 }); pools.push(pool); return pool;
  };
  const cluster = poolFor("postgres"), control = poolFor("nombramientos_control");
  let receipt, receiptFile, tenantId;
  if (mode === "--cleanup") {
    receiptFile = path.resolve(input);
    assert.equal(path.dirname(receiptFile), localRoot);
    assert.match(path.basename(receiptFile), /^gc-browser-fixture-[0-9a-f-]{36}\.json$/u);
    receipt = JSON.parse(await readFile(receiptFile, "utf8"));
    assert.equal(receipt.version, 1); assert.equal(receipt.owner, "gestionchurch-browser-fixture");
    tenantId = receipt.tenantId;
  } else tenantId = input;
  assert.match(tenantId, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u);
  const suffix = tenantId.replaceAll("-", "");
  const database = `nom_t_${suffix}`, ownerRole = `nom_o_${suffix}`, runtimeRole = `nom_r_${suffix}`;
  const secretReference = `tenant-db/${tenantId}/runtime/v1`;
  if (mode === "--cleanup") {
    stage = "cleanup-ownership-preflight";
    assert.equal(receipt.database, database); assert.equal(receipt.ownerRole, ownerRole); assert.equal(receipt.runtimeRole, runtimeRole);
    assert.equal(receipt.secretReference, secretReference); assert.match(receipt.nonce, /^[0-9a-f-]{36}$/u);
    assert.match(receipt.slug, /^premium-[a-f0-9]{16}$/u);
    const route = await control.query("SELECT slug,database_name::text,runtime_role::text,runtime_secret_ref,gestionchurch_tenant_id::text FROM tenants WHERE id=$1", [tenantId]);
    assert.equal(route.rowCount, 1); assert.equal(route.rows[0].slug, receipt.slug);
    assert.equal(route.rows[0].database_name, database); assert.equal(route.rows[0].runtime_role, runtimeRole);
    assert.equal(route.rows[0].runtime_secret_ref, secretReference); assert.equal(route.rows[0].gestionchurch_tenant_id, tenantId);
    const tenant = poolFor(database);
    const proof = await tenant.query("SELECT nonce::text,tenant_id::text FROM premium_gc_browser_fixture_marker");
    assert.equal(proof.rowCount, 1); assert.equal(proof.rows[0].nonce, receipt.nonce); assert.equal(proof.rows[0].tenant_id, tenantId);
    const job = await control.query("SELECT idempotency_key::text FROM provisioning_jobs WHERE tenant_id=$1", [tenantId]);
    assert.equal(job.rowCount, 1); assert.equal(job.rows[0].idempotency_key, receipt.nonce);
    const identities = await control.query("SELECT identity.id::text,identity.gestionchurch_subject FROM tenant_memberships membership JOIN platform_identities identity ON identity.id=membership.identity_id WHERE membership.tenant_id=$1", [tenantId]);
    const identityIds = identities.rows.map((row) => { assert.ok(row.gestionchurch_subject?.startsWith(`tenant:${tenantId}:`)); return row.id; });
    assert.equal((await control.query("SELECT 1 FROM tenant_memberships WHERE identity_id=ANY($1::uuid[]) AND tenant_id<>$2", [identityIds, tenantId])).rowCount, 0);
    assert.equal((await control.query("SELECT 1 FROM platform_role_bindings WHERE identity_id=ANY($1::uuid[])", [identityIds])).rowCount, 0);
    for (const table of ["tenant_invitations", "tenant_onboarding_recovery_requests", "tenant_lifecycle_requests", "tenant_reactivation_requests"]) {
      const exists = await control.query("SELECT to_regclass($1) name", [`public.${table}`]);
      if (exists.rows[0]?.name) assert.equal((await control.query(`SELECT 1 FROM public."${table}" WHERE tenant_id=$1 LIMIT 1`, [tenantId])).rowCount, 0);
    }
    await tenant.end(); pools.splice(pools.indexOf(tenant), 1);
    assert.equal((await cluster.query("SELECT 1 FROM pg_stat_activity WHERE datname=$1", [database])).rowCount, 0, "Close Nom module before cleanup; never terminate unknown connections");
    masterKey = Buffer.from(install.DATABASE_SECRET_MASTER_KEY_B64, "base64url"); assert.equal(masterKey.byteLength, 32);
    const secrets = new EncryptedFileSecretProvider(installedSecretFile(install), masterKey);
    assert.equal(await secrets.hasSecret(secretReference), true);
    stage = "owned-cleanup";
    await control.query("BEGIN");
    try {
      await control.query("DELETE FROM auth_sessions WHERE active_tenant_id=$1 AND identity_id=ANY($2::uuid[])", [tenantId, identityIds]);
      await control.query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND identity_id=ANY($2::uuid[])", [tenantId, identityIds]);
      await control.query("DELETE FROM platform_identities WHERE id=ANY($1::uuid[]) AND gestionchurch_subject LIKE $2", [identityIds, `tenant:${tenantId}:%`]);
      await control.query("DELETE FROM tenants WHERE id=$1 AND slug=$2 AND database_name=$3", [tenantId, receipt.slug, database]);
      await control.query("DELETE FROM provisioning_jobs WHERE tenant_id=$1 AND idempotency_key=$2", [tenantId, receipt.nonce]);
      await control.query("COMMIT");
    } catch (error) { await control.query("ROLLBACK"); throw error; }
    await formatted(cluster, "SELECT format('DROP DATABASE %I',$1::text) sql", [database]);
    for (const role of [runtimeRole, ownerRole]) await formatted(cluster, "SELECT format('DROP ROLE %I',$1::text) sql", [role]);
    await secrets.removeSecret(secretReference);
    assert.equal((await control.query("SELECT 1 FROM tenants WHERE id=$1", [tenantId])).rowCount, 0);
    assert.equal((await cluster.query("SELECT 1 FROM pg_database WHERE datname=$1 UNION ALL SELECT 1 FROM pg_roles WHERE rolname=ANY($2::text[])", [database, [runtimeRole, ownerRole]])).rowCount, 0);
    assert.equal(await secrets.hasSecret(secretReference), false);
    await writeFile(receiptFile, `${JSON.stringify({ ...receipt, cleanedAt: new Date().toISOString(), retainedAuditTrace: true })}\n`, { mode: 0o600 });
    console.log(JSON.stringify({ pass: true, mode, tenantId, resourcesAbsent: true, secretReferenceAbsent: true, retainedAuditTrace: true }));
  } else {
    stage = "source-and-freshness-preflight";
    // GC uses local postgres in this repository. Only fixture metadata is read.
    const gc = poolFor("gestionchurch_control", "postgres", "");
    const source = await gc.query("SELECT id::text,slug,name,timezone,database_name,status FROM control.tenants WHERE id=$1", [tenantId]);
    assert.equal(source.rowCount, 1); const row = source.rows[0];
    assert.equal(row.name, "Synthetic premium validation"); assert.match(row.slug, /^premium-[a-f0-9]{16}$/u);
    assert.equal(row.database_name, `gc_tenant_${tenantId.replaceAll("-", "_")}`); assert.equal(row.status, "ACTIVE");
    assert.equal((await cluster.query("SELECT 1 FROM pg_database WHERE datname=$1", [row.database_name])).rowCount, 1);
    assert.equal((await control.query("SELECT 1 FROM tenants WHERE id=$1 OR gestionchurch_tenant_id=$1 OR slug=$2 OR database_name=$3", [tenantId, row.slug, database])).rowCount, 0);
    assert.equal((await control.query("SELECT 1 FROM provisioning_jobs WHERE tenant_id=$1 OR requested_slug=$2", [tenantId, row.slug])).rowCount, 0);
    assert.equal((await cluster.query("SELECT 1 FROM pg_database WHERE datname=$1 UNION ALL SELECT 1 FROM pg_roles WHERE rolname=ANY($2::text[])", [database, [ownerRole, runtimeRole]])).rowCount, 0);
    if (mode === "--check") console.log(JSON.stringify({ pass: true, mode, tenantId, sourceVerified: true, targetsFresh: true, mutations: 0 }));
    else {
      masterKey = Buffer.from(install.DATABASE_SECRET_MASTER_KEY_B64, "base64url"); assert.equal(masterKey.byteLength, 32);
      const secrets = new EncryptedFileSecretProvider(installedSecretFile(install), masterKey);
      assert.equal(await secrets.hasSecret(secretReference), false);
      const nonce = randomUUID(); receiptFile = path.join(localRoot, `gc-browser-fixture-${tenantId}.json`);
      receipt = { version: 1, owner: "gestionchurch-browser-fixture", tenantId, slug: row.slug, database, ownerRole, runtimeRole, secretReference, nonce, createdAt: new Date().toISOString() };
      await writeFile(receiptFile, `${JSON.stringify(receipt)}\n`, { flag: "wx", mode: 0o600 }); restrictPrivateFile(receiptFile);
      stage = "single-fixture-provisioning";
      const config = { host: admin.hostname, port: Number(admin.port), user: decodeURIComponent(admin.username), password: decodeURIComponent(admin.password), database: "postgres", ssl: false };
      provisioner = new TenantProvisioner({ admin: config, control, secrets, catalog: catalogPackage2025, migrationsRoot: path.join(packageRoot, "migrations") });
      await provisioner.provision({ idempotencyKey: nonce, tenantId, slug: row.slug, displayName: row.name, kind: "real", timezone: row.timezone, locale: "es" });
      const tenant = poolFor(database);
      await tenant.query("CREATE TABLE premium_gc_browser_fixture_marker(nonce uuid PRIMARY KEY,tenant_id uuid NOT NULL)");
      await tenant.query("INSERT INTO premium_gc_browser_fixture_marker VALUES($1,$2)", [nonce, tenantId]);
      await control.query("UPDATE tenants SET gestionchurch_tenant_id=$1 WHERE id=$1 AND slug=$2 AND database_name=$3 AND gestionchurch_tenant_id IS NULL", [tenantId, row.slug, database]);
      console.log(JSON.stringify({ pass: true, mode, tenantId, sourceVerified: true, oneTenantProvisioned: true, receiptFile: path.relative(packageRoot, receiptFile).replaceAll("\\", "/") }));
    }
  }
} catch (error) {
  console.error(JSON.stringify({ pass: false, operation: "scoped-gestionchurch-browser-fixture", stage, code: typeof error?.code === "string" && /^[A-Z0-9_]{3,40}$/u.test(error.code) ? error.code : "GUARD_OR_DATABASE_FAILURE" })); process.exitCode = 1;
} finally {
  await provisioner?.close(); await Promise.all(pools.map((pool) => pool.end())); masterKey?.fill(0);
}

function installedSecretFile(install) {
  const selected = path.resolve(install.DATABASE_SECRET_FILE ?? path.join(localRoot, "secrets.enc.json"));
  assert.equal(path.dirname(selected), localRoot); assert.equal(path.basename(selected), "secrets.enc.json"); return selected;
}
async function formatted(pool, format, values) { const result = await pool.query(format, values); assert.ok(result.rows[0]?.sql); await pool.query(result.rows[0].sql); }
function restrictPrivateFile(filename) {
  if (process.platform !== "win32") return;
  const identity = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true });
  const sid = identity.match(/S-1-\d+(?:-\d+)+/u)?.[0]; assert.ok(sid);
  execFileSync("icacls.exe", [filename, "/inheritance:r", "/grant:r", `*${sid}:(R,W)`], { stdio: "pipe", windowsHide: true });
}
