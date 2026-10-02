import assert from "node:assert/strict";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { inspectMigrationPlan } from "../dist/src/migrations.js";
import { EncryptedFileSecretProvider } from "../dist/src/secrets.js";
import { resolveTenantMaintenanceRoute } from "../dist/src/tenant-maintenance-policy.js";

// Verification only. No migration runner, provisioning, grants, sync, file
// writes, secret-store mutation, or backend termination is available here.
// Baseline IDs are the three routes reviewed before the owned browser run.
const originalTenantIds = [
  "0a2a0000-0000-4000-8000-000000000001",
  "699b078c-4361-45f4-b23a-0c7752bb1969",
  "d0000000-0000-4000-8000-000000000001",
].sort();
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u;
const packageRoot = path.resolve(import.meta.dirname, "..");
const localRoot = path.join(packageRoot, ".local");
const pools = [];
let stage = "arguments", masterKey, idlePoolFailure = false;

try {
  assert.ok(process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === "--check"));
  stage = "local-configuration";
  const install = JSON.parse(await readFile(path.join(localRoot, "install.json"), "utf8"));
  const admin = new URL(install.DATABASE_ADMIN_URL);
  assert.ok(admin.protocol === "postgresql:" && admin.hostname === "127.0.0.1" && admin.port === "55432"
    && decodeURIComponent(admin.username) === "nom_admin" && admin.pathname === "/postgres" && !admin.search && !admin.hash);
  const poolFor = (database, gcSource = false) => {
    const url = new URL(admin.href); url.pathname = `/${database}`;
    if (gcSource) { url.username = "postgres"; url.password = ""; }
    const pool = new Pool({ connectionString: url.href, max: 1, connectionTimeoutMillis: 5_000,
      application_name: "owned-browser-cleanup-readonly-verification",
      options: "-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=2000" });
    pool.on("error", () => { idlePoolFailure = true; });
    pools.push(pool); return pool;
  };
  const cluster = poolFor("postgres"), control = poolFor("nombramientos_control");
  for (const pool of [cluster, control]) await assertReadOnly(pool);

  stage = "original-registry-and-ledgers";
  const registry = await control.query("SELECT id::text FROM tenants ORDER BY id");
  assert.deepEqual(registry.rows.map((row) => row.id), originalTenantIds);
  const ledgers = [await verifiedLedger(control, "control", 32, "032_gestionchurch_explicit_operational_roles.sql")];
  for (const tenantId of originalTenantIds) {
    const route = await resolveTenantMaintenanceRoute(control, tenantId);
    const suffix = tenantId.replaceAll("-", "");
    assert.equal(route.databaseHost, "127.0.0.1"); assert.equal(route.databasePort, 55432);
    assert.equal(route.databaseName, `nom_t_${suffix}`); assert.equal(route.runtimeRole, `nom_r_${suffix}`);
    assert.equal(route.runtimeSecretReference, `tenant-db/${tenantId}/runtime/v1`);
    const tenant = poolFor(route.databaseName); await assertReadOnly(tenant);
    const identity = await tenant.query("SELECT tenant_id::text,kind,setup_state,current_database() AS database FROM tenant_settings WHERE singleton=true");
    assert.equal(identity.rowCount, 1); assert.equal(identity.rows[0].tenant_id, tenantId);
    assert.equal(identity.rows[0].kind, route.kind); assert.equal(identity.rows[0].database, route.databaseName);
    assert.ok(["not_started", "ready"].includes(identity.rows[0].setup_state));
    ledgers.push(await verifiedLedger(tenant, "tenant", 41, "039_device_bound_http_sessions.sql"));
  }

  stage = "owned-receipts";
  const receiptFiles = (await readdir(localRoot)).filter((name) => /^gc-browser-fixture-[0-9a-f-]{36}\.json$/u.test(name)).sort();
  assert.ok(receiptFiles.length > 0, "No owned receipts: cleanup verification would be vacuous");
  const receipts = [];
  for (const filename of receiptFiles) {
    const file = path.join(localRoot, filename), metadata = await lstat(file);
    assert.ok(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size < 32_768);
    const receipt = JSON.parse(await readFile(file, "utf8"));
    assert.equal(receipt.version, 1); assert.equal(receipt.owner, "gestionchurch-browser-fixture");
    assert.match(receipt.tenantId, uuid); assert.match(receipt.nonce, uuid);
    assert.equal(filename, `gc-browser-fixture-${receipt.tenantId}.json`);
    assert.ok(!originalTenantIds.includes(receipt.tenantId)); assert.match(receipt.slug, /^premium-[a-f0-9]{16}$/u);
    const suffix = receipt.tenantId.replaceAll("-", "");
    assert.equal(receipt.database, `nom_t_${suffix}`); assert.equal(receipt.ownerRole, `nom_o_${suffix}`);
    assert.equal(receipt.runtimeRole, `nom_r_${suffix}`); assert.equal(receipt.secretReference, `tenant-db/${receipt.tenantId}/runtime/v1`);
    assert.ok(typeof receipt.createdAt === "string" && typeof receipt.cleanedAt === "string"
      && Number.isFinite(Date.parse(receipt.createdAt)) && Number.isFinite(Date.parse(receipt.cleanedAt))
      && Date.parse(receipt.cleanedAt) >= Date.parse(receipt.createdAt));
    assert.equal(receipt.retainedAuditTrace, true);
    receipts.push(receipt);
  }
  const fixtureIds = receipts.map((receipt) => receipt.tenantId);
  assert.equal(new Set(fixtureIds).size, fixtureIds.length);

  stage = "owned-database-and-registration-absence";
  const databases = receipts.flatMap((receipt) => [receipt.database, `gc_tenant_${receipt.tenantId.replaceAll("-", "_")}`]);
  const roles = receipts.flatMap((receipt) => [receipt.ownerRole, receipt.runtimeRole]);
  const absent = {
    tenantRegistrations: await count(control, "SELECT count(*)::integer AS count FROM tenants WHERE id=ANY($1::uuid[]) OR gestionchurch_tenant_id=ANY($1::uuid[])", [fixtureIds]),
    provisioningJobs: await count(control, "SELECT count(*)::integer AS count FROM provisioning_jobs WHERE tenant_id=ANY($1::uuid[])", [fixtureIds]),
    memberships: await count(control, "SELECT count(*)::integer AS count FROM tenant_memberships WHERE tenant_id=ANY($1::uuid[])", [fixtureIds]),
    authSessions: await count(control, "SELECT count(*)::integer AS count FROM auth_sessions WHERE active_tenant_id=ANY($1::uuid[])", [fixtureIds]),
    federatedIdentities: await count(control, "SELECT count(*)::integer AS count FROM platform_identities identity WHERE EXISTS (SELECT 1 FROM unnest($1::uuid[]) fixture(id) WHERE identity.gestionchurch_subject LIKE 'tenant:' || fixture.id::text || ':%')", [fixtureIds]),
    databases: await count(cluster, "SELECT count(*)::integer AS count FROM pg_database WHERE datname=ANY($1::text[])", [databases]),
    nomRoles: await count(cluster, "SELECT count(*)::integer AS count FROM pg_roles WHERE rolname=ANY($1::text[])", [roles]),
    gcRuntimeRoles: await count(cluster, "SELECT count(*)::integer AS count FROM pg_roles role WHERE EXISTS (SELECT 1 FROM unnest($1::uuid[]) fixture(id) WHERE left(role.rolname::text,37)='gcr_' || replace(fixture.id::text,'-','') || '_')", [fixtureIds]),
  };
  const gc = poolFor("gestionchurch_control", true); await assertReadOnly(gc);
  absent.gcSourceRegistrations = await count(gc, "SELECT count(*)::integer AS count FROM control.tenants WHERE id=ANY($1::uuid[])", [fixtureIds]);
  absent.gcLaunchCodes = await count(gc, "SELECT count(*)::integer AS count FROM control.module_launch_codes WHERE tenant_id=ANY($1::uuid[])", [fixtureIds]);
  for (const value of Object.values(absent)) assert.equal(value, 0);

  stage = "owned-secret-reference-absence";
  const secretFile = path.resolve(install.DATABASE_SECRET_FILE ?? path.join(localRoot, "secrets.enc.json"));
  assert.equal(path.dirname(secretFile), localRoot); assert.equal(path.basename(secretFile), "secrets.enc.json");
  const secretMetadata = await lstat(secretFile);
  assert.ok(secretMetadata.isFile() && !secretMetadata.isSymbolicLink());
  masterKey = Buffer.from(install.DATABASE_SECRET_MASTER_KEY_B64, "base64url"); assert.equal(masterKey.byteLength, 32);
  const secrets = new EncryptedFileSecretProvider(secretFile, masterKey);
  // hasSecret performs only authenticated reads. Values stay in memory and are
  // never logged. No lock file, putSecret, removeSecret or writeAll is invoked.
  for (const receipt of receipts) assert.equal(await secrets.hasSecret(receipt.secretReference), false);
  assert.equal(idlePoolFailure, false);
  console.log(JSON.stringify({ pass: true, operation: "owned-browser-cleanup-readonly-verification",
    verifiedAt: new Date().toISOString(), mutations: 0, originalRegistryCount: registry.rowCount,
    originalRoutesCanonical: true, ledgers, cleanedOwnedReceiptCount: receipts.length,
    remainingOwnedResources: { ...absent, secretReferences: 0 }, auditRetentionDeclaredByReceipts: true, auditIntegrityVerified: false,
    scope: "original-three-routes-and-only-UUIDs-in-validated-owned-browser-receipts" }));
} catch (error) {
  // Never echo server messages, personal records, parser causes, references,
  // receipt contents, credentials, local key material, or connection URLs.
  console.error(JSON.stringify({ pass: false, operation: "owned-browser-cleanup-readonly-verification", stage,
    code: typeof error?.code === "string" && /^[A-Z0-9_]{3,40}$/u.test(error.code) ? error.code : "GUARD_OR_DATABASE_FAILURE" }));
  process.exitCode = 1;
} finally {
  masterKey?.fill(0);
  await Promise.all(pools.map((pool) => pool.end()));
}

async function assertReadOnly(pool) {
  const result = await pool.query("SELECT current_setting('default_transaction_read_only') AS readonly,current_setting('transaction_read_only') AS transaction_readonly");
  assert.equal(result.rows[0].readonly, "on"); assert.equal(result.rows[0].transaction_readonly, "on");
}
async function verifiedLedger(pool, scope, expectedCount, expectedHead) {
  const plan = await inspectMigrationPlan(pool, { scope, directory: path.join(packageRoot, "migrations", scope) });
  assert.equal(plan.applied.length, expectedCount); assert.equal(plan.applied.at(-1)?.name, expectedHead);
  assert.equal(plan.pending.length, 0);
  return { scope, appliedCount: plan.applied.length, appliedHead: plan.applied.at(-1)?.name, pendingCount: 0, checksumsVerified: true };
}
async function count(pool, sql, values) {
  const result = await pool.query(sql, values); assert.equal(result.rowCount, 1);
  const value = result.rows[0].count; assert.ok(Number.isSafeInteger(value) && value >= 0); return value;
}
