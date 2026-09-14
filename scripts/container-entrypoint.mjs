import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import { chmod, lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const command = process.argv[2] ?? "api";
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const databaseLocalRoot = path.join(workspaceRoot, "packages", "database", ".local");
const supportedEnvironments = new Set(["development", "test"]);
const hopByHopHeaders = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
]);

validateContainerBoundary();

switch (command) {
  case "bootstrap":
    await configureRuntime({ admin: true, control: true, masterKey: true, authKey: true });
    await bootstrap();
    break;
  case "api":
    await configureRuntime({ control: true, masterKey: true, authKey: true });
    process.exitCode = await runManaged("node", ["apps/api/dist/src/main.js"]);
    break;
  case "worker":
    await configureRuntime({ admin: true, masterKey: true });
    process.exitCode = await runManaged("node", ["packages/database/dist/scripts/process-provisioning-jobs.js"]);
    break;
  case "web":
    process.exitCode = await runManaged("node", ["apps/web/scripts/start-standalone.mjs"]);
    break;
  case "edge":
    await runEdgeGateway();
    break;
  case "check-worker":
    await configureRuntime({ control: true });
    await checkWorker();
    break;
  case "check-edge":
    await checkEdge();
    break;
  default:
    throw new Error(`Unsupported container command: ${command}`);
}

function validateContainerBoundary() {
  const environment = process.env.NOMBRAMIENTOS_CONTAINER_ENVIRONMENT;
  if (!environment || !supportedEnvironments.has(environment)) {
    throw new Error("Container runtime is limited to explicit development or test environments");
  }
  if ((process.env.NOMBRAMIENTOS_POSTGRES_HOST ?? "127.0.0.1") !== "127.0.0.1") {
    throw new Error("Container runtime preserves the loopback-only PostgreSQL boundary");
  }
  if (parsePort(process.env.NOMBRAMIENTOS_POSTGRES_PORT ?? "55432", "PostgreSQL") !== 55_432) {
    throw new Error("Container runtime requires isolated PostgreSQL port 55432");
  }
}

async function configureRuntime(required) {
  const host = "127.0.0.1";
  const port = 55_432;
  if (required.admin) {
    const password = await readSecret("NOMBRAMIENTOS_POSTGRES_ADMIN_PASSWORD_FILE");
    process.env.DATABASE_ADMIN_URL = postgresUrl("nom_admin", password, host, port, "postgres");
  }
  if (required.control) {
    const password = await readSecret("NOMBRAMIENTOS_CONTROL_PASSWORD_FILE");
    process.env.DATABASE_CONTROL_URL = postgresUrl("nom_control", password, host, port, "nombramientos_control");
  }
  if (required.masterKey) {
    process.env.DATABASE_SECRET_MASTER_KEY_B64 = await readSecret("NOMBRAMIENTOS_DATABASE_MASTER_KEY_FILE", true);
  }
  if (required.authKey) {
    process.env.AUTH_ENCRYPTION_KEY_B64 = await readSecret("NOMBRAMIENTOS_AUTH_KEY_FILE", true);
  }
  process.env.DATABASE_LOCAL_INSTALL_FILE ??= path.join(databaseLocalRoot, "install.json");
  process.env.DATABASE_SECRET_FILE ??= path.join(databaseLocalRoot, "runtime", "secrets.enc.json");
  const runtimeSecretRoot = path.join(databaseLocalRoot, "runtime");
  const configuredSecretFile = path.resolve(process.env.DATABASE_SECRET_FILE);
  if (!configuredSecretFile.startsWith(`${runtimeSecretRoot}${path.sep}`)) {
    throw new Error("Container tenant credentials must stay inside the dedicated runtime-secret mount");
  }
}

async function bootstrap() {
  await mkdir(databaseLocalRoot, { recursive: true, mode: 0o700 });
  await chmod(databaseLocalRoot, 0o700);
  const markerPath = path.join(databaseLocalRoot, "container-bootstrap.json");
  const installPath = path.join(databaseLocalRoot, "install.json");
  const backupKeyPath = path.join(databaseLocalRoot, "backup-keys.json");
  const environment = process.env.NOMBRAMIENTOS_CONTAINER_ENVIRONMENT;
  const runtimeFingerprint = await containerRuntimeFingerprint();
  const configurationDigest = createHash("sha256").update(JSON.stringify({
    environment,
    admin: process.env.DATABASE_ADMIN_URL,
    control: process.env.DATABASE_CONTROL_URL,
    master: process.env.DATABASE_SECRET_MASTER_KEY_B64,
    auth: process.env.AUTH_ENCRYPTION_KEY_B64,
  })).digest("hex");
  const existingMarker = await readJsonIfPresent(markerPath);

  if (existingMarker) {
    assertMarker(existingMarker, configurationDigest, environment, runtimeFingerprint);
    if (existingMarker.status === "completed") {
      await attestBootstrapState();
      await runBootstrapIssuer();
      process.stdout.write("Container bootstrap state was re-attested; existing volumes were left unchanged.\n");
      return;
    }
  } else {
    await assertFreshDatabase();
  }

  const install = {
    version: 1,
    DATABASE_ADMIN_URL: requiredEnvironment("DATABASE_ADMIN_URL"),
    DATABASE_CONTROL_URL: requiredEnvironment("DATABASE_CONTROL_URL"),
    DATABASE_SECRET_MASTER_KEY_B64: requiredEnvironment("DATABASE_SECRET_MASTER_KEY_B64"),
    AUTH_ENCRYPTION_KEY_B64: requiredEnvironment("AUTH_ENCRYPTION_KEY_B64"),
    DATABASE_SECRET_FILE: requiredEnvironment("DATABASE_SECRET_FILE"),
    DATABASE_BACKUP_KEY_FILE: backupKeyPath,
    POSTGRES_BIN: "/opt/nom-postgres-bin",
    API_HOST: "127.0.0.1",
    API_PORT: "4000",
    API_CORS_ORIGINS: requiredEnvironment("API_CORS_ORIGINS"),
    API_COOKIE_SECURE: "false",
    API_SESSION_TTL_SECONDS: requiredEnvironment("API_SESSION_TTL_SECONDS"),
    DATABASE_POOL_MAX_PER_TENANT: requiredEnvironment("DATABASE_POOL_MAX_PER_TENANT"),
    DATABASE_POOL_IDLE_MS: requiredEnvironment("DATABASE_POOL_IDLE_MS"),
  };
  await ensureExactJson(installPath, install);
  await ensureBackupKeyInventory(backupKeyPath);

  const startedAt = typeof existingMarker?.startedAt === "string"
    ? existingMarker.startedAt
    : new Date().toISOString();
  await writeJsonAtomic(markerPath, {
    version: 2,
    environment,
    status: "in_progress",
    configurationDigest,
    runtimeFingerprint,
    startedAt,
  });

  for (const script of [
    "packages/database/dist/scripts/migrate-control.js",
    "packages/database/dist/scripts/provision-tenants.js",
    "packages/database/dist/scripts/seed-demo.js",
  ]) {
    const code = await runManaged("node", [script]);
    if (code !== 0) throw new Error(`Container bootstrap step failed safely: ${path.basename(script)}`);
  }
  await attestBootstrapState();
  await runBootstrapIssuer();

  await writeJsonAtomic(markerPath, {
    version: 2,
    environment,
    status: "completed",
    configurationDigest,
    runtimeFingerprint,
    startedAt,
    completedAt: new Date().toISOString(),
  });
  process.stdout.write("Container bootstrap completed without printing credentials.\n");
}

async function assertFreshDatabase() {
  const server = await psqlScalar({
    user: "nom_admin",
    password: passwordFromUrl(requiredEnvironment("DATABASE_ADMIN_URL")),
    database: "postgres",
    sql: "SELECT current_setting('server_version_num') || ':' || current_setting('port')",
  });
  const [version, port] = server.split(":").map(Number);
  if (!version || version < 180_000 || version >= 190_000 || port !== 55_432) {
    throw new Error("Container bootstrap requires exactly PostgreSQL 18 on isolated port 55432");
  }
  const controlExists = await psqlScalar({
    user: "nom_admin",
    password: passwordFromUrl(requiredEnvironment("DATABASE_ADMIN_URL")),
    database: "postgres",
    sql: "SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname='nombramientos_control') THEN 'yes' ELSE 'no' END",
  });
  if (controlExists !== "no") {
    throw new Error("Control database exists without the matching container bootstrap marker; refusing implicit migration or adoption");
  }
}

async function ensureExactJson(file, expected) {
  const existing = await readJsonIfPresent(file);
  if (existing) {
    if (JSON.stringify(existing) !== JSON.stringify(expected)) {
      throw new Error(`Existing protected state does not match mounted Docker secrets: ${path.basename(file)}`);
    }
    return;
  }
  await writeJsonAtomic(file, expected);
}

async function ensureBackupKeyInventory(file) {
  const existing = await readJsonIfPresent(file);
  if (existing) {
    const active = Array.isArray(existing.keys)
      ? existing.keys.filter((item) => item?.status === "active" && item?.id === existing.activeKeyId)
      : [];
    if (existing.version !== 1 || active.length !== 1 || !isCanonicalKey(active[0]?.keyB64)) {
      throw new Error("Existing backup key inventory is invalid");
    }
    return;
  }
  const id = randomUUID();
  await writeJsonAtomic(file, {
    version: 1,
    activeKeyId: id,
    keys: [{ id, createdAt: new Date().toISOString(), status: "active", keyB64: randomBytes(32).toString("base64url") }],
  });
}

function assertMarker(marker, digest, environment, runtimeFingerprint) {
  if (
    marker.version !== 2
    || marker.environment !== environment
    || !new Set(["in_progress", "completed"]).has(marker.status)
    || marker.configurationDigest !== digest
    || marker.runtimeFingerprint !== runtimeFingerprint
  ) {
    throw new Error("Container bootstrap marker does not match this environment, mounted secret set, or application build");
  }
}

async function runBootstrapIssuer() {
  const script = "packages/database/dist/scripts/issue-platform-admin-bootstrap.js";
  const code = await runManaged("node", [script]);
  if (code !== 0) throw new Error(`Container bootstrap step failed safely: ${path.basename(script)}`);
}

async function containerRuntimeFingerprint() {
  const inventory = {
    controlMigrations: await expectedMigrationLedger("control"),
    tenantMigrations: await expectedMigrationLedger("tenant"),
    buildFiles: {},
  };
  for (const relative of [
    "package.json",
    "pnpm-lock.yaml",
    "scripts/container-entrypoint.mjs",
    "packages/database/dist/src/provisioner.js",
    "apps/api/dist/src/main.js",
    "apps/web/.next/BUILD_ID",
  ]) {
    inventory.buildFiles[relative] = createHash("sha256")
      .update(await readFile(path.join(workspaceRoot, relative)))
      .digest("hex");
  }
  return `sha256:${createHash("sha256").update(JSON.stringify(inventory)).digest("hex")}`;
}

async function expectedMigrationLedger(scope) {
  const directory = path.join(workspaceRoot, "packages", "database", "migrations", scope);
  const names = (await readdir(directory))
    .filter((name) => /^\d+_.+\.sql$/u.test(name))
    .sort((left, right) => left.localeCompare(right));
  return await Promise.all(names.map(async (name) => ({
    name,
    checksum: createHash("sha256").update(await readFile(path.join(directory, name))).digest("hex"),
  })));
}

async function attestBootstrapState() {
  const adminPassword = passwordFromUrl(requiredEnvironment("DATABASE_ADMIN_URL"));
  const server = await psqlScalar({
    user: "nom_admin",
    password: adminPassword,
    database: "postgres",
    sql: "SELECT current_setting('server_version_num') || ':' || current_setting('port')",
  });
  const [version, port] = server.split(":").map(Number);
  if (!version || version < 180_000 || version >= 190_000 || port !== 55_432) {
    throw new Error("Container state attestation requires exactly PostgreSQL 18 on port 55432");
  }

  await attestMigrationLedger("nombramientos_control", "control", adminPassword);
  const routes = await psqlJson({
    user: "nom_admin",
    password: adminPassword,
    database: "nombramientos_control",
    sql: `SELECT COALESCE(json_agg(json_build_object(
      'id',id::text,'kind',kind,'status',status,
      'databaseHost',database_host,'databasePort',database_port,
      'databaseName',database_name::text,'runtimeRole',runtime_role::text,
      'runtimeSecretRef',runtime_secret_ref,'credentialVersion',credential_version
    ) ORDER BY id)::text,'[]') FROM tenants`,
  });
  if (!Array.isArray(routes) || routes.length < 2) {
    throw new Error("Container state attestation requires the provisioned Demo and Ozama routes");
  }
  const expectedAnchors = new Map([
    ["d0000000-0000-4000-8000-000000000001", "demo"],
    ["0a2a0000-0000-4000-8000-000000000001", "real"],
  ]);
  for (const [id, kind] of expectedAnchors) {
    const route = routes.find((candidate) => candidate?.id === id);
    if (!route || route.kind !== kind) throw new Error(`Required container tenant route is unavailable: ${id}`);
  }

  const { EncryptedFileSecretProvider } = await import("../packages/database/dist/src/secrets.js");
  const masterKey = Buffer.from(requiredEnvironment("DATABASE_SECRET_MASTER_KEY_B64"), "base64url");
  if (masterKey.byteLength !== 32) throw new Error("Container database master key must encode 32 bytes");
  const secretProvider = new EncryptedFileSecretProvider(requiredEnvironment("DATABASE_SECRET_FILE"), masterKey);
  const runtimeCredentials = [];
  try {
    for (const route of routes) {
      assertAttestableTenantRoute(route);
      await attestMigrationLedger(route.databaseName, "tenant", adminPassword);
      const suffix = route.id.replaceAll("-", "");
      const ownerRole = `nom_o_${suffix}`;
      const roleState = await psqlJson({
        user: "nom_admin",
        password: adminPassword,
        database: "postgres",
        sql: `SELECT json_build_object(
          'databaseOwner',database_owner.rolname,
          'ownerCanLogin',database_owner.rolcanlogin,
          'ownerSuperuser',database_owner.rolsuper,
          'ownerCreateDb',database_owner.rolcreatedb,
          'ownerCreateRole',database_owner.rolcreaterole,
          'runtimeCanLogin',runtime_role.rolcanlogin,
          'runtimeSuperuser',runtime_role.rolsuper,
          'runtimeCreateDb',runtime_role.rolcreatedb,
          'runtimeCreateRole',runtime_role.rolcreaterole
        )::text
        FROM pg_database database
        JOIN pg_roles database_owner ON database_owner.oid=database.datdba
        JOIN pg_roles runtime_role ON runtime_role.rolname=${sqlLiteral(route.runtimeRole)}
        WHERE database.datname=${sqlLiteral(route.databaseName)}`,
      });
      if (
        roleState?.databaseOwner !== ownerRole
        || roleState.ownerCanLogin !== false
        || roleState.ownerSuperuser !== false
        || roleState.ownerCreateDb !== false
        || roleState.ownerCreateRole !== false
        || roleState.runtimeCanLogin !== true
        || roleState.runtimeSuperuser !== false
        || roleState.runtimeCreateDb !== false
        || roleState.runtimeCreateRole !== false
      ) {
        throw new Error(`Tenant database roles do not satisfy the least-privilege boundary: ${route.id}`);
      }
      const unexpectedOwners = await psqlScalar({
        user: "nom_admin",
        password: adminPassword,
        database: route.databaseName,
        sql: `SELECT count(*)::text FROM (
          SELECT relation.oid
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
          WHERE namespace.nspname='public'
            AND relation.relkind IN ('r','p','S','v','m','f')
            AND relation.relowner<>(SELECT oid FROM pg_roles WHERE rolname=${sqlLiteral(ownerRole)})
            AND NOT EXISTS (
              SELECT 1 FROM pg_depend dependency
              WHERE dependency.classid='pg_class'::regclass
                AND dependency.objid=relation.oid AND dependency.deptype='e'
            )
          UNION ALL
          SELECT routine.oid
          FROM pg_proc routine
          JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
          WHERE namespace.nspname='public'
            AND routine.proowner<>(SELECT oid FROM pg_roles WHERE rolname=${sqlLiteral(ownerRole)})
            AND NOT EXISTS (
              SELECT 1 FROM pg_depend dependency
              WHERE dependency.classid='pg_proc'::regclass
                AND dependency.objid=routine.oid AND dependency.deptype='e'
            )
        ) unexpected`,
      });
      if (unexpectedOwners !== "0") {
        throw new Error(`Tenant application objects are not owned exclusively by the NOLOGIN owner: ${route.id}`);
      }
      const identity = await psqlJson({
        user: "nom_admin",
        password: adminPassword,
        database: route.databaseName,
        sql: "SELECT json_build_object('tenantId',tenant_id::text,'kind',kind)::text FROM tenant_settings WHERE singleton=true",
      });
      if (identity?.tenantId !== route.id || identity.kind !== route.kind) {
        throw new Error(`Tenant database identity does not match its control route: ${route.id}`);
      }
      const runtimePassword = await secretProvider.getSecret(route.runtimeSecretRef);
      const connectedDatabase = await psqlScalar({
        user: route.runtimeRole,
        password: runtimePassword,
        database: route.databaseName,
        sql: "SELECT current_database()",
      });
      if (connectedDatabase !== route.databaseName) {
        throw new Error(`Tenant runtime credential did not connect to its own database: ${route.id}`);
      }
      runtimeCredentials.push({ ...route, password: runtimePassword });
    }
    if (runtimeCredentials.length > 1) {
      const first = runtimeCredentials[0];
      const other = runtimeCredentials.find((candidate) => candidate.databaseName !== first.databaseName);
      if (first && other) {
        await assertPsqlRejected({
          user: first.runtimeRole,
          password: first.password,
          database: other.databaseName,
          sql: "SELECT current_database()",
        });
      }
    }
  } finally {
    masterKey.fill(0);
  }
}

function assertAttestableTenantRoute(route) {
  if (!route || typeof route !== "object" || !/^[0-9a-f-]{36}$/u.test(route.id ?? "")) {
    throw new Error("Container control plane returned a malformed tenant route");
  }
  const suffix = route.id.replaceAll("-", "");
  if (
    !new Set(["demo", "real"]).has(route.kind)
    || typeof route.status !== "string"
    || route.databaseHost !== "127.0.0.1"
    || route.databasePort !== 55_432
    || route.databaseName !== `nom_t_${suffix}`
    || route.runtimeRole !== `nom_r_${suffix}`
    || !Number.isInteger(route.credentialVersion)
    || route.credentialVersion < 1
    || route.runtimeSecretRef !== `tenant-db/${route.id}/runtime/v${route.credentialVersion}`
  ) {
    throw new Error(`Container tenant route violates its deterministic isolation boundary: ${route.id}`);
  }
}

async function attestMigrationLedger(database, scope, adminPassword) {
  const expected = await expectedMigrationLedger(scope);
  const actual = await psqlJson({
    user: "nom_admin",
    password: adminPassword,
    database,
    sql: "SELECT COALESCE(json_agg(json_build_object('name',name,'checksum',checksum) ORDER BY name)::text,'[]') FROM schema_migrations",
  });
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Container ${scope} migration ledger does not match the immutable image inventory`);
  }
}

async function psqlJson(options) {
  const source = await psqlScalar(options);
  try {
    return JSON.parse(source);
  } catch {
    throw new Error("PostgreSQL state attestation returned malformed JSON");
  }
}

async function assertPsqlRejected({ user, password, database, sql }) {
  try {
    await psqlScalar({ user, password, database, sql });
  } catch {
    return;
  }
  throw new Error("A tenant runtime credential connected to another tenant database");
}

function sqlLiteral(value) {
  if (typeof value !== "string" || !/^[a-z0-9_]+$/u.test(value)) {
    throw new Error("Unsafe PostgreSQL attestation identifier");
  }
  return `'${value}'`;
}

async function checkWorker() {
  const healthy = await psqlScalar({
    user: "nom_control",
    password: passwordFromUrl(requiredEnvironment("DATABASE_CONTROL_URL")),
    database: "nombramientos_control",
    sql: `SELECT CASE WHEN EXISTS (
      SELECT 1 FROM platform_worker_status
       WHERE worker_code='tenant-provisioner'
         AND status='running'
         AND heartbeat_at > clock_timestamp() - interval '30 seconds'
    ) THEN 'yes' ELSE 'no' END`,
  });
  if (healthy !== "yes") throw new Error("Provisioning worker heartbeat is stale or unavailable");
}

async function checkEdge() {
  const webPort = parsePort(requiredEnvironment("NOMBRAMIENTOS_EDGE_WEB_PORT"), "edge web");
  const apiPort = parsePort(requiredEnvironment("NOMBRAMIENTOS_EDGE_API_PORT"), "edge API");
  const responses = await Promise.all([
    fetch(`http://127.0.0.1:${webPort}/healthz`, { redirect: "error" }),
    fetch(`http://127.0.0.1:${apiPort}/healthz`),
  ]);
  if (responses.some((response) => !response.ok)) throw new Error("Container edge gateway upstream is unhealthy");
}

async function runEdgeGateway() {
  const webPort = parsePort(requiredEnvironment("NOMBRAMIENTOS_EDGE_WEB_PORT"), "edge web");
  const apiPort = parsePort(requiredEnvironment("NOMBRAMIENTOS_EDGE_API_PORT"), "edge API");
  if (webPort === apiPort || new Set([3_000, 4_000, 55_432]).has(webPort) || new Set([3_000, 4_000, 55_432]).has(apiPort)) {
    throw new Error("Edge ports must be distinct from internal service ports");
  }
  const web = createProxyServer(3_000);
  const api = createProxyServer(4_000);
  await Promise.all([listen(web, webPort), listen(api, apiPort)]);
  process.stdout.write("Container edge gateway is ready on loopback-published ports.\n");
  await new Promise((resolve) => {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      Promise.all([close(web), close(api)]).finally(resolve);
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

function createProxyServer(upstreamPort) {
  return createServer((incoming, outgoing) => {
    const upstream = httpRequest({
      hostname: "127.0.0.1",
      port: upstreamPort,
      method: incoming.method,
      path: incoming.url,
      headers: sanitizeHeaders(incoming.headers),
    }, (response) => {
      outgoing.writeHead(response.statusCode ?? 502, sanitizeHeaders(response.headers));
      response.pipe(outgoing);
    });
    upstream.on("error", () => {
      if (!outgoing.headersSent) {
        outgoing.writeHead(502, { "content-type": "application/json", "cache-control": "no-store" });
      }
      outgoing.end('{"error":"LOCAL_UPSTREAM_UNAVAILABLE"}');
    });
    incoming.on("aborted", () => upstream.destroy());
    incoming.pipe(upstream);
  });
}

function sanitizeHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).filter(([name, value]) =>
    value !== undefined && !hopByHopHeaders.has(name.toLowerCase())));
}

async function listen(server, port) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "0.0.0.0", () => {
      server.off("error", reject);
      resolve();
    });
  });
}

async function close(server) {
  await new Promise((resolve) => server.close(() => resolve()));
}

async function psqlScalar({ user, password, database, sql }) {
  const result = await runCaptured("psql", ["-X", "--no-password", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--command", sql], {
    ...process.env,
    PGHOST: "127.0.0.1",
    PGPORT: "55432",
    PGUSER: user,
    PGPASSWORD: password,
    PGDATABASE: database,
  });
  return result.trim();
}

async function runCaptured(executable, args, env) {
  return await new Promise((resolve, reject) => {
    const child = spawn(executable, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => child.kill("SIGKILL"), 5_000);
    child.stdout.on("data", (chunk) => { stdout += String(chunk).slice(0, 4_096); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk).slice(0, 4_096); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      if (code === 0) resolve(stdout);
      else reject(new Error(`PostgreSQL readiness query failed (${code ?? "signal"}): ${stderr.trim() || "no diagnostic"}`));
    });
  });
}

async function runManaged(executable, args) {
  return await new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd: workspaceRoot, env: process.env, stdio: "inherit" });
    const forward = (signal) => { if (!child.killed) child.kill(signal); };
    const onInt = () => forward("SIGINT");
    const onTerm = () => forward("SIGTERM");
    process.once("SIGINT", onInt);
    process.once("SIGTERM", onTerm);
    child.once("error", (error) => {
      process.off("SIGINT", onInt);
      process.off("SIGTERM", onTerm);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      process.off("SIGINT", onInt);
      process.off("SIGTERM", onTerm);
      resolve(code ?? (signal ? 128 : 1));
    });
  });
}

async function readSecret(variable, key = false) {
  const file = requiredEnvironment(variable);
  if (!path.isAbsolute(file) || !path.resolve(file).startsWith(`${path.parse(file).root}run${path.sep}secrets${path.sep}`)) {
    throw new Error(`${variable} must reference a mounted Docker secret`);
  }
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Unsafe mounted secret: ${variable}`);
  const value = (await readFile(file, "utf8")).trim();
  if (key ? !isCanonicalKey(value) : value.length < 32 || value.length > 256) {
    throw new Error(`Mounted secret has an invalid value: ${variable}`);
  }
  return value;
}

function isCanonicalKey(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) return false;
  const bytes = Buffer.from(value, "base64url");
  const valid = bytes.byteLength === 32 && bytes.toString("base64url") === value;
  bytes.fill(0);
  return valid;
}

function postgresUrl(user, password, host, port, database) {
  const value = new URL("postgresql://localhost");
  value.username = user;
  value.password = password;
  value.hostname = host;
  value.port = String(port);
  value.pathname = `/${database}`;
  return value.toString();
}

function passwordFromUrl(value) {
  return decodeURIComponent(new URL(value).password);
}

function parsePort(value, label) {
  if (!/^[0-9]{1,5}$/u.test(value)) throw new Error(`${label} port must be numeric`);
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1_024 || port > 65_535) throw new Error(`${label} port is outside the allowed range`);
  return port;
}

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required container environment: ${name}`);
  return value;
}

async function readJsonIfPresent(file) {
  try {
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Unsafe protected state path: ${file}`);
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") return null;
    throw error;
  }
}

async function writeJsonAtomic(destination, value) {
  const temporary = `${destination}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, destination);
    await chmod(destination, 0o600);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}
