import path from "node:path";
import { Pool, type PoolConfig } from "pg";
import { catalogPackage2025, validateCatalogPackage } from "@nombramientos/catalog";
import {
  assertLocalStateAdminUrl,
  CONTROL_DATABASE_NAME,
  DEMO_TENANT_ID,
  localStateFailureSqlState,
  localStateFailureStage,
  OZAMA_TENANT_ID,
  parseLocalStateVerificationArguments,
  serializeSanitizedLocalStateFailure,
  serializeSanitizedLocalStateReport,
  verifyLocalState,
} from "../src/local-state-verifier.js";
import { loadLocalScriptEnvironment, resolveDatabasePackageRoot } from "./script-config.js";

const allowedTenantDatabases = new Set([
  tenantDatabaseName(DEMO_TENANT_ID),
  tenantDatabaseName(OZAMA_TENANT_ID),
]);
const pools: Pool[] = [];
let output = "";
let passed = false;

try {
  const arguments_ = parseLocalStateVerificationArguments(process.argv.slice(2));
  const environment = loadLocalScriptEnvironment();
  const administrator = assertLocalStateAdminUrl(environment.DATABASE_ADMIN_URL);
  const packageRoot = resolveDatabasePackageRoot(import.meta.url);
  const catalogErrors = validateCatalogPackage(catalogPackage2025);
  if (catalogErrors.length !== 0) {
    throw new Error("The production catalog package failed validation");
  }
  const controlPool = createPool(administrator, CONTROL_DATABASE_NAME, "control");
  const report = await verifyLocalState({
    controlPool,
    tenantPool: (databaseName) => {
      if (!allowedTenantDatabases.has(databaseName)) {
        throw new Error("Local state verification refused an unexpected tenant database");
      }
      return createPool(administrator, databaseName, "tenant");
    },
    migrationsRoot: path.join(packageRoot, "migrations"),
    demoFixtureExpectation: arguments_.demoFixtureExpectation,
    catalog: catalogPackage2025,
  });
  output = serializeSanitizedLocalStateReport(report);
  passed = report.pass;
} catch (error) {
  output = serializeSanitizedLocalStateFailure(
    new Date(),
    localStateFailureStage(error),
    localStateFailureSqlState(error),
  );
} finally {
  const closeResults = await Promise.allSettled(pools.map(async (pool) => await pool.end()));
  if (closeResults.some(({ status }) => status === "rejected")) {
    output = serializeSanitizedLocalStateFailure();
    passed = false;
  }
}

process.stdout.write(`${output}\n`);
if (!passed) process.exitCode = 1;

function createPool(administrator: URL, database: string, scope: "control" | "tenant"): Pool {
  const connection: PoolConfig = {
    host: administrator.hostname === "[::1]" ? "::1" : administrator.hostname,
    port: Number(administrator.port),
    user: decodeURIComponent(administrator.username),
    password: decodeURIComponent(administrator.password),
    database,
    ssl: false,
    application_name: `nombramientos-state-verify-${scope}`,
    connectionTimeoutMillis: 2_000,
    statement_timeout: 10_000,
    query_timeout: 12_000,
    max: 1,
  };
  const pool = new Pool(connection);
  pools.push(pool);
  return pool;
}

function tenantDatabaseName(tenantId: string): string {
  return `nom_t_${tenantId.replaceAll("-", "")}`;
}
