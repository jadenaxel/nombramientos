import path from "node:path";
import { catalogPackage2025, validateCatalogPackage } from "@nombramientos/catalog";
import { Pool } from "pg";
import { EncryptedFileSecretProvider } from "../src/secrets.js";
import { TenantProvisioner } from "../src/provisioner.js";
import { loadLocalScriptEnvironment, requireMasterKey, resolveDatabasePackageRoot, withoutDatabase } from "./script-config.js";

const environment = loadLocalScriptEnvironment();
const packageRoot = resolveDatabasePackageRoot(import.meta.url);
const secretProvider = new EncryptedFileSecretProvider(
  process.env["DATABASE_SECRET_FILE"] ?? path.join(packageRoot, ".local", "secrets.enc.json"),
  requireMasterKey(environment.DATABASE_SECRET_MASTER_KEY_B64),
);
const controlUrl = withoutDatabase(environment.DATABASE_ADMIN_URL, "nombramientos_control");
const control = new Pool({ connectionString: controlUrl, application_name: "nombramientos-control-provision", max: 2 });
const adminUrl = new URL(environment.DATABASE_ADMIN_URL);
const catalogErrors = validateCatalogPackage(catalogPackage2025);
if (catalogErrors.length > 0) {
  throw new Error(`Catalog package is invalid: ${catalogErrors.join("; ")}`);
}
const provisioner = new TenantProvisioner({
  admin: {
    host: adminUrl.hostname,
    port: Number(adminUrl.port || "5432"),
    user: decodeURIComponent(adminUrl.username),
    password: decodeURIComponent(adminUrl.password),
    database: adminUrl.pathname.slice(1) || "postgres",
    ssl: false,
  },
  catalog: catalogPackage2025,
  control,
  secrets: secretProvider,
  migrationsRoot: path.join(packageRoot, "migrations"),
});

try {
  const results = [];
  results.push(await provisioner.provision({
    idempotencyKey: "10000000-0000-4000-8000-000000000001",
    tenantId: "d0000000-0000-4000-8000-000000000001",
    slug: "iglesia-demostracion",
    displayName: "Iglesia Demostración",
    kind: "demo",
    timezone: "America/Santo_Domingo",
    locale: "es",
  }));
  results.push(await provisioner.provision({
    idempotencyKey: "10000000-0000-4000-8000-000000000002",
    tenantId: "0a2a0000-0000-4000-8000-000000000001",
    slug: "iglesia-adventista-ozama",
    displayName: "Iglesia Adventista Ozama",
    kind: "real",
    timezone: "America/Santo_Domingo",
    locale: "es",
  }));
  for (const result of results) {
    process.stdout.write(
      `${result.tenantId}: tenant=${result.tenantStatus}; provisioning=${result.state}${result.reused ? " (existing tenant preserved; no reprovision or upgrade)" : ""}\n`,
    );
  }
  process.stdout.write("Ozama contains configuration/catalog metadata only; no operational rows were seeded.\n");
} finally {
  await provisioner.close();
  await control.end();
}
