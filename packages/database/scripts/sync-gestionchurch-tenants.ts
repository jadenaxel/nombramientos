import path from "node:path";
import { catalogPackage2025, validateCatalogPackage } from "@nombramientos/catalog";
import { Pool } from "pg";
import { z } from "zod";
import { TenantProvisioner } from "../src/provisioner.js";
import { EncryptedFileSecretProvider } from "../src/secrets.js";
import {
  loadLocalScriptEnvironment,
  requireMasterKey,
  resolveDatabasePackageRoot,
  withoutDatabase,
} from "./script-config.js";

const gestionChurchTenantSchema = z.object({
  id: z.string().uuid(),
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),
  name: z.string().trim().min(2).max(160),
  timezone: z.string().trim().min(1).max(80),
}).strict();

const environment = loadLocalScriptEnvironment();
const packageRoot = resolveDatabasePackageRoot(import.meta.url);
const gestionChurchUrl = validateGestionChurchControlUrl(
  process.env["GESTIONCHURCH_CONTROL_DATABASE_URL"]
    ?? "postgresql://postgres@127.0.0.1:55432/gestionchurch_control",
);
const secretProvider = new EncryptedFileSecretProvider(
  process.env["DATABASE_SECRET_FILE"] ?? path.join(packageRoot, ".local", "secrets.enc.json"),
  requireMasterKey(environment.DATABASE_SECRET_MASTER_KEY_B64),
);
const control = new Pool({
  connectionString: withoutDatabase(environment.DATABASE_ADMIN_URL, "nombramientos_control"),
  application_name: "nombramientos-gestionchurch-tenant-sync",
  max: 2,
});
const gestionChurch = new Pool({
  connectionString: gestionChurchUrl,
  application_name: "nombramientos-gestionchurch-catalog-read",
  max: 1,
});
const administrator = new URL(environment.DATABASE_ADMIN_URL);
const catalogErrors = validateCatalogPackage(catalogPackage2025);
if (catalogErrors.length > 0) throw new Error(`Catalog package is invalid: ${catalogErrors.join("; ")}`);

const provisioner = new TenantProvisioner({
  admin: {
    host: administrator.hostname,
    port: Number(administrator.port || "5432"),
    user: decodeURIComponent(administrator.username),
    password: decodeURIComponent(administrator.password),
    database: administrator.pathname.slice(1) || "postgres",
    ssl: false,
  },
  catalog: catalogPackage2025,
  control,
  secrets: secretProvider,
  migrationsRoot: path.join(packageRoot, "migrations"),
});

try {
  const discovered = await gestionChurch.query(
    `SELECT id::text,slug,name,timezone
       FROM control.tenants
      WHERE status='ACTIVE'
      ORDER BY slug`,
  );
  const tenants = z.array(gestionChurchTenantSchema).parse(discovered.rows);
  for (const tenant of tenants) {
    const candidate = await control.query<{ id: string; gestionchurch_tenant_id: string | null }>(
      `SELECT id::text,gestionchurch_tenant_id::text
         FROM tenants
        WHERE gestionchurch_tenant_id=$1::uuid
           OR (gestionchurch_tenant_id IS NULL AND (slug=$2 OR lower(display_name)=lower($3)))
        ORDER BY (gestionchurch_tenant_id=$1::uuid) DESC,(slug=$2) DESC
        LIMIT 1`,
      [tenant.id, tenant.slug, tenant.name],
    );
    let nominationTenantId = candidate.rows[0]?.id;
    if (!nominationTenantId) {
      const result = await provisioner.provision({
        idempotencyKey: tenant.id,
        tenantId: tenant.id,
        slug: tenant.slug,
        displayName: tenant.name,
        kind: "real",
        timezone: tenant.timezone,
        locale: "es",
      });
      nominationTenantId = result.tenantId;
    }
    await control.query(
      `UPDATE tenants
          SET gestionchurch_tenant_id=$1::uuid,
              display_name=$2,
              timezone=$3,
              updated_at=clock_timestamp()
        WHERE id=$4::uuid
          AND (gestionchurch_tenant_id IS NULL OR gestionchurch_tenant_id=$1::uuid)`,
      [tenant.id, tenant.name, tenant.timezone, nominationTenantId],
    );
    process.stdout.write(`${tenant.slug}: GestionChurch ${tenant.id} -> Nombramientos ${nominationTenantId}\n`);
  }
  process.stdout.write(`Synchronized ${tenants.length} active GestionChurch tenant(s).\n`);
} finally {
  await provisioner.close();
  await Promise.all([control.end(), gestionChurch.end()]);
}

function validateGestionChurchControlUrl(value: string): string {
  const parsed = new URL(value);
  if (
    !["postgres:", "postgresql:"].includes(parsed.protocol)
    || parsed.hostname !== "127.0.0.1"
    || parsed.port !== "55432"
    || parsed.pathname !== "/gestionchurch_control"
    || parsed.search !== ""
    || parsed.hash !== ""
  ) {
    throw new Error("GESTIONCHURCH_CONTROL_DATABASE_URL must target the local GestionChurch control database on port 55432");
  }
  return value;
}
