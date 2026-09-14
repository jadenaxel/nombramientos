import { createHash, randomBytes } from "node:crypto";
import type { Pool } from "pg";
import type { SecretProvider, TenantKind, WritableSecretProvider } from "./types.js";

export interface InitialAdminCapabilitySecrets {
  readonly apply: string;
  readonly cleanup: string;
}

export function initialAdminCapabilitySecretReferences(tenantId: string): {
  readonly apply: string;
  readonly cleanup: string;
} {
  return {
    apply: `tenant-db/${tenantId}/initial-admin/apply/v1`,
    cleanup: `tenant-db/${tenantId}/initial-admin/cleanup/v1`,
  };
}

export async function readInitialAdminCapabilitySecrets(
  provider: SecretProvider,
  tenantId: string,
): Promise<InitialAdminCapabilitySecrets> {
  const references = initialAdminCapabilitySecretReferences(tenantId);
  const [apply, cleanup] = await Promise.all([
    provider.getSecret(references.apply),
    provider.getSecret(references.cleanup),
  ]);
  assertCapabilitySecret(apply);
  assertCapabilitySecret(cleanup);
  if (apply === cleanup) throw new Error("Initial administrator capability duties must use distinct secrets");
  return { apply, cleanup };
}

/**
 * Establishes the hash-only tenant verifier from an out-of-database secret
 * provider. This runs only in owner-operated provisioning/maintenance, never
 * under the tenant runtime role.
 */
export async function ensureInitialAdminActivationCapability(
  pool: Pool,
  provider: WritableSecretProvider,
  tenantId: string,
  expectedKind: TenantKind,
): Promise<"created" | "verified" | "not_applicable"> {
  const inventory = await pool.query<{
    tenant_id: string;
    kind: TenantKind;
    binding_count: number;
    apply_secret_hash: string | null;
    cleanup_secret_hash: string | null;
  }>(
    `SELECT settings.tenant_id::text,settings.kind,
            (SELECT count(*)::int FROM role_bindings) AS binding_count,
            capability.apply_secret_hash,capability.cleanup_secret_hash
       FROM tenant_settings settings
       LEFT JOIN initial_admin_activation_capability capability ON capability.singleton=true
      WHERE settings.singleton=true`,
  );
  const row = inventory.rows[0];
  if (!row || inventory.rowCount !== 1 || row.tenant_id !== tenantId || row.kind !== expectedKind) {
    throw new Error("Initial administrator capability tenant identity is inconsistent");
  }
  if (row.kind === "demo") {
    if (row.apply_secret_hash !== null || row.cleanup_secret_hash !== null) {
      throw new Error("Demo tenants must not contain an initial administrator capability");
    }
    return "not_applicable";
  }

  const references = initialAdminCapabilitySecretReferences(tenantId);
  if (row.apply_secret_hash !== null || row.cleanup_secret_hash !== null) {
    if (row.apply_secret_hash === null || row.cleanup_secret_hash === null) {
      throw new Error("Initial administrator capability verifier is incomplete");
    }
    const secrets = await readInitialAdminCapabilitySecrets(provider, tenantId);
    if (sha256(secrets.apply) !== row.apply_secret_hash || sha256(secrets.cleanup) !== row.cleanup_secret_hash) {
      throw new Error("Initial administrator capability preimages do not match the tenant verifier");
    }
    return "verified";
  }
  if (row.binding_count !== 0) return "not_applicable";

  const applySecret = await getOrCreateSecret(provider, references.apply);
  const cleanupSecret = await getOrCreateSecret(provider, references.cleanup);
  if (applySecret === cleanupSecret) throw new Error("Initial administrator capability duties must use distinct secrets");
  const inserted = await pool.query(
    `INSERT INTO initial_admin_activation_capability(
       apply_secret_hash,cleanup_secret_hash
     ) VALUES ($1,$2)
     ON CONFLICT(singleton) DO NOTHING`,
    [sha256(applySecret), sha256(cleanupSecret)],
  );
  if (inserted.rowCount !== 1) {
    const verified = await readInitialAdminCapabilitySecrets(provider, tenantId);
    const current = await pool.query<{ apply_secret_hash: string; cleanup_secret_hash: string }>(
      `SELECT apply_secret_hash,cleanup_secret_hash
         FROM initial_admin_activation_capability WHERE singleton=true`,
    );
    if (
      current.rows[0]?.apply_secret_hash !== sha256(verified.apply)
      || current.rows[0]?.cleanup_secret_hash !== sha256(verified.cleanup)
    ) {
      throw new Error("Concurrent initial administrator capability establishment disagreed");
    }
    return "verified";
  }
  return "created";
}

export async function initialAdminActivationCapabilityIsReady(
  pool: Pool,
  provider: WritableSecretProvider,
  tenantId: string,
  expectedKind: TenantKind,
): Promise<boolean> {
  const relation = await pool.query<{ exists: boolean }>(
    "SELECT to_regclass('public.initial_admin_activation_capability') IS NOT NULL AS exists",
  );
  if (relation.rows[0]?.exists !== true) return false;
  const inventory = await pool.query<{
    tenant_id: string;
    kind: TenantKind;
    binding_count: number;
    apply_secret_hash: string | null;
    cleanup_secret_hash: string | null;
  }>(
    `SELECT settings.tenant_id::text,settings.kind,
            (SELECT count(*)::int FROM role_bindings) AS binding_count,
            capability.apply_secret_hash,capability.cleanup_secret_hash
       FROM tenant_settings settings
       LEFT JOIN initial_admin_activation_capability capability ON capability.singleton=true
      WHERE settings.singleton=true`,
  );
  const row = inventory.rows[0];
  if (!row || inventory.rowCount !== 1 || row.tenant_id !== tenantId || row.kind !== expectedKind) return false;
  if (row.kind === "demo") return row.apply_secret_hash === null && row.cleanup_secret_hash === null;
  if (row.apply_secret_hash === null && row.cleanup_secret_hash === null) return row.binding_count !== 0;
  if (row.apply_secret_hash === null || row.cleanup_secret_hash === null) return false;
  try {
    const secrets = await readInitialAdminCapabilitySecrets(provider, tenantId);
    return sha256(secrets.apply) === row.apply_secret_hash && sha256(secrets.cleanup) === row.cleanup_secret_hash;
  } catch {
    return false;
  }
}

async function getOrCreateSecret(provider: WritableSecretProvider, reference: string): Promise<string> {
  if (await provider.hasSecret(reference)) {
    const existing = await provider.getSecret(reference);
    assertCapabilitySecret(existing);
    return existing;
  }
  const created = randomBytes(32).toString("base64url");
  await provider.putSecret(reference, created);
  return created;
}

function assertCapabilitySecret(value: string): void {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    throw new Error("Initial administrator capability secret has an invalid shape");
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
