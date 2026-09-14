import type { PoolClient } from "pg";

export type ContentKeyEnvelopeReference = {
  readonly keyId: string;
};

export type WritableTenantContentKey = {
  readonly tenantKind: "demo" | "real";
  readonly tenantKeyId: string;
};

export class ContentKeyWriteGuardError extends Error {
  public constructor(
    public readonly code: "KEY_GRANT_REQUIRED" | "ENVELOPE_KEY_MISMATCH",
    message: string,
  ) {
    super(message);
    this.name = "ContentKeyWriteGuardError";
  }

  public readonly statusCode = 409 as const;
}

/**
 * Pins the tenant kind and, for real tenants, every lifecycle row that
 * authorizes an encrypted write until the caller's transaction commits. Call
 * this from the same transaction that persists the envelopes; an API preflight
 * is not enough.
 *
 * The authenticated session currently identifies a person, not a physical
 * E2EE device. For real tenants this therefore proves that the identity has at
 * least one active device/grant for the active generation; it is not a
 * cryptographic proof that this HTTP request came from that device.
 */
export async function assertWritableTenantContentKey(
  client: PoolClient,
  input: {
    readonly identityId: string;
    readonly envelopes: readonly (ContentKeyEnvelopeReference | null | undefined)[];
  },
): Promise<WritableTenantContentKey | null> {
  const keyIds = [...new Set(input.envelopes.flatMap((envelope) => envelope ? [envelope.keyId] : []))];
  if (keyIds.length === 0) return null;

  const settings = await client.query<{ kind: "demo" | "real" }>(
    "SELECT kind FROM tenant_settings WHERE singleton=true FOR SHARE",
  );
  const tenantKind = settings.rows[0]?.kind;
  if (!tenantKind) throw new Error("Tenant settings are missing");

  const result = tenantKind === "real"
    ? await client.query<{ tenant_key_id: string }>(
        `SELECT generation.tenant_key_id::text
           FROM e2ee_key_generations generation
           JOIN e2ee_key_grants key_grant ON key_grant.generation_id=generation.id
           JOIN e2ee_key_devices device
             ON device.device_id=key_grant.device_id
            AND device.identity_id=key_grant.identity_id
          WHERE generation.status='active'
            AND key_grant.status='active'
            AND device.status='active'
            AND key_grant.identity_id=$1
          ORDER BY key_grant.created_at DESC,key_grant.id DESC
          LIMIT 1
          FOR SHARE OF generation,key_grant,device`,
        [input.identityId],
      )
    : await client.query<{ tenant_key_id: string }>(
        // Legacy Demo grants are privileged bootstrap data and runtime-read-only.
        // Demo maintenance runs while the app is stopped, so requesting a row
        // lock here would add no concurrency protection and would incorrectly
        // require granting UPDATE on device_key_grants to the runtime role.
        `SELECT tenant_key_id
           FROM device_key_grants
          WHERE identity_id=$1 AND status='active'
          ORDER BY created_at DESC,id DESC
          LIMIT 1`,
        [input.identityId],
      );

  const tenantKeyId = result.rows[0]?.tenant_key_id;
  if (!tenantKeyId) {
    throw new ContentKeyWriteGuardError(
      "KEY_GRANT_REQUIRED",
      "An active tenant key grant is required",
    );
  }
  if (keyIds.some((keyId) => keyId !== tenantKeyId)) {
    throw new ContentKeyWriteGuardError(
      "ENVELOPE_KEY_MISMATCH",
      "Every envelope must use the current tenant key",
    );
  }
  return { tenantKind, tenantKeyId };
}
