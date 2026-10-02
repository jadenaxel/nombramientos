import type { PoolClient } from "pg";
import { appendTenantAuditEventV2 } from "./audit-event-chain.js";

export interface DeviceHttpSessionBinding {
  readonly sessionId: string;
  readonly identityId: string;
  readonly deviceId: string;
  readonly sourceSessionId: string | null;
  readonly signingFingerprint: string;
  readonly publicJwk: Record<string, unknown>;
  readonly boundAt: string;
  readonly lastSeenAt: string;
  readonly status: "active" | "revoked";
  readonly deviceStatus: "pending" | "active" | "revoked";
  readonly hasActiveGrant: boolean;
}
export class DeviceSessionStore {
  public constructor(private readonly client: PoolClient) {}
  /** Enrich only the caller's already-authorized control-session list. This
   * query runs in the active tenant database; it never discovers sessions or
   * identities from another tenant and does not modify key/session records. */
  public async getOwnSessionLabels(identityId: string, sessionIds: readonly string[]): Promise<ReadonlyMap<string, string>> {
    if (sessionIds.length === 0) return new Map();
    const allowedIds = new Set(sessionIds);
    const result = await this.client.query<{ session_id: string; label: string }>(
      `SELECT binding.session_id,device.label FROM e2ee_http_session_bindings binding
         JOIN e2ee_key_devices device ON device.device_id=binding.device_id AND device.identity_id=binding.identity_id
        WHERE binding.identity_id=$1 AND binding.session_id=ANY($2::uuid[])`,
      [identityId, [...allowedIds]],
    );
    return new Map(result.rows.filter((row) => allowedIds.has(row.session_id) && row.label.trim().length > 0)
      .map((row) => [row.session_id, row.label]));
  }
  public async getDevice(identityId: string, deviceId: string): Promise<{ wrappingPublicKey: Record<string, unknown>; status: string } | null> {
    const result = await this.client.query<{ wrapping_public_key: Record<string, unknown>; status: string }>(
      "SELECT wrapping_public_key,status FROM e2ee_key_devices WHERE device_id=$1 AND identity_id=$2 AND status<>'revoked' FOR SHARE", [deviceId, identityId]);
    return result.rows[0] ? { wrappingPublicKey: result.rows[0].wrapping_public_key, status: result.rows[0].status } : null;
  }
  public async getBinding(identityId: string, sessionId: string): Promise<DeviceHttpSessionBinding | null> {
    const result = await this.client.query<{
      session_id: string; identity_id: string; device_id: string; source_session_id: string | null; signing_fingerprint: string;
      public_jwk: Record<string, unknown>; bound_at: Date; last_seen_at: Date; revoked_at: Date | null; status: string; has_active_grant:boolean;
    }>(`SELECT binding.*,signer.signing_fingerprint,signer.public_jwk,device.status,
        EXISTS(SELECT 1 FROM e2ee_key_grants key_grant JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id
          WHERE key_grant.device_id=binding.device_id AND key_grant.identity_id=binding.identity_id
            AND key_grant.status='active' AND generation.status='active') has_active_grant
        FROM e2ee_http_session_bindings binding
        JOIN e2ee_http_devices signer ON signer.device_id=binding.device_id AND signer.identity_id=binding.identity_id
        JOIN e2ee_key_devices device ON device.device_id=binding.device_id AND device.identity_id=binding.identity_id
        WHERE binding.session_id=$1 AND binding.identity_id=$2`, [sessionId, identityId]);
    const row = result.rows[0];
    return row ? { sessionId: row.session_id, identityId: row.identity_id, deviceId: row.device_id, sourceSessionId: row.source_session_id,
      signingFingerprint: row.signing_fingerprint, publicJwk: row.public_jwk, boundAt: row.bound_at.toISOString(),
      lastSeenAt: row.last_seen_at.toISOString(), status: row.revoked_at || row.status === "revoked" ? "revoked" : "active",deviceStatus:row.status as "pending"|"active"|"revoked",hasActiveGrant:row.has_active_grant } : null;
  }
  public async issueChallenge(input: { id: string; identityId: string; sessionId: string; deviceId: string;
    purpose: "enrollment" | "request"; secretHash?: string; publicJwk?: Record<string, unknown>; context: Record<string, unknown>; expiresAt: string }): Promise<void> {
    // Bound budget lives in SQL, so concurrent HTTP requests cannot overflow it.
    await this.client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`http-device:${input.sessionId}`]);
    const count = await this.client.query<{ count: string }>("SELECT count(*) FROM e2ee_http_challenges WHERE session_id=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()", [input.sessionId]);
    if (Number(count.rows[0]?.count) >= 32) throw new DeviceSessionStoreError("DEVICE_PROOF_BUDGET_EXCEEDED");
    await this.client.query(`INSERT INTO e2ee_http_challenges(id,identity_id,session_id,device_id,purpose,secret_hash,public_jwk,context,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)`,
    [input.id,input.identityId,input.sessionId,input.deviceId,input.purpose,input.secretHash ?? null,JSON.stringify(input.publicJwk ?? null),JSON.stringify(input.context),input.expiresAt]);
  }
  public async readChallenge(id: string, identityId: string, sessionId: string, purpose: string): Promise<{ publicJwk: Record<string, unknown> | null; context: Record<string, unknown>; secretHash: string | null } | null> {
    const result = await this.client.query<{ public_jwk: Record<string, unknown> | null; context: Record<string, unknown>; secret_hash: string | null }>(
      "SELECT public_jwk,context,secret_hash FROM e2ee_http_challenges WHERE id=$1 AND identity_id=$2 AND session_id=$3 AND purpose=$4 AND consumed_at IS NULL AND expires_at>clock_timestamp()", [id,identityId,sessionId,purpose]);
    return result.rows[0] ? { publicJwk: result.rows[0].public_jwk, context: result.rows[0].context, secretHash: result.rows[0].secret_hash } : null;
  }
  public async bindSession(input: { challengeId: string; identityId: string; sessionId: string; deviceId: string;
    sourceSessionId: string | null; signingFingerprint: string; publicJwk: Record<string, unknown>; secretHash: string }): Promise<DeviceHttpSessionBinding> {
    await this.client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`http-device:${input.sessionId}`]);
    const device = await this.getDevice(input.identityId,input.deviceId);
    if (!device) throw new DeviceSessionStoreError("DEVICE_SESSION_REVOKED");
    const consumed = await this.client.query(`UPDATE e2ee_http_challenges SET consumed_at=clock_timestamp()
      WHERE id=$1 AND identity_id=$2 AND session_id=$3 AND device_id=$4 AND purpose='enrollment'
        AND consumed_at IS NULL AND expires_at>clock_timestamp() AND secret_hash=$5
      RETURNING id`, [input.challengeId,input.identityId,input.sessionId,input.deviceId,input.secretHash]);
    if (consumed.rowCount !== 1) throw new DeviceSessionStoreError("DEVICE_PROOF_INVALID");
    await this.client.query(`INSERT INTO e2ee_http_devices(device_id,identity_id,signing_fingerprint,public_jwk)
      VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(device_id) DO NOTHING`, [input.deviceId,input.identityId,input.signingFingerprint,JSON.stringify(input.publicJwk)]);
    const signer = await this.client.query<{ signing_fingerprint: string; identity_id: string }>("SELECT signing_fingerprint,identity_id FROM e2ee_http_devices WHERE device_id=$1", [input.deviceId]);
    if (signer.rows[0]?.signing_fingerprint !== input.signingFingerprint || signer.rows[0]?.identity_id !== input.identityId) throw new DeviceSessionStoreError("DEVICE_SIGNING_KEY_CHANGED");
    await this.client.query(`INSERT INTO e2ee_http_session_bindings(session_id,identity_id,device_id,source_session_id)
      VALUES($1,$2,$3,$4) ON CONFLICT(session_id) DO NOTHING`, [input.sessionId,input.identityId,input.deviceId,input.sourceSessionId]);
    const bound = await this.getBinding(input.identityId,input.sessionId);
    if (!bound || bound.status !== "active" || bound.deviceId !== input.deviceId || bound.signingFingerprint !== input.signingFingerprint
        || bound.sourceSessionId !== input.sourceSessionId) throw new DeviceSessionStoreError("DEVICE_SESSION_ALREADY_BOUND");
    await appendTenantAuditEventV2(this.client, { action: "e2ee.http_session.bound", entityType: "device", entityId: input.deviceId, result: "success", metadata: { deviceId: input.deviceId, signingFingerprint: input.signingFingerprint } });
    return bound;
  }
  public async consumeProof(input: { id: string; identityId: string; sessionId: string; deviceId: string; signingFingerprint: string }): Promise<void> {
    await this.client.query("SELECT pg_advisory_xact_lock_shared(hashtextextended('e2ee_key_lifecycle_v1',0))");
    await this.client.query("SELECT device_id FROM e2ee_key_devices WHERE device_id=$1 AND identity_id=$2 AND status<>'revoked' FOR SHARE",[input.deviceId,input.identityId]);
    const result = await this.client.query(`SELECT binding.session_id FROM e2ee_http_session_bindings binding
      JOIN e2ee_http_devices signer ON signer.device_id=binding.device_id AND signer.identity_id=binding.identity_id
      JOIN e2ee_key_devices device ON device.device_id=binding.device_id AND device.identity_id=binding.identity_id
      WHERE binding.session_id=$1 AND binding.identity_id=$2 AND binding.device_id=$3 AND binding.revoked_at IS NULL
        AND signer.signing_fingerprint=$4 AND device.status<>'revoked'`,
    [input.sessionId,input.identityId,input.deviceId,input.signingFingerprint]);
    if (result.rowCount !== 1) throw new DeviceSessionStoreError("DEVICE_SESSION_REVOKED");
    const used = await this.client.query(`UPDATE e2ee_http_challenges SET consumed_at=clock_timestamp()
      WHERE id=$1 AND identity_id=$2 AND session_id=$3 AND device_id=$4 AND purpose='request'
        AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING id`, [input.id,input.identityId,input.sessionId,input.deviceId]);
    if (used.rowCount !== 1) throw new DeviceSessionStoreError("DEVICE_PROOF_REPLAYED");
    const touched = await this.client.query("UPDATE e2ee_http_session_bindings SET last_seen_at=clock_timestamp() WHERE session_id=$1 AND revoked_at IS NULL RETURNING session_id", [input.sessionId]);
    if (touched.rowCount !== 1) throw new DeviceSessionStoreError("DEVICE_SESSION_REVOKED");
  }
  public async revokedSessionIds(): Promise<readonly string[]> {
    const result = await this.client.query<{ session_id: string }>("SELECT session_id FROM e2ee_http_session_bindings WHERE revoked_at IS NOT NULL");
    return result.rows.map(({ session_id }) => session_id);
  }
  public async appendProofDenial(input: { code: string; method: string; route: string }): Promise<void> {
    if (!/^DEVICE_[A-Z_]{1,80}$/u.test(input.code) || !/^[A-Z]{3,10}$/u.test(input.method)
        || !input.route.startsWith("/v1/") || input.route.length > 1024 || /[?#\r\n]/u.test(input.route)) {
      throw new Error("Invalid device proof denial metadata");
    }
    const context = await this.client.query<{ session_id: string }>(
      "SELECT NULLIF(current_setting('app.session_id',true),'') session_id");
    const sessionId = context.rows[0]?.session_id;
    if (!sessionId) throw new Error("Missing authenticated session audit context");
    await appendTenantAuditEventV2(this.client, { action: "e2ee.http_session.denied", entityType: "auth_session",
      entityId: sessionId, result: "denied", metadata: { code: input.code, method: input.method, route: input.route } });
  }
}

/** Must execute inside the data transaction, before any protected read/write. */
export async function pinProvenDeviceSession(client: PoolClient, identityId: string, sessionId: string, deviceId: string,allowPending=false): Promise<void> {
  const device = await client.query("SELECT device_id FROM e2ee_key_devices WHERE device_id=$1 AND identity_id=$2 AND status<>'revoked' FOR SHARE",[deviceId,identityId]);
  if (device.rowCount !== 1) throw new DeviceSessionStoreError("DEVICE_SESSION_REVOKED");
  const result = await client.query(`SELECT binding.session_id FROM e2ee_http_session_bindings binding
    JOIN e2ee_key_devices device ON device.device_id=binding.device_id AND device.identity_id=binding.identity_id
    WHERE binding.session_id=$1 AND binding.identity_id=$2 AND binding.device_id=$3
      AND binding.revoked_at IS NULL AND device.status<>'revoked'
      ${allowPending ? "" : "AND device.status='active'"}
      ${allowPending ? "" : `AND EXISTS(SELECT 1 FROM e2ee_key_grants key_grant JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id
        WHERE key_grant.device_id=binding.device_id AND key_grant.identity_id=binding.identity_id
          AND key_grant.status='active' AND generation.status='active')`}
    FOR SHARE OF binding`, [sessionId,identityId,deviceId]);
  if (result.rowCount !== 1) throw new DeviceSessionStoreError("DEVICE_SESSION_REVOKED");
}
export class DeviceSessionStoreError extends Error {
  public constructor(public readonly code: string) { super(code); this.name="DeviceSessionStoreError"; }
}
