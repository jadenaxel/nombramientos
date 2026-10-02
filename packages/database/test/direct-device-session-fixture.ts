import { createHash, generateKeyPairSync } from "node:crypto";
import type { PoolClient } from "pg";

/**
 * Trusted direct-SQL test context only. HTTP cryptographic verification is
 * tested through real HPKE + signed requests in the API/live D10 harness.
 * Refuses all installed/business databases, including real Ozama/Central.
 */
export async function bindDirectFixtureSession(client: PoolClient, exactDeviceId?: string): Promise<void> {
  const context = await client.query<{ database_name: string; identity_id: string; session_id: string }>(`SELECT
    current_database() database_name,current_setting('app.identity_id',true) identity_id,
    current_setting('app.session_id',true) session_id`);
  const row = context.rows[0];
  if (!row || !/^nom_(?:qual_test_[0-9a-f]{24}|photo_test_[ab]_[0-9a-f]{32}|test_catalog_[0-9a-f]{12}|test_eligibility_[0-9a-f]{32}|workflow_test_[0-9a-f_]{36}|key_lifecycle_[0-9a-f]{20})$/u.test(row.database_name)) {
    throw new Error("Direct device fixture refused a non-ephemeral database");
  }
  const existing = await client.query<{ device_id: string }>(
    "SELECT device_id FROM e2ee_http_session_bindings WHERE session_id=$1 AND identity_id=$2", [row.session_id,row.identity_id]);
  let deviceId = existing.rows[0]?.device_id;
  if (deviceId && exactDeviceId && deviceId !== exactDeviceId) throw new Error("Direct fixture session cannot be rebound");
  if (!deviceId) {
    const devices = await client.query<{ device_id: string }>(
      "SELECT device_id FROM e2ee_key_devices WHERE identity_id=$1 AND status<>'revoked' AND ($2::uuid IS NULL OR device_id=$2)", [row.identity_id,exactDeviceId ?? null]);
    if (devices.rowCount === 0) return; // Registration has no owned wrapping device yet.
    if (devices.rowCount !== 1) throw new Error("Direct fixture requires an exact unambiguous device");
    deviceId = devices.rows[0]!.device_id;
    const exported = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" });
    const publicJwk = { crv: "P-256", kty: "EC", x: exported.x, y: exported.y };
    const fingerprint = `sha256:${createHash("sha256").update(JSON.stringify(publicJwk)).digest("hex")}`;
    await client.query(`INSERT INTO e2ee_http_devices(device_id,identity_id,public_jwk,signing_fingerprint)
      VALUES($1,$2,$3,$4) ON CONFLICT(device_id) DO NOTHING`, [deviceId,row.identity_id,publicJwk,fingerprint]);
    await client.query(`INSERT INTO e2ee_http_session_bindings(session_id,identity_id,device_id)
      VALUES($1,$2,$3) ON CONFLICT(session_id) DO NOTHING`, [row.session_id,row.identity_id,deviceId]);
  }
  await client.query("SELECT set_config('app.proven_device_id',$1,true)", [deviceId]);
}
