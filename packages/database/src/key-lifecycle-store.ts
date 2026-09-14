import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { appendTenantAuditEventV2 } from "./audit-event-chain.js";
import {
  KEY_GRANT_REVOKE_REASON_CODES,
  KEY_LOSS_REASON_CODES,
  KEY_ROTATION_REASON_CODES,
  normalizeAllowedReasonCode,
} from "./reason-code.js";

export type KeyLifecycleOperation =
  | "device.register"
  | "grant.initialize"
  | "grant.approve"
  | "grant.revoke"
  | "key.rotate"
  | "key.recover"
  | "key.declare_lost";

export type KeyLifecycleDeviceStatus = "pending" | "active" | "revoked";
export type KeyGenerationStatus = "active" | "retired" | "lost";
export type KeyGrantStatus = "active" | "retired" | "revoked";

export interface KeyLifecycleChallenge {
  readonly challengeId: string;
  readonly operation: KeyLifecycleOperation;
  readonly requestHash: `sha256:${string}`;
  readonly status: "pending" | "consumed";
  readonly expiresAt: string;
}

export interface KeyLifecycleDevice {
  readonly deviceId: string;
  readonly identityId: string;
  readonly label: string;
  readonly wrappingPublicKey: Readonly<Record<string, unknown>>;
  readonly wrappingKeyFingerprint: `sha256:${string}`;
  readonly status: KeyLifecycleDeviceStatus;
  readonly version: number;
  readonly registeredAt: string;
  readonly activatedAt: string | null;
  readonly revokedAt: string | null;
}

export interface KeyGenerationSummary {
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly status: KeyGenerationStatus;
  readonly recoveryKeyFingerprint: `sha256:${string}`;
  readonly createdAt: string;
  readonly retiredAt: string | null;
  readonly lostAt: string | null;
  readonly activeGrantCount: number;
}

export interface KeyLifecycleGrant {
  readonly grantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly identityId: string;
  readonly deviceId: string;
  readonly envelope: Readonly<Record<string, unknown>>;
  readonly envelopeHash: `sha256:${string}`;
  readonly grantKind: "initial" | "admin_approved" | "rotation" | "recovery";
  readonly status: KeyGrantStatus;
  readonly version: number;
  readonly grantedByIdentityId: string;
  readonly createdAt: string;
  readonly retiredAt: string | null;
  readonly revokedAt: string | null;
}

export interface KeyLifecycleState {
  readonly tenantKind: "demo" | "real";
  readonly currentGeneration: KeyGenerationSummary | null;
  readonly generations: readonly KeyGenerationSummary[];
  readonly devices: readonly KeyLifecycleDevice[];
  readonly ownGrants: readonly KeyLifecycleGrant[];
  readonly managedGrants?: readonly KeyLifecycleGrant[];
}

export interface RecoveryVerificationMaterial {
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly recoveryPublicKey: Readonly<Record<string, unknown>>;
  readonly recoveryKeyFingerprint: `sha256:${string}`;
}

export class KeyLifecycleError extends Error {
  public constructor(
    public readonly statusCode: 400 | 403 | 404 | 409 | 410 | 428,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "KeyLifecycleError";
  }
}

interface DeviceRow {
  readonly device_id: string;
  readonly identity_id: string;
  readonly label: string;
  readonly wrapping_public_key: Record<string, unknown>;
  readonly wrapping_key_fingerprint: `sha256:${string}`;
  readonly status: KeyLifecycleDeviceStatus;
  readonly version: number;
  readonly registered_at: Date;
  readonly activated_at: Date | null;
  readonly revoked_at: Date | null;
}

interface GenerationRow {
  readonly id: string;
  readonly tenant_key_id: string;
  readonly generation: number;
  readonly status: KeyGenerationStatus;
  readonly recovery_public_key: Record<string, unknown>;
  readonly recovery_key_fingerprint: `sha256:${string}`;
  readonly created_at: Date;
  readonly retired_at: Date | null;
  readonly lost_at: Date | null;
  readonly active_grant_count?: number;
}

interface GrantRow {
  readonly id: string;
  readonly tenant_key_id: string;
  readonly generation: number;
  readonly identity_id: string;
  readonly device_id: string;
  readonly envelope: Record<string, unknown>;
  readonly envelope_hash: `sha256:${string}`;
  readonly grant_kind: KeyLifecycleGrant["grantKind"];
  readonly status: KeyGrantStatus;
  readonly version: number;
  readonly granted_by_identity_id: string;
  readonly created_at: Date;
  readonly retired_at: Date | null;
  readonly revoked_at: Date | null;
}

const GRANT_SELECT = `
  SELECT key_grant.id,generation.tenant_key_id::text,generation.generation,
         key_grant.identity_id,key_grant.device_id,key_grant.envelope,key_grant.envelope_hash,
         key_grant.grant_kind,key_grant.status,key_grant.version,key_grant.granted_by_identity_id,
         key_grant.created_at,key_grant.retired_at,key_grant.revoked_at
    FROM e2ee_key_grants key_grant
    JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id`;

export function hashKeyLifecycleRequest(value: unknown): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(stableJson(value)).digest("hex")}`;
}

export class KeyLifecycleStore {
  public constructor(private readonly client: PoolClient) {}

  public async issueChallenge(input: {
    readonly actorIdentityId: string;
    readonly sessionId: string;
    readonly operation: KeyLifecycleOperation;
    readonly requestHash: `sha256:${string}`;
    readonly idempotencyKey: string;
    readonly ttlSeconds: number;
  }): Promise<KeyLifecycleChallenge> {
    if (!Number.isSafeInteger(input.ttlSeconds) || input.ttlSeconds < 30 || input.ttlSeconds > 600) {
      throw conflict("CHALLENGE_TTL_INVALID", "Key-lifecycle challenge TTL must be between 30 and 600 seconds");
    }
    const inserted = await this.client.query<{
      id: string; operation: KeyLifecycleOperation; request_hash: `sha256:${string}`;
      status: "pending" | "consumed"; expires_at: Date;
    }>(
      `INSERT INTO e2ee_key_challenges(
         actor_identity_id,session_id,operation,request_hash,idempotency_key,expires_at,request_id
       ) VALUES ($1,$2,$3,$4,$5,clock_timestamp()+($6::int*interval '1 second'),
                 NULLIF(current_setting('app.request_id',true),'')::uuid)
       ON CONFLICT(actor_identity_id,idempotency_key) DO NOTHING
       RETURNING id,operation,request_hash,status,expires_at`,
      [input.actorIdentityId, input.sessionId, input.operation, input.requestHash, input.idempotencyKey, input.ttlSeconds],
    );
    let row = inserted.rows[0];
    if (!row) {
      const existing = await this.client.query<{
        id: string; session_id: string; operation: KeyLifecycleOperation;
        request_hash: `sha256:${string}`; status: "pending" | "consumed"; expires_at: Date;
      }>(
        `SELECT id,session_id,operation,request_hash,status,expires_at
           FROM e2ee_key_challenges
          WHERE actor_identity_id=$1 AND idempotency_key=$2
          FOR UPDATE`,
        [input.actorIdentityId, input.idempotencyKey],
      );
      const replay = existing.rows[0];
      if (
        !replay
        || replay.session_id !== input.sessionId
        || replay.operation !== input.operation
        || replay.request_hash !== input.requestHash
      ) {
        throw conflict("IDEMPOTENCY_CONFLICT", "Challenge idempotency key was reused with different input or session");
      }
      row = replay;
    }
    if (inserted.rowCount === 1) {
      await this.appendAudit("e2ee.challenge.issued", "key_challenge", row.id, "success", {
        operation: row.operation,
        requestHash: row.request_hash,
        expiresAt: row.expires_at.toISOString(),
      });
    }
    return {
      challengeId: row.id,
      operation: row.operation,
      requestHash: row.request_hash,
      status: row.status,
      expiresAt: row.expires_at.toISOString(),
    };
  }

  public async getState(identityId: string, canManage: boolean): Promise<KeyLifecycleState> {
    const settings = await this.client.query<{ kind: "demo" | "real" }>(
      "SELECT kind FROM tenant_settings WHERE singleton=true",
    );
    const tenantKind = settings.rows[0]?.kind;
    if (!tenantKind) throw new Error("Tenant settings are missing");
    const generations = await this.client.query<GenerationRow>(
      `SELECT generation.id,generation.tenant_key_id::text,generation.generation,generation.status,
              generation.recovery_public_key,generation.recovery_key_fingerprint,
              generation.created_at,generation.retired_at,generation.lost_at,
              count(key_grant.id) FILTER (WHERE key_grant.status='active')::int AS active_grant_count
         FROM e2ee_key_generations generation
         LEFT JOIN e2ee_key_grants key_grant ON key_grant.generation_id=generation.id
        GROUP BY generation.id
        ORDER BY generation.generation DESC`,
    );
    const devices = await this.client.query<DeviceRow>(
      `SELECT device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,
              status,version,registered_at,activated_at,revoked_at
         FROM e2ee_key_devices
        WHERE $2::boolean OR identity_id=$1
        ORDER BY registered_at DESC,device_id`,
      [identityId, canManage],
    );
    const grants = await this.client.query<GrantRow>(
      `${GRANT_SELECT}
        WHERE key_grant.identity_id=$1
          AND key_grant.status IN ('active','retired')
        ORDER BY generation.generation DESC,key_grant.created_at DESC`,
      [identityId],
    );
    const managedGrants = canManage
      ? await this.client.query<GrantRow>(
        `${GRANT_SELECT}
          WHERE key_grant.status IN ('active','retired','revoked')
          ORDER BY generation.generation DESC,key_grant.created_at DESC`,
      )
      : null;
    const generationSummaries = generations.rows.map(mapGeneration);
    return {
      tenantKind,
      currentGeneration: generationSummaries.find(({ status }) => status === "active") ?? null,
      generations: generationSummaries,
      devices: devices.rows.map(mapDevice),
      ownGrants: grants.rows.map(mapGrant),
      ...(managedGrants ? { managedGrants: managedGrants.rows.map(mapGrant) } : {}),
    };
  }

  public async getRecoveryVerificationMaterial(tenantKeyId: string): Promise<RecoveryVerificationMaterial> {
    const result = await this.client.query<GenerationRow>(
      `SELECT id,tenant_key_id::text,generation,status,recovery_public_key,recovery_key_fingerprint,
              created_at,retired_at,lost_at
         FROM e2ee_key_generations
        WHERE tenant_key_id=$1`,
      [tenantKeyId],
    );
    const generation = result.rows[0];
    if (!generation) throw notFound("KEY_GENERATION_NOT_FOUND", "Tenant key generation is unavailable");
    if (generation.status === "lost") {
      throw new KeyLifecycleError(410, "TENANT_KEY_PERMANENTLY_LOST", "The tenant key was explicitly declared lost and has no server recovery path");
    }
    if (generation.status !== "active") {
      throw conflict("KEY_GENERATION_NOT_ACTIVE", "Recovery is only available for the active tenant key generation");
    }
    return {
      tenantKeyId: generation.tenant_key_id,
      generation: generation.generation,
      recoveryPublicKey: generation.recovery_public_key,
      recoveryKeyFingerprint: generation.recovery_key_fingerprint,
    };
  }

  public async registerDevice(input: {
    readonly actorIdentityId: string;
    readonly sessionId: string;
    readonly idempotencyKey: string;
    readonly challengeId: string;
    readonly requestHash: `sha256:${string}`;
    readonly deviceId: string;
    readonly label: string;
    readonly wrappingPublicKey: Readonly<Record<string, unknown>>;
    readonly wrappingKeyFingerprint: `sha256:${string}`;
  }): Promise<KeyLifecycleDevice> {
    return this.executeIdempotent(input.actorIdentityId, "e2ee.device.register", input.idempotencyKey, input, async () => {
      await this.consumeChallenge(input, "device.register");
      await this.lockLifecycle();
      await this.assertRealTenant();
      let result;
      try {
        result = await this.client.query<DeviceRow>(
          `INSERT INTO e2ee_key_devices(
             device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint
           ) VALUES ($1,$2,$3,$4,$5)
           RETURNING device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,
                     status,version,registered_at,activated_at,revoked_at`,
          [input.deviceId, input.actorIdentityId, input.label.trim(), input.wrappingPublicKey, input.wrappingKeyFingerprint],
        );
      } catch (error) {
        if (isUniqueViolation(error)) {
          throw conflict("DEVICE_ALREADY_REGISTERED", "Device id or wrapping key is already registered");
        }
        throw error;
      }
      const device = result.rows[0];
      if (!device) throw new Error("Device registration did not return a row");
      await this.emit("e2ee.device.registered", "device", input.deviceId, {
        deviceId: input.deviceId,
        identityId: input.actorIdentityId,
        fingerprint: input.wrappingKeyFingerprint,
        status: device.status,
      });
      await this.appendAudit("e2ee.device.registered", "device", input.deviceId, "success", {
        identityId: input.actorIdentityId,
        fingerprint: input.wrappingKeyFingerprint,
        version: device.version,
      });
      return mapDevice(device);
    });
  }

  public async initializeGrant(input: {
    readonly actorIdentityId: string;
    readonly sessionId: string;
    readonly idempotencyKey: string;
    readonly challengeId: string;
    readonly requestHash: `sha256:${string}`;
    readonly deviceId: string;
    readonly deviceFingerprint: `sha256:${string}`;
    readonly tenantKeyId: string;
    readonly envelope: Readonly<Record<string, unknown>>;
    readonly envelopeHash: `sha256:${string}`;
    readonly recoveryPublicKey: Readonly<Record<string, unknown>>;
    readonly recoveryKeyFingerprint: `sha256:${string}`;
  }): Promise<KeyLifecycleGrant> {
    return this.executeIdempotent(input.actorIdentityId, "e2ee.grant.initialize", input.idempotencyKey, input, async () => {
      await this.consumeChallenge(input, "grant.initialize");
      await this.lockLifecycle();
      await this.assertRealTenant();
      const existing = await this.client.query("SELECT 1 FROM e2ee_key_generations LIMIT 1");
      if (existing.rowCount !== 0) {
        throw conflict("KEY_LIFECYCLE_ALREADY_INITIALIZED", "The tenant already has a key generation");
      }
      await this.requireDevice(input.deviceId, input.actorIdentityId, input.deviceFingerprint, true);
      const generation = await this.client.query<{ id: string; generation: number }>(
        `INSERT INTO e2ee_key_generations(
           tenant_key_id,generation,status,recovery_public_key,recovery_key_fingerprint,created_by_identity_id
         ) VALUES ($1,1,'active',$2,$3,$4)
         RETURNING id,generation`,
        [input.tenantKeyId, input.recoveryPublicKey, input.recoveryKeyFingerprint, input.actorIdentityId],
      );
      const generationRow = generation.rows[0];
      if (!generationRow) throw new Error("Initial key generation did not return a row");
      const grant = await this.insertGrant({
        generationId: generationRow.id,
        tenantKeyId: input.tenantKeyId,
        generation: generationRow.generation,
        identityId: input.actorIdentityId,
        deviceId: input.deviceId,
        envelope: input.envelope,
        envelopeHash: input.envelopeHash,
        grantKind: "initial",
        grantedByIdentityId: input.actorIdentityId,
      });
      await this.activateDevice(input.deviceId);
      await this.emit("e2ee.key.initialized", "key_generation", generationRow.id, {
        tenantKeyId: input.tenantKeyId,
        generation: 1,
        initialDeviceId: input.deviceId,
        recoveryFingerprint: input.recoveryKeyFingerprint,
      });
      await this.appendAudit("e2ee.key.initialized", "key_generation", generationRow.id, "success", {
        tenantKeyId: input.tenantKeyId,
        generation: 1,
        deviceId: input.deviceId,
        deviceFingerprint: input.deviceFingerprint,
        envelopeHash: input.envelopeHash,
        recoveryFingerprint: input.recoveryKeyFingerprint,
      });
      return grant;
    });
  }

  public async approveGrant(input: {
    readonly actorIdentityId: string;
    readonly sessionId: string;
    readonly idempotencyKey: string;
    readonly challengeId: string;
    readonly requestHash: `sha256:${string}`;
    readonly targetIdentityId: string;
    readonly targetDeviceId: string;
    readonly targetDeviceFingerprint: `sha256:${string}`;
    readonly tenantKeyId: string;
    readonly generation: number;
    readonly envelope: Readonly<Record<string, unknown>>;
    readonly envelopeHash: `sha256:${string}`;
  }): Promise<KeyLifecycleGrant> {
    return this.executeIdempotent(input.actorIdentityId, "e2ee.grant.approve", input.idempotencyKey, input, async () => {
      await this.consumeChallenge(input, "grant.approve");
      await this.lockLifecycle();
      const generation = await this.requireGrantableGeneration(input.tenantKeyId);
      if (generation.generation !== input.generation) {
        throw conflict("KEY_GENERATION_CHANGED", "Tenant key generation changed; reload before approving the grant");
      }
      const historical = generation.status === "retired";
      await this.requireActorGrant(input.actorIdentityId, generation.id, historical ? "retired" : "active");
      await this.requireDevice(
        input.targetDeviceId,
        input.targetIdentityId,
        input.targetDeviceFingerprint,
        !historical,
      );
      if (historical) {
        await this.requireTargetCurrentGrant(input.targetIdentityId, input.targetDeviceId);
      }
      const grant = await this.insertGrant({
        generationId: generation.id,
        tenantKeyId: generation.tenant_key_id,
        generation: generation.generation,
        identityId: input.targetIdentityId,
        deviceId: input.targetDeviceId,
        envelope: input.envelope,
        envelopeHash: input.envelopeHash,
        grantKind: "admin_approved",
        grantedByIdentityId: input.actorIdentityId,
        status: historical ? "retired" : "active",
      });
      if (!historical) await this.activateDevice(input.targetDeviceId);
      await this.emit("e2ee.grant.approved", "key_grant", grant.grantId, {
        grantId: grant.grantId,
        tenantKeyId: grant.tenantKeyId,
        generation: grant.generation,
        status: grant.status,
        identityId: input.targetIdentityId,
        deviceId: input.targetDeviceId,
      });
      await this.appendAudit("e2ee.grant.approved", "key_grant", grant.grantId, "success", {
        tenantKeyId: grant.tenantKeyId,
        generation: grant.generation,
        grantStatus: grant.status,
        targetIdentityId: input.targetIdentityId,
        targetDeviceId: input.targetDeviceId,
        targetDeviceFingerprint: input.targetDeviceFingerprint,
        envelopeHash: input.envelopeHash,
      });
      return grant;
    });
  }

  public async revokeGrant(input: {
    readonly actorIdentityId: string;
    readonly sessionId: string;
    readonly idempotencyKey: string;
    readonly challengeId: string;
    readonly requestHash: `sha256:${string}`;
    readonly grantId: string;
    readonly expectedVersion: number;
    readonly reasonCode: string;
    readonly confirmLastActiveGrant: boolean;
  }): Promise<{ readonly grantId: string; readonly version: number; readonly status: "revoked"; readonly activeGrantCount: number }> {
    const reasonCode = requireReasonCode(input.reasonCode, KEY_GRANT_REVOKE_REASON_CODES);
    return this.executeIdempotent(input.actorIdentityId, "e2ee.grant.revoke", input.idempotencyKey, { ...input, reasonCode }, async () => {
      await this.consumeChallenge(input, "grant.revoke");
      await this.lockLifecycle();
      const activeGeneration = await this.requireActiveGeneration();
      await this.requireActorGrant(input.actorIdentityId, activeGeneration.id);
      const target = await this.client.query<{
        id: string; generation_id: string; device_id: string; identity_id: string; version: number; status: KeyGrantStatus;
      }>(
        "SELECT id,generation_id,device_id,identity_id,version,status FROM e2ee_key_grants WHERE id=$1 FOR UPDATE",
        [input.grantId],
      );
      const grant = target.rows[0];
      if (!grant) throw notFound("KEY_GRANT_NOT_FOUND", "Device key grant is unavailable");
      if (grant.generation_id !== activeGeneration.id || grant.status !== "active") {
        throw conflict("KEY_GRANT_NOT_ACTIVE", "Only an active grant for the current generation can be revoked");
      }
      if (grant.version !== input.expectedVersion) {
        throw conflict("VERSION_CONFLICT", "Device key grant changed; reload before retrying");
      }
      const count = await this.activeGrantCount(activeGeneration.id);
      if (count === 1 && !input.confirmLastActiveGrant) {
        throw conflict("LAST_ACTIVE_GRANT_CONFIRMATION_REQUIRED", "Revoking the final online grant requires explicit confirmation and an offline recovery package");
      }
      const updated = await this.client.query<{ version: number }>(
        `UPDATE e2ee_key_grants
            SET status='revoked',version=version+1,revoked_at=clock_timestamp(),
                revoked_by_identity_id=$2,revoke_reason=$3
          WHERE id=$1 AND status='active' AND version=$4
          RETURNING version`,
        [input.grantId, input.actorIdentityId, reasonCode, input.expectedVersion],
      );
      const version = updated.rows[0]?.version;
      if (!version) throw conflict("VERSION_CONFLICT", "Device key grant changed; reload before retrying");
      const remaining = count - 1;
      if (remaining === 0 || !await this.deviceHasActiveGrant(grant.device_id)) {
        await this.client.query(
          `UPDATE e2ee_key_devices
              SET status='revoked',version=version+1,revoked_at=clock_timestamp(),
                  revoked_by_identity_id=$2,revoke_reason=$3
            WHERE device_id=$1 AND status<>'revoked'`,
          [grant.device_id, input.actorIdentityId, reasonCode],
        );
      }
      await this.emit("e2ee.grant.revoked", "key_grant", input.grantId, {
        grantId: input.grantId,
        tenantKeyId: activeGeneration.tenant_key_id,
        identityId: grant.identity_id,
        deviceId: grant.device_id,
        activeGrantCount: remaining,
      });
      await this.appendAudit("e2ee.grant.revoked", "key_grant", input.grantId, "success", {
        tenantKeyId: activeGeneration.tenant_key_id,
        targetIdentityId: grant.identity_id,
        targetDeviceId: grant.device_id,
        previousVersion: input.expectedVersion,
        version,
        activeGrantCount: remaining,
        reasonCode,
      });
      return { grantId: input.grantId, version, status: "revoked", activeGrantCount: remaining };
    });
  }

  public async rotateKey(input: {
    readonly actorIdentityId: string;
    readonly sessionId: string;
    readonly idempotencyKey: string;
    readonly challengeId: string;
    readonly requestHash: `sha256:${string}`;
    readonly expectedTenantKeyId: string;
    readonly expectedGeneration: number;
    readonly newTenantKeyId: string;
    readonly reasonCode: string;
    readonly recoveryPublicKey: Readonly<Record<string, unknown>>;
    readonly recoveryKeyFingerprint: `sha256:${string}`;
    readonly grants: readonly {
      readonly targetIdentityId: string;
      readonly targetDeviceId: string;
      readonly targetDeviceFingerprint: `sha256:${string}`;
      readonly envelope: Readonly<Record<string, unknown>>;
      readonly envelopeHash: `sha256:${string}`;
    }[];
  }): Promise<{ readonly tenantKeyId: string; readonly generation: number; readonly status: "active"; readonly grantCount: number }> {
    const reasonCode = requireReasonCode(input.reasonCode, KEY_ROTATION_REASON_CODES);
    return this.executeIdempotent(input.actorIdentityId, "e2ee.key.rotate", input.idempotencyKey, { ...input, reasonCode }, async () => {
      await this.consumeChallenge(input, "key.rotate");
      await this.lockLifecycle();
      const current = await this.requireActiveGeneration(input.expectedTenantKeyId);
      if (current.generation !== input.expectedGeneration) {
        throw conflict("KEY_GENERATION_CHANGED", "Tenant key generation changed; rebuild every rotation envelope");
      }
      await this.requireActorGrant(input.actorIdentityId, current.id);
      if (input.newTenantKeyId === input.expectedTenantKeyId) {
        throw conflict("KEY_ID_REUSE", "A rotation requires a new tenant key id");
      }
      if (input.grants.length === 0 || !input.grants.some(({ targetIdentityId }) => targetIdentityId === input.actorIdentityId)) {
        throw conflict("ROTATION_ACTOR_GRANT_REQUIRED", "Rotation must retain at least one grant for the approving administrator");
      }
      if (new Set(input.grants.map(({ targetDeviceId }) => targetDeviceId)).size !== input.grants.length) {
        throw conflict("DUPLICATE_DEVICE_GRANT", "Rotation grant targets must be unique");
      }
      for (const grant of input.grants) {
        await this.requireDevice(grant.targetDeviceId, grant.targetIdentityId, grant.targetDeviceFingerprint, false);
      }
      await this.client.query(
        "UPDATE e2ee_key_generations SET status='retired',retired_at=clock_timestamp() WHERE id=$1 AND status='active'",
        [current.id],
      );
      let next;
      try {
        next = await this.client.query<{ id: string; generation: number }>(
          `INSERT INTO e2ee_key_generations(
             tenant_key_id,generation,status,recovery_public_key,recovery_key_fingerprint,
             created_by_identity_id,rotated_from_generation_id,rotation_reason
           ) VALUES ($1,$2,'active',$3,$4,$5,$6,$7)
           RETURNING id,generation`,
          [
            input.newTenantKeyId,
            current.generation + 1,
            input.recoveryPublicKey,
            input.recoveryKeyFingerprint,
            input.actorIdentityId,
            current.id,
            reasonCode,
          ],
        );
      } catch (error) {
        if (isUniqueViolation(error)) throw conflict("KEY_ROTATION_CONFLICT", "Another key rotation already won this race");
        throw error;
      }
      const nextGeneration = next.rows[0];
      if (!nextGeneration) throw new Error("Rotated key generation did not return a row");
      await this.client.query(
        `UPDATE e2ee_key_grants
            SET status='retired',version=version+1,retired_at=clock_timestamp()
          WHERE generation_id=$1 AND status='active'`,
        [current.id],
      );
      for (const requested of input.grants) {
        await this.insertGrant({
          generationId: nextGeneration.id,
          tenantKeyId: input.newTenantKeyId,
          generation: nextGeneration.generation,
          identityId: requested.targetIdentityId,
          deviceId: requested.targetDeviceId,
          envelope: requested.envelope,
          envelopeHash: requested.envelopeHash,
          grantKind: "rotation",
          grantedByIdentityId: input.actorIdentityId,
        });
        await this.activateDevice(requested.targetDeviceId);
      }
      await this.emit("e2ee.key.rotated", "key_generation", nextGeneration.id, {
        previousTenantKeyId: input.expectedTenantKeyId,
        tenantKeyId: input.newTenantKeyId,
        generation: nextGeneration.generation,
        grantCount: input.grants.length,
      });
      await this.appendAudit("e2ee.key.rotated", "key_generation", nextGeneration.id, "success", {
        previousTenantKeyId: input.expectedTenantKeyId,
        tenantKeyId: input.newTenantKeyId,
        generation: nextGeneration.generation,
        grantCount: input.grants.length,
        targetDeviceFingerprints: [...input.grants.map(({ targetDeviceFingerprint }) => targetDeviceFingerprint)].sort(),
        recoveryFingerprint: input.recoveryKeyFingerprint,
        reasonCode,
      });
      return {
        tenantKeyId: input.newTenantKeyId,
        generation: nextGeneration.generation,
        status: "active",
        grantCount: input.grants.length,
      };
    });
  }

  public async recoverGrant(input: {
    readonly actorIdentityId: string;
    readonly sessionId: string;
    readonly idempotencyKey: string;
    readonly challengeId: string;
    readonly requestHash: `sha256:${string}`;
    readonly tenantKeyId: string;
    readonly generation: number;
    readonly recoveryKeyFingerprint: `sha256:${string}`;
    readonly recoveryNonce: string;
    readonly targetIdentityId: string;
    readonly targetDeviceId: string;
    readonly targetDeviceFingerprint: `sha256:${string}`;
    readonly envelope: Readonly<Record<string, unknown>>;
    readonly envelopeHash: `sha256:${string}`;
  }): Promise<KeyLifecycleGrant> {
    return this.executeIdempotent(input.actorIdentityId, "e2ee.key.recover", input.idempotencyKey, input, async () => {
      await this.consumeChallenge(input, "key.recover");
      await this.lockLifecycle();
      const generation = await this.requireActiveGeneration(input.tenantKeyId);
      if (generation.generation !== input.generation) {
        throw conflict("KEY_GENERATION_CHANGED", "Recovery authorization targets a stale tenant-key generation");
      }
      if (generation.recovery_key_fingerprint !== input.recoveryKeyFingerprint) {
        throw new KeyLifecycleError(403, "RECOVERY_SIGNATURE_INVALID", "Recovery key fingerprint does not match this generation");
      }
      await this.requireDevice(input.targetDeviceId, input.targetIdentityId, input.targetDeviceFingerprint, true);
      const grant = await this.insertGrant({
        generationId: generation.id,
        tenantKeyId: generation.tenant_key_id,
        generation: generation.generation,
        identityId: input.targetIdentityId,
        deviceId: input.targetDeviceId,
        envelope: input.envelope,
        envelopeHash: input.envelopeHash,
        grantKind: "recovery",
        grantedByIdentityId: input.actorIdentityId,
        recoveryNonce: input.recoveryNonce,
      });
      await this.activateDevice(input.targetDeviceId);
      await this.emit("e2ee.key.recovered", "key_grant", grant.grantId, {
        grantId: grant.grantId,
        tenantKeyId: input.tenantKeyId,
        targetIdentityId: input.targetIdentityId,
        targetDeviceId: input.targetDeviceId,
      });
      await this.appendAudit("e2ee.key.recovered", "key_grant", grant.grantId, "success", {
        tenantKeyId: input.tenantKeyId,
        targetIdentityId: input.targetIdentityId,
        targetDeviceId: input.targetDeviceId,
        targetDeviceFingerprint: input.targetDeviceFingerprint,
        recoveryFingerprint: input.recoveryKeyFingerprint,
        envelopeHash: input.envelopeHash,
        recoveryNonce: input.recoveryNonce,
      });
      return grant;
    });
  }

  public async declareKeyLost(input: {
    readonly actorIdentityId: string;
    readonly sessionId: string;
    readonly idempotencyKey: string;
    readonly challengeId: string;
    readonly requestHash: `sha256:${string}`;
    readonly tenantKeyId: string;
    readonly confirmation: "PERMANENTLY_LOSE_TENANT_KEY";
    readonly reasonCode: string;
  }): Promise<{ readonly tenantKeyId: string; readonly generation: number; readonly status: "lost"; readonly lostAt: string }> {
    const reasonCode = requireReasonCode(input.reasonCode, KEY_LOSS_REASON_CODES);
    return this.executeIdempotent(input.actorIdentityId, "e2ee.key.declare_lost", input.idempotencyKey, { ...input, reasonCode }, async () => {
      await this.consumeChallenge(input, "key.declare_lost");
      await this.lockLifecycle();
      const generation = await this.requireActiveGeneration(input.tenantKeyId);
      if (await this.activeGrantCount(generation.id) !== 0) {
        throw conflict("ACTIVE_GRANTS_REMAIN", "A tenant key cannot be declared lost while an online grant remains active");
      }
      const updated = await this.client.query<{ lost_at: Date }>(
        `UPDATE e2ee_key_generations
            SET status='lost',lost_at=clock_timestamp(),rotation_reason=$2
          WHERE id=$1 AND status='active'
          RETURNING lost_at`,
        [generation.id, reasonCode],
      );
      const lostAt = updated.rows[0]?.lost_at;
      if (!lostAt) throw conflict("KEY_STATE_CHANGED", "Tenant key generation changed before loss declaration");
      await this.emit("e2ee.key.permanently_lost", "key_generation", generation.id, {
        tenantKeyId: input.tenantKeyId,
        generation: generation.generation,
        status: "lost",
      });
      await this.appendAudit("e2ee.key.permanently_lost", "key_generation", generation.id, "success", {
        tenantKeyId: input.tenantKeyId,
        generation: generation.generation,
        reasonCode,
        noServerRecovery: true,
      });
      return { tenantKeyId: input.tenantKeyId, generation: generation.generation, status: "lost", lostAt: lostAt.toISOString() };
    });
  }

  public async recordDenial(input: {
    readonly action: string;
    readonly entityId: string;
    readonly code: string;
  }): Promise<void> {
    await this.appendAudit(input.action, "key_lifecycle", input.entityId, "denied", { code: input.code });
  }

  private async insertGrant(input: {
    readonly generationId: string;
    readonly tenantKeyId: string;
    readonly generation: number;
    readonly identityId: string;
    readonly deviceId: string;
    readonly envelope: Readonly<Record<string, unknown>>;
    readonly envelopeHash: `sha256:${string}`;
    readonly grantKind: KeyLifecycleGrant["grantKind"];
    readonly grantedByIdentityId: string;
    readonly recoveryNonce?: string;
    readonly status?: Extract<KeyGrantStatus, "active" | "retired">;
  }): Promise<KeyLifecycleGrant> {
    let result;
    try {
      result = await this.client.query<GrantRow>(
        `INSERT INTO e2ee_key_grants(
           generation_id,identity_id,device_id,envelope,envelope_hash,grant_kind,
           granted_by_identity_id,recovery_nonce,status,retired_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,
                   CASE WHEN $9='retired' THEN clock_timestamp() ELSE NULL END)
         RETURNING id,$10::text AS tenant_key_id,$11::int AS generation,
                   identity_id,device_id,envelope,envelope_hash,grant_kind,status,version,
                   granted_by_identity_id,created_at,retired_at,revoked_at`,
        [
          input.generationId, input.identityId, input.deviceId, input.envelope,
          input.envelopeHash, input.grantKind, input.grantedByIdentityId,
          input.recoveryNonce ?? null, input.status ?? "active", input.tenantKeyId, input.generation,
        ],
      );
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw conflict(
          input.recoveryNonce ? "RECOVERY_REPLAYED" : "DEVICE_GRANT_ALREADY_EXISTS",
          input.recoveryNonce
            ? "Recovery nonce or target grant was already consumed"
            : "This device already has a grant for the tenant key generation",
        );
      }
      throw error;
    }
    const row = result.rows[0];
    if (!row) throw new Error("Key grant insertion did not return a row");
    return mapGrant(row);
  }

  private async consumeChallenge(
    input: { readonly actorIdentityId: string; readonly sessionId: string; readonly challengeId: string; readonly requestHash: string },
    operation: KeyLifecycleOperation,
  ): Promise<void> {
    const consumed = await this.client.query(
      `UPDATE e2ee_key_challenges
          SET status='consumed',consumed_at=clock_timestamp()
        WHERE id=$1 AND actor_identity_id=$2 AND session_id=$3
          AND operation=$4 AND request_hash=$5
          AND status='pending' AND expires_at>clock_timestamp()`,
      [input.challengeId, input.actorIdentityId, input.sessionId, operation, input.requestHash],
    );
    if (consumed.rowCount !== 1) {
      throw new KeyLifecycleError(428, "KEY_LIFECYCLE_CHALLENGE_INVALID", "Challenge is expired, consumed, belongs to another session, or does not match the exact request");
    }
  }

  private async assertRealTenant(): Promise<void> {
    const result = await this.client.query<{ kind: "demo" | "real" }>(
      "SELECT kind FROM tenant_settings WHERE singleton=true",
    );
    if (result.rows[0]?.kind !== "real") {
      throw conflict("REAL_TENANT_REQUIRED", "Managed key lifecycle is reserved for real tenants; demo keys remain disposable fixtures");
    }
  }

  private async lockLifecycle(): Promise<void> {
    await this.client.query("SELECT pg_advisory_xact_lock(hashtextextended('e2ee_key_lifecycle_v1',0))");
  }

  private async requireActiveGeneration(tenantKeyId?: string): Promise<GenerationRow> {
    const result = await this.client.query<GenerationRow>(
      `SELECT id,tenant_key_id::text,generation,status,recovery_public_key,recovery_key_fingerprint,
              created_at,retired_at,lost_at
         FROM e2ee_key_generations
        WHERE status='active' ${tenantKeyId === undefined ? "" : "AND tenant_key_id=$1"}
        FOR UPDATE`,
      tenantKeyId === undefined ? [] : [tenantKeyId],
    );
    const generation = result.rows[0];
    if (!generation) {
      const lost = tenantKeyId === undefined ? undefined : await this.client.query(
        "SELECT 1 FROM e2ee_key_generations WHERE tenant_key_id=$1 AND status='lost'",
        [tenantKeyId],
      );
      if (lost?.rowCount === 1) {
        throw new KeyLifecycleError(410, "TENANT_KEY_PERMANENTLY_LOST", "The tenant key was explicitly declared lost and has no server recovery path");
      }
      throw notFound("ACTIVE_KEY_GENERATION_NOT_FOUND", "Active tenant key generation is unavailable");
    }
    return generation;
  }

  private async requireGrantableGeneration(tenantKeyId: string): Promise<GenerationRow> {
    const result = await this.client.query<GenerationRow>(
      `SELECT id,tenant_key_id::text,generation,status,recovery_public_key,recovery_key_fingerprint,
              created_at,retired_at,lost_at
         FROM e2ee_key_generations
        WHERE tenant_key_id=$1
        FOR UPDATE`,
      [tenantKeyId],
    );
    const generation = result.rows[0];
    if (!generation) throw notFound("KEY_GENERATION_NOT_FOUND", "Tenant key generation is unavailable");
    if (generation.status === "lost") {
      throw new KeyLifecycleError(410, "TENANT_KEY_PERMANENTLY_LOST", "The tenant key was explicitly declared lost and has no server recovery path");
    }
    return generation;
  }

  private async requireActorGrant(
    actorIdentityId: string,
    generationId: string,
    status: Extract<KeyGrantStatus, "active" | "retired"> = "active",
  ): Promise<void> {
    const result = await this.client.query(
      `SELECT 1 FROM e2ee_key_grants key_grant
        JOIN e2ee_key_devices device ON device.device_id=key_grant.device_id
       WHERE key_grant.generation_id=$1 AND key_grant.identity_id=$2 AND key_grant.status=$3
         AND device.status='active'
       LIMIT 1
       FOR SHARE OF key_grant,device`,
      [generationId, actorIdentityId, status],
    );
    if (result.rowCount !== 1) {
      throw new KeyLifecycleError(
        403,
        "AUTHORIZED_ADMIN_GRANT_REQUIRED",
        status === "retired"
          ? "An authorized administrator with an exact retired-generation grant is required for historical delegation"
          : "An authorized administrator device grant is required for this operation",
      );
    }
  }

  private async requireTargetCurrentGrant(identityId: string, deviceId: string): Promise<void> {
    const result = await this.client.query(
      `SELECT 1
         FROM e2ee_key_generations generation
         JOIN e2ee_key_grants key_grant ON key_grant.generation_id=generation.id
         JOIN e2ee_key_devices device
           ON device.device_id=key_grant.device_id AND device.identity_id=key_grant.identity_id
        WHERE generation.status='active'
          AND key_grant.identity_id=$1 AND key_grant.device_id=$2
          AND key_grant.status='active' AND device.status='active'
        LIMIT 1
        FOR SHARE OF generation,key_grant,device`,
      [identityId, deviceId],
    );
    if (result.rowCount !== 1) {
      throw conflict(
        "CURRENT_KEY_GRANT_REQUIRED",
        "The target device must have an active grant for the current tenant-key generation before receiving history",
      );
    }
  }

  private async requireDevice(
    deviceId: string,
    identityId: string,
    fingerprint: string,
    allowPending: boolean,
  ): Promise<DeviceRow> {
    const result = await this.client.query<DeviceRow>(
      `SELECT device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,
              status,version,registered_at,activated_at,revoked_at
         FROM e2ee_key_devices
        WHERE device_id=$1 AND identity_id=$2
        FOR UPDATE`,
      [deviceId, identityId],
    );
    const device = result.rows[0];
    if (!device) throw notFound("KEY_DEVICE_NOT_FOUND", "Registered target device is unavailable");
    if (device.wrapping_key_fingerprint !== fingerprint) {
      throw conflict("DEVICE_FINGERPRINT_MISMATCH", "Target device fingerprint changed or does not match the envelope");
    }
    if (device.status === "revoked" || (!allowPending && device.status !== "active")) {
      throw conflict("KEY_DEVICE_NOT_ACTIVE", "Target device is revoked or not active for this operation");
    }
    return device;
  }

  private async activateDevice(deviceId: string): Promise<void> {
    await this.client.query(
      `UPDATE e2ee_key_devices
          SET status='active',activated_at=COALESCE(activated_at,clock_timestamp()),version=version+1
        WHERE device_id=$1 AND status='pending'`,
      [deviceId],
    );
  }

  private async activeGrantCount(generationId: string): Promise<number> {
    const result = await this.client.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM e2ee_key_grants WHERE generation_id=$1 AND status='active'",
      [generationId],
    );
    return result.rows[0]?.count ?? 0;
  }

  private async deviceHasActiveGrant(deviceId: string): Promise<boolean> {
    const result = await this.client.query(
      "SELECT 1 FROM e2ee_key_grants WHERE device_id=$1 AND status='active' LIMIT 1",
      [deviceId],
    );
    return result.rowCount === 1;
  }

  private async executeIdempotent<T>(
    identityId: string,
    operation: string,
    idempotencyKey: string,
    request: unknown,
    work: () => Promise<T>,
  ): Promise<T> {
    const requestHash = hashKeyLifecycleRequest(request);
    const inserted = await this.client.query(
      `INSERT INTO idempotency_records(identity_id,operation,idempotency_key,request_hash)
       VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
      [identityId, operation, idempotencyKey, requestHash],
    );
    if (inserted.rowCount === 0) {
      const existing = await this.client.query<{ request_hash: string; response_body: T | null }>(
        `SELECT request_hash,response_body FROM idempotency_records
          WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
        [identityId, operation, idempotencyKey],
      );
      const row = existing.rows[0];
      if (!row || row.request_hash !== requestHash) {
        throw conflict("IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different key-lifecycle input");
      }
      if (row.response_body === null) {
        throw conflict("IDEMPOTENCY_IN_PROGRESS", "Original key-lifecycle operation is still in progress");
      }
      return row.response_body;
    }
    const response = await work();
    await this.client.query(
      `UPDATE idempotency_records SET response_status=200,response_body=$4
        WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3`,
      [identityId, operation, idempotencyKey, response],
    );
    return response;
  }

  private async emit(
    eventType: string,
    aggregateType: string,
    aggregateId: string,
    payload: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.client.query(
      `INSERT INTO outbox_events(audience,event_type,aggregate_type,aggregate_id,payload)
       VALUES ('tenant.authorized',$1,$2,$3,$4)`,
      [eventType, aggregateType, aggregateId, payload],
    );
  }

  private async appendAudit(
    action: string,
    entityType: string,
    entityId: string,
    result: "success" | "denied" | "failure",
    metadata: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await appendTenantAuditEventV2(this.client, { action, entityType, entityId, result, metadata });
  }
}

function mapDevice(row: DeviceRow): KeyLifecycleDevice {
  return {
    deviceId: row.device_id,
    identityId: row.identity_id,
    label: row.label,
    wrappingPublicKey: row.wrapping_public_key,
    wrappingKeyFingerprint: row.wrapping_key_fingerprint,
    status: row.status,
    version: row.version,
    registeredAt: row.registered_at.toISOString(),
    activatedAt: row.activated_at?.toISOString() ?? null,
    revokedAt: row.revoked_at?.toISOString() ?? null,
  };
}

function mapGeneration(row: GenerationRow): KeyGenerationSummary {
  return {
    tenantKeyId: row.tenant_key_id,
    generation: row.generation,
    status: row.status,
    recoveryKeyFingerprint: row.recovery_key_fingerprint,
    createdAt: row.created_at.toISOString(),
    retiredAt: row.retired_at?.toISOString() ?? null,
    lostAt: row.lost_at?.toISOString() ?? null,
    activeGrantCount: row.active_grant_count ?? 0,
  };
}

function mapGrant(row: GrantRow): KeyLifecycleGrant {
  return {
    grantId: row.id,
    tenantKeyId: row.tenant_key_id,
    generation: row.generation,
    identityId: row.identity_id,
    deviceId: row.device_id,
    envelope: row.envelope,
    envelopeHash: row.envelope_hash,
    grantKind: row.grant_kind,
    status: row.status,
    version: row.version,
    grantedByIdentityId: row.granted_by_identity_id,
    createdAt: row.created_at.toISOString(),
    retiredAt: row.retired_at?.toISOString() ?? null,
    revokedAt: row.revoked_at?.toISOString() ?? null,
  };
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function conflict(code: string, message: string): KeyLifecycleError {
  return new KeyLifecycleError(409, code, message);
}

function requireReasonCode(value: string, allowed: readonly string[]): string {
  const reasonCode = normalizeAllowedReasonCode(value, allowed);
  if (!reasonCode) throw conflict("INVALID_REASON_CODE", "Operational reason code is not allowed for this operation");
  return reasonCode;
}

function notFound(code: string, message: string): KeyLifecycleError {
  return new KeyLifecycleError(404, code, message);
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}
