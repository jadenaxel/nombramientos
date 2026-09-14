import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type {
  SessionBinding,
  SessionRecord,
  TenantCredentialRecord,
  TenantKind,
  TenantProvisionRequest,
} from "./types.js";
import type { AuthenticationAssuranceLevel, AuthenticationMethod } from "./enterprise-auth-store.js";

export interface LoginIdentity {
  readonly identityId: string;
  readonly email: string;
  readonly displayName: string;
  readonly passwordHash: string;
  readonly passwordProvisioned: boolean;
  readonly mfaEnabled: boolean;
  readonly mfaRequired: boolean;
  readonly passkeyEnabled: boolean;
  readonly strongAuthEnabled: boolean;
  readonly totpSecretCiphertext: string | null;
  readonly tenantId: string;
  readonly lockedUntil: Date | null;
}

export interface MfaChallengeRecord {
  readonly challengeId: string;
  readonly identityId: string;
  readonly tenantId: string;
  readonly totpSecretCiphertext: string;
  readonly attemptCount: number;
  readonly expiresAt: Date;
}

export interface SessionCreateInput {
  readonly tokenHash: string;
  readonly csrfHash: string;
  readonly identityId: string;
  readonly tenantId: string;
  readonly expiresAt: Date;
  readonly assuranceLevel: AuthenticationAssuranceLevel;
  readonly authMethod?: AuthenticationMethod;
  readonly aal?: 1 | 2 | 3;
  readonly phishingResistant?: boolean;
  readonly credentialId?: string;
  readonly recoveryLimited?: boolean;
  readonly idleTimeoutMinutes?: number;
  readonly deviceLabel?: string;
  readonly userAgentHash?: string;
  readonly ipPrefixHash?: string;
}

export interface PlatformTenantSummary {
  readonly id: string;
  readonly slug: string;
  readonly displayName: string;
  readonly kind: TenantKind;
  readonly status: string;
  readonly timezone: string;
  readonly locale: "es" | "en" | "fr";
  readonly version: number;
  readonly provisioningState: string | null;
  readonly provisioningAttempts: number;
  readonly lastErrorCode: string | null;
  readonly activationState: "pending_activation" | "invitation_pending" | "admin_active" | "active";
  readonly latestExport: PlatformTenantExportSummary | null;
  readonly decommission: PlatformTenantDecommissionSummary | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface PlatformTenantExportManifest {
  readonly format: "nombramientos-tenant-export";
  readonly version: 1;
  readonly backupId: string;
  readonly tenantId: string;
  readonly recoveryPointAt: string;
  readonly completedAt: string;
  readonly encryption: {
    readonly algorithm: "AES-256-GCM";
    readonly authenticatedCoreSha256: string;
    readonly keyCustody: "platform-managed-not-exported";
  };
  readonly payload: {
    readonly file: "database.dump.aesgcm";
    readonly bytes: number;
    readonly sha256: string;
  };
}

export interface PlatformTenantExportSummary {
  readonly id: string;
  readonly tenantId: string;
  readonly tenantVersion: number;
  readonly state: "queued" | "running" | "ready" | "failed";
  readonly attemptCount: number;
  readonly revision: number;
  readonly publicManifest: PlatformTenantExportManifest | null;
  readonly encryptedBytes: number | null;
  readonly ciphertextSha256: string | null;
  readonly recoveryPointAt: Date | null;
  readonly lastErrorCode: string | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly readyAt: Date | null;
  readonly failedAt: Date | null;
}

export interface PlatformTenantDecommissionSummary {
  readonly id: string;
  readonly state: "scheduled" | "cancelled";
  readonly sourceExportJobId: string;
  readonly reasonCode: "institution_request" | "duplicate_tenant" | "service_ended" | "legal_retention";
  readonly retentionUntil: Date;
  readonly version: number;
  readonly scheduledAt: Date;
  readonly cancelledAt: Date | null;
}

export interface TenantExportQueueResult {
  readonly jobId: string;
  readonly state: string;
  readonly revision: number;
  readonly reused: boolean;
}

export interface TenantExportDownloadAuthorization {
  readonly authorizationId: string;
  readonly status: "active" | "consumed" | "revoked" | "expired";
  readonly revision: number;
  readonly expiresAt: Date;
  readonly reused: boolean;
}

export interface TenantExportDownloadArtifact {
  readonly artifactRelativePath: string;
  readonly publicManifest: PlatformTenantExportManifest;
  readonly encryptedBytes: number;
  readonly ciphertextSha256: string;
  readonly backupId: string;
  readonly tenantSlug: string;
}

export interface TenantDecommissionResult {
  readonly decommissionId: string;
  readonly state: "scheduled" | "cancelled";
  readonly tenantStatus: "active" | "suspended" | "decommission_pending";
  readonly version: number;
  readonly retentionUntil: Date | null;
  readonly sessionsRevoked: number;
  readonly reused: boolean;
}

export type TenantReactivationReasonCode =
  | "security_review_completed"
  | "operational_hold_resolved"
  | "institution_request_resumed"
  | "compliance_review_completed";

export interface TenantReactivationResult {
  readonly tenantId: string;
  readonly status: "active";
  readonly version: number;
  readonly sessionsRevoked: number;
  readonly sessionsCreated: 0;
  readonly reused: boolean;
}

export interface OwnTenantMembership {
  readonly tenantId: string;
  readonly slug: string;
  readonly displayName: string;
  readonly kind: TenantKind;
  readonly tenantStatus: string;
  readonly membershipStatus: string;
  readonly isDefault: boolean;
  readonly locale: "es" | "en" | "fr";
  readonly timezone: string;
}

export interface TenantMembershipIdentity {
  readonly identityId: string;
  readonly displayName: string;
  readonly email: string;
  readonly membershipStatus: string;
}

export interface ProvisioningQueueResult {
  readonly jobId: string;
  readonly state: string;
  readonly reused: boolean;
}

export interface InitialAdminActivationResult {
  readonly tenantId: string;
  readonly invitationId: string;
  readonly version: number;
  readonly activationState: "invitation_pending";
  readonly reused: boolean;
}

export interface PlatformAdminBootstrapResult {
  readonly identityId: string;
  readonly sessionId: string;
  readonly tenantId: string;
}

export interface ProvisioningWorkerStatus {
  readonly code: "tenant-provisioner";
  readonly status: "starting" | "running" | "stopping" | "stopped" | "failed" | "unavailable";
  readonly healthy: boolean;
  readonly startedAt: Date | null;
  readonly heartbeatAt: Date | null;
  readonly processedCount: number;
  readonly lastErrorCode: string | null;
}

export function tenantProvisionRequestHash(request: TenantProvisionRequest): string {
  return createHash("sha256").update(JSON.stringify({
    idempotencyKey: request.idempotencyKey,
    tenantId: request.tenantId,
    slug: request.slug,
    displayName: request.displayName,
    kind: request.kind,
    timezone: request.timezone,
    locale: request.locale,
    ...(request.initialAdmin?.mode === "invitation" ? {
      initialAdmin: {
        mode: "invitation",
        normalizedEmail: request.initialAdmin.normalizedEmail,
        expiresInHours: request.initialAdmin.expiresInHours,
      },
    } : {}),
  })).digest("hex");
}

export function initialAdminInvitationRequestHash(input: {
  readonly tenantId: string;
  readonly normalizedEmail: string;
  readonly expiresInHours: number;
}): string {
  return createHash("sha256").update(JSON.stringify({
    tenantId: input.tenantId,
    normalizedEmail: input.normalizedEmail,
    expiresInHours: input.expiresInHours,
    roleCodes: ["CHURCH_ADMIN"],
  })).digest("hex");
}

export function tenantExportRequestHash(input: {
  readonly tenantId: string;
  readonly expectedVersion: number;
}): string {
  return createHash("sha256").update(JSON.stringify({
    tenantId: input.tenantId,
    expectedVersion: input.expectedVersion,
  })).digest("hex");
}

export function tenantExportDownloadRequestHash(input: {
  readonly tenantId: string;
  readonly exportJobId: string;
}): string {
  return createHash("sha256").update(JSON.stringify({
    tenantId: input.tenantId,
    exportJobId: input.exportJobId,
  })).digest("hex");
}

export function tenantDecommissionRequestHash(input: {
  readonly tenantId: string;
  readonly expectedVersion: number;
  readonly exportJobId: string;
  readonly retentionDays: number;
  readonly reasonCode: string;
}): string {
  return createHash("sha256").update(JSON.stringify({
    tenantId: input.tenantId,
    expectedVersion: input.expectedVersion,
    exportJobId: input.exportJobId,
    retentionDays: input.retentionDays,
    reasonCode: input.reasonCode,
  })).digest("hex");
}

export function tenantDecommissionCancellationHash(input: {
  readonly tenantId: string;
  readonly decommissionId: string;
  readonly expectedVersion: number;
}): string {
  return createHash("sha256").update(JSON.stringify({
    tenantId: input.tenantId,
    decommissionId: input.decommissionId,
    expectedVersion: input.expectedVersion,
  })).digest("hex");
}

export function tenantReactivationRequestHash(input: {
  readonly tenantId: string;
  readonly expectedVersion: number;
  readonly reasonCode: TenantReactivationReasonCode;
}): string {
  return createHash("sha256").update(JSON.stringify({
    tenantId: input.tenantId,
    expectedVersion: input.expectedVersion,
    reasonCode: input.reasonCode,
  })).digest("hex");
}

export class ControlPlaneStore {
  public constructor(private readonly pool: Pool) {}

  public async findIdentityForLogin(normalizedEmail: string): Promise<LoginIdentity | null> {
    const result = await this.pool.query<{
      identity_id: string;
      email: string;
      display_name: string;
      password_hash: string;
      password_provisioned: boolean;
      mfa_enabled: boolean;
      mfa_required: boolean;
      passkey_enabled: boolean;
      strong_auth_enabled: boolean;
      totp_secret_ciphertext: string | null;
      tenant_id: string;
      locked_until: Date | null;
    }>(
      `SELECT i.id AS identity_id, i.email, i.display_name, i.password_hash,i.password_provisioned,
              i.mfa_enabled, i.mfa_required, i.passkey_enabled,i.strong_auth_enabled,
              i.totp_secret_ciphertext, m.tenant_id, i.locked_until
         FROM platform_identities i
         JOIN LATERAL (
           SELECT tm.tenant_id
             FROM tenant_memberships tm
             JOIN tenants t ON t.id = tm.tenant_id
            WHERE tm.identity_id = i.id
              AND tm.status = 'active'
              AND t.status = 'active'
            ORDER BY tm.is_default DESC, tm.created_at ASC
            LIMIT 1
         ) m ON true
        WHERE i.normalized_email = $1
          AND i.status = 'active'`,
      [normalizedEmail],
    );
    const row = result.rows[0];
    return row
      ? {
          identityId: row.identity_id,
          email: row.email,
          displayName: row.display_name,
          passwordHash: row.password_hash,
          passwordProvisioned: row.password_provisioned,
          mfaEnabled: row.mfa_enabled,
          mfaRequired: row.mfa_required,
          passkeyEnabled: row.passkey_enabled,
          strongAuthEnabled: row.strong_auth_enabled,
          totpSecretCiphertext: row.totp_secret_ciphertext,
          tenantId: row.tenant_id,
          lockedUntil: row.locked_until,
        }
      : null;
  }

  public async recordLoginFailure(identityId: string): Promise<void> {
    await this.pool.query(
      `UPDATE platform_identities
          SET failed_login_count = CASE
                WHEN locked_until>clock_timestamp() THEN failed_login_count
                WHEN locked_until IS NOT NULL THEN 1
                ELSE failed_login_count+1
              END,
              locked_until = CASE
                WHEN locked_until>clock_timestamp() THEN locked_until
                WHEN locked_until IS NOT NULL THEN NULL
                WHEN failed_login_count+1>=8 THEN clock_timestamp()+interval '15 minutes'
                ELSE NULL
              END,
              updated_at = clock_timestamp()
        WHERE id = $1`,
      [identityId],
    );
  }

  public async recordLoginSuccess(identityId: string): Promise<void> {
    await this.pool.query(
      `UPDATE platform_identities
          SET failed_login_count = 0, locked_until = NULL, updated_at = clock_timestamp()
        WHERE id = $1`,
      [identityId],
    );
  }

  public async createMfaChallenge(
    tokenHash: string,
    identityId: string,
    tenantId: string,
    expiresAt: Date,
    binding: { originHash: string; userAgentHash?: string; ipPrefixHash?: string },
  ): Promise<{ challengeId: string; expiresAt: Date }> {
    const result = await this.pool.query<{ id: string; expires_at: Date }>(
      `INSERT INTO mfa_challenges(
         token_hash, identity_id, tenant_id, expires_at, origin_hash, user_agent_hash, ip_prefix_hash
       ) SELECT $1,$2,$3,$4,$5,$6,$7
         FROM platform_identities identity
         JOIN tenant_memberships membership
           ON membership.identity_id=identity.id AND membership.tenant_id=$3
         JOIN tenants tenant ON tenant.id=membership.tenant_id
        WHERE identity.id=$2 AND identity.status='active'
          AND identity.mfa_enabled AND identity.totp_secret_ciphertext IS NOT NULL
          AND membership.status='active' AND tenant.status='active'
          AND (identity.locked_until IS NULL OR identity.locked_until<=clock_timestamp())
       RETURNING id, expires_at`,
      [tokenHash, identityId, tenantId, expiresAt, binding.originHash, binding.userAgentHash ?? null, binding.ipPrefixHash ?? null],
    );
    const row = result.rows[0];
    if (!row) throw new Error("MFA challenge creation did not return a row");
    return { challengeId: row.id, expiresAt: row.expires_at };
  }

  /**
   * Atomically reserves one of the challenge's six verification attempts.
   * Verification work must start only after this succeeds; concurrent callers
   * therefore cannot observe and reuse the same pre-increment attempt count.
   */
  public async reserveMfaChallengeAttempt(
    tokenHash: string,
    challengeId: string,
    binding: { originHash: string; userAgentHash?: string; ipPrefixHash?: string },
  ): Promise<MfaChallengeRecord | null> {
    const result = await this.pool.query<{
      challenge_id: string;
      identity_id: string;
      tenant_id: string;
      totp_secret_ciphertext: string;
      attempt_count: number;
      expires_at: Date;
    }>(
      `UPDATE mfa_challenges challenge
          SET attempt_count=challenge.attempt_count+1
         FROM platform_identities identity
        WHERE challenge.token_hash=$1
          AND challenge.id=$2
          AND challenge.origin_hash=$3
          AND challenge.user_agent_hash IS NOT DISTINCT FROM $4
          AND challenge.ip_prefix_hash IS NOT DISTINCT FROM $5
          AND challenge.consumed_at IS NULL
          AND challenge.expires_at>clock_timestamp()
          AND challenge.attempt_count<6
          AND challenge.identity_id=identity.id
          AND identity.status='active'
          AND identity.mfa_enabled AND identity.totp_secret_ciphertext IS NOT NULL
          AND (identity.locked_until IS NULL OR identity.locked_until<=clock_timestamp())
          AND EXISTS (
            SELECT 1
              FROM tenant_memberships membership
              JOIN tenants tenant ON tenant.id=membership.tenant_id
             WHERE membership.identity_id=identity.id
               AND membership.tenant_id=challenge.tenant_id
               AND membership.status='active' AND tenant.status='active'
          )
      RETURNING challenge.id AS challenge_id,challenge.identity_id,challenge.tenant_id,
                identity.totp_secret_ciphertext,challenge.attempt_count,challenge.expires_at`,
      [tokenHash, challengeId, binding.originHash, binding.userAgentHash ?? null, binding.ipPrefixHash ?? null],
    );
    const row = result.rows[0];
    return row
      ? {
          challengeId: row.challenge_id,
          identityId: row.identity_id,
          tenantId: row.tenant_id,
          totpSecretCiphertext: row.totp_secret_ciphertext,
          attemptCount: row.attempt_count,
          expiresAt: row.expires_at,
        }
      : null;
  }

  /**
   * Resolves only the stable identity needed for pre-verification throttling.
   * This deliberately mirrors the eligibility and binding predicates used by
   * reserveMfaChallengeAttempt without reserving/incrementing an attempt.
   */
  public async resolveMfaRateLimitIdentity(
    tokenHash: string,
    challengeId: string,
    binding: { originHash: string; userAgentHash?: string; ipPrefixHash?: string },
  ): Promise<string | null> {
    const result = await this.pool.query<{ identity_id: string }>(
      `SELECT challenge.identity_id
         FROM mfa_challenges challenge
         JOIN platform_identities identity ON identity.id=challenge.identity_id
        WHERE challenge.token_hash=$1
          AND challenge.id=$2
          AND challenge.origin_hash=$3
          AND challenge.user_agent_hash IS NOT DISTINCT FROM $4
          AND challenge.ip_prefix_hash IS NOT DISTINCT FROM $5
          AND challenge.consumed_at IS NULL
          AND challenge.expires_at>clock_timestamp()
          AND challenge.attempt_count<6
          AND identity.status='active'
          AND identity.mfa_enabled AND identity.totp_secret_ciphertext IS NOT NULL
          AND (identity.locked_until IS NULL OR identity.locked_until<=clock_timestamp())
          AND EXISTS (
            SELECT 1
              FROM tenant_memberships membership
              JOIN tenants tenant ON tenant.id=membership.tenant_id
             WHERE membership.identity_id=identity.id
               AND membership.tenant_id=challenge.tenant_id
               AND membership.status='active' AND tenant.status='active'
          )`,
      [tokenHash, challengeId, binding.originHash, binding.userAgentHash ?? null, binding.ipPrefixHash ?? null],
    );
    return result.rows[0]?.identity_id ?? null;
  }

  public async failMfaChallenge(challengeId: string): Promise<void> {
    await this.pool.query(
      `UPDATE platform_identities identity
          SET failed_login_count=CASE
                WHEN identity.locked_until>clock_timestamp() THEN identity.failed_login_count
                WHEN identity.locked_until IS NOT NULL THEN 1
                ELSE identity.failed_login_count+1
              END,
              locked_until=CASE
                WHEN identity.locked_until>clock_timestamp() THEN identity.locked_until
                WHEN identity.locked_until IS NOT NULL THEN NULL
                WHEN identity.failed_login_count+1>=8 THEN clock_timestamp()+interval '15 minutes'
                ELSE NULL
              END,
              updated_at=clock_timestamp()
        WHERE identity.id=(
          SELECT challenge.identity_id
            FROM mfa_challenges challenge
           WHERE challenge.id=$1 AND challenge.attempt_count BETWEEN 1 AND 6
        )`,
      [challengeId],
    );
  }

  public async consumeMfaChallenge(challengeId: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE mfa_challenges challenge
          SET consumed_at=clock_timestamp()
         FROM platform_identities identity
        WHERE challenge.id=$1 AND challenge.identity_id=identity.id
          AND challenge.consumed_at IS NULL AND challenge.expires_at>clock_timestamp()
          AND identity.status='active'
          AND (identity.locked_until IS NULL OR identity.locked_until<=clock_timestamp())`,
      [challengeId],
    );
    if (result.rowCount !== 1) throw new Error("MFA challenge is no longer valid");
  }

  public async createSession(input: SessionCreateInput): Promise<string> {
    const authMethod = input.authMethod ?? defaultAuthMethod(input.assuranceLevel);
    const aal = input.aal ?? (input.assuranceLevel === "mfa" ? 2 : 1);
    const phishingResistant = input.phishingResistant ?? false;
    const recoveryLimited = input.recoveryLimited ?? input.assuranceLevel === "recovery_limited";
    const requestedIdleTimeoutMinutes = input.idleTimeoutMinutes ?? 30;
    if (
      !Number.isInteger(requestedIdleTimeoutMinutes)
      || requestedIdleTimeoutMinutes < 5
      || requestedIdleTimeoutMinutes > 1440
    ) {
      throw new Error("Session idle timeout is invalid");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const membership = await client.query<{ active: boolean }>(
        "SELECT lock_active_authentication_context($1,$2) AS active",
        [input.identityId, input.tenantId],
      );
      if (membership.rows[0]?.active !== true) throw new Error("Session identity has no active tenant membership");
      const effectivePolicy = await client.query<{
        idle_timeout_minutes: number;
        absolute_session_minutes: number;
        maximum_active_sessions: number;
      }>(
        `SELECT COALESCE(policy.idle_timeout_minutes,baseline.idle_timeout_minutes)
                  AS idle_timeout_minutes,
                COALESCE(policy.absolute_session_minutes,baseline.absolute_session_minutes)
                  AS absolute_session_minutes,
                COALESCE(policy.maximum_active_sessions,baseline.maximum_active_sessions)
                  AS maximum_active_sessions
           FROM tenants tenant
           CROSS JOIN identity_policy_baseline baseline
           LEFT JOIN tenant_identity_policies policy ON policy.tenant_id=tenant.id
          WHERE tenant.id=$1 AND tenant.status='active' AND baseline.policy_key='global'`,
        [input.tenantId],
      );
      const policy = effectivePolicy.rows[0];
      if (!policy) throw new Error("Session identity policy is unavailable");
      const expiresAt = new Date(Math.min(
        input.expiresAt.getTime(),
        Date.now() + policy.absolute_session_minutes * 60_000,
      ));
      if (expiresAt.getTime() <= Date.now()) throw new Error("Session expiry must be in the future");
      const idleTimeoutMinutes = Math.min(requestedIdleTimeoutMinutes, policy.idle_timeout_minutes);
      const result = await client.query<{ id: string }>(
        `INSERT INTO auth_sessions(
           token_hash, csrf_hash, identity_id, active_tenant_id, expires_at,
           user_agent_hash, ip_prefix_hash, assurance_level, mfa_verified_at,
           auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,
           idle_timeout_minutes,idle_expires_at,last_ip_prefix_hash,device_label
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,
                   CASE WHEN $8='mfa' THEN clock_timestamp() ELSE NULL END,
                   $9,$10,$11,$12,$13,$14,
                   LEAST($5,clock_timestamp()+make_interval(mins=>$14)),$7,$15)
         RETURNING id`,
        [
          input.tokenHash,
          input.csrfHash,
          input.identityId,
          input.tenantId,
          expiresAt,
          input.userAgentHash ?? null,
          input.ipPrefixHash ?? null,
          input.assuranceLevel,
          authMethod,
          aal,
          phishingResistant,
          input.credentialId ?? null,
          recoveryLimited,
          idleTimeoutMinutes,
          input.deviceLabel?.trim() ?? null,
        ],
      );
      const id = result.rows[0]?.id;
      if (!id) throw new Error("Session creation did not return an id");
      const excess = await client.query<{ id: string }>(
        `WITH ranked AS (
           SELECT id,row_number() OVER (
             ORDER BY (id=$3) DESC,last_seen_at DESC,id
           ) AS position
             FROM auth_sessions
            WHERE identity_id=$1 AND active_tenant_id=$2 AND revoked_at IS NULL
              AND expires_at>clock_timestamp() AND idle_expires_at>clock_timestamp()
         )
         UPDATE auth_sessions session
            SET revoked_at=clock_timestamp(),revoke_reason='active_session_limit'
           FROM ranked
          WHERE session.id=ranked.id AND ranked.position>$4
         RETURNING session.id`,
        [input.identityId, input.tenantId, id, policy.maximum_active_sessions],
      );
      if (excess.rows.length > 0) {
        await client.query(
          `UPDATE authentication_step_up_grants
              SET revoked_at=COALESCE(revoked_at,clock_timestamp())
            WHERE session_id=ANY($1::uuid[]) AND consumed_at IS NULL AND revoked_at IS NULL`,
          [excess.rows.map(({ id: revokedId }) => revokedId)],
        );
      }
      await client.query("COMMIT");
      return id;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async consumePlatformAdminBootstrap(input: {
    readonly tokenHash: string;
    readonly email: string;
    readonly normalizedEmail: string;
    readonly displayName: string;
    readonly passwordHash: string;
    readonly identityId: string;
    readonly sessionId: string;
    readonly sessionTokenHash: string;
    readonly csrfHash: string;
    readonly sessionExpiresAt: Date;
    readonly requestId: string;
    readonly userAgentHash?: string;
    readonly ipPrefixHash?: string;
  }): Promise<PlatformAdminBootstrapResult | null> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query<{
        created_identity_id: string;
        created_session_id: string;
        anchor_tenant_id: string;
      }>(
        `SELECT * FROM consume_platform_admin_bootstrap(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
         )`,
        [
          input.tokenHash,
          input.email,
          input.normalizedEmail,
          input.displayName,
          input.passwordHash,
          input.identityId,
          input.sessionId,
          input.sessionTokenHash,
          input.csrfHash,
          input.sessionExpiresAt,
          input.userAgentHash ?? null,
          input.ipPrefixHash ?? null,
        ],
      );
      const row = result.rows[0];
      if (!row) {
        await client.query("COMMIT");
        return null;
      }
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('platform_audit_chain', 0))");
      const previous = await client.query<{ event_hash: string }>(
        "SELECT event_hash FROM platform_audit_events ORDER BY sequence DESC LIMIT 1",
      );
      const previousHash = previous.rows[0]?.event_hash ?? null;
      const canonical = JSON.stringify({
        previousHash,
        action: "platform.admin_bootstrap_consumed",
        actorIdentityId: row.created_identity_id,
        tenantId: null,
        entityType: "platform_identity",
        entityId: row.created_identity_id,
        result: "success",
        requestId: input.requestId,
        metadata: { assurance: "enrollment_only", contentAccess: false, keyAccess: false },
      });
      const eventHash = createHash("sha256").update(canonical).digest("hex");
      await client.query(
        `INSERT INTO platform_audit_events(
           actor_identity_id,tenant_id,action,entity_type,entity_id,result,request_id,
           metadata,previous_hash,event_hash
         ) VALUES ($1::uuid,NULL,$2,$3,$1::text,'success',$4,$5,$6,$7)`,
        [
          row.created_identity_id,
          "platform.admin_bootstrap_consumed",
          "platform_identity",
          input.requestId,
          { assurance: "enrollment_only", contentAccess: false, keyAccess: false },
          previousHash,
          eventHash,
        ],
      );
      await client.query("COMMIT");
      return {
        identityId: row.created_identity_id,
        sessionId: row.created_session_id,
        tenantId: row.anchor_tenant_id,
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async getSession(tokenHash: string, binding: SessionBinding): Promise<SessionRecord | null> {
    const result = await this.pool.query<{
      session_id: string;
      identity_id: string;
      active_tenant_id: string;
      email: string;
      display_name: string;
      tenant_slug: string;
      tenant_name: string;
      tenant_kind: TenantKind;
      tenant_timezone: string;
      csrf_hash: string;
      expires_at: Date;
      assurance_level: AuthenticationAssuranceLevel;
      authenticated_at: Date;
      mfa_verified_at: Date | null;
      auth_method: AuthenticationMethod;
      aal: 1 | 2 | 3;
      phishing_resistant: boolean;
      authenticated_credential_id: string | null;
      recovery_limited: boolean;
      idle_expires_at: Date;
      device_label: string | null;
      user_agent_change_count: number;
      ip_change_count: number;
      mfa_required: boolean;
      mfa_enabled: boolean;
      passkey_enabled: boolean;
      strong_auth_enabled: boolean;
    }>(
       `UPDATE auth_sessions s
          SET last_seen_at = clock_timestamp(),
              idle_expires_at=LEAST(s.expires_at,clock_timestamp()+make_interval(mins=>s.idle_timeout_minutes)),
              user_agent_change_count=s.user_agent_change_count+CASE
                WHEN $2::text IS NULL OR s.last_user_agent_hash IS NULL
                     OR s.last_user_agent_hash=$2 THEN 0 ELSE 1 END,
              user_agent_context_changed_at=CASE
                WHEN $2::text IS NOT NULL AND s.last_user_agent_hash IS NOT NULL
                     AND s.last_user_agent_hash<>$2 THEN clock_timestamp()
                ELSE s.user_agent_context_changed_at END,
              last_user_agent_hash=COALESCE($2,s.last_user_agent_hash),
              ip_change_count=s.ip_change_count+CASE
                WHEN $3::text IS NULL OR s.last_ip_prefix_hash IS NULL
                     OR s.last_ip_prefix_hash=$3 THEN 0 ELSE 1 END,
              ip_context_changed_at=CASE
                WHEN $3::text IS NOT NULL AND s.last_ip_prefix_hash IS NOT NULL
                     AND s.last_ip_prefix_hash<>$3 THEN clock_timestamp()
                ELSE s.ip_context_changed_at END,
              last_ip_prefix_hash=COALESCE($3,s.last_ip_prefix_hash)
         FROM platform_identities i, tenants t, tenant_memberships m
        WHERE s.token_hash = $1
          AND s.identity_id = i.id
          AND s.active_tenant_id = t.id
          AND m.identity_id = i.id
          AND m.tenant_id = t.id
          AND s.revoked_at IS NULL
          AND s.expires_at > clock_timestamp()
          AND s.idle_expires_at > clock_timestamp()
          AND i.status = 'active'
          AND t.status = 'active'
          AND m.status = 'active'
       RETURNING s.id AS session_id, i.id AS identity_id,
                 t.id AS active_tenant_id, i.email, i.display_name,
                 t.slug AS tenant_slug, t.display_name AS tenant_name,
                 t.kind AS tenant_kind, t.timezone AS tenant_timezone,
                 s.csrf_hash, s.expires_at,
                 s.assurance_level,s.authenticated_at,s.mfa_verified_at,
                 s.auth_method,s.aal,s.phishing_resistant,s.authenticated_credential_id,
                 s.recovery_limited,s.idle_expires_at,s.device_label,
                 s.user_agent_change_count,s.ip_change_count,
                 i.mfa_required,i.mfa_enabled,i.passkey_enabled,i.strong_auth_enabled`,
      [tokenHash, binding.userAgentHash ?? null, binding.ipPrefixHash ?? null],
    );
    const row = result.rows[0];
    return row
      ? {
          sessionId: row.session_id,
          identityId: row.identity_id,
          activeTenantId: row.active_tenant_id,
          email: row.email,
          displayName: row.display_name,
          tenantSlug: row.tenant_slug,
          tenantName: row.tenant_name,
          tenantKind: row.tenant_kind,
          tenantTimezone: requireIanaTimezone(row.tenant_timezone),
          csrfHash: row.csrf_hash,
          expiresAt: row.expires_at,
          assuranceLevel: row.assurance_level,
          authenticatedAt: row.authenticated_at,
          mfaVerifiedAt: row.mfa_verified_at,
          authMethod: row.auth_method,
          aal: row.aal,
          phishingResistant: row.phishing_resistant,
          authenticatedCredentialId: row.authenticated_credential_id,
          recoveryLimited: row.recovery_limited,
          idleExpiresAt: row.idle_expires_at,
          deviceLabel: row.device_label,
          userAgentContextChanged: row.user_agent_change_count > 0,
          ipContextChanged: row.ip_change_count > 0,
          mfaRequired: row.mfa_required,
          mfaEnabled: row.mfa_enabled,
          passkeyEnabled: row.passkey_enabled,
          strongAuthEnabled: row.strong_auth_enabled,
          enrollmentOnly: row.assurance_level === "enrollment_only" || row.assurance_level === "recovery_limited",
        }
      : null;
  }

  public async revokeSession(sessionId: string, reason: string): Promise<void> {
    await this.pool.query(
      `UPDATE auth_sessions
          SET revoked_at = clock_timestamp(), revoke_reason = $2
        WHERE id = $1 AND revoked_at IS NULL`,
      [sessionId, reason],
    );
  }

  public async listOwnMemberships(identityId: string): Promise<readonly OwnTenantMembership[]> {
    const result = await this.pool.query<{
      tenant_id: string;
      slug: string;
      display_name: string;
      kind: TenantKind;
      tenant_status: string;
      membership_status: string;
      is_default: boolean;
      locale: "es" | "en" | "fr";
      timezone: string;
    }>(
      `SELECT tenant.id AS tenant_id, tenant.slug, tenant.display_name, tenant.kind,
              tenant.status AS tenant_status, membership.status AS membership_status,
              membership.is_default, tenant.locale, tenant.timezone
         FROM tenant_memberships membership
         JOIN tenants tenant ON tenant.id = membership.tenant_id
        WHERE membership.identity_id = $1
        ORDER BY membership.is_default DESC, tenant.display_name, tenant.id`,
      [identityId],
    );
    return result.rows.map((row) => ({
      tenantId: row.tenant_id,
      slug: row.slug,
      displayName: row.display_name,
      kind: row.kind,
      tenantStatus: row.tenant_status,
      membershipStatus: row.membership_status,
      isDefault: row.is_default,
      locale: row.locale,
      timezone: row.timezone,
    }));
  }

  public async hasActiveMembership(identityId: string, tenantId: string): Promise<boolean> {
    const result = await this.pool.query(
      `SELECT 1
         FROM tenant_memberships membership
         JOIN tenants tenant ON tenant.id = membership.tenant_id
         JOIN platform_identities identity ON identity.id = membership.identity_id
        WHERE membership.identity_id = $1
          AND membership.tenant_id = $2
          AND membership.status = 'active'
          AND identity.status = 'active'
          AND tenant.status = 'active'`,
      [identityId, tenantId],
    );
    return result.rowCount === 1;
  }

  public async listActiveTenantMembershipIdentities(tenantId: string): Promise<readonly TenantMembershipIdentity[]> {
    const result = await this.pool.query<{
      identity_id: string;
      display_name: string;
      email: string;
      membership_status: string;
    }>(
      `SELECT identity.id AS identity_id, identity.display_name, identity.email,
              membership.status AS membership_status
         FROM tenant_memberships membership
         JOIN platform_identities identity ON identity.id = membership.identity_id
         JOIN tenants tenant ON tenant.id = membership.tenant_id
        WHERE membership.tenant_id = $1
          AND membership.status = 'active'
          AND identity.status = 'active'
          AND tenant.status = 'active'
        ORDER BY identity.display_name, identity.id`,
      [tenantId],
    );
    return result.rows.map((row) => ({
      identityId: row.identity_id,
      displayName: row.display_name,
      email: row.email,
      membershipStatus: row.membership_status,
    }));
  }

  public async listTenantMembershipIdentities(tenantId: string): Promise<readonly TenantMembershipIdentity[]> {
    const result = await this.pool.query<{
      identity_id: string;
      display_name: string;
      email: string;
      membership_status: string;
    }>(
      `SELECT identity.id AS identity_id, identity.display_name, identity.email,
              membership.status AS membership_status
         FROM tenant_memberships membership
         JOIN platform_identities identity ON identity.id = membership.identity_id
        WHERE membership.tenant_id = $1
        ORDER BY identity.display_name, identity.id`,
      [tenantId],
    );
    return result.rows.map((row) => ({
      identityId: row.identity_id,
      displayName: row.display_name,
      email: row.email,
      membershipStatus: row.membership_status,
    }));
  }

  public async rotateSessionTenant(input: {
    readonly currentSessionId: string;
    readonly identityId: string;
    readonly targetTenantId: string;
    readonly tokenHash: string;
    readonly csrfHash: string;
    readonly expiresAt: Date;
    readonly idleTimeoutMinutes: number;
    readonly userAgentHash?: string;
    readonly ipPrefixHash?: string;
  }): Promise<string | null> {
    if (!Number.isInteger(input.idleTimeoutMinutes) || input.idleTimeoutMinutes < 5 || input.idleTimeoutMinutes > 1440) {
      throw new Error("Target session idle timeout is invalid");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const activeContext = await client.query<{ active: boolean }>(
        "SELECT lock_active_authentication_context($1,$2) AS active",
        [input.identityId, input.targetTenantId],
      );
      if (activeContext.rows[0]?.active !== true) {
        await client.query("ROLLBACK");
        return null;
      }
      const current = await client.query<{
        assurance_level: AuthenticationAssuranceLevel;
        authenticated_at: Date;
        mfa_verified_at: Date | null;
        auth_method: AuthenticationMethod;
        aal: 1 | 2 | 3;
        phishing_resistant: boolean;
        authenticated_credential_id: string | null;
        recovery_limited: boolean;
        expires_at: Date;
        device_label: string | null;
      }>(
        `SELECT assurance_level,authenticated_at,mfa_verified_at,auth_method,aal,
                phishing_resistant,authenticated_credential_id,recovery_limited,
                expires_at,device_label
           FROM auth_sessions
          WHERE id = $1 AND identity_id = $2
            AND revoked_at IS NULL AND expires_at > clock_timestamp()
            AND idle_expires_at > clock_timestamp()
          FOR UPDATE`,
        [input.currentSessionId, input.identityId],
      );
      const session = current.rows[0];
      if (!session) {
        await client.query("ROLLBACK");
        return null;
      }
      const targetPolicy = await client.query<{
        idle_timeout_minutes: number;
        absolute_session_minutes: number;
        maximum_active_sessions: number;
      }>(
        `SELECT COALESCE(policy.idle_timeout_minutes,baseline.idle_timeout_minutes)
                  AS idle_timeout_minutes,
                COALESCE(policy.absolute_session_minutes,baseline.absolute_session_minutes)
                  AS absolute_session_minutes,
                COALESCE(policy.maximum_active_sessions,baseline.maximum_active_sessions)
                  AS maximum_active_sessions
           FROM tenants tenant
           CROSS JOIN identity_policy_baseline baseline
           LEFT JOIN tenant_identity_policies policy ON policy.tenant_id=tenant.id
          WHERE tenant.id=$1 AND tenant.status='active' AND baseline.policy_key='global'`,
        [input.targetTenantId],
      );
      const policy = targetPolicy.rows[0];
      if (!policy) {
        await client.query("ROLLBACK");
        return null;
      }
      const expiresAt = new Date(Math.min(
        input.expiresAt.getTime(),
        session.expires_at.getTime(),
        Date.now() + policy.absolute_session_minutes * 60_000,
      ));
      const idleTimeoutMinutes = Math.min(input.idleTimeoutMinutes, policy.idle_timeout_minutes);
      if (expiresAt.getTime() <= Date.now()) {
        await client.query("ROLLBACK");
        return null;
      }
      const created = await client.query<{ id: string }>(
         `INSERT INTO auth_sessions(
           token_hash, csrf_hash, identity_id, active_tenant_id, expires_at,
           user_agent_hash,ip_prefix_hash,assurance_level,authenticated_at,mfa_verified_at,
           auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,
           idle_timeout_minutes,idle_expires_at,last_ip_prefix_hash,device_label
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                   LEAST($5,clock_timestamp()+make_interval(mins=>$16)),$7,$17)
         RETURNING id`,
        [
          input.tokenHash,
          input.csrfHash,
          input.identityId,
          input.targetTenantId,
          expiresAt,
          input.userAgentHash ?? null,
          input.ipPrefixHash ?? null,
          session.assurance_level,
          session.authenticated_at,
          session.mfa_verified_at,
          session.auth_method,
          session.aal,
          session.phishing_resistant,
          session.authenticated_credential_id,
          session.recovery_limited,
          idleTimeoutMinutes,
          session.device_label,
        ],
      );
      const createdSessionId = created.rows[0]?.id;
      if (!createdSessionId) throw new Error("Tenant session rotation did not return an id");
      await client.query(
        `UPDATE auth_sessions
            SET revoked_at = clock_timestamp(), revoke_reason = 'tenant_switched'
          WHERE id = $1 AND revoked_at IS NULL`,
        [input.currentSessionId],
      );
      const excess = await client.query<{ id: string }>(
        `WITH ranked AS (
           SELECT id,row_number() OVER (
             ORDER BY (id=$3) DESC,last_seen_at DESC,id
           ) AS position
             FROM auth_sessions
            WHERE identity_id=$1 AND active_tenant_id=$2 AND revoked_at IS NULL
              AND expires_at>clock_timestamp() AND idle_expires_at>clock_timestamp()
         )
         UPDATE auth_sessions session
            SET revoked_at=clock_timestamp(),revoke_reason='active_session_limit'
           FROM ranked
          WHERE session.id=ranked.id AND ranked.position>$4
         RETURNING session.id`,
        [input.identityId, input.targetTenantId, createdSessionId, policy.maximum_active_sessions],
      );
      await client.query(
        `UPDATE authentication_step_up_grants
            SET revoked_at=COALESCE(revoked_at,clock_timestamp())
          WHERE consumed_at IS NULL AND revoked_at IS NULL
            AND (session_id=$1 OR session_id=ANY($2::uuid[]))`,
        [input.currentSessionId, excess.rows.map(({ id }) => id)],
      );
      await client.query("COMMIT");
      return createdSessionId;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async revokeTenantIdentitySessions(
    tenantId: string,
    identityIds: readonly string[],
    reason: string,
  ): Promise<number> {
    if (identityIds.length === 0) return 0;
    const result = await this.pool.query(
      `UPDATE auth_sessions
          SET revoked_at = clock_timestamp(), revoke_reason = $3
        WHERE active_tenant_id = $1
          AND identity_id = ANY($2::uuid[])
          AND revoked_at IS NULL`,
      [tenantId, [...new Set(identityIds)], reason],
    );
    return result.rowCount ?? 0;
  }

  public async getTenantCredential(tenantId: string): Promise<TenantCredentialRecord> {
    const result = await this.pool.query<{
      id: string;
      database_host: string;
      database_port: number;
      database_name: string;
      runtime_role: string;
      runtime_secret_ref: string;
      credential_version: number;
      ssl_mode: "disable" | "require" | "verify-full";
    }>(
      `SELECT id, database_host, database_port, database_name, runtime_role,
              runtime_secret_ref, credential_version, ssl_mode
         FROM tenants WHERE id = $1 AND status = 'active'`,
      [tenantId],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Active tenant credential was not found");
    return {
      tenantId: row.id,
      host: row.database_host,
      port: row.database_port,
      database: row.database_name,
      user: row.runtime_role,
      secretReference: row.runtime_secret_ref,
      credentialVersion: row.credential_version,
      sslMode: row.ssl_mode,
    };
  }

  /**
   * Narrow route resolution for an already-fenced invitation saga. This is
   * intentionally separate from normal active-tenant routing so compensation
   * can remove an orphaned grant after tenant suspension without making that
   * tenant routable to ordinary requests.
   */
  public async getTenantCredentialForInvitationSaga(input: {
    tenantId: string;
    invitationId: string;
    acceptanceId: string;
    identityId: string;
    acceptanceAttempt: number;
    allowedStatuses: readonly ("compensating" | "revoked" | "expired" | "failed" | "accepted")[];
  }): Promise<TenantCredentialRecord> {
    const result = await this.pool.query<{
      id: string;
      database_host: string;
      database_port: number;
      database_name: string;
      runtime_role: string;
      runtime_secret_ref: string;
      credential_version: number;
      ssl_mode: "disable" | "require" | "verify-full";
    }>(
      `SELECT tenant.id,tenant.database_host,tenant.database_port,tenant.database_name,
              tenant.runtime_role,tenant.runtime_secret_ref,tenant.credential_version,tenant.ssl_mode
         FROM tenants tenant
         JOIN tenant_invitations invitation ON invitation.tenant_id=tenant.id
        WHERE tenant.id=$1
          AND tenant.status IN ('active','suspended','provisioning','decommission_pending','failed')
          AND invitation.id=$2
          AND invitation.acceptance_id=$3
          AND invitation.acceptance_identity_id=$4
          AND invitation.acceptance_attempt=$5
          AND invitation.status=ANY($6::text[])`,
      [
        input.tenantId,
        input.invitationId,
        input.acceptanceId,
        input.identityId,
        input.acceptanceAttempt,
        [...input.allowedStatuses],
      ],
    );
    const row = result.rows[0];
    if (!row || result.rowCount !== 1) throw new Error("Fenced invitation tenant credential was not found");
    return {
      tenantId: row.id,
      host: row.database_host,
      port: row.database_port,
      database: row.database_name,
      user: row.runtime_role,
      secretReference: row.runtime_secret_ref,
      credentialVersion: row.credential_version,
      sslMode: row.ssl_mode,
    };
  }

  public async hasPlatformPermission(identityId: string, permission: string): Promise<boolean> {
    const allowedRoles: Readonly<Record<string, readonly string[]>> = {
      "platform.tenant.provision": ["platform_admin", "platform_operator"],
      "platform.tenant.suspend": ["platform_admin", "platform_operator"],
      "platform.tenant.reactivate": ["platform_admin", "platform_operator"],
      "platform.tenant.export.request": ["platform_admin", "platform_operator"],
      "platform.tenant.export.download": ["platform_admin"],
      "platform.tenant.decommission.schedule": ["platform_admin"],
      "platform.tenant.decommission.cancel": ["platform_admin"],
      "platform.operation.read": ["platform_admin", "platform_operator", "platform_auditor"],
      "platform.security.manage": ["platform_admin"],
    };
    const roleCodes = allowedRoles[permission];
    if (!roleCodes) return false;
    const result = await this.pool.query(
      "SELECT 1 FROM platform_role_bindings WHERE identity_id = $1 AND role_code = ANY($2::text[])",
      [identityId, roleCodes],
    );
    return result.rowCount === 1;
  }

  public async getPlatformPermissions(identityId: string): Promise<readonly string[]> {
    const result = await this.pool.query<{ permission: string }>(
      `SELECT DISTINCT permission
         FROM platform_role_bindings binding
         CROSS JOIN LATERAL unnest(
           CASE binding.role_code
             WHEN 'platform_admin' THEN ARRAY[
               'platform.tenant.provision','platform.tenant.suspend','platform.tenant.reactivate',
               'platform.tenant.export.request','platform.tenant.export.download',
               'platform.tenant.decommission.schedule','platform.tenant.decommission.cancel',
               'platform.operation.read','platform.security.manage'
             ]::text[]
             WHEN 'platform_operator' THEN ARRAY[
               'platform.tenant.provision','platform.tenant.suspend','platform.tenant.reactivate',
               'platform.tenant.export.request','platform.operation.read'
             ]::text[]
             WHEN 'platform_auditor' THEN ARRAY['platform.operation.read']::text[]
             ELSE ARRAY[]::text[]
           END
         ) granted(permission)
        WHERE binding.identity_id = $1
        ORDER BY permission`,
      [identityId],
    );
    return result.rows.map((row) => row.permission);
  }

  public async listTenants(): Promise<readonly PlatformTenantSummary[]> {
    const result = await this.pool.query<{
      id: string; slug: string; display_name: string; kind: TenantKind;
      status: string; timezone: string; locale: "es" | "en" | "fr";
      version: number; provisioning_state: string | null; attempt_count: number;
      last_error_code: string | null;
      activation_state: "pending_activation" | "invitation_pending" | "admin_active" | "active";
      export_id: string | null; export_tenant_version: number | null; export_state: PlatformTenantExportSummary["state"] | null;
      export_attempt_count: number | null; export_revision: number | null;
      export_public_manifest: PlatformTenantExportManifest | null; export_encrypted_bytes: string | null;
      export_ciphertext_sha256: string | null; export_recovery_point_at: Date | null;
      export_last_error_code: string | null; export_created_at: Date | null; export_updated_at: Date | null;
      export_ready_at: Date | null; export_failed_at: Date | null;
      decommission_id: string | null; decommission_state: PlatformTenantDecommissionSummary["state"] | null;
      decommission_export_job_id: string | null; decommission_reason_code: PlatformTenantDecommissionSummary["reasonCode"] | null;
      decommission_retention_until: Date | null; decommission_version: number | null;
      decommission_scheduled_at: Date | null; decommission_cancelled_at: Date | null;
      created_at: Date; updated_at: Date;
    }>(
      `SELECT id,slug,display_name,kind,status,timezone,locale,version,
              provisioning_state,attempt_count,last_error_code,activation_state,
              export_id,export_tenant_version,export_state,export_attempt_count,export_revision,
              export_public_manifest,export_encrypted_bytes::text,export_ciphertext_sha256,
              export_recovery_point_at,export_last_error_code,export_created_at,export_updated_at,
              export_ready_at,export_failed_at,decommission_id,decommission_state,
              decommission_export_job_id,decommission_reason_code,decommission_retention_until,
              decommission_version,decommission_scheduled_at,decommission_cancelled_at,
              created_at,updated_at
         FROM platform_tenant_summaries
        ORDER BY updated_at DESC,id`,
    );
    return result.rows.map((row) => ({
      id: row.id,
      slug: row.slug,
      displayName: row.display_name,
      kind: row.kind,
      status: row.status,
      timezone: row.timezone,
      locale: row.locale,
      version: row.version,
      provisioningState: row.provisioning_state,
      provisioningAttempts: row.attempt_count,
      lastErrorCode: row.last_error_code,
      activationState: row.activation_state,
      latestExport: row.export_id && row.export_tenant_version && row.export_state
        && row.export_attempt_count !== null && row.export_revision && row.export_created_at && row.export_updated_at
        ? {
            id: row.export_id,
            tenantId: row.id,
            tenantVersion: row.export_tenant_version,
            state: row.export_state,
            attemptCount: row.export_attempt_count,
            revision: row.export_revision,
            publicManifest: row.export_public_manifest,
            encryptedBytes: parseNullableSafeInteger(row.export_encrypted_bytes),
            ciphertextSha256: row.export_ciphertext_sha256,
            recoveryPointAt: row.export_recovery_point_at,
            lastErrorCode: row.export_last_error_code,
            createdAt: row.export_created_at,
            updatedAt: row.export_updated_at,
            readyAt: row.export_ready_at,
            failedAt: row.export_failed_at,
          }
        : null,
      decommission: row.decommission_id && row.decommission_state && row.decommission_export_job_id
        && row.decommission_reason_code && row.decommission_retention_until && row.decommission_version
        && row.decommission_scheduled_at
        ? {
            id: row.decommission_id,
            state: row.decommission_state,
            sourceExportJobId: row.decommission_export_job_id,
            reasonCode: row.decommission_reason_code,
            retentionUntil: row.decommission_retention_until,
            version: row.decommission_version,
            scheduledAt: row.decommission_scheduled_at,
            cancelledAt: row.decommission_cancelled_at,
          }
        : null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  public async queueTenantProvisioning(
    request: TenantProvisionRequest,
    actorIdentityId: string,
    requestId: string,
  ): Promise<ProvisioningQueueResult> {
    const result = await this.pool.query<{
      job_id: string;
      job_state: string;
      reused: boolean;
    }>(
      `SELECT * FROM queue_platform_tenant_provisioning(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
       )`,
      [
        request.idempotencyKey,
        request.tenantId,
        request.slug,
        request.displayName,
        request.kind,
        request.timezone,
        request.locale,
        request.initialAdmin?.mode ?? (request.kind === "real" ? "pending" : "demo_seed"),
        request.initialAdmin?.mode === "invitation" ? request.initialAdmin.email : null,
        request.initialAdmin?.mode === "invitation" ? request.initialAdmin.normalizedEmail : null,
        request.initialAdmin?.mode === "invitation" ? request.initialAdmin.tokenHash : null,
        request.initialAdmin?.mode === "invitation" ? request.initialAdmin.expiresAt : null,
        request.initialAdmin?.mode === "invitation" ? request.initialAdmin.expiresInHours : null,
        tenantProvisionRequestHash(request),
        actorIdentityId,
        requestId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Provisioning queue did not return a job");
    return { jobId: row.job_id, state: row.job_state, reused: row.reused };
  }

  public async activateTenantInitialAdmin(input: {
    readonly tenantId: string;
    readonly expectedVersion: number;
    readonly email: string;
    readonly normalizedEmail: string;
    readonly tokenHash: string;
    readonly expiresAt: Date;
    readonly expiresInHours: number;
    readonly idempotencyKey: string;
    readonly actorIdentityId: string;
  }): Promise<InitialAdminActivationResult> {
    const requestHash = initialAdminInvitationRequestHash(input);
    const result = await this.pool.query<{ invitation_id: string; tenant_version: number; reused: boolean }>(
      `SELECT * FROM activate_platform_tenant_initial_admin(
         $1,$2,$3,$4,$5,$6,$7,$8,$9
       )`,
      [
        input.tenantId,
        input.expectedVersion,
        input.email,
        input.normalizedEmail,
        input.tokenHash,
        input.expiresAt,
        input.idempotencyKey,
        requestHash,
        input.actorIdentityId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Initial administrator activation did not return a result");
    return {
      tenantId: input.tenantId,
      invitationId: row.invitation_id,
      version: row.tenant_version,
      activationState: "invitation_pending",
      reused: row.reused,
    };
  }

  public async getProvisioningWorkerStatus(): Promise<ProvisioningWorkerStatus> {
    const result = await this.pool.query<{
      status: "starting" | "running" | "stopping" | "stopped" | "failed";
      started_at: Date;
      heartbeat_at: Date;
      processed_count: string;
      last_error_code: string | null;
      healthy: boolean;
    }>(
      `SELECT status, started_at, heartbeat_at, processed_count::text, last_error_code,
              status = 'running' AND heartbeat_at > clock_timestamp() - interval '15 seconds' AS healthy
         FROM platform_worker_status
        WHERE worker_code = 'tenant-provisioner'`,
    );
    const row = result.rows[0];
    if (!row) return {
      code: "tenant-provisioner",
      status: "unavailable",
      healthy: false,
      startedAt: null,
      heartbeatAt: null,
      processedCount: 0,
      lastErrorCode: null,
    };
    const processedCount = Number(row.processed_count);
    return {
      code: "tenant-provisioner",
      status: row.status,
      healthy: row.healthy,
      startedAt: row.started_at,
      heartbeatAt: row.heartbeat_at,
      processedCount: Number.isSafeInteger(processedCount) ? processedCount : Number.MAX_SAFE_INTEGER,
      lastErrorCode: row.last_error_code,
    };
  }

  public async queueTenantExport(input: {
    readonly tenantId: string;
    readonly expectedVersion: number;
    readonly idempotencyKey: string;
    readonly actorIdentityId: string;
    readonly requestId: string;
  }): Promise<TenantExportQueueResult> {
    const result = await this.pool.query<{
      job_id: string;
      job_state: string;
      job_revision: number;
      reused: boolean;
    }>(
      "SELECT * FROM queue_platform_tenant_export($1,$2,$3,$4,$5,$6)",
      [
        input.tenantId,
        input.expectedVersion,
        input.idempotencyKey,
        tenantExportRequestHash(input),
        input.actorIdentityId,
        input.requestId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Tenant export queue did not return a job");
    return { jobId: row.job_id, state: row.job_state, revision: row.job_revision, reused: row.reused };
  }

  public async authorizeTenantExportDownload(input: {
    readonly authorizationId: string;
    readonly tenantId: string;
    readonly exportJobId: string;
    readonly expiresAt: Date;
    readonly idempotencyKey: string;
    readonly actorIdentityId: string;
  }): Promise<TenantExportDownloadAuthorization> {
    const result = await this.pool.query<{
      authorization_id: string;
      authorization_status: TenantExportDownloadAuthorization["status"];
      authorization_revision: number;
      expires_at: Date;
      reused: boolean;
    }>(
      "SELECT * FROM authorize_platform_tenant_export_download($1,$2,$3,$4,$5,$6,$7)",
      [
        input.authorizationId,
        input.tenantId,
        input.exportJobId,
        input.expiresAt,
        input.idempotencyKey,
        tenantExportDownloadRequestHash(input),
        input.actorIdentityId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Tenant export download authorization was not returned");
    return {
      authorizationId: row.authorization_id,
      status: row.authorization_status,
      revision: row.authorization_revision,
      expiresAt: row.expires_at,
      reused: row.reused,
    };
  }

  public async consumeTenantExportDownload(input: {
    readonly authorizationId: string;
    readonly tenantId: string;
    readonly exportJobId: string;
    readonly actorIdentityId: string;
  }): Promise<TenantExportDownloadArtifact | null> {
    const result = await this.pool.query<{
      artifact_relative_path: string;
      public_manifest: PlatformTenantExportManifest;
      encrypted_bytes: string;
      ciphertext_sha256: string;
      backup_id: string;
      tenant_slug: string;
    }>(
      "SELECT * FROM consume_platform_tenant_export_download($1,$2,$3,$4)",
      [input.authorizationId, input.tenantId, input.exportJobId, input.actorIdentityId],
    );
    const row = result.rows[0];
    if (!row) return null;
    const encryptedBytes = parseSafeInteger(row.encrypted_bytes, "Tenant export size");
    return {
      artifactRelativePath: row.artifact_relative_path,
      publicManifest: row.public_manifest,
      encryptedBytes,
      ciphertextSha256: row.ciphertext_sha256,
      backupId: row.backup_id,
      tenantSlug: row.tenant_slug,
    };
  }

  public async revokeTenantExportDownload(input: {
    readonly authorizationId: string;
    readonly expectedRevision: number;
    readonly actorIdentityId: string;
  }): Promise<{ readonly status: "revoked"; readonly revision: number }> {
    const result = await this.pool.query<{
      authorization_status: "revoked";
      authorization_revision: number;
    }>(
      "SELECT * FROM revoke_platform_tenant_export_download($1,$2,$3)",
      [input.authorizationId, input.expectedRevision, input.actorIdentityId],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Tenant export download revocation was not returned");
    return { status: row.authorization_status, revision: row.authorization_revision };
  }

  public async scheduleTenantDecommission(input: {
    readonly tenantId: string;
    readonly expectedVersion: number;
    readonly exportJobId: string;
    readonly retentionDays: number;
    readonly reasonCode: PlatformTenantDecommissionSummary["reasonCode"];
    readonly idempotencyKey: string;
    readonly actorIdentityId: string;
  }): Promise<TenantDecommissionResult> {
    const result = await this.pool.query<{
      decommission_id: string;
      decommission_state: "scheduled";
      tenant_version: number;
      retention_until: Date;
      sessions_revoked: number;
      reused: boolean;
    }>(
      "SELECT * FROM schedule_platform_tenant_decommission($1,$2,$3,$4,$5,$6,$7,$8)",
      [
        input.tenantId,
        input.expectedVersion,
        input.exportJobId,
        input.retentionDays,
        input.reasonCode,
        input.idempotencyKey,
        tenantDecommissionRequestHash(input),
        input.actorIdentityId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Tenant decommission schedule did not return a result");
    return {
      decommissionId: row.decommission_id,
      state: row.decommission_state,
      tenantStatus: "decommission_pending",
      version: row.tenant_version,
      retentionUntil: row.retention_until,
      sessionsRevoked: row.sessions_revoked,
      reused: row.reused,
    };
  }

  public async cancelTenantDecommission(input: {
    readonly tenantId: string;
    readonly decommissionId: string;
    readonly expectedVersion: number;
    readonly idempotencyKey: string;
    readonly actorIdentityId: string;
  }): Promise<TenantDecommissionResult> {
    const result = await this.pool.query<{
      decommission_id: string;
      decommission_state: "cancelled";
      tenant_status: "active" | "suspended";
      tenant_version: number;
      reused: boolean;
    }>(
      "SELECT * FROM cancel_platform_tenant_decommission($1,$2,$3,$4,$5,$6)",
      [
        input.tenantId,
        input.decommissionId,
        input.expectedVersion,
        input.idempotencyKey,
        tenantDecommissionCancellationHash(input),
        input.actorIdentityId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Tenant decommission cancellation did not return a result");
    return {
      decommissionId: row.decommission_id,
      state: row.decommission_state,
      tenantStatus: row.tenant_status,
      version: row.tenant_version,
      retentionUntil: null,
      sessionsRevoked: 0,
      reused: row.reused,
    };
  }

  public async suspendTenant(input: {
    readonly tenantId: string;
    readonly expectedVersion: number;
    readonly reasonCode: "security_review" | "operational_hold" | "institution_request" | "compliance_review";
    readonly actorIdentityId: string;
  }): Promise<number> {
    const result = await this.pool.query<{ version: number }>(
      "SELECT suspend_platform_tenant($1,$2,$3,$4)::int AS version",
      [input.tenantId, input.expectedVersion, input.reasonCode, input.actorIdentityId],
    );
    const version = result.rows[0]?.version;
    if (!version) throw new Error("Tenant suspension did not return a version");
    return version;
  }

  public async reactivateTenant(input: {
    readonly tenantId: string;
    readonly expectedVersion: number;
    readonly reasonCode: TenantReactivationReasonCode;
    readonly idempotencyKey: string;
    readonly actorIdentityId: string;
    readonly requestId: string;
  }): Promise<TenantReactivationResult> {
    const result = await this.pool.query<{
      tenant_version: number;
      sessions_revoked: number;
      reused: boolean;
    }>(
      "SELECT * FROM reactivate_platform_tenant($1,$2,$3,$4,$5,$6,$7)",
      [
        input.tenantId,
        input.expectedVersion,
        input.reasonCode,
        input.idempotencyKey,
        tenantReactivationRequestHash(input),
        input.actorIdentityId,
        input.requestId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Tenant reactivation did not return a result");
    return {
      tenantId: input.tenantId,
      status: "active",
      version: row.tenant_version,
      sessionsRevoked: row.sessions_revoked,
      sessionsCreated: 0,
      reused: row.reused,
    };
  }

  public async appendAudit(input: {
    actorIdentityId?: string;
    tenantId?: string;
    action: string;
    entityType?: string;
    entityId?: string;
    result: "success" | "denied" | "failure";
    requestId?: string;
    metadata?: Readonly<Record<string, unknown>>;
  }): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended('platform_audit_chain', 0))");
      const previous = await client.query<{ event_hash: string }>(
        "SELECT event_hash FROM platform_audit_events ORDER BY sequence DESC LIMIT 1",
      );
      const previousHash = previous.rows[0]?.event_hash ?? null;
      const canonical = JSON.stringify({
        previousHash,
        action: input.action,
        actorIdentityId: input.actorIdentityId ?? null,
        tenantId: input.tenantId ?? null,
        entityType: input.entityType ?? null,
        entityId: input.entityId ?? null,
        result: input.result,
        requestId: input.requestId ?? null,
        metadata: input.metadata ?? {},
      });
      const eventHash = createHash("sha256").update(canonical).digest("hex");
      await client.query(
        `INSERT INTO platform_audit_events(
           actor_identity_id, tenant_id, action, entity_type, entity_id,
           result, request_id, metadata, previous_hash, event_hash
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          input.actorIdentityId ?? null,
          input.tenantId ?? null,
          input.action,
          input.entityType ?? null,
          input.entityId ?? null,
          input.result,
          input.requestId ?? null,
          input.metadata ?? {},
          previousHash,
          eventHash,
        ],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }
}

function requireIanaTimezone(value: string): string {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value }).format(new Date(0));
    return value;
  } catch {
    throw new Error("The active tenant has an invalid persisted IANA timezone");
  }
}

function defaultAuthMethod(assuranceLevel: AuthenticationAssuranceLevel): AuthenticationMethod {
  switch (assuranceLevel) {
    case "enrollment_only": return "bootstrap";
    case "password": return "password";
    case "mfa": return "totp";
    case "recovery_limited": return "recovery_code";
  }
}

function parseSafeInteger(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`${label} is outside the supported range`);
  return parsed;
}

function parseNullableSafeInteger(value: string | null): number | null {
  return value === null ? null : parseSafeInteger(value, "Stored platform counter");
}
