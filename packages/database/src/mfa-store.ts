import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";

export type MfaAssuranceLevel = "enrollment_only" | "password" | "mfa" | "recovery_limited";

export interface MfaEnrollmentRecord {
  readonly identityId: string;
  readonly tenantId: string;
  readonly tenantSlug: string;
  readonly email: string;
  readonly displayName: string;
  readonly mfaRequired: boolean;
  readonly mfaEnabled: boolean;
  readonly enrollmentId: string | null;
  readonly enrollmentSecretCiphertext: string | null;
  readonly enrollmentStartedAt: Date | null;
  readonly authenticatedAt: Date;
  readonly mfaVerifiedAt: Date | null;
}

export interface RecoveryCodeRecord {
  readonly id: string;
  readonly hash: string;
}

export interface MfaEnrollmentSessionInput {
  readonly id: string;
  readonly tokenHash: string;
  readonly csrfHash: string;
  readonly expiresAt: Date;
  readonly idleTimeoutMinutes: number;
  readonly userAgentHash?: string;
  readonly ipPrefixHash?: string;
}

export class MfaStoreError extends Error {
  public constructor(
    public readonly code:
      | "RECENT_AUTH_REQUIRED"
      | "ENROLLMENT_ALREADY_STARTED"
      | "ENROLLMENT_INVALID"
      | "MFA_REPLAYED"
      | "RECOVERY_GOVERNANCE_INVALID",
    message: string,
  ) {
    super(message);
    this.name = "MfaStoreError";
  }
}

export class MfaStore {
  public constructor(private readonly pool: Pool) {}

  public async startEnrollment(input: {
    sessionId: string;
    identityId: string;
    enrollmentId: string;
    secretCiphertext: string;
    recentWindowMinutes: number;
  }): Promise<MfaEnrollmentRecord> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const record = await this.lockEnrollmentRecord(client, input.sessionId, input.identityId);
      assertRecent(record, input.recentWindowMinutes);
      if (
        record.enrollmentId
        && record.enrollmentSecretCiphertext
        && record.enrollmentStartedAt
        && record.enrollmentStartedAt.getTime() > Date.now() - input.recentWindowMinutes * 60_000
      ) {
        throw new MfaStoreError(
          "ENROLLMENT_ALREADY_STARTED",
          "An MFA enrollment is already active and its secret cannot be returned again",
        );
      }
      await client.query(
        `UPDATE platform_identities
            SET mfa_enrollment_id=$2,
                mfa_enrollment_secret_ciphertext=$3,
                mfa_enrollment_started_at=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE id=$1`,
        [input.identityId, input.enrollmentId, input.secretCiphertext],
      );
      const updated = await this.selectEnrollmentRecord(client, input.sessionId, input.identityId);
      if (!updated || updated.enrollmentId !== input.enrollmentId) {
        throw new MfaStoreError("ENROLLMENT_INVALID", "MFA enrollment could not be started");
      }
      await client.query("COMMIT");
      return updated;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async cancelEnrollment(input: {
    sessionId: string;
    identityId: string;
    enrollmentId: string;
    recentWindowMinutes: number;
  }): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const record = await this.lockEnrollmentRecord(client, input.sessionId, input.identityId);
      assertRecent(record, input.recentWindowMinutes);
      const result = await client.query(
        `UPDATE platform_identities
            SET mfa_enrollment_id=NULL,
                mfa_enrollment_secret_ciphertext=NULL,
                mfa_enrollment_started_at=NULL,
                updated_at=clock_timestamp()
          WHERE id=$1 AND mfa_enrollment_id=$2`,
        [input.identityId, input.enrollmentId],
      );
      await client.query("COMMIT");
      return result.rowCount === 1;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async getEnrollmentForConfirmation(input: {
    sessionId: string;
    identityId: string;
    enrollmentId: string;
    recentWindowMinutes: number;
  }): Promise<MfaEnrollmentRecord | null> {
    const record = await this.selectEnrollmentRecord(this.pool, input.sessionId, input.identityId);
    if (!record) return null;
    assertRecent(record, input.recentWindowMinutes);
    if (
      record.enrollmentId !== input.enrollmentId
      || !record.enrollmentSecretCiphertext
      || !record.enrollmentStartedAt
      || record.enrollmentStartedAt.getTime() <= Date.now() - input.recentWindowMinutes * 60_000
    ) return null;
    return record;
  }

  /**
   * Resumes an unexpired enrollment only through the same authenticated
   * session and identity that started it. The ciphertext never leaves the
   * trusted server layer; callers must not place the decrypted seed in URLs,
   * logs, analytics, or browser storage.
   */
  public async getPendingEnrollment(input: {
    sessionId: string;
    identityId: string;
    recentWindowMinutes: number;
  }): Promise<MfaEnrollmentRecord | null> {
    const record = await this.selectEnrollmentRecord(this.pool, input.sessionId, input.identityId);
    if (!record) return null;
    assertRecent(record, input.recentWindowMinutes);
    if (
      !record.enrollmentId
      || !record.enrollmentSecretCiphertext
      || !record.enrollmentStartedAt
      || record.enrollmentStartedAt.getTime() <= Date.now() - input.recentWindowMinutes * 60_000
    ) return null;
    return record;
  }

  public async completeEnrollment(input: {
    sessionId: string;
    identityId: string;
    enrollmentId: string;
    acceptedTimeStep: number;
    recoveryCodeHashes: readonly string[];
    recentWindowMinutes: number;
    tenantId: string;
    requestId: string;
    newSession: MfaEnrollmentSessionInput;
  }): Promise<{ readonly generation: number; readonly sessionId: string }> {
    if (input.recoveryCodeHashes.length !== 10 || new Set(input.recoveryCodeHashes).size !== 10) {
      throw new Error("MFA enrollment requires exactly ten distinct recovery-code hashes");
    }
    assertSha256(input.newSession.tokenHash, "MFA session token");
    assertSha256(input.newSession.csrfHash, "MFA session CSRF");
    if (!Number.isInteger(input.newSession.idleTimeoutMinutes)
        || input.newSession.idleTimeoutMinutes < 5
        || input.newSession.idleTimeoutMinutes > 1440
        || input.newSession.expiresAt.getTime() <= Date.now()) {
      throw new Error("MFA enrollment session is invalid");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      // This is deliberately the first lock after BEGIN. It serializes both
      // original invitation enrollment and recovery enrollment with governed
      // approval/redemption before either path locks the target identity.
      const recoveryAuthorization = await client.query<{ authorization: string }>(
        `SELECT authorize_initial_admin_recovery_factor_transaction($1,$2)
                AS authorization`,
        [input.sessionId, input.requestId],
      );
      const authorization = recoveryAuthorization.rows[0]?.authorization;
      if (authorization === "governance_invalidated") {
        await client.query("COMMIT");
        throw new MfaStoreError(
          "RECOVERY_GOVERNANCE_INVALID",
          "Initial-admin recovery authority was withdrawn",
        );
      }
      if (authorization !== "authorized" && authorization !== "not_recovery") {
        throw new MfaStoreError("ENROLLMENT_INVALID", "MFA enrollment recovery context is unavailable");
      }
      const record = await this.lockEnrollmentRecord(client, input.sessionId, input.identityId);
      assertRecent(record, input.recentWindowMinutes);
      if (
        record.enrollmentId !== input.enrollmentId
        || !record.enrollmentSecretCiphertext
        || !record.enrollmentStartedAt
        || record.enrollmentStartedAt.getTime() <= Date.now() - input.recentWindowMinutes * 60_000
      ) {
        throw new MfaStoreError("ENROLLMENT_INVALID", "MFA enrollment is invalid or expired");
      }
      const updated = await client.query<{ generation: number }>(
        `UPDATE platform_identities
            SET totp_secret_ciphertext=mfa_enrollment_secret_ciphertext,
                mfa_enabled=true,
                mfa_enrolled_at=clock_timestamp(),
                mfa_recovery_generation=mfa_recovery_generation+1,
                mfa_last_used_step=$3,
                mfa_enrollment_id=NULL,
                mfa_enrollment_secret_ciphertext=NULL,
                mfa_enrollment_started_at=NULL,
                updated_at=clock_timestamp()
          WHERE id=$1 AND mfa_enrollment_id=$2
          RETURNING mfa_recovery_generation AS generation`,
        [input.identityId, input.enrollmentId, input.acceptedTimeStep],
      );
      const generation = updated.rows[0]?.generation;
      if (!generation) throw new MfaStoreError("ENROLLMENT_INVALID", "MFA enrollment is no longer valid");
      await client.query(
        `UPDATE mfa_recovery_codes
            SET revoked_at=clock_timestamp()
          WHERE identity_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL`,
        [input.identityId],
      );
      await client.query(
        `INSERT INTO mfa_recovery_codes(identity_id,generation,code_hash)
         SELECT $1,$2,code_hash
           FROM unnest($3::text[]) AS generated(code_hash)`,
        [input.identityId, generation, [...input.recoveryCodeHashes]],
      );
      await this.revokeSessions(client, input.identityId, "mfa_enrollment_completed");
      await client.query(
        `UPDATE mfa_challenges
            SET consumed_at=COALESCE(consumed_at,clock_timestamp())
          WHERE identity_id=$1 AND consumed_at IS NULL`,
        [input.identityId],
      );
      const authenticationContext = await client.query<{ active: boolean }>(
        "SELECT lock_active_authentication_context($1,$2) AS active",
        [input.identityId, input.tenantId],
      );
      if (authenticationContext.rows[0]?.active !== true) {
        throw new MfaStoreError("ENROLLMENT_INVALID", "MFA enrollment tenant context is unavailable");
      }
      const policyResult = await client.query<{
        idle_timeout_minutes: number;
        absolute_session_minutes: number;
      }>(
        `SELECT COALESCE(policy.idle_timeout_minutes,baseline.idle_timeout_minutes)
                  AS idle_timeout_minutes,
                COALESCE(policy.absolute_session_minutes,baseline.absolute_session_minutes)
                  AS absolute_session_minutes
           FROM public.tenants tenant
           CROSS JOIN public.identity_policy_baseline baseline
           LEFT JOIN public.tenant_identity_policies policy ON policy.tenant_id=tenant.id
          WHERE tenant.id=$1 AND tenant.status='active' AND baseline.policy_key='global'`,
        [input.tenantId],
      );
      const policy = policyResult.rows[0];
      if (!policy) throw new MfaStoreError("ENROLLMENT_INVALID", "MFA session policy is unavailable");
      const idleTimeoutMinutes = Math.min(
        input.newSession.idleTimeoutMinutes,
        policy.idle_timeout_minutes,
      );
      const insertedSession = await client.query<{ id: string }>(
        `INSERT INTO public.auth_sessions(
           id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
           user_agent_hash,ip_prefix_hash,assurance_level,mfa_verified_at,
           auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,
           idle_timeout_minutes,idle_expires_at,last_user_agent_hash,last_ip_prefix_hash
         ) VALUES (
           $1,$2,$3,$4,$5,
           LEAST($6,clock_timestamp()+make_interval(mins=>$7)),
           $8,$9,'mfa',clock_timestamp(),'totp',2,false,NULL,false,$10,
           LEAST($6,clock_timestamp()+make_interval(mins=>$10)),$8,$9
         )
         RETURNING id`,
        [
          input.newSession.id,
          input.newSession.tokenHash,
          input.newSession.csrfHash,
          input.identityId,
          input.tenantId,
          input.newSession.expiresAt,
          policy.absolute_session_minutes,
          input.newSession.userAgentHash ?? null,
          input.newSession.ipPrefixHash ?? null,
          idleTimeoutMinutes,
        ],
      );
      const sessionId = insertedSession.rows[0]?.id;
      if (!sessionId) throw new MfaStoreError("ENROLLMENT_INVALID", "MFA session was not persisted");
      const finalization = await client.query<{ recovery_id: string }>(
        "SELECT recovery_id FROM finalize_initial_admin_onboarding_recovery($1,$2,$3)",
        [input.sessionId, sessionId, input.requestId],
      );
      if (authorization === "authorized" && finalization.rowCount !== 1) {
        throw new MfaStoreError(
          "RECOVERY_GOVERNANCE_INVALID",
          "Initial-admin recovery could not be finalized atomically",
        );
      }
      await appendPlatformAudit(client, {
        actorIdentityId: input.identityId,
        tenantId: input.tenantId,
        action: "auth.mfa_enrolled",
        entityType: "identity",
        entityId: input.identityId,
        requestId: input.requestId,
        metadata: {
          recoveryCodeCount: input.recoveryCodeHashes.length,
          rotated: record.mfaEnabled,
          initialAdminRecoveryFinalized: authorization === "authorized",
        },
      });
      await client.query("COMMIT");
      return { generation, sessionId };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async consumeTotpChallenge(input: {
    challengeId: string;
    identityId: string;
    acceptedTimeStep: number;
  }): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const identity = await client.query<{ last_step: string | null }>(
        `SELECT mfa_last_used_step::text AS last_step
           FROM platform_identities
          WHERE id=$1 AND status='active' AND mfa_enabled
            AND (locked_until IS NULL OR locked_until<=clock_timestamp())
          FOR UPDATE`,
        [input.identityId],
      );
      const lastStep = identity.rows[0]?.last_step;
      if (
        identity.rowCount !== 1
        || (lastStep !== null && lastStep !== undefined && BigInt(lastStep) >= BigInt(input.acceptedTimeStep))
      ) {
        throw new MfaStoreError("MFA_REPLAYED", "The MFA code has already been used");
      }
      const consumed = await client.query(
        `UPDATE mfa_challenges
            SET consumed_at=clock_timestamp()
          WHERE id=$1 AND identity_id=$2 AND consumed_at IS NULL
            AND expires_at>clock_timestamp() AND attempt_count BETWEEN 1 AND 6`,
        [input.challengeId, input.identityId],
      );
      if (consumed.rowCount !== 1) {
        await client.query("ROLLBACK");
        return false;
      }
      await client.query(
        "UPDATE platform_identities SET mfa_last_used_step=$2,updated_at=clock_timestamp() WHERE id=$1",
        [input.identityId, input.acceptedTimeStep],
      );
      await client.query("COMMIT");
      return true;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async listActiveRecoveryCodes(identityId: string): Promise<readonly RecoveryCodeRecord[]> {
    const result = await this.pool.query<{ id: string; code_hash: string }>(
      `SELECT code.id,code.code_hash
         FROM mfa_recovery_codes code
         JOIN platform_identities identity
           ON identity.id=code.identity_id
          AND identity.mfa_recovery_generation=code.generation
        WHERE code.identity_id=$1
          AND code.consumed_at IS NULL
          AND code.revoked_at IS NULL
        ORDER BY code.created_at,code.id`,
      [identityId],
    );
    return result.rows.map((row) => ({ id: row.id, hash: row.code_hash }));
  }

  public async consumeRecoveryChallenge(input: {
    challengeId: string;
    identityId: string;
    recoveryCodeId: string;
    tenantId: string;
    requestId: string;
  }): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const identity = await client.query(
        `SELECT 1
           FROM platform_identities
          WHERE id=$1 AND status='active' AND mfa_enabled
            AND (locked_until IS NULL OR locked_until<=clock_timestamp())
          FOR UPDATE`,
        [input.identityId],
      );
      const challenge = await client.query(
        `SELECT 1 FROM mfa_challenges
          WHERE id=$1 AND identity_id=$2 AND consumed_at IS NULL
            AND expires_at>clock_timestamp() AND attempt_count BETWEEN 1 AND 6
          FOR UPDATE`,
        [input.challengeId, input.identityId],
      );
      const recovery = await client.query(
        `SELECT 1
           FROM mfa_recovery_codes code
           JOIN platform_identities identity
             ON identity.id=code.identity_id
            AND identity.mfa_recovery_generation=code.generation
          WHERE code.id=$1 AND code.identity_id=$2
            AND code.consumed_at IS NULL AND code.revoked_at IS NULL
          FOR UPDATE OF code`,
        [input.recoveryCodeId, input.identityId],
      );
      if (identity.rowCount !== 1 || challenge.rowCount !== 1 || recovery.rowCount !== 1) {
        await client.query("ROLLBACK");
        return false;
      }
      await client.query(
        "UPDATE mfa_recovery_codes SET consumed_at=clock_timestamp() WHERE id=$1",
        [input.recoveryCodeId],
      );
      await client.query(
        `UPDATE mfa_challenges
            SET consumed_at=COALESCE(consumed_at,clock_timestamp())
          WHERE identity_id=$1 AND consumed_at IS NULL`,
        [input.identityId],
      );
      await this.revokeSessions(client, input.identityId, "mfa_recovery_code_used");
      await appendPlatformAudit(client, {
        actorIdentityId: input.identityId,
        tenantId: input.tenantId,
        action: "auth.mfa_recovery_code_used",
        entityType: "identity",
        entityId: input.identityId,
        requestId: input.requestId,
        metadata: { sessionsRevoked: true },
      });
      await client.query("COMMIT");
      return true;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  private async selectEnrollmentRecord(
    queryable: Pick<Pool, "query"> | Pick<PoolClient, "query">,
    sessionId: string,
    identityId: string,
  ): Promise<MfaEnrollmentRecord | null> {
    const result = await queryable.query<EnrollmentRow>(enrollmentRecordSql(false), [sessionId, identityId]);
    return result.rows[0] ? mapEnrollmentRecord(result.rows[0]) : null;
  }

  private async lockEnrollmentRecord(
    client: PoolClient,
    sessionId: string,
    identityId: string,
  ): Promise<MfaEnrollmentRecord> {
    const result = await client.query<EnrollmentRow>(enrollmentRecordSql(true), [sessionId, identityId]);
    const row = result.rows[0];
    if (!row) throw new MfaStoreError("RECENT_AUTH_REQUIRED", "A valid recent session is required");
    return mapEnrollmentRecord(row);
  }

  private async revokeSessions(client: PoolClient, identityId: string, reason: string): Promise<void> {
    await client.query(
      `UPDATE auth_sessions
          SET revoked_at=clock_timestamp(),revoke_reason=$2
        WHERE identity_id=$1 AND revoked_at IS NULL`,
      [identityId, reason],
    );
  }
}

interface EnrollmentRow {
  readonly identity_id: string;
  readonly tenant_id: string;
  readonly tenant_slug: string;
  readonly email: string;
  readonly display_name: string;
  readonly mfa_required: boolean;
  readonly mfa_enabled: boolean;
  readonly mfa_enrollment_id: string | null;
  readonly mfa_enrollment_secret_ciphertext: string | null;
  readonly mfa_enrollment_started_at: Date | null;
  readonly authenticated_at: Date;
  readonly mfa_verified_at: Date | null;
}

function enrollmentRecordSql(lock: boolean): string {
  return `SELECT identity.id AS identity_id,tenant.id AS tenant_id,tenant.slug AS tenant_slug,
                 identity.email,identity.display_name,identity.mfa_required,identity.mfa_enabled,
                 identity.mfa_enrollment_id,identity.mfa_enrollment_secret_ciphertext,
                 identity.mfa_enrollment_started_at,session.authenticated_at,session.mfa_verified_at
            FROM auth_sessions session
            JOIN platform_identities identity ON identity.id=session.identity_id
            JOIN tenants tenant ON tenant.id=session.active_tenant_id
           WHERE session.id=$1 AND identity.id=$2
             AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
             AND session.idle_expires_at>clock_timestamp()
             AND identity.status='active' AND tenant.status='active'
           ${lock ? "FOR UPDATE OF identity,session" : ""}`;
}

function mapEnrollmentRecord(row: EnrollmentRow): MfaEnrollmentRecord {
  return {
    identityId: row.identity_id,
    tenantId: row.tenant_id,
    tenantSlug: row.tenant_slug,
    email: row.email,
    displayName: row.display_name,
    mfaRequired: row.mfa_required,
    mfaEnabled: row.mfa_enabled,
    enrollmentId: row.mfa_enrollment_id,
    enrollmentSecretCiphertext: row.mfa_enrollment_secret_ciphertext,
    enrollmentStartedAt: row.mfa_enrollment_started_at,
    authenticatedAt: row.authenticated_at,
    mfaVerifiedAt: row.mfa_verified_at,
  };
}

function assertRecent(record: MfaEnrollmentRecord, recentWindowMinutes: number): void {
  const lastStrongAuthentication = record.mfaVerifiedAt ?? record.authenticatedAt;
  if (lastStrongAuthentication.getTime() <= Date.now() - recentWindowMinutes * 60_000) {
    throw new MfaStoreError("RECENT_AUTH_REQUIRED", "Recent authentication is required for MFA changes");
  }
}

function assertSha256(value: string, label: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new Error(`${label} hash is invalid`);
}

async function appendPlatformAudit(client: PoolClient, input: {
  actorIdentityId: string;
  tenantId: string;
  action: string;
  entityType: string;
  entityId: string;
  requestId: string;
  metadata: Readonly<Record<string, unknown>>;
}): Promise<void> {
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('platform_audit_chain',0))");
  const previous = await client.query<{ event_hash: string }>(
    "SELECT event_hash FROM platform_audit_events ORDER BY sequence DESC LIMIT 1",
  );
  const previousHash = previous.rows[0]?.event_hash ?? null;
  const canonical = JSON.stringify({
    previousHash,
    action: input.action,
    actorIdentityId: input.actorIdentityId,
    tenantId: input.tenantId,
    entityType: input.entityType,
    entityId: input.entityId,
    result: "success",
    requestId: input.requestId,
    metadata: input.metadata,
  });
  const eventHash = createHash("sha256").update(canonical).digest("hex");
  await client.query(
    `INSERT INTO platform_audit_events(
       actor_identity_id,tenant_id,action,entity_type,entity_id,result,
       request_id,metadata,previous_hash,event_hash
     ) VALUES ($1,$2,$3,$4,$5,'success',$6,$7,$8,$9)`,
    [
      input.actorIdentityId,
      input.tenantId,
      input.action,
      input.entityType,
      input.entityId,
      input.requestId,
      input.metadata,
      previousHash,
      eventHash,
    ],
  );
}
