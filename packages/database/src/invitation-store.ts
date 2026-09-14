import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { INVITATION_REVOKE_REASON_CODES, normalizeAllowedReasonCode } from "./reason-code.js";

export const TENANT_INVITATION_ROLES = [
  "AUDITOR",
  "CHURCH_ADMIN",
  "COMMITTEE_CHAIR",
  "COMMITTEE_MEMBER",
  "COMMITTEE_SECRETARY",
  "TALLY_CUSTODIAN",
] as const;

export type TenantInvitationRole = typeof TENANT_INVITATION_ROLES[number];
export type TenantInvitationAuthorityKind = "tenant_delegate" | "initial_admin";
export type TenantInvitationStatus = "pending" | "accepting" | "compensating" | "accepted" | "revoked" | "expired" | "failed";

export interface TenantInvitationSummary {
  readonly id: string;
  readonly tenantId: string;
  readonly email: string;
  readonly roles: readonly TenantInvitationRole[];
  readonly status: TenantInvitationStatus;
  readonly expiresAt: Date;
  readonly createdAt: Date;
  readonly acceptedAt: Date | null;
  readonly revokedAt: Date | null;
  readonly version: number;
}

/**
 * A successful passwordless invitation can atomically issue an
 * invitation-bound enrollment-only session. Its bearer and CSRF secrets are
 * supplied by the caller and deliberately never returned by the store.
 */
export interface TenantInvitationCompletion extends TenantInvitationSummary {
  readonly enrollmentSession?: {
    readonly id: string;
    readonly expiresAt: Date;
  };
}

export interface TenantInvitationClaim {
  readonly invitationId: string;
  readonly acceptanceId: string;
  readonly identityId: string;
  readonly tenantId: string;
  readonly email: string;
  readonly normalizedEmail: string;
  readonly roles: readonly TenantInvitationRole[];
  readonly expiresAt: Date;
  readonly createdByIdentityId: string;
  readonly authorityKind: TenantInvitationAuthorityKind;
  readonly authorityEpoch: number;
  readonly acceptanceAttempt: number;
}

export interface TenantInvitationRecovery {
  readonly claim: TenantInvitationClaim;
  readonly action: "compensate" | "finalize";
  readonly resetAfterCompensation: boolean;
  readonly fenced: boolean;
}

export interface TenantInvitationReconciliationCandidate {
  readonly claim: TenantInvitationClaim;
  readonly status: TenantInvitationStatus;
  readonly reconciliationAttemptCount: number;
  readonly leaseExpiresAt: Date;
}

export class InvitationStoreError extends Error {
  public constructor(
    public readonly code:
      | "IDEMPOTENCY_CONFLICT"
      | "INVITATION_RECIPIENT_UNAVAILABLE"
      | "INVITATION_GRANTOR_UNAVAILABLE"
      | "INVITATION_NOT_REVOCABLE"
      | "POLICY_CONFLICT"
      | "PASSWORD_REQUIRED"
      | "INVALID_REASON_CODE",
    message: string,
  ) {
    super(message);
    this.name = "InvitationStoreError";
  }
}

interface InvitationRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly email: string;
  readonly normalized_email: string;
  readonly role_codes: TenantInvitationRole[];
  readonly status: TenantInvitationStatus;
  readonly request_hash: string;
  readonly created_by_identity_id: string;
  readonly authority_kind: TenantInvitationAuthorityKind;
  readonly authority_epoch: string | number;
  readonly acceptance_attempt: number;
  readonly created_at: Date;
  readonly expires_at: Date;
  readonly acceptance_started_at: Date | null;
  readonly accepted_at: Date | null;
  readonly revoked_at: Date | null;
  readonly version: number;
}

export class InvitationStore {
  public constructor(private readonly pool: Pool) {}

  public async create(input: {
    tenantId: string;
    actorIdentityId: string;
    email: string;
    normalizedEmail: string;
    roles: readonly TenantInvitationRole[];
    tokenHash: string;
    expiresAt: Date;
    idempotencyKey: string;
    requestHash: string;
    requestId: string;
  }): Promise<{ invitation: TenantInvitationSummary; created: boolean }> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const actor = await client.query<{ active: boolean }>(
        "SELECT lock_active_authentication_context($1,$2) AS active",
        [input.actorIdentityId, input.tenantId],
      );
      if (actor.rows[0]?.active !== true) {
        throw new InvitationStoreError("INVITATION_GRANTOR_UNAVAILABLE", "Invitation grantor is unavailable");
      }
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [input.normalizedEmail]);
      const existing = await client.query<InvitationRow>(
        `SELECT id,tenant_id,email,normalized_email,role_codes,status,request_hash,
                created_by_identity_id,created_at,expires_at,acceptance_started_at,
                accepted_at,revoked_at,version
           FROM find_tenant_invitation_idempotency($1,$2,$3)`,
        [input.tenantId, input.actorIdentityId, input.idempotencyKey],
      );
      const prior = existing.rows[0];
      if (prior) {
        if (prior.request_hash !== input.requestHash) {
          throw new InvitationStoreError("IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different invitation input");
        }
        await client.query("COMMIT");
        return { invitation: summary(prior), created: false };
      }
      const unavailable = await client.query(
        `SELECT 1 FROM platform_identities WHERE normalized_email=$1
         UNION ALL
         SELECT 1 FROM tenant_invitations
          WHERE normalized_email=$1 AND status IN ('pending','accepting')
         LIMIT 1`,
        [input.normalizedEmail],
      );
      if (unavailable.rowCount !== 0) {
        throw new InvitationStoreError("INVITATION_RECIPIENT_UNAVAILABLE", "Invitation cannot be created");
      }

      const inserted = await client.query<InvitationRow>(
        `INSERT INTO tenant_invitations(
           tenant_id,email,normalized_email,role_codes,token_hash,expires_at,
           idempotency_key,request_hash,created_by_identity_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING id,tenant_id,email,normalized_email,role_codes,status,
                   created_by_identity_id,created_at,expires_at,acceptance_started_at,
                   accepted_at,revoked_at,version`,
        [
          input.tenantId,
          input.email,
          input.normalizedEmail,
          [...input.roles],
          input.tokenHash,
          input.expiresAt,
          input.idempotencyKey,
          input.requestHash,
          input.actorIdentityId,
        ],
      );
      const row = inserted.rows[0];
      if (!row) throw new Error("Invitation insert did not return a row");
      await appendPlatformAudit(client, {
        actorIdentityId: input.actorIdentityId,
        tenantId: input.tenantId,
        action: "invitation.created",
        entityType: "tenant_invitation",
        entityId: row.id,
        result: "success",
        requestId: input.requestId,
        metadata: { roles: [...input.roles], expiresAt: input.expiresAt.toISOString() },
      });
      await client.query("COMMIT");
      return { invitation: summary(row), created: true };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (isUniqueViolation(error)) {
        throw new InvitationStoreError("INVITATION_RECIPIENT_UNAVAILABLE", "Invitation cannot be created");
      }
      throw error;
    } finally {
      client.release();
    }
  }

  public async list(tenantId: string, limit: number): Promise<readonly TenantInvitationSummary[]> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `UPDATE tenant_invitations
            SET status='expired',updated_at=clock_timestamp(),version=version+1
          WHERE tenant_id=$1 AND status='pending' AND expires_at<=clock_timestamp()`,
        [tenantId],
      );
      const result = await client.query<InvitationRow>(
        `SELECT id,tenant_id,email,normalized_email,role_codes,status,
                created_by_identity_id,created_at,expires_at,acceptance_started_at,
                accepted_at,revoked_at,version
           FROM tenant_invitations
          WHERE tenant_id=$1
          ORDER BY created_at DESC,id DESC
          LIMIT $2`,
        [tenantId, limit],
      );
      await client.query("COMMIT");
      return result.rows.map(summary);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async revoke(input: {
    invitationId: string;
    tenantId: string;
    actorIdentityId: string;
    reasonCode?: string;
    requestId: string;
  }): Promise<{
    invitation: TenantInvitationSummary;
    tenantCleanupRequired: boolean;
    cleanupClaim: TenantInvitationClaim | null;
  } | null> {
    const reasonCode = input.reasonCode === undefined
      ? null
      : normalizeAllowedReasonCode(input.reasonCode, INVITATION_REVOKE_REASON_CODES);
    if (input.reasonCode !== undefined && !reasonCode) {
      throw new InvitationStoreError("INVALID_REASON_CODE", "Invitation revocation reason code is not allowed");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const selected = await client.query<InvitationRow & {
        acceptance_id: string | null;
        acceptance_identity_id: string | null;
      }>(
        `SELECT id,tenant_id,email,normalized_email,role_codes,status,
                created_by_identity_id,created_at,expires_at,acceptance_started_at,
                acceptance_id,acceptance_identity_id,accepted_at,revoked_at,version,
                authority_kind,authority_epoch,acceptance_attempt
           FROM tenant_invitations
          WHERE id=$1 AND tenant_id=$2
          FOR UPDATE`,
        [input.invitationId, input.tenantId],
      );
      const row = selected.rows[0];
      if (!row) {
        await client.query("COMMIT");
        return null;
      }
      if (row.status === "revoked") {
        await client.query("COMMIT");
        const cleanupClaim = cleanupClaimFromRow(row);
        return {
          invitation: summary(row),
          tenantCleanupRequired: cleanupClaim !== null,
          cleanupClaim,
        };
      }
      if (
        row.status !== "pending"
        && row.status !== "accepting"
        && row.status !== "compensating"
        && row.status !== "expired"
        && row.status !== "failed"
      ) {
        throw new InvitationStoreError("INVITATION_NOT_REVOCABLE", "Invitation is no longer revocable");
      }
      const updated = await client.query<InvitationRow>(
        `UPDATE tenant_invitations
            SET status='revoked',revoked_at=clock_timestamp(),revoked_by_identity_id=$3,
                revocation_reason=$4,updated_at=clock_timestamp(),version=version+1
          WHERE id=$1 AND tenant_id=$2
          RETURNING id,tenant_id,email,normalized_email,role_codes,status,
                    created_by_identity_id,created_at,expires_at,acceptance_started_at,
                    acceptance_id,acceptance_identity_id,accepted_at,revoked_at,version,
                    authority_kind,authority_epoch,acceptance_attempt`,
        [input.invitationId, input.tenantId, input.actorIdentityId, reasonCode],
      );
      const updatedRow = updated.rows[0];
      if (!updatedRow) throw new Error("Invitation revocation did not return a row");
      await appendPlatformAudit(client, {
        actorIdentityId: input.actorIdentityId,
        tenantId: input.tenantId,
        action: "invitation.revoked",
        entityType: "tenant_invitation",
        entityId: input.invitationId,
        result: "success",
        requestId: input.requestId,
        metadata: { reasonCode },
      });
      await client.query("COMMIT");
      const cleanupClaim = cleanupClaimFromRow(row);
      return {
        invitation: summary(updatedRow),
        tenantCleanupRequired: cleanupClaim !== null,
        cleanupClaim,
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async claim(input: {
    token: string;
    normalizedEmail: string;
    recoveryProof: string;
    acceptanceId: string;
    identityId: string;
  }): Promise<TenantInvitationClaim | null> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const candidate = await client.query<{
        id: string;
        tenant_id: string;
        email: string;
        normalized_email: string;
        role_codes: TenantInvitationRole[];
        expires_at: Date;
        created_by_identity_id: string;
        authority_kind: TenantInvitationAuthorityKind;
        status: TenantInvitationStatus;
      }>(
        "SELECT * FROM inspect_tenant_invitation_bearer($1,$2,$3)",
        [input.token, input.normalizedEmail, input.recoveryProof],
      );
      const candidateRow = candidate.rows[0];
      if (!candidateRow) {
        await client.query("COMMIT");
        return null;
      }
      if (candidate.rowCount !== 1 || candidateRow.status !== "pending") {
        await client.query("COMMIT");
        return null;
      }
      // The runtime role intentionally cannot lock identity, membership or
      // tenant rows directly.  The narrow 023 SECURITY DEFINER boundary takes
      // the canonical tenant-policy advisory lock and holds share locks on the
      // exact grantor context for the remainder of this claim transaction.
      const grantor = await client.query<{ active: boolean }>(
        "SELECT lock_active_invitation_grantor($1,$2,$3,$4) AS active",
        [
          candidateRow.id,
          candidateRow.created_by_identity_id,
          candidateRow.tenant_id,
          candidateRow.authority_kind,
        ],
      );
      if (grantor.rows[0]?.active !== true) {
        await client.query("COMMIT");
        return null;
      }
      const begun = await client.query<{
        id: string;
        tenant_id: string;
        email: string;
        normalized_email: string;
        role_codes: TenantInvitationRole[];
        expires_at: Date;
        created_by_identity_id: string;
        authority_kind: TenantInvitationAuthorityKind;
        acceptance_attempt: number;
        authority_epoch: string;
      }>(
        `SELECT * FROM begin_tenant_invitation_acceptance($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          candidateRow.id,
          input.token,
          input.normalizedEmail,
          input.recoveryProof,
          candidateRow.created_by_identity_id,
          candidateRow.tenant_id,
          candidateRow.authority_kind,
          input.acceptanceId,
          input.identityId,
        ],
      );
      const attempt = begun.rows[0];
      if (!attempt) {
        await client.query("COMMIT");
        return null;
      }
      const authorityEpoch = safePositiveInteger(attempt.authority_epoch, "invitation authority epoch", true);
      const acceptanceAttempt = safePositiveInteger(attempt.acceptance_attempt, "invitation acceptance attempt");
      await client.query("COMMIT");
      return {
        invitationId: attempt.id,
        acceptanceId: input.acceptanceId,
        identityId: input.identityId,
        tenantId: attempt.tenant_id,
        email: attempt.email,
        normalizedEmail: attempt.normalized_email,
        roles: attempt.role_codes,
        expiresAt: attempt.expires_at,
        createdByIdentityId: attempt.created_by_identity_id,
        authorityKind: attempt.authority_kind,
        authorityEpoch,
        acceptanceAttempt,
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async complete(input: {
    claim: TenantInvitationClaim;
    displayName: string;
    /** User-selected password hash. Omit for passkey-first onboarding. */
    passwordHash?: string;
    /** Argon2id hash of a random, discarded secret; never a user password. */
    disabledPasswordHash: string;
    requestId: string;
    bootstrapSession: {
      sessionId: string;
      tokenHash: string;
      csrfHash: string;
      expiresAt: Date;
      userAgentHash?: string;
      ipPrefixHash?: string;
    };
  }): Promise<TenantInvitationCompletion | null> {
    if (input.passwordHash !== undefined && !input.passwordHash.startsWith("$argon2id$")) {
      throw new Error("Invitation password hash must use Argon2id");
    }
    if (!input.disabledPasswordHash.startsWith("$argon2id$")) {
      throw new Error("Disabled invitation password hash must use Argon2id");
    }
    assertInvitationBootstrapSession(input.bootstrapSession);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      // Linearization order is grantor authority -> invitation.  The 023
      // definer holds the active identity/membership/tenant rows through the
      // completion transaction, so offboarding either commits first and makes
      // this return null or waits until this authorized acceptance commits.
      const grantor = await client.query<{ active: boolean }>(
        "SELECT lock_active_invitation_grantor($1,$2,$3,$4) AS active",
        [
          input.claim.invitationId,
          input.claim.createdByIdentityId,
          input.claim.tenantId,
          input.claim.authorityKind,
        ],
      );
      if (grantor.rows[0]?.active !== true) {
        await client.query("COMMIT");
        return null;
      }
      // Policy activation locks this same tenant key before it snapshots the
      // active membership set. Hold it through both the policy read and the
      // SECURITY DEFINER activation so a new password-only member cannot slip
      // in after an enforce-mode readiness check.
      await lockTenantIdentityPolicy(client, input.claim.tenantId);
      const applied = await client.query<{ completed: boolean; session_expires_at: Date | null }>(
        `SELECT * FROM complete_tenant_invitation_acceptance(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
         )`,
        [
          input.claim.invitationId,
          input.claim.acceptanceId,
          input.claim.identityId,
          input.claim.acceptanceAttempt,
          input.claim.tenantId,
          input.claim.normalizedEmail,
          input.displayName,
          input.passwordHash ?? null,
          input.bootstrapSession.sessionId,
          input.bootstrapSession.tokenHash,
          input.bootstrapSession.csrfHash,
          input.bootstrapSession.expiresAt,
          input.bootstrapSession.userAgentHash ?? null,
          input.bootstrapSession.ipPrefixHash ?? null,
          input.disabledPasswordHash,
        ],
      );
      if (applied.rows[0]?.completed !== true) {
        await client.query("COMMIT");
        return null;
      }
      const completed = await client.query<InvitationRow>(
        `SELECT id,tenant_id,email,normalized_email,role_codes,status,
                created_by_identity_id,created_at,expires_at,acceptance_started_at,
                accepted_at,revoked_at,version
           FROM tenant_invitations
          WHERE id=$1 AND status='accepted'`,
        [input.claim.invitationId],
      );
      const completedRow = completed.rows[0];
      if (!completedRow) throw new Error("Invitation completion did not return a row");
      const enrollmentExpiresAt = applied.rows[0]?.session_expires_at;
      if (!enrollmentExpiresAt) {
        throw new Error("Invitation enrollment session expiry was not returned");
      }
      await appendPlatformAudit(client, {
        actorIdentityId: input.claim.identityId,
        tenantId: completedRow.tenant_id,
        action: "invitation.accepted",
        entityType: "tenant_invitation",
        entityId: completedRow.id,
        result: "success",
        requestId: input.requestId,
        metadata: {
          roles: [...completedRow.role_codes],
          mfaEnrolled: false,
          enrollmentOnly: true,
        },
      });
      await client.query("COMMIT");
      return {
        ...summary(completedRow),
        enrollmentSession: {
          id: input.bootstrapSession.sessionId,
          expiresAt: enrollmentExpiresAt,
        },
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (isUniqueViolation(error)) {
        throw new InvitationStoreError("INVITATION_RECIPIENT_UNAVAILABLE", "Invitation cannot be accepted");
      }
      if (isInvitationPolicyConflict(error)) {
        throw new InvitationStoreError(
          "POLICY_CONFLICT",
          "Invitation acceptance would create an active identity without a usable authentication path",
        );
      }
      if (isInvitationPasswordRequired(error)) {
        throw new InvitationStoreError(
          "PASSWORD_REQUIRED",
          "A password is required by the current invitation policy",
        );
      }
      if (isInvitationGrantorInactive(error)) {
        throw new InvitationStoreError(
          "INVITATION_GRANTOR_UNAVAILABLE",
          "Invitation grantor is no longer active",
        );
      }
      throw error;
    } finally {
      client.release();
    }
  }

  public async getAcceptanceStatus(claim: TenantInvitationClaim): Promise<TenantInvitationStatus | null> {
    const result = await this.pool.query<{ status: TenantInvitationStatus }>(
      `SELECT status FROM tenant_invitations
        WHERE id=$1 AND acceptance_id=$2 AND acceptance_identity_id=$3
          AND acceptance_attempt=$4 AND tenant_id=$5 AND authority_kind=$6`,
      [
        claim.invitationId,
        claim.acceptanceId,
        claim.identityId,
        claim.acceptanceAttempt,
        claim.tenantId,
        claim.authorityKind,
      ],
    );
    return result.rows[0]?.status ?? null;
  }

  public async claimReconciliationCandidate(
    leaseToken: string,
  ): Promise<TenantInvitationReconciliationCandidate | null> {
    const result = await this.pool.query<InvitationRow & {
      acceptance_id: string;
      acceptance_identity_id: string;
      reconciliation_attempt_count: number;
      reconciliation_lease_expires_at: Date;
    }>(
      "SELECT * FROM claim_tenant_invitation_reconciliation($1)",
      [leaseToken],
    );
    const row = result.rows[0];
    if (!row) return null;
    const claim = cleanupClaimFromRow(row);
    if (!claim) throw new Error("Invitation reconciliation candidate has an incomplete acceptance tuple");
    return {
      claim,
      status: row.status,
      reconciliationAttemptCount: safePositiveInteger(
        row.reconciliation_attempt_count,
        "invitation reconciliation attempt count",
      ),
      leaseExpiresAt: row.reconciliation_lease_expires_at,
    };
  }

  public async finalizeReconciledAuthority(input: {
    claim: TenantInvitationClaim;
    leaseToken: string;
    requestId: string;
  }): Promise<boolean> {
    return this.finishReconciliationWithAudit(input, "authority_finalized", async (client) => {
      const finalized = await client.query<{ finalized: boolean }>(
        "SELECT mark_tenant_invitation_authority_finalized($1,$2,$3,$4) AS finalized",
        [
          input.claim.invitationId,
          input.claim.acceptanceId,
          input.claim.identityId,
          input.claim.acceptanceAttempt,
        ],
      );
      return finalized.rows[0]?.finalized === true;
    });
  }

  public async finalizeReconciledAcceptanceReset(input: {
    claim: TenantInvitationClaim;
    leaseToken: string;
    requestId: string;
  }): Promise<boolean> {
    return this.finishReconciliationWithAudit(input, "acceptance_reset", async (client) => {
      const reset = await client.query(
        `UPDATE tenant_invitations
            SET status=CASE WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'pending' END,
                acceptance_id=NULL,acceptance_identity_id=NULL,acceptance_started_at=NULL,
                acceptance_recovery_hash=NULL,last_error_code='BACKGROUND_ACCEPTANCE_RECOVERED',
                updated_at=clock_timestamp(),version=version+1
          WHERE id=$1 AND acceptance_id=$2 AND acceptance_identity_id=$3
            AND acceptance_attempt=$4 AND status='compensating'`,
        [
          input.claim.invitationId,
          input.claim.acceptanceId,
          input.claim.identityId,
          input.claim.acceptanceAttempt,
        ],
      );
      return reset.rowCount === 1;
    });
  }

  public async finalizeReconciledTerminalCleanup(input: {
    claim: TenantInvitationClaim;
    leaseToken: string;
    requestId: string;
  }): Promise<boolean> {
    return this.finishReconciliationWithAudit(input, "terminal_cleanup_finalized", async (client) => {
      const finalized = await client.query<{ completed: boolean }>(
        "SELECT mark_tenant_invitation_cleanup_completed($1,$2,$3,$4) AS completed",
        [
          input.claim.invitationId,
          input.claim.acceptanceId,
          input.claim.identityId,
          input.claim.acceptanceAttempt,
        ],
      );
      return finalized.rows[0]?.completed === true;
    });
  }

  public async finalizeReconciliationRace(input: {
    claim: TenantInvitationClaim;
    leaseToken: string;
    requestId: string;
  }): Promise<boolean> {
    return this.finishReconciliationWithAudit(input, "race_lost", async () => true);
  }

  public async failReconciliation(input: {
    claim: TenantInvitationClaim;
    leaseToken: string;
    requestId: string;
    errorCode: string;
  }): Promise<boolean> {
    assertErrorCode(input.errorCode);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const finished = await finishReconciliationLease(client, input, false, input.errorCode);
      if (!finished) {
        await client.query("ROLLBACK");
        return false;
      }
      await appendPlatformAudit(client, {
        tenantId: input.claim.tenantId,
        action: "invitation.reconciliation_failed",
        entityType: "tenant_invitation",
        entityId: input.claim.invitationId,
        result: "failure",
        requestId: input.requestId,
        metadata: reconciliationAuditMetadata(input.claim, "failed", input.errorCode),
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

  private async finishReconciliationWithAudit(
    input: { claim: TenantInvitationClaim; leaseToken: string; requestId: string },
    action: "authority_finalized" | "acceptance_reset" | "terminal_cleanup_finalized" | "race_lost",
    mutate: (client: PoolClient) => Promise<boolean>,
  ): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const finished = await finishReconciliationLease(client, input, true, null);
      if (!finished || !await mutate(client)) {
        await client.query("ROLLBACK");
        return false;
      }
      await appendPlatformAudit(client, {
        tenantId: input.claim.tenantId,
        action: `invitation.reconciliation_${action}`,
        entityType: "tenant_invitation",
        entityId: input.claim.invitationId,
        result: "success",
        requestId: input.requestId,
        metadata: reconciliationAuditMetadata(input.claim, action),
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

  public async beginCompensation(claim: TenantInvitationClaim): Promise<boolean> {
    const result = await this.pool.query<{ begin_tenant_invitation_compensation: boolean }>(
      "SELECT begin_tenant_invitation_compensation($1,$2,$3,$4)",
      [claim.invitationId, claim.acceptanceId, claim.identityId, claim.acceptanceAttempt],
    );
    return result.rows[0]?.begin_tenant_invitation_compensation === true;
  }

  public async markAuthorityFinalized(claim: TenantInvitationClaim): Promise<boolean> {
    const result = await this.pool.query<{ finalized: boolean }>(
      `SELECT mark_tenant_invitation_authority_finalized($1,$2,$3,$4) AS finalized`,
      [claim.invitationId, claim.acceptanceId, claim.identityId, claim.acceptanceAttempt],
    );
    return result.rows[0]?.finalized === true;
  }

  public async markCleanupCompleted(claim: TenantInvitationClaim): Promise<boolean> {
    const result = await this.pool.query<{ completed: boolean }>(
      `SELECT mark_tenant_invitation_cleanup_completed($1,$2,$3,$4) AS completed`,
      [claim.invitationId, claim.acceptanceId, claim.identityId, claim.acceptanceAttempt],
    );
    return result.rows[0]?.completed === true;
  }

  /**
   * Finds only an exact bearer/email acceptance that is either terminal or
   * older than the bounded acceptance lease. It never revives a token by
   * itself; the service must first win beginCompensation, clean the exact
   * tenant epoch, and only then call abortAcceptance.
   */
  public async inspectRecovery(input: {
    token: string;
    normalizedEmail: string;
    recoveryProof: string;
  }): Promise<TenantInvitationRecovery | null> {
    const result = await this.pool.query<{
      id: string;
      acceptance_id: string;
      acceptance_identity_id: string;
      acceptance_attempt: number;
      authority_epoch: string;
      tenant_id: string;
      email: string;
      normalized_email: string;
      role_codes: TenantInvitationRole[];
      expires_at: Date;
      created_by_identity_id: string;
      authority_kind: TenantInvitationAuthorityKind;
      status: TenantInvitationStatus;
      lease_stale: boolean;
    }>(
      `SELECT bearer.*,
              bearer.acceptance_started_at <= clock_timestamp() - interval '10 minutes' AS lease_stale
         FROM inspect_tenant_invitation_bearer($1,$2,$3) bearer
        WHERE bearer.acceptance_id IS NOT NULL
          AND bearer.acceptance_identity_id IS NOT NULL`,
      [input.token, input.normalizedEmail, input.recoveryProof],
    );
    const row = result.rows[0];
    if (!row || result.rowCount !== 1) return null;
    const claim: TenantInvitationClaim = {
      invitationId: row.id,
      acceptanceId: row.acceptance_id,
      identityId: row.acceptance_identity_id,
      tenantId: row.tenant_id,
      email: row.email,
      normalizedEmail: row.normalized_email,
      roles: row.role_codes,
      expiresAt: row.expires_at,
      createdByIdentityId: row.created_by_identity_id,
      authorityKind: row.authority_kind,
      authorityEpoch: safePositiveInteger(row.authority_epoch, "invitation authority epoch", true),
      acceptanceAttempt: safePositiveInteger(row.acceptance_attempt, "invitation acceptance attempt"),
    };
    if (row.status === "accepted") {
      return { claim, action: "finalize", resetAfterCompensation: false, fenced: true };
    }
    if (["revoked", "expired", "failed"].includes(row.status)) {
      return { claim, action: "compensate", resetAfterCompensation: false, fenced: true };
    }
    if (row.status === "compensating" || (row.status === "accepting" && row.lease_stale)) {
      return {
        claim,
        action: "compensate",
        resetAfterCompensation: true,
        fenced: row.status === "compensating",
      };
    }
    return null;
  }

  public async recoverAcceptedEnrollmentSession(input: {
    claim: TenantInvitationClaim;
    token: string;
    recoveryProof: string;
    requestId: string;
    bootstrapSession: {
      sessionId: string;
      tokenHash: string;
      csrfHash: string;
      expiresAt: Date;
      userAgentHash?: string;
      ipPrefixHash?: string;
    };
  }): Promise<{ identityId: string; tenantId: string; expiresAt: Date } | null> {
    assertInvitationBootstrapSession(input.bootstrapSession);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const recovered = await client.query<{
        recovered: boolean;
        identity_id: string | null;
        tenant_id: string | null;
        session_expires_at: Date | null;
      }>(
        `SELECT * FROM recover_tenant_invitation_enrollment_session(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
         )`,
        [
          input.claim.invitationId,
          input.token,
          input.recoveryProof,
          input.claim.normalizedEmail,
          input.bootstrapSession.sessionId,
          input.bootstrapSession.tokenHash,
          input.bootstrapSession.csrfHash,
          input.bootstrapSession.expiresAt,
          input.bootstrapSession.userAgentHash ?? null,
          input.bootstrapSession.ipPrefixHash ?? null,
        ],
      );
      const row = recovered.rows[0];
      if (
        row?.recovered !== true
        || row.identity_id !== input.claim.identityId
        || row.tenant_id !== input.claim.tenantId
        || !row.session_expires_at
      ) {
        await client.query("COMMIT");
        return null;
      }
      await appendPlatformAudit(client, {
        actorIdentityId: input.claim.identityId,
        tenantId: input.claim.tenantId,
        action: "invitation.enrollment_session_recovered",
        entityType: "tenant_invitation",
        entityId: input.claim.invitationId,
        result: "success",
        requestId: input.requestId,
        metadata: { rotated: true },
      });
      await client.query("COMMIT");
      return { identityId: row.identity_id, tenantId: row.tenant_id, expiresAt: row.session_expires_at };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async abortAcceptance(claim: TenantInvitationClaim, errorCode: string): Promise<boolean> {
    assertErrorCode(errorCode);
    const result = await this.pool.query(
        `UPDATE tenant_invitations
          SET status=CASE WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'pending' END,
              acceptance_id=NULL,acceptance_identity_id=NULL,acceptance_started_at=NULL,
              acceptance_recovery_hash=NULL,
              last_error_code=$4,updated_at=clock_timestamp(),version=version+1
        WHERE id=$1 AND acceptance_id=$2 AND acceptance_identity_id=$3
          AND acceptance_attempt=$5 AND status='compensating'`,
      [claim.invitationId, claim.acceptanceId, claim.identityId, errorCode, claim.acceptanceAttempt],
    );
    return result.rowCount === 1;
  }

  public async failAcceptance(claim: TenantInvitationClaim, errorCode: string, requestId: string): Promise<void> {
    assertErrorCode(errorCode);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query(
        `UPDATE tenant_invitations
            SET status='failed',last_error_code=$4,updated_at=clock_timestamp(),version=version+1
          WHERE id=$1 AND acceptance_id=$2 AND acceptance_identity_id=$3
            AND acceptance_attempt=$5 AND status='compensating'
          RETURNING tenant_id`,
        [claim.invitationId, claim.acceptanceId, claim.identityId, errorCode, claim.acceptanceAttempt],
      );
      if (updated.rowCount === 1) {
        await appendPlatformAudit(client, {
          tenantId: claim.tenantId,
          action: "invitation.acceptance_failed",
          entityType: "tenant_invitation",
          entityId: claim.invitationId,
          result: "failure",
          requestId,
          metadata: { errorCode },
        });
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }
}

/**
 * Serializes membership activation with tenant identity-policy activation.
 * Keep this key identical to EnterpriseAuthStore.upsertTenantIdentityPolicy.
 */
async function lockTenantIdentityPolicy(client: PoolClient, tenantId: string): Promise<void> {
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtextextended('tenant_identity_policy:' || $1::text,0))",
    [tenantId],
  );
}

function summary(row: InvitationRow): TenantInvitationSummary {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    email: row.email,
    roles: [...row.role_codes],
    status: row.status,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    acceptedAt: row.accepted_at,
    revokedAt: row.revoked_at,
    version: row.version,
  };
}

function cleanupClaimFromRow(row: InvitationRow & {
  readonly acceptance_id: string | null;
  readonly acceptance_identity_id: string | null;
}): TenantInvitationClaim | null {
  if (!row.acceptance_id || !row.acceptance_identity_id || row.acceptance_attempt <= 0) return null;
  return {
    invitationId: row.id,
    acceptanceId: row.acceptance_id,
    identityId: row.acceptance_identity_id,
    tenantId: row.tenant_id,
    email: row.email,
    normalizedEmail: row.normalized_email,
    roles: row.role_codes,
    expiresAt: row.expires_at,
    createdByIdentityId: row.created_by_identity_id,
    authorityKind: row.authority_kind,
    authorityEpoch: safePositiveInteger(row.authority_epoch, "invitation authority epoch", true),
    acceptanceAttempt: safePositiveInteger(row.acceptance_attempt, "invitation acceptance attempt"),
  };
}

async function finishReconciliationLease(
  client: PoolClient,
  input: { claim: TenantInvitationClaim; leaseToken: string },
  succeeded: boolean,
  errorCode: string | null,
): Promise<boolean> {
  const result = await client.query<{ finished: boolean }>(
    `SELECT finish_tenant_invitation_reconciliation(
       $1,$2,$3,$4,$5,$6,$7
     ) AS finished`,
    [
      input.claim.invitationId,
      input.claim.acceptanceId,
      input.claim.identityId,
      input.claim.acceptanceAttempt,
      input.leaseToken,
      succeeded,
      errorCode,
    ],
  );
  return result.rows[0]?.finished === true;
}

function reconciliationAuditMetadata(
  claim: TenantInvitationClaim,
  action: string,
  errorCode?: string,
): Readonly<Record<string, unknown>> {
  return {
    action,
    acceptanceId: claim.acceptanceId,
    acceptanceAttempt: claim.acceptanceAttempt,
    authorityKind: claim.authorityKind,
    authorityEpoch: claim.authorityEpoch,
    ...(errorCode === undefined ? {} : { errorCode }),
  };
}

async function appendPlatformAudit(client: PoolClient, input: {
  actorIdentityId?: string;
  tenantId?: string;
  action: string;
  entityType?: string;
  entityId?: string;
  result: "success" | "denied" | "failure";
  requestId?: string;
  metadata?: Readonly<Record<string, unknown>>;
}): Promise<void> {
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('platform_audit_chain',0))");
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
       actor_identity_id,tenant_id,action,entity_type,entity_id,result,
       request_id,metadata,previous_hash,event_hash
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
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

function isInvitationPolicyConflict(error: unknown): boolean {
  return typeof error === "object"
    && error !== null
    && "code" in error
    && "constraint" in error
    && error.code === "23514"
    && error.constraint === "tenant_invitation_identity_policy_readiness";
}

function isInvitationPasswordRequired(error: unknown): boolean {
  return typeof error === "object"
    && error !== null
    && "code" in error
    && "constraint" in error
    && error.code === "23514"
    && error.constraint === "tenant_invitation_password_required";
}

function isInvitationGrantorInactive(error: unknown): boolean {
  return typeof error === "object"
    && error !== null
    && "code" in error
    && "constraint" in error
    && error.code === "42501"
    && error.constraint === "tenant_invitation_grantor_inactive";
}

function assertInvitationBootstrapSession(input: {
  readonly sessionId: string;
  readonly tokenHash: string;
  readonly csrfHash: string;
  readonly expiresAt: Date;
  readonly userAgentHash?: string;
  readonly ipPrefixHash?: string;
}): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(input.sessionId)) {
    throw new Error("Invitation enrollment session id is invalid");
  }
  for (const [name, value] of [
    ["token", input.tokenHash],
    ["CSRF", input.csrfHash],
    ["user-agent", input.userAgentHash],
    ["IP prefix", input.ipPrefixHash],
  ] as const) {
    if (value !== undefined && !/^[0-9a-f]{64}$/u.test(value)) {
      throw new Error(`Invitation enrollment ${name} hash is invalid`);
    }
  }
  if (!(input.expiresAt instanceof Date) || !Number.isFinite(input.expiresAt.getTime())) {
    throw new Error("Invitation enrollment session expiry is invalid");
  }
  if (input.expiresAt.getTime() <= Date.now()) {
    throw new Error("Invitation enrollment session expiry must be in the future");
  }
}

function assertErrorCode(value: string): void {
  if (!/^[A-Z0-9_]{2,80}$/.test(value)) throw new Error("Invitation failure code is invalid");
}

function safePositiveInteger(value: string | number, label: string, allowZero = false): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || (allowZero ? parsed < 0 : parsed <= 0)) {
    throw new Error(`${label} is outside the supported range`);
  }
  return parsed;
}
