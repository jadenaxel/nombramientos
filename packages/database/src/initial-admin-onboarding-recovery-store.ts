import { createHash } from "node:crypto";
import type { Pool } from "pg";

export const INITIAL_ADMIN_RECOVERY_REASON_CODES = [
  "browser_context_lost",
  "browser_profile_reset",
  "device_lost",
  "session_delivery_failure",
] as const;

export const INITIAL_ADMIN_RECOVERY_DELIVERY_CHANNELS = [
  "local_console",
  "verified_email",
  "verified_sms",
  "service_desk",
] as const;

export type InitialAdminRecoveryReasonCode = typeof INITIAL_ADMIN_RECOVERY_REASON_CODES[number];
export type InitialAdminRecoveryDeliveryChannel = typeof INITIAL_ADMIN_RECOVERY_DELIVERY_CHANNELS[number];
export type InitialAdminRecoveryRevocationReasonCode =
  | "security_response"
  | "requester_cancelled"
  | "delivery_reissue";
export type InitialAdminRecoveryPersistedRevocationReasonCode =
  | InitialAdminRecoveryRevocationReasonCode
  | "governance_invalidated";
export type InitialAdminRecoveryStatus =
  | "pending"
  | "finalization_pending"
  | "enrollment_pending"
  | "admin_active"
  | "revoked"
  | "expired"
  | "failed";
export type InitialAdminRecoveryDeliveryState = "not_started" | "pending" | "delivered" | "failed";

export interface InitialAdminRecoverySource {
  readonly tenantId: string;
  readonly invitationId: string;
  readonly acceptanceId: string;
  readonly acceptanceIdentityId: string;
  readonly acceptanceAttempt: number;
  readonly authorityEpoch: number;
  /** Client-observed source version; PostgreSQL captures the locked version. */
  readonly invitationVersion: number;
}

export interface InitialAdminRecoverySummary extends InitialAdminRecoverySource {
  readonly recoveryId: string;
  readonly sourceInvitationVersion: number;
  readonly requesterIdentityId: string;
  readonly approverIdentityId: string | null;
  readonly status: InitialAdminRecoveryStatus;
  readonly reasonCode: InitialAdminRecoveryReasonCode;
  readonly deliveryChannel: InitialAdminRecoveryDeliveryChannel | null;
  readonly deliveryState: InitialAdminRecoveryDeliveryState;
  readonly requestedAt: Date;
  readonly requestExpiresAt: Date;
  readonly approvedAt: Date | null;
  readonly deliveryConfirmedAt: Date | null;
  readonly tokenExpiresAt: Date | null;
  readonly tokenConsumedAt: Date | null;
  readonly browserContextExpiresAt: Date | null;
  readonly firstRedeemedAt: Date | null;
  readonly lastRedeemedAt: Date | null;
  readonly redemptionCount: number;
  readonly redeemedSessionId: string | null;
  readonly revokedSessionCount: number;
  readonly revokedMfaChallengeCount: number;
  readonly revokedStepUpGrantCount: number;
  readonly revokedWebauthnCeremonyCount: number;
  readonly strongFactorFinalizedAt: Date | null;
  readonly revokedAt: Date | null;
  readonly revokedByIdentityId: string | null;
  readonly revocationReasonCode: InitialAdminRecoveryPersistedRevocationReasonCode | null;
  readonly failureCode: string | null;
  readonly version: number;
}

export interface InitialAdminRecoveryCandidate extends InitialAdminRecoverySource {
  readonly tenantDisplayName: string;
  readonly recipientEmail: string;
  readonly recipientDisplayName: string;
  readonly authorityFinalizedAt: Date;
}

export interface InitialAdminRecoveryQueueItem extends InitialAdminRecoverySource {
  readonly recoveryId: string;
  readonly version: number;
  readonly status: InitialAdminRecoveryStatus;
  readonly tenantDisplayName: string;
  readonly recipientEmail: string;
  readonly recipientDisplayName: string;
  readonly requesterIdentityId: string;
  readonly requesterEmail: string;
  readonly requesterDisplayName: string;
  readonly approverIdentityId: string | null;
  readonly approverEmail: string | null;
  readonly approverDisplayName: string | null;
  readonly reasonCode: InitialAdminRecoveryReasonCode;
  readonly deliveryChannel: InitialAdminRecoveryDeliveryChannel | null;
  readonly deliveryState: InitialAdminRecoveryDeliveryState;
  readonly requestedAt: Date;
  readonly requestExpiresAt: Date;
  readonly approvedAt: Date | null;
  readonly tokenExpiresAt: Date | null;
  readonly redemptionCount: number;
  readonly strongFactorFinalizedAt: Date | null;
  readonly revokedAt: Date | null;
  readonly revocationReasonCode: InitialAdminRecoveryPersistedRevocationReasonCode | null;
  readonly failureCode: string | null;
}

export interface InitialAdminRecoveryApprovalContext extends InitialAdminRecoverySource {
  readonly recoveryId: string;
  readonly version: number;
  readonly status: InitialAdminRecoveryStatus;
  readonly deliveryState: InitialAdminRecoveryDeliveryState;
  readonly recipientEmail: string;
  readonly recipientDisplayName: string;
}

export interface InitialAdminRecoveryRequestResult {
  readonly recoveryId: string;
  readonly version: number;
  readonly status: InitialAdminRecoveryStatus;
  readonly created: boolean;
}

export interface InitialAdminRecoveryApprovalResult {
  readonly recoveryId: string;
  readonly version: number;
  readonly status: InitialAdminRecoveryStatus;
  readonly deliveryState: InitialAdminRecoveryDeliveryState;
  /** Internal delivery destination; never include it in a public response. */
  readonly recipientEmail: string;
  readonly tokenExpiresAt: Date | null;
  /** True only when this call replayed an already-persisted approval. */
  readonly reused: boolean;
}

export interface InitialAdminRecoveryRedemptionResult {
  readonly recovered: boolean;
  readonly identityId: string | null;
  readonly tenantId: string | null;
  readonly sessionId: string | null;
  readonly sessionExpiresAt: Date | null;
  readonly rotated: boolean;
  readonly version: number;
}

export class InitialAdminOnboardingRecoveryStore {
  public constructor(private readonly pool: Pool) {}

  public async listCandidates(input: {
    readonly actorIdentityId: string;
    readonly actorSessionId: string;
    readonly tenantId?: string;
    readonly limit: number;
  }): Promise<readonly InitialAdminRecoveryCandidate[]> {
    const result = await this.pool.query<CandidateRow>(
      "SELECT * FROM list_initial_admin_onboarding_recovery_candidates($1,$2,$3,$4)",
      [input.actorIdentityId, input.actorSessionId, input.tenantId ?? null, input.limit],
    );
    return result.rows.map((row) => {
      const authorityEpoch = Number(row.authority_epoch);
      if (!Number.isSafeInteger(authorityEpoch) || authorityEpoch <= 0) {
        throw new Error("Initial-admin recovery candidate authority epoch is outside the safe range");
      }
      return {
        tenantId: row.tenant_id,
        tenantDisplayName: row.tenant_display_name,
        invitationId: row.invitation_id,
        acceptanceId: row.acceptance_id,
        acceptanceIdentityId: row.acceptance_identity_id,
        acceptanceAttempt: row.acceptance_attempt,
        authorityEpoch,
        invitationVersion: row.invitation_version,
        recipientEmail: row.recipient_email,
        recipientDisplayName: row.recipient_display_name,
        authorityFinalizedAt: row.authority_finalized_at,
      };
    });
  }

  public async expireStale(input: {
    readonly actorIdentityId: string;
    readonly actorSessionId: string;
    readonly tenantId?: string;
    readonly requestId: string;
  }): Promise<number> {
    const result = await this.pool.query<{ expired_count: number }>(
      "SELECT expire_stale_initial_admin_onboarding_recoveries($1,$2,$3,$4) AS expired_count",
      [input.actorIdentityId, input.actorSessionId, input.tenantId ?? null, input.requestId],
    );
    return result.rows[0]?.expired_count ?? 0;
  }

  public async listRecoveries(input: {
    readonly actorIdentityId: string;
    readonly actorSessionId: string;
    readonly tenantId?: string;
    readonly status?: InitialAdminRecoveryStatus;
    readonly beforeRequestedAt?: Date;
    readonly beforeRecoveryId?: string;
    readonly limit: number;
  }): Promise<readonly InitialAdminRecoveryQueueItem[]> {
    if ((input.beforeRequestedAt === undefined) !== (input.beforeRecoveryId === undefined)) {
      throw new Error("Initial-admin recovery queue cursor is incomplete");
    }
    const result = await this.pool.query<QueueRow>(
      `SELECT * FROM list_initial_admin_onboarding_recoveries(
         $1,$2,$3,$4,$5,$6,$7
       )`,
      [
        input.actorIdentityId,
        input.actorSessionId,
        input.tenantId ?? null,
        input.status ?? null,
        input.beforeRequestedAt ?? null,
        input.beforeRecoveryId ?? null,
        input.limit,
      ],
    );
    return result.rows.map(mapQueueItem);
  }

  public async getApprovalContext(input: {
    readonly actorIdentityId: string;
    readonly actorSessionId: string;
    readonly recoveryId: string;
  }): Promise<InitialAdminRecoveryApprovalContext | null> {
    const result = await this.pool.query<ApprovalContextRow>(
      "SELECT * FROM get_initial_admin_onboarding_recovery_approval_context($1,$2,$3)",
      [input.actorIdentityId, input.actorSessionId, input.recoveryId],
    );
    const row = result.rows[0];
    if (!row) return null;
    const authorityEpoch = Number(row.authority_epoch);
    if (!Number.isSafeInteger(authorityEpoch) || authorityEpoch <= 0) {
      throw new Error("Initial-admin recovery approval authority epoch is outside the safe range");
    }
    return {
      recoveryId: row.recovery_id,
      version: row.recovery_version,
      status: asRecoveryStatus(row.recovery_status),
      deliveryState: asDeliveryState(row.delivery_state),
      tenantId: row.tenant_id,
      invitationId: row.invitation_id,
      acceptanceId: row.acceptance_id,
      acceptanceIdentityId: row.acceptance_identity_id,
      acceptanceAttempt: row.acceptance_attempt,
      authorityEpoch,
      invitationVersion: row.source_invitation_version,
      recipientEmail: row.recipient_email,
      recipientDisplayName: row.recipient_display_name,
    };
  }

  public async request(input: {
    readonly recoveryId: string;
    readonly source: InitialAdminRecoverySource;
    readonly requesterIdentityId: string;
    readonly requesterSessionId: string;
    readonly stepUpTokenHash: string;
    readonly operationHash: string;
    readonly idempotencyKey: string;
    readonly reasonCode: InitialAdminRecoveryReasonCode;
    readonly caseReferenceHash: string;
    readonly expiresAt: Date;
    readonly requestId: string;
  }): Promise<InitialAdminRecoveryRequestResult> {
    assertSha256(input.stepUpTokenHash, "requester WebAuthn grant");
    assertSha256(input.operationHash, "request operation");
    assertSha256(input.caseReferenceHash, "case reference");
    const requestHash = initialAdminRecoveryRequestHash({
      recoveryId: input.recoveryId,
      source: input.source,
      requesterIdentityId: input.requesterIdentityId,
      reasonCode: input.reasonCode,
      caseReferenceHash: input.caseReferenceHash,
      expiresAt: input.expiresAt.toISOString(),
    });
    const result = await this.pool.query<RequestRow>(
      `SELECT * FROM request_initial_admin_onboarding_recovery(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
       )`,
      [
        input.recoveryId,
        input.source.tenantId,
        input.source.invitationId,
        input.source.acceptanceId,
        input.source.acceptanceIdentityId,
        input.source.acceptanceAttempt,
        input.source.authorityEpoch,
        input.source.invitationVersion,
        input.requesterIdentityId,
        input.requesterSessionId,
        input.stepUpTokenHash,
        input.operationHash,
        input.idempotencyKey,
        requestHash,
        input.reasonCode,
        input.caseReferenceHash,
        input.expiresAt,
        input.requestId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Initial-admin recovery request returned no result");
    return {
      recoveryId: row.recovery_id,
      version: row.recovery_version,
      status: asRecoveryStatus(row.recovery_status),
      created: row.created,
    };
  }

  public async approve(input: {
    readonly recoveryId: string;
    readonly expectedVersion: number;
    readonly source: InitialAdminRecoverySource;
    readonly approverIdentityId: string;
    readonly approverSessionId: string;
    readonly stepUpTokenHash: string;
    readonly operationHash: string;
    readonly recoveryTokenHash: string;
    readonly tokenExpiresAt: Date;
    readonly deliveryChannel: InitialAdminRecoveryDeliveryChannel;
    readonly deliveryReferenceHash: string;
    readonly requestId: string;
  }): Promise<InitialAdminRecoveryApprovalResult> {
    for (const [label, value] of [
      ["approver WebAuthn grant", input.stepUpTokenHash],
      ["approval operation", input.operationHash],
      ["recovery token", input.recoveryTokenHash],
      ["delivery reference", input.deliveryReferenceHash],
    ] as const) assertSha256(value, label);
    const result = await this.pool.query<ApprovalRow>(
      `SELECT * FROM approve_initial_admin_onboarding_recovery(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
       )`,
      [
        input.recoveryId,
        input.expectedVersion,
        input.source.tenantId,
        input.source.invitationId,
        input.source.acceptanceId,
        input.source.acceptanceIdentityId,
        input.source.acceptanceAttempt,
        input.source.authorityEpoch,
        input.source.invitationVersion,
        input.approverIdentityId,
        input.approverSessionId,
        input.stepUpTokenHash,
        input.operationHash,
        input.recoveryTokenHash,
        input.tokenExpiresAt,
        input.deliveryChannel,
        input.deliveryReferenceHash,
        input.requestId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Initial-admin recovery approval returned no result");
    return {
      recoveryId: row.recovery_id,
      version: row.recovery_version,
      status: asRecoveryStatus(row.recovery_status),
      deliveryState: asDeliveryState(row.delivery_state),
      recipientEmail: row.recipient_email,
      tokenExpiresAt: row.token_expires_at,
      reused: row.reused,
    };
  }

  public async redeem(input: {
    readonly recoveryId: string;
    /** Required on the first redemption, optional on a same-context retry. */
    readonly recoveryToken?: string;
    readonly contextProofs: readonly string[];
    readonly sessionId: string;
    readonly sessionTokenHash: string;
    readonly csrfHash: string;
    readonly sessionExpiresAt: Date;
    readonly requestId: string;
    readonly userAgentHash?: string;
    readonly ipPrefixHash?: string;
  }): Promise<InitialAdminRecoveryRedemptionResult> {
    assertCandidateProofs(input.contextProofs);
    assertSha256(input.sessionTokenHash, "session token");
    assertSha256(input.csrfHash, "session CSRF");
    if (input.recoveryToken !== undefined && !/^[A-Za-z0-9_-]{43}$/u.test(input.recoveryToken)) {
      throw new Error("Initial-admin recovery token is invalid");
    }
    const result = await this.pool.query<RedemptionRow>(
      "SELECT * FROM redeem_initial_admin_onboarding_recovery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
      [
        input.recoveryId,
        input.recoveryToken ?? null,
        [...input.contextProofs],
        input.sessionId,
        input.sessionTokenHash,
        input.csrfHash,
        input.sessionExpiresAt,
        input.userAgentHash ?? null,
        input.ipPrefixHash ?? null,
        input.requestId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Initial-admin recovery redemption returned no result");
    return {
      recovered: row.recovered,
      identityId: row.identity_id,
      tenantId: row.tenant_id,
      sessionId: row.session_id,
      sessionExpiresAt: row.session_expires_at,
      rotated: row.rotated,
      version: row.recovery_version,
    };
  }

  public async revoke(input: {
    readonly recoveryId: string;
    readonly expectedVersion: number;
    readonly source: InitialAdminRecoverySource;
    readonly actorIdentityId: string;
    readonly actorSessionId: string;
    readonly stepUpTokenHash: string;
    readonly operationHash: string;
    readonly reasonCode: InitialAdminRecoveryRevocationReasonCode;
    readonly requestId: string;
  }): Promise<{ version: number; status: InitialAdminRecoveryStatus; sessionsRevoked: number }> {
    assertSha256(input.stepUpTokenHash, "revocation WebAuthn grant");
    assertSha256(input.operationHash, "revocation operation");
    const result = await this.pool.query<RevocationRow>(
      `SELECT * FROM revoke_initial_admin_onboarding_recovery(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
       )`,
      [
        input.recoveryId,
        input.expectedVersion,
        input.source.tenantId,
        input.source.invitationId,
        input.source.acceptanceId,
        input.source.acceptanceIdentityId,
        input.source.acceptanceAttempt,
        input.source.authorityEpoch,
        input.source.invitationVersion,
        input.actorIdentityId,
        input.actorSessionId,
        input.stepUpTokenHash,
        input.operationHash,
        input.reasonCode,
        input.requestId,
      ],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Initial-admin recovery revocation returned no result");
    return {
      version: row.recovery_version,
      status: asRecoveryStatus(row.recovery_status),
      sessionsRevoked: row.sessions_revoked,
    };
  }

  /**
   * The enterprise-auth transaction should invoke the underlying SQL function
   * on its existing PoolClient before COMMIT. This convenience method is for a
   * reconciler/replay and remains safe because PostgreSQL revalidates both the
   * exact source and the newly issued strong-factor session.
   */
  public async finalizeStrongFactor(input: {
    readonly sourceEnrollmentSessionId: string;
    readonly newSessionId: string;
    readonly requestId: string;
  }): Promise<{
    recoveryId: string;
    version: number;
    factorMethod: "passkey" | "totp";
    enrollmentSessionsRevoked: number;
    reused: boolean;
  } | null> {
    const result = await this.pool.query<FinalizationRow>(
      "SELECT * FROM finalize_initial_admin_onboarding_recovery($1,$2,$3)",
      [input.sourceEnrollmentSessionId, input.newSessionId, input.requestId],
    );
    const row = result.rows[0];
    if (!row) return null;
    if (row.factor_method !== "passkey" && row.factor_method !== "totp") {
      throw new Error("Initial-admin recovery finalized with an unknown factor method");
    }
    return {
      recoveryId: row.recovery_id,
      version: row.recovery_version,
      factorMethod: row.factor_method,
      enrollmentSessionsRevoked: row.enrollment_sessions_revoked,
      reused: row.reused,
    };
  }

  public async getSummary(input: {
    readonly actorIdentityId: string;
    readonly actorSessionId: string;
    readonly recoveryId: string;
  }): Promise<InitialAdminRecoverySummary | null> {
    const result = await this.pool.query<SummaryRow>(
      "SELECT * FROM get_initial_admin_onboarding_recovery_summary($1,$2,$3)",
      [input.actorIdentityId, input.actorSessionId, input.recoveryId],
    );
    return result.rows[0] ? mapSummary(result.rows[0]) : null;
  }
}

/** Stable evidence hash; no raw case reference, token, grant, or cookie root. */
export function initialAdminRecoveryRequestHash(input: Readonly<Record<string, unknown>>): string {
  return createHash("sha256").update(stableJson(input), "utf8").digest("hex");
}

interface RequestRow {
  readonly recovery_id: string;
  readonly recovery_version: number;
  readonly recovery_status: string;
  readonly created: boolean;
}

interface CandidateRow {
  readonly tenant_id: string;
  readonly tenant_display_name: string;
  readonly invitation_id: string;
  readonly acceptance_id: string;
  readonly acceptance_identity_id: string;
  readonly acceptance_attempt: number;
  readonly authority_epoch: string | number;
  readonly invitation_version: number;
  readonly recipient_email: string;
  readonly recipient_display_name: string;
  readonly authority_finalized_at: Date;
}

interface ApprovalContextRow {
  readonly recovery_id: string;
  readonly recovery_version: number;
  readonly recovery_status: string;
  readonly delivery_state: string;
  readonly tenant_id: string;
  readonly invitation_id: string;
  readonly acceptance_id: string;
  readonly acceptance_identity_id: string;
  readonly acceptance_attempt: number;
  readonly authority_epoch: string | number;
  readonly source_invitation_version: number;
  readonly recipient_email: string;
  readonly recipient_display_name: string;
}

interface QueueRow {
  readonly recovery_id: string;
  readonly recovery_version: number;
  readonly recovery_status: string;
  readonly tenant_id: string;
  readonly tenant_display_name: string;
  readonly invitation_id: string;
  readonly acceptance_id: string;
  readonly acceptance_identity_id: string;
  readonly acceptance_attempt: number;
  readonly authority_epoch: string | number;
  readonly source_invitation_version: number;
  readonly recipient_email: string;
  readonly recipient_display_name: string;
  readonly requester_identity_id: string;
  readonly requester_email: string;
  readonly requester_display_name: string;
  readonly approver_identity_id: string | null;
  readonly approver_email: string | null;
  readonly approver_display_name: string | null;
  readonly reason_code: InitialAdminRecoveryReasonCode;
  readonly delivery_channel: InitialAdminRecoveryDeliveryChannel | null;
  readonly delivery_state: string;
  readonly requested_at: Date;
  readonly request_expires_at: Date;
  readonly approved_at: Date | null;
  readonly token_expires_at: Date | null;
  readonly redemption_count: number;
  readonly strong_factor_finalized_at: Date | null;
  readonly revoked_at: Date | null;
  readonly revocation_reason_code: InitialAdminRecoveryPersistedRevocationReasonCode | null;
  readonly failure_code: string | null;
}

interface ApprovalRow extends RequestRow {
  readonly delivery_state: string;
  readonly recipient_email: string;
  readonly token_expires_at: Date | null;
  readonly reused: boolean;
}

interface RedemptionRow {
  readonly recovered: boolean;
  readonly identity_id: string | null;
  readonly tenant_id: string | null;
  readonly session_id: string | null;
  readonly session_expires_at: Date | null;
  readonly rotated: boolean;
  readonly recovery_version: number;
}

interface RevocationRow {
  readonly recovery_version: number;
  readonly recovery_status: string;
  readonly sessions_revoked: number;
}

interface FinalizationRow {
  readonly recovery_id: string;
  readonly recovery_version: number;
  readonly factor_method: string;
  readonly enrollment_sessions_revoked: number;
  readonly reused: boolean;
}

interface SummaryRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly invitation_id: string;
  readonly acceptance_id: string;
  readonly acceptance_identity_id: string;
  readonly acceptance_attempt: number;
  readonly authority_epoch: string | number;
  readonly source_invitation_version: number;
  readonly requester_identity_id: string;
  readonly approver_identity_id: string | null;
  readonly status: string;
  readonly reason_code: InitialAdminRecoveryReasonCode;
  readonly delivery_channel: InitialAdminRecoveryDeliveryChannel | null;
  readonly delivery_state: string;
  readonly requested_at: Date;
  readonly request_expires_at: Date;
  readonly approved_at: Date | null;
  readonly delivery_confirmed_at: Date | null;
  readonly token_expires_at: Date | null;
  readonly token_consumed_at: Date | null;
  readonly browser_context_expires_at: Date | null;
  readonly first_redeemed_at: Date | null;
  readonly last_redeemed_at: Date | null;
  readonly redemption_count: number;
  readonly redeemed_session_id: string | null;
  readonly revoked_session_count: number;
  readonly revoked_mfa_challenge_count: number;
  readonly revoked_step_up_grant_count: number;
  readonly revoked_webauthn_ceremony_count: number;
  readonly strong_factor_finalized_at: Date | null;
  readonly revoked_at: Date | null;
  readonly revoked_by_identity_id: string | null;
  readonly revocation_reason_code: InitialAdminRecoveryPersistedRevocationReasonCode | null;
  readonly failure_code: string | null;
  readonly version: number;
}

function mapSummary(row: SummaryRow): InitialAdminRecoverySummary {
  const authorityEpoch = Number(row.authority_epoch);
  if (!Number.isSafeInteger(authorityEpoch) || authorityEpoch <= 0) {
    throw new Error("Initial-admin recovery authority epoch is outside the safe range");
  }
  return {
    recoveryId: row.id,
    tenantId: row.tenant_id,
    invitationId: row.invitation_id,
    acceptanceId: row.acceptance_id,
    acceptanceIdentityId: row.acceptance_identity_id,
    acceptanceAttempt: row.acceptance_attempt,
    authorityEpoch,
    invitationVersion: row.source_invitation_version,
    sourceInvitationVersion: row.source_invitation_version,
    requesterIdentityId: row.requester_identity_id,
    approverIdentityId: row.approver_identity_id,
    status: asRecoveryStatus(row.status),
    reasonCode: row.reason_code,
    deliveryChannel: row.delivery_channel,
    deliveryState: asDeliveryState(row.delivery_state),
    requestedAt: row.requested_at,
    requestExpiresAt: row.request_expires_at,
    approvedAt: row.approved_at,
    deliveryConfirmedAt: row.delivery_confirmed_at,
    tokenExpiresAt: row.token_expires_at,
    tokenConsumedAt: row.token_consumed_at,
    browserContextExpiresAt: row.browser_context_expires_at,
    firstRedeemedAt: row.first_redeemed_at,
    lastRedeemedAt: row.last_redeemed_at,
    redemptionCount: row.redemption_count,
    redeemedSessionId: row.redeemed_session_id,
    revokedSessionCount: row.revoked_session_count,
    revokedMfaChallengeCount: row.revoked_mfa_challenge_count,
    revokedStepUpGrantCount: row.revoked_step_up_grant_count,
    revokedWebauthnCeremonyCount: row.revoked_webauthn_ceremony_count,
    strongFactorFinalizedAt: row.strong_factor_finalized_at,
    revokedAt: row.revoked_at,
    revokedByIdentityId: row.revoked_by_identity_id,
    revocationReasonCode: row.revocation_reason_code,
    failureCode: row.failure_code,
    version: row.version,
  };
}

function mapQueueItem(row: QueueRow): InitialAdminRecoveryQueueItem {
  const authorityEpoch = Number(row.authority_epoch);
  if (!Number.isSafeInteger(authorityEpoch) || authorityEpoch <= 0) {
    throw new Error("Initial-admin recovery queue authority epoch is outside the safe range");
  }
  return {
    recoveryId: row.recovery_id,
    version: row.recovery_version,
    status: asRecoveryStatus(row.recovery_status),
    tenantId: row.tenant_id,
    tenantDisplayName: row.tenant_display_name,
    invitationId: row.invitation_id,
    acceptanceId: row.acceptance_id,
    acceptanceIdentityId: row.acceptance_identity_id,
    acceptanceAttempt: row.acceptance_attempt,
    authorityEpoch,
    invitationVersion: row.source_invitation_version,
    recipientEmail: row.recipient_email,
    recipientDisplayName: row.recipient_display_name,
    requesterIdentityId: row.requester_identity_id,
    requesterEmail: row.requester_email,
    requesterDisplayName: row.requester_display_name,
    approverIdentityId: row.approver_identity_id,
    approverEmail: row.approver_email,
    approverDisplayName: row.approver_display_name,
    reasonCode: row.reason_code,
    deliveryChannel: row.delivery_channel,
    deliveryState: asDeliveryState(row.delivery_state),
    requestedAt: row.requested_at,
    requestExpiresAt: row.request_expires_at,
    approvedAt: row.approved_at,
    tokenExpiresAt: row.token_expires_at,
    redemptionCount: row.redemption_count,
    strongFactorFinalizedAt: row.strong_factor_finalized_at,
    revokedAt: row.revoked_at,
    revocationReasonCode: row.revocation_reason_code,
    failureCode: row.failure_code,
  };
}

function assertSha256(value: string, label: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new Error(`Initial-admin recovery ${label} hash is invalid`);
}

function assertCandidateProofs(proofs: readonly string[]): void {
  if (proofs.length < 1 || proofs.length > 12 || new Set(proofs).size !== proofs.length
      || proofs.some((proof) => !/^[A-Za-z0-9_-]{43}$/u.test(proof))) {
    throw new Error("Initial-admin recovery browser-context candidates are invalid");
  }
}

function asRecoveryStatus(value: string): InitialAdminRecoveryStatus {
  if ([
    "pending", "finalization_pending", "enrollment_pending", "admin_active",
    "revoked", "expired", "failed",
  ].includes(value)) return value as InitialAdminRecoveryStatus;
  throw new Error("Initial-admin recovery has an unknown persisted status");
}

function asDeliveryState(value: string): InitialAdminRecoveryDeliveryState {
  if (["not_started", "pending", "delivered", "failed"].includes(value)) {
    return value as InitialAdminRecoveryDeliveryState;
  }
  throw new Error("Initial-admin recovery has an unknown delivery state");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Readonly<Record<string, unknown>>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}
