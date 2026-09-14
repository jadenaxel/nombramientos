import { createHmac, randomBytes, randomUUID } from "node:crypto";
import type {
  DatabaseRuntime,
  InitialAdminRecoveryQueueItem,
  InitialAdminRecoveryRevocationReasonCode,
  InitialAdminRecoverySource,
  RequestPrincipal,
} from "@nombramientos/database";
import type { ApiConfig } from "../config.js";
import { ApiError } from "../lib/errors.js";
import type { AuthenticatedResult } from "./auth-service.js";
import { AuthService, createSessionBinding, sha256 } from "./auth-service.js";
import type {
  InitialAdminRecoveryApprovalInput,
  InitialAdminRecoveryRequestInput,
} from "./initial-admin-onboarding-recovery-contract.js";

const RECOVERY_REQUEST_MAX_MINUTES = 24 * 60;
const RECOVERY_TOKEN_TTL_MINUTES = 30;
const RECOVERY_SESSION_TTL_MINUTES = 10;

export interface GovernedStepUpEvidence {
  readonly tokenHash: string;
  readonly operationHash: string;
}

export interface InitialAdminRecoveryPublicSession extends Omit<AuthenticatedResult, "sessionToken"> {
  readonly recovered: true;
  readonly status: "mfa_enrollment_required";
}

export class InitialAdminOnboardingRecoveryService {
  public constructor(
    private readonly database: DatabaseRuntime,
    private readonly config: ApiConfig,
    private readonly authService: AuthService,
  ) {}

  public async listCandidates(input: {
    readonly principal: RequestPrincipal;
    readonly tenantId?: string;
    readonly limit: number;
    readonly requestId: string;
  }) {
    await this.expireStale(input);
    const items = await this.database.initialAdminRecovery.listCandidates({
      actorIdentityId: input.principal.identityId,
      actorSessionId: input.principal.sessionId,
      ...(input.tenantId ? { tenantId: input.tenantId } : {}),
      limit: input.limit,
    });
    return { items };
  }

  public async listRecoveries(input: {
    readonly principal: RequestPrincipal;
    readonly tenantId?: string;
    readonly status?: InitialAdminRecoveryQueueItem["status"];
    readonly beforeRequestedAt?: Date;
    readonly beforeRecoveryId?: string;
    readonly limit: number;
    readonly requestId: string;
  }) {
    await this.expireStale(input);
    const items = await this.database.initialAdminRecovery.listRecoveries({
      actorIdentityId: input.principal.identityId,
      actorSessionId: input.principal.sessionId,
      ...(input.tenantId ? { tenantId: input.tenantId } : {}),
      ...(input.status ? { status: input.status } : {}),
      ...(input.beforeRequestedAt ? { beforeRequestedAt: input.beforeRequestedAt } : {}),
      ...(input.beforeRecoveryId ? { beforeRecoveryId: input.beforeRecoveryId } : {}),
      limit: input.limit,
    });
    const last = items.length === input.limit ? items.at(-1) : undefined;
    return {
      items,
      nextCursor: last
        ? { beforeRequestedAt: last.requestedAt, beforeRecoveryId: last.recoveryId }
        : null,
    };
  }

  public async request(input: {
    readonly principal: RequestPrincipal;
    readonly body: InitialAdminRecoveryRequestInput;
    readonly stepUp: GovernedStepUpEvidence;
    readonly idempotencyKey: string;
    readonly requestId: string;
  }) {
    const expiresAt = new Date(Date.now()
      + Math.min(input.body.expiresInMinutes, RECOVERY_REQUEST_MAX_MINUTES) * 60_000);
    try {
      return await this.database.initialAdminRecovery.request({
        recoveryId: input.body.recoveryId,
        source: input.body.source,
        requesterIdentityId: input.principal.identityId,
        requesterSessionId: input.principal.sessionId,
        stepUpTokenHash: input.stepUp.tokenHash,
        operationHash: input.stepUp.operationHash,
        idempotencyKey: input.idempotencyKey,
        reasonCode: input.body.reasonCode,
        caseReferenceHash: evidenceHash(
          this.config.authEncryptionKey,
          "case-reference",
          input.body.caseReference.normalize("NFKC").trim(),
        ),
        expiresAt,
        requestId: input.requestId,
      });
    } catch (error) {
      throw mapRecoveryDatabaseError(error, input.stepUp.operationHash);
    }
  }

  public async approve(input: {
    readonly principal: RequestPrincipal;
    readonly body: InitialAdminRecoveryApprovalInput;
    readonly stepUp: GovernedStepUpEvidence;
    readonly requestId: string;
  }) {
    // Until a separately credentialed OOB adapter is configured, production
    // fails closed before generating or persisting any bearer. The local
    // console is an explicitly development/test-only delivery boundary.
    if (input.body.deliveryChannel !== "local_console" || this.config.environment === "production") {
      throw new ApiError(
        503,
        "RECOVERY_DELIVERY_UNAVAILABLE",
        "The selected verified recovery delivery channel is not configured",
      );
    }
    const summary = await this.database.initialAdminRecovery.getSummary({
      actorIdentityId: input.principal.identityId,
      actorSessionId: input.principal.sessionId,
      recoveryId: input.body.recoveryId,
    }).catch((error: unknown) => {
      throw mapRecoveryDatabaseError(error, input.stepUp.operationHash);
    });
    if (!summary) throw recoveryConflict();
    const now = Date.now();
    const tokenExpiresAt = new Date(Math.min(
      now + RECOVERY_TOKEN_TTL_MINUTES * 60_000,
      summary.requestExpiresAt.getTime(),
    ));
    if (tokenExpiresAt.getTime() <= now + 1_000) throw recoveryConflict();

    const recoveryToken = randomToken();
    const deliveryReferenceHash = evidenceHash(
      this.config.authEncryptionKey,
      "delivery-reference",
      input.body.verifiedChannelReference.normalize("NFKC").trim(),
    );
    let result;
    try {
      result = await this.database.initialAdminRecovery.approve({
        recoveryId: input.body.recoveryId,
        expectedVersion: input.body.expectedVersion,
        source: input.body.source,
        approverIdentityId: input.principal.identityId,
        approverSessionId: input.principal.sessionId,
        stepUpTokenHash: input.stepUp.tokenHash,
        operationHash: input.stepUp.operationHash,
        recoveryTokenHash: sha256(recoveryToken),
        tokenExpiresAt,
        deliveryChannel: input.body.deliveryChannel,
        deliveryReferenceHash,
        requestId: input.requestId,
      });
    } catch (error) {
      throw mapRecoveryDatabaseError(error, input.stepUp.operationHash);
    }
    return {
      recoveryId: result.recoveryId,
      version: result.version,
      status: result.status,
      reused: result.reused,
      delivery: {
        channel: input.body.deliveryChannel,
        state: result.deliveryState,
        tokenExpiresAt: result.tokenExpiresAt,
      },
      // The raw token corresponds to the stored digest only on the fresh
      // transition. A replay receives persisted metadata but never a newly
      // generated, unrelated token.
      ...(result.reused ? {} : { developmentToken: recoveryToken }),
    };
  }

  public async revoke(input: {
    readonly principal: RequestPrincipal;
    readonly recoveryId: string;
    readonly expectedVersion: number;
    readonly source: InitialAdminRecoverySource;
    readonly reasonCode: InitialAdminRecoveryRevocationReasonCode;
    readonly stepUp: GovernedStepUpEvidence;
    readonly requestId: string;
  }) {
    try {
      const result = await this.database.initialAdminRecovery.revoke({
        recoveryId: input.recoveryId,
        expectedVersion: input.expectedVersion,
        source: input.source,
        actorIdentityId: input.principal.identityId,
        actorSessionId: input.principal.sessionId,
        stepUpTokenHash: input.stepUp.tokenHash,
        operationHash: input.stepUp.operationHash,
        reasonCode: input.reasonCode,
        requestId: input.requestId,
      });
      return { recoveryId: input.recoveryId, ...result };
    } catch (error) {
      throw mapRecoveryDatabaseError(error, input.stepUp.operationHash);
    }
  }

  public async redeem(input: {
    readonly recoveryId: string;
    readonly token?: string;
    readonly contextProofs: readonly string[];
    readonly requestId: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<{
    readonly sessionToken: string;
    readonly csrfToken: string;
    readonly expiresAt: Date;
    readonly publicSession: InitialAdminRecoveryPublicSession;
  }> {
    const sessionId = randomUUID();
    const sessionToken = randomToken();
    const csrfToken = randomToken();
    const binding = createSessionBinding(input.userAgent, input.ip);
    let result;
    try {
      result = await this.database.initialAdminRecovery.redeem({
        recoveryId: input.recoveryId,
        ...(input.token ? { recoveryToken: input.token } : {}),
        contextProofs: input.contextProofs,
        sessionId,
        sessionTokenHash: sha256(sessionToken),
        csrfHash: sha256(csrfToken),
        sessionExpiresAt: new Date(Date.now() + RECOVERY_SESSION_TTL_MINUTES * 60_000),
        requestId: input.requestId,
        ...binding,
      });
    } catch (error) {
      throw mapPublicRecoveryError(error);
    }
    if (!result.recovered || result.sessionId !== sessionId || !result.identityId
        || !result.tenantId || !result.sessionExpiresAt) {
      throw invalidRecovery();
    }
    const principal = await this.database.getPrincipal(
      sha256(sessionToken),
      input.requestId,
      binding,
    );
    if (!principal || principal.sessionId !== sessionId
        || principal.identityId !== result.identityId
        || principal.activeTenantId !== result.tenantId
        || principal.assuranceLevel !== "enrollment_only"
        || !principal.enrollmentOnly) {
      await this.database.control.revokeSession(sessionId, "initial_admin_recovery_context_failed")
        .catch(() => undefined);
      throw new ApiError(
        503,
        "INITIAL_ADMIN_RECOVERY_SESSION_UNAVAILABLE",
        "The secure enrollment session could not be established",
      );
    }
    const publicSession = {
      ...this.authService.publicSession(principal, csrfToken, null, 0),
      recovered: true,
      status: "mfa_enrollment_required",
    } satisfies InitialAdminRecoveryPublicSession;
    return {
      sessionToken,
      csrfToken,
      expiresAt: result.sessionExpiresAt,
      publicSession,
    };
  }

  private async expireStale(input: {
    readonly principal: RequestPrincipal;
    readonly tenantId?: string;
    readonly requestId: string;
  }): Promise<void> {
    try {
      await this.database.initialAdminRecovery.expireStale({
        actorIdentityId: input.principal.identityId,
        actorSessionId: input.principal.sessionId,
        ...(input.tenantId ? { tenantId: input.tenantId } : {}),
        requestId: input.requestId,
      });
    } catch (error) {
      throw mapRecoveryDatabaseError(error);
    }
  }
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function evidenceHash(key: Buffer, domain: string, value: string): string {
  return createHmac("sha256", key)
    .update(`nombramientos.initial-admin-recovery.${domain}.v1\0`, "utf8")
    .update(value, "utf8")
    .digest("hex");
}

function mapRecoveryDatabaseError(error: unknown, operationHash?: string): Error {
  const code = databaseErrorField(error, "code");
  const constraint = databaseErrorField(error, "constraint");
  if (constraint === "initial_admin_recovery_step_up_invalid") {
    return stepUpRequired(operationHash);
  }
  if (code === "40001" || code === "23505" || [
    "initial_admin_recovery_unavailable",
    "initial_admin_recovery_source_mismatch",
    "initial_admin_recovery_source_ineligible",
    "initial_admin_recovery_approval_unavailable",
    "initial_admin_recovery_revocation_unavailable",
    "initial_admin_recovery_revocation_race",
    "initial_admin_recovery_idempotency_conflict",
  ].includes(constraint ?? "")) return recoveryConflict();
  if (code === "42501") {
    return new ApiError(403, "INITIAL_ADMIN_RECOVERY_FORBIDDEN", "The governed recovery operation is not permitted");
  }
  if (code === "23514") {
    return new ApiError(400, "INITIAL_ADMIN_RECOVERY_INVALID", "The governed recovery request is invalid");
  }
  return error instanceof Error ? error : new Error("Initial-admin recovery database operation failed");
}

function mapPublicRecoveryError(error: unknown): Error {
  const code = databaseErrorField(error, "code");
  if (code === "23514") return invalidRecovery();
  return error instanceof Error ? error : new Error("Initial-admin recovery redemption failed");
}

function databaseErrorField(error: unknown, field: "code" | "constraint"): string | undefined {
  if (typeof error !== "object" || error === null || !(field in error)) return undefined;
  const value = (error as Record<string, unknown>)[field];
  return typeof value === "string" ? value : undefined;
}

function stepUpRequired(operationHash?: string): ApiError {
  return new ApiError(
    428,
    "WEBAUTHN_STEP_UP_REQUIRED",
    "A fresh passkey verification is required for this exact operation",
    { purpose: "platform_administration", operationHash: operationHash ?? null },
  );
}

function recoveryConflict(): ApiError {
  return new ApiError(
    409,
    "INITIAL_ADMIN_RECOVERY_CONFLICT",
    "The recovery state changed or is no longer eligible; refresh before retrying",
  );
}

function invalidRecovery(): ApiError {
  return new ApiError(
    400,
    "INITIAL_ADMIN_RECOVERY_INVALID",
    "The recovery credential or secure browser context is invalid or unavailable",
  );
}
