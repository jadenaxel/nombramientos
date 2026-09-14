import { createHash, randomBytes, randomUUID } from "node:crypto";
import { hash } from "argon2";
import {
  DataConflictError,
  DatabaseRuntime,
  InvitationStoreError,
  type RequestPrincipal,
  type TenantInvitationCompletion,
  type TenantInvitationClaim,
  type TenantInvitationRecovery,
  type TenantInvitationRole,
  type TenantInvitationSummary,
} from "@nombramientos/database";
import type { ApiConfig } from "../config.js";
import { ApiError } from "../lib/errors.js";
import {
  createSessionBinding,
  type AuthenticatedResult,
  type AuthService,
} from "./auth-service.js";

const INVITATION_ENROLLMENT_WINDOW_MINUTES = 10;
const MAX_INVITATION_RECOVERY_PROOFS_PER_BATCH = 12;
const MAX_INVITATION_RECOVERY_PROOFS_TOTAL = 64;
const MAX_INVITATION_RECOVERY_PROOF_BATCHES = Math.ceil(
  MAX_INVITATION_RECOVERY_PROOFS_TOTAL / MAX_INVITATION_RECOVERY_PROOFS_PER_BATCH,
);
const INVITATION_RECOVERY_PROOF_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

export interface InvitationAcceptanceResult extends AuthenticatedResult {
  readonly accepted: true;
  readonly signInRequired: false;
  readonly enrollmentRequired: true;
  readonly tenantId: string;
  readonly roles: readonly TenantInvitationRole[];
}

export class InvitationService {
  public constructor(
    private readonly database: DatabaseRuntime,
    private readonly config: ApiConfig,
    private readonly authService: AuthService,
  ) {}

  public async create(input: {
    principal: RequestPrincipal;
    email: string;
    roles: readonly TenantInvitationRole[];
    expiresInHours: number;
    idempotencyKey: string;
    requestId: string;
  }): Promise<{
    invitation: TenantInvitationSummary;
    delivery: "local_one_time_token" | "token_already_issued";
    acceptanceToken?: string;
    created: boolean;
  }> {
    if (this.config.environment === "production") {
      throw new ApiError(
        503,
        "INVITATION_DELIVERY_UNAVAILABLE",
        "Invitation delivery requires an approved external channel in production",
      );
    }
    const normalizedEmail = normalizeEmail(input.email);
    const roles = [...new Set(input.roles)].sort() as TenantInvitationRole[];
    const token = randomToken();
    const requestHash = sha256(canonicalJson({
      tenantId: input.principal.activeTenantId,
      normalizedEmail,
      roles,
      expiresInHours: input.expiresInHours,
    }));
    try {
      // Keep the tenant role-binding SHARE locks acquired by the delegation
      // check until the control-plane invitation INSERT commits. A concurrent
      // local offboarding therefore linearizes wholly before or after create;
      // it can never slip between authorization and persistence.
      const result = await this.database.withPrincipal(input.principal, input.requestId, async (tenant) => {
        await tenant.assertInvitationRoleDelegation({
          actorIdentityId: input.principal.identityId,
          roles,
        });
        return this.database.invitations.create({
          tenantId: input.principal.activeTenantId,
          actorIdentityId: input.principal.identityId,
          email: input.email.trim().normalize("NFKC"),
          normalizedEmail,
          roles,
          tokenHash: sha256(token),
          expiresAt: new Date(Date.now() + input.expiresInHours * 60 * 60_000),
          idempotencyKey: input.idempotencyKey,
          requestHash,
          requestId: input.requestId,
        });
      });
      return result.created
        ? {
            invitation: result.invitation,
            delivery: "local_one_time_token",
            acceptanceToken: token,
            created: true,
          }
        : {
            invitation: result.invitation,
            delivery: "token_already_issued",
            created: false,
          };
    } catch (error) {
      if (error instanceof DataConflictError && error.code === "PERMISSION_ESCALATION") {
        await this.database.control.appendAudit({
          actorIdentityId: input.principal.identityId,
          tenantId: input.principal.activeTenantId,
          action: "invitation.delegation_denied",
          entityType: "tenant_invitation",
          result: "denied",
          requestId: input.requestId,
          metadata: { roles },
        });
        throw new ApiError(
          403,
          "PERMISSION_ESCALATION",
          "The requested invitation roles exceed the actor's delegable authority",
        );
      }
      if (error instanceof InvitationStoreError) {
        if (error.code === "IDEMPOTENCY_CONFLICT") {
          throw new ApiError(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different input");
        }
        throw new ApiError(409, "INVITATION_UNAVAILABLE", "Invitation cannot be created for this recipient");
      }
      throw error;
    }
  }

  public async list(principal: RequestPrincipal, limit: number): Promise<{ items: readonly TenantInvitationSummary[] }> {
    return { items: await this.database.invitations.list(principal.activeTenantId, limit) };
  }

  public async revoke(input: {
    principal: RequestPrincipal;
    invitationId: string;
    reasonCode?: string;
    requestId: string;
  }): Promise<TenantInvitationSummary> {
    let result;
    try {
      result = await this.database.invitations.revoke({
        invitationId: input.invitationId,
        tenantId: input.principal.activeTenantId,
        actorIdentityId: input.principal.identityId,
        ...(input.reasonCode ? { reasonCode: input.reasonCode } : {}),
        requestId: input.requestId,
      });
    } catch (error) {
      if (error instanceof InvitationStoreError && error.code === "INVITATION_NOT_REVOCABLE") {
        throw new ApiError(409, "INVITATION_NOT_REVOCABLE", "Invitation is no longer revocable");
      }
      throw error;
    }
    if (!result) throw new ApiError(404, "INVITATION_NOT_FOUND", "Invitation was not found");
    if (result.tenantCleanupRequired && result.cleanupClaim) {
      try {
        await this.compensateTenantClaim(result.cleanupClaim, input.requestId, ["revoked"]);
        if (!await this.database.invitations.markCleanupCompleted(result.cleanupClaim)) {
          throw new Error("Invitation revocation cleanup receipt could not be finalized");
        }
      } catch {
        throw new ApiError(
          503,
          "INVITATION_REVOCATION_PENDING_CLEANUP",
          "Invitation is revoked but tenant cleanup must be retried",
        );
      }
    }
    return result.invitation;
  }

  public async accept(input: {
    token: string;
    recoveryProofs: readonly string[];
    additionalRecoveryProofBatches?: readonly (readonly string[])[];
    email: string;
    displayName: string;
    password?: string;
    requestId: string;
    userAgent?: string;
    ip?: string;
  }): Promise<InvitationAcceptanceResult> {
    const recoveryProofBatches = [input.recoveryProofs, ...(input.additionalRecoveryProofBatches ?? [])];
    const rawRecoveryProofCount = recoveryProofBatches.reduce((total, batch) => total + batch.length, 0);
    if (
      recoveryProofBatches.length > MAX_INVITATION_RECOVERY_PROOF_BATCHES
      || recoveryProofBatches.some((batch) => (
        batch.length === 0
        || batch.length > MAX_INVITATION_RECOVERY_PROOFS_PER_BATCH
        || batch.some((proof) => !INVITATION_RECOVERY_PROOF_PATTERN.test(proof))
      ))
      || rawRecoveryProofCount > MAX_INVITATION_RECOVERY_PROOFS_TOTAL
    ) {
      throw invalidInvitation();
    }
    // Batches only bound transport/validation work. Flattening them here keeps
    // one semantic acceptance operation and one state-machine path: a later
    // batch cannot observe or cause a distinct claim/compensation outcome.
    const recoveryProofs = [...new Set(recoveryProofBatches.flat())];
    const normalizedEmail = normalizeEmail(input.email);
    const displayName = normalizeDisplayName(input.displayName);
    // Perform Argon2id work before looking up the invitation so response timing
    // does not become a practical token-existence oracle. Passwordless requests
    // hash a fresh random, discarded secret; password requests additionally
    // create a distinct disabled hash so a user-derived hash is never persisted
    // if policy changed to passwordless while this request was in flight.
    const candidateOrDummyPasswordHash = await hash(input.password ?? randomBytes(32), {
      type: 2,
      memoryCost: 65_536,
      timeCost: 3,
      parallelism: 1,
    });
    const disabledPasswordHash = input.password === undefined
      ? candidateOrDummyPasswordHash
      : await hash(randomBytes(32), {
          type: 2,
          memoryCost: 65_536,
          timeCost: 3,
          parallelism: 1,
        });
    // The database hashes the canonical bearer preimage internally. Passing a
    // client-side verifier here would make a leaked token_hash reusable as a
    // bearer by the control runtime role.
    const invitationToken = input.token;
    const sessionToken = randomToken();
    const csrfToken = randomToken();
    const sessionId = randomUUID();
    const requestedExpiresAt = new Date(Date.now() + INVITATION_ENROLLMENT_WINDOW_MINUTES * 60_000);
    const binding = createSessionBinding(input.userAgent, input.ip);
    let claim: TenantInvitationClaim | null = null;
    let matchedRecoveryProof: string | undefined;
    for (const recoveryProof of recoveryProofs) {
      claim = await this.database.invitations.claim({
        token: invitationToken,
        normalizedEmail,
        recoveryProof,
        acceptanceId: randomUUID(),
        identityId: randomUUID(),
      });
      if (claim) {
        matchedRecoveryProof = recoveryProof;
        break;
      }
    }
    if (!claim) {
      let recovery: TenantInvitationRecovery | null = null;
      for (const recoveryProof of recoveryProofs) {
        recovery = await this.database.invitations.inspectRecovery({
          token: invitationToken,
          normalizedEmail,
          recoveryProof,
        });
        if (recovery) {
          matchedRecoveryProof = recoveryProof;
          break;
        }
      }
      if (!recovery) throw invalidInvitation();
      if (recovery.action === "finalize") {
        return this.recoverAcceptedInvitation(
          recovery.claim,
          invitationToken,
          matchedRecoveryProof!,
          input.requestId,
          input.userAgent,
          input.ip,
        );
      }
      const recovered = await this.recoverStaleAcceptance(recovery, input.requestId);
      if (recovered === "accepted") {
        return this.recoverAcceptedInvitation(
          recovery.claim,
          invitationToken,
          matchedRecoveryProof!,
          input.requestId,
          input.userAgent,
          input.ip,
        );
      }
      if (!recovered || !recovery.resetAfterCompensation) throw invalidInvitation();
      claim = await this.database.invitations.claim({
        token: invitationToken,
        normalizedEmail,
        recoveryProof: matchedRecoveryProof!,
        acceptanceId: randomUUID(),
        identityId: randomUUID(),
      });
      if (!claim) throw invalidInvitation();
    }
    if (!matchedRecoveryProof) throw invalidInvitation();
    let completed: TenantInvitationCompletion | null;

    try {
      await this.activateTenantClaim(claim, input.requestId);
      completed = await this.database.invitations.complete({
        claim,
        displayName,
        ...(input.password === undefined ? {} : { passwordHash: candidateOrDummyPasswordHash }),
        disabledPasswordHash,
        requestId: input.requestId,
        bootstrapSession: {
          sessionId,
          tokenHash: sha256(sessionToken),
          csrfHash: sha256(csrfToken),
          expiresAt: requestedExpiresAt,
          ...binding,
        },
      });
      if (!completed) throw new InvitationAcceptanceStateError();
      if (claim.authorityKind === "initial_admin") {
        // Never deliver an enrollment bearer until the one-time tenant
        // capability is irreversibly consumed. A lost response can safely
        // resume from accepted control state and rotate the session later.
        const consumed = await this.finalizeInitialAdminClaim(claim, input.requestId).catch(() => false);
        if (!consumed) throw new InitialAdminFinalizationError();
      }
    } catch (error) {
      const passwordRequired = error instanceof InvitationStoreError && error.code === "PASSWORD_REQUIRED";
      const statusBeforeCompensation = await this.database.invitations.getAcceptanceStatus(claim).catch(() => null);
      if (statusBeforeCompensation === "accepted") {
        return this.recoverAcceptedInvitation(
          claim,
          invitationToken,
          matchedRecoveryProof,
          input.requestId,
          input.userAgent,
          input.ip,
        );
      }
      let fenced = statusBeforeCompensation !== null
        && ["compensating", "revoked", "expired", "failed"].includes(statusBeforeCompensation);
      if (!fenced && statusBeforeCompensation === "accepting") {
        fenced = await this.database.invitations.beginCompensation(claim).catch(() => false);
      }
      if (!fenced) {
        const statusAfterRace = await this.database.invitations.getAcceptanceStatus(claim).catch(() => null);
        if (statusAfterRace === "accepted") {
          return this.recoverAcceptedInvitation(
            claim,
            invitationToken,
            matchedRecoveryProof,
            input.requestId,
            input.userAgent,
            input.ip,
          );
        }
        fenced = statusAfterRace !== null
          && ["compensating", "revoked", "expired", "failed"].includes(statusAfterRace);
      }
      let compensated = false;
      if (fenced) {
        try {
          await this.compensateTenantClaim(
            claim,
            input.requestId,
            ["compensating", "revoked", "expired", "failed"],
          );
          compensated = true;
        } catch {
          compensated = false;
        }
      }
      let retryReset = false;
      try {
        if (!compensated) {
          await this.database.invitations.failAcceptance(
            claim,
            "TENANT_COMPENSATION_FAILED",
            input.requestId,
          );
        } else if (passwordRequired) {
          retryReset = await this.database.invitations.abortAcceptance(claim, "PASSWORD_REQUIRED");
        } else if (error instanceof InvitationStoreError) {
          await this.database.invitations.failAcceptance(
            claim,
            "RECIPIENT_UNAVAILABLE",
            input.requestId,
          );
        } else {
          await this.database.invitations.abortAcceptance(claim, "ACCEPTANCE_RETRYABLE_FAILURE");
        }
      } catch {
        // The control row remains accepting/failed and therefore cannot activate
        // silently. An operator can inspect its non-secret error state.
      }
      if (passwordRequired) {
        if (compensated && retryReset) {
          throw new ApiError(
            428,
            "INVITATION_PASSWORD_REQUIRED",
            "A password is required by the current organization policy",
          );
        }
        throw new ApiError(
          503,
          "INVITATION_ACCEPTANCE_UNAVAILABLE",
          "Invitation acceptance could not be reset safely for retry",
        );
      }
      if (error instanceof InvitationStoreError && error.code === "POLICY_CONFLICT") {
        throw new ApiError(
          409,
          "INVITATION_POLICY_CONFLICT",
          "Invitation cannot be accepted under the current identity policy",
        );
      }
      if (
        error instanceof InvitationAcceptanceStateError
        || error instanceof InvitationStoreError
        || error instanceof DataConflictError
      ) {
        throw invalidInvitation();
      }
      throw new ApiError(
        503,
        "INVITATION_ACCEPTANCE_UNAVAILABLE",
        "Invitation acceptance could not be completed; no active access was granted",
      );
    }

    // Invitation completion and its enrollment-only session are committed in
    // one database transaction. Hydrate exactly that database-clamped session;
    // never authorize from the caller's requested expiry or from invitation
    // input alone.
    if (!completed.enrollmentSession || completed.enrollmentSession.id !== sessionId) {
      throw new ApiError(
        503,
        "INVITATION_ENROLLMENT_SESSION_UNAVAILABLE",
        "Invitation was accepted but its secure enrollment session is unavailable",
      );
    }
    const principal = await this.database.getPrincipal(
      sha256(sessionToken),
      input.requestId,
      binding,
    );
    if (
      !principal
      || principal.sessionId !== sessionId
      || principal.identityId !== claim.identityId
      || principal.activeTenantId !== claim.tenantId
      || principal.assuranceLevel !== "enrollment_only"
      || !principal.enrollmentOnly
    ) {
      throw new ApiError(
        503,
        "INVITATION_ENROLLMENT_SESSION_UNAVAILABLE",
        "Invitation was accepted but its secure enrollment session is unavailable",
      );
    }
    return {
      ...this.authService.publicSession(principal, csrfToken, null, 0),
      sessionToken,
      // Cookie lifetime must use the value clamped inside the acceptance
      // transaction, not the advisory ten-minute request above.
      expiresAt: completed.enrollmentSession.expiresAt,
      accepted: true,
      signInRequired: false,
      enrollmentRequired: true,
      tenantId: claim.tenantId,
      roles: claim.roles,
    };
  }

  private async activateTenantClaim(claim: TenantInvitationClaim, requestId: string): Promise<void> {
    if (claim.authorityKind === "initial_admin") {
      const capability = await this.database.getInitialAdminCapabilitySecrets(claim.tenantId);
      await this.database.withInvitationGrantorTenant({
        tenantId: claim.tenantId,
        grantorIdentityId: claim.createdByIdentityId,
        acceptanceId: claim.acceptanceId,
        requestId,
      }, (tenant) => tenant.activateInitialAdminInvitationRole({
        invitationId: claim.invitationId,
        identityId: claim.identityId,
        grantedByIdentityId: claim.createdByIdentityId,
        authorityEpoch: claim.authorityEpoch,
        acceptanceAttempt: claim.acceptanceAttempt,
        capabilitySecret: capability.apply,
      }));
      return;
    }
    await this.database.withInvitationGrantorTenant({
      tenantId: claim.tenantId,
      grantorIdentityId: claim.createdByIdentityId,
      acceptanceId: claim.acceptanceId,
      requestId,
    }, (tenant) => tenant.activateInvitationRoles({
      invitationId: claim.invitationId,
      identityId: claim.identityId,
      roles: claim.roles,
      grantedByIdentityId: claim.createdByIdentityId,
      acceptanceAttempt: claim.acceptanceAttempt,
    }));
  }

  private async compensateTenantClaim(
    claim: TenantInvitationClaim,
    requestId: string,
    allowedStatuses: readonly ("compensating" | "revoked" | "expired" | "failed")[],
  ): Promise<void> {
    if (claim.authorityKind === "initial_admin") {
      const capability = await this.database.getInitialAdminCapabilitySecrets(claim.tenantId);
      const rolledBack = await this.database.withFencedInvitationSagaTenant({
        tenantId: claim.tenantId,
        invitationId: claim.invitationId,
        identityId: claim.identityId,
        acceptanceId: claim.acceptanceId,
        acceptanceAttempt: claim.acceptanceAttempt,
        requestId,
        allowedStatuses,
      }, (tenant) => tenant.rollbackInitialAdminInvitationRole({
        invitationId: claim.invitationId,
        acceptanceId: claim.acceptanceId,
        identityId: claim.identityId,
        grantedByIdentityId: claim.createdByIdentityId,
        authorityEpoch: claim.authorityEpoch,
        acceptanceAttempt: claim.acceptanceAttempt,
        capabilitySecret: capability.cleanup,
      }));
      if (!rolledBack) throw new Error("Initial administrator compensation fence did not match");
      return;
    }
    await this.database.withFencedInvitationSagaTenant({
      tenantId: claim.tenantId,
      invitationId: claim.invitationId,
      identityId: claim.identityId,
      acceptanceId: claim.acceptanceId,
      acceptanceAttempt: claim.acceptanceAttempt,
      requestId,
      allowedStatuses,
    }, (tenant) => tenant.cleanupInvitationRoles({
      invitationId: claim.invitationId,
      acceptanceId: claim.acceptanceId,
      identityId: claim.identityId,
      acceptanceAttempt: claim.acceptanceAttempt,
    }));
  }

  private async finalizeInitialAdminClaim(claim: TenantInvitationClaim, requestId: string): Promise<boolean> {
    if (claim.authorityKind !== "initial_admin") return true;
    const capability = await this.database.getInitialAdminCapabilitySecrets(claim.tenantId);
    const consumed = await this.database.withFencedInvitationSagaTenant({
      tenantId: claim.tenantId,
      invitationId: claim.invitationId,
      identityId: claim.identityId,
      acceptanceId: claim.acceptanceId,
      acceptanceAttempt: claim.acceptanceAttempt,
      requestId,
      allowedStatuses: ["accepted"],
    }, (tenant) => tenant.consumeInitialAdminInvitationRole({
      invitationId: claim.invitationId,
      acceptanceId: claim.acceptanceId,
      identityId: claim.identityId,
      authorityEpoch: claim.authorityEpoch,
      acceptanceAttempt: claim.acceptanceAttempt,
      capabilitySecret: capability.apply,
    }));
    if (!consumed) return false;
    return this.database.invitations.markAuthorityFinalized(claim);
  }

  private async recoverStaleAcceptance(
    recovery: TenantInvitationRecovery,
    requestId: string,
  ): Promise<boolean | "accepted"> {
    let fenced = recovery.fenced;
    if (!fenced) fenced = await this.database.invitations.beginCompensation(recovery.claim);
    if (!fenced) {
      return await this.database.invitations.getAcceptanceStatus(recovery.claim) === "accepted"
        ? "accepted"
        : false;
    }
    try {
      await this.compensateTenantClaim(
        recovery.claim,
        requestId,
        ["compensating", "revoked", "expired", "failed"],
      );
    } catch {
      await this.database.invitations.failAcceptance(
        recovery.claim,
        "TENANT_COMPENSATION_FAILED",
        requestId,
      ).catch(() => undefined);
      return false;
    }
    if (!recovery.resetAfterCompensation) return true;
    return this.database.invitations.abortAcceptance(recovery.claim, "STALE_ACCEPTANCE_RECOVERED");
  }

  private async recoverAcceptedInvitation(
    claim: TenantInvitationClaim,
    invitationToken: string,
    recoveryProof: string,
    requestId: string,
    userAgent?: string,
    ip?: string,
  ): Promise<InvitationAcceptanceResult> {
    if (claim.authorityKind === "initial_admin") {
      const consumed = await this.finalizeInitialAdminClaim(claim, requestId).catch(() => false);
      if (!consumed) {
        throw new ApiError(
          503,
          "INVITATION_ACCEPTANCE_FINALIZATION_UNAVAILABLE",
          "Invitation acceptance is secure but finalization is temporarily unavailable",
        );
      }
    }
    const sessionToken = randomToken();
    const csrfToken = randomToken();
    const sessionId = randomUUID();
    const binding = createSessionBinding(userAgent, ip);
    const recovered = await this.database.invitations.recoverAcceptedEnrollmentSession({
      claim,
      token: invitationToken,
      recoveryProof,
      requestId,
      bootstrapSession: {
        sessionId,
        tokenHash: sha256(sessionToken),
        csrfHash: sha256(csrfToken),
        expiresAt: new Date(Date.now() + INVITATION_ENROLLMENT_WINDOW_MINUTES * 60_000),
        ...binding,
      },
    });
    if (!recovered) throw invalidInvitation();
    const principal = await this.database.getPrincipal(sha256(sessionToken), requestId, binding);
    if (
      !principal || principal.sessionId !== sessionId || principal.identityId !== claim.identityId
      || principal.activeTenantId !== claim.tenantId || principal.assuranceLevel !== "enrollment_only"
      || !principal.enrollmentOnly
    ) {
      throw new ApiError(
        503,
        "INVITATION_ENROLLMENT_SESSION_UNAVAILABLE",
        "Invitation was accepted but its secure enrollment session is unavailable",
      );
    }
    return {
      ...this.authService.publicSession(principal, csrfToken, null, 0),
      sessionToken,
      expiresAt: recovered.expiresAt,
      accepted: true,
      signInRequired: false,
      enrollmentRequired: true,
      tenantId: claim.tenantId,
      roles: claim.roles,
    };
  }
}

class InvitationAcceptanceStateError extends Error {}
class InitialAdminFinalizationError extends Error {}

export function normalizeEmail(value: string): string {
  return value.trim().normalize("NFKC").toLocaleLowerCase("en-US");
}

function normalizeDisplayName(value: string): string {
  return value.trim().normalize("NFKC").replace(/\s+/g, " ");
}

function invalidInvitation(): ApiError {
  return new ApiError(400, "INVITATION_INVALID", "Invitation is invalid or unavailable");
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const result = JSON.stringify(value);
    if (result === undefined) throw new Error("Invitation idempotency accepts JSON-compatible values only");
    return result;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}
