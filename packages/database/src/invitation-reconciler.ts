import { randomUUID } from "node:crypto";
import type { DatabaseRuntime } from "./runtime.js";
import type { TenantInvitationClaim, TenantInvitationStatus } from "./invitation-store.js";

export interface InvitationSagaReconciliationResult {
  readonly processed: boolean;
  readonly invitationId?: string;
  readonly action?: "authority_finalized" | "acceptance_reset" | "terminal_cleanup_finalized" | "race_lost";
}

/**
 * Repairs only durable invitation saga states. It never needs the invitation
 * bearer or browser recovery proof: every tenant mutation is authorized by an
 * exact control-plane tuple/status fence and, for the one-time initial admin,
 * by the distinct out-of-database capability secret.
 */
export class InvitationSagaReconciler {
  public constructor(private readonly database: DatabaseRuntime) {}

  public async reconcileOne(requestId: string): Promise<InvitationSagaReconciliationResult> {
    const leaseToken = randomUUID();
    const candidate = await this.database.invitations.claimReconciliationCandidate(leaseToken);
    if (!candidate) return { processed: false };
    const { claim } = candidate;
    try {
      if (candidate.status === "accepted") {
        return await this.finalizeAcceptedInitialAdmin(claim, leaseToken, requestId);
      }

      let status: TenantInvitationStatus | null = candidate.status;
      if (status === "accepting") {
        const fenced = await this.database.invitations.beginCompensation(claim);
        if (!fenced) {
          status = await this.database.invitations.getAcceptanceStatus(claim);
          if (status === "accepted" && claim.authorityKind === "initial_admin") {
            return await this.finalizeAcceptedInitialAdmin(claim, leaseToken, requestId);
          }
          if (!await this.database.invitations.finalizeReconciliationRace({ claim, leaseToken, requestId })) {
            throw new Error("Invitation reconciliation race receipt did not match its durable lease");
          }
          return { processed: true, invitationId: claim.invitationId, action: "race_lost" };
        }
        status = "compensating";
      }
      if (!status || !["compensating", "revoked", "expired", "failed"].includes(status)) {
        if (!await this.database.invitations.finalizeReconciliationRace({ claim, leaseToken, requestId })) {
          throw new Error("Invitation reconciliation no-op receipt did not match its durable lease");
        }
        return { processed: true, invitationId: claim.invitationId, action: "race_lost" };
      }

      await this.cleanupExactTenantAttempt(claim, requestId);
      if (status === "compensating") {
        if (await this.database.invitations.finalizeReconciledAcceptanceReset({ claim, leaseToken, requestId })) {
          return { processed: true, invitationId: claim.invitationId, action: "acceptance_reset" };
        }
        // Authority loss may linearize after compensation begins and turn the
        // row terminal. Cleanup already won the exact control fence, so record
        // its durable receipt instead of reviving the token.
        status = await this.database.invitations.getAcceptanceStatus(claim);
        if (!status || !["revoked", "expired", "failed"].includes(status)) {
          throw new Error("Invitation compensation completed but its control state is ambiguous");
        }
      }
      if (!await this.database.invitations.finalizeReconciledTerminalCleanup({ claim, leaseToken, requestId })) {
        throw new Error("Invitation tenant cleanup receipt could not be finalized");
      }
      return { processed: true, invitationId: claim.invitationId, action: "terminal_cleanup_finalized" };
    } catch (error) {
      await this.database.invitations.failReconciliation({
        claim,
        leaseToken,
        requestId,
        errorCode: "INVITATION_RECONCILIATION_FAILED",
      }).catch(() => false);
      throw error;
    }
  }

  private async finalizeAcceptedInitialAdmin(
    claim: TenantInvitationClaim,
    leaseToken: string,
    requestId: string,
  ): Promise<InvitationSagaReconciliationResult> {
    if (claim.authorityKind !== "initial_admin") {
      throw new Error("Only an initial-administrator acceptance has an authority capability to finalize");
    }
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
    if (!consumed || !await this.database.invitations.finalizeReconciledAuthority({
      claim,
      leaseToken,
      requestId,
    })) {
      throw new Error("Initial administrator authority finalization did not match the durable saga tuple");
    }
    return { processed: true, invitationId: claim.invitationId, action: "authority_finalized" };
  }

  private async cleanupExactTenantAttempt(claim: TenantInvitationClaim, requestId: string): Promise<void> {
    if (claim.authorityKind === "initial_admin") {
      const capability = await this.database.getInitialAdminCapabilitySecrets(claim.tenantId);
      const rolledBack = await this.database.withFencedInvitationSagaTenant({
        tenantId: claim.tenantId,
        invitationId: claim.invitationId,
        identityId: claim.identityId,
        acceptanceId: claim.acceptanceId,
        acceptanceAttempt: claim.acceptanceAttempt,
        requestId,
        allowedStatuses: ["compensating", "revoked", "expired", "failed"],
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
      allowedStatuses: ["compensating", "revoked", "expired", "failed"],
    }, (tenant) => tenant.cleanupInvitationRoles({
      invitationId: claim.invitationId,
      acceptanceId: claim.acceptanceId,
      identityId: claim.identityId,
      acceptanceAttempt: claim.acceptanceAttempt,
    }));
  }
}
