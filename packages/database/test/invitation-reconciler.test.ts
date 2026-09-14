import { describe, expect, it, vi } from "vitest";
import { InvitationSagaReconciler } from "../src/invitation-reconciler.js";
import type { DatabaseRuntime, TenantInvitationClaim } from "../src/index.js";

const delegateClaim: TenantInvitationClaim = {
  invitationId: "10000000-0000-4000-8000-000000000001",
  acceptanceId: "20000000-0000-4000-8000-000000000001",
  identityId: "30000000-0000-4000-8000-000000000001",
  tenantId: "40000000-0000-4000-8000-000000000001",
  email: "recipient@example.test",
  normalizedEmail: "recipient@example.test",
  roles: ["AUDITOR"],
  expiresAt: new Date(Date.now() + 60_000),
  createdByIdentityId: "50000000-0000-4000-8000-000000000001",
  authorityKind: "tenant_delegate",
  authorityEpoch: 0,
  acceptanceAttempt: 2,
};

describe("durable invitation saga reconciler", () => {
  it("does no tenant work when no durable candidate exists", async () => {
    const claimReconciliationCandidate = vi.fn().mockResolvedValue(null);
    const database = { invitations: { claimReconciliationCandidate } } as unknown as DatabaseRuntime;
    await expect(new InvitationSagaReconciler(database).reconcileOne("request-empty"))
      .resolves.toEqual({ processed: false });
  });

  it("wins the accepting compensation CAS before exact tenant cleanup and resets idempotently", async () => {
    const cleanupInvitationRoles = vi.fn().mockResolvedValue(1);
    const finalizeReconciledAcceptanceReset = vi.fn().mockResolvedValue(true);
    const database = {
      invitations: {
        claimReconciliationCandidate: vi.fn().mockResolvedValue({
          claim: delegateClaim,
          status: "accepting",
          reconciliationAttemptCount: 1,
          leaseExpiresAt: new Date(Date.now() + 300_000),
        }),
        beginCompensation: vi.fn().mockResolvedValue(true),
        finalizeReconciledAcceptanceReset,
        failReconciliation: vi.fn(),
      },
      withFencedInvitationSagaTenant: vi.fn(async (_input, work) => work({ cleanupInvitationRoles })),
    } as unknown as DatabaseRuntime;

    await expect(new InvitationSagaReconciler(database).reconcileOne("request-stale"))
      .resolves.toEqual({
        processed: true,
        invitationId: delegateClaim.invitationId,
        action: "acceptance_reset",
      });
    expect(database.invitations.beginCompensation).toHaveBeenCalledWith(delegateClaim);
    expect(database.withFencedInvitationSagaTenant).toHaveBeenCalledWith(
      expect.objectContaining({
        invitationId: delegateClaim.invitationId,
        acceptanceId: delegateClaim.acceptanceId,
        acceptanceAttempt: 2,
        allowedStatuses: ["compensating", "revoked", "expired", "failed"],
      }),
      expect.any(Function),
    );
    expect(cleanupInvitationRoles).toHaveBeenCalledWith({
      invitationId: delegateClaim.invitationId,
      acceptanceId: delegateClaim.acceptanceId,
      identityId: delegateClaim.identityId,
      acceptanceAttempt: 2,
    });
    expect(finalizeReconciledAcceptanceReset).toHaveBeenCalledWith(expect.objectContaining({
      claim: delegateClaim,
      requestId: "request-stale",
      leaseToken: expect.any(String),
    }));
  });

  it("never rolls back when completion wins and finalizes the exact initial-admin capability", async () => {
    const initialClaim = { ...delegateClaim, authorityKind: "initial_admin" as const, authorityEpoch: 7 };
    const consumeInitialAdminInvitationRole = vi.fn().mockResolvedValue(true);
    const finalizeReconciledAuthority = vi.fn().mockResolvedValue(true);
    const database = {
      invitations: {
        claimReconciliationCandidate: vi.fn().mockResolvedValue({
          claim: initialClaim,
          status: "accepting",
          reconciliationAttemptCount: 1,
          leaseExpiresAt: new Date(Date.now() + 300_000),
        }),
        beginCompensation: vi.fn().mockResolvedValue(false),
        getAcceptanceStatus: vi.fn().mockResolvedValue("accepted"),
        finalizeReconciledAuthority,
        failReconciliation: vi.fn(),
      },
      getInitialAdminCapabilitySecrets: vi.fn().mockResolvedValue({ apply: "a".repeat(43), cleanup: "c".repeat(43) }),
      withFencedInvitationSagaTenant: vi.fn(async (_input, work) => work({ consumeInitialAdminInvitationRole })),
    } as unknown as DatabaseRuntime;

    await expect(new InvitationSagaReconciler(database).reconcileOne("request-race"))
      .resolves.toMatchObject({ action: "authority_finalized" });
    expect(consumeInitialAdminInvitationRole).toHaveBeenCalledWith(expect.objectContaining({
      invitationId: initialClaim.invitationId,
      acceptanceId: initialClaim.acceptanceId,
      authorityEpoch: 7,
      acceptanceAttempt: 2,
      capabilitySecret: "a".repeat(43),
    }));
    expect(finalizeReconciledAuthority).toHaveBeenCalledWith(expect.objectContaining({
      claim: initialClaim,
      requestId: "request-race",
      leaseToken: expect.any(String),
    }));
  });

  it("records a durable terminal cleanup receipt and never revives a revoked token", async () => {
    const cleanupInvitationRoles = vi.fn().mockResolvedValue(0);
    const finalizeReconciledTerminalCleanup = vi.fn().mockResolvedValue(true);
    const finalizeReconciledAcceptanceReset = vi.fn();
    const database = {
      invitations: {
        claimReconciliationCandidate: vi.fn().mockResolvedValue({
          claim: delegateClaim,
          status: "revoked",
          reconciliationAttemptCount: 1,
          leaseExpiresAt: new Date(Date.now() + 300_000),
        }),
        finalizeReconciledTerminalCleanup,
        finalizeReconciledAcceptanceReset,
        failReconciliation: vi.fn(),
      },
      withFencedInvitationSagaTenant: vi.fn(async (_input, work) => work({ cleanupInvitationRoles })),
    } as unknown as DatabaseRuntime;

    await expect(new InvitationSagaReconciler(database).reconcileOne("request-revoked"))
      .resolves.toMatchObject({ action: "terminal_cleanup_finalized" });
    expect(finalizeReconciledTerminalCleanup).toHaveBeenCalledWith(expect.objectContaining({
      claim: delegateClaim,
      requestId: "request-revoked",
      leaseToken: expect.any(String),
    }));
    expect(finalizeReconciledAcceptanceReset).not.toHaveBeenCalled();
  });

  it("persists a per-row failure receipt so a poison candidate cannot impose global backoff", async () => {
    const failReconciliation = vi.fn().mockResolvedValue(true);
    const database = {
      invitations: {
        claimReconciliationCandidate: vi.fn().mockResolvedValue({
          claim: delegateClaim,
          status: "revoked",
          reconciliationAttemptCount: 4,
          leaseExpiresAt: new Date(Date.now() + 300_000),
        }),
        failReconciliation,
      },
      withFencedInvitationSagaTenant: vi.fn().mockRejectedValue(new Error("tenant unavailable")),
    } as unknown as DatabaseRuntime;

    await expect(new InvitationSagaReconciler(database).reconcileOne("request-poison"))
      .rejects.toThrow("tenant unavailable");
    expect(failReconciliation).toHaveBeenCalledWith(expect.objectContaining({
      claim: delegateClaim,
      requestId: "request-poison",
      errorCode: "INVITATION_RECONCILIATION_FAILED",
      leaseToken: expect.any(String),
    }));
  });
});
