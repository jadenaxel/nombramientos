import type { Pool, PoolClient } from "pg";
import { describe, expect, it } from "vitest";
import { CoreWorkflowStore } from "../src/core-workflow-store.js";
import { CustodyStore } from "../src/custody-store.js";
import { InvitationStore } from "../src/invitation-store.js";
import { KeyLifecycleStore } from "../src/key-lifecycle-store.js";
import { TenantStore } from "../src/tenant-store.js";

const ID = "11111111-1111-4111-8111-111111111111";
const UNKNOWN = "PERSONA_TIENE_DIAGNOSTICO";

describe("store reason-code allowlists", () => {
  it("rejects an unknown uppercase token before any tenant query", async () => {
    let queries = 0;
    const client = {
      query: async () => {
        queries += 1;
        throw new Error("database must not be reached");
      },
    } as unknown as PoolClient;
    const tenant = new TenantStore(client);
    const custody = new CustodyStore(client);

    await expect(tenant.archiveMember({ identityId: ID, idempotencyKey: ID, memberId: ID, expectedVersion: 1, reasonCode: UNKNOWN }))
      .rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(tenant.reactivateMember({ identityId: ID, idempotencyKey: ID, memberId: ID, expectedVersion: 1, reasonCode: UNKNOWN }))
      .rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(tenant.closeRound({ identityId: ID, idempotencyKey: ID, roundId: ID, expectedVersion: 1, reasonCode: UNKNOWN }))
      .rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(custody.revokeKey({ identityId: ID, idempotencyKey: ID, keyId: ID, expectedVersion: 1, reasonCode: UNKNOWN }))
      .rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    expect(queries).toBe(0);
  });

  it("rejects unknown key and invitation codes before consuming state", async () => {
    let queries = 0;
    const client = {
      query: async () => {
        queries += 1;
        throw new Error("database must not be reached");
      },
    } as unknown as PoolClient;
    const lifecycle = new KeyLifecycleStore(client);
    const invitations = new InvitationStore({
      connect: async () => {
        queries += 1;
        throw new Error("database must not be reached");
      },
    } as unknown as Pool);

    await expect(lifecycle.revokeGrant({
      actorIdentityId: ID, sessionId: ID, idempotencyKey: ID, challengeId: ID,
      requestHash: `sha256:${"a".repeat(64)}`, grantId: ID, expectedVersion: 1,
      reasonCode: UNKNOWN, confirmLastActiveGrant: false,
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(lifecycle.rotateKey({
      actorIdentityId: ID, sessionId: ID, idempotencyKey: ID, challengeId: ID,
      requestHash: `sha256:${"a".repeat(64)}`, expectedTenantKeyId: ID,
      expectedGeneration: 1, newTenantKeyId: ID, reasonCode: UNKNOWN,
      recoveryPublicKey: {}, recoveryKeyFingerprint: `sha256:${"b".repeat(64)}`,
      grants: [],
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(lifecycle.declareKeyLost({
      actorIdentityId: ID, sessionId: ID, idempotencyKey: ID, challengeId: ID,
      requestHash: `sha256:${"a".repeat(64)}`, tenantKeyId: ID,
      confirmation: "PERMANENTLY_LOSE_TENANT_KEY", reasonCode: UNKNOWN,
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(invitations.revoke({
      invitationId: ID, tenantId: ID, actorIdentityId: ID, reasonCode: UNKNOWN, requestId: ID,
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    expect(queries).toBe(0);
  });

  it("binds workflow codes to their decisions before idempotency state", async () => {
    let queries = 0;
    const client = {
      query: async () => {
        queries += 1;
        throw new Error("database must not be reached");
      },
    } as unknown as PoolClient;
    const workflow = new CoreWorkflowStore(client);

    await expect(workflow.closeProposalRound({
      identityId: ID, idempotencyKey: ID, roundId: ID,
      expectedRoundVersion: 1, expectedProcessVersion: 1, reasonCode: UNKNOWN,
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(workflow.resolveEligibilityPause({
      identityId: ID, idempotencyKey: ID, processId: ID, expectedProcessVersion: 1,
      expectedPauseIds: [ID], resolutionCode: "ANNUL_AND_RESTART",
      reasonCode: "ELIGIBILITY_PROCESS_RESUMED", evidenceEnvelope: {} as never,
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(workflow.reviewCandidacy({
      identityId: ID, idempotencyKey: ID, processId: ID, candidacyId: ID,
      expectedVersion: 1, toState: "EXCLUDED", reasonCode: "REVIEW_STARTED",
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(workflow.finalizeAssignment({
      identityId: ID, idempotencyKey: ID, assignmentId: ID, expectedVersion: 1,
      reasonCode: "TERM_COMPLETED_NO_VACANCY", openVacancy: true,
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(workflow.substituteAssignment({
      identityId: ID, idempotencyKey: ID, assignmentId: ID, expectedVersion: 1,
      reasonCode: "TERM_COMPLETED_OPEN_VACANCY",
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(workflow.recordSessionDecision({
      identityId: ID, idempotencyKey: ID, sessionId: ID, expectedSessionVersion: 1,
      agendaItemId: ID, decisionCode: "INFORMATION_NOTED", outcome: "REJECTED",
    })).rejects.toMatchObject({ code: "INVALID_DECISION_CODE" });
    await expect(workflow.recordSessionDecision({
      identityId: ID, idempotencyKey: ID, sessionId: ID, expectedSessionVersion: 1,
      agendaItemId: ID, decisionCode: UNKNOWN, outcome: "RECORDED",
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    expect(queries).toBe(0);
  });
});
