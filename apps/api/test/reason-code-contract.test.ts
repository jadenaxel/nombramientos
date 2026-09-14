import { describe, expect, it } from "vitest";
import {
  closeWorkflowRoundBodySchema,
  candidacyReviewBodySchema,
  eligibilityPauseResolutionBodySchema,
  assignmentFinalizationBodySchema,
  assignmentSubstitutionBodySchema,
  sessionDecisionBodySchema,
} from "../src/modules/core-workflow-contract.js";
import { revokeKeySchema } from "../src/modules/custody-routes.js";
import { revokeInvitationSchema } from "../src/modules/invitation-routes.js";
import {
  declareKeyLostIntentSchema,
  revokeGrantIntentSchema,
  rotateKeyIntentSchema,
} from "../src/modules/key-lifecycle-contract.js";
import { closeSchema } from "../src/modules/round-routes.js";
import { memberArchiveSchema, memberReactivateSchema } from "../src/modules/tenant-routes.js";

const ID = "11111111-1111-4111-8111-111111111111";

describe("non-sensitive reason-code HTTP boundary", () => {
  it("requires operation-specific reasonCode and rejects prose or uppercase exfiltration tokens", () => {
    expect(memberArchiveSchema.safeParse({ expectedVersion: 1, reasonCode: "RECORD_LIFECYCLE_CHANGE" }).success).toBe(true);
    expect(memberReactivateSchema.safeParse({ expectedVersion: 1, reasonCode: "ARCHIVE_REVERSED" }).success).toBe(true);
    expect(closeSchema.safeParse({ expectedVersion: 1, reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED" }).success).toBe(true);
    expect(closeWorkflowRoundBodySchema.safeParse({ expectedRoundVersion: 1, expectedProcessVersion: 1, reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED" }).success).toBe(true);
    expect(revokeKeySchema.safeParse({ expectedVersion: 1, reasonCode: "DEVICE_RETIRED" }).success).toBe(true);
    expect(revokeInvitationSchema.safeParse({ reasonCode: "ADMIN_ACCESS_REVOCATION" }).success).toBe(true);
    expect(revokeInvitationSchema.safeParse({}).success).toBe(true);

    for (const schema of [memberArchiveSchema, memberReactivateSchema, closeSchema, revokeKeySchema]) {
      expect(schema.safeParse({ expectedVersion: 1, reason: "personal details in clear text" }).success).toBe(false);
      expect(schema.safeParse({ expectedVersion: 1, reasonCode: "PERSONA_TIENE_DIAGNOSTICO" }).success).toBe(false);
    }
    expect(closeWorkflowRoundBodySchema.safeParse({ expectedRoundVersion: 1, expectedProcessVersion: 1, reason: "free text" }).success).toBe(false);
    expect(revokeInvitationSchema.safeParse({ reason: "free text" }).success).toBe(false);
    expect(revokeInvitationSchema.safeParse({ reasonCode: "PERSONA_TIENE_DIAGNOSTICO" }).success).toBe(false);
  });

  it("applies the same code-only field to every tenant-key ceremony that records a reason", () => {
    expect(revokeGrantIntentSchema.shape.reasonCode.safeParse("DEVICE_RETIRED").success).toBe(true);
    expect(rotateKeyIntentSchema.shape.reasonCode.safeParse("SCHEDULED_ROTATION").success).toBe(true);
    expect(declareKeyLostIntentSchema.safeParse({
      tenantKeyId: ID,
      confirmation: "PERMANENTLY_LOSE_TENANT_KEY",
      reasonCode: "RECOVERY_MATERIAL_UNAVAILABLE",
    }).success).toBe(true);
    for (const schema of [revokeGrantIntentSchema.shape.reasonCode, rotateKeyIntentSchema.shape.reasonCode, declareKeyLostIntentSchema.shape.reasonCode]) {
      expect(schema.safeParse("Details about an identifiable person").success).toBe(false);
      expect(schema.safeParse("PERSONA_TIENE_DIAGNOSTICO").success).toBe(false);
    }
  });

  it("binds workflow reason and decision codes to the selected outcome", () => {
    const evidenceEnvelope = {
      algorithm: "AES-256-GCM",
      keyId: "tenant-key-v1",
      nonce: Buffer.alloc(12).toString("base64url"),
      ciphertext: Buffer.alloc(16).toString("base64url"),
      aad: Buffer.from("{}").toString("base64url"),
    };
    expect(eligibilityPauseResolutionBodySchema.safeParse({
      expectedProcessVersion: 1,
      expectedPauseIds: [ID],
      resolutionCode: "ANNUL_AND_RESTART",
      reasonCode: "ELIGIBILITY_ROUND_RESTARTED",
      evidenceEnvelope,
    }).success).toBe(true);
    expect(eligibilityPauseResolutionBodySchema.safeParse({
      expectedProcessVersion: 1,
      expectedPauseIds: [ID],
      resolutionCode: "ANNUL_AND_RESTART",
      reasonCode: "ELIGIBILITY_PROCESS_RESUMED",
      evidenceEnvelope,
    }).success).toBe(false);
    expect(candidacyReviewBodySchema.safeParse({ expectedVersion: 1, toState: "EXCLUDED", reasonCode: "COMMITTEE_EXCLUDED" }).success).toBe(true);
    expect(candidacyReviewBodySchema.safeParse({ expectedVersion: 1, toState: "EXCLUDED", reasonCode: "REVIEW_STARTED" }).success).toBe(false);
    expect(assignmentFinalizationBodySchema.safeParse({ expectedVersion: 1, reasonCode: "TERM_COMPLETED_OPEN_VACANCY", openVacancy: true }).success).toBe(true);
    expect(assignmentFinalizationBodySchema.safeParse({ expectedVersion: 1, reasonCode: "TERM_COMPLETED_NO_VACANCY", openVacancy: true }).success).toBe(false);
    expect(assignmentSubstitutionBodySchema.safeParse({ expectedVersion: 1, reasonCode: "ASSIGNMENT_REPLACED" }).success).toBe(true);
    expect(sessionDecisionBodySchema.safeParse({ expectedSessionVersion: 1, agendaItemId: ID, decisionCode: "AGREEMENT", outcome: "APPROVED" }).success).toBe(true);
    expect(sessionDecisionBodySchema.safeParse({ expectedSessionVersion: 1, agendaItemId: ID, decisionCode: "PERSONA_TIENE_DIAGNOSTICO", outcome: "RECORDED" }).success).toBe(false);
    expect(sessionDecisionBodySchema.safeParse({ expectedSessionVersion: 1, agendaItemId: ID, decisionCode: "INFORMATION_NOTED", outcome: "REJECTED" }).success).toBe(false);
  });
});
