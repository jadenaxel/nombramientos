import {
  ASSIGNMENT_FINALIZATION_REASON_CODES,
  ASSIGNMENT_SUBSTITUTION_REASON_CODES,
  CANDIDACY_REVIEW_REASON_CODES,
  CUSTODY_KEY_REVOKE_REASON_CODES,
  ELIGIBILITY_PAUSE_REASON_CODES,
  INVITATION_REVOKE_REASON_CODES,
  KEY_GRANT_REVOKE_REASON_CODES,
  KEY_LOSS_REASON_CODES,
  KEY_ROTATION_REASON_CODES,
  MEMBER_ARCHIVE_REASON_CODES,
  MEMBER_REACTIVATE_REASON_CODES,
  OFFICE_PROCESS_APPLICABILITY_REASON_CODES,
  ROUND_CLOSE_REASON_CODES,
  SESSION_DECISION_CODES,
} from "@nombramientos/database";
import { z } from "zod";

// Closed vocabularies are intentional. A format-only uppercase token can still
// encode sensitive prose joined with underscores.
export const memberArchiveReasonCodeSchema = z.enum(MEMBER_ARCHIVE_REASON_CODES);
export const memberReactivateReasonCodeSchema = z.enum(MEMBER_REACTIVATE_REASON_CODES);
export const officeProcessApplicabilityReasonCodeSchema = z.enum(OFFICE_PROCESS_APPLICABILITY_REASON_CODES);
export const roundCloseReasonCodeSchema = z.enum(ROUND_CLOSE_REASON_CODES);
export const custodyKeyRevokeReasonCodeSchema = z.enum(CUSTODY_KEY_REVOKE_REASON_CODES);
export const keyGrantRevokeReasonCodeSchema = z.enum(KEY_GRANT_REVOKE_REASON_CODES);
export const keyRotationReasonCodeSchema = z.enum(KEY_ROTATION_REASON_CODES);
export const keyLossReasonCodeSchema = z.enum(KEY_LOSS_REASON_CODES);
export const invitationRevokeReasonCodeSchema = z.enum(INVITATION_REVOKE_REASON_CODES);
export const sessionDecisionCodeSchema = z.enum(SESSION_DECISION_CODES);
export const eligibilityPauseReasonCodeSchema = z.enum(ELIGIBILITY_PAUSE_REASON_CODES);
export const candidacyReviewReasonCodeSchema = z.enum(CANDIDACY_REVIEW_REASON_CODES);
export const assignmentFinalizationReasonCodeSchema = z.enum(ASSIGNMENT_FINALIZATION_REASON_CODES);
export const assignmentSubstitutionReasonCodeSchema = z.enum(ASSIGNMENT_SUBSTITUTION_REASON_CODES);
