import { z } from "zod";

const uuid = z.string().uuid();

export const initialAdminRecoverySourceSchema = z.object({
  tenantId: uuid,
  invitationId: uuid,
  acceptanceId: uuid,
  acceptanceIdentityId: uuid,
  acceptanceAttempt: z.number().int().positive(),
  authorityEpoch: z.number().int().positive(),
  invitationVersion: z.number().int().positive(),
}).strict();

export const initialAdminRecoveryReasonSchema = z.enum([
  "browser_context_lost",
  "browser_profile_reset",
  "device_lost",
  "session_delivery_failure",
]);

export const initialAdminRecoveryDeliveryChannelSchema = z.enum([
  "local_console",
  "verified_email",
  "verified_sms",
  "service_desk",
]);

export const initialAdminRecoveryCandidatesQuerySchema = z.object({
  tenantId: uuid.optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
}).strict();

export const initialAdminRecoveryQueueQuerySchema = z.object({
  tenantId: uuid.optional(),
  status: z.enum([
    "pending", "finalization_pending", "enrollment_pending", "admin_active",
    "revoked", "expired", "failed",
  ]).optional(),
  beforeRequestedAt: z.string().datetime({ offset: true }).optional(),
  beforeRecoveryId: uuid.optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
}).strict().superRefine((value, context) => {
  if ((value.beforeRequestedAt === undefined) !== (value.beforeRecoveryId === undefined)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["beforeRecoveryId"],
      message: "Both stable cursor fields are required together",
    });
  }
});

export const requestInitialAdminRecoverySchema = z.object({
  // Client-generated and included in the operation-bound WebAuthn hash.  The
  // server never swaps a freshly generated aggregate id after authorization.
  recoveryId: uuid,
  source: initialAdminRecoverySourceSchema,
  reasonCode: initialAdminRecoveryReasonSchema,
  caseReference: z.string().trim().min(8).max(160)
    .regex(/^[\p{L}\p{N}][\p{L}\p{N} ._:/-]+$/u),
  expiresInMinutes: z.number().int().min(15).max(1_440).default(1_440),
}).strict();

export const approveInitialAdminRecoverySchema = z.object({
  recoveryId: uuid,
  expectedVersion: z.number().int().positive(),
  source: initialAdminRecoverySourceSchema,
  deliveryChannel: initialAdminRecoveryDeliveryChannelSchema,
  verifiedChannelReference: z.string().trim().min(8).max(240)
    .refine((value) => !/[\p{Cc}\p{Cf}]/u.test(value), "Delivery reference contains control characters"),
}).strict();

export const revokeInitialAdminRecoverySchema = z.object({
  recoveryId: uuid,
  expectedVersion: z.number().int().positive(),
  source: initialAdminRecoverySourceSchema,
  reasonCode: z.enum(["security_response", "requester_cancelled", "delivery_reissue"]),
}).strict();

export const redeemInitialAdminRecoverySchema = z.object({
  recoveryId: uuid,
  // Present exactly once for the initial bearer redemption. A response-loss
  // retry may omit it because the previously completed HttpOnly context is the
  // only credential admitted after token consumption.
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/u).optional(),
}).strict();

export const prepareInitialAdminRecoveryContextSchema = z.object({}).strict();

export type InitialAdminRecoverySourceInput = z.infer<typeof initialAdminRecoverySourceSchema>;
export type InitialAdminRecoveryRequestInput = z.infer<typeof requestInitialAdminRecoverySchema>;
export type InitialAdminRecoveryApprovalInput = z.infer<typeof approveInitialAdminRecoverySchema>;
export type InitialAdminRecoveryRevocationInput = z.infer<typeof revokeInitialAdminRecoverySchema>;
