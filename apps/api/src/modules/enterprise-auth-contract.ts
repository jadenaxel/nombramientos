import { createHash, timingSafeEqual } from "node:crypto";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { z } from "zod";
import { ApiError } from "../lib/errors.js";

const base64Url = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9_-]+$/u);
const credentialId = base64Url(2_048);
const clientExtensionResults = z.record(z.unknown());
const authenticatorAttachment = z.enum(["cross-platform", "platform"]).optional();
const transports = z.array(z.enum([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
])).max(8).optional();

export const registrationResponseSchema = z.object({
  id: credentialId,
  rawId: credentialId,
  response: z.object({
    clientDataJSON: base64Url(16_384),
    attestationObject: base64Url(1_500_000),
    authenticatorData: base64Url(65_536).optional(),
    transports,
    publicKeyAlgorithm: z.number().int().optional(),
    publicKey: base64Url(65_536).optional(),
  }).strict(),
  authenticatorAttachment,
  clientExtensionResults,
  type: z.literal("public-key"),
}).strict().superRefine((value, context) => {
  if (value.id !== value.rawId) {
    context.addIssue({ code: "custom", path: ["rawId"], message: "Credential id and rawId must match" });
  }
});

export const authenticationResponseSchema = z.object({
  id: credentialId,
  rawId: credentialId,
  response: z.object({
    clientDataJSON: base64Url(16_384),
    authenticatorData: base64Url(65_536),
    signature: base64Url(65_536),
    userHandle: base64Url(512).optional(),
  }).strict(),
  authenticatorAttachment,
  clientExtensionResults,
  type: z.literal("public-key"),
}).strict().superRefine((value, context) => {
  if (value.id !== value.rawId) {
    context.addIssue({ code: "custom", path: ["rawId"], message: "Credential id and rawId must match" });
  }
});

export const passkeyAuthenticationOptionsSchema = z.object({
  email: z.string().trim().email().max(320).optional(),
  mediation: z.enum(["conditional", "optional"]).default("optional"),
}).strict();

export const passkeyAuthenticationVerificationSchema = z.object({
  ceremonyId: z.string().uuid(),
  response: authenticationResponseSchema,
}).strict();

export const passkeyRegistrationOptionsSchema = z.object({
  replacementCredentialId: z.string().uuid().optional(),
}).strict();

export const passkeyRegistrationVerificationSchema = z.object({
  ceremonyId: z.string().uuid(),
  response: registrationResponseSchema,
  name: z.string().trim().min(1).max(80),
}).strict();

export const passkeyNameSchema = z.object({
  name: z.string().trim().min(1).max(80),
  expectedVersion: z.number().int().positive(),
}).strict();

export const passkeyRevocationSchema = z.object({
  reason: z.enum(["user_revoked", "compromised", "replaced"]),
}).strict();

export const sessionRevocationSchema = z.object({
  reason: z.literal("user_revoked"),
}).strict();

const identityActionRequirementSchema = z.object({
  minAal: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  phishingResistant: z.boolean().optional(),
  stepUpRequired: z.boolean().optional(),
}).strict();

export const identityPolicyValuesSchema = z.object({
  enforcementMode: z.enum(["monitor", "enforce"]),
  minimumAal: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  privilegedMinimumAal: z.union([z.literal(2), z.literal(3)]),
  requireUserVerification: z.boolean(),
  requirePhishingResistantForPrivileged: z.boolean(),
  requireDeviceBoundForPrivileged: z.boolean(),
  requireAttestationForPrivileged: z.boolean(),
  allowPassword: z.boolean(),
  allowTotpFallback: z.boolean(),
  allowRecoveryCodes: z.boolean(),
  allowSyncedPasskeys: z.boolean(),
  minimumPasskeyCount: z.number().int().min(0).max(10),
  privilegedMinimumPasskeyCount: z.number().int().min(1).max(10),
  maximumPasskeys: z.number().int().min(1).max(20),
  maximumActiveSessions: z.number().int().min(1).max(100),
  idleTimeoutMinutes: z.number().int().min(5).max(1_440),
  absoluteSessionMinutes: z.number().int().min(5).max(10_080),
  stepUpTtlSeconds: z.number().int().min(60).max(900),
  actionRequirements: z.record(
    z.string().regex(/^[a-z][a-z0-9._:-]{1,127}$/u),
    identityActionRequirementSchema,
  ).refine((value) => Object.keys(value).length <= 100, "Too many action requirements"),
}).strict().superRefine((value, context) => {
  if (value.privilegedMinimumAal < value.minimumAal) {
    context.addIssue({ code: "custom", path: ["privilegedMinimumAal"], message: "Privileged AAL cannot be lower than minimum AAL" });
  }
  if (value.minimumPasskeyCount > value.maximumPasskeys) {
    context.addIssue({ code: "custom", path: ["minimumPasskeyCount"], message: "Minimum passkeys exceeds maximum" });
  }
  if (value.privilegedMinimumPasskeyCount > value.maximumPasskeys) {
    context.addIssue({ code: "custom", path: ["privilegedMinimumPasskeyCount"], message: "Privileged minimum passkeys exceeds maximum" });
  }
  if (value.privilegedMinimumPasskeyCount < value.minimumPasskeyCount) {
    context.addIssue({ code: "custom", path: ["privilegedMinimumPasskeyCount"], message: "Privileged minimum passkeys cannot be lower than minimum passkeys" });
  }
  if (value.idleTimeoutMinutes > value.absoluteSessionMinutes) {
    context.addIssue({ code: "custom", path: ["idleTimeoutMinutes"], message: "Idle timeout cannot exceed absolute lifetime" });
  }
});

export const identityPolicyUpdateSchema = z.object({
  expectedVersion: z.number().int().min(0),
  policy: identityPolicyValuesSchema,
}).strict();

export const resourceIdSchema = z.object({ id: z.string().uuid() }).strict();

export const stepUpPurposeSchema = z.enum([
  "custody_operation",
  "data_export",
  "identity_security_change",
  "key_lifecycle",
  "passkey_enrollment",
  "platform_administration",
  "recovery_completion",
  "role_administration",
  "session_revocation",
  "tenant_administration",
]);
export type StepUpPurpose = z.infer<typeof stepUpPurposeSchema>;

export const stepUpOptionsSchema = z.object({
  purpose: stepUpPurposeSchema,
  operationHash: z.string().regex(/^[0-9a-f]{64}$/u),
}).strict();

export const stepUpVerificationSchema = z.object({
  ceremonyId: z.string().uuid(),
  response: authenticationResponseSchema,
}).strict();

export function asRegistrationResponse(value: z.infer<typeof registrationResponseSchema>): RegistrationResponseJSON {
  return value as RegistrationResponseJSON;
}

export function asAuthenticationResponse(value: z.infer<typeof authenticationResponseSchema>): AuthenticationResponseJSON {
  return value as AuthenticationResponseJSON;
}

export function hashStepUpOperation(
  purpose: StepUpPurpose,
  method: string,
  path: string,
  body: unknown,
): string {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    throw new ApiError(400, "STEP_UP_OPERATION_INVALID", "Step-up supports state-changing HTTP methods only");
  }
  if (!/^\/v1\/[A-Za-z0-9/_-]+$/u.test(path)) {
    throw new ApiError(400, "STEP_UP_OPERATION_INVALID", "Step-up path is not canonical");
  }
  const canonical = stableJson({
    version: 1,
    purpose,
    method,
    path,
    body: body ?? null,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Readonly<Record<string, unknown>>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

/** Compare a client-supplied WebAuthn challenge with a stored digest only. */
export function challengeMatchesDigest(candidate: string, expectedSha256: string): boolean {
  if (!/^[0-9a-f]{64}$/u.test(expectedSha256)) return false;
  const actual = createHash("sha256").update(candidate, "utf8").digest();
  const expected = Buffer.from(expectedSha256, "hex");
  return actual.byteLength === expected.byteLength && timingSafeEqual(actual, expected);
}

export function requireExactWebAuthnOrigin(
  origin: string | undefined,
  expectedOrigins: readonly string[],
): string {
  if (!origin || !expectedOrigins.includes(origin)) {
    throw new ApiError(403, "WEBAUTHN_ORIGIN_DENIED", "WebAuthn requires an explicitly allowed browser origin");
  }
  return origin;
}
