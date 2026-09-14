import { z } from "zod";
import { encryptedEnvelopeSchema } from "../lib/envelopes.js";

export const photoUuidSchema = z.string().uuid();
export const photoSha256Schema = z.string().regex(/^sha256:[0-9a-f]{64}$/);
export const normalizedPhotoMediaTypeSchema = z.literal("image/jpeg");

export const photoPutSchema = z.object({
  photoId: photoUuidSchema,
  expectedVersion: z.number().int().min(0),
  version: z.number().int().positive(),
  mediaType: normalizedPhotoMediaTypeSchema,
  width: z.number().int().min(128).max(1024),
  height: z.number().int().min(128).max(1024),
  plaintextBytes: z.number().int().min(128).max(786_432),
  envelope: encryptedEnvelopeSchema,
  contentHash: photoSha256Schema,
}).strict().superRefine((value, context) => {
  if (value.width !== value.height) {
    context.addIssue({
      code: "custom",
      path: ["height"],
      message: "Normalized photographs must be square",
    });
  }
  if (value.envelope.algorithm !== "AES-256-GCM") {
    context.addIssue({
      code: "custom",
      path: ["envelope", "algorithm"],
      message: "Photographs require AES-256-GCM",
    });
  }
  const cipherBytes = Buffer.from(value.envelope.ciphertext, "base64url").byteLength;
  if (cipherBytes !== value.plaintextBytes + 16) {
    context.addIssue({
      code: "custom",
      path: ["envelope", "ciphertext"],
      message: "Ciphertext length must authenticate exactly the declared normalized image length",
    });
  }
});

export const photoArchiveSchema = z.object({
  expectedVersion: z.number().int().positive(),
}).strict();

export type PhotoPutRequest = z.infer<typeof photoPutSchema>;

export function photoAadContext(input: {
  readonly tenantId: string;
  readonly memberId: string;
  readonly photoId: string;
  readonly version: number;
  readonly mediaType: "image/jpeg";
  readonly width: number;
  readonly height: number;
  readonly plaintextBytes: number;
}): Readonly<Record<string, string | number>> {
  return {
    tenantId: input.tenantId,
    memberId: input.memberId,
    photoId: input.photoId,
    purpose: "member-photo",
    schemaVersion: 1,
    version: input.version,
    mediaType: input.mediaType,
    width: input.width,
    height: input.height,
    plaintextBytes: input.plaintextBytes,
  };
}
