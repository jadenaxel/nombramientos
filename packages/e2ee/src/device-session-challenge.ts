import { assertCustodianPrivateKey, assertCustodianPublicKey } from "./keys.js";
import type { CustodianPrivateKey, CustodianPublicKey } from "./keys.js";
import { hpkeSuite } from "./suite.js";
import { canonicalize, decodeBase64Url, encodeBase64Url, utf8 } from "./internal.js";
import { E2eeError } from "./errors.js";

/** RFC 9180 HPKE with a purpose separate from grants, ballots and recovery. */
const INFO = utf8("NOMBRAMIENTOS-E2EE\u0000device-session-enrollment\u0000v1");
export interface DeviceSessionEnrollmentContext {
  readonly purpose: "nombramientos.device-session-enrollment";
  readonly version: 1;
  readonly challengeId: string;
  readonly tenantId: string;
  readonly identityId: string;
  readonly sessionId: string;
  readonly sourceSessionId: string | null;
  readonly deviceId: string;
  readonly signingFingerprint: string;
  readonly expiresAt: string;
}
export interface DeviceSessionEncryptedChallenge {
  readonly context: DeviceSessionEnrollmentContext;
  readonly enc: string;
  readonly ciphertext: string;
}
export async function sealDeviceSessionChallenge(input: {
  readonly recipient: CustodianPublicKey;
  readonly context: DeviceSessionEnrollmentContext;
  readonly secret: Uint8Array<ArrayBuffer>;
}): Promise<DeviceSessionEncryptedChallenge> {
  await assertCustodianPublicKey(input.recipient);
  assertContext(input.context);
  if (input.secret.byteLength !== 32) throw new E2eeError("INVALID_KEY", "Invalid device enrollment challenge");
  const sealed = await hpkeSuite.seal(
    { recipientPublicKey: input.recipient.publicKey, info: INFO },
    input.secret,
    utf8(canonicalize(input.context)),
  );
  return { context: input.context, enc: encodeBase64Url(sealed.enc), ciphertext: encodeBase64Url(sealed.ct) };
}
export async function openDeviceSessionChallenge(input: {
  readonly recipient: CustodianPrivateKey;
  readonly challenge: DeviceSessionEncryptedChallenge;
  readonly expected: DeviceSessionEnrollmentContext;
  /** Authoritative server-issued time for browsers with a skewed clock. The
   * server always enforces the stored nonce expiration independently. */
  readonly nowMs?: number;
}): Promise<Uint8Array<ArrayBuffer>> {
  assertContext(input.expected);
  assertContext(input.challenge.context);
  if (canonicalize(input.challenge.context) !== canonicalize(input.expected)
      || input.recipient.recipientId !== `tenant:${input.expected.tenantId}:device:${input.expected.deviceId}`
      || !Number.isFinite(input.nowMs ?? Date.now())
      || Date.parse(input.expected.expiresAt) <= (input.nowMs ?? Date.now())) {
    throw new E2eeError("INVALID_KEY", "Device enrollment context does not match");
  }
  await assertCustodianPrivateKey(input.recipient);
  const opened = new Uint8Array(await hpkeSuite.open(
    { recipientKey: input.recipient.keyPair, enc: decodeBase64Url(input.challenge.enc,"enc","INVALID_ENVELOPE",hpkeSuite.kem.encSize), info: INFO },
    decodeBase64Url(input.challenge.ciphertext,"ciphertext","INVALID_ENVELOPE",48),
    utf8(canonicalize(input.expected)),
  ));
  if (opened.byteLength !== 32) {
    opened.fill(0);
    throw new E2eeError("INVALID_KEY", "Invalid device enrollment challenge");
  }
  return opened;
}
function assertContext(context: DeviceSessionEnrollmentContext): void {
  if (context.purpose !== "nombramientos.device-session-enrollment" || context.version !== 1
      || !/^sha256:[a-f0-9]{64}$/u.test(context.signingFingerprint)
      || !Number.isFinite(Date.parse(context.expiresAt))) {
    throw new E2eeError("INVALID_KEY", "Invalid device enrollment context");
  }
  for (const id of [context.challengeId, context.tenantId, context.identityId, context.sessionId, context.deviceId,
    ...(context.sourceSessionId === null ? [] : [context.sourceSessionId])]) {
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(id)) {
      throw new E2eeError("INVALID_KEY", "Invalid device enrollment context");
    }
  }
}
