import type { MfaEnrollmentStarted } from "./api.ts";

const expectedParameters = new Set(["algorithm", "digits", "issuer", "period", "secret"]);
const base32Secret = /^[A-Z2-7]{16,128}$/u;

/**
 * Treat the enrollment URI as untrusted server input before giving it to a QR
 * encoder, the clipboard, or an external protocol handler. The returned value
 * is the original URI only when it describes the exact TOTP contract shown in
 * the UI and contains no alternate authority or hidden parameter channel.
 */
export function validatedTotpEnrollmentUri(enrollment: MfaEnrollmentStarted): string | undefined {
  const candidate = enrollment.otpauthUri;
  if (
    candidate.length < 1
    || candidate.length > 2_048
    || /[\u0000-\u001f\u007f]/u.test(candidate)
    || !base32Secret.test(enrollment.secret)
    || enrollment.algorithm !== "SHA1"
    || enrollment.digits !== 6
    || enrollment.period !== 30
  ) return undefined;

  let uri: URL;
  try {
    uri = new URL(candidate);
  } catch {
    return undefined;
  }
  if (
    uri.protocol !== "otpauth:"
    || uri.hostname !== "totp"
    || uri.username !== ""
    || uri.password !== ""
    || uri.port !== ""
    || uri.hash !== ""
    || !uri.pathname.startsWith("/")
  ) return undefined;

  let label: string;
  try {
    label = decodeURIComponent(uri.pathname.slice(1));
  } catch {
    return undefined;
  }
  if (!label.includes(":") || label.length > 512 || /[\/\\\u0000-\u001f\u007f]/u.test(label)) return undefined;

  const entries = [...uri.searchParams.entries()];
  const keys = entries.map(([key]) => key);
  if (
    entries.length !== expectedParameters.size
    || new Set(keys).size !== expectedParameters.size
    || keys.some((key) => !expectedParameters.has(key))
    || uri.searchParams.get("secret") !== enrollment.secret
    || uri.searchParams.get("issuer") !== "Nombramientos"
    || uri.searchParams.get("algorithm") !== "SHA1"
    || uri.searchParams.get("digits") !== "6"
    || uri.searchParams.get("period") !== "30"
  ) return undefined;

  return candidate;
}
