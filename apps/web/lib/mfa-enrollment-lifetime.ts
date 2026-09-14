export function scheduleMfaEnrollmentExpiry(
  expiresAt: string,
  onExpire: () => void,
  now = Date.now(),
): () => void {
  const parsedExpiry = Date.parse(expiresAt);
  const remaining = parsedExpiry - now;
  if (!Number.isFinite(parsedExpiry) || remaining <= 0) {
    onExpire();
    return () => undefined;
  }
  const timer = setTimeout(onExpire, remaining);
  return () => clearTimeout(timer);
}
