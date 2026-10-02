/** Server expiry remains authoritative. Monotonic elapsed time prevents device
 * wall-clock skew and UI rerenders from extending the client warning timer. */
export function sessionTimeRemaining(session: { expiresAt: string; serverTime?: string; receivedAtMonotonic?: number },
  clock: { wallNow?: number; monotonicNow?: number } = {}): number {
  const expiry = Date.parse(session.expiresAt);
  if (!Number.isFinite(expiry)) return 0;
  const issued = session.serverTime ? Date.parse(session.serverTime) : Number.NaN;
  if (Number.isFinite(issued)) {
    const receipt = session.receivedAtMonotonic;
    const monotonic = clock.monotonicNow ?? performance.now();
    const elapsed = receipt !== undefined && Number.isFinite(receipt) ? Math.max(0, monotonic - receipt) : 0;
    return expiry - issued - elapsed;
  }
  // Compatibility for older/standalone fixtures only. The server independently
  // rejects expired or revoked sessions on every request, including SSE.
  return expiry - (clock.wallNow ?? Date.now());
}
