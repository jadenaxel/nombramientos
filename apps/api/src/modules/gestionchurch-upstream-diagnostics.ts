/** Fixed, minimized connector diagnostics. Never accept request/response objects. */
export type GestionChurchUpstreamOperation = "authorize" | "redeem" | "organization";

export interface GestionChurchRejectionLogger {
  warn(record: {
    readonly event: "gestionchurch.upstream_rejected";
    readonly operation: GestionChurchUpstreamOperation;
    readonly upstreamStatus: number;
    readonly observedAt: string;
  }, message: string): void;
}

export function logGestionChurchUpstreamRejection(
  logger: GestionChurchRejectionLogger | undefined,
  operation: GestionChurchUpstreamOperation,
  upstreamStatus: number,
): void {
  if (!logger || !Number.isInteger(upstreamStatus) || upstreamStatus < 400 || upstreamStatus > 599) return;
  try {
    logger.warn({
      event: "gestionchurch.upstream_rejected",
      operation,
      upstreamStatus,
      observedAt: new Date().toISOString(),
    }, "GestionChurch upstream request rejected");
  } catch {
    // Diagnostics must never replace or relax the original fail-closed denial.
  }
}
