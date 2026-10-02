export const REQUEST_TIMEOUT_MS = 30_000;
export const TRANSFER_TIMEOUT_MS = 120_000;

export class RequestInterruptedError extends Error {
  public readonly code: "REQUEST_TIMEOUT" | "REQUEST_CANCELLED";
  constructor(code: "REQUEST_TIMEOUT" | "REQUEST_CANCELLED") {
    super(code);
    this.name = "RequestInterruptedError";
    this.code = code;
  }
}

/** Covers both headers and response body; always detaches the caller's listener. */
export async function withRequestDeadline<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  options: { signal?: AbortSignal | null; timeoutMs?: number } = {},
): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onCancel: (() => void) | undefined;
  const interrupted = new Promise<never>((_resolve, reject) => {
    const stop = (code: RequestInterruptedError["code"]) => {
      const error = new RequestInterruptedError(code);
      controller.abort(error);
      reject(error);
    };
    onCancel = () => stop("REQUEST_CANCELLED");
    if (options.signal?.aborted) {
      onCancel();
      return;
    }
    options.signal?.addEventListener("abort", onCancel, { once: true });
    timer = setTimeout(() => stop("REQUEST_TIMEOUT"), options.timeoutMs ?? REQUEST_TIMEOUT_MS);
  });
  try {
    // Do not send an already cancelled request. Race also bounds a stalled body.
    return await Promise.race([
      controller.signal.aborted ? interrupted : operation(controller.signal),
      interrupted,
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (onCancel) options.signal?.removeEventListener("abort", onCancel);
  }
}
