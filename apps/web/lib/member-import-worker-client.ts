import type {
  BuildImportPreviewRequest,
  BuildImportPreviewResult,
  InspectImportFileRequest,
  InspectImportFileResult,
  MemberImportWorkerRequest,
  MemberImportWorkerResponse,
} from "./member-import-worker-protocol";

type PendingRequest = {
  readonly resolve: (value: unknown) => void;
  readonly reject: (reason: Error) => void;
};

export type MemberImportWorkerClient = {
  inspect(
    input: Omit<InspectImportFileRequest, "requestId" | "type">,
  ): Promise<InspectImportFileResult>;
  preview(
    input: Omit<BuildImportPreviewRequest, "requestId" | "type">,
  ): Promise<BuildImportPreviewResult>;
  terminate(): void;
};

export function createMemberImportWorkerClient(): MemberImportWorkerClient {
  const worker = new Worker(new URL("../workers/member-import.worker.ts", import.meta.url), {
    name: "nombramientos-member-import",
    type: "module",
  });
  const pending = new Map<string, PendingRequest>();
  let terminated = false;

  worker.addEventListener("message", (event: MessageEvent<MemberImportWorkerResponse>) => {
    const request = pending.get(event.data.requestId);
    if (!request) return;
    pending.delete(event.data.requestId);
    if (event.data.ok) request.resolve(event.data.result);
    else request.reject(new Error(event.data.message));
  });
  worker.addEventListener("error", () => {
    failPending(new Error("The browser import worker stopped unexpectedly."));
  });
  worker.addEventListener("messageerror", () => {
    failPending(new Error("The browser import worker returned an unreadable result."));
  });

  function failPending(error: Error): void {
    for (const request of pending.values()) request.reject(error);
    pending.clear();
  }

  function request<TResult>(
    value: Omit<MemberImportWorkerRequest, "requestId">,
    transfer: Transferable[] = [],
  ): Promise<TResult> {
    if (terminated) return Promise.reject(new Error("The browser import worker is unavailable."));
    const requestId = crypto.randomUUID();
    return new Promise<TResult>((resolve, reject) => {
      pending.set(requestId, {
        resolve: (result) => resolve(result as TResult),
        reject,
      });
      worker.postMessage({ ...value, requestId } as MemberImportWorkerRequest, transfer);
    });
  }

  return {
    inspect: (input) => request<InspectImportFileResult>({ ...input, type: "inspect" }, [input.bytes]),
    preview: (input) => request<BuildImportPreviewResult>({ ...input, type: "preview" }),
    terminate: () => {
      if (terminated) return;
      terminated = true;
      worker.terminate();
      failPending(new Error("The browser import worker was closed."));
    },
  };
}
