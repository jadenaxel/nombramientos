import assert from "node:assert/strict";
import test from "node:test";
import { api, ApiError, apiRequest, openDeviceEventStream, setCsrfToken } from "./api.ts";
import { activateDeviceSigner, createLocalDeviceSigner, setDeviceProofContext } from "./device-session-proof.ts";
import { RequestInterruptedError, withRequestDeadline } from "./request-deadline.ts";
import { keyLifecycleApi } from "./key-lifecycle-client.ts";

test("deadline bounds a stalled response and aborts transport", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let signal: AbortSignal | undefined;
  const request = withRequestDeadline(async (value) => { signal = value; return new Promise(() => {}); });
  const outcome = assert.rejects(request, (error) => error instanceof RequestInterruptedError && error.code === "REQUEST_TIMEOUT");
  context.mock.timers.tick(30_000);
  await outcome;
  assert.equal(signal?.aborted, true);
});

test("caller cancellation propagates and detaches its listener", async (context) => {
  const controller = new AbortController();
  const remove = context.mock.method(controller.signal, "removeEventListener");
  let signal: AbortSignal | undefined;
  const request = withRequestDeadline(async (value) => { signal = value; return new Promise(() => {}); }, { signal: controller.signal });
  const outcome = assert.rejects(request, (error) => error instanceof RequestInterruptedError && error.code === "REQUEST_CANCELLED");
  controller.abort();
  await outcome;
  assert.equal(signal?.aborted, true);
  assert.equal(remove.mock.calls.length, 1);
});

test("already cancelled requests never send and completed requests clear deadline", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  await assert.rejects(withRequestDeadline(async () => { calls++; return 1; }, { signal: controller.signal }), RequestInterruptedError);
  assert.equal(calls, 0);
  let signal: AbortSignal | undefined;
  assert.equal(await withRequestDeadline(async (value) => { signal = value; return 2; }), 2);
  context.mock.timers.tick(120_000);
  assert.equal(signal?.aborted, false);
});

test("API retains Headers, CSRF, logical idempotency and server errors without retries", async (context) => {
  let captured: RequestInit | undefined;
  const fetch = context.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => {
    captured = init;
    return new Response(JSON.stringify({ error: { code: "VERSION_CONFLICT", message: "conflict" } }), { status: 409, headers: { "x-request-id": "fixture-request" } });
  });
  setCsrfToken("fixture-csrf");
  try {
    await assert.rejects(apiRequest("/fixture", { method: "POST", body: "{}", headers: new Headers({ "x-fixture": "yes" }), idempotent: true, idempotencyKey: "fixture-operation" }),
      (error) => error instanceof ApiError && error.status === 409 && error.requestId === "fixture-request");
    const headers = new Headers(captured?.headers);
    assert.equal(headers.get("x-fixture"), "yes");
    assert.equal(headers.get("x-csrf-token"), "fixture-csrf");
    assert.equal(headers.get("idempotency-key"), "fixture-operation");
    assert.equal(fetch.mock.calls.length, 1);
  } finally { setCsrfToken(undefined); }
});

test("federated protected requests do not send unsigned while the session/device fence is initializing", async (context) => {
  const originalIdentityProvider = process.env.NEXT_PUBLIC_GESTIONCHURCH_URL;
  process.env.NEXT_PUBLIC_GESTIONCHURCH_URL = "https://synthetic-identity-provider.example";
  setDeviceProofContext(undefined);
  const fetch = context.mock.method(globalThis, "fetch", async () => new Response());
  try {
    await assert.rejects(apiRequest("/v1/memberships"), (error) => error instanceof ApiError
      && error.status === 428 && error.code === "DEVICE_SESSION_ENROLLMENT_REQUIRED");
    assert.equal(fetch.mock.calls.length, 0, "the guarded background query must not cause a server 401/SSO loop");
  } finally {
    if (originalIdentityProvider === undefined) delete process.env.NEXT_PUBLIC_GESTIONCHURCH_URL;
    else process.env.NEXT_PUBLIC_GESTIONCHURCH_URL = originalIdentityProvider;
    setDeviceProofContext(undefined);
  }
});

test("stalled response bodies time out with an uncertain mutation, without resubmission", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const fetch = context.mock.method(globalThis, "fetch", async () => ({ ok: true, status: 200, headers: new Headers(), json: () => new Promise(() => {}) }) as Response);
  const request = apiRequest("/fixture", { method: "POST", body: "{}", idempotent: true });
  const outcome = assert.rejects(request, (error) => error instanceof ApiError && error.code === "REQUEST_TIMEOUT_UNCERTAIN");
  context.mock.timers.tick(30_000);
  await outcome;
  assert.equal(fetch.mock.calls.length, 1);
});

test("multipart gets 120 seconds and leaves the boundary to the browser", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let captured: RequestInit | undefined;
  context.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => { captured = init; return new Promise<Response>(() => {}); });
  const request = apiRequest("/fixture", { method: "POST", body: new FormData() });
  const outcome = assert.rejects(request, (error) => error instanceof ApiError && error.code === "REQUEST_TIMEOUT_UNCERTAIN");
  context.mock.timers.tick(30_000);
  assert.equal(captured?.signal?.aborted, false);
  assert.equal(new Headers(captured?.headers).has("content-type"), false);
  context.mock.timers.tick(90_000);
  await outcome;
});

test("already serialized multipart retains its transfer deadline and prepared content type", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let captured: RequestInit | undefined;
  context.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => { captured = init; return new Promise<Response>(() => {}); });
  const contentType = "multipart/form-data; boundary=synthetic-retry-boundary";
  const transfer = apiRequest("/fixture", { method: "POST", body: new ArrayBuffer(0), headers: new Headers({ "content-type": contentType }) });
  const outcome = assert.rejects(transfer, (error) => error instanceof ApiError && error.code === "REQUEST_TIMEOUT_UNCERTAIN");
  context.mock.timers.tick(30_000);
  assert.equal(captured?.signal?.aborted, false);
  assert.equal(new Headers(captured?.headers).get("content-type"), contentType);
  context.mock.timers.tick(90_000);
  await outcome;
});

test("API cancellation reports uncertainty for a write and no fetch for pre-cancellation", async (context) => {
  const controller = new AbortController();
  controller.abort();
  const fetch = context.mock.method(globalThis, "fetch", async () => new Response());
  await assert.rejects(apiRequest("/fixture", { method: "PATCH", signal: controller.signal }),
    (error) => error instanceof ApiError && error.code === "REQUEST_CANCELLED_UNCERTAIN");
  assert.equal(fetch.mock.calls.length, 0);
});

test("network loss and malformed success never assert that a write did not commit", async (context) => {
  const fetch = context.mock.method(globalThis, "fetch", async () => { throw new TypeError("synthetic lost response"); });
  await assert.rejects(apiRequest("/fixture", { method: "POST" }), (error) => error instanceof ApiError && error.code === "NETWORK_ERROR_UNCERTAIN");
  assert.equal(fetch.mock.calls.length, 1);
  fetch.mock.mockImplementation(async () => new Response("{}", { status: 200 }));
  await assert.rejects(apiRequest("/fixture", { method: "POST" }), (error) => error instanceof ApiError && error.code === "INVALID_RESPONSE_UNCERTAIN");
});

test("key lifecycle never resubmits an uncertain malformed mutation response", async (context) => {
  const fetch = context.mock.method(globalThis, "fetch", async (url: RequestInfo | URL) => new Response(JSON.stringify(
    String(url).endsWith("/challenges") ? { data: { challengeId: "11111111-1111-4111-8111-111111111111", expiresAt: new Date().toISOString() } } : {},
  ), { status: 200 }));
  await assert.rejects(keyLifecycleApi.mutate("key.declare_lost", {
    tenantKeyId: "synthetic-key", confirmation: "PERMANENTLY_LOSE_TENANT_KEY", reasonCode: "SYNTHETIC_FIXTURE",
  }), (error) => error instanceof ApiError && error.code === "INVALID_RESPONSE_UNCERTAIN");
  assert.equal(fetch.mock.calls.length, 2, "one challenge plus one mutation; no automatic replay");
});

test("SSE deadline includes stalled proof preparation and never sends the protected stream", async (context) => {
  const scope = { sessionId: "synthetic-session", tenantId: "synthetic-tenant", identityId: "synthetic-identity" };
  const signer = await createLocalDeviceSigner({ ...scope, deviceId: "synthetic-device" });
  activateDeviceSigner(scope, signer);
  context.mock.method(crypto.subtle, "digest", async () => new Promise<ArrayBuffer>(() => {}));
  const fetch = context.mock.method(globalThis, "fetch", async () => new Response());
  context.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const stream = openDeviceEventStream("/v1/events", new AbortController().signal);
    const outcome = assert.rejects(stream, (error) => error instanceof ApiError && error.code === "REQUEST_TIMEOUT");
    context.mock.timers.tick(30_000);
    await outcome;
    assert.equal(fetch.mock.calls.length, 0);
  } finally { setDeviceProofContext(undefined); }
});

test("SSE retains parent cancellation after headers complete and its deadline timer is removed", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const parent = new AbortController();
  let transportSignal: AbortSignal | undefined;
  context.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => {
    transportSignal = init?.signal ?? undefined;
    return new Response(new ReadableStream({ start() {} }), { headers: { "content-type": "text/event-stream" } });
  });
  await openDeviceEventStream("/v1/events", parent.signal);
  context.mock.timers.tick(30_000);
  assert.equal(transportSignal?.aborted, false);
  parent.abort();
  assert.equal(transportSignal?.aborted, true);
});

test("binary download deadline includes its body and never blindly resubmits", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const fetch = context.mock.method(globalThis, "fetch", async () => ({ ok: true, headers: new Headers(), blob: () => new Promise(() => {}) }) as Response);
  const transfer = api.downloadTenantExport("synthetic-tenant", "synthetic-export", "synthetic-authorization");
  const outcome = assert.rejects(transfer, (error) => error instanceof ApiError && error.code === "REQUEST_TIMEOUT_UNCERTAIN");
  context.mock.timers.tick(120_000);
  await outcome;
  assert.equal(fetch.mock.calls.length, 1);
});
