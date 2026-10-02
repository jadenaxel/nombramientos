import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import {
  activateDeviceSigner, createLocalDeviceSigner, currentDeviceSigner, deviceRequestRequiresProof,
  deviceRequestRetryHeaders,
  hashDeviceRequestBody, setDeviceProofContext, signDeviceClaims, validateDeviceRequestClaims, type DeviceRequestClaims,
} from "./device-session-proof.ts";
import { takeSseEvents, consumeDeviceEventStream } from "./device-event-stream.ts";
import { sessionTimeRemaining } from "./session-clock.ts";
import { deviceWorkspaceReady } from "./device-session-readiness.ts";
import type { AuthenticatedSession } from "./api.ts";
import type { DeviceSessionState } from "./device-session-client.ts";

const context = { sessionId: "00000000-0000-4000-8000-000000000001", tenantId: "00000000-0000-4000-8000-000000000002", identityId: "00000000-0000-4000-8000-000000000003" };
const deviceId = "00000000-0000-4000-8000-000000000004";

test("device signer is separate, nonextractable and produces 64-byte ES256 JWS signatures", async () => {
  const signer = await createLocalDeviceSigner({ ...context, deviceId });
  assert.equal(signer.privateKey.extractable, false);
  assert.deepEqual(signer.privateKey.usages, ["sign"]);
  await assert.rejects(crypto.subtle.exportKey("jwk", signer.privateKey));
  const token = await signDeviceClaims(signer, { purpose: "test", tenantId: context.tenantId });
  const [header, payload, signature] = token.split(".");
  assert.equal(Buffer.from(signature!, "base64url").length, 64);
  assert.equal(JSON.parse(Buffer.from(header!, "base64url").toString()).typ, "dpop+jwt");
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, signer.publicKey, Buffer.from(signature!, "base64url"), new TextEncoder().encode(`${header}.${payload}`)), true);
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, signer.publicKey, Buffer.from(signature!, "base64url"), new TextEncoder().encode(`${header}.${payload}x`)), false);
});

test("request hashes exact transfer bytes, including empty reads and JSON whitespace", async () => {
  assert.equal(await hashDeviceRequestBody(undefined), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.notEqual(await hashDeviceRequestBody('{"a":1}'), await hashDeviceRequestBody('{ "a":1 }'));
  assert.equal(await hashDeviceRequestBody("é"), await hashDeviceRequestBody(new TextEncoder().encode("é")));
});

test("client refuses to sign server claims substituted across every request and context component", async () => {
  const signer = await createLocalDeviceSigner({ ...context, deviceId });
  const claims: DeviceRequestClaims = { purpose: "nombramientos.device-session-request", version: 1, ...context, sourceSessionId: null, deviceId,
    signingFingerprint: signer.fingerprint, htm: "PATCH", path: "/v1/members/a", htu: "https://api.example.org/v1/members/a",
    bodyHash: await hashDeviceRequestBody("{}"), idempotencyKey: "logical-key", iat: 1_000, nonce: "n".repeat(43), jti: "challenge-id-123456" };
  const input = { claims, signer, context, publicJwk: signer.publicJwk, method: claims.htm, path: claims.path, url: claims.htu,
    bodyHash: claims.bodyHash, idempotencyKey: claims.idempotencyKey, issuedAt: 1_000 };
  assert.doesNotThrow(() => validateDeviceRequestClaims(input));
  for (const [field, value] of Object.entries({ sessionId: "other", sourceSessionId: "other", tenantId: "other", identityId: "other", deviceId: "other", signingFingerprint: "other", htm: "POST", path: "/v1/members/b", htu: "https://other.example.org/v1/members/a", bodyHash: "changed", idempotencyKey: "other", nonce: "short", jti: "short", iat: 1_200 })) {
    assert.throws(() => validateDeviceRequestClaims({ ...input, claims: { ...claims, [field]: value } }), /DEVICE_SESSION_CONTEXT_MISMATCH/u, field);
  }
  assert.throws(() => validateDeviceRequestClaims({ ...input, publicJwk: { ...signer.publicJwk, x: "other" } }), /DEVICE_SESSION_CONTEXT_MISMATCH/u);
});

test("session/tenant switches clear only volatile signer association, not persisted historical keys", async () => {
  const signer = await createLocalDeviceSigner({ ...context, deviceId });
  activateDeviceSigner(context, signer);
  assert.equal(currentDeviceSigner(), signer);
  setDeviceProofContext({ ...context });
  assert.equal(currentDeviceSigner(), signer);
  setDeviceProofContext({ ...context, sourceSessionId: "changed-source" });
  assert.equal(currentDeviceSigner(), undefined);
  activateDeviceSigner(context, signer);
  setDeviceProofContext({ ...context, sessionId: "next" });
  assert.equal(currentDeviceSigner(), undefined);
  assert.throws(() => activateDeviceSigner({ ...context, tenantId: "other" }, signer));
  setDeviceProofContext(undefined);
});

test("proof timestamps follow the authoritative nonce issue time, not a skewed mobile clock", async (testContext) => {
  const signer = await createLocalDeviceSigner({ ...context, deviceId });
  const claims: DeviceRequestClaims = { purpose: "nombramientos.device-session-request", version: 1, ...context, sourceSessionId: null,
    deviceId, signingFingerprint: signer.fingerprint, htm: "GET", path: "/v1/cycles", htu: "https://api.example.org/v1/cycles",
    bodyHash: await hashDeviceRequestBody(undefined), idempotencyKey: "", iat: 1_000, nonce: "n".repeat(43), jti: "challenge-id-123456" };
  const input = { claims, signer, context, publicJwk: signer.publicJwk, method: "GET", path: claims.path, url: claims.htu,
    bodyHash: claims.bodyHash, idempotencyKey: "", issuedAt: 1_000 };
  testContext.mock.method(Date, "now", () => Date.UTC(2050, 0, 1));
  assert.doesNotThrow(() => validateDeviceRequestClaims(input));
  assert.throws(() => validateDeviceRequestClaims({ ...input, issuedAt: 1_001 }), /DEVICE_SESSION_CONTEXT_MISMATCH/u);
});

test("real tenant reads/writes/SSE require proof; only explicit identity bootstrap and platform plane are exempt", () => {
  for (const path of ["/v1/members", "/v1/access/roles", "/v1/events?tenantId=a", "/v1/cycles", "/v1/auth/sessions"]) assert.equal(deviceRequestRequiresProof(path, "GET"), true, path);
  assert.equal(deviceRequestRequiresProof("/v1/key-lifecycle/grants", "POST"), true);
  for (const path of ["/v1/session", "/v1/device-session", "/v1/key-lifecycle", "/v1/platform/tenants"]) assert.equal(deviceRequestRequiresProof(path, "GET"), false, path);
  assert.equal(deviceRequestRequiresProof("/v1/key-lifecycle/challenges", "POST"), false);
  assert.equal(deviceRequestRequiresProof("/v1/device-session-unknown", "GET"), true);
  assert.equal(deviceRequestRequiresProof("/v1/device-session/proofs", "GET"), true);
  assert.equal(deviceRequestRequiresProof("/v1/auth/logout", "DELETE"), true);
  assert.equal(deviceRequestRequiresProof("/v1/key-lifecycle/grants/revoke", "POST"), true);
});

test("signed SSE parser preserves ready/phase events across chunks and bounds incomplete frames", async () => {
  assert.deepEqual(takeSseEvents(": heartbeat\n\nevent: ready\r\ndata: {}\r\n\r\nevent: round.phase\n"), { events: ["ready"], remainder: "event: round.phase\n" });
  assert.throws(() => takeSseEvents("x".repeat(65_537)), /EVENT_STREAM_FRAME_TOO_LARGE/u);
  assert.throws(() => takeSseEvents("x".repeat(65_537) + "\n\n"), /EVENT_STREAM_FRAME_TOO_LARGE/u);
  const events: string[] = [];
  const body = new ReadableStream({ start(controller) { for (const part of ["event: re", "ady\ndata: {}\n\nevent: round.part", "icipation\ndata: {}\n\n"]) controller.enqueue(new TextEncoder().encode(part)); controller.close(); } });
  await consumeDeviceEventStream(new Response(body, { headers: { "content-type": "text/event-stream" } }), (event) => events.push(event), new AbortController().signal);
  assert.deepEqual(events, ["ready", "round.participation"]);
});

test("enrollment preserves wrapping keys and never signs or stores bearer secrets in URLs/browser string storage", () => {
  const client = readFileSync(new URL("./device-session-client.ts", import.meta.url), "utf8");
  const proof = readFileSync(new URL("./device-session-proof.ts", import.meta.url), "utf8");
  const stream = readFileSync(new URL("../components/nombramientos/round-view.tsx", import.meta.url), "utf8");
  assert.match(client, /openDeviceSessionChallenge/u);
  assert.match(client, /secret\.fill\(0\)/u);
  assert.match(proof, /privateKey\.extractable/u);
  assert.match(proof, /store\.add\(signer/u);
  assert.doesNotMatch(proof, /store\.put/u);
  assert.doesNotMatch(`${proof}${client}`, /localStorage|sessionStorage|exportKey\("(?:pkcs8|raw)"/u);
  assert.match(stream, /openDeviceEventStream/u);
  assert.doesNotMatch(stream, /new EventSource|device-proof=/u);
});

test("pending browsers cannot render workspace data or active custody administration", () => {
  const boundary = readFileSync(new URL("../components/nombramientos/device-session-boundary.tsx", import.meta.url), "utf8");
  const custody = readFileSync(new URL("../components/nombramientos/key-lifecycle-view.tsx", import.meta.url), "utf8");
  assert.match(boundary, /query\.workspaceReady\) return children/u);
  assert.match(boundary, /permissions\.includes\("recovery\.activate"\)[^\n]*pendingDeviceOnly/u);
  assert.match(custody, /canManageDevices = canManage && !pendingDeviceOnly/u);
  assert.match(custody, /canManageDevices && pendingDevices/u);
  assert.match(custody, /!pendingDeviceOnly && state\.devices[^\n]*<DeviceSessionsPanel/u);
  assert.match(custody, /grant\.deviceId === currentDeviceSigner\(\)\?\.deviceId[^\n]*vault\.lock\(\)/u);
});

test("sidebar and workspace defer protected requests until the exact current HTTP session is proven", async () => {
  const signer = await createLocalDeviceSigner({ ...context, deviceId });
  const session = { sessionId: context.sessionId, tenant: { id: context.tenantId }, user: { id: context.identityId } } as AuthenticatedSession;
  const state = { session: { ...context, sourceSessionId: null }, enrollmentRequired: false,
    binding: { sessionId: context.sessionId, sourceSessionId: null, deviceId, identityId: context.identityId,
      signingFingerprint: signer.fingerprint, publicJwk: signer.publicJwk, boundAt: "", lastSeenAt: "", status: "active",
      deviceStatus: "active", hasActiveGrant: true } } satisfies DeviceSessionState;
  setDeviceProofContext(undefined);
  assert.equal(deviceWorkspaceReady(session, state, true), false);
  activateDeviceSigner({ ...context, sourceSessionId: null }, signer);
  try {
    assert.equal(deviceWorkspaceReady(session, state, true), true);
    assert.equal(deviceWorkspaceReady({ ...session, sessionId: "new-session" }, state, true), false);
    assert.equal(deviceWorkspaceReady(session, { ...state, binding: { ...state.binding, hasActiveGrant: false } }, true), false);
    assert.equal(deviceWorkspaceReady(session, { ...state, binding: { ...state.binding, deviceStatus: "pending" } }, true), false);
    assert.equal(deviceWorkspaceReady(session, state, false), false);
    const sidebar = readFileSync(new URL("../components/nombramientos/tenant-switcher.tsx", import.meta.url), "utf8");
    const shared = readFileSync(new URL("./device-session-readiness.ts", import.meta.url), "utf8");
    assert.match(sidebar, /enabled: session\.tenant\.kind !== "real" \|\| deviceReady/u);
    assert.match(shared, /queryKey: \["device-session", session\?\.tenant\.id, session\?\.user\.id, session\?\.sessionId\]/u);
  } finally { setDeviceProofContext(undefined); }
});

test("routine route cleanup preserves a recognized session while explicit identity loss still clears it", () => {
  const shell = readFileSync(new URL("../components/nombramientos/app-shell.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(shell, /setCsrfToken\(session\?\.csrfToken\);\s*return \(\) => setCsrfToken\(undefined\)/u);
  assert.match(shell, /lockVault\(\);\s*setCsrfToken\(undefined\);\s*void queryClient\.cancelQueries\(\)/u);
  assert.match(shell, /async function signOut\(\)[\s\S]*?finally[\s\S]*?vault\.lock\(\); setCsrfToken\(undefined\); queryClient\.clear\(\)/u);
  const switcher = readFileSync(new URL("../components/nombramientos/tenant-switcher.tsx", import.meta.url), "utf8");
  assert.match(switcher, /vault\.lock\(\);\s*setCsrfToken\(undefined\);\s*queryClient\.clear\(\)/u);
});

test("translated header controls retain their actions and reflow without crushing the compact church identity", () => {
  const shell = readFileSync(new URL("../components/nombramientos/app-shell.tsx", import.meta.url), "utf8");
  const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(shell, /topbar-compact-brand lg:hidden/u);
  assert.match(shell, /topbar-actions ml-auto flex items-center gap-2/u);
  assert.match(css, /\.session-topbar\{height:auto;min-height:72px/u);
  assert.match(css, /\.topbar-compact-brand\{min-width:84px/u);
  assert.match(css, /\.topbar-actions\{min-width:0;[^}]*flex-wrap:wrap/u);
  const responsive = readFileSync(new URL("../app/responsive.css", import.meta.url), "utf8");
  assert.match(responsive, /\.topbar\.session-topbar \{ display: grid; grid-template-columns: 44px minmax\(0,1fr\)/u);
  assert.match(responsive, /\.topbar\.session-topbar > \.topbar-actions \{[^}]*grid-column: 1\/-1;[^}]*flex-shrink: 1/u);
  assert.match(shell, /aria-label=\{message\(locale, "shell.returnToGestionChurch"\)\}/u);
});

test("prepared multipart retry keeps its exact boundary and logical operation, but drops the consumed proof", () => {
  const prepared = new Headers({ "content-type": "multipart/form-data; boundary=synthetic-fixed-boundary",
    "x-csrf-token": "synthetic-csrf", "idempotency-key": "synthetic-logical-key", "x-device-proof": "already-consumed" });
  const retry = deviceRequestRetryHeaders(prepared);
  assert.equal(retry.get("content-type"), prepared.get("content-type"));
  assert.equal(retry.get("x-csrf-token"), "synthetic-csrf");
  assert.equal(retry.get("idempotency-key"), "synthetic-logical-key");
  assert.equal(retry.has("x-device-proof"), false);
  assert.equal(prepared.get("x-device-proof"), "already-consumed");
  const api = readFileSync(new URL("./api.ts", import.meta.url), "utf8");
  assert.match(api, /const retryHeaders = deviceRequestRetryHeaders\(headers\)/u);
});

test("focused page controls use the measured translated header height without clipping or changing session cleanup", () => {
  const shell = readFileSync(new URL("../components/nombramientos/app-shell.tsx", import.meta.url), "utf8");
  const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(shell, /function SessionTopbar/u);
  assert.match(shell, /useLayoutEffect\(\(\) => \{[\s\S]*?measure\(\);[\s\S]*?new ResizeObserver\(measure\)/u);
  assert.match(shell, /observer\.observe\(header\)/u);
  assert.match(shell, /observer\.disconnect\(\)/u);
  assert.match(shell, /if \(previous\) root\.style\.setProperty\(property, previous, priority\)/u);
  assert.match(css, /html:has\(\.session-topbar\) \{ scroll-padding-top: var\(--session-header-scroll-offset, 84px\)/u);
  assert.doesNotMatch(css, /html:has\(\.session-topbar\)[^}]*overflow[^}]*hidden/u);
  const panel = readFileSync(new URL("../components/nombramientos/device-sessions-panel.tsx", import.meta.url), "utf8");
  const boundary = readFileSync(new URL("../components/nombramientos/device-session-boundary.tsx", import.meta.url), "utf8");
  assert.match(panel, /className="session-refresh-control shrink-0 whitespace-nowrap"[^>]*onClick=\{\(\) => void query\.refetch\(\)\}/u);
  assert.match(css, /#tenant-key-lifecycle \.session-refresh-control\[data-slot=button\]\{flex-shrink:0;white-space:nowrap;overflow-wrap:normal\}/u);
  assert.match(boundary, /AlertTitle className="line-clamp-none whitespace-normal leading-6">\{message\(locale, "deviceSession.pendingTitle"\)/u);
});

test("client session countdown uses server time and monotonic elapsed time without extending server expiry", () => {
  const session = { serverTime: "2026-10-02T12:00:00Z", expiresAt: "2026-10-02T13:00:00Z", receivedAtMonotonic: 10 };
  for (const wallNow of [Date.UTC(2026, 9, 1), Date.UTC(2026, 9, 3), Date.UTC(2050, 0, 1)]) {
    assert.equal(sessionTimeRemaining(session, { wallNow, monotonicNow: 10 }), 3_600_000);
    assert.equal(sessionTimeRemaining(session, { wallNow, monotonicNow: 3_600_010 }), 0);
  }
  assert.equal(sessionTimeRemaining({ ...session, expiresAt: "invalid" }), 0);
  assert.equal(sessionTimeRemaining({ expiresAt: session.expiresAt }, { wallNow: Date.UTC(2026, 9, 2, 12) }), 3_600_000);
  const shell = readFileSync(new URL("../components/nombramientos/app-shell.tsx", import.meta.url), "utf8");
  const client = readFileSync(new URL("./device-session-client.ts", import.meta.url), "utf8");
  assert.match(shell, /sessionTimeRemaining\(session\)/u);
  assert.match(client, /state\.binding\.sourceSessionId !== state\.session\.sourceSessionId/u);
});
