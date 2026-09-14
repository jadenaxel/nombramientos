import assert from "node:assert/strict";
import test from "node:test";

import {
  api,
  apiRequest,
  ApiError,
  setCsrfToken,
  type AuthenticatedSession,
  type InitialAdminRecoveryRedemption,
} from "./api.ts";
import { redeemInitialAdminRecoverySafely } from "./initial-admin-recovery-browser.ts";

const recoveryId = "93000000-0000-4000-8000-000000000001";
const syntheticToken = "A".repeat(43);

test("prepares the HttpOnly context before first redemption and confirms the installed restricted session", async () => {
  const events: string[] = [];
  const recovered = recoverySession("csrf-recovery-one-0000000001");
  let reads = 0;
  const result = await redeemInitialAdminRecoverySafely(recoveryId, syntheticToken, {
    readSession: async () => {
      events.push("session");
      reads += 1;
      if (reads === 1) throw new ApiError(401, "UNAUTHENTICATED", "Synthetic baseline");
      return recovered;
    },
    prepareContext: async () => { events.push("prepare"); },
    redeem: async (_id, token) => {
      events.push(token ? "redeem:token" : "redeem:context");
      return recovered;
    },
    beforeMutation: () => { events.push("clear-client-context"); },
  });

  assert.equal(result.csrfToken, recovered.csrfToken);
  assert.deepEqual(events, ["session", "clear-client-context", "prepare", "redeem:token", "session"]);
});

test("an uncertain transport repeats the exact bearer before using a context-only repair", async () => {
  const baseline = ordinarySession("csrf-baseline-0000000000001");
  const recovered = recoverySession("csrf-recovery-two-0000000002");
  const calls: Array<string | undefined> = [];
  let reads = 0;
  const result = await redeemInitialAdminRecoverySafely(recoveryId, syntheticToken, {
    readSession: async () => (++reads === 1 ? baseline : recovered),
    prepareContext: async () => {},
    redeem: async (_id, token) => {
      calls.push(token);
      if (calls.length === 1) throw new TypeError("synthetic transport loss");
      return recovered;
    },
    beforeMutation: () => {},
  });

  assert.equal(result.csrfToken, recovered.csrfToken);
  assert.deepEqual(calls, [syntheticToken, syntheticToken]);
});

test("a valid redemption without its cookie performs one bounded context-only repair", async () => {
  const baseline = ordinarySession("csrf-baseline-0000000000002");
  const firstResponse = recoverySession("csrf-response-missing-cookie-1");
  const repaired = recoverySession("csrf-context-repair-000000001");
  const calls: Array<string | undefined> = [];
  let reads = 0;
  const result = await redeemInitialAdminRecoverySafely(recoveryId, syntheticToken, {
    readSession: async () => {
      reads += 1;
      if (reads <= 2) return baseline;
      return repaired;
    },
    prepareContext: async () => {},
    redeem: async (_id, token) => {
      calls.push(token);
      return token ? firstResponse : repaired;
    },
    beforeMutation: () => {},
  });

  assert.equal(result.csrfToken, repaired.csrfToken);
  assert.deepEqual(calls, [syntheticToken, undefined]);
});

test("never adopts a restricted session for a different identity or tenant", async () => {
  const baseline = ordinarySession("csrf-baseline-0000000000003");
  const expected = recoverySession("csrf-expected-0000000000001");
  const other = recoverySession("csrf-other-user-000000000001", "93000000-0000-4000-8000-000000000099");
  let reads = 0;
  await assert.rejects(
    redeemInitialAdminRecoverySafely(recoveryId, syntheticToken, {
      readSession: async () => (++reads === 1 ? baseline : other),
      prepareContext: async () => {},
      redeem: async () => expected,
      beforeMutation: () => {},
    }),
    (error: unknown) => error instanceof ApiError && error.code === "INITIAL_ADMIN_RECOVERY_SESSION_NOT_CONFIRMED",
  );
});

test("public 204 context preparation accepts an empty success and excludes stale CSRF", async () => {
  const originalFetch = globalThis.fetch;
  let requestHeaders: Headers | undefined;
  globalThis.fetch = async (_input, init) => {
    requestHeaders = new Headers(init?.headers);
    return new Response(null, { status: 204, headers: { "x-request-id": "synthetic-204" } });
  };
  setCsrfToken("csrf-that-must-not-cross-public-boundary");
  try {
    assert.equal(await api.prepareInitialAdminRecoveryContext(), undefined);
    assert.equal(requestHeaders?.has("x-csrf-token"), false);
    assert.equal(await apiRequest<void>("/synthetic-204", { method: "POST", body: "{}", csrf: false }), undefined);
  } finally {
    setCsrfToken(undefined);
    globalThis.fetch = originalFetch;
  }
});

function ordinarySession(csrfToken: string): AuthenticatedSession {
  return {
    authenticated: true,
    status: "authenticated",
    user: { id: "93000000-0000-4000-8000-000000000010", displayName: "Synthetic Operator", email: "operator@example.invalid" },
    tenant: { id: "93000000-0000-4000-8000-000000000011", slug: "synthetic", name: "Synthetic Tenant", kind: "real", timezone: "UTC" },
    permissions: ["platform.security.manage"],
    csrfToken,
    expiresAt: future(),
    security: { mfaRequired: true, mfaEnabled: true, enrollmentOnly: false, assurance: "aal2", aal: 2, authMethod: "passkey", phishingResistant: true },
  };
}

function recoverySession(csrfToken: string, identityId = "93000000-0000-4000-8000-000000000020"): InitialAdminRecoveryRedemption {
  return {
    authenticated: true,
    recovered: true,
    status: "mfa_enrollment_required",
    user: { id: identityId, displayName: "Synthetic Recipient", email: "recipient@example.invalid" },
    tenant: { id: "93000000-0000-4000-8000-000000000021", slug: "recovery", name: "Recovery Tenant", kind: "real", timezone: "UTC" },
    permissions: [],
    csrfToken,
    expiresAt: future(),
    keyGrant: null,
    security: { mfaRequired: true, mfaEnabled: false, enrollmentOnly: true, assurance: "enrollment_only", aal: 1, authMethod: "bootstrap" },
  };
}

function future(): string {
  return new Date(Date.now() + 600_000).toISOString();
}
