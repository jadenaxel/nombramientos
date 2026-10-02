import { randomUUID } from "node:crypto";
import type { DeviceSessionStore, RequestPrincipal } from "@nombramientos/database";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";
import { revalidateStreamAuthority } from "../src/modules/event-routes.js";

afterEach(() => vi.unstubAllGlobals());

function fixture() {
  const identityId = randomUUID(), tenantId = randomUUID(), sessionId = randomUUID(), deviceId = randomUUID();
  const original = { identityId, activeTenantId: tenantId, sessionId, tenantKind: "real", authMethod: "federated", provenDeviceId: deviceId } as RequestPrincipal;
  const refreshed = { ...original, provenDeviceId: undefined } as unknown as RequestPrincipal;
  const sourceId = randomUUID();
  const binding = { deviceId, sourceSessionId: sourceId, status: "active", deviceStatus: "active", hasActiveGrant: true };
  const getBinding = vi.fn().mockResolvedValue(binding);
  const control = {
    getGestionChurchFederation: vi.fn().mockResolvedValue({ subject: `tenant:${tenantId}:${identityId}`, gestionChurchTenantId: tenantId, roleFingerprint: "a".repeat(64) }),
    getGestionChurchSessionBinding: vi.fn().mockResolvedValue(sourceId),
    revokeSession: vi.fn().mockResolvedValue(undefined),
  };
  const withDeviceSessionPrincipal = vi.fn(async (_principal: RequestPrincipal, _requestId: string, work: (store: DeviceSessionStore) => Promise<unknown>) => work({ getBinding } as unknown as DeviceSessionStore));
  const app = { apiConfig: { gestionChurchIntegration: { enabled: true, authorizeUrl: "http://fixture.invalid/authorize", sharedSecret: "synthetic-only" } }, database: { control, withDeviceSessionPrincipal } } as unknown as FastifyInstance;
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ authorized: true, roleFingerprint: "a".repeat(64) }), { status: 200 })));
  return { app, original, refreshed, getBinding, control, withDeviceSessionPrincipal, sourceId };
}

describe("device-bound live stream authority", () => {
  it("revalidates source and carries only the device proven at stream-open into the next data transaction", async () => {
    const item = fixture();
    expect(await revalidateStreamAuthority(item.app, item.original, item.refreshed, randomUUID())).toMatchObject({ provenDeviceId: item.original.provenDeviceId });
    expect(item.getBinding).toHaveBeenCalledWith(item.original.identityId, item.original.sessionId);
    expect(item.control.getGestionChurchSessionBinding).toHaveBeenCalledWith(item.original.sessionId, item.original.identityId, item.original.activeTenantId);
  });
  it.each([null, { deviceId: randomUUID(), status: "active" }, { deviceId: "same", status: "revoked" }])("fails closed for a removed, substituted or revoked binding", async (binding) => {
    const item = fixture();
    item.getBinding.mockResolvedValue(binding && { ...binding, deviceId: binding.deviceId === "same" ? item.original.provenDeviceId : binding.deviceId });
    await expect(revalidateStreamAuthority(item.app, item.original, item.refreshed, randomUUID())).rejects.toMatchObject({ statusCode: 401 });
  });
  it("does not treat a cookie-only original request as a device proof", async () => {
    const item = fixture();
    await expect(revalidateStreamAuthority(item.app, { ...item.original, provenDeviceId: undefined } as unknown as RequestPrincipal, item.refreshed, randomUUID())).rejects.toMatchObject({ statusCode: 401 });
    expect(item.withDeviceSessionPrincipal).not.toHaveBeenCalled();
  });
  it.each([{ deviceStatus: "pending", hasActiveGrant: true }, { deviceStatus: "active", hasActiveGrant: false }])("does not keep streaming after device or current content grant authority is lost", async (authority) => {
    const item = fixture();
    item.getBinding.mockResolvedValue({ deviceId: item.original.provenDeviceId, status: "active", ...authority });
    await expect(revalidateStreamAuthority(item.app, item.original, item.refreshed, randomUUID())).rejects.toMatchObject({ statusCode: 401 });
  });
  it("closes on source logout or role withdrawal before reading any additional event", async () => {
    const item = fixture();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ authorized: false }), { status: 200 })));
    await expect(revalidateStreamAuthority(item.app, item.original, item.refreshed, randomUUID())).rejects.toMatchObject({ statusCode: 401 });
    expect(item.control.revokeSession).toHaveBeenCalledWith(item.original.sessionId, "gestionchurch_access_changed");
    expect(item.withDeviceSessionPrincipal).not.toHaveBeenCalled();
  });
  it("does not adopt a different central session for an already bound live stream", async () => {
    const item = fixture();
    // Central authority may still say this identity/role is valid. It must not
    // substitute the exact source session proven when the browser was bound.
    item.control.getGestionChurchSessionBinding.mockResolvedValue(randomUUID());
    await expect(revalidateStreamAuthority(item.app, item.original, item.refreshed, randomUUID())).rejects.toMatchObject({ statusCode: 401 });
  });
  it("does not follow a changed tenant, identity or session context", async () => {
    const item = fixture();
    for (const field of ["activeTenantId", "identityId", "sessionId"] as const) {
      await expect(revalidateStreamAuthority(item.app, item.original, { ...item.refreshed, [field]: randomUUID() }, randomUUID())).rejects.toMatchObject({ statusCode: 401 });
    }
    expect(item.control.getGestionChurchFederation).not.toHaveBeenCalled();
    expect(item.withDeviceSessionPrincipal).not.toHaveBeenCalled();
  });
  it("closes when device or central authority cannot be checked instead of streaming from an old snapshot", async () => {
    const item = fixture();
    item.getBinding.mockRejectedValue(new Error("synthetic-store-unavailable"));
    await expect(revalidateStreamAuthority(item.app, item.original, item.refreshed, randomUUID())).rejects.toThrow("synthetic-store-unavailable");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("synthetic-source-unavailable")));
    await expect(revalidateStreamAuthority(item.app, item.original, item.refreshed, randomUUID())).rejects.toMatchObject({ statusCode: 503 });
  });
});
