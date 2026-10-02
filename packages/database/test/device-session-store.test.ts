import type { PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { DeviceSessionStore } from "../src/device-session-store.js";

describe("tenant-local own session labels", () => {
  it("joins exact own device and identity and limits results to the supplied authorized session IDs", async () => {
    const sessionA = "10000000-0000-4000-8000-000000000001";
    const sessionB = "10000000-0000-4000-8000-000000000002";
    const identity = "20000000-0000-4000-8000-000000000001";
    const query = vi.fn().mockResolvedValue({ rows: [
      { session_id: sessionA, label: "Computadora A" },
      { session_id: sessionB, label: "Teléfono B" },
      { session_id: "10000000-0000-4000-8000-000000000099", label: "Outside allowed sessions" },
    ] });
    const store = new DeviceSessionStore({ query } as unknown as PoolClient);
    expect([...await store.getOwnSessionLabels(identity, [sessionA, sessionB, sessionA])]).toEqual([
      [sessionA, "Computadora A"], [sessionB, "Teléfono B"],
    ]);
    expect(query).toHaveBeenCalledExactlyOnceWith(expect.stringContaining("binding.identity_id=$1 AND binding.session_id=ANY($2::uuid[])"),
      [identity, [sessionA, sessionB]]);
    const sql = query.mock.calls[0]![0] as string;
    expect(sql).toContain("device.device_id=binding.device_id AND device.identity_id=binding.identity_id");
    expect(sql).not.toMatch(/INSERT|UPDATE|DELETE|auth_sessions|tenants\b/u);
  });

  it("does not query for an empty session list", async () => {
    const query = vi.fn().mockRejectedValue(new Error("Must not query"));
    expect((await new DeviceSessionStore({ query } as unknown as PoolClient).getOwnSessionLabels("identity", [])).size).toBe(0);
    expect(query).not.toHaveBeenCalled();
  });

  it("retains an unlabeled fallback by omitting empty labels and propagates database failures", async () => {
    const id = "10000000-0000-4000-8000-000000000001";
    const query = vi.fn().mockResolvedValueOnce({ rows: [{ session_id: id, label: "  " }] })
      .mockRejectedValueOnce(new Error("Unavailable"));
    const store = new DeviceSessionStore({ query } as unknown as PoolClient);
    expect((await store.getOwnSessionLabels("identity", [id])).size).toBe(0);
    await expect(store.getOwnSessionLabels("identity", [id])).rejects.toThrow("Unavailable");
  });
});
