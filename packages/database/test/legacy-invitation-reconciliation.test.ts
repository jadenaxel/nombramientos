import type { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import { inspectLegacyInvitationReconciliation } from "../src/legacy-invitation-reconciliation.js";

describe("legacy invitation reconciliation inspection", () => {
  it("treats a pre-provenance tenant as an exact empty inventory without querying control", async () => {
    const tenantQuery = vi.fn(async () => ({
      rowCount: 1,
      rows: [{
        has_source_invitation_id: false,
        has_acceptance_id: false,
        has_fences: false,
      }],
    }));
    const controlQuery = vi.fn();
    const result = await inspectLegacyInvitationReconciliation(
      { query: tenantQuery } as unknown as Pick<Pool, "query">,
      { query: controlQuery } as unknown as Pick<Pool, "query">,
      "00000000-0000-4000-8000-000000000001",
    );

    expect(result.entries).toEqual([]);
    expect(result.evidence).toMatchObject({
      required: false,
      sourceSchema: "legacy_035",
      invitationCount: 0,
      bindingCount: 0,
    });
    expect(result.evidence.manifestSha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(result.evidence.controlSnapshotSha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(tenantQuery).toHaveBeenCalledTimes(1);
    expect(controlQuery).not.toHaveBeenCalled();
  });

  it("fails closed if acceptance artifacts exist without source provenance", async () => {
    const tenantQuery = vi.fn(async () => ({
      rowCount: 1,
      rows: [{
        has_source_invitation_id: false,
        has_acceptance_id: true,
        has_fences: true,
      }],
    }));
    await expect(inspectLegacyInvitationReconciliation(
      { query: tenantQuery } as unknown as Pick<Pool, "query">,
      { query: vi.fn() } as unknown as Pick<Pool, "query">,
      "00000000-0000-4000-8000-000000000001",
    )).rejects.toThrow("Tenant invitation acceptance schema is partial or unavailable");
  });
});
