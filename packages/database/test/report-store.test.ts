import type { PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { TenantStore } from "../src/tenant-store.js";

describe("TenantStore report metadata boundary", () => {
  it("passes the permission-filtered type/audience scope allow-list into the report query", async () => {
    const query = vi.fn(async () => ({ rows: [], rowCount: 0 }));
    const store = new TenantStore({ query } as unknown as PoolClient);
    const permitted = ["cycle_summary:committee", "audit_integrity:auditor"] as const;

    await expect(store.listReports(30, permitted)).resolves.toEqual([]);

    expect(query).toHaveBeenCalledOnce();
    expect(query).toHaveBeenCalledWith(expect.stringContaining("WHERE (report.report_type || ':' || report.audience)=ANY($2::text[])"), [30, permitted]);
  });

  it("fails closed with an empty allow-list rather than omitting the predicate", async () => {
    const query = vi.fn(async (_sql: string, values: readonly unknown[]) => {
      expect(values).toEqual([10, []]);
      return { rows: [], rowCount: 0 };
    });
    const store = new TenantStore({ query } as unknown as PoolClient);

    await expect(store.listReports(10, [])).resolves.toEqual([]);
    expect(query).toHaveBeenCalledOnce();
  });

  it("returns the persisted ciphertext length needed to verify a historical artifact", async () => {
    const query = vi.fn(async () => ({
      rows: [{
        id: "10000000-0000-4000-8000-000000000001",
        report_type: "cycle_summary",
        audience: "committee",
        locale: "fr",
        format: "csv",
        filters: { snapshotSha256: `sha256:${"a".repeat(64)}` },
        state: "ready",
        filename: "cycle.csv",
        media_type: "text/csv",
        artifact_sha256: `sha256:${"b".repeat(64)}`,
        ciphertext_sha256: `sha256:${"c".repeat(64)}`,
        plaintext_bytes: "41",
        artifact_manifest: { rowCount: 1 },
        error_code: null,
        supersedes_report_id: null,
        corrected_by_report_id: null,
        correction_reason_code: null,
        lineage_root_id: "10000000-0000-4000-8000-000000000001",
        lineage_revision: 1,
        version: 2,
        created_at: new Date("2026-01-01T00:00:00Z"),
        ready_at: new Date("2026-01-01T00:00:01Z"),
        failed_at: null,
      }],
      rowCount: 1,
    }));
    const store = new TenantStore({ query } as unknown as PoolClient);

    await expect(store.listReports(1, ["cycle_summary:committee"])).resolves.toEqual([
      expect.objectContaining({
        plaintextBytes: 41,
        ciphertextBytes: 57,
        supersedesReportId: null,
        correctedByReportId: null,
        lineageRootId: "10000000-0000-4000-8000-000000000001",
        lineageRevision: 1,
      }),
    ]);
  });

  it("rejects free-text correction reasons before writing idempotency or audit data", async () => {
    const query = vi.fn();
    const store = new TenantStore({ query } as unknown as PoolClient);

    await expect(store.correctReport({
      identityId: "10000000-0000-4000-8000-000000000010",
      idempotencyKey: "report-correction-unit-0001",
      previousReportId: "10000000-0000-4000-8000-000000000001",
      expectedPreviousVersion: 2,
      reasonCode: "the member name was wrong",
      filters: {
        cycleId: "10000000-0000-4000-8000-000000000020",
        snapshotSha256: `sha256:${"d".repeat(64)}`,
        snapshotAt: "2026-09-12T12:00:00.000Z",
      },
    })).rejects.toMatchObject({ code: "REPORT_CORRECTION_REASON_INVALID" });
    expect(query).not.toHaveBeenCalled();
  });
});
