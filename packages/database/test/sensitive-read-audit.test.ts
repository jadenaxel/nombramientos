import type { PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import {
  appendSensitiveReadAuditEvent,
  SENSITIVE_READ_AUDIT_ACTIONS,
} from "../src/sensitive-read-audit.js";

describe("sanitized sensitive-read audit contract", () => {
  it("binds actor/request/entity through the append-only v2 event and writes only allow-listed metadata", async () => {
    const query = auditClientQuery();
    await appendSensitiveReadAuditEvent({ query } as unknown as PoolClient, {
      action: SENSITIVE_READ_AUDIT_ACTIONS.memberPhoto,
      entityType: "member-photo",
      entityId: "10000000-0000-4000-8000-000000000001",
      metadata: {
        memberId: "20000000-0000-4000-8000-000000000001",
        version: 3,
      },
    });

    const inserted = query.mock.calls.find(([sql]) => String(sql).includes("INSERT INTO audit_events"));
    expect(inserted?.[1]).toEqual([
      "9",
      "30000000-0000-4000-8000-000000000001",
      "2026-09-12T01:02:03.000Z",
      "40000000-0000-4000-8000-000000000001",
      "member.photo.read",
      "member-photo",
      "10000000-0000-4000-8000-000000000001",
      "success",
      "50000000-0000-4000-8000-000000000001",
      { memberId: "20000000-0000-4000-8000-000000000001", version: 3 },
      null,
      expect.stringMatching(/^[0-9a-f]{64}$/u),
    ]);
    expect(JSON.stringify(inserted?.[1])).not.toMatch(/ciphertext|nonce|aad|envelope|secret|token|contentHash/iu);
  });

  it("rejects metadata expansion or a mismatched entity before any database query", async () => {
    const query = vi.fn();
    await expect(appendSensitiveReadAuditEvent({ query } as unknown as PoolClient, {
      action: SENSITIVE_READ_AUDIT_ACTIONS.memberContact,
      entityType: "member_roster",
      entityId: "members",
      metadata: { recordCount: 1, ciphertext: "must-never-enter-audit" },
    })).rejects.toThrow("metadata is invalid");
    await expect(appendSensitiveReadAuditEvent({ query } as unknown as PoolClient, {
      action: SENSITIVE_READ_AUDIT_ACTIONS.reportArtifact,
      entityType: "wrong-entity",
      entityId: "10000000-0000-4000-8000-000000000001",
      metadata: {
        reportType: "cycle_summary",
        audience: "committee",
        format: "pdf",
        version: 2,
        lineageRevision: 1,
      },
    })).rejects.toThrow("entity type is invalid");
    expect(query).not.toHaveBeenCalled();
  });

  it("records one sanitized review-material event for photo and rationale counts", async () => {
    const query = auditClientQuery();
    await appendSensitiveReadAuditEvent({ query } as unknown as PoolClient, {
      action: SENSITIVE_READ_AUDIT_ACTIONS.candidacyReviewMaterial,
      entityType: "office_process",
      entityId: "10000000-0000-4000-8000-000000000001",
      metadata: {
        photoRecordCount: 2,
        rationaleRecordCount: 1,
        processVersion: 4,
      },
    });

    const inserted = query.mock.calls.find(([sql]) => String(sql).includes("INSERT INTO audit_events"));
    expect(inserted?.[1]).toEqual(expect.arrayContaining([
      "candidacy.review-material.read",
      "office_process",
      "10000000-0000-4000-8000-000000000001",
      { photoRecordCount: 2, rationaleRecordCount: 1, processVersion: 4 },
    ]));
    expect(JSON.stringify(inserted?.[1])).not.toMatch(/ciphertext|nonce|aad|envelope|secret|token|contentHash|sha256|hash/iu);
  });

  it("rejects an empty review-material event before any database query", async () => {
    const query = vi.fn();
    await expect(appendSensitiveReadAuditEvent({ query } as unknown as PoolClient, {
      action: SENSITIVE_READ_AUDIT_ACTIONS.candidacyReviewMaterial,
      entityType: "office_process",
      entityId: "10000000-0000-4000-8000-000000000001",
      metadata: {
        photoRecordCount: 0,
        rationaleRecordCount: 0,
        processVersion: 4,
      },
    })).rejects.toThrow("review material is not materialized");
    expect(query).not.toHaveBeenCalled();
  });
});

function auditClientQuery() {
  return vi.fn(async (sql: string, _values?: readonly unknown[]) => {
    if (sql.includes("pg_advisory_xact_lock")) return { rows: [] };
    if (sql.includes("SELECT event_hash FROM audit_events")) return { rows: [] };
    if (sql.includes("current_setting('app.identity_id')")) return { rows: [{
      identity_id: "40000000-0000-4000-8000-000000000001",
      request_id: "50000000-0000-4000-8000-000000000001",
    }] };
    if (sql.includes("nextval(pg_get_serial_sequence")) return { rows: [{
      sequence: "9",
      id: "30000000-0000-4000-8000-000000000001",
      occurred_at: new Date("2026-09-12T01:02:03.000Z"),
    }] };
    if (sql.includes("INSERT INTO audit_events")) return { rows: [], rowCount: 1 };
    throw new Error(`Unexpected SQL in audit test: ${sql}`);
  });
}
