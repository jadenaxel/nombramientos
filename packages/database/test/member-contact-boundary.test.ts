import type { PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { TenantStore } from "../src/tenant-store.js";

const displayEnvelope = { algorithm: "AES-256-GCM", keyId: "tenant-key-v1", nonce: "nonce", ciphertext: "ciphertext", aad: "aad" };
const contactEnvelope = { ...displayEnvelope, ciphertext: "CONTACT_CANARY" };

describe("member display/contact persistence boundary", () => {
  it("does not even select contact or the quarantined legacy envelope without contact authority", async () => {
    const query = vi.fn(async (sql: string) => ({ rows: [{
      id: "40000000-0000-4000-8000-000000000001",
      stable_code: "MEM-1",
      display_envelope: displayEnvelope,
      profile_migration_required: false,
      eligibility_status: "eligible",
      available: true,
      version: 1,
      archived_at: null,
      created_at: new Date(0),
      updated_at: new Date(0),
      current_responsibilities: 0,
      total_count: 1,
    }] }));
    const store = new TenantStore({ query } as unknown as PoolClient);

    const result = await store.listMembers(25, undefined, false, false, false);
    const sql = String(query.mock.calls[0]?.[0]);

    expect(sql).not.toContain("m.contact_envelope");
    expect(sql).not.toContain("m.profile_envelope");
    expect(sql).toMatch(/WITH filtered_member_keys AS MATERIALIZED/u);
    expect(sql).toMatch(/SELECT member_key\.id,member_key\.created_at/u);
    expect(sql).toMatch(/JOIN members m ON m\.id=page_keys\.id/u);
    expect(sql).not.toMatch(/count\(\*\) OVER\(\)/u);
    expect(JSON.stringify(result)).not.toContain("CONTACT_CANARY");
    expect(query).toHaveBeenCalledOnce();
  });

  it("selects and returns contact only when the caller explicitly enables that projection", async () => {
    const query = auditCapableMemberQuery({ contact_envelope: contactEnvelope });
    const store = new TenantStore({ query } as unknown as PoolClient);

    const result = await store.listMembers(25, undefined, false, false, true);

    expect(String(query.mock.calls[0]?.[0])).toContain("m.contact_envelope");
    expect(result).toMatchObject({ items: [expect.objectContaining({ contactEnvelope })] });
    const insert = query.mock.calls.find(([sql]) => String(sql).includes("INSERT INTO audit_events"));
    expect(insert?.[1]).toEqual(expect.arrayContaining([
      "member.contact.read",
      "member_roster",
      "members",
      { recordCount: 1 },
    ]));
    expect(JSON.stringify(insert?.[1])).not.toMatch(/CONTACT_CANARY|ciphertext|nonce|aad|hash/iu);
  });

  it("does not audit an optional sensitive projection when no envelope was materialized", async () => {
    const query = vi.fn(async () => ({ rows: [{
      ...memberRow(),
      contact_envelope: null,
    }] }));
    const store = new TenantStore({ query } as unknown as PoolClient);

    const result = await store.listMembers(25, undefined, false, false, true);

    expect(result).toMatchObject({ items: [expect.not.objectContaining({ contactEnvelope: expect.anything() })] });
    expect(query).toHaveBeenCalledOnce();
  });
});

function auditCapableMemberQuery(extra: Readonly<Record<string, unknown>>) {
  return vi.fn(async (sql: string, _values?: readonly unknown[]) => {
    if (sql.includes("FROM members m")) return { rows: [{ ...memberRow(), ...extra }] };
    if (sql.includes("pg_advisory_xact_lock")) return { rows: [] };
    if (sql.includes("SELECT event_hash FROM audit_events")) return { rows: [] };
    if (sql.includes("current_setting('app.identity_id')")) return { rows: [{
      identity_id: "50000000-0000-4000-8000-000000000001",
      request_id: "60000000-0000-4000-8000-000000000001",
    }] };
    if (sql.includes("nextval(pg_get_serial_sequence")) return { rows: [{
      sequence: "1",
      id: "70000000-0000-4000-8000-000000000001",
      occurred_at: new Date("2026-09-12T00:00:00.000Z"),
    }] };
    if (sql.includes("INSERT INTO audit_events")) return { rows: [], rowCount: 1 };
    throw new Error(`Unexpected SQL in member boundary test: ${sql}`);
  });
}

function memberRow(): Record<string, unknown> {
  return {
    id: "40000000-0000-4000-8000-000000000001",
    stable_code: "MEM-1",
    display_envelope: displayEnvelope,
    profile_migration_required: false,
    eligibility_status: "eligible",
    available: true,
    version: 1,
    archived_at: null,
    created_at: new Date(0),
    updated_at: new Date(0),
    current_responsibilities: 0,
    total_count: 1,
  };
}
