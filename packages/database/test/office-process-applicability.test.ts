import { readFileSync } from "node:fs";
import type { PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { CoreWorkflowStore } from "../src/core-workflow-store.js";

const ACTOR_ID = "11111111-1111-4111-8111-111111111111";
const CYCLE_ID = "22222222-2222-4222-8222-222222222222";
const OFFICE_ID = "33333333-3333-4333-8333-333333333333";
const PROCESS_ID = "44444444-4444-4444-8444-444444444444";
const REPLACEMENT_ID = "55555555-5555-4555-8555-555555555555";
const UPDATED_AT = new Date("2026-09-11T12:00:00.000Z");

describe("office process applicability", () => {
  it("rejects an unrecognized or state-mismatched reason before consuming idempotency state", async () => {
    const query = vi.fn(async () => {
      throw new Error("database must not be reached");
    });
    const store = new CoreWorkflowStore({ query } as unknown as PoolClient);

    await expect(store.setOfficeProcessApplicability({
      identityId: ACTOR_ID,
      idempotencyKey: "invalid-reason",
      processId: PROCESS_ID,
      expectedCycleVersion: 8,
      expectedProcessVersion: 2,
      enabled: false,
      reasonCode: "PERSONA_TIENE_DIAGNOSTICO",
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    await expect(store.setOfficeProcessApplicability({
      identityId: ACTOR_ID,
      idempotencyKey: "mismatched-reason",
      processId: PROCESS_ID,
      expectedCycleVersion: 8,
      expectedProcessVersion: 2,
      enabled: true,
      reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE",
    })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
    expect(query).not.toHaveBeenCalled();
  });

  it("returns a version-checked no-op for an already disabled replacement group", async () => {
    const query = vi.fn(async (sql: string, _values?: readonly unknown[]) => {
      if (sql.includes("INSERT INTO idempotency_records")) return result([], 1);
      if (sql.includes("SELECT cycle_id,office_id FROM office_processes")) {
        return result([{ cycle_id: CYCLE_ID, office_id: OFFICE_ID }]);
      }
      if (sql.includes("SELECT id,status,version FROM election_cycles")) {
        return result([{ id: CYCLE_ID, status: "active", version: 8 }]);
      }
      if (sql.includes("ORDER BY procedure_sequence,id") && sql.includes("FOR UPDATE")) {
        return result(processGroup(false));
      }
      if (sql.includes("UPDATE idempotency_records")) return result([], 1);
      throw new Error(`Unexpected query: ${sql}`);
    });
    const store = new CoreWorkflowStore({ query } as unknown as PoolClient);

    await expect(store.setOfficeProcessApplicability({
      identityId: ACTOR_ID,
      idempotencyKey: "already-disabled",
      processId: REPLACEMENT_ID,
      expectedCycleVersion: 8,
      expectedProcessVersion: 5,
      enabled: false,
      reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE",
    })).resolves.toMatchObject({
      cycleId: CYCLE_ID,
      officeId: OFFICE_ID,
      baseProcessId: PROCESS_ID,
      affectedProcessIds: [PROCESS_ID, REPLACEMENT_ID],
      enabled: false,
      changed: false,
      cycleVersion: 8,
      processVersions: [
        { processId: PROCESS_ID, version: 2 },
        { processId: REPLACEMENT_ID, version: 5 },
      ],
    });
    expect(query.mock.calls.some(([sql]) => String(sql).includes("SET enabled="))).toBe(false);
  });

  it("blocks the whole group when any historical procedure still has an active round", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("INSERT INTO idempotency_records")) return result([], 1);
      if (sql.includes("SELECT cycle_id,office_id FROM office_processes")) return result([{ cycle_id: CYCLE_ID, office_id: OFFICE_ID }]);
      if (sql.includes("SELECT id,status,version FROM election_cycles")) return result([{ id: CYCLE_ID, status: "active", version: 8 }]);
      if (sql.includes("ORDER BY procedure_sequence,id") && sql.includes("FOR UPDATE")) return result(processGroup(true));
      if (sql.includes("FROM rounds")) return result([{ exists: 1 }]);
      throw new Error(`Unexpected query: ${sql}`);
    });
    const store = new CoreWorkflowStore({ query } as unknown as PoolClient);

    await expect(store.setOfficeProcessApplicability({
      identityId: ACTOR_ID,
      idempotencyKey: "active-round",
      processId: PROCESS_ID,
      expectedCycleVersion: 8,
      expectedProcessVersion: 2,
      enabled: false,
      reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE",
    })).rejects.toMatchObject({ code: "OFFICE_PROCESS_HAS_ACTIVE_ROUNDS" });
    expect(query.mock.calls.some(([sql]) => String(sql).includes("UPDATE office_processes"))).toBe(false);
  });

  it.each([
    ["FROM assignments", "OFFICE_PROCESS_HAS_ACTIVE_DECISIONS"],
    ["FROM member_eligibility_workflow_pauses", "OFFICE_PROCESS_HAS_UNRESOLVED_ELIGIBILITY"],
    ["FROM session_agenda_items", "OFFICE_PROCESS_HAS_OPEN_AGENDA"],
    ["FROM offices base_office", "OFFICE_PROCESS_REQUIRED_BY_ENABLED_STRUCTURE"],
  ] as const)("blocks deactivation on %s with a stable conflict", async (blockedQuery, expectedCode) => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("INSERT INTO idempotency_records")) return result([], 1);
      if (sql.includes("SELECT cycle_id,office_id FROM office_processes")) return result([{ cycle_id: CYCLE_ID, office_id: OFFICE_ID }]);
      if (sql.includes("SELECT id,status,version FROM election_cycles")) return result([{ id: CYCLE_ID, status: "active", version: 8 }]);
      if (sql.includes("ORDER BY procedure_sequence,id") && sql.includes("FOR UPDATE")) return result(processGroup(true));
      if (sql.includes(blockedQuery)) return result([{ exists: 1 }]);
      if (sql.includes("FROM rounds") || sql.includes("FROM assignments")
        || sql.includes("FROM member_eligibility_workflow_pauses")
        || sql.includes("FROM session_agenda_items") || sql.includes("FROM offices base_office")) {
        return result([]);
      }
      throw new Error(`Unexpected query: ${sql}`);
    });
    const store = new CoreWorkflowStore({ query } as unknown as PoolClient);

    await expect(store.setOfficeProcessApplicability({
      identityId: ACTOR_ID,
      idempotencyKey: `blocked-${expectedCode}`,
      processId: PROCESS_ID,
      expectedCycleVersion: 8,
      expectedProcessVersion: 2,
      enabled: false,
      reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE",
    })).rejects.toMatchObject({ code: expectedCode });
  });

  it("requires an enabled linked base before restoring a linked responsibility", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("INSERT INTO idempotency_records")) return result([], 1);
      if (sql.includes("SELECT cycle_id,office_id FROM office_processes")) return result([{ cycle_id: CYCLE_ID, office_id: OFFICE_ID }]);
      if (sql.includes("SELECT id,status,version FROM election_cycles")) return result([{ id: CYCLE_ID, status: "active", version: 8 }]);
      if (sql.includes("ORDER BY procedure_sequence,id") && sql.includes("FOR UPDATE")) return result(processGroup(false));
      if (sql.includes("FROM offices WHERE id=$1 AND active")) {
        return result([{
          canonical_code: "LINKED_OFFICE",
          appointment_mechanism: "linked_designation",
          catalog_metadata: { linkedBaseOfficeCode: "BASE_OFFICE" },
        }]);
      }
      if (sql.includes("JOIN offices office ON office.id=process.office_id")) return result([]);
      throw new Error(`Unexpected query: ${sql}`);
    });
    const store = new CoreWorkflowStore({ query } as unknown as PoolClient);

    await expect(store.setOfficeProcessApplicability({
      identityId: ACTOR_ID,
      idempotencyKey: "missing-linked-base",
      processId: PROCESS_ID,
      expectedCycleVersion: 8,
      expectedProcessVersion: 2,
      enabled: true,
      reasonCode: "CYCLE_STRUCTURE_APPLICABILITY_RESTORED",
    })).rejects.toMatchObject({ code: "LINKED_BASE_UNCONFIGURED" });
  });

  it("atomically updates every replacement procedure and advances the cycle version", async () => {
    const query = vi.fn(async (sql: string, _values?: readonly unknown[]) => {
      if (sql.includes("INSERT INTO idempotency_records")) return result([], 1);
      if (sql.includes("SELECT cycle_id,office_id FROM office_processes")) return result([{ cycle_id: CYCLE_ID, office_id: OFFICE_ID }]);
      if (sql.includes("SELECT id,status,version FROM election_cycles")) return result([{ id: CYCLE_ID, status: "active", version: 8 }]);
      if (sql.includes("ORDER BY procedure_sequence,id") && sql.includes("FOR UPDATE")) return result(processGroup(true));
      if (sql.includes("FROM rounds") || sql.includes("FROM assignments")
        || sql.includes("FROM member_eligibility_workflow_pauses")
        || sql.includes("FROM session_agenda_items") || sql.includes("FROM offices base_office")) {
        return result([]);
      }
      if (sql.includes("UPDATE office_processes") && sql.includes("SET enabled=")) {
        return result([
          { id: PROCESS_ID, version: 3, updated_at: UPDATED_AT },
          { id: REPLACEMENT_ID, version: 6, updated_at: UPDATED_AT },
        ]);
      }
      if (sql.includes("UPDATE election_cycles")) return result([{ version: 9 }]);
      if (sql.includes("INSERT INTO outbox_events")) return result([], 1);
      if (sql.includes("pg_advisory_xact_lock")) return result([{ pg_advisory_xact_lock: null }]);
      if (sql.includes("SELECT event_hash FROM audit_events")) return result([]);
      if (sql.includes("current_setting('app.identity_id')")) return result([{ identity_id: ACTOR_ID, request_id: "request-1" }]);
      if (sql.includes("nextval(pg_get_serial_sequence")) {
        return result([{ sequence: "1", id: "66666666-6666-4666-8666-666666666666", occurred_at: UPDATED_AT }]);
      }
      if (sql.includes("INSERT INTO audit_events")) return result([], 1);
      if (sql.includes("UPDATE idempotency_records")) return result([], 1);
      throw new Error(`Unexpected query: ${sql}`);
    });
    const store = new CoreWorkflowStore({ query } as unknown as PoolClient);

    await expect(store.setOfficeProcessApplicability({
      identityId: ACTOR_ID,
      idempotencyKey: "disable-group",
      processId: PROCESS_ID,
      expectedCycleVersion: 8,
      expectedProcessVersion: 2,
      enabled: false,
      reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE",
    })).resolves.toMatchObject({
      cycleId: CYCLE_ID,
      baseProcessId: PROCESS_ID,
      affectedProcessIds: [PROCESS_ID, REPLACEMENT_ID],
      enabled: false,
      changed: true,
      cycleVersion: 9,
      processVersions: [
        { processId: PROCESS_ID, version: 3 },
        { processId: REPLACEMENT_ID, version: 6 },
      ],
    });
    const groupUpdate = query.mock.calls.find(([sql]) => String(sql).includes("SET enabled="));
    expect(groupUpdate?.[1]).toEqual([[PROCESS_ID, REPLACEMENT_ID], false]);
  });

  it("keeps legacy vacancies applicable and exposes disabled workflow history", () => {
    const tenantStore = readFileSync(new URL("../src/tenant-store.ts", import.meta.url), "utf8");
    const workflowStore = readFileSync(new URL("../src/core-workflow-store.ts", import.meta.url), "utf8");
    const workflowProjection = readFileSync(new URL("../src/core-workflow.ts", import.meta.url), "utf8");
    const migration = readFileSync(new URL("../migrations/tenant/028_office_process_applicability.sql", import.meta.url), "utf8");

    expect(tenantStore).toContain("v.process_id IS NULL OR EXISTS");
    expect(tenantStore).toContain("vacancy.process_id IS NULL OR EXISTS");
    expect(tenantStore).toContain("applicable.reused_vacancy_id=vacancy.id");
    expect(workflowStore.match(/vacancy\.process_id IS NULL OR EXISTS/g)?.length).toBeGreaterThanOrEqual(5);
    expect(workflowStore).toContain("process.reused_vacancy_id AS \"reusedVacancyId\",process.enabled,process.version");
    expect(workflowProjection).toContain('"reusedVacancyId", "enabled", "version"');
    expect(migration).toContain("while preserving its immutable workflow history");
    expect(migration).toContain("WHERE enabled AND reused_vacancy_id IS NOT NULL");
  });
});

function processGroup(enabled: boolean): Array<Record<string, unknown>> {
  return [
    {
      id: PROCESS_ID,
      cycle_id: CYCLE_ID,
      office_id: OFFICE_ID,
      phase: "CONFIGURADO",
      enabled,
      version: 2,
      procedure_sequence: 1,
      updated_at: UPDATED_AT,
    },
    {
      id: REPLACEMENT_ID,
      cycle_id: CYCLE_ID,
      office_id: OFFICE_ID,
      phase: "VACANTE_PENDIENTE",
      enabled,
      version: 5,
      procedure_sequence: 2,
      updated_at: UPDATED_AT,
    },
  ];
}

function result(rows: readonly Record<string, unknown>[], rowCount = rows.length): { rows: readonly Record<string, unknown>[]; rowCount: number } {
  return { rows, rowCount };
}
