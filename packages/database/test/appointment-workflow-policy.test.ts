import {
  BLOCKED_ORDINARY_WORKFLOW_MECHANISMS,
  CONFIGURABLE_VACANCY_PROCESS_MECHANISMS,
  classifyAppointmentWorkflow,
  isConfigurableVacancyProcessMechanism,
  isOrdinaryProposalBallotMechanism,
} from "@nombramientos/catalog";
import type { PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { CoreWorkflowStore } from "../src/core-workflow-store.js";
import { TenantStore } from "../src/tenant-store.js";

const ID = "11111111-1111-4111-8111-111111111111";

describe("appointment workflow policy", () => {
  it("admits only church-election mechanisms to proposal and ballot rounds", () => {
    expect(CONFIGURABLE_VACANCY_PROCESS_MECHANISMS).toEqual([
      "church_election_after_nominating_report",
      "church_election",
      "linked_designation",
    ]);
    expect(isOrdinaryProposalBallotMechanism("church_election_after_nominating_report")).toBe(true);
    expect(isOrdinaryProposalBallotMechanism("church_election")).toBe(true);
    expect(isOrdinaryProposalBallotMechanism("linked_designation")).toBe(false);
  });

  it("keeps council recommendation catalogable but outside configured election workflows", () => {
    const mechanism = "council_recommendation_board_approval";
    expect(BLOCKED_ORDINARY_WORKFLOW_MECHANISMS).toContain(mechanism);
    expect(classifyAppointmentWorkflow(mechanism)).toBe("separate_procedure");
    expect(isConfigurableVacancyProcessMechanism(mechanism)).toBe(false);
    expect(isOrdinaryProposalBallotMechanism(mechanism)).toBe(false);
    expect(classifyAppointmentWorkflow("unknown_legacy_mechanism")).toBe("unsupported");
    expect(classifyAppointmentWorkflow("toString")).toBe("unsupported");
  });

  it("emits a stable conflict before persisting a council-board vacancy process", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("INSERT INTO idempotency_records")) return { rows: [], rowCount: 1 };
      if (sql.includes("FROM election_cycles")) {
        return { rows: [{ id: ID, status: "draft", version: 1 }], rowCount: 1 };
      }
      if (sql.includes("FROM offices")) {
        return {
          rows: [{
            id: ID,
            canonical_code: "TEST_COUNCIL_BOARD",
            appointment_mechanism: "council_recommendation_board_approval",
            cardinality: 1,
            catalog_metadata: {},
          }],
          rowCount: 1,
        };
      }
      throw new Error(`Unexpected query: ${sql}`);
    });
    const store = new CoreWorkflowStore({ query } as unknown as PoolClient);

    await expect(store.configureVacancyProcess({
      identityId: ID,
      idempotencyKey: ID,
      cycleId: ID,
      expectedCycleVersion: 1,
      configuration: {
        officeId: ID,
        vacancyCount: 1,
        maxProposalSelections: 1,
        maxBallotSelections: 1,
        decisionRule: { kind: "PLURALITY" },
        abstentionRule: "EXCLUDED_FROM_CANDIDATE_TOTALS",
        tiebreakPolicy: "NEW_BALLOT_ROUND",
        quorumRule: { kind: "ALL_REQUIRED" },
        aggregateAudience: "committee",
        agendaOrder: 1,
      },
    })).rejects.toMatchObject({
      code: "COUNCIL_BOARD_PROCEDURE_REQUIRED",
      message: expect.stringContaining("cannot enter the ordinary proposal or ballot workflow"),
    });
    expect(query.mock.calls.some(([sql]) => String(sql).includes("INSERT INTO office_processes"))).toBe(false);
  });

  it("rejects writes to a legacy council-board round before processing the payload", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("INSERT INTO idempotency_records")) return { rows: [], rowCount: 1 };
      if (sql.includes("FROM rounds round_state")) {
        return {
          rows: [{
            version: 1,
            phase: "PROPUESTAS_ABIERTAS",
            submission_kind: "proposal",
            cycle_id: ID,
            candidate_set_hash: `sha256:${"a".repeat(64)}`,
            rules_hash: `sha256:${"b".repeat(64)}`,
            appointment_mechanism: "council_recommendation_board_approval",
          }],
          rowCount: 1,
        };
      }
      throw new Error(`Unexpected query: ${sql}`);
    });
    const client = { query } as unknown as PoolClient;
    const workflow = new CoreWorkflowStore(client);
    const tenant = new TenantStore(client);

    await expect(workflow.closeProposalRound({
      identityId: ID,
      idempotencyKey: ID,
      roundId: ID,
      expectedRoundVersion: 1,
      expectedProcessVersion: 1,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    })).rejects.toMatchObject({ code: "COUNCIL_BOARD_PROCEDURE_REQUIRED" });

    await expect(tenant.submit({
      identityId: ID,
      idempotencyKey: ID,
      roundId: ID,
      kind: "proposal",
      expectedVersion: 1,
      envelope: {
        algorithm: "AES-256-GCM",
        keyId: "legacy",
        nonce: "ignored",
        ciphertext: "ignored",
        aad: "ignored",
      },
      contentHash: `sha256:${"c".repeat(64)}`,
    })).rejects.toMatchObject({ code: "COUNCIL_BOARD_PROCEDURE_REQUIRED" });
    expect(query).toHaveBeenCalledTimes(4);
  });
});
