import {
  createHash,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { bindDirectFixtureSession } from "./direct-device-session-fixture.js";
import {
  createTenantKeyGrantEnvelope,
  exportCustodianSigningPublicKey,
  exportTenantDevicePublicKey,
  generateCustodianSigningKeyPair,
  generateTenantDeviceKeyPair,
  openTenantKeyGrantEnvelope,
  verifyTenantKeyGrantEnvelope,
} from "@nombramientos/e2ee";
import { Pool, type PoolClient } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { normalizeProposalAggregate, workflowSha256 } from "../src/core-workflow.js";
import { CoreWorkflowStore } from "../src/core-workflow-store.js";
import { runMigrations } from "../src/migrations.js";
import { TenantStore, type SubmissionInput } from "../src/tenant-store.js";
import type { EncryptedEnvelope } from "../src/types.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const WORKFLOW_TENANT_KEY_ID = "72af9ffc-388b-4a9b-b194-12c22b3733fc";
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Core workflow live tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface Fixture {
  readonly cluster: Pool;
  readonly tenant: Pool;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly actorId: string;
  readonly secondElectorId: string;
  readonly electorIds: readonly [string, string, string, string, string];
  readonly memberIds: readonly [string, string];
  readonly departmentId: string;
  readonly officeId: string;
}

let fixture: Fixture | undefined;
let exactAcceptanceFixture: Fixture | undefined;

live("AC-10..26 persistent core workflow", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    const current = fixture;
    fixture = undefined;
    if (current) await cleanupFixture(current);
  }, 60_000);

  it("runs cycle → proposals → review → ballot → published aggregate → provisional assignment", async () => {
    const current = requireFixture();
    const cycleKey = randomUUID();
    const cycleInput = {
      identityId: current.actorId,
      idempotencyKey: cycleKey,
      name: "Temporary verified cycle",
      locale: "es" as const,
      timezone: "America/La_Paz",
      jurisdiction: "local-test-only",
      termStart: "2025-01-01",
      termEnd: "2035-12-31",
      normativeVersion: "test-v1",
      configuration: { parallelRooms: false },
    };
    const created = await withStore(current, current.actorId, (store) => store.createCycle(cycleInput));
    const replayed = await withStore(current, current.actorId, (store) => store.createCycle(cycleInput));
    expect(replayed).toEqual(JSON.parse(JSON.stringify(created)));
    const cycleId = stringField(created, "id");
    const discovered = await withStore(current, current.actorId, (store) => store.listCycles());
    expect(discovered.items).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: cycleId, status: "draft", version: 1 }),
    ]));

    const sessionId = randomUUID();
    const session = await withStore(current, current.actorId, (store) => store.addSession({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      sessionId,
      expectedCycleVersion: 1,
      sequence: 1,
      titleEnvelope: envelopeWithAad({ tenantId: current.tenantId, cycleId, sessionId, purpose: "session-title", schemaVersion: 1, titleVersion: 1 }),
      startsAt: "2030-10-01T18:00:00-04:00",
      endsAt: "2030-10-01T20:00:00-04:00",
    }));
    const institutionalSessionId = stringField(session, "id");
    expect(session["cycleVersion"]).toBe(2);
    expect(session).toMatchObject({ titleEnvelope: expect.any(Object), titleVersion: 1, legacyTitleUnavailable: false });
    const encryptedSessionTitle = await current.tenant.query<{ title: string | null; title_envelope_version: number }>(
      "SELECT title,title_envelope_version FROM cycle_sessions WHERE id=$1",
      [institutionalSessionId],
    );
    expect(encryptedSessionTitle.rows[0]).toEqual({ title: null, title_envelope_version: 1 });

    await expect(withStore(current, current.actorId, (store) => store.configureCommittee({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 2,
      activeTenantIdentityIds: [current.actorId, current.secondElectorId],
      members: [
        {
          identityId: current.actorId,
          memberId: current.memberIds[0],
          displayEnvelope: envelope("committee-a"),
          roleCode: "chair",
          votingRight: true,
          pastoralCapacity: false,
        },
        {
          identityId: randomUUID(),
          memberId: current.memberIds[1],
          displayEnvelope: envelope("committee-phantom"),
          roleCode: "secretary",
          votingRight: true,
          pastoralCapacity: false,
        },
      ],
    }))).rejects.toMatchObject({ code: "COMMITTEE_IDENTITY_UNAVAILABLE" });

    const committee = await withStore(current, current.actorId, (store) => store.configureCommittee({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 2,
      activeTenantIdentityIds: [current.actorId, current.secondElectorId],
      members: [
        {
          identityId: current.actorId,
          memberId: current.memberIds[0],
          displayEnvelope: envelope("committee-a"),
          roleCode: "chair",
          votingRight: true,
          pastoralCapacity: false,
        },
        {
          identityId: current.secondElectorId,
          memberId: current.memberIds[1],
          displayEnvelope: envelope("committee-b"),
          roleCode: "secretary",
          votingRight: true,
          pastoralCapacity: false,
        },
      ],
    }));
    expect(committee).toMatchObject({ memberCount: 2, votingCount: 2, cycleVersion: 3 });

    await expect(withStore(current, current.actorId, (store) => store.configureElectorate({
      activeTenantIdentityIds: [current.actorId],
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 3,
      electors: [
        { identityId: current.actorId, canPropose: true, canVote: true, recused: false },
        { identityId: current.secondElectorId, canPropose: true, canVote: true, recused: false },
      ],
    }))).rejects.toMatchObject({ code: "ELECTORATE_IDENTITY_UNAVAILABLE" });

    const electorate = await withStore(current, current.actorId, (store) => store.configureElectorate({
      activeTenantIdentityIds: [current.actorId, current.secondElectorId],
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 3,
      electors: [
        { identityId: current.actorId, canPropose: true, canVote: true, recused: false },
        { identityId: current.secondElectorId, canPropose: true, canVote: true, recused: false },
      ],
    }));
    expect(electorate).toMatchObject({ proposalCount: 2, ballotCount: 2, cycleVersion: 4 });

    const processResult = await withStore(current, current.actorId, (store) => store.configureVacancyProcess({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 4,
      configuration: {
        officeId: current.officeId,
        vacancyCount: 1,
        maxProposalSelections: 2,
        maxBallotSelections: 1,
        decisionRule: { kind: "PLURALITY" },
        abstentionRule: "EXCLUDED_FROM_CANDIDATE_TOTALS",
        tiebreakPolicy: "NEW_BALLOT_ROUND",
        quorumRule: { kind: "ALL_REQUIRED" },
        aggregateAudience: "committee",
        agendaOrder: 1,
      },
    }));
    const processId = stringField(processResult, "processId");
    expect(processResult).toMatchObject({ phase: "CONFIGURADO", version: 1, cycleVersion: 5 });

    await expect(withStore(current, current.actorId, (store) => store.activateCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedVersion: 4,
    }))).rejects.toMatchObject({ code: "VERSION_CONFLICT" });
    const activation = await withStore(current, current.actorId, (store) => store.activateCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedVersion: 5,
    }));
    expect(activation).toMatchObject({ status: "active", version: 6 });

    const attendance = await withStore(current, current.actorId, (store) => store.upsertSessionAttendance({
      actorIdentityId: current.actorId,
      idempotencyKey: randomUUID(),
      sessionId: institutionalSessionId,
      identityId: current.actorId,
      activeTenantIdentityIds: [current.actorId, current.secondElectorId],
      expectedVersion: 0,
      memberId: current.memberIds[0],
      presenceStatus: "PRESENT",
      advisory: false,
      votingRight: true,
    }));
    expect(attendance).toMatchObject({ identityId: current.actorId, version: 1, sessionVersion: 2, displayEnvelope: expect.any(Object) });
    await expect(withStore(current, current.actorId, (store) => store.getSession(institutionalSessionId))).resolves.toMatchObject({
      version: 2,
      titleVersion: 1,
      legacyTitleUnavailable: false,
    });
    const updatedSessionTitle = await withStore(current, current.actorId, (store) => store.updateSession({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      sessionId: institutionalSessionId,
      expectedVersion: 2,
      titleEnvelope: envelopeWithAad({ tenantId: current.tenantId, cycleId, sessionId: institutionalSessionId, purpose: "session-title", schemaVersion: 1, titleVersion: 2 }),
    }));
    expect(updatedSessionTitle).toMatchObject({ version: 3, titleVersion: 2, legacyTitleUnavailable: false });
    const agendaItemIdInput = randomUUID();
    const agenda = await withStore(current, current.actorId, (store) => store.addSessionAgendaItem({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      sessionId: institutionalSessionId,
      expectedSessionVersion: 3,
      itemId: agendaItemIdInput,
      position: 1,
      titleEnvelope: envelopeWithAad({ tenantId: current.tenantId, sessionId: institutionalSessionId, agendaItemId: agendaItemIdInput, purpose: "session-agenda-title", schemaVersion: 1, titleVersion: 1 }),
      processId,
      notesEnvelope: envelope("agenda-notes"),
    }));
    const agendaItemId = stringField(agenda, "id");
    expect(agenda).toMatchObject({ status: "pending", version: 1, titleVersion: 1, legacyTitleUnavailable: false, sessionVersion: 4 });
    const startedSession = await withStore(current, current.actorId, (store) => store.transitionSession({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      sessionId: institutionalSessionId,
      expectedVersion: 4,
      operation: "start",
    }));
    expect(startedSession).toMatchObject({ status: "in_progress", version: 5, titleVersion: 2, actualStartedAt: expect.any(Date) });
    await expect(withStore(current, current.actorId, (store) => store.transitionSession({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      sessionId: institutionalSessionId,
      expectedVersion: 5,
      operation: "close",
    }))).rejects.toMatchObject({ code: "SESSION_AGENDA_UNRESOLVED" });
    const sessionDecision = await withStore(current, current.actorId, (store) => store.recordSessionDecision({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      sessionId: institutionalSessionId,
      expectedSessionVersion: 5,
      agendaItemId,
      decisionCode: "INFORMATION_NOTED",
      outcome: "RECORDED",
      evidenceEnvelope: envelope("session-decision"),
    }));
    expect(sessionDecision).toMatchObject({ agendaItemStatus: "decided", agendaItemVersion: 2, sessionVersion: 6 });
    const closedSession = await withStore(current, current.actorId, (store) => store.transitionSession({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      sessionId: institutionalSessionId,
      expectedVersion: 6,
      operation: "close",
    }));
    expect(closedSession).toMatchObject({ status: "closed", version: 7, titleVersion: 2, actualClosedAt: expect.any(Date) });
    const sessionDetail = await withStore(current, current.actorId, (store) => store.getSession(institutionalSessionId));
    expect(sessionDetail).toMatchObject({
      attendance: [expect.objectContaining({ identityId: current.actorId, displayEnvelope: expect.any(Object) })],
      agendaItems: [expect.objectContaining({ id: agendaItemId, status: "decided", decision: expect.objectContaining({ outcome: "RECORDED" }) })],
    });

    const proposalPrepared = await withStore(current, current.actorId, (store) => store.createProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      expectedProcessVersion: 1,
    }));
    const proposalRoundId = stringField(proposalPrepared, "roundId");
    expect(proposalPrepared["electorateHash"]).toMatch(/^sha256:[0-9a-f]{64}$/);
    const proposalOpened = await withStore(current, current.actorId, (store) => store.openProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: proposalRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 1,
    }));
    expect(proposalOpened).toMatchObject({ phase: "PROPUESTAS_ABIERTAS", version: 2, processVersion: 2 });
    await insertOpaqueResponses(current, proposalRoundId, "proposal", [current.actorId, current.secondElectorId]);
    const participation = await withStore(current, current.actorId, (store) => store.getNominalParticipation(proposalRoundId));
    expect(participation?.["participants"]).toEqual(expect.arrayContaining([
      expect.objectContaining({ identityId: current.actorId, status: "received" }),
      expect.objectContaining({ identityId: current.secondElectorId, status: "received" }),
    ]));
    expect(JSON.stringify(participation)).not.toContain(current.memberIds[0]);
    expect(JSON.stringify(participation)).not.toContain(current.memberIds[1]);
    const proposalClosed = await withStore(current, current.actorId, (store) => store.closeProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: proposalRoundId,
      expectedRoundVersion: 2,
      expectedProcessVersion: 2,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }));
    expect(proposalClosed).toMatchObject({ phase: "PROPUESTAS_CERRADAS", version: 3, processVersion: 3 });

    const proposalManifest = await withStore(current, current.actorId, (store) => store.createProposalManifest({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: proposalRoundId,
      expectedRoundVersion: 3,
    }));
    const proposalManifestId = stringField(proposalManifest, "manifestId");
    const proposalManifestHash = stringField(proposalManifest, "manifestHash");
    const downloadableManifest = await withStore(current, current.actorId, (store) => store.getProposalManifest(proposalRoundId));
    expect(downloadableManifest).toMatchObject({
      manifestId: proposalManifestId,
      manifestHash: proposalManifestHash,
      entryCount: 2,
    });
    expect(downloadableManifest?.["entries"]).toHaveLength(2);
    expect(JSON.stringify(downloadableManifest)).not.toContain(current.actorId);
    expect(JSON.stringify(downloadableManifest)).not.toContain(current.secondElectorId);

    const aggregate = normalizeProposalAggregate({
      sourceRoundId: proposalRoundId,
      sourceManifestHash: proposalManifestHash,
      completedResponses: 2,
      electorateDenominator: 2,
      effectiveResponseDenominator: 2,
      maxProposalSelections: 2,
      candidates: [
        { memberId: current.memberIds[0], distinctProponentCount: 2 },
        { memberId: current.memberIds[1], distinctProponentCount: 1 },
      ],
    });
    const consolidated = await withStore(current, current.actorId, (store) => store.consolidateProposals({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: proposalRoundId,
      expectedRoundVersion: 3,
      expectedProcessVersion: 3,
      manifestId: proposalManifestId,
      manifestHash: proposalManifestHash,
      effectiveResponseDenominator: 2,
      aggregateHash: workflowSha256(aggregate),
      candidates: aggregate.candidates,
    }));
    expect(consolidated).toMatchObject({ phase: "DEPURACION", processVersion: 4, roundVersion: 4 });
    const firstCandidacyIds = stringArrayField(consolidated, "candidacyIds");
    expect(firstCandidacyIds).toHaveLength(2);

    for (const [index, candidacyId] of firstCandidacyIds.entries()) {
      const reviewed = await withStore(current, current.actorId, (store) => store.reviewCandidacy({
        identityId: current.actorId,
        idempotencyKey: randomUUID(),
        processId,
        candidacyId,
        expectedVersion: 1,
        toState: "UNDER_REVIEW",
        reasonCode: "REVIEW_STARTED",
        ...(index === 0 ? {
          rationaleEnvelope: envelope("review-rationale-canary"),
          restrictedNoteEnvelope: envelope("restricted-review-note-canary"),
        } : {}),
      }));
      expect(reviewed).toMatchObject({ state: "UNDER_REVIEW", version: 2 });
    }
    const reviewBoard = await withStore(current, current.actorId, (store) => store.getReviewBoard(processId, false));
    expect(reviewBoard?.["candidates"]).toEqual(expect.arrayContaining([
      expect.objectContaining({ distinctProponentCount: 2, electorateDenominator: 2, supportDenominator: 2, supportPercent: 100, photoSnapshot: expect.any(Object) }),
      expect.objectContaining({ distinctProponentCount: 1, electorateDenominator: 2, supportDenominator: 2, supportPercent: 50, photoSnapshot: expect.any(Object) }),
    ]));
    expect(JSON.stringify(reviewBoard)).not.toContain(current.secondElectorId);
    expect(JSON.stringify(reviewBoard)).not.toContain("restrictedNoteEnvelope");
    const ordinaryMaterialRead = await current.tenant.query<{
      actor_identity_id: string | null; request_id: string | null;
      entity_type: string | null; entity_id: string | null;
      metadata: Record<string, unknown>; metadata_text: string;
    }>(
      `SELECT actor_identity_id,request_id,entity_type,entity_id,metadata,metadata::text AS metadata_text
         FROM audit_events
        WHERE action='candidacy.review-material.read' AND entity_id=$1::text
        ORDER BY audit_events.sequence`,
      [processId],
    );
    expect(ordinaryMaterialRead.rows).toEqual([
      expect.objectContaining({
        actor_identity_id: current.actorId,
        request_id: expect.stringMatching(/^[0-9a-f-]{36}$/u),
        entity_type: "office_process",
        entity_id: processId,
        metadata: { photoRecordCount: 2, rationaleRecordCount: 1, processVersion: 4 },
      }),
    ]);
    expect(ordinaryMaterialRead.rows[0]?.metadata_text)
      .not.toMatch(/review-rationale-canary|ciphertext|nonce|aad|envelope|memberId|sha256|hash/iu);
    const unauditedRestrictedRead = await current.tenant.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM audit_events WHERE action='candidacy.private-note.read' AND entity_id=$1::text",
      [processId],
    );
    expect(unauditedRestrictedRead.rows[0]?.count).toBe(0);
    const restrictedReviewBoard = await withStore(current, current.actorId, (store) => store.getReviewBoard(processId, true));
    expect(JSON.stringify(restrictedReviewBoard)).toContain("restrictedNoteEnvelope");
    const restrictedReadAudit = await current.tenant.query<{
      actor_identity_id: string | null; request_id: string | null;
      entity_type: string | null; entity_id: string | null;
      metadata: Record<string, unknown>; metadata_text: string;
    }>(
      `SELECT actor_identity_id,request_id,entity_type,entity_id,metadata,metadata::text AS metadata_text
         FROM audit_events
        WHERE action='candidacy.private-note.read' AND entity_id=$1::text
        ORDER BY audit_events.sequence`,
      [processId],
    );
    expect(restrictedReadAudit.rows).toEqual([
      expect.objectContaining({
        actor_identity_id: current.actorId,
        request_id: expect.stringMatching(/^[0-9a-f-]{36}$/u),
        entity_type: "office_process",
        entity_id: processId,
        metadata: { recordCount: 1, processVersion: 4 },
      }),
    ]);
    expect(restrictedReadAudit.rows[0]?.metadata_text)
      .not.toMatch(/restricted-review-note-canary|ciphertext|nonce|aad|envelope|sha256|hash/iu);
    const materialReadAfterRestrictedResponse = await current.tenant.query<{
      metadata: Record<string, unknown>; metadata_text: string;
    }>(
      `SELECT metadata,metadata::text AS metadata_text
         FROM audit_events
        WHERE action='candidacy.review-material.read' AND entity_id=$1::text
        ORDER BY audit_events.sequence`,
      [processId],
    );
    expect(materialReadAfterRestrictedResponse.rows).toHaveLength(2);
    expect(materialReadAfterRestrictedResponse.rows.every(({ metadata }) => (
      metadata["photoRecordCount"] === 2
      && metadata["rationaleRecordCount"] === 1
      && metadata["processVersion"] === 4
    ))).toBe(true);
    expect(materialReadAfterRestrictedResponse.rows.map(({ metadata_text }) => metadata_text).join(" "))
      .not.toMatch(/review-rationale-canary|ciphertext|nonce|aad|envelope|memberId|sha256|hash/iu);

    for (const candidacyId of firstCandidacyIds) {
      const excluded = await withStore(current, current.actorId, (store) => store.reviewCandidacy({
        identityId: current.actorId,
        idempotencyKey: randomUUID(),
        processId,
        candidacyId,
        expectedVersion: 2,
        toState: "EXCLUDED",
        reasonCode: "COMMITTEE_EXCLUDED",
      }));
      expect(excluded).toMatchObject({ state: "EXCLUDED", version: 3 });
    }
    const emptyCandidateList = await withStore(current, current.actorId, (store) => store.confirmCandidateList({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      expectedProcessVersion: 4,
      orderedCandidacyIds: [],
    }));
    expect(emptyCandidateList).toMatchObject({ candidateCount: 0, phase: "SIN_CANDIDATOS", processVersion: 5 });

    const retryPreparedInput = {
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      expectedProcessVersion: 5,
    };
    const retryPrepared = await withStore(current, current.actorId, (store) => store.createProposalRound(retryPreparedInput));
    const retryReplay = await withStore(current, current.actorId, (store) => store.createProposalRound(retryPreparedInput));
    expect(retryReplay).toEqual(JSON.parse(JSON.stringify(retryPrepared)));
    expect(retryPrepared).toMatchObject({ workflowStage: "proposal", workflowAttempt: 2, phase: "CONFIGURADO", version: 1 });
    const retryRoundId = stringField(retryPrepared, "roundId");
    const retryOpened = await withStore(current, current.actorId, (store) => store.openProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: retryRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 5,
    }));
    expect(retryOpened).toMatchObject({ phase: "PROPUESTAS_ABIERTAS", version: 2, processVersion: 6 });
    await insertOpaqueResponses(current, retryRoundId, "proposal", [current.actorId, current.secondElectorId]);
    const retryClosed = await withStore(current, current.actorId, (store) => store.closeProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: retryRoundId,
      expectedRoundVersion: 2,
      expectedProcessVersion: 6,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }));
    expect(retryClosed).toMatchObject({ phase: "PROPUESTAS_CERRADAS", version: 3, processVersion: 7 });
    const retryManifest = await withStore(current, current.actorId, (store) => store.createProposalManifest({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: retryRoundId,
      expectedRoundVersion: 3,
    }));
    const retryManifestId = stringField(retryManifest, "manifestId");
    const retryManifestHash = stringField(retryManifest, "manifestHash");
    const retryAggregate = normalizeProposalAggregate({
      sourceRoundId: retryRoundId,
      sourceManifestHash: retryManifestHash,
      completedResponses: 2,
      electorateDenominator: 2,
      effectiveResponseDenominator: 2,
      maxProposalSelections: 2,
      candidates: [
        { memberId: current.memberIds[0], distinctProponentCount: 2 },
        { memberId: current.memberIds[1], distinctProponentCount: 1 },
      ],
    });
    const retryConsolidated = await withStore(current, current.actorId, (store) => store.consolidateProposals({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: retryRoundId,
      expectedRoundVersion: 3,
      expectedProcessVersion: 7,
      manifestId: retryManifestId,
      manifestHash: retryManifestHash,
      effectiveResponseDenominator: 2,
      aggregateHash: workflowSha256(retryAggregate),
      candidates: retryAggregate.candidates,
    }));
    expect(retryConsolidated).toMatchObject({ phase: "DEPURACION", processVersion: 8, roundVersion: 4 });
    const candidacyIds = stringArrayField(retryConsolidated, "candidacyIds");
    expect(candidacyIds).toHaveLength(2);
    expect(candidacyIds).not.toEqual(firstCandidacyIds);
    for (const candidacyId of candidacyIds) {
      await withStore(current, current.actorId, (store) => store.reviewCandidacy({
        identityId: current.actorId,
        idempotencyKey: randomUUID(),
        processId,
        candidacyId,
        expectedVersion: 1,
        toState: "UNDER_REVIEW",
        reasonCode: "REVIEW_STARTED",
      }));
    }
    const retryReviewBoard = await withStore(current, current.actorId, (store) => store.getReviewBoard(processId, false));
    expect((retryReviewBoard?.["candidates"] as Array<{ id: string }>).map(({ id }) => id).sort()).toEqual([...candidacyIds].sort());
    const candidateList = await withStore(current, current.actorId, (store) => store.confirmCandidateList({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      expectedProcessVersion: 8,
      orderedCandidacyIds: candidacyIds,
    }));
    expect(candidateList).toMatchObject({ candidateCount: 2, phase: "LISTA_CONFIRMADA", processVersion: 9 });
    expect(candidateList["candidateSetHash"]).toBe(workflowSha256({ candidateIds: [...candidacyIds].sort() }));
    expect(candidateList["rulesHash"]).toBe(workflowSha256({ allowAbstention: true, maxSelections: 1, minSelections: 1 }));

    const ballotPrepared = await withStore(current, current.actorId, (store) => store.prepareBallotRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      expectedProcessVersion: 9,
    }));
    const ballotRoundId = stringField(ballotPrepared, "roundId");
    expect(ballotPrepared).toMatchObject({ phase: "LISTA_CONFIRMADA", version: 1 });
    await insertFrozenCustody(current, ballotRoundId);
    const ballotOpened = await withStore(current, current.actorId, (store) => store.openBallotRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: ballotRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 9,
    }));
    expect(ballotOpened).toMatchObject({ phase: "VOTACION_ABIERTA", version: 2, processVersion: 10 });
    await insertOpaqueResponses(current, ballotRoundId, "vote", [current.actorId, current.secondElectorId]);
    const ballotClosed = await withStore(current, current.actorId, (store) => store.closeBallotRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: ballotRoundId,
      expectedRoundVersion: 2,
      expectedProcessVersion: 10,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }));
    expect(ballotClosed).toMatchObject({ phase: "VOTACION_CERRADA", version: 3, processVersion: 11 });

    const tied = await insertPublishedAggregate(current, ballotRoundId, candidacyIds, null);
    const tieDecision = await withStore(current, current.actorId, (store) => store.createProvisionalAssignments({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      roundId: ballotRoundId,
      expectedProcessVersion: 11,
      expectedAggregateHash: tied.aggregateHash,
    }));
    expect(tieDecision).toMatchObject({
      processId,
      roundId: ballotRoundId,
      aggregateHash: tied.aggregateHash,
      assignments: [],
      phase: "DESEMPATE_PENDIENTE",
      processVersion: 13,
      roundVersion: 5,
    });

    const tiebreakInput = {
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      expectedProcessVersion: 13,
      sourceRoundId: ballotRoundId,
      expectedAggregateHash: tied.aggregateHash,
    };
    const tiebreakPrepared = await withStore(current, current.actorId, (store) => store.prepareTiebreakRound(tiebreakInput));
    const tiebreakReplay = await withStore(current, current.actorId, (store) => store.prepareTiebreakRound(tiebreakInput));
    expect(tiebreakReplay).toEqual(JSON.parse(JSON.stringify(tiebreakPrepared)));
    const tiebreakRoundId = stringField(tiebreakPrepared, "roundId");
    expect(tiebreakPrepared).toMatchObject({
      workflowStage: "tiebreak",
      workflowAttempt: 1,
      sourceRoundId: ballotRoundId,
      sourceAggregateHash: tied.aggregateHash,
      phase: "LISTA_CONFIRMADA",
      version: 1,
      candidateSetHash: workflowSha256({ candidateIds: [...candidacyIds].sort() }),
      rulesHash: workflowSha256({ allowAbstention: true, maxSelections: 1, minSelections: 1 }),
    });
    await insertFrozenCustody(current, tiebreakRoundId);
    const tiebreakOpened = await withStore(current, current.actorId, (store) => store.openBallotRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: tiebreakRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 13,
    }));
    expect(tiebreakOpened).toMatchObject({ workflowStage: "tiebreak", workflowAttempt: 1, phase: "VOTACION_ABIERTA", version: 2, processVersion: 14 });
    await insertOpaqueResponses(current, tiebreakRoundId, "vote", [current.actorId, current.secondElectorId]);
    const tiebreakClosed = await withStore(current, current.actorId, (store) => store.closeBallotRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: tiebreakRoundId,
      expectedRoundVersion: 2,
      expectedProcessVersion: 14,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }));
    expect(tiebreakClosed).toMatchObject({ phase: "VOTACION_CERRADA", version: 3, processVersion: 15 });

    const selectedCandidateId = [...candidacyIds].sort()[0];
    if (!selectedCandidateId) throw new Error("Candidate fixture is empty");
    const published = await insertPublishedAggregate(current, tiebreakRoundId, candidacyIds, selectedCandidateId);
    const provisional = await withStore(current, current.actorId, (store) => store.createProvisionalAssignments({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      roundId: tiebreakRoundId,
      expectedProcessVersion: 15,
      expectedAggregateHash: published.aggregateHash,
    }));
    expect(provisional).toMatchObject({
      processId,
      roundId: tiebreakRoundId,
      aggregateHash: published.aggregateHash,
      phase: "RESULTADO_INTERNO",
      processVersion: 17,
      roundVersion: 5,
    });
    const assignments = provisional["assignments"];
    expect(Array.isArray(assignments)).toBe(true);
    expect(assignments).toHaveLength(1);
    await expect(withStore(current, current.actorId, (store) => store.closeCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedVersion: 6,
    }))).rejects.toMatchObject({ code: "CYCLE_DECISIONS_PENDING" });

    const evidence = await current.tenant.query<{
      assignments: number; aggregate_links: number; proposal_identity_columns: number;
      reviews: number; final_lists: number; source_round: string; source_manifest: string;
      source_hash: string; member_snapshot: boolean; photo_snapshot: boolean; office_snapshot: boolean; proposal_manifest_links: number;
    }>(
      `SELECT
         (SELECT count(*)::int FROM assignments WHERE process_id=$1) AS assignments,
         (SELECT count(*)::int FROM assignments WHERE process_id=$1 AND source_aggregate_hash=$2) AS aggregate_links,
         (SELECT count(*)::int FROM information_schema.columns
           WHERE table_schema='public'
             AND table_name IN ('proposal_manifests','proposal_manifest_entries','proposal_aggregates','candidacies','candidacy_reviews','candidate_list_versions','candidate_list_entries')
             AND column_name = 'elector_identity_id') AS proposal_identity_columns,
         (SELECT count(*)::int FROM proposal_aggregates WHERE process_id=$1 AND source_manifest_id=$3) AS proposal_manifest_links,
         (SELECT count(*)::int FROM candidacy_reviews review JOIN candidacies candidate ON candidate.id=review.candidacy_id WHERE candidate.process_id=$1) AS reviews,
         (SELECT count(*)::int FROM candidate_list_versions WHERE process_id=$1) AS final_lists,
         assignment.source_round_id::text AS source_round,
         assignment.source_manifest_id::text AS source_manifest,
         assignment.source_aggregate_hash AS source_hash,
         assignment.member_snapshot IS NOT NULL AS member_snapshot,
         assignment.member_snapshot ? 'photo' AS photo_snapshot,
         assignment.office_snapshot IS NOT NULL AS office_snapshot
       FROM assignments assignment WHERE assignment.process_id=$1 LIMIT 1`,
      [processId, published.aggregateHash, proposalManifestId],
    );
    expect(evidence.rows[0]).toMatchObject({
      assignments: 1,
      aggregate_links: 1,
      proposal_identity_columns: 0,
      proposal_manifest_links: 1,
      reviews: 8,
      final_lists: 2,
      source_round: tiebreakRoundId,
      source_manifest: published.manifestId,
      source_hash: published.aggregateHash,
      member_snapshot: true,
      photo_snapshot: true,
      office_snapshot: true,
    });

    const assignmentId = stringField((assignments as Record<string, unknown>[])[0] ?? {}, "assignmentId");
    await expect(current.tenant.query(
      "UPDATE assignments SET source_aggregate_hash=$2 WHERE id=$1",
      [assignmentId, `sha256:${"f".repeat(64)}`],
    )).rejects.toMatchObject({ code: "55000" });

    await expect(withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 1,
      status: "ACCEPTED",
      envelope: envelope("consent-direct-accept-forbidden"),
    }))).rejects.toMatchObject({ code: "INVALID_STATE_TRANSITION" });
    await expect(withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 1,
      status: "DECLINED",
      envelope: envelope("consent-direct-decline-forbidden"),
    }))).rejects.toMatchObject({ code: "INVALID_STATE_TRANSITION" });

    await expect(withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 1,
      status: "CONTACTED",
      envelope: envelope("consent-invalid-session"),
      sessionId: randomUUID(),
    }))).rejects.toMatchObject({ code: "ASSIGNMENT_SESSION_INVALID" });
    const consentPending = await withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 1,
      status: "CONTACTED",
      envelope: envelope("consent-contacted"),
      sessionId: institutionalSessionId,
    }));
    expect(consentPending).toMatchObject({ state: "ACEPTACION_PENDIENTE", version: 2 });
    const consentAccepted = await withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 2,
      status: "ACCEPTED",
      envelope: envelope("consent-accepted"),
    }));
    expect(consentAccepted).toMatchObject({ state: "ACEPTADA", version: 3 });
    const presented = await withStore(current, current.actorId, (store) => store.presentAssignment({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 3,
      envelope: envelope("church-presentation"),
    }));
    expect(presented).toMatchObject({ state: "PRESENTADA_A_IGLESIA", version: 4 });
    const elected = await withStore(current, current.actorId, (store) => store.recordCongregationalDecision({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 4,
      outcome: "ELECTED",
      envelope: envelope("church-elected"),
    }));
    expect(elected).toMatchObject({ state: "ELEGIDA_POR_IGLESIA", version: 5 });
    const activatedAssignment = await withStore(current, current.actorId, (store) => store.activateAssignment({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 5,
    }));
    expect(activatedAssignment).toMatchObject({ state: "VIGENTE", version: 6 });

    const historyBeforeRename = await withStore(current, current.actorId, (store) => store.getAssignmentHistory(assignmentId));
    const historyAssignment = historyBeforeRename?.["assignment"] as Record<string, unknown>;
    const frozenMember = historyAssignment?.["memberSnapshot"];
    const frozenOffice = historyAssignment?.["officeSnapshot"];
    const assignedMemberId = stringField(historyAssignment, "memberId");
    const renamedDisplayEnvelope = memberDisplayEnvelope(current.tenantId, assignedMemberId);
    await current.tenant.query(
      "UPDATE members SET display_envelope=$2,display_content_hash=$3,version=version+1 WHERE id=$1",
      [assignedMemberId, renamedDisplayEnvelope, envelopeContentHash(renamedDisplayEnvelope)],
    );
    await current.tenant.query("UPDATE offices SET names=$2,version=version+1 WHERE id=$1", [current.officeId, { es: "Cargo renombrado", en: "Renamed office", fr: "Fonction renommée" }]);
    const historyAfterRename = await withStore(current, current.actorId, (store) => store.getAssignmentHistory(assignmentId));
    expect((historyAfterRename?.["assignment"] as Record<string, unknown>)?.["memberSnapshot"]).toEqual(frozenMember);
    expect((historyAfterRename?.["assignment"] as Record<string, unknown>)?.["officeSnapshot"]).toEqual(frozenOffice);

    const internalReport = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "office_round",
      audience: "committee",
      cycleId,
      includeNominalParticipation: false,
      viewerPermissions: ["aggregate.read", "member.read", "candidate.review", "consent.record"],
    }));
    expect(internalReport).toMatchObject({
      cycle: { id: cycleId },
      candidacies: expect.arrayContaining([expect.objectContaining({ supportDenominator: 2, photoSnapshot: expect.any(Object) })]),
      publishedAggregates: expect.arrayContaining([
        expect.objectContaining({ roundId: ballotRoundId, aggregateHash: tied.aggregateHash }),
        expect.objectContaining({ roundId: tiebreakRoundId, aggregateHash: published.aggregateHash }),
      ]),
      committee: [],
      participation: [],
      redactions: expect.arrayContaining(["nominal_participation", "audit_actors", "reasons_and_notes"]),
    });
    expect(JSON.stringify(internalReport)).not.toContain("electorIdentityId");
    expect(JSON.stringify(internalReport)).not.toContain("elector_identity_id");

    const cycleOrganizationReport = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "general_recommendations",
      audience: "committee",
      cycleId,
      includeNominalParticipation: false,
      viewerPermissions: ["aggregate.read", "organigram.read"],
    }));
    expect(cycleOrganizationReport).toMatchObject({
      cycle: { id: cycleId },
      metrics: {
        vacanciesTotal: 1,
        recommended: 1,
        accepted: 1,
        congregationallyElected: 1,
        coveragePercent: 100,
      },
      organization: [expect.objectContaining({
        officeId: current.officeId,
        status: "elected",
        memberId: assignedMemberId,
        memberSnapshot: frozenMember,
        officeNames: (frozenOffice as Record<string, unknown>)["names"],
      })],
    });

    const minimumAggregateReport = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "office_round",
      audience: "committee",
      cycleId,
      includeNominalParticipation: false,
      viewerPermissions: ["aggregate.read"],
    }));
    expect(minimumAggregateReport).toMatchObject({
      candidacies: [],
      candidacyReviews: [],
      publishedAggregates: expect.arrayContaining([expect.objectContaining({ aggregateHash: published.aggregateHash })]),
      assignments: [expect.objectContaining({ id: assignmentId, state: "VIGENTE" })],
    });
    const minimumSerialized = JSON.stringify(minimumAggregateReport);
    expect(minimumSerialized).not.toMatch(/memberId|memberSnapshot|displayEnvelope|photoSnapshot|consentStatus|actorIdentityId|reasonCode/u);

    const rosterOnlyReport = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "roster_import_incidents",
      audience: "committee",
      cycleId,
      includeNominalParticipation: false,
      viewerPermissions: ["member.read", "member.import"],
    }));
    expect(rosterOnlyReport).toMatchObject({ metrics: null, organization: [], processes: [], rounds: [], assignments: [] });
    expect(JSON.stringify(rosterOnlyReport)).not.toMatch(/memberSnapshot|displayEnvelope|recommended|accepted|coveragePercent/u);

    const churchReport = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "progress",
      audience: "church",
      cycleId,
      includeNominalParticipation: false,
      viewerPermissions: ["aggregate.read", "organigram.read", "member.read"],
    }));
    expect(churchReport).toMatchObject({
      metrics: { vacanciesTotal: 1, congregationallyElected: 1 },
      organization: [expect.objectContaining({ status: "elected", memberId: assignedMemberId, memberSnapshot: frozenMember })],
      candidacies: [], candidacyReviews: [], publishedAggregates: [], eligibleMembers: [], committee: [], participation: [],
    });
    expect(JSON.stringify(churchReport)).not.toMatch(/distinctProponentCount|effectiveResponseDenominator|abstentions|reasonCode|actorIdentityId/u);
    expect(JSON.stringify(churchReport)).not.toMatch(/"recommended"|"accepted"|coveragePercent|membersTotal|eligibleReference/u);

    const nominalReport = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "committee_participation",
      audience: "auditor",
      cycleId,
      includeNominalParticipation: true,
      viewerPermissions: ["member.read", "participation.nominal.read"],
    }));
    expect(nominalReport).toMatchObject({
      committee: expect.arrayContaining([expect.objectContaining({ identityId: current.actorId })]),
      participation: expect.arrayContaining([expect.objectContaining({ identityId: current.actorId, status: "received" })]),
      redactions: expect.not.arrayContaining(["nominal_participation"]),
    });
    expect(JSON.stringify(nominalReport)).not.toMatch(/selections|preference|ballotEnvelope/u);

    const sessionIndex = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "session_minutes",
      audience: "committee",
      cycleId,
      includeNominalParticipation: false,
      viewerPermissions: ["aggregate.read", "member.read"],
    }));
    expect(sessionIndex).toMatchObject({
      sessions: expect.arrayContaining([expect.objectContaining({ id: institutionalSessionId, status: "closed" })]),
      sessionMinutes: null,
      transitions: [],
    });

    const sessionMinutes = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "session_minutes",
      audience: "committee",
      cycleId,
      sessionId: institutionalSessionId,
      includeNominalParticipation: false,
      viewerPermissions: ["aggregate.read", "member.read"],
    }));
    expect(sessionMinutes).toMatchObject({
      sessions: expect.arrayContaining([expect.objectContaining({ id: institutionalSessionId, status: "closed" })]),
      sessionMinutes: {
        id: institutionalSessionId,
        attendance: [expect.objectContaining({ identityId: current.actorId, displayEnvelope: expect.any(Object) })],
        agendaItems: [expect.objectContaining({ id: agendaItemId, decision: expect.objectContaining({ outcome: "RECORDED" }) })],
      },
      transitions: expect.arrayContaining([expect.objectContaining({ sessionId: institutionalSessionId })]),
    });
    expect(JSON.stringify(sessionMinutes)).not.toMatch(/agenda-notes|session-decision/u);

    const churchMinutes = await withStore(current, current.actorId, (store) => store.getWorkflowReportSnapshot({
      reportType: "session_minutes",
      audience: "church",
      cycleId,
      sessionId: institutionalSessionId,
      includeNominalParticipation: false,
      viewerPermissions: ["aggregate.read", "member.read", "audit.read", "private-note.read"],
    }));
    expect(churchMinutes).toMatchObject({
      sessionMinutes: {
        id: institutionalSessionId,
        attendance: [],
        agendaItems: [expect.objectContaining({ decision: expect.objectContaining({ outcome: "RECORDED" }) })],
      },
      publishedAggregates: [],
    });
    expect(JSON.stringify(churchMinutes)).not.toMatch(/displayEnvelope|photoSnapshot|reasonCode|actorIdentityId|notesEnvelope|evidenceEnvelope/u);

    const snapshotReadAudit = await current.tenant.query<{
      actor_identity_id: string | null; request_id: string | null;
      entity_type: string | null; entity_id: string | null;
      metadata: Record<string, unknown>; metadata_text: string;
    }>(
      `SELECT actor_identity_id,request_id,entity_type,entity_id,metadata,metadata::text AS metadata_text
         FROM audit_events
        WHERE action='workflow-report.snapshot.read' AND entity_id=$1::text
        ORDER BY audit_events.sequence`,
      [cycleId],
    );
    expect(snapshotReadAudit.rows).toHaveLength(7);
    expect(snapshotReadAudit.rows.every((event) => event.actor_identity_id === current.actorId)).toBe(true);
    expect(snapshotReadAudit.rows.every((event) => event.request_id !== null)).toBe(true);
    expect(snapshotReadAudit.rows.every((event) => event.entity_type === "election_cycle" && event.entity_id === cycleId)).toBe(true);
    expect(snapshotReadAudit.rows.every((event) => (
      Object.keys(event.metadata).sort().join(",") === "audience,classification,cycleVersion,reportType"
    ))).toBe(true);
    expect(snapshotReadAudit.rows.some(({ metadata }) => metadata["reportType"] === "roster_import_incidents")).toBe(false);
    expect(snapshotReadAudit.rows.some(({ metadata }) => (
      metadata["reportType"] === "progress"
      && metadata["audience"] === "church"
      && metadata["classification"] === "congregational-personal"
    ))).toBe(true);
    expect(snapshotReadAudit.rows.map(({ metadata_text }) => metadata_text).join(" "))
      .not.toMatch(/ciphertext|nonce|aad|envelope|memberId|candidateSetHash|rulesHash|sha256/iu);
    const snapshotOutbox = await current.tenant.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM outbox_events WHERE event_type='workflow-report.snapshot.read'",
    );
    expect(snapshotOutbox.rows[0]?.count).toBe(0);

    const substituted = await withStore(current, current.actorId, (store) => store.substituteAssignment({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId,
      expectedVersion: 6,
      reasonCode: "ASSIGNMENT_REPLACED",
      evidenceEnvelope: envelope("substitution-evidence"),
    }));
    expect(substituted).toMatchObject({ state: "SUSTITUIDA", version: 7, vacancyOpened: true });
    expect(substituted["replacementProcess"]).toMatchObject({
      phase: "VACANTE_PENDIENTE",
      procedureSequence: 2,
      reusedVacancyId: expect.any(String),
      replacementForAssignmentId: assignmentId,
    });
    const completedHistory = await withStore(current, current.actorId, (store) => store.getAssignmentHistory(assignmentId));
    expect(completedHistory?.["transitions"]).toHaveLength(8);
    expect(completedHistory?.["transitions"]).toEqual(expect.arrayContaining([
      expect.objectContaining({ action: "CONSENT_RECORDED", sessionId: institutionalSessionId }),
    ]));
    expect(completedHistory?.["replacementProcesses"]).toEqual([
      expect.objectContaining({ phase: "VACANTE_PENDIENTE", procedureSequence: 2 }),
    ]);
    const transitionId = stringField(((completedHistory?.["transitions"] as Record<string, unknown>[])?.[0]) ?? {}, "id");
    await expect(current.tenant.query(
      "UPDATE assignment_transitions SET reason_code='ILLEGAL_REWRITE' WHERE id=$1",
      [transitionId],
    )).rejects.toMatchObject({ code: "55000" });

    const acceptedThenDeclined = await insertLifecycleAssignment(current, {
      cycleId, processId, memberId: current.memberIds[0], ordinal: 7, state: "ACEPTADA",
    });
    await expect(withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: acceptedThenDeclined,
      expectedVersion: 1,
      status: "DECLINED",
      envelope: envelope("accepted-then-declined"),
    }))).resolves.toMatchObject({ state: "DECLINADA", version: 2, replacementProcess: { phase: "VACANTE_PENDIENTE" } });
    const acceptedThenWithdrawn = await insertLifecycleAssignment(current, {
      cycleId, processId, memberId: current.memberIds[0], ordinal: 8, state: "ACEPTADA",
    });
    await expect(withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: acceptedThenWithdrawn,
      expectedVersion: 1,
      status: "WITHDRAWN",
      envelope: envelope("accepted-then-withdrawn"),
    }))).resolves.toMatchObject({ state: "RETIRADA", version: 2, replacementProcess: { phase: "VACANTE_PENDIENTE" } });

    const congregationVariant = await insertLifecycleAssignment(current, {
      cycleId, processId, memberId: current.memberIds[0], ordinal: 2, state: "PRESENTADA_A_IGLESIA",
    });
    const deferred = await withStore(current, current.actorId, (store) => store.recordCongregationalDecision({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: congregationVariant,
      expectedVersion: 1,
      outcome: "DEFERRED",
      envelope: envelope("church-deferred"),
    }));
    expect(deferred).toMatchObject({ state: "PRESENTADA_A_IGLESIA", version: 2, replacementProcess: null });
    const notElected = await withStore(current, current.actorId, (store) => store.recordCongregationalDecision({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: congregationVariant,
      expectedVersion: 2,
      outcome: "NOT_ELECTED",
      envelope: envelope("church-not-elected"),
    }));
    expect(notElected).toMatchObject({ state: "DEVUELTA_A_COMISION", version: 3, replacementProcess: { phase: "VACANTE_PENDIENTE" } });

    const closedTerm = await insertLifecycleAssignment(current, {
      cycleId, processId, memberId: current.memberIds[0], ordinal: 3, state: "VIGENTE",
    });
    const finalizedWithoutVacancy = await withStore(current, current.actorId, (store) => store.finalizeAssignment({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: closedTerm,
      expectedVersion: 1,
      reasonCode: "TERM_COMPLETED_NO_VACANCY",
      openVacancy: false,
      evidenceEnvelope: envelope("term-completed"),
    }));
    expect(finalizedWithoutVacancy).toMatchObject({ state: "FINALIZADA", version: 2, vacancyOpened: false, replacementProcess: null });

    const openTerm = await insertLifecycleAssignment(current, {
      cycleId, processId, memberId: current.memberIds[0], ordinal: 4, state: "VIGENTE",
    });
    const finalizedWithVacancy = await withStore(current, current.actorId, (store) => store.finalizeAssignment({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: openTerm,
      expectedVersion: 1,
      reasonCode: "TERM_COMPLETED_OPEN_VACANCY",
      openVacancy: true,
      evidenceEnvelope: envelope("term-open-vacancy"),
    }));
    expect(finalizedWithVacancy).toMatchObject({ state: "FINALIZADA", version: 2, vacancyOpened: true, replacementProcess: { phase: "VACANTE_PENDIENTE" } });

    const linkedOfficeId = randomUUID();
    const linkedProcessId = randomUUID();
    const linkedVacancyId = randomUUID();
    await current.tenant.query(
      `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality,catalog_metadata)
       SELECT $1,department_id,'WORKFLOW_LINKED_OFFICE',$2,'linked_designation',1,$3
         FROM offices WHERE id=$4`,
      [linkedOfficeId, { es: "Responsabilidad vinculada", en: "Linked responsibility", fr: "Responsabilité liée" }, { linkedBaseOfficeCode: "WORKFLOW_TEST_OFFICE" }, current.officeId],
    );
    await current.tenant.query(
      `INSERT INTO office_processes(
         id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
         decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,agenda_order,created_by_identity_id
       ) VALUES ($1,$2,$3,'ANULADO',1,1,1,$4,'EXCLUDED_FROM_CANDIDATE_TOTALS','NEW_BALLOT_ROUND',$5,'committee',
                (SELECT coalesce(max(agenda_order),0)+1 FROM office_processes WHERE cycle_id=$2),$6)`,
      [linkedProcessId, cycleId, linkedOfficeId, { kind: "PLURALITY" }, { kind: "ALL_REQUIRED" }, current.actorId],
    );
    await current.tenant.query(
      "INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status,process_id) VALUES ($1,$2,$3,1,'pending',$4)",
      [linkedVacancyId, cycleId, linkedOfficeId, linkedProcessId],
    );

    const clone = await withStore(current, current.actorId, (store) => store.cloneCycle({
      ...cycleInput,
      idempotencyKey: randomUUID(),
      sourceCycleId: cycleId,
      name: "Cloned structure only",
      termStart: "2036-01-01",
      termEnd: "2037-12-31",
    }));
    const clonedCycleId = stringField(clone, "id");
    expect(clone).toMatchObject({ processCount: 2, copiedSubmissions: 0, copiedAssignments: 0 });
    const copied = await current.tenant.query<{ processes: number; submissions: number; assignments: number }>(
      `SELECT
         (SELECT count(*)::int FROM office_processes WHERE cycle_id=$1) AS processes,
         (SELECT count(*)::int FROM encrypted_submissions submission JOIN rounds round_state ON round_state.id=submission.round_id WHERE round_state.cycle_id=$1) AS submissions,
         (SELECT count(*)::int FROM assignments WHERE cycle_id=$1) AS assignments`,
      [clonedCycleId],
    );
    expect(copied.rows[0]).toEqual({ processes: 2, submissions: 0, assignments: 0 });

    const clonedSessionId = randomUUID();
    const clonedSession = await withStore(current, current.actorId, (store) => store.addSession({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId: clonedCycleId,
      sessionId: clonedSessionId,
      expectedCycleVersion: 1,
      sequence: 1,
      titleEnvelope: envelopeWithAad({ tenantId: current.tenantId, cycleId: clonedCycleId, sessionId: clonedSessionId, purpose: "session-title", schemaVersion: 1, titleVersion: 1 }),
      startsAt: "2036-10-01T18:00:00-04:00",
      endsAt: "2036-10-01T20:00:00-04:00",
    }));
    const clonedInstitutionalSessionId = stringField(clonedSession, "id");
    expect(clonedSession["cycleVersion"]).toBe(2);
    const clonedCommittee = await withStore(current, current.actorId, (store) => store.configureCommittee({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId: clonedCycleId,
      expectedCycleVersion: 2,
      activeTenantIdentityIds: [current.actorId, current.secondElectorId],
      members: [
        {
          identityId: current.actorId,
          memberId: current.memberIds[0],
          displayEnvelope: envelope("cloned-committee-a"),
          roleCode: "chair",
          votingRight: true,
          pastoralCapacity: false,
        },
        {
          identityId: current.secondElectorId,
          memberId: current.memberIds[1],
          displayEnvelope: envelope("cloned-committee-b"),
          roleCode: "secretary",
          votingRight: true,
          pastoralCapacity: false,
        },
      ],
    }));
    expect(clonedCommittee["cycleVersion"]).toBe(3);
    const clonedElectorate = await withStore(current, current.actorId, (store) => store.configureElectorate({
      activeTenantIdentityIds: [current.actorId, current.secondElectorId],
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId: clonedCycleId,
      expectedCycleVersion: 3,
      electors: [
        { identityId: current.actorId, canPropose: true, canVote: true, recused: false },
        { identityId: current.secondElectorId, canPropose: true, canVote: true, recused: false },
      ],
    }));
    expect(clonedElectorate["cycleVersion"]).toBe(4);

    const closeInput = {
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedVersion: 6,
    };
    const closedCycle = await withStore(current, current.actorId, (store) => store.closeCycle(closeInput));
    const closeReplay = await withStore(current, current.actorId, (store) => store.closeCycle(closeInput));
    expect(closeReplay).toEqual(JSON.parse(JSON.stringify(closedCycle)));
    expect(closedCycle).toMatchObject({ id: cycleId, status: "closed", version: 7, closedAt: expect.anything() });

    const archiveInput = {
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedVersion: 7,
    };
    const archivedCycle = await withStore(current, current.actorId, (store) => store.archiveCycle(archiveInput));
    const archiveReplay = await withStore(current, current.actorId, (store) => store.archiveCycle(archiveInput));
    expect(archiveReplay).toEqual(JSON.parse(JSON.stringify(archivedCycle)));
    expect(archivedCycle).toMatchObject({ id: cycleId, status: "archived", version: 8, archivedAt: expect.anything() });
    const archivedWorkflow = await withStore(current, current.actorId, (store) => store.getCycleWorkflow(cycleId));
    expect(archivedWorkflow).toMatchObject({ cycle: { id: cycleId, status: "archived", version: 8 } });
    expect(archivedWorkflow?.["rounds"]).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: retryRoundId, workflow_attempt: 2 }),
      expect.objectContaining({ id: tiebreakRoundId, workflow_stage: "tiebreak" }),
    ]));

    const activatedClone = await withStore(current, current.actorId, (store) => store.activateCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId: clonedCycleId,
      expectedVersion: 4,
    }));
    expect(activatedClone).toMatchObject({ id: clonedCycleId, status: "active", version: 5 });

    const clonedBaseProcess = await current.tenant.query<{ id: string; version: number }>(
      "SELECT id,version FROM office_processes WHERE cycle_id=$1 AND office_id=$2 AND phase='CONFIGURADO'",
      [clonedCycleId, current.officeId],
    );
    const clonedBaseProcessId = clonedBaseProcess.rows[0]?.id ?? "";
    const frozenRound = await withStore(current, current.actorId, (store) => store.createProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId: clonedBaseProcessId,
      expectedProcessVersion: 1,
    }));
    const frozenRoundId = stringField(frozenRound, "roundId");
    await withStore(current, current.actorId, (store) => store.openProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: frozenRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 1,
    }));
    const frozenBefore = await current.tenant.query<{
      candidate_set_hash: string; electorate_hash: string; candidates: number; denominator: number;
    }>(
      `SELECT round_state.candidate_set_hash,round_state.electorate_hash,
              (SELECT count(*)::int FROM candidate_snapshots WHERE round_id=round_state.id) AS candidates,
              (SELECT count(*)::int FROM round_elector_snapshots WHERE round_id=round_state.id AND can_submit AND NOT recused) AS denominator
         FROM rounds round_state WHERE round_state.id=$1`,
      [frozenRoundId],
    );
    expect(frozenBefore.rows[0]).toMatchObject({ candidates: 2, denominator: 2 });

    await current.tenant.query(
      "UPDATE cycle_elector_roster SET active=false,version=version+1 WHERE cycle_id=$1 AND identity_id=$2",
      [clonedCycleId, current.secondElectorId],
    );
    const currentMemberVersion = await current.tenant.query<{ version: number }>(
      "SELECT version FROM members WHERE id=$1",
      [current.memberIds[1]],
    );
    const eligibilityChange = await withTenantStore(current, current.actorId, (store) => store.updateMember({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      memberId: current.memberIds[1],
      expectedVersion: currentMemberVersion.rows[0]?.version ?? 0,
      eligibilityStatus: "ineligible",
      eligibilityEnvelope: envelope("member-b-ineligible"),
    }));
    const pause = ((eligibilityChange["pausedWorkflows"] as Record<string, unknown>[] | undefined) ?? [])[0] ?? {};
    const pauseId = stringField(pause, "pauseId");
    expect(pause).toMatchObject({
      processId: clonedBaseProcessId,
      roundId: frozenRoundId,
      previousProcessPhase: "PROPUESTAS_ABIERTAS",
      previousRoundPhase: "PROPUESTAS_ABIERTAS",
      processVersion: 3,
      roundVersion: 3,
    });
    const frozenAfterPause = await current.tenant.query<{
      phase: string; version: number; candidate_set_hash: string; electorate_hash: string;
      candidates: number; denominator: number;
    }>(
      `SELECT round_state.phase,round_state.version,round_state.candidate_set_hash,round_state.electorate_hash,
              (SELECT count(*)::int FROM candidate_snapshots WHERE round_id=round_state.id) AS candidates,
              (SELECT count(*)::int FROM round_elector_snapshots WHERE round_id=round_state.id AND can_submit AND NOT recused) AS denominator
         FROM rounds round_state WHERE round_state.id=$1`,
      [frozenRoundId],
    );
    expect(frozenAfterPause.rows[0]).toEqual({
      phase: "PAUSADO",
      version: 3,
      candidate_set_hash: frozenBefore.rows[0]?.candidate_set_hash,
      electorate_hash: frozenBefore.rows[0]?.electorate_hash,
      candidates: 2,
      denominator: 2,
    });
    const restoredMember = await withTenantStore(current, current.actorId, (store) => store.updateMember({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      memberId: current.memberIds[1],
      expectedVersion: Number(eligibilityChange["version"]),
      eligibilityStatus: "eligible",
      eligibilityEnvelope: envelope("member-b-restored"),
    }));
    expect(restoredMember["pausedWorkflows"]).toEqual([]);
    await expect(withStore(current, current.actorId, (store) => store.resolveEligibilityPause({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId: clonedBaseProcessId,
      expectedProcessVersion: 3,
      expectedRoundVersion: 3,
      expectedPauseIds: [pauseId],
      resolutionCode: "RESUME_UNCHANGED",
      reasonCode: "ELIGIBILITY_PROCESS_RESUMED",
      evidenceEnvelope: envelope("unsafe-resume-rejected"),
    }))).rejects.toMatchObject({ code: "OPEN_ROUND_REQUIRES_ANNULMENT" });
    const resolvedPause = await withStore(current, current.actorId, (store) => store.resolveEligibilityPause({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId: clonedBaseProcessId,
      expectedProcessVersion: 3,
      expectedRoundVersion: 3,
      expectedPauseIds: [pauseId],
      resolutionCode: "ANNUL_AND_RESTART",
      reasonCode: "ELIGIBILITY_ROUND_RESTARTED",
      evidenceEnvelope: envelope("eligibility-resolution"),
    }));
    expect(resolvedPause).toMatchObject({
      resolutionCode: "ANNUL_AND_RESTART",
      processPhase: "CONFIGURADO",
      processVersion: 4,
      roundId: frozenRoundId,
      roundVersion: 4,
      replacementRound: { phase: "CONFIGURADO", version: 1, workflowAttempt: 2 },
    });
    const replacementRoundId = stringField(resolvedPause["replacementRound"] as Record<string, unknown>, "roundId");
    const frozenAfterResolution = await current.tenant.query<{
      phase: string; candidate_set_hash: string; electorate_hash: string; candidates: number; denominator: number;
    }>(
      `SELECT round_state.phase,round_state.candidate_set_hash,round_state.electorate_hash,
              (SELECT count(*)::int FROM candidate_snapshots WHERE round_id=round_state.id) AS candidates,
              (SELECT count(*)::int FROM round_elector_snapshots WHERE round_id=round_state.id AND can_submit AND NOT recused) AS denominator
         FROM rounds round_state WHERE round_state.id=$1`,
      [frozenRoundId],
    );
    expect(frozenAfterResolution.rows[0]).toEqual({
      phase: "ANULADO",
      candidate_set_hash: frozenBefore.rows[0]?.candidate_set_hash,
      electorate_hash: frozenBefore.rows[0]?.electorate_hash,
      candidates: 2,
      denominator: 2,
    });
    const replacementFreeze = await current.tenant.query<{
      phase: string; candidate_set_hash: string; electorate_hash: string; candidates: number; denominator: number;
    }>(
      `SELECT round_state.phase,round_state.candidate_set_hash,round_state.electorate_hash,
              (SELECT count(*)::int FROM candidate_snapshots WHERE round_id=round_state.id) AS candidates,
              (SELECT count(*)::int FROM round_elector_snapshots WHERE round_id=round_state.id AND can_submit AND NOT recused) AS denominator
         FROM rounds round_state WHERE round_state.id=$1`,
      [replacementRoundId],
    );
    expect(replacementFreeze.rows[0]).toMatchObject({ phase: "CONFIGURADO", candidates: 2, denominator: 1 });
    expect(replacementFreeze.rows[0]?.electorate_hash).not.toBe(frozenBefore.rows[0]?.electorate_hash);
    const resolutionRecord = await current.tenant.query<{
      resolution_code: string; resolution_reason_code: string; replacement_round_id: string;
      resolution_evidence_envelope: Record<string, unknown>;
    }>(
      `SELECT resolution_code,resolution_reason_code,replacement_round_id,resolution_evidence_envelope
         FROM member_eligibility_workflow_pauses WHERE id=$1`,
      [pauseId],
    );
    expect(resolutionRecord.rows[0]).toMatchObject({
      resolution_code: "ANNUL_AND_RESTART",
      resolution_reason_code: "ELIGIBILITY_ROUND_RESTARTED",
      replacement_round_id: replacementRoundId,
      resolution_evidence_envelope: expect.any(Object),
    });
    await expect(current.tenant.query(
      "UPDATE member_eligibility_workflow_pauses SET resolution_reason_code='ILLEGAL_REWRITE' WHERE id=$1",
      [pauseId],
    )).rejects.toMatchObject({ code: "55000" });

    await withStore(current, current.actorId, (store) => store.openProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: replacementRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 4,
    }));
    const replacementRound = await current.tenant.query<{ candidate_set_hash: string; rules_hash: string }>(
      "SELECT candidate_set_hash,rules_hash FROM rounds WHERE id=$1",
      [replacementRoundId],
    );
    const nonElectorEnvelope = envelopeWithAad({
      tenantId: current.tenantId,
      cycleId: clonedCycleId,
      roundId: replacementRoundId,
      purpose: "proposal",
      schemaVersion: 1,
      roundVersion: 2,
      candidateSetHash: replacementRound.rows[0]?.candidate_set_hash,
      rulesHash: replacementRound.rows[0]?.rules_hash,
    });
    await expect(withTenantStore(current, current.secondElectorId, (store) => store.submit({
      identityId: current.secondElectorId,
      idempotencyKey: randomUUID(),
      roundId: replacementRoundId,
      kind: "proposal",
      expectedVersion: 2,
      envelope: nonElectorEnvelope,
      contentHash: `sha256:${createHash("sha256").update(JSON.stringify(nonElectorEnvelope), "utf8").digest("hex")}`,
    }))).rejects.toMatchObject({ code: "NOT_AN_ELECTOR" });

    const clonedLinkedProcess = await current.tenant.query<{ id: string }>(
      "SELECT id FROM office_processes WHERE cycle_id=$1 AND office_id=$2 AND phase='CONFIGURADO'",
      [clonedCycleId, linkedOfficeId],
    );
    await expect(withStore(current, current.actorId, (store) => store.createProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId: clonedLinkedProcess.rows[0]?.id ?? "",
      expectedProcessVersion: 1,
    }))).rejects.toMatchObject({ code: "LINKED_DESIGNATION_DIRECT_ELECTION" });

    const clonedBaseVacancy = await current.tenant.query<{ id: string }>(
      "SELECT id FROM vacancies WHERE process_id=$1 ORDER BY ordinal LIMIT 1",
      [clonedBaseProcessId],
    );
    const baseAssignmentId = randomUUID();
    const [baseMemberSnapshot, baseOfficeSnapshot] = await assignmentSnapshots(
      current,
      current.memberIds[0],
      "cloned-base-member",
    );
    await current.tenant.query(
      `INSERT INTO assignments(
         id,vacancy_id,member_id,state,effective,independent,cycle_id,office_id,process_id,
         member_snapshot,office_snapshot
       ) VALUES ($1,$2,$3,'ACEPTADA',true,true,$4,$5,$6,$7,$8)`,
      [
        baseAssignmentId,
        clonedBaseVacancy.rows[0]?.id,
        current.memberIds[0],
        clonedCycleId,
        current.officeId,
        clonedBaseProcessId,
        baseMemberSnapshot,
        baseOfficeSnapshot,
      ],
    );
    await current.tenant.query("UPDATE vacancies SET status='accepted' WHERE id=$1", [clonedBaseVacancy.rows[0]?.id]);
    const linkedDesignation = await withStore(current, current.actorId, (store) => store.createLinkedDesignation({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId: clonedLinkedProcess.rows[0]?.id ?? "",
      expectedProcessVersion: 1,
      baseAssignmentId,
      evidenceEnvelope: envelope("linked-designation-decision"),
      sessionId: clonedInstitutionalSessionId,
    }));
    expect(linkedDesignation).toMatchObject({
      baseAssignmentId,
      memberId: current.memberIds[0],
      state: "PROPUESTA_INTERNA",
      independent: false,
      processPhase: "RESULTADO_INTERNO",
      processVersion: 2,
      workload: { independent_count: 1, nominal_count: 2 },
    });
    const linkedAssignmentId = stringField(linkedDesignation, "assignmentId");
    const linkedEvidence = await current.tenant.query<{
      independent: boolean; linked_to_assignment_id: string; source_round_id: string | null;
      source_manifest_id: string | null; source_candidate_id: string | null; action: string;
      evidence_present: boolean; rounds: number;
    }>(
      `SELECT assignment.independent,assignment.linked_to_assignment_id,assignment.source_round_id,
              assignment.source_manifest_id,assignment.source_candidate_id,transition.action,
              transition.evidence_envelope IS NOT NULL AS evidence_present,
              (SELECT count(*)::int FROM rounds WHERE process_id=assignment.process_id) AS rounds
         FROM assignments assignment
         JOIN assignment_transitions transition ON transition.assignment_id=assignment.id
        WHERE assignment.id=$1`,
      [linkedAssignmentId],
    );
    expect(linkedEvidence.rows[0]).toEqual({
      independent: false,
      linked_to_assignment_id: baseAssignmentId,
      source_round_id: null,
      source_manifest_id: null,
      source_candidate_id: null,
      action: "LINKED_DESIGNATION_CREATED",
      evidence_present: true,
      rounds: 0,
    });
    const linkedContact = await withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: linkedAssignmentId,
      expectedVersion: 1,
      status: "CONTACTED",
      envelope: envelope("linked-contact"),
    }));
    expect(linkedContact).toMatchObject({ state: "ACEPTACION_PENDIENTE", version: 2 });
    await expect(withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: linkedAssignmentId,
      expectedVersion: 2,
      status: "ACCEPTED",
      envelope: envelope("linked-accepted"),
    }))).resolves.toMatchObject({ state: "ACEPTADA", version: 3 });

    const linkedMemberVersion = await current.tenant.query<{ version: number }>(
      "SELECT version FROM members WHERE id=$1",
      [current.memberIds[0]],
    );
    const linkedEligibilityChange = await withTenantStore(current, current.actorId, (store) => store.updateMember({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      memberId: current.memberIds[0],
      expectedVersion: linkedMemberVersion.rows[0]?.version ?? 0,
      eligibilityStatus: "ineligible",
      eligibilityEnvelope: envelope("linked-member-ineligible"),
    }));
    const linkedPause = ((linkedEligibilityChange["pausedWorkflows"] as Record<string, unknown>[] | undefined) ?? [])
      .find(({ processId }) => processId === clonedLinkedProcess.rows[0]?.id) ?? {};
    const linkedPauseId = stringField(linkedPause, "pauseId");
    expect(linkedPause).toMatchObject({
      processId: clonedLinkedProcess.rows[0]?.id,
      roundId: null,
      previousProcessPhase: "RESULTADO_INTERNO",
      previousRoundPhase: null,
      processVersion: 3,
    });
    const blockedPresentationKey = randomUUID();
    const blockedPresentationInput = {
      identityId: current.actorId,
      idempotencyKey: blockedPresentationKey,
      assignmentId: linkedAssignmentId,
      expectedVersion: 3,
      envelope: envelope("unsafe-presentation"),
    } as const;
    const blockedPresentation = await withStore(
      current,
      current.actorId,
      (store) => store.presentAssignment(blockedPresentationInput),
    );
    expect(blockedPresentation).toMatchObject({
      eligibilityPaused: true,
      code: "ASSIGNMENT_ELIGIBILITY_PAUSED",
      assignmentId: linkedAssignmentId,
      memberId: current.memberIds[0],
      processId: clonedLinkedProcess.rows[0]?.id,
      roundId: null,
      pauseIds: [linkedPauseId],
      processVersion: 3,
      roundVersion: null,
    });
    const replayedBlockedPresentation = await withStore(
      current,
      current.actorId,
      (store) => store.presentAssignment(blockedPresentationInput),
    );
    expect(replayedBlockedPresentation).toEqual(JSON.parse(JSON.stringify(blockedPresentation)));
    const blockedPresentationEvidence = await current.tenant.query<{
      state: string; version: number; presented_at: Date | null; presentation_transitions: number; open_pauses: number;
    }>(
      `SELECT assignment.state,assignment.version,assignment.presented_at,
              (SELECT count(*)::int FROM assignment_transitions transition
                WHERE transition.assignment_id=assignment.id AND transition.action='PRESENTED_TO_CHURCH') AS presentation_transitions,
              (SELECT count(*)::int FROM member_eligibility_workflow_pauses pause
                WHERE pause.process_id=assignment.process_id AND pause.resolved_at IS NULL) AS open_pauses
         FROM assignments assignment WHERE assignment.id=$1`,
      [linkedAssignmentId],
    );
    expect(blockedPresentationEvidence.rows[0]).toEqual({
      state: "ACEPTADA",
      version: 3,
      presented_at: null,
      presentation_transitions: 0,
      open_pauses: 1,
    });
    const withdrawnLinked = await withStore(current, current.actorId, (store) => store.recordAssignmentConsent({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      assignmentId: linkedAssignmentId,
      expectedVersion: 3,
      status: "WITHDRAWN",
      envelope: envelope("linked-withdrawal"),
    }));
    expect(withdrawnLinked).toMatchObject({
      state: "RETIRADA",
      version: 4,
      replacementProcess: { phase: "VACANTE_PENDIENTE", replacementForAssignmentId: linkedAssignmentId },
    });
    const linkedReplacementProcessId = stringField(withdrawnLinked["replacementProcess"] as Record<string, unknown>, "processId");
    const closedLinkedPause = await withStore(current, current.actorId, (store) => store.resolveEligibilityPause({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId: clonedLinkedProcess.rows[0]?.id ?? "",
      expectedProcessVersion: 3,
      expectedPauseIds: [linkedPauseId],
      resolutionCode: "CLOSE_AFTER_REPLACEMENT",
      reasonCode: "ELIGIBILITY_REPLACEMENT_COMPLETED",
      evidenceEnvelope: envelope("linked-eligibility-closure"),
    }));
    expect(closedLinkedPause).toMatchObject({
      resolutionCode: "CLOSE_AFTER_REPLACEMENT",
      processPhase: "CERRADO",
      processVersion: 4,
      replacementProcessId: linkedReplacementProcessId,
    });
    const linkedClosure = await current.tenant.query<{
      phase: string; resolution_code: string; replacement_process_id: string; resolved_at: Date;
    }>(
      `SELECT process.phase,pause.resolution_code,pause.replacement_process_id,pause.resolved_at
         FROM office_processes process
         JOIN member_eligibility_workflow_pauses pause ON pause.process_id=process.id
        WHERE process.id=$1 AND pause.id=$2`,
      [clonedLinkedProcess.rows[0]?.id, linkedPauseId],
    );
    expect(linkedClosure.rows[0]).toMatchObject({
      phase: "CERRADO",
      resolution_code: "CLOSE_AFTER_REPLACEMENT",
      replacement_process_id: linkedReplacementProcessId,
      resolved_at: expect.any(Date),
    });
  }, 180_000);

  it("keeps council recommendation and board approval outside ordinary workflow, including legacy rows", async () => {
    const current = requireFixture();
    const councilOfficeId = randomUUID();
    const cycle = await withStore(current, current.actorId, (store) => store.createCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      name: "Council-board procedure boundary",
      locale: "es",
      timezone: "America/La_Paz",
      jurisdiction: "local-test-only",
      termStart: "2042-01-01",
      termEnd: "2043-12-31",
      normativeVersion: "test-v1",
      configuration: {},
    }));
    const cycleId = stringField(cycle, "id");
    await current.tenant.query(
      `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality,catalog_metadata)
       SELECT $1,department_id,'WORKFLOW_COUNCIL_BOARD_OFFICE',$2,
              'council_recommendation_board_approval',1,$3
         FROM offices WHERE id=$4`,
      [
        councilOfficeId,
        { es: "Cargo consejo-junta", en: "Council-board office", fr: "Fonction conseil-comité" },
        {},
        current.officeId,
      ],
    );

    await expect(withStore(current, current.actorId, (store) => store.configureVacancyProcess({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 1,
      configuration: {
        officeId: councilOfficeId,
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
    }))).rejects.toMatchObject({ code: "COUNCIL_BOARD_PROCEDURE_REQUIRED" });
    const rejectedConfiguration = await current.tenant.query<{ processes: number; vacancies: number; cycle_version: number }>(
      `SELECT
         (SELECT count(*)::int FROM office_processes WHERE cycle_id=$1) AS processes,
         (SELECT count(*)::int FROM vacancies WHERE cycle_id=$1) AS vacancies,
         (SELECT version FROM election_cycles WHERE id=$1) AS cycle_version`,
      [cycleId],
    );
    expect(rejectedConfiguration.rows[0]).toEqual({ processes: 0, vacancies: 0, cycle_version: 1 });

    const legacyProcessId = randomUUID();
    const legacyRoundId = randomUUID();
    await current.tenant.query(
      `INSERT INTO office_processes(
         id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
         decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,agenda_order,created_by_identity_id
       ) VALUES ($1,$2,$3,'PROPUESTAS_ABIERTAS',1,1,1,$4,
                 'EXCLUDED_FROM_CANDIDATE_TOTALS','NEW_BALLOT_ROUND',$5,'committee',1,$6)`,
      [legacyProcessId, cycleId, councilOfficeId, { kind: "PLURALITY" }, { kind: "ALL_REQUIRED" }, current.actorId],
    );
    await current.tenant.query(
      "INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status,process_id) VALUES ($1,$2,$3,1,'pending',$4)",
      [randomUUID(), cycleId, councilOfficeId, legacyProcessId],
    );
    await current.tenant.query(
      `INSERT INTO rounds(
         id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,candidate_set_hash,rules_hash,
         max_proposal_selections,max_ballot_selections,process_id,workflow_stage,opened_at
       ) VALUES ($1,$2,$3,'PROPUESTAS_ABIERTAS','proposal',1,1,$4,$5,1,1,$6,'proposal',clock_timestamp())`,
      [
        legacyRoundId,
        cycleId,
        councilOfficeId,
        `sha256:${"a".repeat(64)}`,
        `sha256:${"b".repeat(64)}`,
        legacyProcessId,
      ],
    );

    await expect(withStore(current, current.actorId, (store) => store.closeProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: legacyRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 1,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }))).rejects.toMatchObject({ code: "COUNCIL_BOARD_PROCEDURE_REQUIRED" });
    await expect(withTenantStore(current, current.actorId, (store) => store.submit({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: legacyRoundId,
      kind: "proposal",
      expectedVersion: 1,
      envelope: envelope("legacy-council-submission"),
      contentHash: `sha256:${"c".repeat(64)}`,
    }))).rejects.toMatchObject({ code: "COUNCIL_BOARD_PROCEDURE_REQUIRED" });
    await expect(withTenantStore(current, current.actorId, (store) => store.closeRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: legacyRoundId,
      expectedVersion: 1,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }))).rejects.toMatchObject({ code: "COUNCIL_BOARD_PROCEDURE_REQUIRED" });

    await current.tenant.query("UPDATE election_cycles SET status='closed' WHERE id=$1", [cycleId]);
    const clone = await withStore(current, current.actorId, (store) => store.cloneCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      sourceCycleId: cycleId,
      name: "Council-board procedure boundary clone",
      locale: "es",
      timezone: "America/La_Paz",
      jurisdiction: "local-test-only",
      termStart: "2044-01-01",
      termEnd: "2045-12-31",
      normativeVersion: "test-v1",
      configuration: {},
    }));
    expect(clone).toMatchObject({ processCount: 0, skippedNonConfigurableProcessCount: 1 });
    const clonedProcesses = await current.tenant.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM office_processes WHERE cycle_id=$1",
      [stringField(clone, "id")],
    );
    expect(clonedProcesses.rows[0]?.count).toBe(0);
  }, 60_000);
});

live("AC-11 and AC-12 exact proposal acceptance evidence", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    exactAcceptanceFixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    const current = exactAcceptanceFixture;
    exactAcceptanceFixture = undefined;
    if (current) await cleanupFixture(current);
  }, 60_000);

  it("stores five concurrent final ciphertexts once and persists client-validated abstention denominators while drafts remain absent", async () => {
    const current = requireExactAcceptanceFixture();
    const electors = current.electorIds;
    expect(new Set(electors).size).toBe(5);

    const secondOfficeId = randomUUID();
    await current.tenant.query(
      `INSERT INTO offices(
         id,department_id,canonical_code,names,appointment_mechanism,cardinality,catalog_metadata
       ) SELECT $1,department_id,'WORKFLOW_ABSTENTION_OFFICE',$2,
                'church_election_after_nominating_report',1,$3
           FROM offices WHERE id=$4`,
      [
        secondOfficeId,
        { es: "Cargo de abstención temporal", en: "Temporary abstention office", fr: "Fonction temporaire d'abstention" },
        { linkedBaseOfficeCode: null },
        current.officeId,
      ],
    );

    const cycle = await withStore(current, current.actorId, (store) => store.createCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      name: "AC-11 and AC-12 exact evidence",
      locale: "es",
      timezone: "America/La_Paz",
      jurisdiction: "local-test-only",
      termStart: "2040-01-01",
      termEnd: "2041-12-31",
      normativeVersion: "test-v1",
      configuration: {},
    }));
    const cycleId = stringField(cycle, "id");

    const exactSessionId = randomUUID();
    const session = await withStore(current, current.actorId, (store) => store.addSession({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      sessionId: exactSessionId,
      expectedCycleVersion: 1,
      sequence: 1,
      titleEnvelope: envelopeWithAad({ tenantId: current.tenantId, cycleId, sessionId: exactSessionId, purpose: "session-title", schemaVersion: 1, titleVersion: 1 }),
      startsAt: "2040-10-01T18:00:00-04:00",
      endsAt: "2040-10-01T20:00:00-04:00",
    }));
    expect(session["cycleVersion"]).toBe(2);

    const exactCommitteeMembers = electors.map((identityId, index) => ({
      identityId,
      memberId: index === 0 ? current.memberIds[0] : index === 1 ? current.memberIds[1] : null,
      displayEnvelope: envelope(`exact-committee-${index + 1}`),
      roleCode: index === 0 ? "chair" as const : index === 1 ? "secretary" as const : "member" as const,
      votingRight: true,
      pastoralCapacity: false,
    }));
    const committee = await withStore(current, current.actorId, (store) => store.configureCommittee({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 2,
      activeTenantIdentityIds: electors,
      members: exactCommitteeMembers,
    }));
    expect(committee).toMatchObject({ memberCount: 5, votingCount: 5, cycleVersion: 3 });

    const electorate = await withStore(current, current.actorId, (store) => store.configureElectorate({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 3,
      activeTenantIdentityIds: electors,
      electors: electors.map((identityId) => ({
        identityId,
        canPropose: true,
        canVote: true,
        recused: false,
      })),
    }));
    expect(electorate).toMatchObject({ rosterCount: 5, proposalCount: 5, ballotCount: 5, cycleVersion: 4 });

    const commonConfiguration = {
      vacancyCount: 1,
      maxProposalSelections: 1,
      maxBallotSelections: 1,
      decisionRule: { kind: "PLURALITY" },
      abstentionRule: "EXCLUDED_FROM_CANDIDATE_TOTALS" as const,
      tiebreakPolicy: "NEW_BALLOT_ROUND" as const,
      quorumRule: { kind: "ALL_REQUIRED" },
      aggregateAudience: "committee" as const,
    };
    const fiveProponentsProcess = await withStore(current, current.actorId, (store) => store.configureVacancyProcess({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 4,
      configuration: { ...commonConfiguration, officeId: current.officeId, agendaOrder: 1 },
    }));
    const fiveProponentsProcessId = stringField(fiveProponentsProcess, "processId");
    expect(fiveProponentsProcess["cycleVersion"]).toBe(5);

    const abstentionProcess = await withStore(current, current.actorId, (store) => store.configureVacancyProcess({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 5,
      configuration: { ...commonConfiguration, officeId: secondOfficeId, agendaOrder: 2 },
    }));
    const abstentionProcessId = stringField(abstentionProcess, "processId");
    expect(abstentionProcess["cycleVersion"]).toBe(6);

    const activated = await withStore(current, current.actorId, (store) => store.activateCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedVersion: 6,
    }));
    expect(activated).toMatchObject({ status: "active", version: 7 });

    const fiveProponentsRound = await withStore(current, current.actorId, (store) => store.createProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId: fiveProponentsProcessId,
      expectedProcessVersion: 1,
    }));
    const fiveProponentsRoundId = stringField(fiveProponentsRound, "roundId");
    await withStore(current, current.actorId, (store) => store.openProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: fiveProponentsRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 1,
    }));

    const fiveProponentsContext = await loadProposalRoundContext(current, fiveProponentsRoundId);
    const concurrentInputs = electors.map((identityId) => proposalSubmissionInput(
      current,
      fiveProponentsRoundId,
      fiveProponentsContext,
      identityId,
    ));
    const originalReceipts = await Promise.all(concurrentInputs.map((input) => (
      withTenantStore(current, input.identityId, (store) => store.submit(input))
    )));
    const replayReceipts = await Promise.all(concurrentInputs.map((input) => (
      withTenantStore(current, input.identityId, (store) => store.submit(input))
    )));
    expect(replayReceipts.map(({ receiptId, contentHash, status }) => ({ receiptId, contentHash, status })))
      .toEqual(originalReceipts.map(({ receiptId, contentHash, status }) => ({ receiptId, contentHash, status })));

    const concurrentEvidence = await current.tenant.query<{
      submissions: number; distinct_electors: number; receipts: number; idempotency_records: number;
    }>(
      `SELECT
         (SELECT count(*)::int FROM encrypted_submissions WHERE round_id=$1 AND kind='proposal') AS submissions,
         (SELECT count(DISTINCT elector_identity_id)::int FROM encrypted_submissions WHERE round_id=$1 AND kind='proposal') AS distinct_electors,
         (SELECT count(*)::int FROM participation_receipts WHERE round_id=$1 AND kind='proposal') AS receipts,
         (SELECT count(*)::int FROM idempotency_records
           WHERE operation='round.proposal.submit' AND identity_id=ANY($2::uuid[])) AS idempotency_records`,
      [fiveProponentsRoundId, electors],
    );
    expect(concurrentEvidence.rows[0]).toEqual({
      submissions: 5,
      distinct_electors: 5,
      receipts: 5,
      idempotency_records: 5,
    });

    await withStore(current, current.actorId, (store) => store.closeProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: fiveProponentsRoundId,
      expectedRoundVersion: 2,
      expectedProcessVersion: 2,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }));
    const fiveProponentsManifest = await withStore(current, current.actorId, (store) => store.createProposalManifest({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: fiveProponentsRoundId,
      expectedRoundVersion: 3,
    }));
    const fiveProponentsManifestId = stringField(fiveProponentsManifest, "manifestId");
    const fiveProponentsManifestHash = stringField(fiveProponentsManifest, "manifestHash");
    const fiveProponentsAggregate = normalizeProposalAggregate({
      sourceRoundId: fiveProponentsRoundId,
      sourceManifestHash: fiveProponentsManifestHash,
      completedResponses: 5,
      electorateDenominator: 5,
      effectiveResponseDenominator: 5,
      maxProposalSelections: 1,
      candidates: [{ memberId: current.memberIds[0], distinctProponentCount: 5 }],
    });
    const fiveProponentsConsolidated = await withStore(current, current.actorId, (store) => store.consolidateProposals({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: fiveProponentsRoundId,
      expectedRoundVersion: 3,
      expectedProcessVersion: 3,
      manifestId: fiveProponentsManifestId,
      manifestHash: fiveProponentsManifestHash,
      effectiveResponseDenominator: 5,
      aggregateHash: workflowSha256(fiveProponentsAggregate),
      candidates: fiveProponentsAggregate.candidates,
    }));
    expect(fiveProponentsConsolidated).toMatchObject({ phase: "DEPURACION", candidacyIds: [expect.any(String)] });

    const fiveProponentsStored = await current.tenant.query<{
      candidacies: number; member_id: string; distinct_proponent_count: number;
      completed_responses: number; electorate_denominator: number; effective_response_denominator: number;
      manifest_entries: number;
    }>(
      `SELECT count(candidate.id)::int AS candidacies,min(candidate.member_id::text) AS member_id,
              min(candidate.distinct_proponent_count)::int AS distinct_proponent_count,
              min(aggregate.completed_responses)::int AS completed_responses,
              min(aggregate.electorate_denominator)::int AS electorate_denominator,
              min(aggregate.effective_response_denominator)::int AS effective_response_denominator,
              (SELECT count(*)::int FROM proposal_manifest_entries WHERE manifest_id=$2) AS manifest_entries
         FROM proposal_aggregates aggregate
         JOIN candidacies candidate ON candidate.source_aggregate_id=aggregate.id
        WHERE aggregate.process_id=$1`,
      [fiveProponentsProcessId, fiveProponentsManifestId],
    );
    expect(fiveProponentsStored.rows[0]).toEqual({
      candidacies: 1,
      member_id: current.memberIds[0],
      distinct_proponent_count: 5,
      completed_responses: 5,
      electorate_denominator: 5,
      effective_response_denominator: 5,
      manifest_entries: 5,
    });

    const abstentionRound = await withStore(current, current.actorId, (store) => store.createProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId: abstentionProcessId,
      expectedProcessVersion: 1,
    }));
    const abstentionRoundId = stringField(abstentionRound, "roundId");
    await withStore(current, current.actorId, (store) => store.openProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: abstentionRoundId,
      expectedRoundVersion: 1,
      expectedProcessVersion: 1,
    }));
    const abstentionContext = await loadProposalRoundContext(current, abstentionRoundId);
    const finalInputs = electors.map((identityId) => proposalSubmissionInput(
      current,
      abstentionRoundId,
      abstentionContext,
      identityId,
    ));

    await Promise.all(finalInputs.slice(0, 4).map((input) => (
      withTenantStore(current, input.identityId, (store) => store.submit(input))
    )));
    // A client-side draft has not crossed the final-submission boundary, so the server must have no row or receipt for it.
    const unsubmittedDraft = finalInputs[4];
    if (!unsubmittedDraft) throw new Error("Exact abstention fixture is missing its fifth elector");
    const participationWithDraft = await withStore(current, current.actorId, (store) => store.getNominalParticipation(abstentionRoundId));
    const draftParticipants = participationItems(participationWithDraft);
    expect(draftParticipants.filter(({ status }) => status === "received")).toHaveLength(4);
    expect(draftParticipants.filter(({ status }) => status === "pending")).toEqual([
      expect.objectContaining({ identityId: unsubmittedDraft.identityId, status: "pending" }),
    ]);
    const draftStorage = await current.tenant.query<{ submissions: number; receipts: number; draft_content_stored: boolean }>(
      `SELECT
         (SELECT count(*)::int FROM encrypted_submissions WHERE round_id=$1 AND kind='proposal') AS submissions,
         (SELECT count(*)::int FROM participation_receipts WHERE round_id=$1 AND kind='proposal') AS receipts,
         EXISTS(SELECT 1 FROM encrypted_submissions WHERE round_id=$1 AND content_hash=$2) AS draft_content_stored`,
      [abstentionRoundId, unsubmittedDraft.contentHash],
    );
    expect(draftStorage.rows[0]).toEqual({ submissions: 4, receipts: 4, draft_content_stored: false });
    await expect(withStore(current, current.actorId, (store) => store.closeProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: abstentionRoundId,
      expectedRoundVersion: 2,
      expectedProcessVersion: 2,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }))).rejects.toMatchObject({ code: "PARTICIPATION_INCOMPLETE" });

    const abstentionReceipt = await withTenantStore(current, unsubmittedDraft.identityId, (store) => store.submit(unsubmittedDraft));
    expect(abstentionReceipt).toMatchObject({ status: "received", roundId: abstentionRoundId });
    const participationAfterAbstention = await withStore(current, current.actorId, (store) => store.getNominalParticipation(abstentionRoundId));
    const finalParticipants = participationItems(participationAfterAbstention);
    expect(finalParticipants.filter(({ status }) => status === "received")).toHaveLength(5);
    expect(finalParticipants.filter(({ status }) => status === "pending")).toHaveLength(0);

    await withStore(current, current.actorId, (store) => store.closeProposalRound({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: abstentionRoundId,
      expectedRoundVersion: 2,
      expectedProcessVersion: 2,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }));
    const abstentionManifest = await withStore(current, current.actorId, (store) => store.createProposalManifest({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: abstentionRoundId,
      expectedRoundVersion: 3,
    }));
    const abstentionManifestId = stringField(abstentionManifest, "manifestId");
    const abstentionManifestHash = stringField(abstentionManifest, "manifestHash");
    // The authorized E2EE tally client validates the fifth response as an abstention; persistence records only its aggregate effect.
    const abstentionAggregate = normalizeProposalAggregate({
      sourceRoundId: abstentionRoundId,
      sourceManifestHash: abstentionManifestHash,
      completedResponses: 5,
      electorateDenominator: 5,
      effectiveResponseDenominator: 4,
      maxProposalSelections: 1,
      candidates: [{ memberId: current.memberIds[1], distinctProponentCount: 4 }],
    });
    await withStore(current, current.actorId, (store) => store.consolidateProposals({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      roundId: abstentionRoundId,
      expectedRoundVersion: 3,
      expectedProcessVersion: 3,
      manifestId: abstentionManifestId,
      manifestHash: abstentionManifestHash,
      effectiveResponseDenominator: 4,
      aggregateHash: workflowSha256(abstentionAggregate),
      candidates: abstentionAggregate.candidates,
    }));

    const abstentionStored = await current.tenant.query<{
      candidacies: number; distinct_proponent_count: number; support_denominator: number;
      completed_responses: number; electorate_denominator: number; effective_response_denominator: number;
      submissions: number; receipts: number;
    }>(
      `SELECT count(candidate.id)::int AS candidacies,
              min(candidate.distinct_proponent_count)::int AS distinct_proponent_count,
              min(candidate.support_denominator)::int AS support_denominator,
              min(aggregate.completed_responses)::int AS completed_responses,
              min(aggregate.electorate_denominator)::int AS electorate_denominator,
              min(aggregate.effective_response_denominator)::int AS effective_response_denominator,
              (SELECT count(*)::int FROM encrypted_submissions WHERE round_id=$2 AND kind='proposal') AS submissions,
              (SELECT count(*)::int FROM participation_receipts WHERE round_id=$2 AND kind='proposal') AS receipts
         FROM proposal_aggregates aggregate
         JOIN candidacies candidate ON candidate.source_aggregate_id=aggregate.id
        WHERE aggregate.process_id=$1`,
      [abstentionProcessId, abstentionRoundId],
    );
    expect(abstentionStored.rows[0]).toEqual({
      candidacies: 1,
      distinct_proponent_count: 4,
      support_denominator: 4,
      completed_responses: 5,
      electorate_denominator: 5,
      effective_response_denominator: 4,
      submissions: 5,
      receipts: 5,
    });
  }, 180_000);
});

live("NM-009 cycle office applicability", () => {
  let applicabilityFixture: Fixture | undefined;

  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    applicabilityFixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    const current = applicabilityFixture;
    applicabilityFixture = undefined;
    if (current) await cleanupFixture(current);
  }, 60_000);

  it("excludes a disabled structure from current metrics while retaining history and legacy vacancies", async () => {
    const current = applicabilityFixture;
    if (!current) throw new Error("Applicability fixture is unavailable");
    const cycle = await withStore(current, current.actorId, (store) => store.createCycle({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      name: "Applicability verification cycle",
      locale: "es",
      timezone: "America/La_Paz",
      jurisdiction: "local-test-only",
      termStart: "2036-01-01",
      termEnd: "2037-12-31",
      normativeVersion: "test-v1",
      configuration: {},
    }));
    const cycleId = stringField(cycle, "id");
    const configured = await withStore(current, current.actorId, (store) => store.configureVacancyProcess({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      cycleId,
      expectedCycleVersion: 1,
      configuration: {
        officeId: current.officeId,
        vacancyCount: 2,
        maxProposalSelections: 2,
        maxBallotSelections: 2,
        decisionRule: { kind: "PLURALITY" },
        abstentionRule: "EXCLUDED_FROM_CANDIDATE_TOTALS",
        tiebreakPolicy: "NEW_BALLOT_ROUND",
        quorumRule: { kind: "ALL_REQUIRED" },
        aggregateAudience: "committee",
        agendaOrder: 1,
      },
    }));
    const processId = stringField(configured, "processId");
    const disableKey = randomUUID();
    const disableInput = {
      identityId: current.actorId,
      idempotencyKey: disableKey,
      processId,
      expectedCycleVersion: 2,
      expectedProcessVersion: 1,
      enabled: false,
      reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE",
    } as const;
    const disabled = await withStore(current, current.actorId, (store) => store.setOfficeProcessApplicability(disableInput));
    const replayed = await withStore(current, current.actorId, (store) => store.setOfficeProcessApplicability(disableInput));
    expect(replayed).toEqual(JSON.parse(JSON.stringify(disabled)));
    expect(disabled).toMatchObject({
      baseProcessId: processId,
      affectedProcessIds: [processId],
      enabled: false,
      changed: true,
      cycleVersion: 3,
      processVersions: [{ processId, version: 2 }],
    });

    const dashboardWithoutLegacy = await withTenantStore(current, current.actorId, (store) => store.getDashboard());
    expect(dashboardWithoutLegacy["metrics"]).toMatchObject({ vacanciesTotal: 0, recommended: 0, coveragePercent: null });
    expect(dashboardWithoutLegacy["analytics"]).toMatchObject({ roundParticipation: [], departments: [], sessions: [] });
    const organizationWithoutLegacy = await withTenantStore(current, current.actorId, (store) => store.getOrganization({ cycleId, stage: "elected" }));
    expect(organizationWithoutLegacy["items"]).toEqual([]);
    const workflow = await withStore(current, current.actorId, (store) => store.getCycleWorkflow(cycleId));
    expect(workflow?.["processes"]).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: processId, enabled: false, version: 2 }),
    ]));

    await current.tenant.query(
      "INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status,process_id) VALUES ($1,$2,$3,3,'pending',NULL)",
      [randomUUID(), cycleId, current.officeId],
    );
    const dashboardWithLegacy = await withTenantStore(current, current.actorId, (store) => store.getDashboard());
    expect(dashboardWithLegacy["metrics"]).toMatchObject({ vacanciesTotal: 1, recommended: 0, coveragePercent: 0 });
    expect(dashboardWithLegacy["analytics"]).toMatchObject({
      roundParticipation: [],
      departments: [expect.objectContaining({ vacanciesTotal: 1, recommended: 0, accepted: 0, elected: 0, coveragePercent: 0 })],
      sessions: [],
    });
    const organizationWithLegacy = await withTenantStore(current, current.actorId, (store) => store.getOrganization({ cycleId, stage: "elected" }));
    expect(organizationWithLegacy["items"]).toEqual([expect.objectContaining({ officeId: current.officeId, status: "vacant" })]);

    const restored = await withStore(current, current.actorId, (store) => store.setOfficeProcessApplicability({
      identityId: current.actorId,
      idempotencyKey: randomUUID(),
      processId,
      expectedCycleVersion: 3,
      expectedProcessVersion: 2,
      enabled: true,
      reasonCode: "CYCLE_STRUCTURE_APPLICABILITY_RESTORED",
    }));
    expect(restored).toMatchObject({ enabled: true, changed: true, cycleVersion: 4 });
    const restoredDashboard = await withTenantStore(current, current.actorId, (store) => store.getDashboard());
    expect(restoredDashboard["metrics"]).toMatchObject({ vacanciesTotal: 3, recommended: 0, coveragePercent: 0 });
    expect(restoredDashboard["analytics"]).toMatchObject({
      departments: [expect.objectContaining({ vacanciesTotal: 3, recommended: 0, coveragePercent: 0 })],
    });
    const unchangedDashboard = await withTenantStore(current, current.actorId, (store) => store.getDashboard());
    expect(unchangedDashboard["updatedAt"]).toBe(restoredDashboard["updatedAt"]);

    const annulledRoundId = randomUUID();
    await current.tenant.query(
      `INSERT INTO rounds(
         id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,
         candidate_set_hash,rules_hash,closed_at
       ) VALUES ($1,$2,$3,'ANULADO','proposal',1,1,$4,$5,clock_timestamp())`,
      [annulledRoundId, cycleId, current.officeId, `sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`],
    );
    const dashboardAfterAnnulment = await withTenantStore(current, current.actorId, (store) => store.getDashboard());
    expect((dashboardAfterAnnulment["analytics"] as { roundParticipation: Array<{ roundId: string }> }).roundParticipation)
      .not.toEqual(expect.arrayContaining([expect.objectContaining({ roundId: annulledRoundId })]));

    const audit = await current.tenant.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM audit_events WHERE action='office-process.applicability.updated' AND entity_id=$1",
      [processId],
    );
    expect(audit.rows[0]?.count).toBe(2);
  }, 120_000);
});

async function createFixture(databaseAdminUrl: string): Promise<Fixture> {
  const databaseName = `nom_workflow_test_${randomUUID().replaceAll("-", "_")}`;
  const cluster = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    application_name: "nombramientos-workflow-live-cluster",
    max: 1,
  });
  const tenant = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, databaseName),
    application_name: "nombramientos-workflow-live-tenant",
    max: 8,
  });
  try {
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [databaseName]);
    await runMigrations(tenant, { scope: "tenant", directory: path.join(packageRoot, "migrations", "tenant") });
    const tenantId = randomUUID();
    const actorId = randomUUID();
    const secondElectorId = randomUUID();
    const electorIds = [actorId, secondElectorId, randomUUID(), randomUUID(), randomUUID()] as const;
    const memberIds = [randomUUID(), randomUUID()] as const;
    const departmentId = randomUUID();
    const officeId = randomUUID();
    await tenant.query(
      `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state,catalog_version)
       VALUES ($1,'Workflow temporary tenant','real','America/La_Paz','es','ready','test-v1')`,
      [tenantId],
    );
    const generationId = randomUUID();
    const tenantContentKey = randomTenantContentKey();
    try {
      const recoverySigningKey = await generateCustodianSigningKeyPair();
      const recoveryPublicKey = await exportCustodianSigningPublicKey(recoverySigningKey);
      await tenant.query(
        `INSERT INTO e2ee_key_generations(
           id,tenant_key_id,generation,status,recovery_public_key,
           recovery_key_fingerprint,created_by_identity_id
         ) VALUES ($1,$2,1,'active',$3,$4,$5)`,
        [
          generationId,
          WORKFLOW_TENANT_KEY_ID,
          recoveryPublicKey,
          recoveryPublicKey.fingerprint,
          actorId,
        ],
      );
      for (const [index, identityId] of electorIds.entries()) {
        const grant = await createRealTenantKeyGrant({
          tenantId,
          tenantKeyId: WORKFLOW_TENANT_KEY_ID,
          generation: 1,
          identityId,
          tenantContentKey,
        });
        await tenant.query(
          `INSERT INTO e2ee_key_devices(
             device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,
             status,activated_at
           ) VALUES ($1,$2,$3,$4,$5,'active',clock_timestamp())`,
          [grant.deviceId, identityId, `Ephemeral workflow browser ${index + 1}`, grant.wrappingPublicKey, grant.deviceFingerprint],
        );
        await tenant.query(
          `INSERT INTO e2ee_key_grants(
             generation_id,identity_id,device_id,envelope,envelope_hash,
             grant_kind,status,granted_by_identity_id
           ) VALUES ($1,$2,$3,$4,$5,$6,'active',$7)`,
          [
            generationId,
            identityId,
            grant.deviceId,
            grant.envelope,
            grant.envelopeHash,
            index === 0 ? "initial" : "admin_approved",
            actorId,
          ],
        );
      }
    } finally {
      tenantContentKey.fill(0);
    }
    await assertRealTenantKeyFixture(tenant, electorIds);
    await tenant.query(
      "INSERT INTO departments(id,canonical_code,names) VALUES ($1,'WORKFLOW_TEST',$2)",
      [departmentId, { es: "Workflow", en: "Workflow", fr: "Workflow" }],
    );
    await tenant.query(
      `INSERT INTO offices(
         id,department_id,canonical_code,names,appointment_mechanism,cardinality,catalog_metadata
       ) VALUES ($1,$2,'WORKFLOW_TEST_OFFICE',$3,'church_election_after_nominating_report',2,$4)`,
      [officeId, departmentId, { es: "Cargo temporal", en: "Temporary office", fr: "Fonction temporaire" }, { linkedBaseOfficeCode: null }],
    );
    for (let index = 0; index < memberIds.length; index += 1) {
      const memberId = memberIds[index]!;
      const displayEnvelope = memberDisplayEnvelope(tenantId, memberId);
      await tenant.query(
        `INSERT INTO members(
           id,stable_code,display_envelope,display_content_hash,eligibility_envelope,eligibility_status,available
         ) VALUES ($1,$2,$3,$4,$5,'eligible',true)`,
        [memberId, `WORKFLOW-${index + 1}`, displayEnvelope, envelopeContentHash(displayEnvelope), envelope(`eligibility-${index + 1}`)],
      );
      const storedEnvelope = envelope(`photo-${index + 1}`);
      const fixedEnvelopeJson = JSON.stringify({
        algorithm: storedEnvelope.algorithm,
        keyId: storedEnvelope.keyId,
        nonce: storedEnvelope.nonce,
        ciphertext: storedEnvelope.ciphertext,
        aad: storedEnvelope.aad,
      });
      await tenant.query(
        `INSERT INTO member_photo_assets(
           id,member_id,version,media_type,width,height,plaintext_bytes,cipher_bytes,
           envelope,content_hash,created_by_identity_id
         ) VALUES ($1,$2,1,'image/jpeg',128,128,128,144,$3,$4,$5)`,
        [randomUUID(), memberIds[index], storedEnvelope, `sha256:${createHash("sha256").update(fixedEnvelopeJson, "utf8").digest("hex")}`, actorId],
      );
    }
    return { cluster, tenant, databaseName, tenantId, actorId, secondElectorId, electorIds, memberIds, departmentId, officeId };
  } catch (error) {
    return cleanupAfterFailure(error, () => cleanupWorkflowDatabase(cluster, tenant, databaseName), "Workflow fixture setup");
  }
}

async function withStore<T>(current: Fixture, identityId: string, work: (store: CoreWorkflowStore) => Promise<T>): Promise<T> {
  const client = await current.tenant.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, current.tenantId, identityId);
    const result = await work(new CoreWorkflowStore(client));
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function withTenantStore<T>(current: Fixture, identityId: string, work: (store: TenantStore) => Promise<T>): Promise<T> {
  const client = await current.tenant.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, current.tenantId, identityId);
    const result = await work(new TenantStore(client));
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function setContext(client: PoolClient, tenantId: string, identityId: string): Promise<void> {
  await client.query(
    `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
            set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
    [tenantId, identityId, randomUUID(), randomUUID()],
  );
  await bindDirectFixtureSession(client);
}

interface ProposalRoundContext {
  readonly cycleId: string;
  readonly version: number;
  readonly candidateSetHash: string;
  readonly rulesHash: string;
}

async function loadProposalRoundContext(current: Fixture, roundId: string): Promise<ProposalRoundContext> {
  const result = await current.tenant.query<{
    cycle_id: string; version: number; candidate_set_hash: string; rules_hash: string;
  }>(
    "SELECT cycle_id,version,candidate_set_hash,rules_hash FROM rounds WHERE id=$1",
    [roundId],
  );
  const row = result.rows[0];
  if (!row) throw new Error("Proposal round context is unavailable");
  return {
    cycleId: row.cycle_id,
    version: row.version,
    candidateSetHash: row.candidate_set_hash,
    rulesHash: row.rules_hash,
  };
}

function proposalSubmissionInput(
  current: Fixture,
  roundId: string,
  context: ProposalRoundContext,
  identityId: string,
): SubmissionInput {
  const submissionEnvelope = envelopeWithAad({
    tenantId: current.tenantId,
    cycleId: context.cycleId,
    roundId,
    purpose: "proposal",
    schemaVersion: 1,
    roundVersion: context.version,
    candidateSetHash: context.candidateSetHash,
    rulesHash: context.rulesHash,
  });
  const canonicalEnvelope = JSON.stringify({
    algorithm: submissionEnvelope.algorithm,
    keyId: submissionEnvelope.keyId,
    nonce: submissionEnvelope.nonce,
    ciphertext: submissionEnvelope.ciphertext,
    aad: submissionEnvelope.aad,
  });
  return {
    identityId,
    idempotencyKey: randomUUID(),
    roundId,
    kind: "proposal",
    expectedVersion: context.version,
    envelope: submissionEnvelope,
    contentHash: `sha256:${createHash("sha256").update(canonicalEnvelope, "utf8").digest("hex")}`,
  };
}

function participationItems(value: Record<string, unknown> | null): Array<Record<string, unknown>> {
  const participants = value?.["participants"];
  if (!Array.isArray(participants) || participants.some((participant) => !participant || typeof participant !== "object" || Array.isArray(participant))) {
    throw new Error("Nominal participation response is malformed");
  }
  return participants as Array<Record<string, unknown>>;
}

async function insertOpaqueResponses(current: Fixture, roundId: string, kind: "proposal" | "vote", identities: readonly string[]): Promise<void> {
  for (const identityId of identities) {
    const submissionId = randomUUID();
    const contentHash = `sha256:${randomBytes(32).toString("hex")}`;
    await current.tenant.query(
      `INSERT INTO encrypted_submissions(id,round_id,elector_identity_id,kind,envelope,content_hash,round_version)
       VALUES ($1,$2,$3,$4,$5,$6,(SELECT version FROM rounds WHERE id=$2))`,
      [submissionId, roundId, identityId, kind, { opaque: true }, contentHash],
    );
    await current.tenant.query(
      `INSERT INTO participation_receipts(id,submission_id,round_id,elector_identity_id,kind,content_hash,received_at)
       VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp())`,
      [randomUUID(), submissionId, roundId, identityId, kind, contentHash],
    );
  }
}

async function insertFrozenCustody(current: Fixture, roundId: string): Promise<void> {
  await current.tenant.query(
    "INSERT INTO round_custody_sets(round_id,round_version,version,decision_rule,frozen_by_identity_id) VALUES ($1,1,1,$2,$3)",
    [roundId, { kind: "PLURALITY" }, current.actorId],
  );
  for (let index = 0; index < 2; index += 1) {
    const identityId = index === 0 ? current.actorId : current.secondElectorId;
    const existing = await current.tenant.query<{ id: string }>(
      "SELECT id FROM custodian_device_keys WHERE custodian_identity_id=$1 AND status='active' ORDER BY registered_at DESC LIMIT 1",
      [identityId],
    );
    const keyId = existing.rows[0]?.id ?? randomUUID();
    if (existing.rowCount === 0) {
      const deviceId = randomUUID();
      const fingerprint = `sha256:${randomBytes(32).toString("hex")}`;
      const signingFingerprint = `sha256:${randomBytes(32).toString("hex")}`;
      await current.tenant.query(
        `INSERT INTO custodian_device_keys(
           id,custodian_identity_id,device_id,recipient_id,key_version,status,
           hpke_kem,hpke_kdf,hpke_aead,hpke_public_key,hpke_fingerprint,
           signing_algorithm,signing_public_key_spki,signing_fingerprint,registered_by_identity_id
         ) VALUES ($1,$2,$3,$4,1,'active','DHKEM(P-256, HKDF-SHA256)','HKDF-SHA256','AES-256-GCM',$5,$6,'Ed25519',$7,$8,$2)`,
        [keyId, identityId, deviceId, `workflow-custodian-${index + 1}`, randomBytes(65).toString("base64url"), fingerprint, randomBytes(44).toString("base64url"), signingFingerprint],
      );
    }
    await current.tenant.query(
      `INSERT INTO round_custodian_key_snapshots(
         round_id,custodian_identity_id,device_id,source_key_id,recipient_id,key_version,
         hpke_kem,hpke_kdf,hpke_aead,hpke_public_key,hpke_fingerprint,
         signing_algorithm,signing_public_key_spki,signing_fingerprint
       ) SELECT $1,custodian_identity_id,device_id,id,recipient_id,key_version,
                hpke_kem,hpke_kdf,hpke_aead,hpke_public_key,hpke_fingerprint,
                signing_algorithm,signing_public_key_spki,signing_fingerprint
           FROM custodian_device_keys WHERE id=$2`,
      [roundId, keyId],
    );
  }
}

async function insertPublishedAggregate(
  current: Fixture,
  roundId: string,
  candidateIds: readonly string[],
  selectedCandidateId: string | null,
): Promise<{ aggregateHash: string; manifestId: string }> {
  const sorted = [...candidateIds].sort();
  const tieRequired = selectedCandidateId === null;
  const aggregate = {
    schemaVersion: 1,
    receivedBallots: 2,
    nonAbstainingBallots: 2,
    abstentions: 0,
    maxSelections: 1,
    candidates: sorted.map((candidateId) => ({ candidateId, votes: tieRequired ? 1 : candidateId === selectedCandidateId ? 2 : 0 })),
    rule: { kind: "PLURALITY" },
    decision: tieRequired
      ? {
          status: "TIEBREAK_REQUIRED",
          reason: "CUTOFF_TIE",
          selectedCandidateIds: [],
          tiebreakCandidateIds: sorted,
          unfilledSeats: 1,
        }
      : {
          status: "SELECTED",
          reason: "TOP_K",
          selectedCandidateIds: [selectedCandidateId],
          tiebreakCandidateIds: [],
          unfilledSeats: 0,
        },
  };
  const aggregateHash = workflowSha256(aggregate);
  const manifestId = randomUUID();
  await current.tenant.query("UPDATE rounds SET phase='RESULTADO_INTERNO',version=version+1 WHERE id=$1", [roundId]);
  await current.tenant.query(
    `INSERT INTO tally_manifests(
       id,round_id,custody_version,round_version,decision_rule,manifest_hash,entry_count,state,
       agreed_aggregate_hash,agreed_aggregate,version,created_by_identity_id,
       published_by_identity_id,published_at
     ) VALUES ($1,$2,1,4,$3,$4,2,'published',$5,$6,4,$7,$7,clock_timestamp())`,
    [manifestId, roundId, { kind: "PLURALITY" }, `sha256:${randomBytes(32).toString("hex")}`, aggregateHash, aggregate, current.actorId],
  );
  return { aggregateHash, manifestId };
}

async function assignmentSnapshots(
  current: Fixture,
  memberId: string,
  label: string,
): Promise<readonly [Record<string, unknown>, Record<string, unknown>]> {
  const state = await current.tenant.query<{
    version: number;
    eligibility_status: string;
    available: boolean;
    eligibility_department_id: string | null;
    eligibility_valid_until: string | null;
    evaluated_on: string;
  }>(
    `SELECT member.version,member.eligibility_status,member.available,
            member.eligibility_department_id,
            to_char(member.eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until,
            to_char((clock_timestamp() AT TIME ZONE settings.timezone)::date,'YYYY-MM-DD') AS evaluated_on
       FROM members member CROSS JOIN tenant_settings settings
      WHERE member.id=$1 AND settings.singleton=true`,
    [memberId],
  );
  const member = state.rows[0];
  if (!member || member.eligibility_status !== "eligible" || !member.available) {
    throw new Error("Lifecycle assignment fixture requires a currently eligible member");
  }
  return [
    {
      memberId,
      memberVersion: member.version,
      displayEnvelope: envelope(label),
      eligibility: {
        departmentRestriction: member.eligibility_department_id,
        validUntil: member.eligibility_valid_until,
        evaluatedOn: member.evaluated_on,
        effective: true,
      },
    },
    {
      officeId: current.officeId,
      departmentId: current.departmentId,
      canonicalCode: "WORKFLOW_TEST_OFFICE",
      names: { es: "Cargo temporal", en: "Temporary office", fr: "Fonction temporaire" },
    },
  ];
}

async function insertLifecycleAssignment(current: Fixture, input: {
  readonly cycleId: string;
  readonly processId: string;
  readonly memberId: string;
  readonly ordinal: number;
  readonly state: "ACEPTADA" | "PRESENTADA_A_IGLESIA" | "VIGENTE";
}): Promise<string> {
  const vacancyId = randomUUID();
  const assignmentId = randomUUID();
  const [memberSnapshot, officeSnapshot] = await assignmentSnapshots(
    current,
    input.memberId,
    `lifecycle-member-${input.ordinal}`,
  );
  await current.tenant.query(
    `INSERT INTO vacancies(id,cycle_id,office_id,process_id,ordinal,status)
     VALUES ($1,$2,$3,$4,$5,'elected')`,
    [vacancyId, input.cycleId, current.officeId, input.processId, input.ordinal],
  );
  await current.tenant.query(
    `INSERT INTO assignments(
       id,vacancy_id,member_id,state,effective,cycle_id,office_id,process_id,
       member_snapshot,office_snapshot
     ) VALUES ($1,$2,$3,$4,true,$5,$6,$7,$8,$9)`,
    [
      assignmentId,
      vacancyId,
      input.memberId,
      input.state,
      input.cycleId,
      current.officeId,
      input.processId,
      memberSnapshot,
      officeSnapshot,
    ],
  );
  return assignmentId;
}

async function createRealTenantKeyGrant(input: {
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly identityId: string;
  readonly tenantContentKey: Uint8Array<ArrayBuffer>;
}) {
  const deviceId = randomUUID();
  const recipient = await generateTenantDeviceKeyPair({ tenantId: input.tenantId, deviceId });
  const wrappingPublicKey = await exportTenantDevicePublicKey(recipient);
  const envelope = await createTenantKeyGrantEnvelope({
    tenantId: input.tenantId,
    tenantKeyId: input.tenantKeyId,
    generation: input.generation,
    identityId: input.identityId,
    deviceId,
    tenantKey: input.tenantContentKey,
    recipient,
  });
  const verified = await verifyTenantKeyGrantEnvelope(envelope);
  if (verified.envelopeHash !== envelope.envelopeHash) {
    throw new Error("Workflow tenant key grant canonical hash verification failed");
  }
  const opened = await openTenantKeyGrantEnvelope({
    envelope: verified,
    recipient,
    expected: {
      tenantId: input.tenantId,
      tenantKeyId: input.tenantKeyId,
      generation: input.generation,
      identityId: input.identityId,
      deviceId,
    },
  });
  try {
    if (
      opened.keyBytes.byteLength !== 32
      || !Buffer.from(opened.keyBytes).equals(Buffer.from(input.tenantContentKey))
      || opened.tenantKeyId !== input.tenantKeyId
    ) {
      throw new Error("Workflow grant did not recover the exact 32-byte tenant key");
    }
  } finally {
    opened.keyBytes.fill(0);
  }
  return {
    deviceId,
    deviceFingerprint: wrappingPublicKey.fingerprint,
    wrappingPublicKey,
    envelope,
    envelopeHash: envelope.envelopeHash,
  } as const;
}

function randomTenantContentKey(): Uint8Array<ArrayBuffer> {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

async function assertRealTenantKeyFixture(tenant: Pool, identities: readonly string[]): Promise<void> {
  const result = await tenant.query<{
    kind: string;
    legacy_grants: number;
    active_generations: number;
    active_devices: number;
    active_grants: number;
    exact_grants: number;
  }>(
    `SELECT settings.kind,
            (SELECT count(*)::int FROM device_key_grants) AS legacy_grants,
            (SELECT count(*)::int FROM e2ee_key_generations WHERE status='active') AS active_generations,
            (SELECT count(*)::int FROM e2ee_key_devices WHERE status='active') AS active_devices,
            (SELECT count(*)::int FROM e2ee_key_grants WHERE status='active') AS active_grants,
            (SELECT count(*)::int
               FROM e2ee_key_grants key_grant
               JOIN e2ee_key_generations generation ON generation.id=key_grant.generation_id
               JOIN e2ee_key_devices device
                 ON device.device_id=key_grant.device_id
                AND device.identity_id=key_grant.identity_id
              WHERE generation.status='active' AND key_grant.status='active' AND device.status='active'
                AND generation.tenant_key_id::text=$1
                AND key_grant.identity_id=ANY($2::uuid[])
                AND key_grant.envelope_hash=key_grant.envelope->>'envelopeHash'
                AND key_grant.envelope->'aad'->>'tenantKeyId'=$1
                AND key_grant.envelope->'aad'->>'generation'=generation.generation::text
                AND key_grant.envelope->'aad'->>'identityId'=key_grant.identity_id::text
                AND key_grant.envelope->'aad'->>'deviceId'=key_grant.device_id::text
                AND key_grant.envelope->'aad'->>'deviceFingerprint'=device.wrapping_key_fingerprint
                AND key_grant.envelope->>'recipientFingerprint'=device.wrapping_key_fingerprint
                AND device.wrapping_public_key->>'fingerprint'=device.wrapping_key_fingerprint
            ) AS exact_grants
       FROM tenant_settings settings WHERE settings.singleton=true`,
    [WORKFLOW_TENANT_KEY_ID, [...identities]],
  );
  const expectedCount = identities.length;
  const row = result.rows[0];
  if (!row
    || row.kind !== "real"
    || row.legacy_grants !== 0
    || row.active_generations !== 1
    || row.active_devices !== expectedCount
    || row.active_grants !== expectedCount
    || row.exact_grants !== expectedCount) {
    throw new Error("Real workflow E2EE fixture is incomplete or internally inconsistent");
  }
  const storedGrants = await tenant.query<{ envelope: unknown; envelope_hash: string }>(
    `SELECT envelope,envelope_hash
       FROM e2ee_key_grants
      WHERE status='active' AND identity_id=ANY($1::uuid[])
      ORDER BY identity_id,created_at,id`,
    [[...identities]],
  );
  if (storedGrants.rowCount !== expectedCount) {
    throw new Error("Real workflow E2EE fixture has an unexpected persisted grant count");
  }
  for (const storedGrant of storedGrants.rows) {
    const verified = await verifyTenantKeyGrantEnvelope(storedGrant.envelope);
    if (verified.envelopeHash !== storedGrant.envelope_hash) {
      throw new Error("Persisted workflow tenant key grant hash is not canonical");
    }
  }
}

function envelope(label: string): EncryptedEnvelope {
  return {
    algorithm: "AES-256-GCM",
    keyId: WORKFLOW_TENANT_KEY_ID,
    nonce: randomBytes(12).toString("base64url"),
    ciphertext: randomBytes(32).toString("base64url"),
    aad: Buffer.from(JSON.stringify({ label })).toString("base64url"),
  };
}

function envelopeWithAad(aad: Readonly<Record<string, unknown>>): EncryptedEnvelope {
  return {
    algorithm: "AES-256-GCM",
    keyId: WORKFLOW_TENANT_KEY_ID,
    nonce: randomBytes(12).toString("base64url"),
    ciphertext: randomBytes(32).toString("base64url"),
    aad: Buffer.from(JSON.stringify(aad)).toString("base64url"),
  };
}

function memberDisplayEnvelope(tenantId: string, memberId: string): EncryptedEnvelope {
  return envelopeWithAad({ tenantId, memberId, purpose: "member-display", schemaVersion: 1 });
}

function envelopeContentHash(value: EncryptedEnvelope): string {
  return `sha256:${createHash("sha256").update(JSON.stringify({
    algorithm: value.algorithm,
    keyId: value.keyId,
    nonce: value.nonce,
    ciphertext: value.ciphertext,
    aad: value.aad,
  }), "utf8").digest("hex")}`;
}

async function cleanupFixture(current: Fixture): Promise<void> {
  await cleanupWorkflowDatabase(current.cluster, current.tenant, current.databaseName);
}

async function cleanupWorkflowDatabase(cluster: Pool, tenant: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [tenant], assertSafeDatabaseName: assertWorkflowDatabaseName }],
    label: "Temporary workflow database",
  });
}

function assertWorkflowDatabaseName(databaseName: string): void {
  if (!/^nom_workflow_test_[0-9a-f]{8}_[0-9a-f]{4}_4[0-9a-f]{3}_[89ab][0-9a-f]{3}_[0-9a-f]{12}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-workflow-test UUID database");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the workflow test statement");
  await pool.query(sql);
}

function discoverAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (parsed && typeof parsed === "object" && "DATABASE_ADMIN_URL" in parsed && typeof parsed.DATABASE_ADMIN_URL === "string") {
        candidate = parsed.DATABASE_ADMIN_URL;
      }
    }
    if (!candidate) return undefined;
    return assertWorkspacePostgresUrl(candidate, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReachWorkspace(databaseAdminUrl: string): Promise<boolean> {
  const pool = new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), connectionTimeoutMillis: 1_500, max: 1 });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === WORKSPACE_PORT;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)) throw new Error("Invalid local database name");
  const url = new URL(databaseAdminUrl);
  if (!isLoopback(url.hostname) || Number(url.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Workflow tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}

function requireFixture(): Fixture {
  if (!fixture) throw new Error("Workflow live fixture is unavailable");
  return fixture;
}

function requireExactAcceptanceFixture(): Fixture {
  if (!exactAcceptanceFixture) throw new Error("Exact acceptance workflow fixture is unavailable");
  return exactAcceptanceFixture;
}

function stringField(value: Record<string, unknown>, field: string): string {
  const item = value[field];
  if (typeof item !== "string") throw new Error(`Expected ${field} in workflow response`);
  return item;
}

function stringArrayField(value: Record<string, unknown>, field: string): string[] {
  const item = value[field];
  if (!Array.isArray(item) || item.some((entry) => typeof entry !== "string")) throw new Error(`Expected ${field} string array in workflow response`);
  return item as string[];
}
