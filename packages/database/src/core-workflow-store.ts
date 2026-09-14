import { createHash, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import {
  isConfigurableVacancyProcessMechanism,
  isOrdinaryProposalBallotMechanism,
} from "@nombramientos/catalog";
import {
  assertAssignmentTransition,
  evaluateMemberEligibilityForOffice,
  isCanonicalCivilDate,
  type AssignmentState,
} from "@nombramientos/domain";
import { appendTenantAuditEventV2 } from "./audit-event-chain.js";
import { assertWritableTenantContentKey } from "./content-key-write-guard.js";
import {
  assertCandidacyTransition,
  ballotRulesHash,
  buildWorkflowCycleMetrics,
  candidateSetHash,
  classifyWorkflowReportSensitiveProjection,
  electorateHash,
  normalizeProposalAggregate,
  planEligibilityPauseResolution,
  projectWorkflowReportSnapshot,
  workflowSha256,
  type CandidacyState,
  type EligibilityPauseResolutionCode,
  type ProposalAggregateCandidate,
  type WorkflowReportAudience,
} from "./core-workflow.js";
import { DataConflictError } from "./tenant-store.js";
import {
  acquireMemberEligibilityPolicySharedLock,
  inspectCurrentMemberEligibilityForOffice,
  MemberEligibilityGuardError,
  requireRoundCandidatesOperationallyEligible,
  type CurrentMemberEligibility,
} from "./member-eligibility-guard.js";
import {
  CANDIDACY_REVIEW_REASON_CODE_BY_STATE,
  CANDIDACY_REVIEW_REASON_CODES,
  ELIGIBILITY_PAUSE_REASON_CODE_BY_RESOLUTION,
  ELIGIBILITY_PAUSE_REASON_CODES,
  OFFICE_PROCESS_APPLICABILITY_REASON_CODE_BY_ENABLED,
  OFFICE_PROCESS_APPLICABILITY_REASON_CODES,
  ROUND_CLOSE_REASON_CODES,
  SESSION_DECISION_CODES,
  SESSION_DECISION_CODES_BY_OUTCOME,
  normalizeAllowedReasonCode,
} from "./reason-code.js";
import {
  appendSensitiveReadAuditEvent,
  SENSITIVE_READ_AUDIT_ACTIONS,
} from "./sensitive-read-audit.js";
import type { EncryptedEnvelope } from "./types.js";

export interface CycleInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly name: string;
  readonly locale: "es" | "en" | "fr";
  readonly timezone: string;
  readonly jurisdiction: string;
  readonly termStart: string;
  readonly termEnd: string;
  readonly normativeVersion: string;
  readonly configuration: Readonly<Record<string, unknown>>;
}

export interface CommitteeMemberInput {
  readonly identityId: string;
  readonly memberId?: string | null;
  readonly displayEnvelope: EncryptedEnvelope;
  readonly roleCode: "chair" | "pastor" | "secretary" | "member" | "custodian" | "advisor";
  readonly votingRight: boolean;
  readonly pastoralCapacity: boolean;
}

export interface ElectorInput {
  readonly identityId: string;
  readonly canPropose: boolean;
  readonly canVote: boolean;
  readonly recused: boolean;
}

export interface VacancyProcessInput {
  readonly officeId: string;
  readonly vacancyCount: number;
  readonly maxProposalSelections: number;
  readonly maxBallotSelections: number;
  readonly decisionRule: Readonly<Record<string, unknown>>;
  readonly abstentionRule: "EXCLUDED_FROM_CANDIDATE_TOTALS" | "INCLUDED_IN_ALL_RECEIVED_DENOMINATOR";
  readonly tiebreakPolicy: "NEW_BALLOT_ROUND" | "DOCUMENTED_HUMAN_RESOLUTION";
  readonly quorumRule: Readonly<Record<string, unknown>>;
  readonly aggregateAudience: "committee" | "auditor" | "church_after_publication";
  readonly agendaOrder: number;
}

interface CycleRow {
  readonly id: string;
  readonly status: "draft" | "active" | "closed" | "archived";
  readonly version: number;
}

interface SessionRow {
  readonly id: string;
  readonly cycle_id: string;
  readonly sequence: number;
  readonly title: string | null;
  readonly title_envelope: EncryptedEnvelope | null;
  readonly title_envelope_version: number;
  readonly starts_at: Date;
  readonly ends_at: Date;
  readonly status: "scheduled" | "in_progress" | "closed" | "cancelled";
  readonly location_envelope: EncryptedEnvelope | null;
  readonly version: number;
  readonly actual_started_at: Date | null;
  readonly actual_closed_at: Date | null;
  readonly created_at: Date;
  readonly updated_at: Date;
}

interface ProcessRow {
  readonly id: string;
  readonly cycle_id: string;
  readonly office_id: string;
  readonly phase: string;
  readonly vacancy_count: number;
  readonly max_proposal_selections: number;
  readonly max_ballot_selections: number;
  readonly decision_rule: Record<string, unknown>;
  readonly abstention_rule: string;
  readonly tiebreak_policy: string;
  readonly quorum_rule: Record<string, unknown>;
  readonly aggregate_audience: string;
  readonly enabled: boolean;
  readonly version: number;
}

interface ApplicabilityProcessRow {
  readonly id: string;
  readonly cycle_id: string;
  readonly office_id: string;
  readonly phase: string;
  readonly enabled: boolean;
  readonly version: number;
  readonly procedure_sequence: number;
  readonly updated_at: Date;
}

interface RoundRow {
  readonly id: string;
  readonly cycle_id: string;
  readonly process_id: string | null;
  readonly workflow_stage: "proposal" | "ballot" | "tiebreak" | null;
  readonly workflow_attempt: number;
  readonly phase: string;
  readonly submission_kind: "proposal" | "vote";
  readonly version: number;
  readonly max_proposal_selections: number;
  readonly max_ballot_selections: number;
  readonly candidate_set_hash: string;
  readonly rules_hash: string;
  readonly configuration_hash: string | null;
  readonly electorate_hash: string | null;
  readonly appointment_mechanism: string;
}

export const COUNCIL_BOARD_PROCEDURE_REQUIRED = "COUNCIL_BOARD_PROCEDURE_REQUIRED" as const;

interface AssignmentRow {
  readonly id: string;
  readonly vacancy_id: string;
  readonly member_id: string;
  readonly cycle_id: string;
  readonly office_id: string;
  readonly process_id: string | null;
  readonly state: string;
  readonly version: number;
  readonly effective: boolean;
  readonly member_snapshot: Record<string, unknown> | null;
  readonly office_snapshot: Record<string, unknown> | null;
}

export interface AssignmentEligibilityPausedResult extends Record<string, unknown> {
  readonly eligibilityPaused: true;
  readonly code: "ASSIGNMENT_ELIGIBILITY_PAUSED";
  readonly assignmentId: string;
  readonly memberId: string;
  readonly processId: string;
  readonly roundId: string | null;
  readonly pauseIds: readonly string[];
  readonly processVersion: number;
  readonly roundVersion: number | null;
  readonly message: string;
}

interface MemberOfficeEligibilityRow {
  readonly id: string;
  readonly member_version: number;
  readonly display_envelope: EncryptedEnvelope | null;
  readonly eligibility_department_id: string | null;
  readonly eligibility_valid_until: string | null;
  readonly eligibility_evaluated_on: string;
  readonly office_department_id: string | null;
  readonly eligibility_effective: boolean;
}

export class CoreWorkflowStore {
  public constructor(private readonly client: PoolClient) {}

  public async listCycles(): Promise<{ readonly items: readonly Record<string, unknown>[] }> {
    const result = await this.client.query<{
      id: string; name: string; status: string; locale: string; timezone: string; jurisdiction: string;
      term_start: string; term_end: string; normative_version: string; version: number;
      cloned_from_cycle_id: string | null; created_at: Date; updated_at: Date;
      activated_at: Date | null; closed_at: Date | null; archived_at: Date | null;
      processes: number; sessions: number; committee_members: number; electors: number;
    }>(
      `SELECT cycle.id,cycle.name,cycle.status,cycle.locale,cycle.timezone,cycle.jurisdiction,
              cycle.term_start::text,cycle.term_end::text,cycle.normative_version,cycle.version,
              cycle.cloned_from_cycle_id,cycle.created_at,cycle.updated_at,
              cycle.activated_at,cycle.closed_at,cycle.archived_at,
              (SELECT count(*)::int FROM office_processes process
                WHERE process.cycle_id=cycle.id AND process.enabled AND process.procedure_sequence=1) AS processes,
              (SELECT count(*)::int FROM cycle_sessions session WHERE session.cycle_id=cycle.id AND session.status <> 'cancelled') AS sessions,
              (SELECT count(*)::int FROM committee_memberships membership WHERE membership.cycle_id=cycle.id AND membership.status='active') AS committee_members,
              (SELECT count(*)::int FROM cycle_elector_roster roster WHERE roster.cycle_id=cycle.id AND roster.active) AS electors
         FROM election_cycles cycle
        ORDER BY cycle.created_at DESC,cycle.id`,
    );
    return {
      items: result.rows.map((cycle) => ({
        id: cycle.id,
        name: cycle.name,
        status: cycle.status,
        locale: cycle.locale,
        timezone: cycle.timezone,
        jurisdiction: cycle.jurisdiction,
        termStart: cycle.term_start,
        termEnd: cycle.term_end,
        normativeVersion: cycle.normative_version,
        version: cycle.version,
        clonedFromCycleId: cycle.cloned_from_cycle_id,
        createdAt: cycle.created_at,
        updatedAt: cycle.updated_at,
        activatedAt: cycle.activated_at,
        closedAt: cycle.closed_at,
        archivedAt: cycle.archived_at,
        readiness: {
          processes: cycle.processes,
          sessions: cycle.sessions,
          committeeMembers: cycle.committee_members,
          electors: cycle.electors,
        },
      })),
    };
  }

  public async createCycle(input: CycleInput): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.cycle.create", input.idempotencyKey, input, async () => {
      const id = randomUUID();
      const result = await this.client.query<{ created_at: Date }>(
        `INSERT INTO election_cycles(
           id,name,status,locale,timezone,jurisdiction,term_start,term_end,normative_version,
           configuration,created_by_identity_id
         ) VALUES ($1,$2,'draft',$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING created_at`,
        [
          id,
          input.name,
          input.locale,
          input.timezone,
          input.jurisdiction,
          input.termStart,
          input.termEnd,
          input.normativeVersion,
          input.configuration,
          input.identityId,
        ],
      );
      const createdAt = result.rows[0]?.created_at;
      if (!createdAt) throw new Error("Cycle creation did not return a row");
      await this.emit("cycle.created", "cycle", id, { cycleId: id, status: "draft", version: 1 });
      await this.appendAudit("cycle.created", "cycle", id, "success", {
        locale: input.locale,
        timezone: input.timezone,
        jurisdiction: input.jurisdiction,
        normativeVersion: input.normativeVersion,
        termStart: input.termStart,
        termEnd: input.termEnd,
      });
      return { id, status: "draft", version: 1, createdAt };
    });
  }

  public async cloneCycle(input: CycleInput & { readonly sourceCycleId: string }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.cycle.clone", input.idempotencyKey, input, async () => {
      const source = await this.client.query<{ id: string }>(
        "SELECT id FROM election_cycles WHERE id=$1 AND status IN ('active','closed','archived') FOR SHARE",
        [input.sourceCycleId],
      );
      if (!source.rows[0]) throw conflict("SOURCE_CYCLE_UNAVAILABLE", "Source cycle must be active, closed, or archived");
      const cycleId = randomUUID();
      await this.client.query(
        `INSERT INTO election_cycles(
           id,name,status,locale,timezone,jurisdiction,term_start,term_end,normative_version,
           configuration,cloned_from_cycle_id,created_by_identity_id
         ) VALUES ($1,$2,'draft',$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          cycleId,
          input.name,
          input.locale,
          input.timezone,
          input.jurisdiction,
          input.termStart,
          input.termEnd,
          input.normativeVersion,
          input.configuration,
          input.sourceCycleId,
          input.identityId,
        ],
      );
      const processes = await this.client.query<{
        id: string; office_id: string; vacancy_count: number; max_proposal_selections: number;
        max_ballot_selections: number; decision_rule: Record<string, unknown>; abstention_rule: string;
        tiebreak_policy: string; quorum_rule: Record<string, unknown>; aggregate_audience: string; agenda_order: number;
        appointment_mechanism: string;
      }>(
        `SELECT process.id,process.office_id,process.vacancy_count,process.max_proposal_selections,
                process.max_ballot_selections,process.decision_rule,process.abstention_rule,
                process.tiebreak_policy,process.quorum_rule,process.aggregate_audience,process.agenda_order,
                office.appointment_mechanism
           FROM office_processes process
           JOIN offices office ON office.id=process.office_id
          WHERE process.cycle_id=$1 AND process.enabled AND process.procedure_sequence=1
          ORDER BY process.agenda_order`,
        [input.sourceCycleId],
      );
      const cloneableProcesses = processes.rows.filter(({ appointment_mechanism }) =>
        isConfigurableVacancyProcessMechanism(appointment_mechanism));
      const skippedNonConfigurableProcessCount = processes.rows.length - cloneableProcesses.length;
      for (const process of cloneableProcesses) {
        const processId = randomUUID();
        await this.client.query(
          `INSERT INTO office_processes(
             id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
             decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,agenda_order,
             source_process_id,created_by_identity_id
           ) VALUES ($1,$2,$3,'CONFIGURADO',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            processId,
            cycleId,
            process.office_id,
            process.vacancy_count,
            process.max_proposal_selections,
            process.max_ballot_selections,
            process.decision_rule,
            process.abstention_rule,
            process.tiebreak_policy,
            process.quorum_rule,
            process.aggregate_audience,
            process.agenda_order,
            process.id,
            input.identityId,
          ],
        );
        for (let ordinal = 1; ordinal <= process.vacancy_count; ordinal += 1) {
          await this.client.query(
            `INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status,process_id)
             VALUES ($1,$2,$3,$4,'pending',$5)`,
            [randomUUID(), cycleId, process.office_id, ordinal, processId],
          );
        }
      }
      const forbiddenCopies = await this.client.query<{ submissions: number; assignments: number }>(
        `SELECT
           (SELECT count(*)::int FROM encrypted_submissions submission
             JOIN rounds round_state ON round_state.id=submission.round_id
            WHERE round_state.cycle_id=$1) AS submissions,
           (SELECT count(*)::int FROM assignments WHERE cycle_id=$1) AS assignments`,
        [cycleId],
      );
      if ((forbiddenCopies.rows[0]?.submissions ?? -1) !== 0 || (forbiddenCopies.rows[0]?.assignments ?? -1) !== 0) {
        throw new Error("Cycle clone copied forbidden election evidence");
      }
      await this.emit("cycle.cloned", "cycle", cycleId, {
        cycleId,
        sourceCycleId: input.sourceCycleId,
        processCount: cloneableProcesses.length,
        skippedNonConfigurableProcessCount,
        version: 1,
      });
      await this.appendAudit("cycle.cloned", "cycle", cycleId, "success", {
        sourceCycleId: input.sourceCycleId,
        processCount: cloneableProcesses.length,
        skippedNonConfigurableProcessCount,
        copiedSubmissions: 0,
        copiedAssignments: 0,
      });
      return {
        id: cycleId,
        sourceCycleId: input.sourceCycleId,
        status: "draft",
        version: 1,
        processCount: cloneableProcesses.length,
        skippedNonConfigurableProcessCount,
        copiedSubmissions: 0,
        copiedAssignments: 0,
      };
    });
  }

  public async addSession(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly cycleId: string;
    readonly sessionId: string; readonly expectedCycleVersion: number; readonly sequence: number;
    readonly titleEnvelope: EncryptedEnvelope;
    readonly startsAt: string; readonly endsAt: string; readonly locationEnvelope?: EncryptedEnvelope | null;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.session.create", input.idempotencyKey, input, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.titleEnvelope, input.locationEnvelope],
      });
      const cycle = await this.lockCycle(input.cycleId);
      assertVersion(cycle.version, input.expectedCycleVersion, "cycle");
      if (!['draft', 'active'].includes(cycle.status)) throw conflict("CYCLE_NOT_CONFIGURABLE", "Cycle no longer accepts sessions");
      const row = await this.client.query<SessionRow>(
        `INSERT INTO cycle_sessions(
           id,cycle_id,sequence,title,title_envelope,title_envelope_version,starts_at,ends_at,location_envelope,created_by_identity_id
         ) VALUES ($1,$2,$3,NULL,$4,1,$5,$6,$7,$8)
         RETURNING id,cycle_id,sequence,title,title_envelope,title_envelope_version,starts_at,ends_at,status,location_envelope,version,
                   actual_started_at,actual_closed_at,created_at,updated_at`,
        [input.sessionId, input.cycleId, input.sequence, input.titleEnvelope, input.startsAt, input.endsAt, input.locationEnvelope ?? null, input.identityId],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("SESSION_SEQUENCE_EXISTS", "Session sequence already exists in this cycle");
        throw error;
      });
      const cycleVersion = await this.bumpCycle(input.cycleId, cycle.version);
      await this.emit("cycle.session.created", "cycle", input.cycleId, { cycleId: input.cycleId, sessionId: input.sessionId, cycleVersion });
      await this.appendAudit("cycle.session.created", "cycle_session", input.sessionId, "success", {
        cycleId: input.cycleId,
        sequence: input.sequence,
        startsAt: input.startsAt,
        endsAt: input.endsAt,
        cycleVersion,
      });
      const session = row.rows[0];
      if (!session) throw new Error("Session create returned no row");
      return { ...sessionProjection(session), cycleVersion };
    });
  }

  public async updateSession(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly sessionId: string;
    readonly expectedVersion: number; readonly titleEnvelope?: EncryptedEnvelope; readonly startsAt?: string;
    readonly endsAt?: string; readonly locationEnvelope?: EncryptedEnvelope | null;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.session.update", input.idempotencyKey, input, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.titleEnvelope, input.locationEnvelope],
      });
      const session = await this.lockSession(input.sessionId);
      assertVersion(session.version, input.expectedVersion, "session");
      if (session.status !== "scheduled") throw conflict("SESSION_NOT_EDITABLE", "Only a scheduled session can be edited");
      const startsAt = input.startsAt ?? session.starts_at.toISOString();
      const endsAt = input.endsAt ?? session.ends_at.toISOString();
      if (Date.parse(endsAt) <= Date.parse(startsAt)) throw conflict("SESSION_TIME_INVALID", "Session end must follow its start");
      const updated = await this.client.query<SessionRow>(
        `UPDATE cycle_sessions
            SET title=CASE WHEN $3::jsonb IS NULL THEN title ELSE NULL END,
                title_envelope=COALESCE($3::jsonb,title_envelope),
                title_envelope_version=CASE WHEN $3::jsonb IS NULL THEN title_envelope_version ELSE title_envelope_version+1 END,
                starts_at=$4,ends_at=$5,location_envelope=$6,
                version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2
        RETURNING id,cycle_id,sequence,title,title_envelope,title_envelope_version,starts_at,ends_at,status,location_envelope,version,
                  actual_started_at,actual_closed_at,created_at,updated_at`,
        [session.id, session.version, input.titleEnvelope ?? null, startsAt, endsAt,
          input.locationEnvelope === undefined ? session.location_envelope : input.locationEnvelope],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Session changed during update");
      await this.emit("session.updated", "cycle_session", row.id, { sessionId: row.id, cycleId: row.cycle_id, version: row.version });
      await this.appendAudit("session.updated", "cycle_session", row.id, "success", { cycleId: row.cycle_id, version: row.version });
      return sessionProjection(row);
    });
  }

  public async listSessions(input: {
    readonly cycleId: string; readonly status?: "scheduled" | "in_progress" | "closed" | "cancelled";
    readonly sessionId?: string;
  }): Promise<{ readonly items: readonly Record<string, unknown>[] }> {
    const result = await this.client.query<SessionRow & { attendance_count: number; agenda_count: number; decision_count: number }>(
      `SELECT session.id,session.cycle_id,session.sequence,session.title,session.title_envelope,
              session.title_envelope_version,session.starts_at,session.ends_at,
              session.status,session.location_envelope,session.version,session.actual_started_at,
              session.actual_closed_at,session.created_at,session.updated_at,
              (SELECT count(*)::int FROM session_attendance attendance WHERE attendance.session_id=session.id) AS attendance_count,
              (SELECT count(*)::int FROM session_agenda_items agenda WHERE agenda.session_id=session.id) AS agenda_count,
              (SELECT count(*)::int FROM session_decisions decision WHERE decision.session_id=session.id) AS decision_count
         FROM cycle_sessions session
        WHERE session.cycle_id=$1 AND ($2::text IS NULL OR session.status=$2)
          AND ($3::uuid IS NULL OR session.id=$3)
        ORDER BY session.sequence,session.id`,
      [input.cycleId, input.status ?? null, input.sessionId ?? null],
    );
    return { items: result.rows.map((row) => ({ ...sessionProjection(row), attendanceCount: row.attendance_count, agendaCount: row.agenda_count, decisionCount: row.decision_count })) };
  }

  public async getSession(sessionId: string): Promise<Record<string, unknown> | null> {
    const sessionResult = await this.client.query<SessionRow>(
      `SELECT id,cycle_id,sequence,title,title_envelope,title_envelope_version,starts_at,ends_at,status,location_envelope,version,
              actual_started_at,actual_closed_at,created_at,updated_at
         FROM cycle_sessions WHERE id=$1`,
      [sessionId],
    );
    const session = sessionResult.rows[0];
    if (!session) return null;
    const [attendance, agenda] = await Promise.all([
      this.client.query<{
        identity_id: string; member_id: string | null; display_envelope_snapshot: EncryptedEnvelope | null;
        photo_snapshot: Record<string, unknown> | null; presence_status: string; advisory: boolean;
        voting_right: boolean; substitute_for_identity_id: string | null; version: number;
        recorded_by_identity_id: string; created_at: Date; updated_at: Date;
      }>(
        `SELECT identity_id,member_id,display_envelope_snapshot,photo_snapshot,presence_status,advisory,voting_right,substitute_for_identity_id,
                version,recorded_by_identity_id,created_at,updated_at
           FROM session_attendance WHERE session_id=$1 ORDER BY identity_id`,
        [sessionId],
      ),
      this.client.query<{
        id: string; position: number; title: string | null; title_envelope: EncryptedEnvelope | null;
        title_envelope_version: number; process_id: string | null;
        notes_envelope: EncryptedEnvelope | null; status: string; version: number;
        created_by_identity_id: string; created_at: Date; updated_at: Date;
        decision_id: string | null; decision_code: string | null; outcome: string | null;
        evidence_envelope: EncryptedEnvelope | null; decision_recorded_by: string | null; decision_created_at: Date | null;
      }>(
        `SELECT agenda.id,agenda.position,agenda.title,agenda.title_envelope,agenda.title_envelope_version,
                agenda.process_id,agenda.notes_envelope,
                agenda.status,agenda.version,agenda.created_by_identity_id,agenda.created_at,agenda.updated_at,
                decision.id AS decision_id,decision.decision_code,decision.outcome,decision.evidence_envelope,
                decision.recorded_by_identity_id AS decision_recorded_by,decision.created_at AS decision_created_at
           FROM session_agenda_items agenda
           LEFT JOIN session_decisions decision ON decision.agenda_item_id=agenda.id
          WHERE agenda.session_id=$1 ORDER BY agenda.position,agenda.id`,
        [sessionId],
      ),
    ]);
    return {
      ...sessionProjection(session),
      attendance: attendance.rows.map((row) => ({
        identityId: row.identity_id, memberId: row.member_id, presenceStatus: row.presence_status,
        displayEnvelope: row.display_envelope_snapshot, photoSnapshot: row.photo_snapshot,
        advisory: row.advisory, votingRight: row.voting_right,
        substituteForIdentityId: row.substitute_for_identity_id, version: row.version,
        recordedByIdentityId: row.recorded_by_identity_id, createdAt: row.created_at, updatedAt: row.updated_at,
      })),
      agendaItems: agenda.rows.map((row) => ({
        id: row.id, position: row.position,
        ...encryptedTitleProjection(row.title, row.title_envelope, row.title_envelope_version),
        processId: row.process_id,
        notesEnvelope: row.notes_envelope, status: row.status, version: row.version,
        createdByIdentityId: row.created_by_identity_id, createdAt: row.created_at, updatedAt: row.updated_at,
        decision: row.decision_id ? {
          id: row.decision_id, decisionCode: row.decision_code, outcome: row.outcome,
          evidenceEnvelope: row.evidence_envelope, recordedByIdentityId: row.decision_recorded_by,
          createdAt: row.decision_created_at,
        } : null,
      })),
    };
  }

  public async transitionSession(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly sessionId: string;
    readonly expectedVersion: number; readonly operation: "start" | "close";
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, `workflow.session.${input.operation}`, input.idempotencyKey, input, async () => {
      const session = await this.lockSession(input.sessionId);
      assertVersion(session.version, input.expectedVersion, "session");
      const expectedStatus = input.operation === "start" ? "scheduled" : "in_progress";
      if (session.status !== expectedStatus) throw conflict("SESSION_STATE_CONFLICT", `Session must be ${expectedStatus} to ${input.operation}`);
      if (input.operation === "close") {
        const unresolvedAgenda = await this.client.query("SELECT 1 FROM session_agenda_items WHERE session_id=$1 AND status NOT IN ('decided','deferred') LIMIT 1", [session.id]);
        if (unresolvedAgenda.rowCount) throw conflict("SESSION_AGENDA_UNRESOLVED", "Every agenda item must have a recorded decision or deferral before closing the session");
      }
      const nextStatus = input.operation === "start" ? "in_progress" : "closed";
      const updated = await this.client.query<SessionRow>(
        `UPDATE cycle_sessions SET status=$3,
                actual_started_at=CASE WHEN $3='in_progress' THEN clock_timestamp() ELSE actual_started_at END,
                actual_closed_at=CASE WHEN $3='closed' THEN clock_timestamp() ELSE actual_closed_at END,
                version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2
        RETURNING id,cycle_id,sequence,title,title_envelope,title_envelope_version,starts_at,ends_at,status,location_envelope,version,
                  actual_started_at,actual_closed_at,created_at,updated_at`,
        [session.id, session.version, nextStatus],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("SESSION_ALREADY_IN_PROGRESS", "Another session in this cycle is already in progress");
        throw error;
      });
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Session changed during transition");
      await this.emit(`session.${input.operation === "start" ? "started" : "closed"}`, "cycle_session", row.id, { sessionId: row.id, cycleId: row.cycle_id, version: row.version });
      await this.appendAudit(`session.${input.operation === "start" ? "started" : "closed"}`, "cycle_session", row.id, "success", { cycleId: row.cycle_id, version: row.version });
      return sessionProjection(row);
    });
  }

  public async upsertSessionAttendance(input: {
    readonly actorIdentityId: string; readonly idempotencyKey: string; readonly sessionId: string;
    readonly identityId: string; readonly activeTenantIdentityIds: readonly string[]; readonly expectedVersion: number;
    readonly memberId?: string | null; readonly presenceStatus: "PRESENT" | "REMOTE" | "ABSENT" | "EXCUSED";
    readonly advisory: boolean; readonly votingRight: boolean; readonly substituteForIdentityId?: string | null;
  }): Promise<Record<string, unknown>> {
    const request = { ...input, activeTenantIdentityIds: undefined };
    return this.executeIdempotent(input.actorIdentityId, "workflow.session.attendance.upsert", input.idempotencyKey, request, async () => {
      const session = await this.lockSession(input.sessionId);
      if (!['scheduled', 'in_progress'].includes(session.status)) throw conflict("SESSION_ATTENDANCE_CLOSED", "Attendance can be recorded only before or during a session");
      const active = new Set(input.activeTenantIdentityIds);
      if (!active.has(input.identityId) || (input.substituteForIdentityId && !active.has(input.substituteForIdentityId))) {
        throw conflict("ATTENDANCE_IDENTITY_UNAVAILABLE", "Participants and substituted identities require active tenant membership");
      }
      if (input.substituteForIdentityId === input.identityId) throw conflict("ATTENDANCE_SUBSTITUTE_INVALID", "A participant cannot substitute for itself");
      if (input.substituteForIdentityId && (!['PRESENT', 'REMOTE'].includes(input.presenceStatus) || input.advisory)) {
        throw conflict("ATTENDANCE_SUBSTITUTE_INVALID", "A substitute must be present or remote and cannot be advisory");
      }
      if (input.memberId) {
        const member = await this.client.query("SELECT 1 FROM members WHERE id=$1 AND archived_at IS NULL", [input.memberId]);
        if (!member.rowCount) throw conflict("ATTENDANCE_MEMBER_UNAVAILABLE", "Linked member is unavailable");
      }
      if (input.votingRight) {
        const votingIdentity = input.substituteForIdentityId ?? input.identityId;
        const votingSeat = await this.client.query(
          `SELECT 1 FROM committee_memberships
            WHERE cycle_id=$1 AND identity_id=$2 AND status='active' AND voting_right`,
          [session.cycle_id, votingIdentity],
        );
        if (!votingSeat.rowCount) throw conflict("ATTENDANCE_VOTING_RIGHT_INVALID", "Voting right requires an active voting committee seat, directly or by substitution");
      }
      const existing = await this.client.query<{ version: number; member_id: string | null }>(
        "SELECT version,member_id FROM session_attendance WHERE session_id=$1 AND identity_id=$2 FOR UPDATE",
        [session.id, input.identityId],
      );
      const currentVersion = existing.rows[0]?.version ?? 0;
      if (currentVersion !== input.expectedVersion) throw conflict("VERSION_CONFLICT", "Attendance version is stale");
      if (existing.rows[0] && existing.rows[0].member_id !== (input.memberId ?? null)) {
        throw conflict("ATTENDANCE_IDENTITY_SNAPSHOT_IMMUTABLE", "The linked member snapshot cannot change after attendance is first recorded");
      }
      const snapshots = await this.client.query<{
        display_envelope: EncryptedEnvelope | null; photo_snapshot: Record<string, unknown> | null;
      }>(
        `SELECT CASE WHEN $3::uuid IS NOT NULL THEN member.display_envelope ELSE membership.display_envelope END AS display_envelope,
                CASE WHEN photo.id IS NULL THEN NULL ELSE jsonb_build_object(
                  'id',photo.id,'memberId',photo.member_id,'version',photo.version,'mediaType',photo.media_type,
                  'width',photo.width,'height',photo.height,'plaintextBytes',photo.plaintext_bytes,
                  'contentHash',photo.content_hash,'envelope',photo.envelope
                ) END AS photo_snapshot
           FROM (SELECT 1) anchor
           LEFT JOIN committee_memberships membership
             ON membership.cycle_id=$1 AND membership.identity_id=$2 AND membership.status='active'
           LEFT JOIN members member ON member.id=COALESCE($3::uuid,membership.member_id)
           LEFT JOIN LATERAL (
             SELECT asset.* FROM member_photo_assets asset
              WHERE asset.member_id=member.id AND asset.archived_at IS NULL
              ORDER BY asset.version DESC LIMIT 1
           ) photo ON true`,
        [session.cycle_id, input.identityId, input.memberId ?? null],
      );
      const snapshot = snapshots.rows[0];
      if (!snapshot?.display_envelope) {
        throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "Attendance cannot snapshot an unavailable encrypted display identity");
      }
      const attendance = await this.client.query<{
        member_id: string | null; display_envelope_snapshot: EncryptedEnvelope | null;
        photo_snapshot: Record<string, unknown> | null; presence_status: string; advisory: boolean; voting_right: boolean;
        substitute_for_identity_id: string | null; version: number; created_at: Date; updated_at: Date;
      }>(
        `INSERT INTO session_attendance(
           session_id,identity_id,member_id,display_envelope_snapshot,photo_snapshot,presence_status,advisory,voting_right,
           substitute_for_identity_id,recorded_by_identity_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT(session_id,identity_id) DO UPDATE SET
           member_id=session_attendance.member_id,presence_status=EXCLUDED.presence_status,
           advisory=EXCLUDED.advisory,voting_right=EXCLUDED.voting_right,
           substitute_for_identity_id=EXCLUDED.substitute_for_identity_id,
           version=session_attendance.version+1,recorded_by_identity_id=EXCLUDED.recorded_by_identity_id,
           updated_at=clock_timestamp()
         RETURNING member_id,display_envelope_snapshot,photo_snapshot,presence_status,advisory,voting_right,
                   substitute_for_identity_id,version,created_at,updated_at`,
        [session.id, input.identityId, input.memberId ?? null, snapshot?.display_envelope ?? null,
          snapshot?.photo_snapshot ?? null, input.presenceStatus, input.advisory,
          input.votingRight, input.substituteForIdentityId ?? null, input.actorIdentityId],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("ATTENDANCE_SUBSTITUTE_CONFLICT", "The substituted identity already has a substitute in this session");
        throw error;
      });
      const row = attendance.rows[0];
      if (!row) throw new Error("Attendance upsert returned no row");
      const sessionVersion = await this.bumpSession(session.id, session.version);
      await this.emit("session.attendance.recorded", "cycle_session", session.id, { sessionId: session.id, identityId: input.identityId, version: row.version, sessionVersion });
      await this.appendAudit("session.attendance.recorded", "cycle_session", session.id, "success", { identityId: input.identityId, presenceStatus: row.presence_status, advisory: row.advisory, votingRight: row.voting_right, substituteForIdentityId: row.substitute_for_identity_id, version: row.version, sessionVersion });
      return {
        sessionId: session.id, identityId: input.identityId, memberId: row.member_id,
        displayEnvelope: row.display_envelope_snapshot, photoSnapshot: row.photo_snapshot,
        presenceStatus: row.presence_status, advisory: row.advisory, votingRight: row.voting_right,
        substituteForIdentityId: row.substitute_for_identity_id, version: row.version,
        sessionVersion, createdAt: row.created_at, updatedAt: row.updated_at,
      };
    });
  }

  public async addSessionAgendaItem(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly sessionId: string;
    readonly expectedSessionVersion: number; readonly itemId: string; readonly position: number;
    readonly titleEnvelope: EncryptedEnvelope; readonly processId?: string | null; readonly notesEnvelope?: EncryptedEnvelope | null;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.session.agenda.create", input.idempotencyKey, input, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.titleEnvelope, input.notesEnvelope],
      });
      const session = await this.lockSession(input.sessionId);
      assertVersion(session.version, input.expectedSessionVersion, "session");
      if (!['scheduled', 'in_progress'].includes(session.status)) throw conflict("SESSION_AGENDA_CLOSED", "Agenda items can be added only before or during a session");
      if (input.processId) {
        const process = await this.client.query(
          "SELECT 1 FROM office_processes WHERE id=$1 AND cycle_id=$2 AND enabled FOR SHARE",
          [input.processId, session.cycle_id],
        );
        if (!process.rowCount) throw conflict("SESSION_AGENDA_PROCESS_INVALID", "Agenda process must belong to the session cycle");
      }
      const inserted = await this.client.query<{ created_at: Date; updated_at: Date }>(
        `INSERT INTO session_agenda_items(
           id,session_id,position,title,title_envelope,title_envelope_version,process_id,notes_envelope,created_by_identity_id
         ) VALUES ($1,$2,$3,NULL,$4,1,$5,$6,$7) RETURNING created_at,updated_at`,
        [input.itemId, session.id, input.position, input.titleEnvelope, input.processId ?? null, input.notesEnvelope ?? null, input.identityId],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("SESSION_AGENDA_CONFLICT", "Agenda item id or position already exists");
        throw error;
      });
      const sessionVersion = await this.bumpSession(session.id, session.version);
      await this.emit("session.agenda.created", "cycle_session", session.id, { sessionId: session.id, agendaItemId: input.itemId, sessionVersion });
      await this.appendAudit("session.agenda.created", "cycle_session", session.id, "success", { agendaItemId: input.itemId, position: input.position, processId: input.processId ?? null, sessionVersion });
      return {
        id: input.itemId, sessionId: session.id, position: input.position,
        titleEnvelope: input.titleEnvelope, titleVersion: 1, legacyTitleUnavailable: false,
        processId: input.processId ?? null, notesEnvelope: input.notesEnvelope ?? null,
        status: "pending", version: 1, sessionVersion,
        createdAt: inserted.rows[0]?.created_at, updatedAt: inserted.rows[0]?.updated_at,
      };
    });
  }

  public async reorderSessionAgenda(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly sessionId: string;
    readonly expectedSessionVersion: number; readonly itemIds: readonly string[];
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.session.agenda.reorder", input.idempotencyKey, input, async () => {
      const session = await this.lockSession(input.sessionId);
      assertVersion(session.version, input.expectedSessionVersion, "session");
      if (session.status !== "scheduled") throw conflict("SESSION_AGENDA_ORDER_LOCKED", "Agenda order is locked once the session starts");
      assertUnique(input.itemIds, "SESSION_AGENDA_DUPLICATE", "Agenda item ids must be unique");
      const existing = await this.client.query<{ id: string }>("SELECT id FROM session_agenda_items WHERE session_id=$1 FOR UPDATE", [session.id]);
      if (existing.rows.length !== input.itemIds.length || existing.rows.some(({ id }) => !input.itemIds.includes(id))) {
        throw conflict("SESSION_AGENDA_SET_MISMATCH", "Agenda order must include every session item exactly once");
      }
      await this.client.query("UPDATE session_agenda_items SET position=position+1000000 WHERE session_id=$1", [session.id]);
      const agendaItems: Array<{ id: string; position: number; version: number }> = [];
      for (const [index, itemId] of input.itemIds.entries()) {
        const updated = await this.client.query<{ version: number }>(
          `UPDATE session_agenda_items SET position=$3,version=version+1,updated_at=clock_timestamp()
            WHERE session_id=$1 AND id=$2 RETURNING version`,
          [session.id, itemId, index + 1],
        );
        const version = updated.rows[0]?.version;
        if (!version) throw conflict("SESSION_AGENDA_SET_MISMATCH", "Agenda item disappeared during reorder");
        agendaItems.push({ id: itemId, position: index + 1, version });
      }
      const sessionVersion = await this.bumpSession(session.id, session.version);
      await this.emit("session.agenda.reordered", "cycle_session", session.id, { sessionId: session.id, sessionVersion });
      await this.appendAudit("session.agenda.reordered", "cycle_session", session.id, "success", { itemIds: input.itemIds, sessionVersion });
      return { id: session.id, version: sessionVersion, agendaItems };
    });
  }

  public async recordSessionDecision(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly sessionId: string;
    readonly expectedSessionVersion: number; readonly agendaItemId: string; readonly decisionCode: string;
    readonly outcome: "APPROVED" | "REJECTED" | "DEFERRED" | "RECORDED";
    readonly evidenceEnvelope?: EncryptedEnvelope | null;
  }): Promise<Record<string, unknown>> {
    const decisionCode = requireAllowedReasonCode(input.decisionCode, SESSION_DECISION_CODES);
    if (!(SESSION_DECISION_CODES_BY_OUTCOME[input.outcome] as readonly string[]).includes(decisionCode)) {
      throw conflict("INVALID_DECISION_CODE", "Session decision code must match the selected outcome");
    }
    return this.executeIdempotent(input.identityId, "workflow.session.decision.record", input.idempotencyKey, { ...input, decisionCode }, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.evidenceEnvelope],
      });
      const session = await this.lockSession(input.sessionId);
      assertVersion(session.version, input.expectedSessionVersion, "session");
      if (session.status !== "in_progress") throw conflict("SESSION_NOT_IN_PROGRESS", "Decisions require an in-progress session");
      const agenda = await this.client.query<{ status: string; version: number }>(
        "SELECT status,version FROM session_agenda_items WHERE session_id=$1 AND id=$2 FOR UPDATE",
        [session.id, input.agendaItemId],
      );
      const item = agenda.rows[0];
      if (!item) throw conflict("SESSION_AGENDA_ITEM_UNAVAILABLE", "Agenda item is unavailable");
      if (['decided', 'deferred'].includes(item.status)) throw conflict("SESSION_AGENDA_ALREADY_DECIDED", "Agenda item already has a terminal decision");
      const id = randomUUID();
      const decision = await this.client.query<{ created_at: Date }>(
        `INSERT INTO session_decisions(
           id,session_id,agenda_item_id,decision_code,outcome,evidence_envelope,recorded_by_identity_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
        [id, session.id, input.agendaItemId, decisionCode, input.outcome, input.evidenceEnvelope ?? null, input.identityId],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("SESSION_AGENDA_ALREADY_DECIDED", "Agenda item already has a decision");
        throw error;
      });
      const agendaStatus = input.outcome === "DEFERRED" ? "deferred" : "decided";
      const agendaUpdate = await this.client.query<{ version: number; updated_at: Date }>(
        `UPDATE session_agenda_items SET status=$3,version=version+1,updated_at=clock_timestamp()
          WHERE session_id=$1 AND id=$2 RETURNING version,updated_at`,
        [session.id, input.agendaItemId, agendaStatus],
      );
      const sessionVersion = await this.bumpSession(session.id, session.version);
      await this.emit("session.decision.recorded", "cycle_session", session.id, { sessionId: session.id, decisionId: id, agendaItemId: input.agendaItemId, outcome: input.outcome, sessionVersion });
      await this.appendAudit("session.decision.recorded", "cycle_session", session.id, "success", { decisionId: id, agendaItemId: input.agendaItemId, decisionCode, outcome: input.outcome, sessionVersion });
      return {
        id, sessionId: session.id, agendaItemId: input.agendaItemId, decisionCode,
        outcome: input.outcome, evidenceEnvelope: input.evidenceEnvelope ?? null,
        createdAt: decision.rows[0]?.created_at, agendaItemStatus: agendaStatus,
        agendaItemVersion: agendaUpdate.rows[0]?.version, sessionVersion,
      };
    });
  }

  public async configureCommittee(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly cycleId: string;
    readonly expectedCycleVersion: number; readonly members: readonly CommitteeMemberInput[];
    readonly activeTenantIdentityIds: readonly string[];
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.committee.configure", input.idempotencyKey, {
      cycleId: input.cycleId,
      expectedCycleVersion: input.expectedCycleVersion,
      members: input.members,
    }, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: input.members.map(({ displayEnvelope }) => displayEnvelope),
      });
      const cycle = await this.lockDraftCycle(input.cycleId, input.expectedCycleVersion);
      const identities = input.members.map((member) => member.identityId);
      assertUnique(identities, "COMMITTEE_DUPLICATE_IDENTITY", "Committee identities must be unique");
      const activeTenantIdentities = new Set(input.activeTenantIdentityIds);
      if (identities.some((identityId) => !activeTenantIdentities.has(identityId))) {
        throw conflict("COMMITTEE_IDENTITY_UNAVAILABLE", "Every committee identity must be an active identity with active membership in this tenant");
      }
      const memberIds = input.members.flatMap((member) => member.memberId ? [member.memberId] : []);
      assertUnique(memberIds, "COMMITTEE_DUPLICATE_MEMBER", "A member cannot occupy two committee seats");
      if (memberIds.length > 0) {
        const members = await this.client.query<{ id: string }>(
          "SELECT id FROM members WHERE id=ANY($1::uuid[]) AND archived_at IS NULL",
          [memberIds],
        );
        if (members.rowCount !== memberIds.length) throw conflict("COMMITTEE_MEMBER_UNAVAILABLE", "Every linked committee member must exist and be active");
      }
      await this.client.query(
        `UPDATE committee_memberships
            SET status='withdrawn',left_at=clock_timestamp()
          WHERE cycle_id=$1 AND status='active' AND NOT (identity_id=ANY($2::uuid[]))`,
        [input.cycleId, identities],
      );
      for (const member of input.members) {
        await this.client.query(
          `INSERT INTO committee_memberships(
             id,cycle_id,identity_id,member_id,display_envelope,role_code,voting_right,
             pastoral_capacity,status,joined_at,left_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',clock_timestamp(),NULL)
           ON CONFLICT(cycle_id,identity_id) DO UPDATE SET
             member_id=EXCLUDED.member_id,display_envelope=EXCLUDED.display_envelope,
             role_code=EXCLUDED.role_code,voting_right=EXCLUDED.voting_right,
             pastoral_capacity=EXCLUDED.pastoral_capacity,status='active',left_at=NULL`,
          [
            randomUUID(), input.cycleId, member.identityId, member.memberId ?? null,
            member.displayEnvelope, member.roleCode, member.votingRight, member.pastoralCapacity,
          ],
        );
      }
      const votingCount = input.members.filter(({ votingRight }) => votingRight).length;
      if (votingCount < 2) throw conflict("COMMITTEE_TOO_SMALL", "At least two committee members must have voting rights");
      const cycleVersion = await this.bumpCycle(input.cycleId, cycle.version);
      await this.emit("committee.configured", "cycle", input.cycleId, { cycleId: input.cycleId, memberCount: input.members.length, votingCount, cycleVersion });
      await this.appendAudit("committee.configured", "cycle", input.cycleId, "success", { memberCount: input.members.length, votingCount, cycleVersion });
      return { cycleId: input.cycleId, memberCount: input.members.length, votingCount, cycleVersion };
    });
  }

  public async configureElectorate(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly cycleId: string;
    readonly expectedCycleVersion: number; readonly electors: readonly ElectorInput[];
    readonly activeTenantIdentityIds: readonly string[];
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.electorate.configure", input.idempotencyKey, {
      identityId: input.identityId,
      idempotencyKey: input.idempotencyKey,
      cycleId: input.cycleId,
      expectedCycleVersion: input.expectedCycleVersion,
      electors: input.electors,
    }, async () => {
      const cycle = await this.lockDraftCycle(input.cycleId, input.expectedCycleVersion);
      const identities = input.electors.map(({ identityId }) => identityId);
      assertUnique(identities, "ELECTORATE_DUPLICATE_IDENTITY", "Elector identities must be unique");
      const activeTenantIdentities = new Set(input.activeTenantIdentityIds);
      if (identities.some((identityId) => !activeTenantIdentities.has(identityId))) {
        throw conflict("ELECTORATE_IDENTITY_UNAVAILABLE", "Every elector must have an active membership in this tenant");
      }
      const eligibleCommittee = await this.client.query<{ identity_id: string }>(
        `SELECT identity_id FROM committee_memberships
          WHERE cycle_id=$1 AND status='active' AND voting_right AND identity_id=ANY($2::uuid[])`,
        [input.cycleId, identities],
      );
      if (eligibleCommittee.rowCount !== identities.length) {
        throw conflict("ELECTOR_NOT_VOTING_COMMITTEE_MEMBER", "Every elector must be an active voting committee member");
      }
      await this.client.query(
        "UPDATE cycle_elector_roster SET active=false,version=version+1,configured_at=clock_timestamp(),configured_by_identity_id=$3 WHERE cycle_id=$1 AND active AND NOT (identity_id=ANY($2::uuid[]))",
        [input.cycleId, identities, input.identityId],
      );
      for (const elector of input.electors) {
        if (!elector.canPropose && !elector.canVote && !elector.recused) {
          throw conflict("ELECTORATE_INVALID", "An active non-recused elector must participate in proposals or ballots");
        }
        await this.client.query(
          `INSERT INTO cycle_elector_roster(
             cycle_id,identity_id,can_propose,can_vote,recused,active,configured_by_identity_id
           ) VALUES ($1,$2,$3,$4,$5,true,$6)
           ON CONFLICT(cycle_id,identity_id) DO UPDATE SET
             can_propose=EXCLUDED.can_propose,can_vote=EXCLUDED.can_vote,recused=EXCLUDED.recused,
             active=true,version=cycle_elector_roster.version+1,
             configured_by_identity_id=EXCLUDED.configured_by_identity_id,configured_at=clock_timestamp()`,
          [input.cycleId, elector.identityId, elector.canPropose, elector.canVote, elector.recused, input.identityId],
        );
      }
      const proposalCount = input.electors.filter(({ canPropose, recused }) => canPropose && !recused).length;
      const ballotCount = input.electors.filter(({ canVote, recused }) => canVote && !recused).length;
      if (proposalCount === 0 || ballotCount === 0) throw conflict("ELECTORATE_EMPTY", "At least one non-recused elector is required for both stages");
      const cycleVersion = await this.bumpCycle(input.cycleId, cycle.version);
      await this.emit("electorate.configured", "cycle", input.cycleId, { cycleId: input.cycleId, proposalCount, ballotCount, cycleVersion });
      await this.appendAudit("electorate.configured", "cycle", input.cycleId, "success", {
        rosterCount: input.electors.length,
        proposalCount,
        ballotCount,
        recusedCount: input.electors.filter(({ recused }) => recused).length,
        cycleVersion,
      });
      return { cycleId: input.cycleId, rosterCount: input.electors.length, proposalCount, ballotCount, cycleVersion };
    });
  }

  public async configureVacancyProcess(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly cycleId: string;
    readonly expectedCycleVersion: number; readonly configuration: VacancyProcessInput;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.vacancy-process.configure", input.idempotencyKey, input, async () => {
      const cycle = await this.lockDraftCycle(input.cycleId, input.expectedCycleVersion);
      const office = await this.client.query<{
        id: string; canonical_code: string; appointment_mechanism: string; cardinality: number; catalog_metadata: Record<string, unknown>;
      }>(
        "SELECT id,canonical_code,appointment_mechanism,cardinality,catalog_metadata FROM offices WHERE id=$1 AND active FOR SHARE",
        [input.configuration.officeId],
      );
      const officeRow = office.rows[0];
      if (!officeRow) throw conflict("OFFICE_UNAVAILABLE", "Office is not available in this catalog");
      assertConfigurableVacancyProcessMechanism(officeRow.appointment_mechanism);
      const catalogCardinality = officeRow.catalog_metadata["cardinality"];
      const catalogMaximum = catalogCardinality && typeof catalogCardinality === "object" && !Array.isArray(catalogCardinality)
        ? (catalogCardinality as Record<string, unknown>)["maximum"]
        : undefined;
      const effectiveMaximum = catalogMaximum === null
        ? null
        : typeof catalogMaximum === "number"
          ? catalogMaximum
          : officeRow.cardinality;
      if (effectiveMaximum !== null && input.configuration.vacancyCount > effectiveMaximum) {
        throw conflict("VACANCY_CARDINALITY_EXCEEDED", "Configured vacancies exceed the catalog cardinality");
      }
      if (input.configuration.maxBallotSelections > input.configuration.vacancyCount) {
        throw conflict("BALLOT_LIMIT_INVALID", "Ballot selection limit cannot exceed vacancies");
      }
      if (officeRow.appointment_mechanism === "linked_designation") {
        const linkedBase = officeRow.catalog_metadata["linkedBaseOfficeCode"];
        if (typeof linkedBase !== "string" || linkedBase.length === 0) {
          throw conflict("LINKED_BASE_UNCONFIGURED", "Linked office is missing its catalog base office");
        }
        const base = await this.client.query(
          `SELECT 1 FROM office_processes process
             JOIN offices office ON office.id=process.office_id
            WHERE process.cycle_id=$1 AND process.enabled AND office.canonical_code=$2`,
          [input.cycleId, linkedBase],
        );
        if (base.rowCount === 0) throw conflict("LINKED_BASE_UNCONFIGURED", "Configure the base office process before its linked responsibility");
      }
      const processId = randomUUID();
      await this.client.query(
        `INSERT INTO office_processes(
           id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
           decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,agenda_order,
           created_by_identity_id
         ) VALUES ($1,$2,$3,'CONFIGURADO',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [
          processId,
          input.cycleId,
          input.configuration.officeId,
          input.configuration.vacancyCount,
          input.configuration.maxProposalSelections,
          input.configuration.maxBallotSelections,
          input.configuration.decisionRule,
          input.configuration.abstentionRule,
          input.configuration.tiebreakPolicy,
          input.configuration.quorumRule,
          input.configuration.aggregateAudience,
          input.configuration.agendaOrder,
          input.identityId,
        ],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("VACANCY_PROCESS_EXISTS", "Office or agenda position is already configured in this cycle");
        throw error;
      });
      const vacancyIds: string[] = [];
      for (let ordinal = 1; ordinal <= input.configuration.vacancyCount; ordinal += 1) {
        const vacancyId = randomUUID();
        vacancyIds.push(vacancyId);
        await this.client.query(
          "INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status,process_id) VALUES ($1,$2,$3,$4,'pending',$5)",
          [vacancyId, input.cycleId, input.configuration.officeId, ordinal, processId],
        );
      }
      const cycleVersion = await this.bumpCycle(input.cycleId, cycle.version);
      await this.emit("vacancy-process.configured", "office_process", processId, {
        cycleId: input.cycleId,
        processId,
        officeId: input.configuration.officeId,
        vacancyCount: input.configuration.vacancyCount,
        phase: "CONFIGURADO",
        version: 1,
      });
      await this.appendAudit("vacancy-process.configured", "office_process", processId, "success", {
        cycleId: input.cycleId,
        officeCode: officeRow.canonical_code,
        vacancyCount: input.configuration.vacancyCount,
        maxProposalSelections: input.configuration.maxProposalSelections,
        maxBallotSelections: input.configuration.maxBallotSelections,
        cycleVersion,
      });
      return { processId, vacancyIds, phase: "CONFIGURADO", version: 1, cycleVersion };
    });
  }

  public async setOfficeProcessApplicability(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly processId: string;
    readonly expectedCycleVersion: number;
    readonly expectedProcessVersion: number;
    readonly enabled: boolean;
    readonly reasonCode: string;
  }): Promise<Record<string, unknown>> {
    const reasonCode = requireAllowedReasonCode(input.reasonCode, OFFICE_PROCESS_APPLICABILITY_REASON_CODES);
    if (reasonCode !== OFFICE_PROCESS_APPLICABILITY_REASON_CODE_BY_ENABLED[String(input.enabled) as "true" | "false"]) {
      throw conflict("INVALID_REASON_CODE", "Applicability reason code must match the requested state");
    }
    return this.executeIdempotent(
      input.identityId,
      "workflow.office-process.applicability.update",
      input.idempotencyKey,
      { ...input, reasonCode },
      async () => {
        const referenceResult = await this.client.query<{ cycle_id: string; office_id: string }>(
          "SELECT cycle_id,office_id FROM office_processes WHERE id=$1",
          [input.processId],
        );
        const reference = referenceResult.rows[0];
        if (!reference) throw conflict("OFFICE_PROCESS_UNAVAILABLE", "Office process is unavailable");

        const cycle = await this.lockCycle(reference.cycle_id);
        assertVersion(cycle.version, input.expectedCycleVersion, "cycle");
        if (!['draft', 'active'].includes(cycle.status)) {
          throw conflict("CYCLE_NOT_CONFIGURABLE", "Applicability can change only while the cycle is draft or active");
        }

        const groupResult = await this.client.query<ApplicabilityProcessRow>(
          `SELECT id,cycle_id,office_id,phase,enabled,version,procedure_sequence,updated_at
             FROM office_processes
            WHERE cycle_id=$1 AND office_id=$2
            ORDER BY procedure_sequence,id
            FOR UPDATE`,
          [reference.cycle_id, reference.office_id],
        );
        const anchor = groupResult.rows.find(({ id }) => id === input.processId);
        if (!anchor) throw conflict("OFFICE_PROCESS_UNAVAILABLE", "Office process is unavailable");
        assertVersion(anchor.version, input.expectedProcessVersion, "office process");

        const processes = groupResult.rows;
        const processIds = processes.map(({ id }) => id);
        const baseProcessId = processes.find(({ procedure_sequence }) => procedure_sequence === 1)?.id ?? anchor.id;
        const changed = processes.some(({ enabled }) => enabled !== input.enabled);
        if (!changed) {
          return {
            cycleId: cycle.id,
            officeId: reference.office_id,
            baseProcessId,
            affectedProcessIds: processIds,
            enabled: input.enabled,
            reasonCode,
            changed: false,
            cycleVersion: cycle.version,
            processVersions: processes.map((process) => ({ processId: process.id, version: process.version })),
            updatedAt: anchor.updated_at,
          };
        }

        if (!input.enabled) {
          await this.assertOfficeProcessGroupMayBeDisabled(reference.cycle_id, reference.office_id, processIds, processes);
        } else {
          await this.assertOfficeProcessGroupMayBeEnabled(reference.cycle_id, reference.office_id);
        }

        const updatedResult = await this.client.query<{ id: string; version: number; updated_at: Date }>(
          `UPDATE office_processes
              SET enabled=$2,version=version+1,updated_at=clock_timestamp()
            WHERE id=ANY($1::uuid[])
            RETURNING id,version,updated_at`,
          [processIds, input.enabled],
        );
        if (updatedResult.rows.length !== processIds.length) {
          throw conflict("VERSION_CONFLICT", "Office process group changed during applicability update");
        }
        const versions = new Map(updatedResult.rows.map((row) => [row.id, row]));
        const processVersions = processIds.map((processId) => ({
          processId,
          version: versions.get(processId)?.version,
        }));
        const cycleVersion = await this.bumpCycle(cycle.id, cycle.version);
        const updatedAt = versions.get(input.processId)?.updated_at ?? updatedResult.rows[0]?.updated_at;
        const eventPayload = {
          cycleId: cycle.id,
          officeId: reference.office_id,
          baseProcessId,
          affectedProcessIds: processIds,
          enabled: input.enabled,
          reasonCode,
          cycleVersion,
          processVersions,
        };
        await this.emit("office-process.applicability.updated", "office_process", input.processId, eventPayload);
        await this.appendAudit("office-process.applicability.updated", "office_process", input.processId, "success", {
          cycleId: cycle.id,
          officeId: reference.office_id,
          baseProcessId,
          affectedProcessIds: processIds,
          previousStates: processes.map((process) => ({ processId: process.id, enabled: process.enabled, version: process.version })),
          enabled: input.enabled,
          reasonCode,
          cycleVersion,
          processVersions,
        });
        return {
          ...eventPayload,
          changed: true,
          updatedAt,
        };
      },
    );
  }

  public async activateCycle(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly cycleId: string; readonly expectedVersion: number;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.cycle.activate", input.idempotencyKey, input, async () => {
      const cycle = await this.lockDraftCycle(input.cycleId, input.expectedVersion);
      const readiness = await this.client.query<{
        processes: number; sessions: number; voting_members: number; proposal_electors: number; ballot_electors: number;
        members: number; members_missing_display: number;
      }>(
        `SELECT
           (SELECT count(*)::int FROM office_processes
             WHERE cycle_id=$1 AND enabled AND procedure_sequence=1) AS processes,
           (SELECT count(*)::int FROM cycle_sessions WHERE cycle_id=$1 AND status='scheduled') AS sessions,
           (SELECT count(*)::int FROM committee_memberships WHERE cycle_id=$1 AND status='active' AND voting_right) AS voting_members,
           (SELECT count(*)::int FROM cycle_elector_roster WHERE cycle_id=$1 AND active AND can_propose AND NOT recused) AS proposal_electors,
           (SELECT count(*)::int FROM cycle_elector_roster WHERE cycle_id=$1 AND active AND can_vote AND NOT recused) AS ballot_electors,
           (SELECT count(*)::int FROM members WHERE archived_at IS NULL) AS members,
           (SELECT count(*)::int FROM members WHERE archived_at IS NULL AND display_envelope IS NULL) AS members_missing_display`,
        [input.cycleId],
      );
      const ready = readiness.rows[0];
      if (!ready || ready.processes === 0 || ready.sessions === 0 || ready.voting_members < 2 || ready.proposal_electors === 0 || ready.ballot_electors === 0 || ready.members === 0) {
        throw conflict("CYCLE_NOT_READY", "Cycle requires sessions, vacancy processes, committee, electorate, and members before activation");
      }
      if (ready.members_missing_display > 0) {
        throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "Every active member must have a split encrypted display identity before cycle activation");
      }
      await this.client.query(
        `INSERT INTO cycle_member_snapshots(
           cycle_id,member_id,member_version,eligibility_status,available,display_envelope,eligibility_envelope,
           eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
           eligibility_evaluated_on,eligibility_effective
         ) SELECT $1,member.id,member.version,member.eligibility_status,member.available,
                  member.display_envelope,member.eligibility_envelope,
                  member.eligibility_department_id,member.eligibility_valid_until,
                  (clock_timestamp() AT TIME ZONE settings.timezone)::date,
                  (member.eligibility_status='eligible'
                   AND member.available
                   AND (member.eligibility_valid_until IS NULL
                        OR member.eligibility_valid_until >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
                   AND (member.eligibility_department_id IS NULL OR COALESCE(restriction.active,false)))
             FROM members member
             CROSS JOIN tenant_settings settings
             LEFT JOIN departments restriction ON restriction.id=member.eligibility_department_id
            WHERE member.archived_at IS NULL AND settings.singleton=true
         ON CONFLICT(cycle_id,member_id) DO NOTHING`,
        [input.cycleId],
      );
      const updated = await this.client.query<{ version: number; activated_at: Date }>(
        `UPDATE election_cycles SET
           status='active',version=version+1,activated_at=clock_timestamp(),updated_at=clock_timestamp(),
           eligible_reference_count=(SELECT count(*)::int FROM cycle_member_snapshots WHERE cycle_id=$1 AND eligibility_effective)
         WHERE id=$1 AND version=$2 AND status='draft'
         RETURNING version,activated_at`,
        [input.cycleId, cycle.version],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("ACTIVE_CYCLE_EXISTS", "Another cycle is already active");
        throw error;
      });
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Cycle changed during activation");
      await this.emit("cycle.activated", "cycle", input.cycleId, { cycleId: input.cycleId, status: "active", version: row.version });
      await this.appendAudit("cycle.activated", "cycle", input.cycleId, "success", { ...ready, version: row.version });
      return { id: input.cycleId, status: "active", version: row.version, activatedAt: row.activated_at, readiness: ready };
    });
  }

  public async closeCycle(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly cycleId: string; readonly expectedVersion: number;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.cycle.close", input.idempotencyKey, input, async () => {
      const cycle = await this.lockCycle(input.cycleId);
      assertVersion(cycle.version, input.expectedVersion, "cycle");
      if (cycle.status !== "active") throw conflict("CYCLE_NOT_ACTIVE", "Only an active cycle can be institutionally closed");
      const blockers = await this.client.query<{
        unfinished_rounds: number; unfinished_processes: number; pending_decisions: number; sessions_in_progress: number;
      }>(
        `SELECT
           (SELECT count(*)::int FROM rounds
             WHERE cycle_id=$1 AND phase NOT IN ('CERRADO','ANULADO')) AS unfinished_rounds,
           (SELECT count(*)::int FROM office_processes
             WHERE cycle_id=$1 AND enabled
               AND phase NOT IN ('CERRADO','SIN_CANDIDATOS','VACANTE_PENDIENTE','ANULADO')) AS unfinished_processes,
           (SELECT count(*)::int FROM assignments
             WHERE cycle_id=$1 AND state IN (
               'PROPUESTA_INTERNA','ACEPTACION_PENDIENTE','ACEPTADA',
               'PRESENTADA_A_IGLESIA','ELEGIDA_POR_IGLESIA'
             )) AS pending_decisions,
           (SELECT count(*)::int FROM cycle_sessions
             WHERE cycle_id=$1 AND status='in_progress') AS sessions_in_progress`,
        [cycle.id],
      );
      const state = blockers.rows[0];
      if (!state) throw new Error("Cycle closure preconditions could not be evaluated");
      if (state.unfinished_rounds > 0) {
        throw conflict("CYCLE_ROUNDS_UNFINISHED", "Every workflow round must be consumed, closed, or annulled before cycle closure");
      }
      if (state.unfinished_processes > 0 || state.pending_decisions > 0 || state.sessions_in_progress > 0) {
        throw conflict("CYCLE_DECISIONS_PENDING", "Cycle closure requires terminal processes, compatible appointment decisions, and no session in progress");
      }
      const updated = await this.client.query<{ version: number; closed_at: Date }>(
        `UPDATE election_cycles
            SET status='closed',version=version+1,closed_at=clock_timestamp(),updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 AND status='active'
          RETURNING version,closed_at`,
        [cycle.id, cycle.version],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Cycle changed during institutional closure");
      await this.emit("cycle.closed", "cycle", cycle.id, { cycleId: cycle.id, status: "closed", version: row.version });
      await this.appendAudit("cycle.closed", "cycle", cycle.id, "success", { ...state, version: row.version });
      return { id: cycle.id, status: "closed", version: row.version, closedAt: row.closed_at };
    });
  }

  public async archiveCycle(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly cycleId: string; readonly expectedVersion: number;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "workflow.cycle.archive", input.idempotencyKey, input, async () => {
      const cycle = await this.lockCycle(input.cycleId);
      assertVersion(cycle.version, input.expectedVersion, "cycle");
      if (cycle.status !== "closed") throw conflict("CYCLE_NOT_CLOSED", "Only an institutionally closed cycle can be archived");
      const updated = await this.client.query<{ version: number; archived_at: Date }>(
        `UPDATE election_cycles
            SET status='archived',version=version+1,archived_at=clock_timestamp(),updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 AND status='closed'
          RETURNING version,archived_at`,
        [cycle.id, cycle.version],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Cycle changed during archival");
      await this.emit("cycle.archived", "cycle", cycle.id, { cycleId: cycle.id, status: "archived", version: row.version });
      await this.appendAudit("cycle.archived", "cycle", cycle.id, "success", { version: row.version });
      return { id: cycle.id, status: "archived", version: row.version, archivedAt: row.archived_at };
    });
  }

  public async createProposalRound(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly processId: string; readonly expectedProcessVersion: number;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.proposal-round.create", input.idempotencyKey, input, async () => {
      const process = await this.lockProcess(input.processId);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      if (!["CONFIGURADO", "SIN_CANDIDATOS", "VACANTE_PENDIENTE"].includes(process.phase)) {
        throw conflict("PHASE_CONFLICT", "Proposal round cannot be prepared from the current process phase");
      }
      await this.requireActiveCycle(process.cycle_id);
      return this.prepareProposalRoundRecord(process, input.identityId);
    });
  }

  public async resolveEligibilityPause(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly processId: string;
    readonly expectedProcessVersion: number;
    readonly expectedRoundVersion?: number | null;
    readonly expectedPauseIds: readonly string[];
    readonly resolutionCode: EligibilityPauseResolutionCode;
    readonly reasonCode: string;
    readonly evidenceEnvelope: EncryptedEnvelope;
  }): Promise<Record<string, unknown>> {
    const reasonCode = requireAllowedReasonCode(input.reasonCode, ELIGIBILITY_PAUSE_REASON_CODES);
    if (reasonCode !== ELIGIBILITY_PAUSE_REASON_CODE_BY_RESOLUTION[input.resolutionCode]) {
      throw conflict("INVALID_REASON_CODE", "Eligibility reason code must match the selected resolution");
    }
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.eligibility-pause.resolve", input.idempotencyKey, { ...input, reasonCode }, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.evidenceEnvelope],
      });
      const process = await this.lockProcess(input.processId);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      if (process.phase !== "PAUSADO") {
        throw conflict("ELIGIBILITY_PAUSE_UNAVAILABLE", "Office process is not paused by an unresolved eligibility incident");
      }
      const pauses = await this.client.query<{
        id: string; cycle_id: string; round_id: string | null; member_id: string;
        previous_process_phase: string; previous_round_phase: string | null;
      }>(
        `SELECT id,cycle_id,round_id,member_id,previous_process_phase,previous_round_phase
           FROM member_eligibility_workflow_pauses
          WHERE process_id=$1 AND resolved_at IS NULL
          ORDER BY id FOR UPDATE`,
        [process.id],
      );
      if (pauses.rowCount === 0) {
        throw conflict("ELIGIBILITY_PAUSE_UNAVAILABLE", "No unresolved eligibility incident exists for this process");
      }
      const actualPauseIds = pauses.rows.map(({ id }) => id).sort();
      const expectedPauseIds = [...input.expectedPauseIds].sort();
      if (actualPauseIds.length !== expectedPauseIds.length
          || actualPauseIds.some((id, index) => id !== expectedPauseIds[index])) {
        throw conflict("ELIGIBILITY_PAUSE_SET_CHANGED", "Eligibility incidents changed; reload before resolving them");
      }
      const firstPause = pauses.rows[0];
      if (!firstPause || firstPause.cycle_id !== process.cycle_id
          || pauses.rows.some((pause) => pause.cycle_id !== firstPause.cycle_id
            || pause.round_id !== firstPause.round_id
            || pause.previous_process_phase !== firstPause.previous_process_phase
            || pause.previous_round_phase !== firstPause.previous_round_phase)) {
        throw conflict("ELIGIBILITY_PAUSE_INVALID", "Active eligibility incidents do not share one recoverable workflow state");
      }
      await this.requireActiveCycle(process.cycle_id);
      const affectedMemberIds = [...new Set(pauses.rows.map(({ member_id }) => member_id))];
      const memberStates = await this.loadMemberEligibilityForOffice(affectedMemberIds, process.office_id);
      const affectedMembersEligible = memberStates.length === affectedMemberIds.length
        && memberStates.every((member) => member.eligibility_effective);
      const affectedCandidacies = await this.client.query<{ id: string; state: CandidacyState; version: number }>(
        `SELECT candidate.id,candidate.state,candidate.version
           FROM candidacies candidate
          WHERE candidate.process_id=$1
            AND candidate.member_id=ANY($2::uuid[])
            AND candidate.source_aggregate_id=(
              SELECT aggregate.id FROM proposal_aggregates aggregate
               WHERE aggregate.process_id=$1 ORDER BY aggregate.created_at DESC,aggregate.id DESC LIMIT 1
            )
          ORDER BY candidate.id FOR UPDATE`,
        [process.id, affectedMemberIds],
      );
      const affectedAssignments = await this.client.query<{
        id: string; state: string; effective: boolean;
      }>(
        `SELECT assignment.id,assignment.state,assignment.effective
           FROM assignments assignment
          WHERE assignment.process_id=$1
            AND assignment.member_id=ANY($2::uuid[])
          ORDER BY assignment.id FOR UPDATE`,
        [process.id, affectedMemberIds],
      );
      const affectedAssignmentIds = affectedAssignments.rows.map(({ id }) => id);
      const replacementProcesses = affectedAssignmentIds.length > 0
        ? await this.client.query<{ id: string; replacement_for_assignment_id: string }>(
            `SELECT replacement.id,replacement.replacement_for_assignment_id
               FROM office_processes replacement
              WHERE replacement.replacement_for_assignment_id=ANY($1::uuid[])
              ORDER BY replacement.id FOR SHARE`,
            [affectedAssignmentIds],
          )
        : { rows: [] as { id: string; replacement_for_assignment_id: string }[] };
      const activeAffectedAssignments = affectedAssignments.rows.filter(({ effective }) => effective);
      let replacementProcessId: string | null = null;
      if (input.resolutionCode === "CLOSE_AFTER_REPLACEMENT") {
        if (activeAffectedAssignments.length > 0) {
          throw conflict(
            "ASSIGNMENT_LIFECYCLE_REQUIRED",
            "Withdraw, decline, return, or substitute the affected assignment before closing the paused process",
          );
        }
        if (affectedAssignments.rows.length !== 1 || replacementProcesses.rows.length > 1) {
          throw conflict(
            "ASSIGNMENT_RESOLUTION_AMBIGUOUS",
            "Close-after-replacement requires exactly one affected assignment and one linked replacement procedure",
          );
        }
        replacementProcessId = replacementProcesses.rows[0]?.id ?? null;
      } else if (affectedAssignments.rows.length > 0) {
        const mayResumeActiveAssignment = input.resolutionCode === "RESUME_UNCHANGED"
          && activeAffectedAssignments.length === affectedAssignments.rows.length
          && replacementProcesses.rows.length === 0;
        if (!mayResumeActiveAssignment) {
          throw conflict(
            replacementProcesses.rows.length > 0
              ? "ASSIGNMENT_REPLACEMENT_ALREADY_OPEN"
              : "ASSIGNMENT_LIFECYCLE_REQUIRED",
            replacementProcesses.rows.length > 0
              ? "The affected assignment already has a replacement procedure; close the source process through the replacement resolution"
              : "Resolve the affected assignment lifecycle before changing the source process workflow",
          );
        }
      }
      const plan = planEligibilityPauseResolution({
        resolutionCode: input.resolutionCode,
        previousProcessPhase: firstPause.previous_process_phase,
        previousRoundPhase: firstPause.previous_round_phase,
        affectedMembersEligible,
        affectedCandidacyCount: affectedCandidacies.rows.length,
        replacementProcessAvailable: replacementProcessId !== null,
      });

      let roundVersion: number | null = null;
      if (firstPause.round_id) {
        if (!input.expectedRoundVersion) {
          throw conflict("ROUND_VERSION_REQUIRED", "The paused round version is required for resolution");
        }
        const round = await this.lockRound(firstPause.round_id);
        assertVersion(round.version, input.expectedRoundVersion, "round");
        if (round.process_id !== process.id || round.phase !== "PAUSADO") {
          throw conflict("ELIGIBILITY_PAUSE_INVALID", "The frozen round is no longer in the expected paused state");
        }
        const targetRoundPhase = plan.annulRound ? "ANULADO" : plan.roundPhase;
        if (!targetRoundPhase) throw conflict("ELIGIBILITY_PAUSE_INVALID", "Resolution did not produce a valid round state");
        const roundUpdate = await this.client.query<{ version: number }>(
          `UPDATE rounds SET phase=$2,version=version+1,
                  closed_at=CASE WHEN $2='ANULADO' THEN clock_timestamp() ELSE closed_at END
            WHERE id=$1 AND version=$3 AND phase='PAUSADO' RETURNING version`,
          [round.id, targetRoundPhase, round.version],
        );
        roundVersion = roundUpdate.rows[0]?.version ?? null;
        if (!roundVersion) throw conflict("VERSION_CONFLICT", "Paused round changed during eligibility resolution");
      } else if (input.expectedRoundVersion !== undefined && input.expectedRoundVersion !== null) {
        throw conflict("ROUND_VERSION_UNEXPECTED", "This eligibility pause is not attached to a mutable round");
      }

      const candidacyReviewIds: string[] = [];
      if (input.resolutionCode === "EXCLUDE_AND_REVIEW") {
        for (const candidate of affectedCandidacies.rows) {
          if (["WITHDRAWN", "EXCLUDED", "INELIGIBLE"].includes(candidate.state)) continue;
          const updated = await this.client.query<{ version: number }>(
            `UPDATE candidacies SET state='INELIGIBLE',version=version+1,updated_at=clock_timestamp()
              WHERE id=$1 AND version=$2 RETURNING version`,
            [candidate.id, candidate.version],
          );
          const candidacyVersion = updated.rows[0]?.version;
          if (!candidacyVersion) throw conflict("VERSION_CONFLICT", "Candidacy changed during eligibility resolution");
          const reviewId = randomUUID();
          candidacyReviewIds.push(reviewId);
          await this.client.query(
            `INSERT INTO candidacy_reviews(
               id,candidacy_id,from_state,to_state,reason_code,actor_identity_id,candidacy_version
             ) VALUES ($1,$2,$3,'INELIGIBLE',$4,$5,$6)`,
            [reviewId, candidate.id, candidate.state, reasonCode, input.identityId, candidacyVersion],
          );
        }
      }

      const processUpdate = await this.client.query<{ version: number }>(
        `UPDATE office_processes SET phase=$2,version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$3 AND phase='PAUSADO' RETURNING version`,
        [process.id, plan.processPhase, process.version],
      );
      const processVersion = processUpdate.rows[0]?.version;
      if (!processVersion) throw conflict("VERSION_CONFLICT", "Paused process changed during eligibility resolution");

      const replacementRound = plan.prepareProposalRound
        ? await this.prepareProposalRoundRecord({ ...process, phase: plan.processPhase, version: processVersion }, input.identityId)
        : null;
      const resolutionId = randomUUID();
      const resolved = await this.client.query<{ resolved_at: Date }>(
        `UPDATE member_eligibility_workflow_pauses SET
           resolution_id=$2,resolution_code=$3,resolution_reason_code=$4,
           resolution_evidence_envelope=$5,resolved_by_identity_id=$6,
           replacement_round_id=$7,replacement_process_id=$8,
           resolution_process_phase=$9,resolved_at=clock_timestamp()
         WHERE process_id=$1 AND id=ANY($10::uuid[]) AND resolved_at IS NULL
         RETURNING resolved_at`,
        [
          process.id, resolutionId, input.resolutionCode, reasonCode,
          input.evidenceEnvelope, input.identityId,
          replacementRound ? String(replacementRound["roundId"]) : null,
          replacementProcessId, plan.processPhase, actualPauseIds,
        ],
      );
      if (resolved.rows.length !== actualPauseIds.length) {
        throw conflict("ELIGIBILITY_PAUSE_SET_CHANGED", "Eligibility incidents changed during resolution");
      }
      const outcome = {
        resolutionId,
        resolutionCode: input.resolutionCode,
        reasonCode,
        processId: process.id,
        processPhase: plan.processPhase,
        processVersion,
        roundId: firstPause.round_id,
        roundVersion,
        replacementRound,
        replacementProcessId,
        pauseIds: actualPauseIds,
        candidacyReviewIds,
        resolvedAt: resolved.rows[0]?.resolved_at,
      };
      await this.emit("eligibility-pause.resolved", "office_process", process.id, {
        resolutionId, resolutionCode: input.resolutionCode, processId: process.id,
        processPhase: plan.processPhase, processVersion, roundId: firstPause.round_id,
        replacementRoundId: replacementRound?.["roundId"] ?? null,
        replacementProcessId, pauseCount: actualPauseIds.length,
      });
      await this.appendAudit("eligibility-pause.resolved", "office_process", process.id, "success", {
        resolutionId, resolutionCode: input.resolutionCode, reasonCode,
        previousProcessPhase: firstPause.previous_process_phase,
        previousRoundPhase: firstPause.previous_round_phase,
        processPhase: plan.processPhase, processVersion, roundId: firstPause.round_id,
        replacementRoundId: replacementRound?.["roundId"] ?? null,
        replacementProcessId,
        pauseIds: actualPauseIds, candidacyReviewIds,
      });
      return outcome;
    });
  }

  public async openProposalRound(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly roundId: string;
    readonly expectedRoundVersion: number; readonly expectedProcessVersion: number;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.proposal-round.open", input.idempotencyKey, input, async () => {
      const round = await this.lockRound(input.roundId);
      if (!round.process_id || round.submission_kind !== "proposal" || round.phase !== "CONFIGURADO") {
        throw conflict("PHASE_CONFLICT", "Proposal round is not prepared for opening");
      }
      assertVersion(round.version, input.expectedRoundVersion, "round");
      const process = await this.lockProcess(round.process_id);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      if (!["CONFIGURADO", "SIN_CANDIDATOS", "VACANTE_PENDIENTE"].includes(process.phase)) {
        throw conflict("PHASE_CONFLICT", "Office process does not permit proposal opening");
      }
      await this.assertRoundCandidatesEligible(round.id, process.office_id);
      const updatedRound = await this.client.query<{ version: number; opened_at: Date }>(
        `UPDATE rounds SET phase='PROPUESTAS_ABIERTAS',version=version+1,opened_at=clock_timestamp(),closed_at=NULL
          WHERE id=$1 AND version=$2 AND phase='CONFIGURADO' RETURNING version,opened_at`,
        [round.id, round.version],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("ANOTHER_ROUND_ACTIVE", "Another round is already active in this cycle");
        throw error;
      });
      const updatedProcess = await this.client.query<{ version: number }>(
        `UPDATE office_processes SET phase='PROPUESTAS_ABIERTAS',version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 RETURNING version`,
        [process.id, process.version],
      );
      const roundState = updatedRound.rows[0];
      const processVersion = updatedProcess.rows[0]?.version;
      if (!roundState || !processVersion) throw conflict("VERSION_CONFLICT", "Workflow changed during proposal opening");
      await this.emit("round.phase", "round", round.id, { roundId: round.id, processId: process.id, phase: "PROPUESTAS_ABIERTAS", version: roundState.version });
      await this.appendAudit("proposal-round.opened", "round", round.id, "success", { processId: process.id, roundVersion: roundState.version, processVersion });
      return { roundId: round.id, processId: process.id, phase: "PROPUESTAS_ABIERTAS", version: roundState.version, processVersion, openedAt: roundState.opened_at };
    });
  }

  public async closeProposalRound(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly roundId: string;
    readonly expectedRoundVersion: number; readonly expectedProcessVersion: number; readonly reasonCode: string;
  }): Promise<Record<string, unknown>> {
    return this.closeSubmissionRound({ ...input, kind: "proposal" });
  }

  public async createProposalManifest(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly roundId: string;
    readonly expectedRoundVersion: number;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.proposal-manifest.create", input.idempotencyKey, input, async () => {
      const round = await this.lockRound(input.roundId);
      if (round.submission_kind !== "proposal" || round.phase !== "PROPUESTAS_CERRADAS") {
        throw conflict("PHASE_CONFLICT", "Proposal manifest requires a closed proposal round");
      }
      assertVersion(round.version, input.expectedRoundVersion, "round");
      await this.assertRoundCandidatesEligible(round.id);
      const counts = await this.participationCounts(round.id, "proposal");
      if (counts.received !== counts.required) throw conflict("PARTICIPATION_INCOMPLETE", "Proposal manifest requires every frozen elector response");
      const submissions = await this.client.query<{
        receipt_id: string; receipt_content_hash: string; content_hash: string; submission_round_version: number;
      }>(
        `SELECT receipt.id AS receipt_id,receipt.content_hash AS receipt_content_hash,submission.content_hash,
                submission.round_version AS submission_round_version
           FROM encrypted_submissions submission
           JOIN participation_receipts receipt ON receipt.submission_id=submission.id
          WHERE submission.round_id=$1 AND submission.kind='proposal' AND receipt.kind='proposal'
          ORDER BY receipt.id`,
        [round.id],
      );
      if (submissions.rows.length !== counts.required || submissions.rows.some((row) => row.receipt_content_hash !== row.content_hash)) {
        throw conflict("RECEIPT_SET_INVALID", "Every proposal must have one matching opaque receipt");
      }
      const tenant = await this.client.query<{ tenant_id: string }>(
        "SELECT current_setting('app.tenant_id') AS tenant_id",
      );
      const candidateResult = await this.client.query<{ candidate_id: string }>(
        "SELECT candidate_id FROM candidate_snapshots WHERE round_id=$1 AND eligible ORDER BY candidate_id",
        [round.id],
      );
      if (candidateResult.rowCount === 0) throw conflict("CANDIDATE_POOL_EMPTY", "Proposal manifest has no frozen eligible candidates");
      const candidateIds = candidateResult.rows.map((candidate) => candidate.candidate_id);
      const entries = submissions.rows.map((row, index) => ({
        position: index + 1,
        receiptId: row.receipt_id,
        contentHash: row.content_hash,
        submissionRoundVersion: row.submission_round_version,
      }));
      const manifestBody = {
        schemaVersion: 1 as const,
        tenantId: tenant.rows[0]?.tenant_id,
        roundId: round.id,
        roundVersion: round.version,
        candidateSetHash: round.candidate_set_hash,
        rulesHash: round.rules_hash,
        configurationHash: round.configuration_hash,
        electorateHash: round.electorate_hash,
        candidateIds,
        entries,
      };
      const manifestHash = workflowSha256(manifestBody);
      const manifestId = randomUUID();
      const created = await this.client.query<{ created_at: Date }>(
        `INSERT INTO proposal_manifests(
           id,round_id,round_version,manifest_hash,entry_count,created_by_identity_id
         ) VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`,
        [manifestId, round.id, round.version, manifestHash, entries.length, input.identityId],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("PROPOSAL_MANIFEST_EXISTS", "A proposal manifest already exists for this round");
        throw error;
      });
      for (const entry of entries) {
        await this.client.query(
          `INSERT INTO proposal_manifest_entries(manifest_id,position,receipt_id,content_hash,submission_round_version)
           VALUES ($1,$2,$3,$4,$5)`,
          [manifestId, entry.position, entry.receiptId, entry.contentHash, entry.submissionRoundVersion],
        );
      }
      await this.emit("proposal-manifest.created", "round", round.id, {
        roundId: round.id,
        manifestId,
        manifestHash,
        entryCount: entries.length,
      });
      await this.appendAudit("proposal-manifest.created", "proposal_manifest", manifestId, "success", {
        roundId: round.id,
        roundVersion: round.version,
        manifestHash,
        entryCount: entries.length,
      });
      return { manifestId, manifestHash, ...manifestBody, createdAt: created.rows[0]?.created_at };
    });
  }

  public async getProposalManifest(roundId: string): Promise<Record<string, unknown> | null> {
    const manifestResult = await this.client.query<{
      id: string; round_id: string; round_version: number; manifest_hash: string; entry_count: number;
      created_at: Date; phase: string; candidate_set_hash: string; rules_hash: string;
      configuration_hash: string | null; electorate_hash: string | null;
    }>(
      `SELECT manifest.id,manifest.round_id,manifest.round_version,manifest.manifest_hash,
              manifest.entry_count,manifest.created_at,round_state.phase,round_state.candidate_set_hash,
              round_state.rules_hash,round_state.configuration_hash,round_state.electorate_hash
         FROM proposal_manifests manifest
         JOIN rounds round_state ON round_state.id=manifest.round_id
        WHERE manifest.round_id=$1 AND round_state.submission_kind='proposal'
          AND round_state.phase IN ('PROPUESTAS_CERRADAS','CERRADO')`,
      [roundId],
    );
    const manifest = manifestResult.rows[0];
    if (!manifest) return null;
    const entries = await this.client.query<{
      position: number; receipt_id: string; content_hash: string; submission_round_version: number; envelope: EncryptedEnvelope;
    }>(
      `SELECT entry.position,entry.receipt_id,entry.content_hash,entry.submission_round_version,submission.envelope
         FROM proposal_manifest_entries entry
         JOIN participation_receipts receipt ON receipt.id=entry.receipt_id
         JOIN encrypted_submissions submission ON submission.id=receipt.submission_id
        WHERE entry.manifest_id=$1 AND submission.kind='proposal'
        ORDER BY entry.position`,
      [manifest.id],
    );
    if (entries.rows.length !== manifest.entry_count) throw conflict("PROPOSAL_MANIFEST_INVALID", "Stored proposal manifest is incomplete");
    const tenant = await this.client.query<{ tenant_id: string }>("SELECT current_setting('app.tenant_id') AS tenant_id");
    const candidates = await this.client.query<{ candidate_id: string }>(
      "SELECT candidate_id FROM candidate_snapshots WHERE round_id=$1 AND eligible ORDER BY candidate_id",
      [manifest.round_id],
    );
    await this.appendAudit("proposal-manifest.read", "proposal_manifest", manifest.id, "success", {
      roundId: manifest.round_id,
      manifestHash: manifest.manifest_hash,
      entryCount: manifest.entry_count,
    });
    return {
      manifestId: manifest.id,
      manifestHash: manifest.manifest_hash,
      schemaVersion: 1,
      tenantId: tenant.rows[0]?.tenant_id,
      roundId: manifest.round_id,
      roundVersion: manifest.round_version,
      candidateSetHash: manifest.candidate_set_hash,
      rulesHash: manifest.rules_hash,
      configurationHash: manifest.configuration_hash,
      electorateHash: manifest.electorate_hash,
      candidateIds: candidates.rows.map((candidate) => candidate.candidate_id),
      entryCount: manifest.entry_count,
      createdAt: manifest.created_at,
      entries: entries.rows.map((entry) => ({
        position: entry.position,
        receiptId: entry.receipt_id,
        contentHash: entry.content_hash,
        submissionRoundVersion: entry.submission_round_version,
        envelope: entry.envelope,
      })),
    };
  }

  public async consolidateProposals(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly roundId: string;
    readonly expectedRoundVersion: number; readonly expectedProcessVersion: number;
    readonly manifestId: string; readonly manifestHash: string;
    readonly effectiveResponseDenominator: number;
    readonly aggregateHash: string; readonly candidates: readonly ProposalAggregateCandidate[];
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.proposals.consolidate", input.idempotencyKey, input, async () => {
      const round = await this.lockRound(input.roundId);
      if (!round.process_id || round.submission_kind !== "proposal" || round.phase !== "PROPUESTAS_CERRADAS") {
        throw conflict("PHASE_CONFLICT", "Only a closed proposal round can be consolidated");
      }
      assertVersion(round.version, input.expectedRoundVersion, "round");
      const process = await this.lockProcess(round.process_id);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      if (process.phase !== "PROPUESTAS_CERRADAS") throw conflict("PHASE_CONFLICT", "Office process is not awaiting proposal consolidation");
      await this.assertRoundCandidatesEligible(round.id, process.office_id);
      // Proposal manifests are immutable append-only evidence. The round and
      // process FOR UPDATE locks above serialize consolidation; locking this
      // row too would only require an invalid UPDATE grant for the runtime role.
      const manifestResult = await this.client.query<{ id: string; manifest_hash: string; round_version: number; entry_count: number }>(
        `SELECT id,manifest_hash,round_version,entry_count FROM proposal_manifests
          WHERE id=$1 AND round_id=$2`,
        [input.manifestId, round.id],
      );
      const manifest = manifestResult.rows[0];
      if (!manifest || manifest.manifest_hash !== input.manifestHash || manifest.round_version !== round.version) {
        throw conflict("PROPOSAL_MANIFEST_MISMATCH", "Proposal aggregate is not bound to the immutable closed-round manifest");
      }
      const counts = await this.participationCounts(round.id, "proposal");
      if (manifest.entry_count !== counts.received) throw conflict("PROPOSAL_MANIFEST_MISMATCH", "Proposal manifest count differs from frozen participation");
      const aggregate = normalizeProposalAggregate({
        sourceRoundId: round.id,
        sourceManifestHash: manifest.manifest_hash,
        completedResponses: counts.received,
        electorateDenominator: counts.required,
        effectiveResponseDenominator: input.effectiveResponseDenominator,
        maxProposalSelections: process.max_proposal_selections,
        candidates: input.candidates,
      });
      const computedHash = workflowSha256(aggregate);
      if (computedHash !== input.aggregateHash) throw conflict("PROPOSAL_AGGREGATE_HASH_MISMATCH", "Proposal aggregate hash is invalid");
      const memberIds = aggregate.candidates.map(({ memberId }) => memberId);
      const currentEligibility = await this.requireMembersEligibleForOffice(
        memberIds,
        process.office_id,
        "PROPOSED_MEMBER_INELIGIBLE",
        "Every aggregate candidate must remain eligible for this office on the tenant civil date",
      );
      const members = memberIds.length === 0
        ? { rows: [] as Array<{ member_id: string; member_version: number; display_envelope: EncryptedEnvelope | null; photo_snapshot: Record<string, unknown> | null; available: boolean; assigned: number }> }
        : await this.client.query<{
            member_id: string; member_version: number; display_envelope: EncryptedEnvelope | null;
            photo_snapshot: Record<string, unknown> | null; available: boolean; assigned: number;
          }>(
            `SELECT frozen.member_id,
                    COALESCE(frozen.member_version_snapshot,snapshot.member_version) AS member_version,
                    frozen.display_envelope,snapshot.available,
                    (SELECT jsonb_build_object(
                       'id',photo.id,'memberId',photo.member_id,'version',photo.version,
                       'mediaType',photo.media_type,'width',photo.width,'height',photo.height,
                       'plaintextBytes',photo.plaintext_bytes,'contentHash',photo.content_hash,
                       'createdAt',photo.created_at,'archivedAt',photo.archived_at,'envelope',photo.envelope
                     )
                       FROM member_photo_assets photo
                       WHERE photo.member_id=frozen.member_id AND photo.archived_at IS NULL
                      ORDER BY photo.version DESC LIMIT 1) AS photo_snapshot,
                    (SELECT count(*)::int FROM assignments assignment WHERE assignment.member_id=frozen.member_id AND assignment.effective) AS assigned
               FROM candidate_snapshots frozen
               JOIN cycle_member_snapshots snapshot
                 ON snapshot.cycle_id=$1 AND snapshot.member_id=frozen.member_id
              WHERE frozen.round_id=$2 AND frozen.member_id=ANY($3::uuid[])
                AND frozen.eligible AND frozen.eligibility_effective`,
            [process.cycle_id, round.id, memberIds],
          );
      if (members.rows.length !== memberIds.length) {
        throw conflict("PROPOSED_MEMBER_INELIGIBLE", "Every aggregate candidate must belong to the frozen eligible cycle snapshot");
      }
      const aggregateId = randomUUID();
      await this.client.query(
        `INSERT INTO proposal_aggregates(
           id,process_id,source_round_id,source_manifest_id,aggregate_hash,completed_responses,
           electorate_denominator,effective_response_denominator,created_by_identity_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [aggregateId, process.id, round.id, manifest.id, computedHash, counts.received, counts.required,
          input.effectiveResponseDenominator, input.identityId],
      );
      const candidacyIds: string[] = [];
      for (const candidate of aggregate.candidates) {
        const member = members.rows.find(({ member_id }) => member_id === candidate.memberId);
        if (!member) throw new Error("Eligible proposal member disappeared during consolidation");
        const eligibility = currentEligibility.find(({ id }) => id === candidate.memberId);
        if (!eligibility) throw new Error("Current proposal-member eligibility disappeared during consolidation");
        if (!member.display_envelope) throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "The frozen candidate display identity is unavailable");
        const candidacyId = randomUUID();
        candidacyIds.push(candidacyId);
        await this.client.query(
           `INSERT INTO candidacies(
              id,process_id,member_id,source_aggregate_id,member_version,display_envelope_snapshot,photo_snapshot,state,
              distinct_proponent_count,electorate_denominator,support_denominator,available_snapshot,already_assigned_count,
              eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
              eligibility_evaluated_on,eligibility_effective_snapshot
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,'PROPOSED',$8,$9,$10,$11,$12,$13,$14,$15,true)`,
           [
              candidacyId, process.id, candidate.memberId, aggregateId, member.member_version,
              member.display_envelope, member.photo_snapshot, candidate.distinctProponentCount, counts.required,
              input.effectiveResponseDenominator, member.available, member.assigned,
              eligibility.eligibility_department_id, eligibility.eligibility_valid_until,
              eligibility.eligibility_evaluated_on,
           ],
        );
      }
      const nextPhase = candidacyIds.length === 0 ? "SIN_CANDIDATOS" : "DEPURACION";
      const roundUpdate = await this.client.query<{ version: number }>(
        "UPDATE rounds SET phase='CERRADO',version=version+1 WHERE id=$1 AND version=$2 RETURNING version",
        [round.id, round.version],
      );
      const processUpdate = await this.client.query<{ version: number }>(
        "UPDATE office_processes SET phase=$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$3 RETURNING version",
        [process.id, nextPhase, process.version],
      );
      const roundVersion = roundUpdate.rows[0]?.version;
      const processVersion = processUpdate.rows[0]?.version;
      if (!roundVersion || !processVersion) throw conflict("VERSION_CONFLICT", "Workflow changed during consolidation");
      await this.emit("proposals.consolidated", "office_process", process.id, {
        processId: process.id,
        sourceRoundId: round.id,
        sourceManifestId: manifest.id,
        sourceManifestHash: manifest.manifest_hash,
        aggregateHash: computedHash,
        candidacyCount: candidacyIds.length,
        phase: nextPhase,
        processVersion,
      });
      await this.appendAudit("proposals.consolidated", "proposal_aggregate", aggregateId, "success", {
        processId: process.id,
        sourceRoundId: round.id,
        sourceManifestId: manifest.id,
        sourceManifestHash: manifest.manifest_hash,
        aggregateHash: computedHash,
        completedResponses: counts.received,
        electorateDenominator: counts.required,
        effectiveResponseDenominator: input.effectiveResponseDenominator,
        candidacyCount: candidacyIds.length,
      });
      return { aggregateId, aggregateHash: computedHash, sourceManifestId: manifest.id, sourceManifestHash: manifest.manifest_hash, processId: process.id, candidacyIds, phase: nextPhase, processVersion, roundVersion };
    });
  }

  public async reviewCandidacy(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly processId: string; readonly candidacyId: string;
    readonly expectedVersion: number; readonly toState: Exclude<CandidacyState, "PROPOSED" | "CONFIRMED_FOR_BALLOT">;
    readonly reasonCode: string; readonly rationaleEnvelope?: EncryptedEnvelope | null; readonly restrictedNoteEnvelope?: EncryptedEnvelope | null;
  }): Promise<Record<string, unknown>> {
    const reasonCode = requireAllowedReasonCode(input.reasonCode, CANDIDACY_REVIEW_REASON_CODES);
    if (reasonCode !== CANDIDACY_REVIEW_REASON_CODE_BY_STATE[input.toState]) {
      throw conflict("INVALID_REASON_CODE", "Candidacy reason code must match the selected review decision");
    }
    return this.executeIdempotent(input.identityId, "workflow.candidacy.review", input.idempotencyKey, { ...input, reasonCode }, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.rationaleEnvelope, input.restrictedNoteEnvelope],
      });
      const process = await this.lockProcess(input.processId);
      if (process.phase !== "DEPURACION") throw conflict("PHASE_CONFLICT", "Candidate review requires the review phase");
      const result = await this.client.query<{ state: CandidacyState; version: number }>(
        `SELECT candidate.state,candidate.version
           FROM candidacies candidate
          WHERE candidate.id=$1 AND candidate.process_id=$2
            AND candidate.source_aggregate_id=(
              SELECT aggregate.id FROM proposal_aggregates aggregate
               WHERE aggregate.process_id=$2 ORDER BY aggregate.created_at DESC,aggregate.id DESC LIMIT 1
            )
          FOR UPDATE`,
        [input.candidacyId, input.processId],
      );
      const candidate = result.rows[0];
      if (!candidate) throw conflict("CANDIDACY_UNAVAILABLE", "Candidacy is unavailable in this process");
      assertVersion(candidate.version, input.expectedVersion, "candidacy");
      assertCandidacyTransition(candidate.state, input.toState);
      const updated = await this.client.query<{ version: number; updated_at: Date }>(
        `UPDATE candidacies SET state=$2,version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$3 RETURNING version,updated_at`,
        [input.candidacyId, input.toState, candidate.version],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Candidacy changed during review");
      const reviewId = randomUUID();
      await this.client.query(
        `INSERT INTO candidacy_reviews(
           id,candidacy_id,from_state,to_state,reason_code,rationale_envelope,
           restricted_note_envelope,actor_identity_id,candidacy_version
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          reviewId, input.candidacyId, candidate.state, input.toState, reasonCode,
          input.rationaleEnvelope ?? null, input.restrictedNoteEnvelope ?? null, input.identityId, row.version,
        ],
      );
      await this.emit("candidacy.reviewed", "candidacy", input.candidacyId, { candidacyId: input.candidacyId, processId: process.id, state: input.toState, version: row.version });
      await this.appendAudit("candidacy.reviewed", "candidacy", input.candidacyId, "success", { fromState: candidate.state, toState: input.toState, reasonCode, version: row.version });
      return { reviewId, candidacyId: input.candidacyId, processId: process.id, state: input.toState, version: row.version, updatedAt: row.updated_at };
    });
  }

  public async confirmCandidateList(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly processId: string;
    readonly expectedProcessVersion: number; readonly orderedCandidacyIds: readonly string[];
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.candidate-list.confirm", input.idempotencyKey, input, async () => {
      assertUnique(input.orderedCandidacyIds, "CANDIDATE_SET_INVALID", "Confirmed candidacies must be unique");
      const process = await this.lockProcess(input.processId);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      if (process.phase !== "DEPURACION") throw conflict("PHASE_CONFLICT", "Candidate list confirmation requires the review phase");
      const candidacies = await this.client.query<{
        id: string; member_id: string; state: CandidacyState; version: number; display_envelope_snapshot: EncryptedEnvelope | null;
        eligibility_snapshot_effective: boolean;
      }>(
        `SELECT candidate.id,candidate.member_id,candidate.state,candidate.version,candidate.display_envelope_snapshot,
                (candidate.eligibility_effective_snapshot
                 AND (candidate.eligibility_valid_until_snapshot IS NULL
                      OR candidate.eligibility_valid_until_snapshot >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
                 AND (candidate.eligibility_department_id_snapshot IS NULL
                      OR (candidate.eligibility_department_id_snapshot=office.department_id
                          AND COALESCE(restriction.active,false)))) AS eligibility_snapshot_effective
           FROM candidacies candidate
           JOIN offices office ON office.id=$2 AND office.active
           CROSS JOIN tenant_settings settings
           LEFT JOIN departments restriction ON restriction.id=candidate.eligibility_department_id_snapshot
          WHERE candidate.process_id=$1 AND settings.singleton=true
            AND candidate.source_aggregate_id=(
              SELECT aggregate.id FROM proposal_aggregates aggregate
               WHERE aggregate.process_id=$1 ORDER BY aggregate.created_at DESC,aggregate.id DESC LIMIT 1
            )
          ORDER BY candidate.id FOR UPDATE OF candidate`,
        [process.id, process.office_id],
      );
      const selected = input.orderedCandidacyIds.map((id) => candidacies.rows.find((candidate) => candidate.id === id));
      if (selected.some((candidate) => !candidate)) throw conflict("CANDIDATE_SET_INVALID", "Confirmed list contains a candidacy outside this process");
      const selectedIds = new Set(input.orderedCandidacyIds);
      const unresolved = candidacies.rows.filter((candidate) => !selectedIds.has(candidate.id) && !["WITHDRAWN", "EXCLUDED", "INELIGIBLE"].includes(candidate.state));
      if (unresolved.length > 0) throw conflict("CANDIDACY_REVIEW_INCOMPLETE", "Every omitted candidacy needs an explicit terminal review decision");
      for (const candidate of selected) {
        if (!candidate) continue;
        if (!["UNDER_REVIEW", "PRELIMINARY_ACCEPTED"].includes(candidate.state)) {
          throw conflict("CANDIDATE_NOT_CONFIRMABLE", "Every ballot candidate must complete human review");
        }
        if (!candidate.eligibility_snapshot_effective) {
          throw conflict("CANDIDATE_NOT_ELIGIBLE", "A selected candidacy is outside its frozen office scope or validity window");
        }
        if (!candidate.display_envelope_snapshot) {
          throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "A selected historical candidacy has no split encrypted display identity");
        }
      }
      const normalizedCandidates = selected.flatMap((candidate) => candidate ? [{ candidateId: candidate.id, memberId: candidate.member_id }] : []);
      const currentEligibility = await this.requireMembersEligibleForOffice(
        normalizedCandidates.map(({ memberId }) => memberId),
        process.office_id,
        "CANDIDATE_NOT_ELIGIBLE",
        "Every selected candidacy must remain eligible for this office on the tenant civil date",
      );
      const setHash = candidateSetHash(normalizedCandidates);
      if (selected.length > 0 && selected.length < process.max_ballot_selections) {
        throw conflict("CANDIDATE_SET_TOO_SMALL", "Confirmed candidate set is smaller than the frozen ballot selection limit");
      }
      const rulesHash = ballotRulesHash(process.max_ballot_selections);
      const listVersionResult = await this.client.query<{ version: number }>(
        "SELECT COALESCE(max(version),0)::int + 1 AS version FROM candidate_list_versions WHERE process_id=$1",
        [process.id],
      );
      const listVersion = listVersionResult.rows[0]?.version ?? 1;
      const listId = randomUUID();
      await this.client.query(
        `INSERT INTO candidate_list_versions(id,process_id,version,candidate_set_hash,rules_hash,created_by_identity_id)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [listId, process.id, listVersion, setHash, rulesHash, input.identityId],
      );
      for (let index = 0; index < selected.length; index += 1) {
        const candidate = selected[index];
        if (!candidate) continue;
        if (!candidate.display_envelope_snapshot) throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "Candidate display identity is unavailable");
        const eligibility = currentEligibility.find(({ id }) => id === candidate.member_id);
        if (!eligibility) throw new Error("Current candidate eligibility disappeared during list confirmation");
        const nextVersion = candidate.version + 1;
        await this.client.query(
          "UPDATE candidacies SET state='CONFIRMED_FOR_BALLOT',version=$2,updated_at=clock_timestamp() WHERE id=$1 AND version=$3",
          [candidate.id, nextVersion, candidate.version],
        );
        await this.client.query(
          `INSERT INTO candidacy_reviews(
             id,candidacy_id,from_state,to_state,reason_code,actor_identity_id,candidacy_version
           ) VALUES ($1,$2,$3,'CONFIRMED_FOR_BALLOT','FINAL_LIST_CONFIRMED',$4,$5)`,
          [randomUUID(), candidate.id, candidate.state, input.identityId, nextVersion],
        );
        await this.client.query(
          `INSERT INTO candidate_list_entries(
             list_id,candidacy_id,candidate_id,member_id,display_envelope_snapshot,visible_order,
             eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
             eligibility_evaluated_on,eligibility_effective_snapshot
           ) VALUES ($1,$2,$2,$3,$4,$5,$6,$7,$8,true)`,
          [
            listId, candidate.id, candidate.member_id, candidate.display_envelope_snapshot, index + 1,
            eligibility.eligibility_department_id, eligibility.eligibility_valid_until,
            eligibility.eligibility_evaluated_on,
          ],
        );
      }
      const nextPhase = selected.length === 0 ? "SIN_CANDIDATOS" : "LISTA_CONFIRMADA";
      const updated = await this.client.query<{ version: number }>(
        "UPDATE office_processes SET phase=$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$3 RETURNING version",
        [process.id, nextPhase, process.version],
      );
      const processVersion = updated.rows[0]?.version;
      if (!processVersion) throw conflict("VERSION_CONFLICT", "Office process changed during list confirmation");
      await this.emit("candidate-list.confirmed", "office_process", process.id, { processId: process.id, listId, candidateSetHash: setHash, candidateCount: selected.length, phase: nextPhase, processVersion });
      await this.appendAudit("candidate-list.confirmed", "candidate_list", listId, "success", { processId: process.id, candidateSetHash: setHash, rulesHash, candidateCount: selected.length, processVersion });
      return { listId, listVersion, processId: process.id, candidateSetHash: setHash, rulesHash, candidateCount: selected.length, phase: nextPhase, processVersion };
    });
  }

  public async prepareBallotRound(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly processId: string; readonly expectedProcessVersion: number;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.ballot-round.prepare", input.idempotencyKey, input, async () => {
      const process = await this.lockProcess(input.processId);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      await this.assertDirectElectionAllowed(process.office_id);
      if (process.phase !== "LISTA_CONFIRMADA") throw conflict("PHASE_CONFLICT", "Ballot preparation requires a confirmed candidate list");
      const list = await this.client.query<{ id: string; candidate_set_hash: string; rules_hash: string }>(
        "SELECT id,candidate_set_hash,rules_hash FROM candidate_list_versions WHERE process_id=$1 ORDER BY version DESC LIMIT 1",
        [process.id],
      );
      const listRow = list.rows[0];
      if (!listRow) throw conflict("CANDIDATE_LIST_UNAVAILABLE", "Confirmed candidate list is unavailable");
      const entries = await this.client.query<{
        candidate_id: string; member_id: string; display_envelope_snapshot: EncryptedEnvelope | null;
        visible_order: number; assigned: number; eligibility_snapshot_effective: boolean;
      }>(
        `SELECT entry.candidate_id,entry.member_id,entry.display_envelope_snapshot,entry.visible_order,
                (entry.eligibility_effective_snapshot
                 AND (entry.eligibility_valid_until_snapshot IS NULL
                      OR entry.eligibility_valid_until_snapshot >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
                 AND (entry.eligibility_department_id_snapshot IS NULL
                      OR (entry.eligibility_department_id_snapshot=office.department_id
                          AND COALESCE(restriction.active,false)))) AS eligibility_snapshot_effective,
                (SELECT count(*)::int FROM assignments assignment WHERE assignment.member_id=entry.member_id AND assignment.effective) AS assigned
           FROM candidate_list_entries entry
           JOIN offices office ON office.id=$2 AND office.active
           CROSS JOIN tenant_settings settings
           LEFT JOIN departments restriction ON restriction.id=entry.eligibility_department_id_snapshot
          WHERE entry.list_id=$1 AND settings.singleton=true
          ORDER BY entry.visible_order`,
        [listRow.id, process.office_id],
      );
      if (entries.rowCount === 0) throw conflict("CANDIDATE_POOL_EMPTY", "Cannot prepare a ballot without candidates");
      if (entries.rows.some((entry) => !entry.eligibility_snapshot_effective)) {
        throw conflict("CANDIDATE_NOT_ELIGIBLE", "The confirmed list contains a member outside its frozen office scope or validity window");
      }
      if (entries.rows.some((entry) => !entry.display_envelope_snapshot)) {
        throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "The confirmed candidate list contains an unavailable encrypted display identity");
      }
      const currentEligibility = await this.requireMembersEligibleForOffice(
        entries.rows.map(({ member_id }) => member_id),
        process.office_id,
        "CANDIDATE_NOT_ELIGIBLE",
        "Every ballot candidate must remain eligible for this office on the tenant civil date",
      );
      const roster = await this.loadElectors(process.cycle_id, "vote");
      if (roster.filter(({ canSubmit, recused }) => canSubmit && !recused).length === 0) throw conflict("ELECTORATE_EMPTY", "Ballot electorate is empty");
      const roundId = randomUUID();
      const frozenElectorateHash = electorateHash(roster);
      const configurationHash = workflowSha256({ candidateSetHash: listRow.candidate_set_hash, rulesHash: listRow.rules_hash, electorateHash: frozenElectorateHash });
      const workflowAttempt = await this.nextRoundAttempt(process.id, "ballot");
      await this.client.query(
        `INSERT INTO rounds(
           id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,candidate_set_hash,rules_hash,
           vacancy_id,max_proposal_selections,max_ballot_selections,process_id,workflow_stage,
           workflow_attempt,configuration_hash,electorate_hash,decision_rule
         ) VALUES ($1,$2,$3,'LISTA_CONFIRMADA','vote',$4,$5,$6,$7,
           COALESCE(
             (SELECT reused_vacancy_id FROM office_processes WHERE id=$8),
             (SELECT id FROM vacancies WHERE process_id=$8 ORDER BY ordinal LIMIT 1)
           ),$9,$5,$8,'ballot',$10,$11,$12,$13)`,
        [
          roundId, process.cycle_id, process.office_id, process.vacancy_count,
          process.max_ballot_selections, listRow.candidate_set_hash, listRow.rules_hash, process.id,
          process.max_proposal_selections, workflowAttempt, configurationHash, frozenElectorateHash, process.decision_rule,
        ],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("BALLOT_ROUND_EXISTS", "A ballot round already exists for this process");
        throw error;
      });
      await this.insertRoundElectors(roundId, roster);
      for (const entry of entries.rows) {
        const eligibility = currentEligibility.find(({ id }) => id === entry.member_id);
        if (!eligibility) throw new Error("Current candidate eligibility disappeared during ballot preparation");
        await this.client.query(
          `INSERT INTO candidate_snapshots(
             round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
             member_version_snapshot,eligibility_department_id_snapshot,
             eligibility_valid_until_snapshot,eligibility_evaluated_on,eligibility_effective
           ) VALUES ($1,$2,$3,$4,true,$5,$6,$7,$8,$9,$10,true)`,
          [
            roundId, entry.candidate_id, entry.member_id, entry.display_envelope_snapshot,
            entry.visible_order, entry.assigned, eligibility.member_version,
            eligibility.eligibility_department_id, eligibility.eligibility_valid_until,
            eligibility.eligibility_evaluated_on,
          ],
        );
      }
      await this.emit("ballot-round.prepared", "round", roundId, { roundId, processId: process.id, phase: "LISTA_CONFIRMADA", version: 1 });
      await this.appendAudit("ballot-round.prepared", "round", roundId, "success", {
        processId: process.id,
        candidateSetHash: listRow.candidate_set_hash,
        rulesHash: listRow.rules_hash,
        electorateHash: frozenElectorateHash,
        configurationHash,
        candidateCount: entries.rows.length,
        electorateCount: roster.filter(({ canSubmit, recused }) => canSubmit && !recused).length,
      });
      return { roundId, processId: process.id, workflowStage: "ballot", workflowAttempt, phase: "LISTA_CONFIRMADA", version: 1, candidateSetHash: listRow.candidate_set_hash, rulesHash: listRow.rules_hash, electorateHash: frozenElectorateHash, configurationHash };
    });
  }

  public async prepareTiebreakRound(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly processId: string;
    readonly expectedProcessVersion: number; readonly sourceRoundId: string; readonly expectedAggregateHash: string;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.tiebreak-round.prepare", input.idempotencyKey, input, async () => {
      const process = await this.lockProcess(input.processId);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      await this.assertDirectElectionAllowed(process.office_id);
      if (process.phase !== "DESEMPATE_PENDIENTE") throw conflict("PHASE_CONFLICT", "Tiebreak preparation requires a pending tiebreak decision");
      if (process.tiebreak_policy !== "NEW_BALLOT_ROUND") throw conflict("TIEBREAK_POLICY_MISMATCH", "This process does not permit a new ballot tiebreak");
      await this.requireActiveCycle(process.cycle_id);
      const latestRound = await this.client.query<{ id: string }>(
        `SELECT id FROM rounds
          WHERE process_id=$1 AND submission_kind='vote' AND workflow_stage IN ('ballot','tiebreak')
          ORDER BY created_at DESC,id DESC LIMIT 1`,
        [process.id],
      );
      if (latestRound.rows[0]?.id !== input.sourceRoundId) {
        throw conflict("TIEBREAK_SOURCE_STALE", "Tiebreak must branch from the latest consumed ballot result");
      }
      const sourceRound = await this.lockRound(input.sourceRoundId);
      if (sourceRound.process_id !== process.id || sourceRound.submission_kind !== "vote" || sourceRound.phase !== "CERRADO") {
        throw conflict("TIEBREAK_SOURCE_INVALID", "Tiebreak source must be a consumed published ballot from this process");
      }
      const publishedResult = await this.client.query<{
        id: string; agreed_aggregate_hash: string; agreed_aggregate: {
          decision: {
            status: string; selectedCandidateIds: string[]; tiebreakCandidateIds: string[]; unfilledSeats: number;
          };
        };
      }>(
        `SELECT id,agreed_aggregate_hash,agreed_aggregate
           FROM tally_manifests WHERE round_id=$1 AND state='published' FOR SHARE`,
        [sourceRound.id],
      );
      const published = publishedResult.rows[0];
      if (!published || published.agreed_aggregate_hash !== input.expectedAggregateHash) {
        throw conflict("AGGREGATE_HASH_MISMATCH", "Tiebreak source aggregate does not match the published evidence");
      }
      const decision = published.agreed_aggregate.decision;
      if (!['TIEBREAK_REQUIRED', 'PARTIAL_SELECTION'].includes(decision.status)
          || decision.tiebreakCandidateIds.length < 2
          || decision.unfilledSeats <= 0) {
        throw conflict("TIEBREAK_NOT_REQUIRED", "Published decision does not require another ballot round");
      }
      assertUnique(decision.tiebreakCandidateIds, "PUBLISHED_AGGREGATE_INVALID", "Tiebreak candidates must be unique");
      const candidates = await this.client.query<{
        candidate_id: string; member_id: string; display_envelope: EncryptedEnvelope | null; visible_order: number; already_assigned_count: number;
      }>(
        `SELECT snapshot.candidate_id,snapshot.member_id,snapshot.display_envelope,
                snapshot.visible_order,snapshot.already_assigned_count
           FROM candidate_snapshots snapshot
           JOIN offices office ON office.id=$3 AND office.active
           CROSS JOIN tenant_settings settings
           LEFT JOIN departments restriction ON restriction.id=snapshot.eligibility_department_id_snapshot
          WHERE snapshot.round_id=$1 AND snapshot.candidate_id=ANY($2::uuid[])
            AND settings.singleton=true AND snapshot.eligible AND snapshot.eligibility_effective
            AND (snapshot.eligibility_valid_until_snapshot IS NULL
                 OR snapshot.eligibility_valid_until_snapshot >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
            AND (snapshot.eligibility_department_id_snapshot IS NULL
                 OR (snapshot.eligibility_department_id_snapshot=office.department_id
                     AND COALESCE(restriction.active,false)))
          ORDER BY snapshot.candidate_id`,
        [sourceRound.id, decision.tiebreakCandidateIds, process.office_id],
      );
      if (candidates.rows.length !== decision.tiebreakCandidateIds.length) {
        throw conflict("PUBLISHED_AGGREGATE_INVALID", "Tiebreak decision references a candidate outside the frozen source ballot");
      }
      if (candidates.rows.some((candidate) => !candidate.display_envelope)) {
        throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "The tiebreak candidate set contains an unavailable encrypted display identity");
      }
      const currentEligibility = await this.requireMembersEligibleForOffice(
        candidates.rows.map(({ member_id }) => member_id),
        process.office_id,
        "CANDIDATE_NOT_ELIGIBLE",
        "Every tiebreak candidate must remain eligible for this office on the tenant civil date",
      );
      const availableVacancies = await this.client.query<{ count: number }>(
        `SELECT count(*)::int AS count FROM vacancies vacancy
          WHERE (vacancy.process_id=$1 OR vacancy.id=(SELECT reused_vacancy_id FROM office_processes WHERE id=$1))
            AND vacancy.status IN ('pending','vacant')`,
        [process.id],
      );
      if ((availableVacancies.rows[0]?.count ?? 0) < decision.unfilledSeats) {
        throw conflict("VACANCY_CAPACITY_EXCEEDED", "Tiebreak decision exceeds the remaining process vacancies");
      }
      const maxSelections = Math.min(process.max_ballot_selections, decision.unfilledSeats, candidates.rows.length);
      const setHash = candidateSetHash(candidates.rows.map((candidate) => ({
        candidateId: candidate.candidate_id,
        memberId: candidate.member_id,
      })));
      const rulesHash = ballotRulesHash(maxSelections);
      const roster = await this.loadElectors(process.cycle_id, "vote");
      if (roster.filter(({ canSubmit, recused }) => canSubmit && !recused).length === 0) {
        throw conflict("ELECTORATE_EMPTY", "Tiebreak electorate is empty");
      }
      const frozenElectorateHash = electorateHash(roster);
      const configurationHash = workflowSha256({
        candidateSetHash: setHash,
        rulesHash,
        electorateHash: frozenElectorateHash,
        sourceRoundId: sourceRound.id,
        sourceAggregateHash: published.agreed_aggregate_hash,
      });
      const workflowAttempt = await this.nextRoundAttempt(process.id, "tiebreak");
      const roundId = randomUUID();
      await this.client.query(
        `INSERT INTO rounds(
           id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,candidate_set_hash,rules_hash,
           vacancy_id,max_proposal_selections,max_ballot_selections,process_id,workflow_stage,
           workflow_attempt,configuration_hash,electorate_hash,decision_rule
         ) VALUES ($1,$2,$3,'LISTA_CONFIRMADA','vote',$4,$5,$6,$7,
           (SELECT vacancy.id FROM vacancies vacancy
             WHERE (vacancy.process_id=$8 OR vacancy.id=(SELECT reused_vacancy_id FROM office_processes WHERE id=$8))
               AND vacancy.status IN ('pending','vacant') ORDER BY vacancy.ordinal LIMIT 1),
           $9,$5,$8,'tiebreak',$10,$11,$12,$13)`,
        [
          roundId, process.cycle_id, process.office_id, decision.unfilledSeats, maxSelections,
          setHash, rulesHash, process.id, process.max_proposal_selections, workflowAttempt,
          configurationHash, frozenElectorateHash, process.decision_rule,
        ],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("TIEBREAK_ROUND_EXISTS", "Another tiebreak attempt is already pending for this process");
        throw error;
      });
      await this.insertRoundElectors(roundId, roster);
      for (let index = 0; index < candidates.rows.length; index += 1) {
        const candidate = candidates.rows[index];
        if (!candidate) continue;
        const eligibility = currentEligibility.find(({ id }) => id === candidate.member_id);
        if (!eligibility) throw new Error("Current candidate eligibility disappeared during tiebreak preparation");
        await this.client.query(
          `INSERT INTO candidate_snapshots(
             round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
             member_version_snapshot,eligibility_department_id_snapshot,
             eligibility_valid_until_snapshot,eligibility_evaluated_on,eligibility_effective
           ) VALUES ($1,$2,$3,$4,true,$5,$6,$7,$8,$9,$10,true)`,
          [
            roundId, candidate.candidate_id, candidate.member_id, candidate.display_envelope,
            index + 1, candidate.already_assigned_count, eligibility.member_version,
            eligibility.eligibility_department_id, eligibility.eligibility_valid_until,
            eligibility.eligibility_evaluated_on,
          ],
        );
      }
      await this.emit("tiebreak-round.prepared", "round", roundId, {
        roundId, processId: process.id, sourceRoundId: sourceRound.id,
        sourceAggregateHash: published.agreed_aggregate_hash, workflowAttempt,
        candidateSetHash: setHash, rulesHash, phase: "LISTA_CONFIRMADA", version: 1,
      });
      await this.appendAudit("tiebreak-round.prepared", "round", roundId, "success", {
        processId: process.id, sourceRoundId: sourceRound.id, sourceManifestId: published.id,
        sourceAggregateHash: published.agreed_aggregate_hash, workflowAttempt,
        candidateSetHash: setHash, rulesHash, electorateHash: frozenElectorateHash,
        candidateCount: candidates.rows.length, vacancyCount: decision.unfilledSeats,
      });
      return {
        roundId, processId: process.id, workflowStage: "tiebreak", workflowAttempt,
        sourceRoundId: sourceRound.id, sourceAggregateHash: published.agreed_aggregate_hash,
        phase: "LISTA_CONFIRMADA", version: 1, candidateSetHash: setHash, rulesHash,
        electorateHash: frozenElectorateHash, configurationHash,
      };
    });
  }

  public async openBallotRound(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly roundId: string;
    readonly expectedRoundVersion: number; readonly expectedProcessVersion: number;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.ballot-round.open", input.idempotencyKey, input, async () => {
      const round = await this.lockRound(input.roundId);
      if (!round.process_id || round.submission_kind !== "vote" || round.phase !== "LISTA_CONFIRMADA"
          || !["ballot", "tiebreak"].includes(round.workflow_stage ?? "")) {
        throw conflict("PHASE_CONFLICT", "Ballot round is not prepared for opening");
      }
      assertVersion(round.version, input.expectedRoundVersion, "round");
      const process = await this.lockProcess(round.process_id);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      const expectedProcessPhase = round.workflow_stage === "tiebreak" ? "DESEMPATE_PENDIENTE" : "LISTA_CONFIRMADA";
      if (process.phase !== expectedProcessPhase) throw conflict("PHASE_CONFLICT", "Office process does not permit this ballot attempt to open");
      await this.assertRoundCandidatesEligible(round.id, process.office_id);
      const custody = await this.client.query<{ frozen: number; usable: number }>(
        `SELECT
           count(*)::int AS frozen,
           count(*) FILTER (WHERE source.status='active')::int AS usable
           FROM round_custodian_key_snapshots snapshot
           JOIN custodian_device_keys source ON source.id=snapshot.source_key_id
          WHERE snapshot.round_id=$1`,
        [round.id],
      );
      if ((custody.rows[0]?.frozen ?? 0) < 2 || custody.rows[0]?.usable !== custody.rows[0]?.frozen) {
        throw conflict("CUSTODY_NOT_READY", "At least two frozen, active custodian keys are required before opening ballots");
      }
      const roundUpdate = await this.client.query<{ version: number; opened_at: Date }>(
        `UPDATE rounds SET phase='VOTACION_ABIERTA',version=version+1,opened_at=clock_timestamp(),closed_at=NULL
          WHERE id=$1 AND version=$2 RETURNING version,opened_at`,
        [round.id, round.version],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("ANOTHER_ROUND_ACTIVE", "Another round is already active in this cycle");
        throw error;
      });
      const processUpdate = await this.client.query<{ version: number }>(
        "UPDATE office_processes SET phase='VOTACION_ABIERTA',version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$2 RETURNING version",
        [process.id, process.version],
      );
      const roundState = roundUpdate.rows[0];
      const processVersion = processUpdate.rows[0]?.version;
      if (!roundState || !processVersion) throw conflict("VERSION_CONFLICT", "Workflow changed during ballot opening");
      await this.emit("round.phase", "round", round.id, { roundId: round.id, processId: process.id, phase: "VOTACION_ABIERTA", version: roundState.version });
      await this.appendAudit("ballot-round.opened", "round", round.id, "success", { processId: process.id, workflowStage: round.workflow_stage, workflowAttempt: round.workflow_attempt, custodianCount: custody.rows[0]?.frozen ?? 0, roundVersion: roundState.version, processVersion });
      return { roundId: round.id, processId: process.id, workflowStage: round.workflow_stage, workflowAttempt: round.workflow_attempt, phase: "VOTACION_ABIERTA", version: roundState.version, processVersion, openedAt: roundState.opened_at };
    });
  }

  public async closeBallotRound(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly roundId: string;
    readonly expectedRoundVersion: number; readonly expectedProcessVersion: number; readonly reasonCode: string;
  }): Promise<Record<string, unknown>> {
    return this.closeSubmissionRound({ ...input, kind: "vote" });
  }

  public async createProvisionalAssignments(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly processId: string; readonly roundId: string;
    readonly expectedProcessVersion: number; readonly expectedAggregateHash: string; readonly sessionId?: string | null;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.assignments.provisional", input.idempotencyKey, input, async () => {
      let process = await this.lockProcess(input.processId);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      await this.assertDirectElectionAllowed(process.office_id);
      if (!["VOTACION_CERRADA", "ESCRUTINIO"].includes(process.phase)) {
        throw conflict("PHASE_CONFLICT", "Office process is not awaiting a published tally aggregate");
      }
      const round = await this.lockRound(input.roundId);
      if (round.process_id !== process.id || round.submission_kind !== "vote" || round.phase !== "RESULTADO_INTERNO") {
        throw conflict("ROUND_RESULT_UNAVAILABLE", "Round has no published internal result for this process");
      }
      await this.assertRoundCandidatesEligible(round.id, process.office_id);
      const manifestResult = await this.client.query<{
        id: string; agreed_aggregate_hash: string; agreed_aggregate: {
          rule: Record<string, unknown>;
          decision: {
            status: "SELECTED" | "PARTIAL_SELECTION" | "TIEBREAK_REQUIRED" | "NO_SELECTION";
            selectedCandidateIds: string[];
            tiebreakCandidateIds: string[];
            unfilledSeats: number;
          };
        };
      }>(
        `SELECT id,agreed_aggregate_hash,agreed_aggregate
           FROM tally_manifests WHERE round_id=$1 AND state='published' FOR SHARE`,
        [round.id],
      );
      const manifest = manifestResult.rows[0];
      if (!manifest) throw conflict("AGGREGATE_NOT_PUBLISHED", "A two-custodian aggregate must be published first");
      if (manifest.agreed_aggregate_hash !== input.expectedAggregateHash) throw conflict("AGGREGATE_HASH_MISMATCH", "Published aggregate hash differs from the requested evidence");
      if (workflowSha256(manifest.agreed_aggregate.rule) !== workflowSha256(process.decision_rule)) {
        throw conflict("DECISION_RULE_MISMATCH", "Published aggregate was not evaluated with the configured process rule");
      }
      if (process.phase === "VOTACION_CERRADA") {
        const synchronized = await this.client.query<{ version: number }>(
          "UPDATE office_processes SET phase='ESCRUTINIO',version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$2 RETURNING version",
          [process.id, process.version],
        );
        const synchronizedVersion = synchronized.rows[0]?.version;
        if (!synchronizedVersion) throw conflict("VERSION_CONFLICT", "Office process changed during tally synchronization");
        await this.emit("office-process.phase", "office_process", process.id, { processId: process.id, phase: "ESCRUTINIO", version: synchronizedVersion, sourceRoundId: round.id });
        await this.appendAudit("office-process.tally-synchronized", "office_process", process.id, "success", { sourceRoundId: round.id, manifestId: manifest.id, version: synchronizedVersion });
        process = { ...process, phase: "ESCRUTINIO", version: synchronizedVersion };
      }
      const selectedIds = manifest.agreed_aggregate.decision.selectedCandidateIds;
      assertUnique(selectedIds, "PUBLISHED_AGGREGATE_INVALID", "Published decision contains duplicate selected candidates");
      const candidates = selectedIds.length === 0
        ? { rows: [] as Array<{ candidate_id: string; member_id: string; display_envelope: EncryptedEnvelope | null; photo_snapshot: Record<string, unknown> | null }> }
        : await this.client.query<{ candidate_id: string; member_id: string; display_envelope: EncryptedEnvelope | null; photo_snapshot: Record<string, unknown> | null }>(
            `SELECT snapshot.candidate_id,snapshot.member_id,snapshot.display_envelope,candidate.photo_snapshot
               FROM candidate_snapshots snapshot
               JOIN candidacies candidate ON candidate.id=snapshot.candidate_id
              WHERE snapshot.round_id=$1 AND snapshot.candidate_id=ANY($2::uuid[])
              ORDER BY snapshot.candidate_id`,
            [round.id, selectedIds],
          );
      if (candidates.rows.length !== selectedIds.length) throw conflict("PUBLISHED_AGGREGATE_INVALID", "Published decision references a candidate outside the frozen ballot");
      if (candidates.rows.some((candidate) => !candidate.display_envelope)) {
        throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "The published candidate set contains an unavailable encrypted display identity");
      }
      const selectedEligibility = await this.requireMembersEligibleForOffice(
        candidates.rows.map(({ member_id }) => member_id),
        process.office_id,
        "SELECTED_MEMBER_INELIGIBLE",
        "Every selected member must remain eligible for this office on the tenant civil date",
      );
      const vacancies = await this.client.query<{ id: string; ordinal: number }>(
        `SELECT vacancy.id,vacancy.ordinal
           FROM vacancies vacancy
           JOIN office_processes process ON process.id=$1
          WHERE (vacancy.process_id=process.id OR vacancy.id=process.reused_vacancy_id)
            AND vacancy.status IN ('pending','vacant')
          ORDER BY vacancy.ordinal FOR UPDATE OF vacancy`,
        [process.id],
      );
      if (candidates.rows.length > vacancies.rows.length) throw conflict("VACANCY_CAPACITY_EXCEEDED", "Published decision exceeds available vacancies");
      const officeResult = await this.client.query<{
        id: string; department_id: string; canonical_code: string; names: Record<string, string>; appointment_mechanism: string;
        catalog_metadata: Record<string, unknown>; version: number; catalog_version: string;
      }>(
        `SELECT office.id,office.department_id,office.canonical_code,office.names,office.appointment_mechanism,
                office.catalog_metadata,office.version,settings.catalog_version
           FROM offices office CROSS JOIN tenant_settings settings
          WHERE office.id=$1 AND settings.singleton=true`,
        [process.office_id],
      );
      const office = officeResult.rows[0];
      if (!office) throw new Error("Process office is unavailable");
      const assignments: Array<Record<string, unknown>> = [];
      for (let index = 0; index < candidates.rows.length; index += 1) {
        const candidate = candidates.rows[index];
        const vacancy = vacancies.rows[index];
        if (!candidate || !vacancy) throw new Error("Published decision mapping is incomplete");
        if (!candidate.display_envelope) throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "Selected candidate display identity is unavailable");
        const eligibility = selectedEligibility.find(({ id }) => id === candidate.member_id);
        if (!eligibility) throw new Error("Current selected-member eligibility disappeared during assignment creation");
        let independent = true;
        let linkedToAssignmentId: string | null = null;
        if (office.appointment_mechanism === "linked_designation") {
          const linkedBaseCode = office.catalog_metadata["linkedBaseOfficeCode"];
          if (typeof linkedBaseCode !== "string" || linkedBaseCode.length === 0) throw conflict("LINKED_BASE_UNCONFIGURED", "Linked responsibility has no base office");
          const base = await this.client.query<{ id: string }>(
            `SELECT assignment.id FROM assignments assignment
               JOIN offices base_office ON base_office.id=assignment.office_id
              WHERE assignment.cycle_id=$1 AND assignment.member_id=$2 AND assignment.effective
                AND base_office.canonical_code=$3
                AND assignment.state NOT IN ('DECLINADA','RETIRADA','SUSTITUIDA','FINALIZADA')
              ORDER BY assignment.created_at LIMIT 1`,
            [process.cycle_id, candidate.member_id, linkedBaseCode],
          );
          linkedToAssignmentId = base.rows[0]?.id ?? null;
          if (!linkedToAssignmentId) throw conflict("LINKED_BASE_ASSIGNMENT_REQUIRED", "Selected person must hold the configured base responsibility in this term");
          independent = false;
        }
        const assignmentId = randomUUID();
        await this.client.query(
          `INSERT INTO assignments(
             id,vacancy_id,member_id,state,effective,independent,linked_to_assignment_id,
             cycle_id,office_id,process_id,source_round_id,source_manifest_id,source_aggregate_hash,
             source_candidate_id,member_snapshot,office_snapshot
           ) VALUES ($1,$2,$3,'PROPUESTA_INTERNA',true,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            assignmentId, vacancy.id, candidate.member_id, independent, linkedToAssignmentId,
            process.cycle_id, process.office_id, process.id, round.id, manifest.id,
            manifest.agreed_aggregate_hash, candidate.candidate_id,
            {
              memberId: candidate.member_id,
              memberVersion: eligibility.member_version,
              displayEnvelope: candidate.display_envelope,
              eligibility: {
                departmentRestriction: eligibility.eligibility_department_id,
                validUntil: eligibility.eligibility_valid_until,
                evaluatedOn: eligibility.eligibility_evaluated_on,
                effective: true,
              },
              ...(candidate.photo_snapshot ? { photo: candidate.photo_snapshot } : {}),
            },
            {
              officeId: office.id,
              departmentId: office.department_id,
              canonicalCode: office.canonical_code,
              names: office.names,
              officeVersion: office.version,
              catalogVersion: office.catalog_version,
            },
          ],
        ).catch((error: unknown) => {
          if (isUniqueViolation(error)) throw conflict("ASSIGNMENT_CONFLICT", "An effective assignment already occupies this vacancy or office/member term");
          throw error;
        });
        await this.insertAssignmentTransition({
          assignmentId,
          fromState: null,
          toState: "PROPUESTA_INTERNA",
          action: "PROVISIONAL_CREATED",
          reasonCode: "PUBLISHED_AGGREGATE_SELECTED",
          evidenceEnvelope: null,
          identityId: input.identityId,
          assignmentVersion: 1,
          sessionId: input.sessionId ?? null,
        });
        await this.client.query("UPDATE vacancies SET status='recommended' WHERE id=$1", [vacancy.id]);
        const load = await this.client.query<{ independent_count: number; nominal_count: number }>(
          `SELECT
             count(*) FILTER (WHERE independent)::int AS independent_count,
             count(*)::int AS nominal_count
             FROM assignments
            WHERE cycle_id=$1 AND member_id=$2 AND effective
              AND state NOT IN ('DECLINADA','RETIRADA','SUSTITUIDA','FINALIZADA')`,
          [process.cycle_id, candidate.member_id],
        );
        assignments.push({
          assignmentId,
          vacancyId: vacancy.id,
          candidateId: candidate.candidate_id,
          state: "PROPUESTA_INTERNA",
          independent,
          ...(linkedToAssignmentId ? { linkedToAssignmentId } : {}),
          workload: load.rows[0] ?? { independent_count: 0, nominal_count: 0 },
          warning: (load.rows[0]?.nominal_count ?? 0) > 1,
          independentLoadWarning: independent && (load.rows[0]?.independent_count ?? 0) > 1,
        });
      }
      const decision = manifest.agreed_aggregate.decision;
      const nextPhase = decision.status === "TIEBREAK_REQUIRED"
        ? "DESEMPATE_PENDIENTE"
        : decision.status === "NO_SELECTION"
          ? "VACANTE_PENDIENTE"
          : decision.status === "PARTIAL_SELECTION"
            ? decision.tiebreakCandidateIds.length > 0 ? "DESEMPATE_PENDIENTE" : "VACANTE_PENDIENTE"
            : "RESULTADO_INTERNO";
      const consumedRound = await this.client.query<{ version: number }>(
        `UPDATE rounds SET phase='CERRADO',version=version+1,closed_at=COALESCE(closed_at,clock_timestamp())
          WHERE id=$1 AND version=$2 AND phase='RESULTADO_INTERNO' RETURNING version`,
        [round.id, round.version],
      );
      const roundVersion = consumedRound.rows[0]?.version;
      if (!roundVersion) throw conflict("VERSION_CONFLICT", "Published round changed while its decision was being consumed");
      const updated = await this.client.query<{ version: number }>(
        "UPDATE office_processes SET phase=$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$3 RETURNING version",
        [process.id, nextPhase, process.version],
      );
      const processVersion = updated.rows[0]?.version;
      if (!processVersion) throw conflict("VERSION_CONFLICT", "Office process changed during provisional assignment creation");
      await this.emit("assignments.provisional.created", "office_process", process.id, {
        processId: process.id,
        roundId: round.id,
        aggregateHash: manifest.agreed_aggregate_hash,
        assignmentCount: assignments.length,
        phase: nextPhase,
        processVersion,
        roundVersion,
      });
      await this.appendAudit("assignments.provisional.created", "office_process", process.id, "success", {
        roundId: round.id,
        manifestId: manifest.id,
        aggregateHash: manifest.agreed_aggregate_hash,
        assignmentCount: assignments.length,
        decisionStatus: decision.status,
        unfilledSeats: decision.unfilledSeats,
        phase: nextPhase,
        roundVersion,
      });
      return { processId: process.id, roundId: round.id, aggregateHash: manifest.agreed_aggregate_hash, assignments, phase: nextPhase, processVersion, roundVersion };
    });
  }

  public async createLinkedDesignation(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly processId: string;
    readonly expectedProcessVersion: number; readonly baseAssignmentId: string;
    readonly evidenceEnvelope: EncryptedEnvelope; readonly sessionId?: string | null;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.assignment.linked-designation", input.idempotencyKey, input, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.evidenceEnvelope],
      });
      const process = await this.lockProcess(input.processId);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      if (!["CONFIGURADO", "VACANTE_PENDIENTE"].includes(process.phase)) {
        throw conflict("PHASE_CONFLICT", "Linked designation requires a configured or pending-vacancy process");
      }
      await this.requireActiveCycle(process.cycle_id);
      const officeResult = await this.client.query<{
        id: string; department_id: string; canonical_code: string; names: Record<string, string>; appointment_mechanism: string;
        catalog_metadata: Record<string, unknown>; version: number; catalog_version: string;
      }>(
        `SELECT office.id,office.department_id,office.canonical_code,office.names,office.appointment_mechanism,
                office.catalog_metadata,office.version,settings.catalog_version
           FROM offices office CROSS JOIN tenant_settings settings
          WHERE office.id=$1 AND office.active AND settings.singleton=true FOR SHARE OF office`,
        [process.office_id],
      );
      const office = officeResult.rows[0];
      if (!office) throw conflict("OFFICE_UNAVAILABLE", "Linked designation office is unavailable");
      if (office.appointment_mechanism !== "linked_designation") {
        throw conflict("LINKED_DESIGNATION_REQUIRED", "This process does not use the linked-designation mechanism");
      }
      const linkedBaseCode = office.catalog_metadata["linkedBaseOfficeCode"];
      if (typeof linkedBaseCode !== "string" || linkedBaseCode.length === 0) {
        throw conflict("LINKED_BASE_UNCONFIGURED", "Linked responsibility has no configured base office");
      }
      const conflictingRound = await this.client.query(
        "SELECT 1 FROM rounds WHERE process_id=$1 AND phase <> 'ANULADO' LIMIT 1 FOR SHARE",
        [process.id],
      );
      if (conflictingRound.rowCount) {
        throw conflict("LINKED_DESIGNATION_ROUND_CONFLICT", "A linked designation cannot consume or coexist with a workflow round");
      }
      const baseResult = await this.client.query<{
        id: string; member_id: string; state: string; cycle_id: string; effective: boolean;
        display_envelope: EncryptedEnvelope | null; photo_snapshot: Record<string, unknown> | null;
        eligibility_status: string; available: boolean; archived_at: Date | null; canonical_code: string;
      }>(
        `SELECT assignment.id,assignment.member_id,assignment.state,assignment.cycle_id,assignment.effective,
                member.display_envelope,member.eligibility_status,member.available,member.archived_at,
                base_office.canonical_code,
                (SELECT jsonb_build_object(
                   'id',photo.id,'memberId',photo.member_id,'version',photo.version,
                   'mediaType',photo.media_type,'width',photo.width,'height',photo.height,
                   'plaintextBytes',photo.plaintext_bytes,'contentHash',photo.content_hash,
                   'createdAt',photo.created_at,'archivedAt',photo.archived_at,'envelope',photo.envelope
                 ) FROM member_photo_assets photo
                  WHERE photo.member_id=assignment.member_id AND photo.archived_at IS NULL
                  ORDER BY photo.version DESC LIMIT 1) AS photo_snapshot
           FROM assignments assignment
           JOIN offices base_office ON base_office.id=assignment.office_id
           JOIN members member ON member.id=assignment.member_id
          WHERE assignment.id=$1 FOR SHARE OF assignment,base_office,member`,
        [input.baseAssignmentId],
      );
      const base = baseResult.rows[0];
      if (!base || base.cycle_id !== process.cycle_id || base.canonical_code !== linkedBaseCode) {
        throw conflict("LINKED_BASE_ASSIGNMENT_REQUIRED", "The selected base assignment does not belong to the configured group and term");
      }
      if (!base.effective || ![
        "PROPUESTA_INTERNA", "ACEPTACION_PENDIENTE", "ACEPTADA", "PRESENTADA_A_IGLESIA",
        "ELEGIDA_POR_IGLESIA", "VIGENTE",
      ].includes(base.state)) {
        throw conflict("LINKED_BASE_ASSIGNMENT_INACTIVE", "The selected base assignment is neither preliminary nor current");
      }
      const [eligibility] = await this.requireMembersEligibleForOffice(
        [base.member_id],
        process.office_id,
        "LINKED_BASE_MEMBER_INELIGIBLE",
        "The base assignment holder is not eligible for the linked office on the tenant civil date",
      );
      if (!eligibility) throw new Error("Current linked-member eligibility disappeared during assignment creation");
      if (base.archived_at || base.eligibility_status !== "eligible" || !base.available) {
        throw conflict("LINKED_BASE_MEMBER_INELIGIBLE", "The base assignment holder is not currently eligible and available");
      }
      if (!base.display_envelope) {
        throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "The linked base assignment holder has no split encrypted display identity");
      }
      const vacancyResult = await this.client.query<{ id: string; ordinal: number }>(
        `SELECT vacancy.id,vacancy.ordinal
           FROM vacancies vacancy
          WHERE (vacancy.process_id=$1 OR vacancy.id=(SELECT reused_vacancy_id FROM office_processes WHERE id=$1))
            AND vacancy.status IN ('pending','vacant')
          ORDER BY vacancy.ordinal LIMIT 1 FOR UPDATE OF vacancy`,
        [process.id],
      );
      const vacancy = vacancyResult.rows[0];
      if (!vacancy) throw conflict("LINKED_DESIGNATION_CAPACITY_UNAVAILABLE", "The linked responsibility has no available vacancy");
      const assignmentId = randomUUID();
      await this.client.query(
        `INSERT INTO assignments(
           id,vacancy_id,member_id,state,effective,independent,linked_to_assignment_id,
           cycle_id,office_id,process_id,source_round_id,source_manifest_id,source_aggregate_hash,
           source_candidate_id,member_snapshot,office_snapshot
         ) VALUES ($1,$2,$3,'PROPUESTA_INTERNA',true,false,$4,$5,$6,$7,NULL,NULL,NULL,NULL,$8,$9)`,
        [
          assignmentId, vacancy.id, base.member_id, base.id, process.cycle_id, process.office_id, process.id,
          {
            memberId: base.member_id,
            memberVersion: eligibility.member_version,
            displayEnvelope: base.display_envelope,
            eligibility: {
              departmentRestriction: eligibility.eligibility_department_id,
              validUntil: eligibility.eligibility_valid_until,
              evaluatedOn: eligibility.eligibility_evaluated_on,
              effective: true,
            },
            ...(base.photo_snapshot ? { photo: base.photo_snapshot } : {}),
          },
          {
            officeId: office.id,
            departmentId: office.department_id,
            canonicalCode: office.canonical_code,
            names: office.names,
            officeVersion: office.version,
            catalogVersion: office.catalog_version,
          },
        ],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw conflict("ASSIGNMENT_CONFLICT", "An effective linked assignment already occupies this responsibility");
        throw error;
      });
      await this.insertAssignmentTransition({
        assignmentId,
        fromState: null,
        toState: "PROPUESTA_INTERNA",
        action: "LINKED_DESIGNATION_CREATED",
        reasonCode: "LINKED_BASE_DESIGNATION",
        evidenceEnvelope: input.evidenceEnvelope,
        identityId: input.identityId,
        assignmentVersion: 1,
        sessionId: input.sessionId ?? null,
      });
      await this.client.query("UPDATE vacancies SET status='recommended' WHERE id=$1", [vacancy.id]);
      const processUpdate = await this.client.query<{ version: number }>(
        `UPDATE office_processes SET phase='RESULTADO_INTERNO',version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 RETURNING version`,
        [process.id, process.version],
      );
      const processVersion = processUpdate.rows[0]?.version;
      if (!processVersion) throw conflict("VERSION_CONFLICT", "Linked-designation process changed during assignment creation");
      const workload = await this.client.query<{ independent_count: number; nominal_count: number }>(
        `SELECT count(*) FILTER (WHERE independent)::int AS independent_count,count(*)::int AS nominal_count
           FROM assignments
          WHERE cycle_id=$1 AND member_id=$2 AND effective
            AND state NOT IN ('DECLINADA','RETIRADA','SUSTITUIDA','FINALIZADA')`,
        [process.cycle_id, base.member_id],
      );
      await this.emit("assignment.linked-designation.created", "assignment", assignmentId, {
        assignmentId, processId: process.id, baseAssignmentId: base.id,
        state: "PROPUESTA_INTERNA", version: 1, processVersion,
      });
      await this.appendAudit("assignment.linked-designation.created", "assignment", assignmentId, "success", {
        processId: process.id,
        baseAssignmentId: base.id,
        linkedBaseOfficeCode: linkedBaseCode,
        independent: false,
        assignmentVersion: 1,
        processVersion,
        sessionId: input.sessionId ?? null,
      });
      return {
        assignmentId,
        processId: process.id,
        vacancyId: vacancy.id,
        baseAssignmentId: base.id,
        memberId: base.member_id,
        state: "PROPUESTA_INTERNA",
        version: 1,
        processPhase: "RESULTADO_INTERNO",
        processVersion,
        independent: false,
        workload: workload.rows[0] ?? { independent_count: 0, nominal_count: 0 },
      };
    });
  }

  public async recordAssignmentConsent(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly assignmentId: string;
    readonly expectedVersion: number;
    readonly status: "PENDING" | "CONTACTED" | "ACCEPTED" | "DECLINED" | "WITHDRAWN";
    readonly envelope: EncryptedEnvelope; readonly sessionId?: string | null;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.assignment.consent", input.idempotencyKey, input, async () => {
      const assignment = await this.lockAssignment(input.assignmentId);
      assertVersion(assignment.version, input.expectedVersion, "assignment");
      if (!["PROPUESTA_INTERNA", "ACEPTACION_PENDIENTE", "ACEPTADA", "PRESENTADA_A_IGLESIA"].includes(assignment.state)) {
        throw conflict("INVALID_STATE_TRANSITION", "Assignment is not awaiting consent");
      }
      const nextState = input.status === "ACCEPTED"
        ? "ACEPTADA"
        : input.status === "DECLINED"
          ? "DECLINADA"
          : input.status === "WITHDRAWN"
            ? "RETIRADA"
            : "ACEPTACION_PENDIENTE";
      if (["PENDING", "CONTACTED", "ACCEPTED"].includes(input.status)) {
        const eligibilityPause = await this.ensureAssignmentMayAdvance(input.identityId, assignment);
        if (eligibilityPause) return eligibilityPause;
      }
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.envelope],
      });
      assertPersistedAssignmentTransition(assignment.state, nextState);
      const effective = !["DECLINADA", "RETIRADA"].includes(nextState);
      const updated = await this.client.query<{ version: number; updated_at: Date }>(
        `UPDATE assignments SET state=$2,consent_status=$3,consent_envelope=$4,effective=$5,
                version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$6 RETURNING version,updated_at`,
        [assignment.id, nextState, input.status, input.envelope, effective, assignment.version],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Assignment changed while recording consent");
      let replacementProcess: Record<string, unknown> | null = null;
      if (input.status === "ACCEPTED") {
        await this.client.query("UPDATE vacancies SET status='accepted' WHERE id=$1", [assignment.vacancy_id]);
      } else if (!effective) {
        await this.client.query("UPDATE vacancies SET status='vacant' WHERE id=$1", [assignment.vacancy_id]);
        replacementProcess = await this.createReplacementProcess(assignment, input.identityId);
      }
      await this.insertAssignmentTransition({
        assignmentId: assignment.id,
        fromState: assignment.state,
        toState: nextState,
        action: "CONSENT_RECORDED",
        reasonCode: `CONSENT_${input.status}`,
        evidenceEnvelope: input.envelope,
        identityId: input.identityId,
        assignmentVersion: row.version,
        sessionId: input.sessionId ?? null,
      });
      await this.emit("assignment.consent.recorded", "assignment", assignment.id, {
        assignmentId: assignment.id,
        state: nextState,
        version: row.version,
        replacementProcessId: replacementProcess?.["processId"] ?? null,
      });
      await this.appendAudit("assignment.consent.recorded", "assignment", assignment.id, "success", {
        previousState: assignment.state,
        nextState,
        consentStatus: input.status,
        version: row.version,
        replacementProcessId: replacementProcess?.["processId"] ?? null,
      });
      return { id: assignment.id, state: nextState, version: row.version, updatedAt: row.updated_at, replacementProcess };
    });
  }

  public async presentAssignment(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly assignmentId: string;
    readonly expectedVersion: number; readonly envelope: EncryptedEnvelope; readonly sessionId?: string | null;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.assignment.present", input.idempotencyKey, input, async () => {
      const assignment = await this.lockAssignment(input.assignmentId);
      assertVersion(assignment.version, input.expectedVersion, "assignment");
      const eligibilityPause = await this.ensureAssignmentMayAdvance(input.identityId, assignment);
      if (eligibilityPause) return eligibilityPause;
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.envelope],
      });
      assertPersistedAssignmentTransition(assignment.state, "PRESENTADA_A_IGLESIA");
      const updated = await this.client.query<{ version: number; updated_at: Date; presented_at: Date }>(
        `UPDATE assignments SET state='PRESENTADA_A_IGLESIA',presented_at=clock_timestamp(),
                version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 RETURNING version,updated_at,presented_at`,
        [assignment.id, assignment.version],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Assignment changed during presentation");
      await this.insertAssignmentTransition({
        assignmentId: assignment.id, fromState: assignment.state, toState: "PRESENTADA_A_IGLESIA",
        action: "PRESENTED_TO_CHURCH", reasonCode: "PRESENTATION_RECORDED", evidenceEnvelope: input.envelope,
        identityId: input.identityId, assignmentVersion: row.version, sessionId: input.sessionId ?? null,
      });
      await this.emit("assignment.presented", "assignment", assignment.id, { assignmentId: assignment.id, state: "PRESENTADA_A_IGLESIA", version: row.version });
      await this.appendAudit("assignment.presented", "assignment", assignment.id, "success", { previousState: assignment.state, nextState: "PRESENTADA_A_IGLESIA", version: row.version });
      return { id: assignment.id, state: "PRESENTADA_A_IGLESIA", version: row.version, presentedAt: row.presented_at, updatedAt: row.updated_at };
    });
  }

  public async recordCongregationalDecision(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly assignmentId: string;
    readonly expectedVersion: number;
    readonly outcome: "ELECTED" | "RETURNED_TO_COMMITTEE" | "NOT_ELECTED" | "DEFERRED";
    readonly envelope: EncryptedEnvelope; readonly sessionId?: string | null;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.assignment.congregational-decision", input.idempotencyKey, input, async () => {
      const assignment = await this.lockAssignment(input.assignmentId);
      assertVersion(assignment.version, input.expectedVersion, "assignment");
      if (assignment.state !== "PRESENTADA_A_IGLESIA") throw conflict("INVALID_STATE_TRANSITION", "Assignment is not presented to the congregation");
      if (["ELECTED", "DEFERRED"].includes(input.outcome)) {
        const eligibilityPause = await this.ensureAssignmentMayAdvance(input.identityId, assignment);
        if (eligibilityPause) return eligibilityPause;
      }
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.envelope],
      });
      const nextState = input.outcome === "ELECTED"
        ? "ELEGIDA_POR_IGLESIA"
        : input.outcome === "DEFERRED"
          ? "PRESENTADA_A_IGLESIA"
          : "DEVUELTA_A_COMISION";
      if (input.outcome !== "DEFERRED") assertPersistedAssignmentTransition(assignment.state, nextState);
      const effective = nextState !== "DEVUELTA_A_COMISION";
      const updated = await this.client.query<{ version: number; updated_at: Date }>(
        `UPDATE assignments SET state=$2,congregational_outcome=$3,congregational_decision=$4,
                effective=$5,version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$6 RETURNING version,updated_at`,
        [assignment.id, nextState, input.outcome, input.envelope, effective, assignment.version],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Assignment changed during congregational decision");
      let replacementProcess: Record<string, unknown> | null = null;
      if (input.outcome === "ELECTED") {
        await this.client.query("UPDATE vacancies SET status='elected' WHERE id=$1", [assignment.vacancy_id]);
      } else if (!effective) {
        await this.client.query("UPDATE vacancies SET status='vacant' WHERE id=$1", [assignment.vacancy_id]);
        replacementProcess = await this.createReplacementProcess(assignment, input.identityId);
      }
      await this.insertAssignmentTransition({
        assignmentId: assignment.id, fromState: assignment.state, toState: nextState,
        action: "CONGREGATIONAL_DECISION_RECORDED", reasonCode: `CONGREGATIONAL_${input.outcome}`,
        evidenceEnvelope: input.envelope, identityId: input.identityId, assignmentVersion: row.version, sessionId: input.sessionId ?? null,
      });
      await this.emit("assignment.congregational-decision.recorded", "assignment", assignment.id, {
        assignmentId: assignment.id, state: nextState, version: row.version,
        replacementProcessId: replacementProcess?.["processId"] ?? null,
      });
      await this.appendAudit("assignment.congregational-decision.recorded", "assignment", assignment.id, "success", {
        previousState: assignment.state, nextState, outcome: input.outcome, version: row.version,
        replacementProcessId: replacementProcess?.["processId"] ?? null,
      });
      return { id: assignment.id, state: nextState, version: row.version, updatedAt: row.updated_at, replacementProcess };
    });
  }

  public async activateAssignment(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly assignmentId: string; readonly expectedVersion: number;
    readonly sessionId?: string | null;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "workflow.assignment.activate", input.idempotencyKey, input, async () => {
      const assignment = await this.lockAssignment(input.assignmentId);
      assertVersion(assignment.version, input.expectedVersion, "assignment");
      const eligibilityPause = await this.ensureAssignmentMayAdvance(input.identityId, assignment);
      if (eligibilityPause) return eligibilityPause;
      assertPersistedAssignmentTransition(assignment.state, "VIGENTE");
      const term = await this.client.query<{ in_term: boolean; status: string }>(
        `SELECT (clock_timestamp() AT TIME ZONE settings.timezone)::date
                  BETWEEN cycle.term_start AND cycle.term_end AS in_term,cycle.status
           FROM election_cycles cycle CROSS JOIN tenant_settings settings
          WHERE cycle.id=$1 AND settings.singleton=true FOR SHARE OF cycle,settings`,
        [assignment.cycle_id],
      );
      if (!term.rows[0]?.in_term || term.rows[0]?.status !== "active") {
        throw conflict("TERM_NOT_CURRENT", "Assignment can become current only during its active election-cycle term");
      }
      const updated = await this.client.query<{ version: number; started_at: Date; updated_at: Date }>(
        `UPDATE assignments SET state='VIGENTE',started_at=clock_timestamp(),version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 RETURNING version,started_at,updated_at`,
        [assignment.id, assignment.version],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Assignment changed during term activation");
      if (assignment.process_id) {
        await this.client.query(
          `UPDATE office_processes SET phase='CERRADO',version=version+1,updated_at=clock_timestamp()
            WHERE id=$1 AND phase NOT IN ('CERRADO','ANULADO')`,
          [assignment.process_id],
        );
      }
      await this.insertAssignmentTransition({
        assignmentId: assignment.id, fromState: assignment.state, toState: "VIGENTE", action: "TERM_ACTIVATED",
        reasonCode: "TERM_STARTED", evidenceEnvelope: null, identityId: input.identityId, assignmentVersion: row.version,
        sessionId: input.sessionId ?? null,
      });
      await this.emit("assignment.activated", "assignment", assignment.id, { assignmentId: assignment.id, state: "VIGENTE", version: row.version });
      await this.appendAudit("assignment.activated", "assignment", assignment.id, "success", { previousState: assignment.state, nextState: "VIGENTE", version: row.version });
      return { id: assignment.id, state: "VIGENTE", version: row.version, startedAt: row.started_at, updatedAt: row.updated_at };
    });
  }

  public async finalizeAssignment(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly assignmentId: string;
    readonly expectedVersion: number; readonly reasonCode: string; readonly openVacancy: boolean;
    readonly evidenceEnvelope?: EncryptedEnvelope | null; readonly sessionId?: string | null;
  }): Promise<Record<string, unknown>> {
    return this.endAssignment({ ...input, operation: "finalize" });
  }

  public async substituteAssignment(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly assignmentId: string;
    readonly expectedVersion: number; readonly reasonCode: string; readonly evidenceEnvelope?: EncryptedEnvelope | null;
    readonly sessionId?: string | null;
  }): Promise<Record<string, unknown>> {
    return this.endAssignment({ ...input, operation: "substitute", openVacancy: true });
  }

  public async getAssignmentHistory(assignmentId: string): Promise<Record<string, unknown> | null> {
    const assignmentResult = await this.client.query<AssignmentRow & {
      consent_status: string | null; congregational_outcome: string | null; created_at: Date; updated_at: Date;
      presented_at: Date | null; started_at: Date | null; ended_at: Date | null;
      source_round_id: string | null; source_manifest_id: string | null; source_aggregate_hash: string | null;
      source_candidate_id: string | null; independent: boolean; linked_to_assignment_id: string | null;
    }>(
      `SELECT id,vacancy_id,member_id,cycle_id,office_id,process_id,state,version,effective,
              consent_status,congregational_outcome,member_snapshot,office_snapshot,created_at,updated_at,
              presented_at,started_at,ended_at,source_round_id,source_manifest_id,source_aggregate_hash,
              source_candidate_id,independent,linked_to_assignment_id
         FROM assignments WHERE id=$1`,
      [assignmentId],
    );
    const assignment = assignmentResult.rows[0];
    if (!assignment) return null;
    const [transitions, replacements] = await Promise.all([
      this.client.query<{
        id: string; from_state: string | null; to_state: string; action: string; reason_code: string | null;
        evidence_envelope: EncryptedEnvelope | null; actor_identity_id: string; assignment_version: number;
        session_id: string | null; occurred_at: Date;
      }>(
        `SELECT id,from_state,to_state,action,reason_code,evidence_envelope,actor_identity_id,
                assignment_version,session_id,occurred_at
           FROM assignment_transitions WHERE assignment_id=$1 ORDER BY occurred_at,id`,
        [assignmentId],
      ),
      this.client.query<{ id: string; phase: string; procedure_sequence: number; reused_vacancy_id: string | null; created_at: Date }>(
        `SELECT id,phase,procedure_sequence,reused_vacancy_id,created_at
           FROM office_processes WHERE replacement_for_assignment_id=$1 ORDER BY procedure_sequence`,
        [assignmentId],
      ),
    ]);
    await this.appendAudit("assignment.history.read", "assignment", assignment.id, "success", {
      state: assignment.state, transitionCount: transitions.rows.length, replacementCount: replacements.rows.length,
    });
    return {
      assignment: {
        id: assignment.id,
        vacancyId: assignment.vacancy_id,
        memberId: assignment.member_id,
        cycleId: assignment.cycle_id,
        officeId: assignment.office_id,
        processId: assignment.process_id,
        state: assignment.state,
        version: assignment.version,
        effective: assignment.effective,
        consentStatus: assignment.consent_status,
        congregationalOutcome: assignment.congregational_outcome,
        independent: assignment.independent,
        linkedToAssignmentId: assignment.linked_to_assignment_id,
        memberSnapshot: assignment.member_snapshot,
        officeSnapshot: assignment.office_snapshot,
        sourceRoundId: assignment.source_round_id,
        sourceManifestId: assignment.source_manifest_id,
        sourceAggregateHash: assignment.source_aggregate_hash,
        sourceCandidateId: assignment.source_candidate_id,
        createdAt: assignment.created_at,
        updatedAt: assignment.updated_at,
        presentedAt: assignment.presented_at,
        startedAt: assignment.started_at,
        endedAt: assignment.ended_at,
      },
      transitions: transitions.rows.map((transition) => ({
        id: transition.id,
        fromState: transition.from_state,
        toState: transition.to_state,
        action: transition.action,
        reasonCode: transition.reason_code,
        evidenceEnvelope: transition.evidence_envelope,
        actorIdentityId: transition.actor_identity_id,
        assignmentVersion: transition.assignment_version,
        sessionId: transition.session_id,
        occurredAt: transition.occurred_at,
      })),
      replacementProcesses: replacements.rows.map((replacement) => ({
        processId: replacement.id,
        phase: replacement.phase,
        procedureSequence: replacement.procedure_sequence,
        reusedVacancyId: replacement.reused_vacancy_id,
        createdAt: replacement.created_at,
      })),
    };
  }

  public async getCycleWorkflow(cycleId: string): Promise<Record<string, unknown> | null> {
    const cycleResult = await this.client.query<{
      id: string; name: string; status: string; locale: string; timezone: string; jurisdiction: string;
      term_start: string; term_end: string; normative_version: string; version: number; cloned_from_cycle_id: string | null;
      activated_at: Date | null; closed_at: Date | null; archived_at: Date | null;
    }>(
      `SELECT id,name,status,locale,timezone,jurisdiction,term_start::text,term_end::text,
              normative_version,version,cloned_from_cycle_id,activated_at,closed_at,archived_at
         FROM election_cycles WHERE id=$1`,
      [cycleId],
    );
    const cycle = cycleResult.rows[0];
    if (!cycle) return null;
    const [sessions, processes, committee, electorate, rounds, assignments, eligibilityPauses] = await Promise.all([
      this.client.query(
        `SELECT id,sequence,title_envelope,title_envelope_version,
                (title='LEGACY_TITLE_REDACTED' AND title_envelope IS NULL AND title_envelope_version=0) AS legacy_title_unavailable,
                starts_at,ends_at,status,version
           FROM cycle_sessions WHERE cycle_id=$1 ORDER BY sequence`,
        [cycleId],
      ),
      this.client.query(
        `SELECT process.id,process.office_id,office.canonical_code,office.names,
                office.appointment_mechanism,office.catalog_metadata,process.phase,
                process.vacancy_count,process.max_proposal_selections,process.max_ballot_selections,
                process.decision_rule,process.abstention_rule,process.tiebreak_policy,process.quorum_rule,
                process.aggregate_audience,process.agenda_order,process.procedure_sequence,
                process.source_process_id,process.replacement_for_assignment_id,process.reused_vacancy_id,
                process.enabled,process.version
           FROM office_processes process JOIN offices office ON office.id=process.office_id
          WHERE process.cycle_id=$1 ORDER BY process.agenda_order,process.procedure_sequence,process.id`,
        [cycleId],
      ),
      this.client.query("SELECT identity_id,member_id,display_envelope,role_code,voting_right,pastoral_capacity,status FROM committee_memberships WHERE cycle_id=$1 ORDER BY joined_at,id", [cycleId]),
      this.client.query("SELECT identity_id,can_propose,can_vote,recused,version FROM cycle_elector_roster WHERE cycle_id=$1 AND active ORDER BY identity_id", [cycleId]),
      this.client.query(
        `SELECT id,process_id,workflow_stage,workflow_attempt,phase,submission_kind,version,opened_at,closed_at,
                candidate_set_hash,rules_hash,configuration_hash,electorate_hash
           FROM rounds WHERE cycle_id=$1 ORDER BY created_at,id`,
        [cycleId],
      ),
      this.client.query(
        `SELECT id,vacancy_id,member_id,office_id,process_id,state,version,effective,consent_status,
                congregational_outcome,member_snapshot,office_snapshot,presented_at,started_at,ended_at,
                created_at,updated_at
           FROM assignments WHERE cycle_id=$1 ORDER BY created_at,id`,
        [cycleId],
      ),
      this.client.query(
        `SELECT pause.id,pause.process_id AS "processId",pause.round_id AS "roundId",
                pause.member_id AS "memberId",pause.member_version AS "memberVersion",
                pause.previous_process_phase AS "previousProcessPhase",
                pause.previous_round_phase AS "previousRoundPhase",pause.reason_code AS "reasonCode",
                pause.created_at AS "createdAt",pause.resolution_id AS "resolutionId",
                pause.resolution_code AS "resolutionCode",
                pause.resolution_reason_code AS "resolutionReasonCode",
                pause.resolved_by_identity_id AS "resolvedByIdentityId",
                pause.replacement_round_id AS "replacementRoundId",
                pause.replacement_process_id AS "replacementProcessId",
                pause.resolution_process_phase AS "resolutionProcessPhase",
                pause.resolved_at AS "resolvedAt"
           FROM member_eligibility_workflow_pauses pause
          WHERE pause.cycle_id=$1
          ORDER BY pause.created_at,pause.id`,
        [cycleId],
      ),
    ]);
    return {
      cycle: {
        id: cycle.id,
        name: cycle.name,
        status: cycle.status,
        locale: cycle.locale,
        timezone: cycle.timezone,
        jurisdiction: cycle.jurisdiction,
        termStart: cycle.term_start,
        termEnd: cycle.term_end,
        normativeVersion: cycle.normative_version,
        version: cycle.version,
        clonedFromCycleId: cycle.cloned_from_cycle_id,
        activatedAt: cycle.activated_at,
        closedAt: cycle.closed_at,
        archivedAt: cycle.archived_at,
      },
      sessions: sessions.rows,
      processes: processes.rows,
      committee: committee.rows,
      electorate: electorate.rows,
      rounds: rounds.rows,
      assignments: assignments.rows,
      eligibilityPauses: eligibilityPauses.rows,
    };
  }

  public async getWorkflowReportSnapshot(input: {
    readonly reportType: string;
    readonly audience: WorkflowReportAudience;
    readonly cycleId?: string;
    readonly sessionId?: string;
    readonly includeNominalParticipation: boolean;
    readonly viewerPermissions: readonly string[];
  }): Promise<Record<string, unknown>> {
    const cycles = await this.client.query<{
      id: string; name: string; status: string; locale: string; timezone: string; jurisdiction: string;
      termStart: string; termEnd: string; normativeVersion: string; version: number;
      activatedAt: Date | null; closedAt: Date | null; archivedAt: Date | null;
    }>(
      `SELECT id,name,status,locale,timezone,jurisdiction,term_start::text AS "termStart",
              term_end::text AS "termEnd",normative_version AS "normativeVersion",version,
              activated_at AS "activatedAt",closed_at AS "closedAt",archived_at AS "archivedAt"
         FROM election_cycles ORDER BY term_start DESC,created_at DESC,id`,
    );
    const cycle = input.cycleId
      ? cycles.rows.find(({ id }) => id === input.cycleId)
      : cycles.rows.find(({ status }) => status === "active") ?? cycles.rows[0];
    const emptySnapshot: Record<string, unknown> = {
      schemaVersion: 1,
      reportType: input.reportType,
      audience: input.audience,
      generatedAt: new Date(),
      cycleOptions: cycles.rows,
      cycle: cycle ?? null,
      metrics: null,
      organization: [],
      sessions: [],
      sessionMinutes: null,
      departments: [],
      offices: [],
      processes: [],
      rounds: [],
      candidacies: [],
      candidacyReviews: [],
      publishedAggregates: [],
      assignments: [],
      transitions: [],
      eligibleMembers: [],
      committee: [],
      participation: [],
    };
    if (!cycle) return projectWorkflowReportSnapshot(emptySnapshot, input.audience, {
      reportType: input.reportType,
      permissions: input.viewerPermissions,
      includeNominalParticipation: input.includeNominalParticipation,
    });

    const [
      sessions,
      departments,
      offices,
      processes,
      rounds,
      candidacies,
      candidacyReviews,
      publishedAggregates,
      assignments,
      transitions,
      committee,
      participation,
      eligibleMembers,
      metrics,
      organization,
    ] = await Promise.all([
      this.client.query<Record<string, unknown>>(
        `SELECT id,sequence,title_envelope AS "titleEnvelope",title_envelope_version AS "titleVersion",
                (title='LEGACY_TITLE_REDACTED' AND title_envelope IS NULL AND title_envelope_version=0) AS "legacyTitleUnavailable",
                starts_at AS "startsAt",ends_at AS "endsAt",status,version,
                actual_started_at AS "actualStartedAt",actual_closed_at AS "actualClosedAt"
           FROM cycle_sessions
          WHERE cycle_id=$1
          ORDER BY sequence,id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT DISTINCT department.id,department.canonical_code AS "canonicalCode",department.names
           FROM office_processes process
           JOIN offices office ON office.id=process.office_id
           JOIN departments department ON department.id=office.department_id
          WHERE process.cycle_id=$1 ORDER BY department.canonical_code,department.id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT DISTINCT office.id,office.department_id AS "departmentId",office.canonical_code AS "canonicalCode",
                office.names,office.appointment_mechanism AS "appointmentMechanism",office.version
           FROM office_processes process JOIN offices office ON office.id=process.office_id
          WHERE process.cycle_id=$1 ORDER BY office.canonical_code,office.id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT process.id,process.office_id AS "officeId",office.department_id AS "departmentId",
                process.phase,process.vacancy_count AS "vacancyCount",
                process.max_proposal_selections AS "maxProposalSelections",
                process.max_ballot_selections AS "maxBallotSelections",
                process.decision_rule AS "decisionRule",process.abstention_rule AS "abstentionRule",
                process.tiebreak_policy AS "tiebreakPolicy",process.quorum_rule AS "quorumRule",
                process.aggregate_audience AS "aggregateAudience",process.agenda_order AS "agendaOrder",
                process.procedure_sequence AS "procedureSequence",process.source_process_id AS "sourceProcessId",
                process.replacement_for_assignment_id AS "replacementForAssignmentId",
                process.reused_vacancy_id AS "reusedVacancyId",process.enabled,process.version,
                CASE WHEN proposal.id IS NULL THEN NULL ELSE jsonb_build_object(
                  'aggregateHash',proposal.aggregate_hash,
                  'completedResponses',proposal.completed_responses,
                  'electorateDenominator',proposal.electorate_denominator,
                  'effectiveResponseDenominator',proposal.effective_response_denominator
                ) END AS "proposalAggregate"
           FROM office_processes process
           JOIN offices office ON office.id=process.office_id
           LEFT JOIN LATERAL (
             SELECT candidate_aggregate.* FROM proposal_aggregates candidate_aggregate
              WHERE candidate_aggregate.process_id=process.id
              ORDER BY candidate_aggregate.created_at DESC,candidate_aggregate.id DESC LIMIT 1
           ) proposal ON true
          WHERE process.cycle_id=$1 ORDER BY process.agenda_order,process.procedure_sequence,process.id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT round_state.id,round_state.process_id AS "processId",round_state.workflow_stage AS "workflowStage",
                round_state.workflow_attempt AS "workflowAttempt",
                round_state.phase,round_state.submission_kind AS "submissionKind",round_state.version,
                round_state.opened_at AS "openedAt",round_state.closed_at AS "closedAt",
                round_state.candidate_set_hash AS "candidateSetHash",round_state.rules_hash AS "rulesHash"
           FROM rounds round_state WHERE round_state.cycle_id=$1 ORDER BY round_state.created_at,round_state.id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT candidate.id,candidate.process_id AS "processId",candidate.member_id AS "memberId",
                candidate.display_envelope_snapshot AS "displayEnvelope",candidate.photo_snapshot AS "photoSnapshot",
                candidate.state,candidate.distinct_proponent_count AS "distinctProponentCount",
                candidate.electorate_denominator AS "electorateDenominator",
                 candidate.support_denominator AS "supportDenominator",
                 candidate.available_snapshot AS "availableSnapshot",
                 candidate.eligibility_department_id_snapshot AS "departmentRestriction",
                 to_char(candidate.eligibility_valid_until_snapshot,'YYYY-MM-DD') AS "validUntil",
                 to_char(candidate.eligibility_evaluated_on,'YYYY-MM-DD') AS "eligibilityEvaluatedOn",
                 candidate.eligibility_effective_snapshot AS "eligibilityEffective",
                 candidate.already_assigned_count AS "alreadyAssignedCount",candidate.version,candidate.updated_at AS "updatedAt"
           FROM candidacies candidate
           JOIN office_processes process ON process.id=candidate.process_id
          WHERE process.cycle_id=$1 ORDER BY process.agenda_order,candidate.distinct_proponent_count DESC,candidate.id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT review.id,review.candidacy_id AS "candidacyId",review.from_state AS "fromState",
                review.to_state AS "toState",review.decided_at AS "decidedAt"
           FROM candidacy_reviews review
           JOIN candidacies candidate ON candidate.id=review.candidacy_id
           JOIN office_processes process ON process.id=candidate.process_id
          WHERE process.cycle_id=$1 ORDER BY review.decided_at,review.id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT manifest.id AS "manifestId",manifest.round_id AS "roundId",
                manifest.agreed_aggregate_hash AS "aggregateHash",manifest.agreed_aggregate AS aggregate,
                manifest.version,manifest.published_at AS "publishedAt"
           FROM tally_manifests manifest
           JOIN rounds round_state ON round_state.id=manifest.round_id
          WHERE round_state.cycle_id=$1 AND manifest.state='published'
          ORDER BY manifest.published_at,manifest.id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT assignment.id,assignment.vacancy_id AS "vacancyId",assignment.member_id AS "memberId",
                assignment.office_id AS "officeId",assignment.process_id AS "processId",assignment.state,
                assignment.version,assignment.effective,assignment.consent_status AS "consentStatus",
                assignment.congregational_outcome AS "congregationalOutcome",
                assignment.member_snapshot AS "memberSnapshot",assignment.office_snapshot AS "officeSnapshot",
                assignment.source_manifest_id AS "sourceManifestId",
                assignment.source_aggregate_hash AS "sourceAggregateHash",
                assignment.source_candidate_id AS "sourceCandidateId",assignment.presented_at AS "presentedAt",
                assignment.started_at AS "startedAt",assignment.ended_at AS "endedAt",
                assignment.created_at AS "createdAt",assignment.updated_at AS "updatedAt"
           FROM assignments assignment WHERE assignment.cycle_id=$1 ORDER BY assignment.created_at,assignment.id`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT transition.id,transition.assignment_id AS "assignmentId",transition.from_state AS "fromState",
                transition.to_state AS "toState",transition.action,transition.reason_code AS "reasonCode",
                transition.actor_identity_id AS "actorIdentityId",
                transition.assignment_version AS "assignmentVersion",transition.session_id AS "sessionId",
                transition.occurred_at AS "occurredAt"
           FROM assignment_transitions transition
           JOIN assignments assignment ON assignment.id=transition.assignment_id
          WHERE assignment.cycle_id=$1
            AND (NOT $3::boolean OR ($2::uuid IS NOT NULL AND transition.session_id=$2))
          ORDER BY transition.occurred_at,transition.id`,
        [cycle.id, input.reportType === "session_minutes" ? input.sessionId ?? null : null, input.reportType === "session_minutes"],
      ),
      input.includeNominalParticipation
        ? this.client.query<Record<string, unknown>>(
            `SELECT membership.identity_id AS "identityId",membership.member_id AS "memberId",
                    membership.display_envelope AS "displayEnvelope",membership.role_code AS "roleCode",
                    membership.voting_right AS "votingRight",membership.pastoral_capacity AS "pastoralCapacity",
                    membership.status,membership.joined_at AS "joinedAt"
               FROM committee_memberships membership WHERE membership.cycle_id=$1
              ORDER BY membership.joined_at,membership.id`,
            [cycle.id],
          )
        : Promise.resolve({ rows: [] as Record<string, unknown>[] }),
      input.includeNominalParticipation
        ? this.client.query<Record<string, unknown>>(
            `SELECT snapshot.round_id AS "roundId",round_state.submission_kind AS "submissionKind",
                    snapshot.identity_id AS "identityId",snapshot.can_submit AS "canSubmit",snapshot.recused,
                    CASE WHEN snapshot.recused THEN 'recused'
                         WHEN NOT snapshot.can_submit THEN 'not_required'
                         WHEN receipt.id IS NOT NULL THEN 'received' ELSE 'pending' END AS status,
                    receipt.received_at AS "receivedAt"
               FROM round_elector_snapshots snapshot
               JOIN rounds round_state ON round_state.id=snapshot.round_id
               LEFT JOIN participation_receipts receipt
                 ON receipt.round_id=snapshot.round_id
                AND receipt.elector_identity_id=snapshot.identity_id
                AND receipt.kind=round_state.submission_kind
              WHERE round_state.cycle_id=$1 ORDER BY round_state.created_at,snapshot.identity_id`,
            [cycle.id],
          )
        : Promise.resolve({ rows: [] as Record<string, unknown>[] }),
      input.reportType === "unconsidered_unassigned"
        ? this.client.query<Record<string, unknown>>(
             `SELECT snapshot.member_id AS "memberId",snapshot.member_version AS "memberVersion",
                     snapshot.display_envelope AS "displayEnvelope",snapshot.eligibility_status AS "eligibilityStatus",
                     snapshot.available,snapshot.eligibility_department_id_snapshot AS "departmentRestriction",
                     to_char(snapshot.eligibility_valid_until_snapshot,'YYYY-MM-DD') AS "validUntil",
                     to_char(snapshot.eligibility_evaluated_on,'YYYY-MM-DD') AS "eligibilityEvaluatedOn",
                     snapshot.eligibility_effective AS "eligibilityEffective",
                    (SELECT jsonb_build_object(
                       'id',photo.id,'memberId',photo.member_id,'version',photo.version,'mediaType',photo.media_type,
                       'width',photo.width,'height',photo.height,'plaintextBytes',photo.plaintext_bytes,
                       'contentHash',photo.content_hash,'createdAt',photo.created_at,'archivedAt',photo.archived_at,
                       'envelope',photo.envelope
                     ) FROM member_photo_assets photo
                      WHERE photo.member_id=snapshot.member_id AND photo.archived_at IS NULL
                      ORDER BY photo.version DESC LIMIT 1) AS "photoSnapshot",
                    (SELECT count(*)::int FROM candidacies candidate
                      JOIN office_processes process ON process.id=candidate.process_id
                     WHERE process.cycle_id=snapshot.cycle_id AND process.enabled
                       AND candidate.member_id=snapshot.member_id) AS "consideredCount",
                    (SELECT count(*)::int FROM assignments assignment
                     WHERE assignment.cycle_id=snapshot.cycle_id AND assignment.member_id=snapshot.member_id
                       AND assignment.effective) AS "assignedCount"
               FROM cycle_member_snapshots snapshot WHERE snapshot.cycle_id=$1
              ORDER BY snapshot.member_id`,
            [cycle.id],
          )
        : Promise.resolve({ rows: [] as Record<string, unknown>[] }),
      this.client.query<Record<string, unknown>>(
        `SELECT
            (SELECT count(*)::int FROM cycle_member_snapshots snapshot WHERE snapshot.cycle_id=cycle.id) AS "membersTotal",
            cycle.eligible_reference_count AS "eligibleReference",
            (SELECT count(*)::int FROM vacancies vacancy
              WHERE vacancy.cycle_id=cycle.id AND (
                vacancy.process_id IS NULL OR EXISTS (
                  SELECT 1 FROM office_processes applicable
                   WHERE applicable.cycle_id=vacancy.cycle_id AND applicable.enabled
                     AND (applicable.id=vacancy.process_id OR applicable.reused_vacancy_id=vacancy.id)
                )
              )) AS "vacanciesTotal",
            (SELECT count(*)::int FROM vacancies vacancy
              WHERE vacancy.cycle_id=cycle.id AND vacancy.status IN ('recommended','accepted','elected') AND (
                vacancy.process_id IS NULL OR EXISTS (
                  SELECT 1 FROM office_processes applicable
                   WHERE applicable.cycle_id=vacancy.cycle_id AND applicable.enabled
                     AND (applicable.id=vacancy.process_id OR applicable.reused_vacancy_id=vacancy.id)
                )
              )) AS recommended,
            (SELECT count(*)::int FROM vacancies vacancy
              WHERE vacancy.cycle_id=cycle.id AND vacancy.status IN ('accepted','elected') AND (
                vacancy.process_id IS NULL OR EXISTS (
                  SELECT 1 FROM office_processes applicable
                   WHERE applicable.cycle_id=vacancy.cycle_id AND applicable.enabled
                     AND (applicable.id=vacancy.process_id OR applicable.reused_vacancy_id=vacancy.id)
                )
              )) AS accepted,
            (SELECT count(*)::int FROM vacancies vacancy
              WHERE vacancy.cycle_id=cycle.id AND vacancy.status='elected' AND (
                vacancy.process_id IS NULL OR EXISTS (
                  SELECT 1 FROM office_processes applicable
                   WHERE applicable.cycle_id=vacancy.cycle_id AND applicable.enabled
                     AND (applicable.id=vacancy.process_id OR applicable.reused_vacancy_id=vacancy.id)
                )
              )) AS "congregationallyElected"
           FROM election_cycles cycle WHERE cycle.id=$1`,
        [cycle.id],
      ),
      this.client.query<Record<string, unknown>>(
        `SELECT COALESCE(assignment.id,vacancy.id) AS id,vacancy.id AS "vacancyId",vacancy.ordinal,
                office.id AS "officeId",department.id AS "departmentId",
                COALESCE(assignment.office_snapshot->'names'->>cycle.locale,assignment.office_snapshot->'names'->>'es',
                         office.names->>cycle.locale,office.names->>'es',office.canonical_code) AS "officeName",
                COALESCE(department.names->>cycle.locale,department.names->>'es',department.canonical_code) AS "departmentName",
                COALESCE(assignment.office_snapshot->'names',office.names) AS "officeNames",department.names AS "departmentNames",
                CASE
                  WHEN assignment.state IN ('ELEGIDA_POR_IGLESIA','VIGENTE','FINALIZADA') THEN 'elected'
                  WHEN assignment.state IN ('ACEPTADA','PRESENTADA_A_IGLESIA') THEN 'accepted'
                  WHEN assignment.state IS NOT NULL THEN 'recommended'
                  ELSE vacancy.status
                END AS status,
                assignment.state AS "processState",assignment.effective,
                assignment.member_id AS "memberId",assignment.member_snapshot AS "memberSnapshot",
                assignment.linked_to_assignment_id AS "linkedToId"
           FROM vacancies vacancy
           JOIN election_cycles cycle ON cycle.id=vacancy.cycle_id
           JOIN offices office ON office.id=vacancy.office_id
           JOIN departments department ON department.id=office.department_id
           LEFT JOIN LATERAL (
             SELECT candidate.* FROM assignments candidate
              WHERE candidate.vacancy_id=vacancy.id
              ORDER BY candidate.effective DESC,candidate.updated_at DESC,candidate.created_at DESC,candidate.id
              LIMIT 1
           ) assignment ON true
          WHERE vacancy.cycle_id=$1
            AND (
              vacancy.process_id IS NULL OR EXISTS (
                SELECT 1 FROM office_processes applicable
                 WHERE applicable.cycle_id=vacancy.cycle_id AND applicable.enabled
                   AND (applicable.id=vacancy.process_id OR applicable.reused_vacancy_id=vacancy.id)
              )
            )
          ORDER BY department.sort_order,department.canonical_code,office.canonical_code,vacancy.ordinal,vacancy.id`,
        [cycle.id],
      ),
    ]);
    const metricValues = metrics.rows[0] ?? {
      membersTotal: 0,
      eligibleReference: 0,
      vacanciesTotal: 0,
      recommended: 0,
      accepted: 0,
      congregationallyElected: 0,
    };
    const cycleMetrics = buildWorkflowCycleMetrics({
      membersTotal: Number(metricValues["membersTotal"] ?? 0),
      eligibleReference: Number(metricValues["eligibleReference"] ?? 0),
      vacanciesTotal: Number(metricValues["vacanciesTotal"] ?? 0),
      recommended: Number(metricValues["recommended"] ?? 0),
      accepted: Number(metricValues["accepted"] ?? 0),
      congregationallyElected: Number(metricValues["congregationallyElected"] ?? 0),
    });
    const sessionMinutes = input.reportType === "session_minutes" && input.sessionId
      ? await this.getSession(input.sessionId)
      : null;
    if (input.reportType === "session_minutes" && input.sessionId
      && (!sessionMinutes || sessionMinutes["cycleId"] !== cycle.id)) {
      throw conflict("REPORT_SESSION_UNAVAILABLE", "Session minutes require a session from the selected cycle");
    }
    const snapshot = {
      ...emptySnapshot,
      cycle,
      metrics: cycleMetrics,
      organization: organization.rows,
      sessions: sessions.rows,
      sessionMinutes,
      departments: departments.rows,
      offices: offices.rows,
      processes: processes.rows,
      rounds: rounds.rows,
      candidacies: candidacies.rows,
      candidacyReviews: candidacyReviews.rows,
      publishedAggregates: publishedAggregates.rows,
      assignments: assignments.rows,
      transitions: transitions.rows,
      eligibleMembers: eligibleMembers.rows,
      committee: committee.rows,
      participation: participation.rows,
    };
    const projected = projectWorkflowReportSnapshot(snapshot, input.audience, {
      reportType: input.reportType,
      permissions: input.viewerPermissions,
      includeNominalParticipation: input.includeNominalParticipation,
    });
    const classification = classifyWorkflowReportSensitiveProjection(projected, input.audience);
    if (classification) {
      await appendSensitiveReadAuditEvent(this.client, {
        action: SENSITIVE_READ_AUDIT_ACTIONS.workflowReportSnapshot,
        entityType: "election_cycle",
        entityId: cycle.id,
        metadata: {
          reportType: input.reportType,
          audience: input.audience,
          cycleVersion: cycle.version,
          classification,
        },
      });
    }
    return projected;
  }

  public async getReviewBoard(
    processId: string,
    includeRestrictedNotes: boolean,
  ): Promise<Record<string, unknown> | null> {
    const processResult = await this.client.query<{
      id: string; cycle_id: string; phase: string; version: number; aggregate_hash: string | null;
      completed_responses: number | null; electorate_denominator: number | null; effective_response_denominator: number | null;
      office_id: string; canonical_code: string; names: Record<string, string>; appointment_mechanism: string;
    }>(
      `SELECT process.id,process.cycle_id,process.phase,process.version,
              aggregate.aggregate_hash,aggregate.completed_responses,aggregate.electorate_denominator,
              aggregate.effective_response_denominator,office.id AS office_id,office.canonical_code,
              office.names,office.appointment_mechanism
         FROM office_processes process
         JOIN offices office ON office.id=process.office_id
         LEFT JOIN LATERAL (
           SELECT candidate_aggregate.* FROM proposal_aggregates candidate_aggregate
            WHERE candidate_aggregate.process_id=process.id
            ORDER BY candidate_aggregate.created_at DESC,candidate_aggregate.id DESC LIMIT 1
         ) aggregate ON true
        WHERE process.id=$1 AND process.enabled`,
      [processId],
    );
    const process = processResult.rows[0];
    if (!process) return null;
    const candidates = await this.client.query<{
      id: string; member_id: string; display_envelope_snapshot: EncryptedEnvelope | null;
      photo_snapshot: Record<string, unknown> | null; state: CandidacyState;
      distinct_proponent_count: number; electorate_denominator: number; support_denominator: number; available_snapshot: boolean;
      already_assigned_count: number; version: number; updated_at: Date;
    }>(
      `SELECT id,member_id,display_envelope_snapshot,photo_snapshot,state,distinct_proponent_count,
              electorate_denominator,support_denominator,available_snapshot,already_assigned_count,version,updated_at
         FROM candidacies WHERE process_id=$1
          AND source_aggregate_id=(
            SELECT aggregate.id FROM proposal_aggregates aggregate
             WHERE aggregate.process_id=$1 ORDER BY aggregate.created_at DESC,aggregate.id DESC LIMIT 1
          )
        ORDER BY distinct_proponent_count DESC,id`,
      [processId],
    );
    const reviews = candidates.rows.length === 0
      ? { rows: [] as Array<{
          id: string; candidacy_id: string; from_state: string; to_state: string; reason_code: string;
          rationale_envelope: EncryptedEnvelope | null; restricted_note_envelope: EncryptedEnvelope | null;
          actor_identity_id: string; candidacy_version: number; decided_at: Date;
        }> }
      : await this.client.query<{
          id: string; candidacy_id: string; from_state: string; to_state: string; reason_code: string;
          rationale_envelope: EncryptedEnvelope | null; restricted_note_envelope: EncryptedEnvelope | null;
          actor_identity_id: string; candidacy_version: number; decided_at: Date;
        }>(
          `SELECT review.id,review.candidacy_id,review.from_state,review.to_state,review.reason_code,
                  review.rationale_envelope,review.restricted_note_envelope,review.actor_identity_id,
                  review.candidacy_version,review.decided_at
             FROM candidacy_reviews review
             JOIN candidacies candidate ON candidate.id=review.candidacy_id
            WHERE candidate.process_id=$1 ORDER BY review.decided_at,review.id`,
          [processId],
        );
    const photoRecordCount = candidates.rows.filter((candidate) => candidate.photo_snapshot !== null).length;
    const rationaleRecordCount = reviews.rows.filter((review) => review.rationale_envelope !== null).length;
    if (photoRecordCount > 0 || rationaleRecordCount > 0) {
      await appendSensitiveReadAuditEvent(this.client, {
        action: SENSITIVE_READ_AUDIT_ACTIONS.candidacyReviewMaterial,
        entityType: "office_process",
        entityId: process.id,
        metadata: {
          photoRecordCount,
          rationaleRecordCount,
          processVersion: process.version,
        },
      });
    }
    const restrictedNoteRecordCount = includeRestrictedNotes
      ? reviews.rows.filter((review) => review.restricted_note_envelope !== null).length
      : 0;
    if (restrictedNoteRecordCount > 0) {
      await appendSensitiveReadAuditEvent(this.client, {
        action: SENSITIVE_READ_AUDIT_ACTIONS.candidacyPrivateNote,
        entityType: "office_process",
        entityId: process.id,
        metadata: {
          recordCount: restrictedNoteRecordCount,
          processVersion: process.version,
        },
      });
    }
    return {
      process: {
        id: process.id,
        cycleId: process.cycle_id,
        phase: process.phase,
        version: process.version,
        sourceProposalAggregateHash: process.aggregate_hash,
        participation: process.completed_responses === null ? null : {
          completedResponses: process.completed_responses,
          electorateDenominator: process.electorate_denominator,
          effectiveResponseDenominator: process.effective_response_denominator,
        },
      },
      office: {
        id: process.office_id,
        canonicalCode: process.canonical_code,
        names: process.names,
        appointmentMechanism: process.appointment_mechanism,
      },
      candidates: candidates.rows.map((candidate) => ({
        id: candidate.id,
        memberId: candidate.member_id,
        displayEnvelope: candidate.display_envelope_snapshot,
        photoSnapshot: candidate.photo_snapshot,
        state: candidate.state,
        distinctProponentCount: candidate.distinct_proponent_count,
        electorateDenominator: candidate.electorate_denominator,
        supportDenominator: candidate.support_denominator,
        supportPercent: candidate.support_denominator === 0
          ? null
          : Number(((candidate.distinct_proponent_count / candidate.support_denominator) * 100).toFixed(2)),
        available: candidate.available_snapshot,
        alreadyAssignedCount: candidate.already_assigned_count,
        version: candidate.version,
        updatedAt: candidate.updated_at,
        reviews: reviews.rows
          .filter((review) => review.candidacy_id === candidate.id)
          .map((review) => ({
            id: review.id,
            fromState: review.from_state,
            toState: review.to_state,
            reasonCode: review.reason_code,
            rationaleEnvelope: review.rationale_envelope,
            ...(includeRestrictedNotes ? { restrictedNoteEnvelope: review.restricted_note_envelope } : {}),
            actorIdentityId: review.actor_identity_id,
            candidacyVersion: review.candidacy_version,
            decidedAt: review.decided_at,
          })),
      })),
    };
  }

  public async getNominalParticipation(roundId: string): Promise<Record<string, unknown> | null> {
    const round = await this.client.query<{ id: string; process_id: string | null; phase: string; submission_kind: "proposal" | "vote"; version: number }>(
      "SELECT id,process_id,phase,submission_kind,version FROM rounds WHERE id=$1",
      [roundId],
    );
    const roundRow = round.rows[0];
    if (!roundRow) return null;
    const participants = await this.client.query<{
      identity_id: string; can_submit: boolean; recused: boolean; received_at: Date | null;
    }>(
      `SELECT elector.identity_id,elector.can_submit,elector.recused,receipt.received_at
         FROM round_elector_snapshots elector
         LEFT JOIN participation_receipts receipt
           ON receipt.round_id=elector.round_id
          AND receipt.elector_identity_id=elector.identity_id
          AND receipt.kind=$2
        WHERE elector.round_id=$1 ORDER BY elector.identity_id`,
      [roundId, roundRow.submission_kind],
    );
    const items = participants.rows.map((participant) => ({
      identityId: participant.identity_id,
      status: participant.recused
        ? "recused"
        : !participant.can_submit
          ? "not_required"
          : participant.received_at
            ? "received"
            : "pending",
      ...(participant.received_at ? { receivedAt: participant.received_at } : {}),
    }));
    await this.appendAudit("round.participation.read", "round", roundId, "success", {
      kind: roundRow.submission_kind,
      phase: roundRow.phase,
      required: items.filter(({ status }) => status === "received" || status === "pending").length,
      received: items.filter(({ status }) => status === "received").length,
    });
    return {
      round: {
        id: roundRow.id,
        processId: roundRow.process_id,
        phase: roundRow.phase,
        submissionKind: roundRow.submission_kind,
        version: roundRow.version,
      },
      participants: items,
    };
  }

  private async endAssignment(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly assignmentId: string;
    readonly expectedVersion: number; readonly reasonCode: string; readonly openVacancy: boolean;
    readonly evidenceEnvelope?: EncryptedEnvelope | null; readonly sessionId?: string | null;
    readonly operation: "finalize" | "substitute";
  }): Promise<Record<string, unknown>> {
    const expectedReasonCode = input.operation === "substitute"
      ? "ASSIGNMENT_REPLACED"
      : input.openVacancy ? "TERM_COMPLETED_OPEN_VACANCY" : "TERM_COMPLETED_NO_VACANCY";
    const reasonCode = requireAllowedReasonCode(input.reasonCode, [expectedReasonCode]);
    return this.executeIdempotent(input.identityId, `workflow.assignment.${input.operation}`, input.idempotencyKey, { ...input, reasonCode }, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.evidenceEnvelope],
      });
      const assignment = await this.lockAssignment(input.assignmentId);
      assertVersion(assignment.version, input.expectedVersion, "assignment");
      const allowedStates = input.operation === "finalize" ? ["VIGENTE"] : ["ELEGIDA_POR_IGLESIA", "VIGENTE"];
      if (!allowedStates.includes(assignment.state)) {
        throw conflict("INVALID_STATE_TRANSITION", `Assignment cannot be ${input.operation}d from its current state`);
      }
      const nextState = input.operation === "finalize" ? "FINALIZADA" : "SUSTITUIDA";
      assertPersistedAssignmentTransition(assignment.state, nextState);
      const updated = await this.client.query<{ version: number; ended_at: Date; updated_at: Date }>(
        `UPDATE assignments SET state=$2,effective=false,ended_at=clock_timestamp(),
                version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$3 RETURNING version,ended_at,updated_at`,
        [assignment.id, nextState, assignment.version],
      );
      const row = updated.rows[0];
      if (!row) throw conflict("VERSION_CONFLICT", "Assignment changed during lifecycle completion");
      let replacementProcess: Record<string, unknown> | null = null;
      if (input.openVacancy) {
        await this.client.query("UPDATE vacancies SET status='vacant' WHERE id=$1", [assignment.vacancy_id]);
        replacementProcess = await this.createReplacementProcess(assignment, input.identityId);
      }
      await this.insertAssignmentTransition({
        assignmentId: assignment.id,
        fromState: assignment.state,
        toState: nextState,
        action: input.operation === "finalize" ? "ASSIGNMENT_FINALIZED" : "ASSIGNMENT_SUBSTITUTED",
        reasonCode,
        evidenceEnvelope: input.evidenceEnvelope ?? null,
        identityId: input.identityId,
        assignmentVersion: row.version,
        sessionId: input.sessionId ?? null,
      });
      if (input.openVacancy) {
        await this.insertAssignmentTransition({
          assignmentId: assignment.id,
          fromState: nextState,
          toState: nextState,
          action: "VACANCY_OPENED",
          reasonCode,
          evidenceEnvelope: input.evidenceEnvelope ?? null,
          identityId: input.identityId,
          assignmentVersion: row.version,
          sessionId: input.sessionId ?? null,
        });
      }
      await this.emit(`assignment.${input.operation}d`, "assignment", assignment.id, {
        assignmentId: assignment.id,
        state: nextState,
        version: row.version,
        vacancyOpened: input.openVacancy,
        replacementProcessId: replacementProcess?.["processId"] ?? null,
      });
      await this.appendAudit(`assignment.${input.operation}d`, "assignment", assignment.id, "success", {
        previousState: assignment.state,
        nextState,
        reasonCode,
        vacancyOpened: input.openVacancy,
        replacementProcessId: replacementProcess?.["processId"] ?? null,
        version: row.version,
      });
      return {
        id: assignment.id,
        state: nextState,
        version: row.version,
        endedAt: row.ended_at,
        updatedAt: row.updated_at,
        vacancyOpened: input.openVacancy,
        replacementProcess,
      };
    });
  }

  private async lockAssignment(assignmentId: string): Promise<AssignmentRow> {
    const result = await this.client.query<AssignmentRow>(
      `SELECT id,vacancy_id,member_id,cycle_id,office_id,process_id,state,version,effective,
              member_snapshot,office_snapshot
         FROM assignments WHERE id=$1 FOR UPDATE`,
      [assignmentId],
    );
    const assignment = result.rows[0];
    if (!assignment) throw conflict("ASSIGNMENT_UNAVAILABLE", "Assignment is unavailable");
    return assignment;
  }

  private async assertOfficeProcessGroupMayBeDisabled(
    cycleId: string,
    officeId: string,
    processIds: readonly string[],
    processes: readonly ApplicabilityProcessRow[],
  ): Promise<void> {
    const activeRounds = await this.client.query(
      `SELECT 1 FROM rounds
        WHERE process_id=ANY($1::uuid[]) AND phase NOT IN ('CERRADO','ANULADO')
        LIMIT 1`,
      [processIds],
    );
    if (activeRounds.rowCount) {
      throw conflict("OFFICE_PROCESS_HAS_ACTIVE_ROUNDS", "Applicability cannot be removed while the office has an active workflow round");
    }

    const activeAssignments = await this.client.query(
      `SELECT 1 FROM assignments
        WHERE process_id=ANY($1::uuid[])
          AND (effective OR state NOT IN ('FINALIZADA','DECLINADA','DEVUELTA_A_COMISION','RETIRADA','SUSTITUIDA'))
        LIMIT 1`,
      [processIds],
    );
    if (activeAssignments.rowCount) {
      throw conflict("OFFICE_PROCESS_HAS_ACTIVE_DECISIONS", "Applicability cannot be removed while the office has an active appointment decision");
    }

    const unresolvedEligibility = await this.client.query(
      `SELECT 1 FROM member_eligibility_workflow_pauses
        WHERE process_id=ANY($1::uuid[]) AND resolved_at IS NULL
        LIMIT 1`,
      [processIds],
    );
    if (unresolvedEligibility.rowCount) {
      throw conflict("OFFICE_PROCESS_HAS_UNRESOLVED_ELIGIBILITY", "Resolve every eligibility incident before removing applicability");
    }

    const openAgenda = await this.client.query(
      `SELECT 1 FROM session_agenda_items
        WHERE process_id=ANY($1::uuid[]) AND status IN ('pending','in_progress','deferred')
        LIMIT 1`,
      [processIds],
    );
    if (openAgenda.rowCount) {
      throw conflict("OFFICE_PROCESS_HAS_OPEN_AGENDA", "Resolve every open session agenda item before removing applicability");
    }

    const enabledDependent = await this.client.query(
      `SELECT 1
         FROM offices base_office
         JOIN offices dependent_office
           ON dependent_office.appointment_mechanism='linked_designation'
          AND dependent_office.catalog_metadata->>'linkedBaseOfficeCode'=base_office.canonical_code
         JOIN office_processes dependent_process
           ON dependent_process.office_id=dependent_office.id
          AND dependent_process.cycle_id=$1
          AND dependent_process.enabled
        WHERE base_office.id=$2 AND dependent_office.id<>base_office.id
        LIMIT 1`,
      [cycleId, officeId],
    );
    if (enabledDependent.rowCount) {
      throw conflict("OFFICE_PROCESS_REQUIRED_BY_ENABLED_STRUCTURE", "Disable linked responsibilities before removing their base office applicability");
    }

    const safePhases = new Set(["PENDIENTE", "CONFIGURADO", "SIN_CANDIDATOS", "VACANTE_PENDIENTE", "CERRADO", "ANULADO"]);
    if (processes.some(({ phase }) => !safePhases.has(phase))) {
      throw conflict("OFFICE_PROCESS_ACTIVE_WORKFLOW", "Applicability cannot be removed while the office workflow remains active");
    }
  }

  private async assertOfficeProcessGroupMayBeEnabled(cycleId: string, officeId: string): Promise<void> {
    const officeResult = await this.client.query<{
      canonical_code: string;
      appointment_mechanism: string;
      catalog_metadata: Record<string, unknown>;
    }>(
      "SELECT canonical_code,appointment_mechanism,catalog_metadata FROM offices WHERE id=$1 AND active FOR SHARE",
      [officeId],
    );
    const office = officeResult.rows[0];
    if (!office) throw conflict("OFFICE_UNAVAILABLE", "Office is not available in this catalog");
    if (office.appointment_mechanism !== "linked_designation") return;

    const linkedBaseOfficeCode = office.catalog_metadata["linkedBaseOfficeCode"];
    if (typeof linkedBaseOfficeCode !== "string" || linkedBaseOfficeCode.length === 0) {
      throw conflict("LINKED_BASE_UNCONFIGURED", "Linked office is missing its catalog base office");
    }
    const base = await this.client.query(
      `SELECT 1 FROM office_processes process
         JOIN offices office ON office.id=process.office_id
        WHERE process.cycle_id=$1 AND process.enabled AND office.canonical_code=$2
        LIMIT 1
        FOR SHARE OF process,office`,
      [cycleId, linkedBaseOfficeCode],
    );
    if (!base.rowCount) {
      throw conflict("LINKED_BASE_UNCONFIGURED", "Enable the base office process before its linked responsibility");
    }
  }

  private async ensureAssignmentMayAdvance(
    identityId: string,
    assignment: AssignmentRow,
  ): Promise<AssignmentEligibilityPausedResult | null> {
    const current = await this.inspectAssignmentMemberEligibility(assignment);
    if (!assignment.process_id) {
      if (!current.effective || !await this.assignmentEligibilitySnapshotEffective(assignment, current)) {
        throw conflict(
          "ASSIGNMENT_ELIGIBILITY_CHANGED",
          "Assignment member is outside current validity or department scope",
        );
      }
      return null;
    }
    const process = await this.lockProcess(assignment.process_id);
    if (!process.enabled) {
      throw conflict("OFFICE_PROCESS_NOT_APPLICABLE", "The assignment cannot advance while its office process is not applicable");
    }
    if (process.phase === "PAUSADO") {
      return this.existingAssignmentEligibilityPause(assignment, process);
    }
    const snapshotEffective = await this.assignmentEligibilitySnapshotEffective(assignment, current);
    if (current.effective && snapshotEffective) return null;
    return this.pauseAssignmentForEligibility(identityId, assignment, process, current.memberVersion);
  }

  private async inspectAssignmentMemberEligibility(assignment: AssignmentRow) {
    try {
      return await inspectCurrentMemberEligibilityForOffice(this.client, assignment.member_id, assignment.office_id);
    } catch (error) {
      if (error instanceof MemberEligibilityGuardError) throw conflict(error.code, error.message);
      throw error;
    }
  }

  private async assignmentEligibilitySnapshotEffective(
    assignment: AssignmentRow,
    current: CurrentMemberEligibility,
  ): Promise<boolean> {
    const snapshot = assignment.member_snapshot;
    const officeSnapshot = assignment.office_snapshot;
    if (!snapshot || !officeSnapshot
        || snapshot["memberId"] !== assignment.member_id
        || officeSnapshot["departmentId"] !== current.officeDepartmentId
        || !Number.isSafeInteger(snapshot["memberVersion"])
        || Number(snapshot["memberVersion"]) < 1) return false;
    const rawEligibility = snapshot["eligibility"];
    if (!rawEligibility || typeof rawEligibility !== "object" || Array.isArray(rawEligibility)) return false;
    const eligibility = rawEligibility as Record<string, unknown>;
    const departmentRestriction = eligibility["departmentRestriction"];
    const validUntil = eligibility["validUntil"];
    const evaluatedOn = eligibility["evaluatedOn"];
    if (eligibility["effective"] !== true
        || (departmentRestriction !== null && typeof departmentRestriction !== "string")
        || (validUntil !== null && typeof validUntil !== "string")
        || typeof evaluatedOn !== "string"
        || !isCanonicalCivilDate(evaluatedOn)
        || evaluatedOn > current.evaluatedOn) return false;
    const frozen = evaluateMemberEligibilityForOffice({
      eligibilityStatus: "eligible",
      available: true,
      archived: false,
      departmentRestriction: departmentRestriction as string | null,
      validUntil: validUntil as string | null,
      evaluatedOn: current.evaluatedOn,
      officeDepartmentId: current.officeDepartmentId,
      ...(typeof departmentRestriction === "string" ? { restrictionDepartmentActive: true } : {}),
    });
    if (!frozen.eligible) return false;
    if (typeof departmentRestriction !== "string") return true;
    const department = await this.client.query<{ active: boolean }>(
      "SELECT active FROM departments WHERE id=$1 FOR SHARE",
      [departmentRestriction],
    );
    return department.rows[0]?.active === true;
  }

  private async existingAssignmentEligibilityPause(
    assignment: AssignmentRow,
    process: ProcessRow,
  ): Promise<AssignmentEligibilityPausedResult> {
    const pauses = await this.client.query<{ id: string; round_id: string | null }>(
      `SELECT id,round_id FROM member_eligibility_workflow_pauses
        WHERE process_id=$1 AND resolved_at IS NULL ORDER BY id FOR SHARE`,
      [process.id],
    );
    const first = pauses.rows[0];
    if (!first) {
      throw conflict("ELIGIBILITY_PAUSE_INVALID", "Paused assignment process has no unresolved eligibility incident");
    }
    const roundVersion = first.round_id
      ? await this.client.query<{ version: number }>("SELECT version FROM rounds WHERE id=$1 FOR SHARE", [first.round_id])
      : null;
    return assignmentEligibilityPausedResult({
      assignment,
      process,
      roundId: first.round_id,
      roundVersion: roundVersion?.rows[0]?.version ?? null,
      pauseIds: pauses.rows.map(({ id }) => id),
    });
  }

  private async pauseAssignmentForEligibility(
    identityId: string,
    assignment: AssignmentRow,
    process: ProcessRow,
    memberVersion: number,
  ): Promise<AssignmentEligibilityPausedResult> {
    const existing = await this.client.query<{ id: string; round_id: string | null }>(
      `SELECT id,round_id FROM member_eligibility_workflow_pauses
        WHERE process_id=$1 AND resolved_at IS NULL ORDER BY id FOR UPDATE`,
      [process.id],
    );
    if (existing.rows[0]) return this.existingAssignmentEligibilityPause(assignment, process);
    const roundResult = await this.client.query<{ id: string; phase: string; version: number }>(
      `SELECT id,phase,version FROM rounds
        WHERE process_id=$1 AND phase NOT IN ('CERRADO','ANULADO')
        ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE`,
      [process.id],
    );
    const round = roundResult.rows[0] ?? null;
    const pauseId = randomUUID();
    await this.client.query(
      `INSERT INTO member_eligibility_workflow_pauses(
         id,cycle_id,process_id,round_id,member_id,member_version,
         previous_process_phase,previous_round_phase,reason_code,actor_identity_id
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'MEMBER_ELIGIBILITY_CHANGED',$9)`,
      [
        pauseId, process.cycle_id, process.id, round?.id ?? null, assignment.member_id,
        memberVersion, process.phase, round?.phase ?? null, identityId,
      ],
    );
    const processUpdate = await this.client.query<{ version: number }>(
      `UPDATE office_processes SET phase='PAUSADO',version=version+1,updated_at=clock_timestamp()
        WHERE id=$1 AND version=$2 RETURNING version`,
      [process.id, process.version],
    );
    const processVersion = processUpdate.rows[0]?.version;
    if (!processVersion) throw conflict("VERSION_CONFLICT", "Assignment workflow changed while applying eligibility pause");
    const roundUpdate = round
      ? await this.client.query<{ version: number }>(
          "UPDATE rounds SET phase='PAUSADO',version=version+1 WHERE id=$1 AND version=$2 RETURNING version",
          [round.id, round.version],
        )
      : null;
    const roundVersion = roundUpdate?.rows[0]?.version ?? null;
    if (round && !roundVersion) throw conflict("VERSION_CONFLICT", "Assignment round changed while applying eligibility pause");
    await this.emit("workflow.paused", "office_process", process.id, {
      pauseId, processId: process.id, roundId: round?.id ?? null,
      memberId: assignment.member_id, memberVersion,
      processVersion, roundVersion, reasonCode: "MEMBER_ELIGIBILITY_CHANGED",
    });
    await this.appendAudit("workflow.paused", "office_process", process.id, "success", {
      pauseId, assignmentId: assignment.id, roundId: round?.id ?? null,
      memberId: assignment.member_id, memberVersion,
      previousProcessPhase: process.phase, previousRoundPhase: round?.phase ?? null,
      processVersion, roundVersion, reasonCode: "MEMBER_ELIGIBILITY_CHANGED",
    });
    return assignmentEligibilityPausedResult({
      assignment,
      process: { ...process, phase: "PAUSADO", version: processVersion },
      roundId: round?.id ?? null,
      roundVersion,
      pauseIds: [pauseId],
    });
  }

  private async createReplacementProcess(assignment: AssignmentRow, identityId: string): Promise<Record<string, unknown>> {
    if (!assignment.process_id) throw conflict("WORKFLOW_ASSIGNMENT_REQUIRED", "Only a workflow-created assignment can open a replacement procedure");
    const existing = await this.client.query<{ id: string; procedure_sequence: number; phase: string }>(
      "SELECT id,procedure_sequence,phase FROM office_processes WHERE replacement_for_assignment_id=$1 FOR SHARE",
      [assignment.id],
    );
    if (existing.rows[0]) {
      return { processId: existing.rows[0].id, procedureSequence: existing.rows[0].procedure_sequence, phase: existing.rows[0].phase, reusedVacancyId: assignment.vacancy_id };
    }
    const sourceResult = await this.client.query<{
      id: string; cycle_id: string; office_id: string; max_proposal_selections: number;
      decision_rule: Record<string, unknown>; abstention_rule: string; tiebreak_policy: string;
      quorum_rule: Record<string, unknown>; aggregate_audience: string; cycle_status: string;
    }>(
      `SELECT process.id,process.cycle_id,process.office_id,process.max_proposal_selections,
              process.decision_rule,process.abstention_rule,process.tiebreak_policy,
              process.quorum_rule,process.aggregate_audience,cycle.status AS cycle_status
         FROM office_processes process
         JOIN election_cycles cycle ON cycle.id=process.cycle_id
        WHERE process.id=$1 AND process.enabled FOR SHARE OF process,cycle`,
      [assignment.process_id],
    );
    const source = sourceResult.rows[0];
    if (!source || source.cycle_status !== "active") {
      throw conflict("REPLACEMENT_CYCLE_NOT_ACTIVE", "A replacement procedure requires the active source cycle");
    }
    const ordering = await this.client.query<{ procedure_sequence: number; agenda_order: number }>(
      `SELECT
         COALESCE(max(procedure_sequence),0)::int + 1 AS procedure_sequence,
         (SELECT COALESCE(max(agenda_order),0)::int + 1 FROM office_processes WHERE cycle_id=$1) AS agenda_order
       FROM office_processes WHERE cycle_id=$1 AND office_id=$2`,
      [source.cycle_id, source.office_id],
    );
    const next = ordering.rows[0];
    if (!next) throw new Error("Replacement process ordering is unavailable");
    const processId = randomUUID();
    await this.client.query(
      `INSERT INTO office_processes(
         id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
         decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,agenda_order,
         procedure_sequence,source_process_id,replacement_for_assignment_id,reused_vacancy_id,
         created_by_identity_id
       ) VALUES ($1,$2,$3,'VACANTE_PENDIENTE',1,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [
        processId, source.cycle_id, source.office_id, source.max_proposal_selections,
        source.decision_rule, source.abstention_rule, source.tiebreak_policy, source.quorum_rule,
        source.aggregate_audience, next.agenda_order, next.procedure_sequence, source.id,
        assignment.id, assignment.vacancy_id, identityId,
      ],
    ).catch((error: unknown) => {
      if (isUniqueViolation(error)) throw conflict("REPLACEMENT_PROCESS_CONFLICT", "A replacement procedure already exists or its ordering changed");
      throw error;
    });
    return {
      processId,
      phase: "VACANTE_PENDIENTE",
      procedureSequence: next.procedure_sequence,
      reusedVacancyId: assignment.vacancy_id,
      sourceProcessId: source.id,
      replacementForAssignmentId: assignment.id,
    };
  }

  private async insertAssignmentTransition(input: {
    readonly assignmentId: string; readonly fromState: string | null; readonly toState: string;
    readonly action: "PROVISIONAL_CREATED" | "LINKED_DESIGNATION_CREATED" | "CONSENT_RECORDED" | "PRESENTED_TO_CHURCH" |
      "CONGREGATIONAL_DECISION_RECORDED" | "TERM_ACTIVATED" | "ASSIGNMENT_FINALIZED" |
      "ASSIGNMENT_SUBSTITUTED" | "VACANCY_OPENED";
    readonly reasonCode: string | null; readonly evidenceEnvelope: EncryptedEnvelope | null;
    readonly identityId: string; readonly assignmentVersion: number; readonly sessionId?: string | null;
  }): Promise<void> {
    if (input.sessionId) {
      const session = await this.client.query(
        `SELECT 1 FROM cycle_sessions session
          JOIN assignments assignment ON assignment.cycle_id=session.cycle_id
         WHERE session.id=$1 AND assignment.id=$2 AND session.status <> 'cancelled' FOR SHARE OF session`,
        [input.sessionId, input.assignmentId],
      );
      if (session.rowCount !== 1) {
        throw conflict("ASSIGNMENT_SESSION_INVALID", "The institutional session must belong to the assignment cycle and cannot be cancelled");
      }
    }
    await this.client.query(
      `INSERT INTO assignment_transitions(
         id,assignment_id,from_state,to_state,action,reason_code,evidence_envelope,
         actor_identity_id,assignment_version,session_id
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [randomUUID(), input.assignmentId, input.fromState, input.toState, input.action, input.reasonCode,
        input.evidenceEnvelope, input.identityId, input.assignmentVersion, input.sessionId ?? null],
    );
  }

  private async closeSubmissionRound(input: {
    readonly identityId: string; readonly idempotencyKey: string; readonly roundId: string;
    readonly expectedRoundVersion: number; readonly expectedProcessVersion: number;
    readonly kind: "proposal" | "vote"; readonly reasonCode: string;
  }): Promise<Record<string, unknown>> {
    const reasonCode = requireAllowedReasonCode(input.reasonCode, ROUND_CLOSE_REASON_CODES);
    return this.executeIdempotent(input.identityId, `workflow.${input.kind}-round.close`, input.idempotencyKey, { ...input, reasonCode }, async () => {
      const round = await this.lockRound(input.roundId);
      const expectedPhase = input.kind === "proposal" ? "PROPUESTAS_ABIERTAS" : "VOTACION_ABIERTA";
      const nextPhase = input.kind === "proposal" ? "PROPUESTAS_CERRADAS" : "VOTACION_CERRADA";
      if (!round.process_id || round.submission_kind !== input.kind || round.phase !== expectedPhase) {
        throw conflict("PHASE_CONFLICT", `${input.kind} round is not open`);
      }
      assertVersion(round.version, input.expectedRoundVersion, "round");
      const process = await this.lockProcess(round.process_id);
      assertVersion(process.version, input.expectedProcessVersion, "office process");
      if (process.phase !== expectedPhase) throw conflict("PHASE_CONFLICT", "Office process and round phases differ");
      const counts = await this.participationCounts(round.id, input.kind);
      if (counts.required !== counts.received) throw conflict("PARTICIPATION_INCOMPLETE", "Frozen electorate has pending responses");
      const roundUpdate = await this.client.query<{ version: number; closed_at: Date }>(
        "UPDATE rounds SET phase=$2,version=version+1,closed_at=clock_timestamp() WHERE id=$1 AND version=$3 RETURNING version,closed_at",
        [round.id, nextPhase, round.version],
      );
      const processUpdate = await this.client.query<{ version: number }>(
        "UPDATE office_processes SET phase=$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$3 RETURNING version",
        [process.id, nextPhase, process.version],
      );
      const roundState = roundUpdate.rows[0];
      const processVersion = processUpdate.rows[0]?.version;
      if (!roundState || !processVersion) throw conflict("VERSION_CONFLICT", "Workflow changed during close");
      await this.emit("round.closed", "round", round.id, { roundId: round.id, processId: process.id, phase: nextPhase, version: roundState.version, received: counts.received, required: counts.required });
      await this.appendAudit(`${input.kind}-round.closed`, "round", round.id, "success", { processId: process.id, reasonCode, received: counts.received, required: counts.required, roundVersion: roundState.version, processVersion });
      return { roundId: round.id, processId: process.id, phase: nextPhase, version: roundState.version, processVersion, closedAt: roundState.closed_at, participation: counts };
    });
  }

  private async lockCycle(cycleId: string): Promise<CycleRow> {
    const result = await this.client.query<CycleRow>("SELECT id,status,version FROM election_cycles WHERE id=$1 FOR UPDATE", [cycleId]);
    const row = result.rows[0];
    if (!row) throw conflict("CYCLE_UNAVAILABLE", "Cycle is unavailable");
    return row;
  }

  private async lockSession(sessionId: string): Promise<SessionRow> {
    const result = await this.client.query<SessionRow>(
      `SELECT id,cycle_id,sequence,title,title_envelope,title_envelope_version,starts_at,ends_at,status,location_envelope,version,
              actual_started_at,actual_closed_at,created_at,updated_at
         FROM cycle_sessions WHERE id=$1 FOR UPDATE`,
      [sessionId],
    );
    const row = result.rows[0];
    if (!row) throw conflict("SESSION_UNAVAILABLE", "Session is unavailable");
    return row;
  }

  private async lockDraftCycle(cycleId: string, expectedVersion: number): Promise<CycleRow> {
    const cycle = await this.lockCycle(cycleId);
    assertVersion(cycle.version, expectedVersion, "cycle");
    if (cycle.status !== "draft") throw conflict("CYCLE_NOT_CONFIGURABLE", "Only a draft cycle can be configured");
    return cycle;
  }

  private async requireActiveCycle(cycleId: string): Promise<void> {
    const result = await this.client.query("SELECT 1 FROM election_cycles WHERE id=$1 AND status='active'", [cycleId]);
    if (result.rowCount !== 1) throw conflict("CYCLE_NOT_ACTIVE", "Workflow rounds require an active cycle");
  }

  private async assertDirectElectionAllowed(officeId: string): Promise<void> {
    const result = await this.client.query<{ appointment_mechanism: string }>(
      "SELECT appointment_mechanism FROM offices WHERE id=$1 AND active FOR SHARE",
      [officeId],
    );
    const mechanism = result.rows[0]?.appointment_mechanism;
    if (!mechanism) throw conflict("OFFICE_UNAVAILABLE", "Office is not available in this catalog");
    assertOrdinaryProposalBallotMechanism(mechanism);
  }

  /**
   * Evaluates operational eligibility against one office on the tenant's civil
   * date.  The structured scope is deliberately kept outside encrypted private
   * notes so the server can enforce it without learning any rationale.
   */
  private async loadMemberEligibilityForOffice(
    memberIds: readonly string[],
    officeId: string,
  ): Promise<readonly MemberOfficeEligibilityRow[]> {
    const uniqueMemberIds = [...new Set(memberIds)];
    if (uniqueMemberIds.length === 0) return [];
    const result = await this.client.query<MemberOfficeEligibilityRow>(
      `SELECT member.id,
              member.version AS member_version,
              member.display_envelope,
              member.eligibility_department_id,
              to_char(member.eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until,
              to_char((clock_timestamp() AT TIME ZONE settings.timezone)::date,'YYYY-MM-DD') AS eligibility_evaluated_on,
              office.department_id AS office_department_id,
              (office.active
               AND member.archived_at IS NULL
               AND member.eligibility_status='eligible'
               AND member.available
               AND (member.eligibility_valid_until IS NULL
                    OR member.eligibility_valid_until >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
               AND (member.eligibility_department_id IS NULL
                    OR (member.eligibility_department_id=office.department_id
                        AND COALESCE(restriction.active,false)))) AS eligibility_effective
         FROM members member
         JOIN offices office ON office.id=$2
         CROSS JOIN tenant_settings settings
         LEFT JOIN departments restriction ON restriction.id=member.eligibility_department_id
        WHERE settings.singleton=true
          AND member.id=ANY($1::uuid[])
        ORDER BY member.id
        FOR SHARE OF member,office`,
      [uniqueMemberIds, officeId],
    );
    return result.rows;
  }

  private async requireMembersEligibleForOffice(
    memberIds: readonly string[],
    officeId: string,
    code: string,
    message: string,
  ): Promise<readonly MemberOfficeEligibilityRow[]> {
    const uniqueMemberIds = [...new Set(memberIds)];
    const rows = await this.loadMemberEligibilityForOffice(uniqueMemberIds, officeId);
    if (rows.length !== uniqueMemberIds.length || rows.some((row) => !row.eligibility_effective)) {
      throw conflict(code, message);
    }
    return rows;
  }

  private async assertRoundCandidatesEligible(roundId: string, officeId?: string): Promise<void> {
    try {
      const result = await requireRoundCandidatesOperationallyEligible(this.client, roundId);
      if (officeId !== undefined && result.officeId !== officeId) {
        throw conflict("ROUND_OFFICE_MISMATCH", "Round and office eligibility context differ");
      }
    } catch (error) {
      if (error instanceof MemberEligibilityGuardError) throw conflict(error.code, error.message);
      throw error;
    }
  }

  private async lockProcess(processId: string): Promise<ProcessRow> {
    const result = await this.client.query<ProcessRow>(
      `SELECT id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
              decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,enabled,version
         FROM office_processes WHERE id=$1 AND enabled FOR UPDATE`,
      [processId],
    );
    const row = result.rows[0];
    if (!row) throw conflict("OFFICE_PROCESS_UNAVAILABLE", "Office process is unavailable");
    return row;
  }

  private async lockRound(roundId: string): Promise<RoundRow> {
    const result = await this.client.query<RoundRow>(
      `SELECT round_state.id,round_state.cycle_id,round_state.process_id,round_state.workflow_stage,
              round_state.workflow_attempt,round_state.phase,round_state.submission_kind,round_state.version,
              round_state.max_proposal_selections,round_state.max_ballot_selections,
              round_state.candidate_set_hash,round_state.rules_hash,round_state.configuration_hash,
              round_state.electorate_hash,office.appointment_mechanism
         FROM rounds round_state
         JOIN offices office ON office.id=round_state.office_id
        WHERE round_state.id=$1 FOR UPDATE OF round_state`,
      [roundId],
    );
    const row = result.rows[0];
    if (!row) throw conflict("ROUND_UNAVAILABLE", "Round is unavailable");
    assertOrdinaryProposalBallotMechanism(row.appointment_mechanism);
    return row;
  }

  private async nextRoundAttempt(processId: string, stage: "proposal" | "ballot" | "tiebreak"): Promise<number> {
    const result = await this.client.query<{ attempt: number }>(
      `SELECT COALESCE(max(workflow_attempt),0)::int + 1 AS attempt
         FROM rounds WHERE process_id=$1 AND workflow_stage=$2`,
      [processId, stage],
    );
    const attempt = result.rows[0]?.attempt;
    if (!attempt || attempt < 1) throw new Error("Workflow round attempt could not be allocated");
    return attempt;
  }

  private async prepareProposalRoundRecord(
    process: ProcessRow,
    identityId: string,
  ): Promise<Record<string, unknown>> {
    await this.assertDirectElectionAllowed(process.office_id);
    const members = await this.client.query<{
      member_id: string; member_version: number; display_envelope: EncryptedEnvelope | null;
      already_assigned_count: number; eligibility_department_id: string | null;
      eligibility_valid_until: string | null; eligibility_evaluated_on: string;
    }>(
      `SELECT snapshot.member_id,current_member.version AS member_version,snapshot.display_envelope,
              current_member.eligibility_department_id,
              to_char(current_member.eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until,
              to_char((clock_timestamp() AT TIME ZONE settings.timezone)::date,'YYYY-MM-DD') AS eligibility_evaluated_on,
              (SELECT count(*)::int FROM assignments assignment
                WHERE assignment.member_id=snapshot.member_id AND assignment.effective) AS already_assigned_count
         FROM cycle_member_snapshots snapshot
         JOIN members current_member ON current_member.id=snapshot.member_id
         JOIN offices office ON office.id=$2 AND office.active
         CROSS JOIN tenant_settings settings
         LEFT JOIN departments frozen_restriction ON frozen_restriction.id=snapshot.eligibility_department_id_snapshot
         LEFT JOIN departments current_restriction ON current_restriction.id=current_member.eligibility_department_id
        WHERE snapshot.cycle_id=$1
          AND settings.singleton=true
          AND snapshot.eligibility_effective
          AND (snapshot.eligibility_valid_until_snapshot IS NULL
               OR snapshot.eligibility_valid_until_snapshot >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
          AND (snapshot.eligibility_department_id_snapshot IS NULL
               OR (snapshot.eligibility_department_id_snapshot=office.department_id
                   AND COALESCE(frozen_restriction.active,false)))
          AND current_member.archived_at IS NULL
          AND current_member.eligibility_status='eligible'
          AND current_member.available
          AND (current_member.eligibility_valid_until IS NULL
               OR current_member.eligibility_valid_until >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
          AND (current_member.eligibility_department_id IS NULL
               OR (current_member.eligibility_department_id=office.department_id
                   AND COALESCE(current_restriction.active,false)))
        ORDER BY snapshot.member_id`,
      [process.cycle_id, process.office_id],
    );
    if (members.rowCount === 0) {
      throw conflict("CANDIDATE_POOL_EMPTY", "The cycle reference universe has no currently eligible candidate for a new frozen round");
    }
    if (members.rows.some((member) => !member.display_envelope)) {
      throw conflict("MEMBER_DISPLAY_UNAVAILABLE", "The frozen candidate universe contains an unavailable encrypted display identity");
    }
    const roster = await this.loadElectors(process.cycle_id, "proposal");
    if (roster.filter(({ canSubmit, recused }) => canSubmit && !recused).length === 0) {
      throw conflict("ELECTORATE_EMPTY", "Proposal electorate is empty");
    }
    const roundId = randomUUID();
    const candidateHash = workflowSha256({ schemaVersion: 1, eligibleMemberIds: members.rows.map(({ member_id }) => member_id) });
    const rulesHash = this.proposalRulesHash(process);
    const frozenElectorateHash = electorateHash(roster);
    const configurationHash = workflowSha256({ candidateSetHash: candidateHash, rulesHash, electorateHash: frozenElectorateHash });
    const workflowAttempt = await this.nextRoundAttempt(process.id, "proposal");
    await this.client.query(
      `INSERT INTO rounds(
         id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,candidate_set_hash,rules_hash,
         vacancy_id,max_proposal_selections,max_ballot_selections,process_id,workflow_stage,
         workflow_attempt,configuration_hash,electorate_hash,decision_rule
       ) VALUES ($1,$2,$3,'CONFIGURADO','proposal',$4,$5,$6,$7,
         COALESCE(
           (SELECT reused_vacancy_id FROM office_processes WHERE id=$8),
           (SELECT id FROM vacancies WHERE process_id=$8 ORDER BY ordinal LIMIT 1)
         ),$5,$9,$8,'proposal',$10,$11,$12,$13)`,
      [
        roundId, process.cycle_id, process.office_id, process.vacancy_count,
        process.max_proposal_selections, candidateHash, rulesHash, process.id,
        process.max_ballot_selections, workflowAttempt, configurationHash, frozenElectorateHash, process.decision_rule,
      ],
    ).catch((error: unknown) => {
      if (isUniqueViolation(error)) throw conflict("PROPOSAL_ROUND_EXISTS", "Another proposal attempt is already pending for this process");
      throw error;
    });
    await this.insertRoundElectors(roundId, roster);
    for (let index = 0; index < members.rows.length; index += 1) {
      const member = members.rows[index];
      if (!member) continue;
        await this.client.query(
          `INSERT INTO candidate_snapshots(
            round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
            member_version_snapshot,eligibility_department_id_snapshot,
            eligibility_valid_until_snapshot,eligibility_evaluated_on,eligibility_effective
          ) VALUES ($1,$2,$2,$3,true,$4,$5,$6,$7,$8,$9,true)`,
        [
          roundId, member.member_id, member.display_envelope, index + 1, member.already_assigned_count,
          member.member_version, member.eligibility_department_id, member.eligibility_valid_until,
          member.eligibility_evaluated_on,
        ],
      );
    }
    await this.emit("proposal-round.prepared", "round", roundId, { roundId, processId: process.id, phase: "CONFIGURADO", version: 1 });
    await this.appendAudit("proposal-round.prepared", "round", roundId, "success", {
      processId: process.id,
      preparedByIdentityId: identityId,
      candidateUniverse: "cycle-reference-current-eligibility",
      electorateCount: roster.filter(({ canSubmit, recused }) => canSubmit && !recused).length,
      candidateSetHash: candidateHash,
      rulesHash,
      configurationHash,
    });
    return {
      roundId, processId: process.id, workflowStage: "proposal", workflowAttempt,
      phase: "CONFIGURADO", version: 1, candidateSetHash: candidateHash,
      rulesHash, configurationHash, electorateHash: frozenElectorateHash,
    };
  }

  private async loadElectors(cycleId: string, kind: "proposal" | "vote"): Promise<Array<{ identityId: string; canSubmit: boolean; recused: boolean }>> {
    const capability = kind === "proposal" ? "can_propose" : "can_vote";
    const result = await this.client.query<{ identity_id: string; can_submit: boolean; recused: boolean }>(
      `SELECT identity_id,${capability} AS can_submit,recused
         FROM cycle_elector_roster WHERE cycle_id=$1 AND active ORDER BY identity_id`,
      [cycleId],
    );
    return result.rows.map((row) => ({ identityId: row.identity_id, canSubmit: row.can_submit, recused: row.recused }));
  }

  private async insertRoundElectors(roundId: string, electors: readonly { identityId: string; canSubmit: boolean; recused: boolean }[]): Promise<void> {
    for (const elector of electors) {
      await this.client.query(
        "INSERT INTO round_elector_snapshots(round_id,identity_id,can_submit,recused) VALUES ($1,$2,$3,$4)",
        [roundId, elector.identityId, elector.canSubmit && !elector.recused, elector.recused],
      );
    }
  }

  private proposalRulesHash(process: ProcessRow): string {
    return workflowSha256({
      schemaVersion: 1,
      vacancyCount: process.vacancy_count,
      maxProposalSelections: process.max_proposal_selections,
      maxBallotSelections: process.max_ballot_selections,
      decisionRule: process.decision_rule,
      abstentionRule: process.abstention_rule,
      tiebreakPolicy: process.tiebreak_policy,
      quorumRule: process.quorum_rule,
      aggregateAudience: process.aggregate_audience,
    });
  }

  private async participationCounts(roundId: string, kind: "proposal" | "vote"): Promise<{ required: number; received: number }> {
    const result = await this.client.query<{ required: number; received: number }>(
      `SELECT
         (SELECT count(*)::int FROM round_elector_snapshots WHERE round_id=$1 AND can_submit AND NOT recused) AS required,
         (SELECT count(*)::int FROM participation_receipts WHERE round_id=$1 AND kind=$2) AS received`,
      [roundId, kind],
    );
    const counts = result.rows[0];
    if (!counts || counts.required <= 0 || counts.received > counts.required) {
      throw conflict("PARTICIPATION_INVALID", "Frozen participation counts are invalid");
    }
    return counts;
  }

  private async bumpCycle(cycleId: string, expectedVersion: number): Promise<number> {
    const result = await this.client.query<{ version: number }>(
      "UPDATE election_cycles SET version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$2 RETURNING version",
      [cycleId, expectedVersion],
    );
    const version = result.rows[0]?.version;
    if (!version) throw conflict("VERSION_CONFLICT", "Cycle changed during configuration");
    return version;
  }

  private async bumpSession(sessionId: string, expectedVersion: number): Promise<number> {
    const result = await this.client.query<{ version: number }>(
      "UPDATE cycle_sessions SET version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$2 RETURNING version",
      [sessionId, expectedVersion],
    );
    const version = result.rows[0]?.version;
    if (!version) throw conflict("VERSION_CONFLICT", "Session changed during update");
    return version;
  }

  private async executeIdempotent<T>(
    identityId: string,
    operation: string,
    idempotencyKey: string,
    request: unknown,
    work: () => Promise<T>,
  ): Promise<T> {
    const requestHash = workflowSha256(request);
    const inserted = await this.client.query(
      `INSERT INTO idempotency_records(identity_id,operation,idempotency_key,request_hash)
       VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
      [identityId, operation, idempotencyKey, requestHash],
    );
    if (inserted.rowCount === 0) {
      const existing = await this.client.query<{ request_hash: string; response_body: T | null }>(
        `SELECT request_hash,response_body FROM idempotency_records
          WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
        [identityId, operation, idempotencyKey],
      );
      const row = existing.rows[0];
      if (!row || row.request_hash !== requestHash) throw conflict("IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different input");
      if (row.response_body === null) throw conflict("IDEMPOTENCY_IN_PROGRESS", "Original operation is still in progress");
      return row.response_body;
    }
    const response = await work();
    await this.client.query(
      `UPDATE idempotency_records SET response_status=200,response_body=$4
        WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3`,
      [identityId, operation, idempotencyKey, response],
    );
    return response;
  }

  private async emit(eventType: string, aggregateType: string, aggregateId: string, payload: Readonly<Record<string, unknown>>): Promise<void> {
    await this.client.query(
      `INSERT INTO outbox_events(audience,event_type,aggregate_type,aggregate_id,payload)
       VALUES ('tenant.authorized',$1,$2,$3,$4)`,
      [eventType, aggregateType, aggregateId, payload],
    );
  }

  private async appendAudit(
    action: string,
    entityType: string,
    entityId: string,
    result: "success" | "denied" | "failure",
    metadata: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await appendTenantAuditEventV2(this.client, { action, entityType, entityId, result, metadata });
  }
}

function assertVersion(actual: number, expected: number, aggregate: string): void {
  if (actual !== expected) throw conflict("VERSION_CONFLICT", `${aggregate} version is stale`);
}

function assertUnique(values: readonly string[], code: string, message: string): void {
  if (new Set(values).size !== values.length) throw conflict(code, message);
}

function conflict(code: string, message: string): DataConflictError {
  return new DataConflictError(code, message);
}

function assignmentEligibilityPausedResult(input: {
  readonly assignment: AssignmentRow;
  readonly process: ProcessRow;
  readonly roundId: string | null;
  readonly roundVersion: number | null;
  readonly pauseIds: readonly string[];
}): AssignmentEligibilityPausedResult {
  return {
    eligibilityPaused: true,
    code: "ASSIGNMENT_ELIGIBILITY_PAUSED",
    assignmentId: input.assignment.id,
    memberId: input.assignment.member_id,
    processId: input.process.id,
    roundId: input.roundId,
    pauseIds: [...input.pauseIds].sort(),
    processVersion: input.process.version,
    roundVersion: input.roundVersion,
    message: "Assignment eligibility changed; resolve the persisted workflow pause before advancing",
  };
}

export function isAssignmentEligibilityPausedResult(value: unknown): value is AssignmentEligibilityPausedResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record["eligibilityPaused"] === true
    && record["code"] === "ASSIGNMENT_ELIGIBILITY_PAUSED"
    && typeof record["assignmentId"] === "string"
    && typeof record["processId"] === "string"
    && Array.isArray(record["pauseIds"]);
}

function assertConfigurableVacancyProcessMechanism(mechanism: string): void {
  if (isConfigurableVacancyProcessMechanism(mechanism)) return;
  if (mechanism === "council_recommendation_board_approval") {
    throw conflict(
      COUNCIL_BOARD_PROCEDURE_REQUIRED,
      "This office requires council recommendation and board approval and cannot enter the ordinary proposal or ballot workflow",
    );
  }
  throw conflict("OFFICE_NOT_ELECTABLE", "This office cannot be filled by the committee election workflow");
}

function assertOrdinaryProposalBallotMechanism(mechanism: string): void {
  if (isOrdinaryProposalBallotMechanism(mechanism)) return;
  if (mechanism === "council_recommendation_board_approval") {
    throw conflict(
      COUNCIL_BOARD_PROCEDURE_REQUIRED,
      "This office requires council recommendation and board approval and cannot enter the ordinary proposal or ballot workflow",
    );
  }
  if (mechanism === "linked_designation") {
    throw conflict(
      "LINKED_DESIGNATION_DIRECT_ELECTION",
      "A linked responsibility must be derived from its configured base appointment and cannot enter an independent proposal or ballot",
    );
  }
  throw conflict("OFFICE_NOT_ELECTABLE", "This office cannot enter the ordinary proposal or ballot workflow");
}

function requireAllowedReasonCode(value: string, allowed: readonly string[]): string {
  const reasonCode = normalizeAllowedReasonCode(value, allowed);
  if (!reasonCode) throw conflict("INVALID_REASON_CODE", "Operational reason code is not allowed for this operation");
  return reasonCode;
}

function assertPersistedAssignmentTransition(from: string, to: string): void {
  try {
    assertAssignmentTransition(from as AssignmentState, to as AssignmentState);
  } catch {
    throw conflict("INVALID_STATE_TRANSITION", `Assignment cannot transition from ${from} to ${to}`);
  }
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

function sessionProjection(row: SessionRow): Record<string, unknown> {
  return {
    id: row.id,
    cycleId: row.cycle_id,
    sequence: row.sequence,
    ...encryptedTitleProjection(row.title, row.title_envelope, row.title_envelope_version),
    startsAt: row.starts_at,
    endsAt: row.ends_at,
    status: row.status,
    locationEnvelope: row.location_envelope,
    version: row.version,
    actualStartedAt: row.actual_started_at,
    actualClosedAt: row.actual_closed_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const LEGACY_TITLE_REDACTED = "LEGACY_TITLE_REDACTED";

function encryptedTitleProjection(
  legacyTitle: string | null,
  titleEnvelope: EncryptedEnvelope | null,
  titleVersion: number,
): { readonly titleEnvelope: EncryptedEnvelope | null; readonly titleVersion: number; readonly legacyTitleUnavailable: boolean } {
  const legacyTitleUnavailable = legacyTitle === LEGACY_TITLE_REDACTED
    && titleEnvelope === null
    && titleVersion === 0;
  if (!legacyTitleUnavailable && (legacyTitle !== null || titleEnvelope === null || !Number.isSafeInteger(titleVersion) || titleVersion < 1)) {
    throw new Error("Session title encryption state is invalid");
  }
  return { titleEnvelope, titleVersion, legacyTitleUnavailable };
}
