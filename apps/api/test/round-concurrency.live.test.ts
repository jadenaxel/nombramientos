import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DatabaseRuntime,
  MemorySecretProvider,
  sealAesGcmJson,
  TenantProvisioner,
  type EncryptedEnvelope,
} from "@nombramientos/database";
import type { FastifyInstance } from "fastify";
import { Pool, type PoolConfig } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseApiConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";
import {
  cleanupStageError,
  closePoolOwnerAndConfirmDrained,
  collectCleanupFailure,
  dropEphemeralDatabase,
  dropEphemeralRole,
  endPoolAndConfirmDrained,
} from "./ephemeral-postgres-cleanup.js";
import { assertExactWorkspaceAdminUrl } from "./local-test-database-boundary.js";

const CONTROL_DATABASE = "nombramientos_control";
const ORIGIN = "http://localhost:3000";
const USER_AGENT = "nombramientos-ac15-ac16-live-test";
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const migrationsRoot = path.join(workspaceRoot, "packages", "database", "migrations");
const requireLiveIntegration = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverLocalAdminUrl();
const liveReady = adminUrl ? await canReachLocalCluster(adminUrl) : false;

if (requireLiveIntegration && !liveReady) {
  throw new Error(
    "NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true requires the reachable local PostgreSQL administrator and control database",
  );
}

const live = liveReady ? describe.sequential : describe.skip;

live("AC-15/AC-16 live HTTP transaction matrix", () => {
  let fixture: ConcurrencyFixture | undefined;

  beforeAll(async () => {
    if (!adminUrl) throw new Error("The local PostgreSQL administrator is unavailable");
    fixture = await createFixture(adminUrl);
  }, 45_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture.cleanup);
  }, 30_000);

  it("AC-15 coalesces same-key retries and permits only one effective cross-tab submission", async () => {
    const current = requireFixture(fixture);
    const retryKey = randomUUID();
    const retryResponses = await Promise.all(
      Array.from({ length: 6 }, async () => submit(current, current.rounds.retry, retryKey)),
    );
    expect(
      retryResponses.every((response) => response.status === 201),
      JSON.stringify(retryResponses.map(sanitizedResponseDiagnostic)),
    ).toBe(true);
    const retryReceipt = receiptFingerprint(retryResponses[0]?.body);
    expect(Boolean(retryReceipt)).toBe(true);
    expect(retryResponses.every((response) => receiptFingerprint(response.body) === retryReceipt)).toBe(true);

    const retryLookup = await getReceipt(current, current.rounds.retry.id);
    expect(retryLookup.status).toBe(200);
    expect(receiptFingerprint(retryLookup.body) === retryReceipt).toBe(true);
    expect(await roundStatsMatch(current, current.rounds.retry.id, {
      phase: "PROPUESTAS_ABIERTAS",
      version: 1,
      submissions: 1,
      receipts: 1,
      idempotencyRecords: 1,
      auditEvents: 1,
      outboxEvents: 1,
    })).toBe(true);

    const tabKeys = [randomUUID(), randomUUID()] as const;
    const tabResponses = await Promise.all(tabKeys.map(async (key) => ({ key, response: await submit(current, current.rounds.tabs, key) })));
    const accepted = tabResponses.filter(({ response }) => response.status === 201);
    const rejected = tabResponses.filter(({ response }) => response.status === 409);
    expect(accepted).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(apiErrorCode(rejected[0]?.response.body)).toBe("ALREADY_SUBMITTED");

    const winningAttempt = accepted[0];
    if (!winningAttempt) throw new Error("The AC-15 accepted tab attempt is unavailable");
    const winningReceipt = receiptFingerprint(winningAttempt.response.body);
    const winningReplay = await submit(current, current.rounds.tabs, winningAttempt.key);
    expect(winningReplay.status).toBe(201);
    expect(receiptFingerprint(winningReplay.body) === winningReceipt).toBe(true);
    const tabLookup = await getReceipt(current, current.rounds.tabs.id);
    expect(tabLookup.status).toBe(200);
    expect(receiptFingerprint(tabLookup.body) === winningReceipt).toBe(true);
    expect(await roundStatsMatch(current, current.rounds.tabs.id, {
      phase: "PROPUESTAS_ABIERTAS",
      version: 1,
      submissions: 1,
      receipts: 1,
      idempotencyRecords: 1,
      auditEvents: 1,
      outboxEvents: 1,
    })).toBe(true);
  });

  it("AC-16 serializes the last submission against close and rejects a genuinely late submission", async () => {
    const current = requireFixture(fixture);
    const submissionKey = randomUUID();
    const closeKey = randomUUID();
    const [submissionResponse, closeResponse] = await Promise.all([
      submit(current, current.rounds.race, submissionKey),
      close(current, current.rounds.race.id, 1, closeKey),
    ]);

    expect(submissionResponse.status, JSON.stringify(sanitizedResponseDiagnostic(submissionResponse))).toBe(201);
    expect([200, 409]).toContain(closeResponse.status);
    if (closeResponse.status === 409) {
      expect(apiErrorCode(closeResponse.body)).toBe("PARTICIPATION_INCOMPLETE");
    }

    const effectiveClose = closeResponse.status === 200
      ? closeResponse
      : await close(current, current.rounds.race.id, 1, closeKey);
    expect(effectiveClose.status).toBe(200);
    const closeReceipt = closeFingerprint(effectiveClose.body);
    expect(Boolean(closeReceipt)).toBe(true);

    const closeReplay = await close(current, current.rounds.race.id, 1, closeKey);
    expect(closeReplay.status).toBe(200);
    expect(closeFingerprint(closeReplay.body) === closeReceipt).toBe(true);
    const submissionReplay = await submit(current, current.rounds.race, submissionKey);
    expect(submissionReplay.status).toBe(201);
    expect(receiptFingerprint(submissionReplay.body) === receiptFingerprint(submissionResponse.body)).toBe(true);

    const latePayload = submissionPayload(current, current.rounds.race, 2);
    const lateSubmission = await submit(current, current.rounds.race, randomUUID(), latePayload);
    expect(lateSubmission.status).toBe(409);
    expect(apiErrorCode(lateSubmission.body)).toBe("ROUND_CLOSED");
    expect(await roundStatsMatch(current, current.rounds.race.id, {
      phase: "PROPUESTAS_CERRADAS",
      version: 2,
      submissions: 1,
      receipts: 1,
      idempotencyRecords: 2,
      auditEvents: 2,
      outboxEvents: 3,
    })).toBe(true);
  });

  it("AC-16 elects one winner in a distinct-key double close and replays that close idempotently", async () => {
    const current = requireFixture(fixture);
    const initialSubmission = await submit(current, current.rounds.doubleClose, randomUUID());
    expect(initialSubmission.status, JSON.stringify(sanitizedResponseDiagnostic(initialSubmission))).toBe(201);

    const closeKeys = [randomUUID(), randomUUID()] as const;
    const closeAttempts = await Promise.all(
      closeKeys.map(async (key) => ({ key, response: await close(current, current.rounds.doubleClose.id, 1, key) })),
    );
    const accepted = closeAttempts.filter(({ response }) => response.status === 200);
    const rejected = closeAttempts.filter(({ response }) => response.status === 409);
    expect(accepted).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(apiErrorCode(rejected[0]?.response.body)).toBe("VERSION_CONFLICT");

    const winner = accepted[0];
    if (!winner) throw new Error("The AC-16 accepted close attempt is unavailable");
    const winningClose = closeFingerprint(winner.response.body);
    const replays = await Promise.all([
      close(current, current.rounds.doubleClose.id, 1, winner.key),
      close(current, current.rounds.doubleClose.id, 1, winner.key),
    ]);
    expect(replays.every((response) => response.status === 200)).toBe(true);
    expect(replays.every((response) => closeFingerprint(response.body) === winningClose)).toBe(true);

    const newCloseAfterCompletion = await close(current, current.rounds.doubleClose.id, 2, randomUUID());
    expect(newCloseAfterCompletion.status).toBe(409);
    expect(apiErrorCode(newCloseAfterCompletion.body)).toBe("PHASE_CONFLICT");
    expect(await roundStatsMatch(current, current.rounds.doubleClose.id, {
      phase: "PROPUESTAS_CERRADAS",
      version: 2,
      submissions: 1,
      receipts: 1,
      idempotencyRecords: 2,
      auditEvents: 2,
      outboxEvents: 3,
    })).toBe(true);
  });
});

interface RoundFixture {
  readonly id: string;
  readonly cycleId: string;
  readonly candidateId: string;
  readonly candidateSetHash: string;
  readonly rulesHash: string;
  readonly initialPayload: SubmissionPayload;
}

interface SubmissionPayload {
  readonly kind: "proposal";
  readonly expectedVersion: number;
  readonly envelope: EncryptedEnvelope;
  readonly contentHash: string;
}

interface TestSession {
  readonly id: string;
  readonly identityId: string;
  readonly sessionToken: string;
  readonly csrfToken: string;
}

interface ExpectedRoundStats {
  readonly phase: string;
  readonly version: number;
  readonly submissions: number;
  readonly receipts: number;
  readonly idempotencyRecords: number;
  readonly auditEvents: number;
  readonly outboxEvents: number;
}

interface RoundStatsRow {
  readonly phase: string;
  readonly version: number;
  readonly submissions: number;
  readonly receipts: number;
  readonly idempotency_records: number;
  readonly audit_events: number;
  readonly outbox_events: number;
}

interface CleanupState {
  app?: FastifyInstance;
  database?: DatabaseRuntime;
  provisioner: TenantProvisioner | undefined;
  tenant?: Pool;
  readonly control: Pool;
  readonly cluster: Pool;
  readonly tenantId: string;
  readonly databaseName: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly identityId: string;
  readonly sessionId: string;
  readonly provisioningKey: string;
}

interface ConcurrencyFixture {
  readonly baseUrl: string;
  readonly tenant: Pool;
  readonly tenantId: string;
  readonly tenantKey: Buffer;
  readonly tenantKeyId: string;
  readonly session: TestSession;
  readonly rounds: {
    readonly retry: RoundFixture;
    readonly tabs: RoundFixture;
    readonly race: RoundFixture;
    readonly doubleClose: RoundFixture;
  };
  readonly cleanup: CleanupState;
}

interface JsonResponse {
  readonly status: number;
  readonly body: unknown;
}

async function createFixture(databaseAdminUrl: string): Promise<ConcurrencyFixture> {
  const tenantId = randomUUID();
  const suffix = tenantId.replaceAll("-", "");
  const cleanup: CleanupState = {
    control: new Pool({
      connectionString: databaseUrl(databaseAdminUrl, CONTROL_DATABASE),
      application_name: "nombramientos-ac15-ac16-control",
      max: 1,
    }),
    cluster: new Pool({
      connectionString: databaseUrl(databaseAdminUrl, "postgres"),
      application_name: "nombramientos-ac15-ac16-cluster",
      max: 1,
    }),
    provisioner: undefined,
    tenantId,
    databaseName: `nom_t_${suffix}`,
    ownerRole: `nom_o_${suffix}`,
    runtimeRole: `nom_r_${suffix}`,
    identityId: randomUUID(),
    sessionId: randomUUID(),
    provisioningKey: randomUUID(),
  };
  const secrets = new MemorySecretProvider();

  try {
    cleanup.provisioner = new TenantProvisioner({
      admin: adminPoolConfig(databaseAdminUrl),
      control: cleanup.control,
      secrets,
      catalog: temporaryCatalog,
      migrationsRoot,
    });
    const provisioned = await cleanup.provisioner.provision({
      idempotencyKey: cleanup.provisioningKey,
      tenantId,
      slug: `ac-concurrency-${suffix.slice(0, 16)}`,
      displayName: "AC concurrency temporary tenant",
      kind: "demo",
      timezone: "America/La_Paz",
      locale: "es",
    });
    if (
      provisioned.database !== cleanup.databaseName
      || provisioned.runtimeRole !== cleanup.runtimeRole
      || provisioned.tenantId !== tenantId
    ) {
      throw new Error("The temporary tenant provisioner returned mismatched metadata");
    }
    await cleanup.provisioner.close();
    cleanup.provisioner = undefined;

    cleanup.tenant = new Pool({
      connectionString: databaseUrl(databaseAdminUrl, cleanup.databaseName),
      application_name: "nombramientos-ac15-ac16-fixture",
      max: 1,
    });
    await assertTenantTarget(cleanup.tenant, tenantId);

    const session = temporarySession(cleanup.sessionId, cleanup.identityId);
    await insertControlFixture(cleanup.control, tenantId, session);
    const tenantKey = randomBytes(32);
    const tenantKeyId = `ac-concurrency-key-${suffix.slice(0, 16)}`;
    const rounds = await insertTenantFixture(cleanup.tenant, tenantId, cleanup.identityId, tenantKey, tenantKeyId);

    const config = parseApiConfig();
    cleanup.database = new DatabaseRuntime({
      control: {
        connectionString: config.controlDatabaseUrl,
        application_name: "nombramientos-ac15-ac16-api",
        max: 4,
        ssl: false,
      },
      secretProvider: secrets,
      tenantPoolMax: 8,
      tenantPoolIdleMs: 5_000,
    });
    cleanup.app = await buildServer({
      config,
      database: cleanup.database,
      logger: false,
      closeDatabaseOnShutdown: false,
    });
    await cleanup.app.listen({ host: "127.0.0.1", port: 0 });
    const address = cleanup.app.server.address();
    if (!address || typeof address === "string") throw new Error("The AC-15/AC-16 listener has no TCP address");

    return {
      baseUrl: `http://127.0.0.1:${(address as AddressInfo).port}`,
      tenant: cleanup.tenant,
      tenantId,
      tenantKey,
      tenantKeyId,
      session,
      rounds,
      cleanup,
    };
  } catch (setupError) {
    try {
      await cleanupFixture(cleanup);
    } catch (cleanupError) {
      throw new AggregateError(
        [
          cleanupStageError("AC-15/AC-16 fixture setup", setupError),
          cleanupStageError("AC-15/AC-16 setup-failure cleanup", cleanupError),
        ],
        "AC-15/AC-16 fixture setup failed closed",
      );
    }
    throw setupError;
  }
}

async function insertControlFixture(control: Pool, tenantId: string, session: TestSession): Promise<void> {
  const email = `ac-concurrency-${session.identityId.replaceAll("-", "")}@invalid.example`;
  const client = await control.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO platform_identities(
         id,email,normalized_email,display_name,password_hash,mfa_enabled,status
       ) VALUES ($1,$2,$2,'AC concurrency temporary identity','AC_CONCURRENCY_DISABLED_LOGIN',false,'active')`,
      [session.identityId, email],
    );
    await client.query(
      "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
      [tenantId, session.identityId],
    );
    await client.query(
      `INSERT INTO auth_sessions(
         id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,user_agent_hash,ip_prefix_hash
       ) VALUES ($1,$2,$3,$4,$5,clock_timestamp() + interval '20 minutes',$6,$7)`,
      [
        session.id,
        sha256(session.sessionToken),
        sha256(session.csrfToken),
        session.identityId,
        tenantId,
        sha256(USER_AGENT),
        sha256("127.0.0"),
      ],
    );
    await client.query("COMMIT");
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      throw new AggregateError(
        [
          cleanupStageError("AC-15/AC-16 control fixture transaction", error),
          cleanupStageError("AC-15/AC-16 control fixture rollback", rollbackError),
        ],
        "AC-15/AC-16 control fixture transaction and rollback failed",
      );
    }
    throw error;
  } finally {
    client.release();
  }
}

async function insertTenantFixture(
  tenant: Pool,
  tenantId: string,
  identityId: string,
  tenantKey: Uint8Array,
  tenantKeyId: string,
): Promise<ConcurrencyFixture["rounds"]> {
  const memberId = randomUUID();
  const memberEnvelope = sealAesGcmJson(
    { synthetic: true, displayName: "AC concurrency candidate" },
    tenantKey,
    tenantKeyId,
    { tenantId, memberId, purpose: "member-display", schemaVersion: 1 },
  );
  const labels = ["retry", "tabs", "race", "doubleClose"] as const;
  const fixtures = {} as Record<(typeof labels)[number], RoundFixture>;
  const client = await tenant.connect();
  try {
    await client.query("BEGIN");
    const roles = await client.query(
      `INSERT INTO role_bindings(identity_id,role_id)
       SELECT $1,id FROM roles WHERE code IN ('CHURCH_ADMIN','COMMITTEE_MEMBER')
       RETURNING role_id`,
      [identityId],
    );
    if (roles.rowCount !== 2) throw new Error("The temporary tenant is missing required concurrency roles");
    await client.query(
      `INSERT INTO members(id,stable_code,display_envelope,display_content_hash,eligibility_status,available)
       VALUES ($1,$2,$3::jsonb,$4,'eligible',true)`,
      [memberId, `AC-CONCURRENCY-${memberId.slice(0, 8)}`, memberEnvelope, envelopeContentHash(memberEnvelope)],
    );
    const office = await client.query<{ id: string }>("SELECT id::text FROM offices ORDER BY canonical_code LIMIT 1");
    const officeId = office.rows[0]?.id;
    if (!officeId) throw new Error("The temporary concurrency catalog has no office");

    for (const [index, label] of labels.entries()) {
      const cycleId = randomUUID();
      const roundId = randomUUID();
      const candidateId = randomUUID();
      const candidateSetHash = `sha256:${sha256(candidateId)}`;
      const rulesHash = `sha256:${sha256(`proposal|1|1|${label}`)}`;
      await client.query(
        `INSERT INTO election_cycles(
           id,name,status,locale,timezone,term_start,term_end,normative_version,eligible_reference_count
         ) VALUES ($1,$2,'draft','es','America/La_Paz',DATE '2027-01-01',DATE '2027-12-31','ac-concurrency-v1',1)`,
        [cycleId, `AC concurrency ${label}`],
      );
      await client.query(
        `INSERT INTO rounds(
           id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,
           max_proposal_selections,max_ballot_selections,candidate_set_hash,rules_hash,version,opened_at,created_at
         ) VALUES ($1,$2,$3,'PROPUESTAS_ABIERTAS','proposal',1,1,1,1,$4,$5,1,clock_timestamp(),clock_timestamp() + ($6 * interval '1 millisecond'))`,
        [roundId, cycleId, officeId, candidateSetHash, rulesHash, index],
      );
      await client.query(
        "INSERT INTO round_elector_snapshots(round_id,identity_id,can_submit,recused) VALUES ($1,$2,true,false)",
        [roundId, identityId],
      );
      await client.query(
        `INSERT INTO candidate_snapshots(
           round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
           member_version_snapshot,eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
           eligibility_evaluated_on,eligibility_effective
         ) SELECT $1,$2,member.id,$4::jsonb,true,1,0,member.version,
                  member.eligibility_department_id,member.eligibility_valid_until,
                  (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
             FROM members member CROSS JOIN tenant_settings settings
            WHERE member.id=$3 AND settings.singleton=true`,
        [roundId, candidateId, memberId, memberEnvelope],
      );
      const fixture: Omit<RoundFixture, "initialPayload"> = {
        id: roundId,
        cycleId,
        candidateId,
        candidateSetHash,
        rulesHash,
      };
      fixtures[label] = {
        ...fixture,
        initialPayload: createSubmissionPayload(tenantId, tenantKey, tenantKeyId, fixture, 1),
      };
    }
    await client.query("COMMIT");
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      throw new AggregateError(
        [
          cleanupStageError("AC-15/AC-16 tenant fixture transaction", error),
          cleanupStageError("AC-15/AC-16 tenant fixture rollback", rollbackError),
        ],
        "AC-15/AC-16 tenant fixture transaction and rollback failed",
      );
    }
    throw error;
  } finally {
    client.release();
  }
  return {
    retry: fixtures.retry,
    tabs: fixtures.tabs,
    race: fixtures.race,
    doubleClose: fixtures.doubleClose,
  };
}

function createSubmissionPayload(
  tenantId: string,
  tenantKey: Uint8Array,
  tenantKeyId: string,
  round: Omit<RoundFixture, "initialPayload">,
  expectedVersion: number,
): SubmissionPayload {
  const envelope = sealAesGcmJson(
    { schema: "nombramientos-submission/v1", abstain: false, selections: [round.candidateId] },
    tenantKey,
    tenantKeyId,
    {
      tenantId,
      cycleId: round.cycleId,
      roundId: round.id,
      purpose: "proposal",
      schemaVersion: 1,
      roundVersion: expectedVersion,
      candidateSetHash: round.candidateSetHash,
      rulesHash: round.rulesHash,
    },
  );
  return {
    kind: "proposal",
    expectedVersion,
    envelope,
    contentHash: envelopeContentHash(envelope),
  };
}

function submissionPayload(fixture: ConcurrencyFixture, round: RoundFixture, expectedVersion: number): SubmissionPayload {
  return createSubmissionPayload(fixture.tenantId, fixture.tenantKey, fixture.tenantKeyId, round, expectedVersion);
}

async function submit(
  fixture: ConcurrencyFixture,
  round: RoundFixture,
  idempotencyKey: string,
  payload: SubmissionPayload = round.initialPayload,
): Promise<JsonResponse> {
  return postJson(fixture, `/v1/rounds/${round.id}/submissions`, idempotencyKey, payload);
}

async function close(
  fixture: ConcurrencyFixture,
  roundId: string,
  expectedVersion: number,
  idempotencyKey: string,
): Promise<JsonResponse> {
  return postJson(fixture, `/v1/rounds/${roundId}/close`, idempotencyKey, {
    expectedVersion,
    reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
  });
}

async function getReceipt(fixture: ConcurrencyFixture, roundId: string): Promise<JsonResponse> {
  return requestJson(fixture, `/v1/rounds/${roundId}/submissions/me`, { method: "GET" });
}

async function postJson(
  fixture: ConcurrencyFixture,
  route: string,
  idempotencyKey: string,
  payload: Readonly<Record<string, unknown>> | SubmissionPayload,
): Promise<JsonResponse> {
  return requestJson(fixture, route, { method: "POST", idempotencyKey, payload });
}

async function requestJson(
  fixture: ConcurrencyFixture,
  route: string,
  options: {
    readonly method: "GET" | "POST";
    readonly idempotencyKey?: string;
    readonly payload?: Readonly<Record<string, unknown>> | SubmissionPayload;
  },
): Promise<JsonResponse> {
  const headers: Record<string, string> = {
    origin: ORIGIN,
    "user-agent": USER_AGENT,
    cookie: `nom_session=${fixture.session.sessionToken}; nom_csrf=${fixture.session.csrfToken}`,
  };
  if (options.method === "POST") {
    if (!options.idempotencyKey || !options.payload) throw new Error("POST test requests require payload and idempotency key");
    headers["content-type"] = "application/json";
    headers["x-csrf-token"] = fixture.session.csrfToken;
    headers["idempotency-key"] = options.idempotencyKey;
  }
  const response = await fetch(fixture.baseUrl + route, {
    method: options.method,
    headers,
    ...(options.payload ? { body: JSON.stringify(options.payload) } : {}),
  });
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  return { status: response.status, body };
}

async function roundStatsMatch(fixture: ConcurrencyFixture, roundId: string, expected: ExpectedRoundStats): Promise<boolean> {
  const result = await fixture.tenant.query<RoundStatsRow>(
    `SELECT round_state.phase,round_state.version,
            (SELECT count(*)::int FROM encrypted_submissions WHERE round_id=$1) AS submissions,
            (SELECT count(*)::int FROM participation_receipts WHERE round_id=$1) AS receipts,
            (SELECT count(*)::int FROM idempotency_records
              WHERE operation IN ('round.proposal.submit','round.close')
                AND response_body->>'roundId'=$1::text) AS idempotency_records,
            (SELECT count(*)::int FROM audit_events WHERE entity_type='round' AND entity_id=$1::text) AS audit_events,
            (SELECT count(*)::int FROM outbox_events WHERE aggregate_type='round' AND aggregate_id=$1) AS outbox_events
       FROM rounds round_state WHERE round_state.id=$1`,
    [roundId],
  );
  const actual = result.rows[0];
  return Boolean(
    actual
    && actual.phase === expected.phase
    && actual.version === expected.version
    && actual.submissions === expected.submissions
    && actual.receipts === expected.receipts
    && actual.idempotency_records === expected.idempotencyRecords
    && actual.audit_events === expected.auditEvents
    && actual.outbox_events === expected.outboxEvents,
  );
}

function receiptFingerprint(body: unknown): string | undefined {
  const data = apiData(body);
  if (!data) return undefined;
  const fields = ["receiptId", "receivedAt", "roundId", "roundVersion", "contentHash", "status"] as const;
  if (fields.some((field) => data[field] === undefined)) return undefined;
  return fields.map((field) => String(data[field])).join("|");
}

function closeFingerprint(body: unknown): string | undefined {
  const data = apiData(body);
  if (!data) return undefined;
  const fields = ["roundId", "previousPhase", "newPhase", "version", "closedAt", "manifestPending"] as const;
  if (fields.some((field) => data[field] === undefined)) return undefined;
  return fields.map((field) => String(data[field])).join("|");
}

function apiData(body: unknown): Record<string, unknown> | undefined {
  if (!body || typeof body !== "object" || !("data" in body)) return undefined;
  const data = body.data;
  return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : undefined;
}

function apiErrorCode(body: unknown): unknown {
  if (!body || typeof body !== "object" || !("error" in body)) return undefined;
  const error = body.error;
  return error && typeof error === "object" && "code" in error ? error.code : undefined;
}

function sanitizedResponseDiagnostic(response: JsonResponse): Readonly<Record<string, unknown>> {
  const body = response.body;
  const error = body && typeof body === "object" && "error" in body
    && body.error && typeof body.error === "object"
    ? body.error as Record<string, unknown>
    : undefined;
  const meta = body && typeof body === "object" && "meta" in body
    && body.meta && typeof body.meta === "object"
    ? body.meta as Record<string, unknown>
    : undefined;
  return {
    status: response.status,
    errorCode: typeof error?.["code"] === "string" ? error["code"] : null,
    requestIdPresent: typeof meta?.["requestId"] === "string",
  };
}

function envelopeContentHash(envelope: EncryptedEnvelope): string {
  const canonical = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  return `sha256:${sha256(canonical)}`;
}

function temporarySession(id: string, identityId: string): TestSession {
  return {
    id,
    identityId,
    sessionToken: randomBytes(32).toString("base64url"),
    csrfToken: randomBytes(32).toString("base64url"),
  };
}

async function cleanupFixture(state: CleanupState): Promise<void> {
  assertConcurrencyEphemeralNames(state);
  const failures: Error[] = [];
  let runtimeTenantPool: Pool | undefined;
  if (state.database) {
    await collectCleanupFailure(failures, "AC-15/AC-16 runtime tenant pool lookup", async () => {
      runtimeTenantPool = await state.database!.tenantPools.getPool(state.tenantId);
    });
  }
  if (state.app) {
    await collectCleanupFailure(failures, "AC-15/AC-16 API close", async () => state.app!.close());
  }
  if (state.database) {
    await collectCleanupFailure(failures, "AC-15/AC-16 database runtime close", async () => {
      await closePoolOwnerAndConfirmDrained(
        [
          { pool: state.database!.controlPool, label: "AC-15/AC-16 runtime control pool" },
          ...(runtimeTenantPool ? [{ pool: runtimeTenantPool, label: "AC-15/AC-16 runtime tenant pool" }] : []),
        ],
        async () => state.database!.close(),
        "AC-15/AC-16 database runtime close",
      );
    });
  }
  if (state.tenant) {
    await collectCleanupFailure(failures, "AC-15/AC-16 fixture tenant pool close", async () => {
      await endPoolAndConfirmDrained(state.tenant!, "AC-15/AC-16 fixture tenant pool");
    });
  }
  if (state.provisioner) {
    await collectCleanupFailure(failures, "AC-15/AC-16 provisioner close", async () => state.provisioner!.close());
  }

  await collectCleanupFailure(failures, "AC-15/AC-16 control-plane cleanup", async () => {
    const record = await state.control.query<{ database_name: string; runtime_role: string }>(
      "SELECT database_name::text,runtime_role::text FROM tenants WHERE id=$1",
      [state.tenantId],
    );
    const row = record.rows[0];
    if (row && (row.database_name !== state.databaseName || row.runtime_role !== state.runtimeRole)) {
      throw new Error("Refusing cleanup for mismatched temporary tenant metadata");
    }
    await state.control.query("DELETE FROM auth_sessions WHERE id=$1 OR identity_id=$2", [state.sessionId, state.identityId]);
    await state.control.query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND identity_id=$2", [state.tenantId, state.identityId]);
    await state.control.query("DELETE FROM platform_identities WHERE id=$1", [state.identityId]);
    await state.control.query("DELETE FROM tenants WHERE id=$1", [state.tenantId]);
    await state.control.query("DELETE FROM provisioning_jobs WHERE tenant_id=$1 OR idempotency_key=$2", [state.tenantId, state.provisioningKey]);
    const remaining = await state.control.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM auth_sessions WHERE id=$1 OR identity_id=$2)
         + (SELECT count(*) FROM tenant_memberships WHERE tenant_id=$3 OR identity_id=$2)
         + (SELECT count(*) FROM platform_identities WHERE id=$2)
         + (SELECT count(*) FROM tenants WHERE id=$3)
         + (SELECT count(*) FROM provisioning_jobs WHERE tenant_id=$3 OR idempotency_key=$4)
       )::int AS count`,
      [state.sessionId, state.identityId, state.tenantId, state.provisioningKey],
    );
    if (remaining.rows[0]?.count !== 0) throw new Error("Temporary control-plane cleanup is incomplete");
  });

  try {
    await collectCleanupFailure(failures, "AC-15/AC-16 database drop", async () => dropEphemeralDatabase(
      state.cluster,
      state.databaseName,
      { pattern: /^nom_t_[0-9a-f]{32}$/u, label: "AC-15/AC-16 temporary database" },
    ));
    await collectCleanupFailure(failures, "AC-15/AC-16 runtime role drop", async () => dropEphemeralRole(
      state.cluster,
      state.runtimeRole,
      { pattern: /^nom_r_[0-9a-f]{32}$/u, label: "AC-15/AC-16 runtime role" },
    ));
    await collectCleanupFailure(failures, "AC-15/AC-16 owner role drop", async () => dropEphemeralRole(
      state.cluster,
      state.ownerRole,
      { pattern: /^nom_o_[0-9a-f]{32}$/u, label: "AC-15/AC-16 owner role" },
    ));
    await collectCleanupFailure(failures, "AC-15/AC-16 PostgreSQL residue attestation", async () => {
      const remaining = await state.cluster.query<{ databases: number; roles: number }>(
        `SELECT
           (SELECT count(*)::int FROM pg_database WHERE datname=$1) AS databases,
           (SELECT count(*)::int FROM pg_roles WHERE rolname = ANY($2::text[])) AS roles`,
        [state.databaseName, [state.runtimeRole, state.ownerRole]],
      );
      const row = remaining.rows[0];
      if (!row || row.databases !== 0 || row.roles !== 0) throw new Error("Temporary PostgreSQL objects remain after cleanup");
    });
  } finally {
    await collectCleanupFailure(failures, "AC-15/AC-16 control pool close", async () => {
      await endPoolAndConfirmDrained(state.control, "AC-15/AC-16 control pool");
    });
    await collectCleanupFailure(failures, "AC-15/AC-16 maintenance pool close", async () => {
      await endPoolAndConfirmDrained(state.cluster, "AC-15/AC-16 maintenance pool");
    });
  }
  if (failures.length > 0) {
    throw new AggregateError(failures, "AC-15/AC-16 temporary fixture cleanup failed closed");
  }
}

function assertConcurrencyEphemeralNames(state: CleanupState): void {
  const suffix = state.tenantId.replaceAll("-", "");
  if (
    !/^[0-9a-f]{32}$/u.test(suffix)
    || state.databaseName !== `nom_t_${suffix}`
    || state.ownerRole !== `nom_o_${suffix}`
    || state.runtimeRole !== `nom_r_${suffix}`
  ) {
    throw new Error("Refusing cleanup outside the exact AC-15/AC-16 tenant boundary");
  }
}

async function assertTenantTarget(tenant: Pool, tenantId: string): Promise<void> {
  const target = await tenant.query<{ database_name: string; tenant_id: string; kind: string }>(
    `SELECT current_database() AS database_name,tenant_id::text,kind
       FROM tenant_settings WHERE singleton=true`,
  );
  const row = target.rows[0];
  if (!row || row.database_name !== `nom_t_${tenantId.replaceAll("-", "")}` || row.tenant_id !== tenantId || row.kind !== "demo") {
    throw new Error("The temporary concurrency tenant target is invalid");
  }
}

function requireFixture(fixture: ConcurrencyFixture | undefined): ConcurrencyFixture {
  if (!fixture) throw new Error("The AC-15/AC-16 fixture is unavailable");
  return fixture;
}

function discoverLocalAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const value: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (value && typeof value === "object" && "DATABASE_ADMIN_URL" in value) {
        const configured = value.DATABASE_ADMIN_URL;
        if (typeof configured === "string") candidate = configured;
      }
    }
    if (!candidate) return undefined;
    return assertExactWorkspaceAdminUrl(candidate);
  } catch {
    return undefined;
  }
}

async function canReachLocalCluster(databaseAdminUrl: string): Promise<boolean> {
  const pools = [
    new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), connectionTimeoutMillis: 1_500, max: 1 }),
    new Pool({ connectionString: databaseUrl(databaseAdminUrl, CONTROL_DATABASE), connectionTimeoutMillis: 1_500, max: 1 }),
  ];
  try {
    await Promise.all(pools.map(async (pool) => pool.query("SELECT 1")));
    parseApiConfig();
    return true;
  } catch {
    return false;
  } finally {
    await closePoolOwnerAndConfirmDrained(
      pools.map((pool, index) => ({ pool, label: `AC-15/AC-16 reachability pool ${index + 1}` })),
      async () => Promise.all(pools.map(async (pool) => pool.end())),
      "AC-15/AC-16 reachability pool close",
    );
  }
}

function adminPoolConfig(databaseAdminUrl: string): PoolConfig {
  const value = new URL(databaseAdminUrl);
  return {
    host: value.hostname,
    port: Number(value.port || "5432"),
    database: "postgres",
    user: decodeURIComponent(value.username),
    password: decodeURIComponent(value.password),
    ssl: false,
    max: 1,
  };
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(databaseName)) throw new Error("Refusing an invalid local PostgreSQL database name");
  const value = new URL(databaseAdminUrl);
  value.pathname = `/${databaseName}`;
  return value.toString();
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

const temporaryCatalog = {
  version: "ac-concurrency-v1",
  departments: [{
    canonicalCode: "ac_concurrency_department",
    names: { es: "Departamento temporal", en: "Temporary department", fr: "Département temporaire" },
    parentDepartmentCode: null,
  }],
  offices: [{
    canonicalCode: "ac_concurrency_office",
    departmentCode: "ac_concurrency_department",
    names: { es: "Cargo temporal", en: "Temporary office", fr: "Poste temporaire" },
    mechanism: "church_election_after_nominating_report",
    cardinality: { minimum: 1, maximum: 1 },
  }],
} as const;
