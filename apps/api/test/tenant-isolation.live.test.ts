import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseRuntime, EncryptedFileSecretProvider, encryptServerSecret } from "@nombramientos/database";
import type { FastifyInstance } from "fastify";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseApiConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";
import {
  cleanupStageError,
  closePoolOwnerAndConfirmDrained,
  collectCleanupFailure,
  endPoolAndConfirmDrained,
} from "./ephemeral-postgres-cleanup.js";
import { assertExactWorkspaceAdminUrl } from "./local-test-database-boundary.js";
import {
  destroyTemporaryActiveTenant,
  provisionTemporaryActiveTenant,
  type TemporaryActiveTenant,
} from "./temporary-active-tenant.js";

const DEMO_TENANT_ID = "d0000000-0000-4000-8000-000000000001";
const OZAMA_TENANT_ID = "0a2a0000-0000-4000-8000-000000000001";
const CONTROL_DATABASE = "nombramientos_control";
const ORIGIN = "http://localhost:3000";
const USER_AGENT = "nombramientos-ac02-live-http-test";
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const requireLiveIntegration = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverLocalAdminUrl();
const liveReady = adminUrl ? await canReachAc02Targets(adminUrl) : false;

if (requireLiveIntegration && !liveReady) {
  throw new Error(
    "NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true requires reachable Demo, Ozama, and control PostgreSQL databases",
  );
}

const live = liveReady ? describe : describe.skip;

live("AC-02 live HTTP tenant-isolation matrix", () => {
  let fixture: Ac02Fixture | undefined;

  beforeAll(async () => {
    if (!adminUrl) throw new Error("The local administrator connection is unavailable");
    fixture = await createFixture(adminUrl);
  }, 30_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture.cleanup);
  }, 30_000);

  it("derives every read tenant from the authenticated session despite query, header, and cookie hints", async () => {
    const current = requireFixture(fixture);
    for (const actor of actorPairs(current)) {
      const sessionResponse = await requestJson(current, "/v1/session?tenantId=" + actor.foreignTenantId, {
        session: actor.session,
        headers: { "x-tenant-id": actor.foreignTenantId },
        cookieTenantHint: actor.foreignTenantId,
      });
      expect(sessionResponse.status).toBe(200);
      expect(sessionTenantId(sessionResponse.body) === actor.session.tenantId).toBe(true);

      const attempts: readonly RequestOptions[] = [
        { session: actor.session },
        { session: actor.session, queryTenantHint: actor.foreignTenantId },
        { session: actor.session, headers: { "x-tenant-id": actor.foreignTenantId } },
        { session: actor.session, cookieTenantHint: actor.foreignTenantId },
      ];
      for (const attempt of attempts) {
        const response = await requestJson(current, memberListPath(attempt.queryTenantHint), attempt);
        expect(response.status).toBe(200);
        expect(containsOnlyExpectedFirstMember(response.body, actor.ownMemberId, actor.foreignMemberId)).toBe(true);
      }
    }
  });

  it("does not disclose a foreign member's existence through a cross-tenant path identifier", async () => {
    const current = requireFixture(fixture);
    for (const actor of actorPairs(current)) {
      const missingMemberId = randomUUID();
      const foreign = await patchMember(current, actor.session, actor.foreignMemberId, actor.foreignMemberVersion);
      const absent = await patchMember(current, actor.session, missingMemberId, actor.foreignMemberVersion);

      expect(foreign.status).toBe(409);
      expect(apiErrorCode(foreign.body)).toBe("VERSION_CONFLICT");
      expect(samePublicError(foreign, absent)).toBe(true);
    }
    await expectPristineMembers(current);
  });

  it("never routes writes by query, header, body, or tenant-like cookie values", async () => {
    const current = requireFixture(fixture);
    for (const actor of actorPairs(current)) {
      const baseline = await patchMember(current, actor.session, randomUUID(), actor.foreignMemberVersion);
      const attempts: readonly RequestOptions[] = [
        { session: actor.session, queryTenantHint: actor.foreignTenantId },
        { session: actor.session, headers: { "x-tenant-id": actor.foreignTenantId } },
        { session: actor.session, bodyTenantHint: actor.foreignTenantId },
        { session: actor.session, cookieTenantHint: actor.foreignTenantId },
      ];

      for (const [attemptIndex, attempt] of attempts.entries()) {
        const response = await patchMember(
          current,
          actor.session,
          actor.foreignMemberId,
          actor.foreignMemberVersion,
          attempt,
        );
        if (attempt.bodyTenantHint) {
          expect(response.status, `actor=${actor.session.tenantId} attempt=${attemptIndex}`).toBe(400);
          expect(apiErrorCode(response.body)).toBe("VALIDATION_ERROR");
        } else {
          expect(
            samePublicError(response, baseline),
            `actor=${actor.session.tenantId} attempt=${attemptIndex} baseline=${baseline.status}/${apiErrorCode(baseline.body)} response=${response.status}/${apiErrorCode(response.body)}`,
          ).toBe(true);
        }
      }
    }
    await expectPristineMembers(current);
  });

  it("rejects crossed CSRF/session cookies and invalid sessions before any tenant write", async () => {
    const current = requireFixture(fixture);
    for (const actor of actorPairs(current)) {
      const crossed = await patchMember(
        current,
        actor.session,
        actor.ownMemberId,
        actor.ownMemberVersion,
        {
          session: actor.session,
          csrfCookieOverride: actor.otherSession.csrfToken,
          csrfHeaderOverride: actor.otherSession.csrfToken,
        },
      );
      expect(crossed.status).toBe(403);
      expect(apiErrorCode(crossed.body)).toBe("CSRF_INVALID");
    }

    const invalidSessionToken = randomBytes(32).toString("base64url");
    const invalidCsrfToken = randomBytes(32).toString("base64url");
    const invalidCookie = `nom_session=${invalidSessionToken}; nom_csrf=${invalidCsrfToken}`;
    const demoTarget = await requestJson(current, `/v1/members?limit=1&tenantId=${DEMO_TENANT_ID}`, { cookie: invalidCookie });
    const ozamaTarget = await requestJson(current, `/v1/members?limit=1&tenantId=${OZAMA_TENANT_ID}`, { cookie: invalidCookie });
    expect(demoTarget.status).toBe(401);
    expect(samePublicError(demoTarget, ozamaTarget)).toBe(true);
    expect(apiErrorCode(demoTarget.body)).toBe("AUTHENTICATION_REQUIRED");
    await expectPristineMembers(current);
  });

  it("returns the same neutral 404 for existing and unknown tenant-shaped route alterations", async () => {
    const current = requireFixture(fixture);
    const unknownTenantId = randomUUID();
    for (const actor of actorPairs(current)) {
      const existing = await requestJson(current, `/v1/tenants/${actor.foreignTenantId}/members`, { session: actor.session });
      const absent = await requestJson(current, `/v1/tenants/${unknownTenantId}/members`, { session: actor.session });
      expect(existing.status).toBe(404);
      expect(apiErrorCode(existing.body)).toBe("NOT_FOUND");
      expect(samePublicError(existing, absent)).toBe(true);
    }
  });
});

interface TenantRecord {
  readonly id: string;
  readonly kind: "demo" | "real";
  readonly status: string;
  readonly database_name: string;
  readonly runtime_secret_ref: string;
}

interface TestSession {
  readonly id: string;
  readonly identityId: string;
  readonly tenantId: string;
  readonly sessionToken: string;
  readonly csrfToken: string;
}

interface MemberSnapshot {
  readonly id: string;
  readonly version: number;
  readonly available: boolean;
}

interface CleanupState {
  app?: FastifyInstance;
  database?: DatabaseRuntime;
  control: Pool;
  demo?: Pool;
  scratch?: Pool;
  temporaryTenant?: TemporaryActiveTenant;
  readonly databaseAdminUrl: string;
  readonly demoSessionId: string;
  readonly scratchSessionId: string;
  readonly scratchIdentityId: string;
  readonly scratchMemberId: string;
  readonly idempotencyKeys: string[];
}

interface Ac02Fixture {
  readonly baseUrl: string;
  readonly demo: Pool;
  readonly scratch: Pool;
  readonly scratchTenantId: string;
  readonly demoSession: TestSession;
  readonly scratchSession: TestSession;
  readonly demoMember: MemberSnapshot;
  readonly scratchMember: MemberSnapshot;
  readonly cleanup: CleanupState;
}

interface ActorPair {
  readonly session: TestSession;
  readonly otherSession: TestSession;
  readonly ownMemberId: string;
  readonly ownMemberVersion: number;
  readonly foreignMemberId: string;
  readonly foreignMemberVersion: number;
  readonly foreignTenantId: string;
}

interface RequestOptions {
  readonly method?: "GET" | "PATCH";
  readonly session?: TestSession;
  readonly cookie?: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly queryTenantHint?: string;
  readonly cookieTenantHint?: string;
  readonly bodyTenantHint?: string;
  readonly csrfCookieOverride?: string;
  readonly csrfHeaderOverride?: string;
  readonly payload?: Readonly<Record<string, unknown>>;
}

interface JsonResponse {
  readonly status: number;
  readonly body: unknown;
}

async function createFixture(databaseAdminUrl: string): Promise<Ac02Fixture> {
  const cleanup: CleanupState = {
    control: new Pool({
      connectionString: databaseUrl(databaseAdminUrl, CONTROL_DATABASE),
      application_name: "nombramientos-ac02-control",
      max: 1,
    }),
    databaseAdminUrl,
    demoSessionId: randomUUID(),
    scratchSessionId: randomUUID(),
    scratchIdentityId: randomUUID(),
    scratchMemberId: randomUUID(),
    idempotencyKeys: [],
  };

  try {
    await assertCanonicalOzamaPendingAndEmpty(databaseAdminUrl, cleanup.control);
    const tenants = await cleanup.control.query<TenantRecord>(
      `SELECT id::text,kind,database_name::text,runtime_secret_ref
         FROM tenants
        WHERE id=$1 AND status='active'`,
      [DEMO_TENANT_ID],
    );
    const demoRecord = tenants.rows.find((row) => row.id === DEMO_TENANT_ID && row.kind === "demo");
    if (!demoRecord || tenants.rowCount !== 1) {
      throw new Error("AC-02 requires the expected active Demo tenant record");
    }

    cleanup.temporaryTenant = await provisionTemporaryActiveTenant(databaseAdminUrl, cleanup.control, "ac02");

    cleanup.demo = new Pool({
      connectionString: databaseUrl(databaseAdminUrl, demoRecord.database_name),
      application_name: "nombramientos-ac02-demo-admin",
      max: 1,
    });
    cleanup.scratch = new Pool({
      connectionString: databaseUrl(databaseAdminUrl, cleanup.temporaryTenant.databaseName),
      application_name: "nombramientos-ac02-scratch-admin",
      max: 1,
    });
    await Promise.all([
      assertTenantTarget(cleanup.demo, DEMO_TENANT_ID, "demo"),
      assertTenantTarget(cleanup.scratch, cleanup.temporaryTenant.tenantId, "demo"),
    ]);

    const config = parseApiConfig();
    const demoIdentityId = await findDemoAdministrator(cleanup.control, cleanup.demo);
    const demoMember = await findFirstDemoMember(cleanup.demo);
    const temporaryEmail = `ac02-${cleanup.scratchIdentityId.replaceAll("-", "")}@invalid.example`;
    const temporaryTotpSecret = encryptServerSecret(
      randomBytes(20).toString("base64url"),
      config.authEncryptionKey,
    );
    await cleanup.control.query(
      `INSERT INTO platform_identities(
         id,email,normalized_email,display_name,password_hash,mfa_enabled,totp_secret_ciphertext,
         mfa_required,mfa_enrolled_at,status
       ) VALUES (
         $1,$2,$2,'AC-02 temporary identity','AC02_DISABLED_NON_LOGIN_IDENTITY',true,$3,
         true,clock_timestamp(),'active'
       )`,
      [cleanup.scratchIdentityId, temporaryEmail, temporaryTotpSecret],
    );
    await cleanup.control.query(
      "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
      [cleanup.temporaryTenant.tenantId, cleanup.scratchIdentityId],
    );
    const role = await cleanup.scratch.query(
      `INSERT INTO role_bindings(identity_id,role_id)
       SELECT $1,id FROM roles WHERE code='CHURCH_ADMIN'
       RETURNING identity_id`,
      [cleanup.scratchIdentityId],
    );
    if (role.rowCount !== 1) throw new Error("Scratch CHURCH_ADMIN role is unavailable");

    const scratchEnvelope = temporaryEnvelope(cleanup.temporaryTenant.tenantId, cleanup.scratchMemberId);
    const insertedMember = await cleanup.scratch.query<MemberSnapshot>(
      `INSERT INTO members(
         id,stable_code,display_envelope,display_content_hash,eligibility_status,available,created_at,updated_at
       ) VALUES ($1,$2,$3::jsonb,$4,'eligible',true,TIMESTAMPTZ '1970-01-01 00:00:00+00',TIMESTAMPTZ '1970-01-01 00:00:00+00')
       RETURNING id::text,version,available`,
      [
        cleanup.scratchMemberId,
        `AC02-${cleanup.scratchMemberId.slice(0, 12)}`,
        scratchEnvelope,
        envelopeContentHash(scratchEnvelope),
      ],
    );
    const scratchMember = insertedMember.rows[0];
    if (!scratchMember) throw new Error("The temporary scratch member was not created");

    const demoSession = temporarySession(cleanup.demoSessionId, demoIdentityId, DEMO_TENANT_ID);
    const scratchSession = temporarySession(
      cleanup.scratchSessionId,
      cleanup.scratchIdentityId,
      cleanup.temporaryTenant.tenantId,
    );
    await Promise.all([
      insertSession(cleanup.control, demoSession),
      insertSession(cleanup.control, scratchSession),
    ]);

    const persistentSecrets = new EncryptedFileSecretProvider(config.secretFile, config.secretMasterKey);
    await cleanup.temporaryTenant.secrets.putSecret(
      demoRecord.runtime_secret_ref,
      await persistentSecrets.getSecret(demoRecord.runtime_secret_ref),
    );
    cleanup.database = new DatabaseRuntime({
      control: {
        connectionString: config.controlDatabaseUrl,
        application_name: "nombramientos-ac02-api",
        max: 2,
        ssl: false,
      },
      secretProvider: cleanup.temporaryTenant.secrets,
      tenantPoolMax: 1,
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
    if (!address || typeof address === "string") throw new Error("The AC-02 HTTP listener did not expose a TCP address");

    return {
      baseUrl: `http://127.0.0.1:${(address as AddressInfo).port}`,
      demo: cleanup.demo,
      scratch: cleanup.scratch,
      scratchTenantId: cleanup.temporaryTenant.tenantId,
      demoSession,
      scratchSession,
      demoMember,
      scratchMember,
      cleanup,
    };
  } catch (setupError) {
    try {
      await cleanupFixture(cleanup);
    } catch (cleanupError) {
      throw new AggregateError(
        [
          cleanupStageError("AC-02 fixture setup", setupError),
          cleanupStageError("AC-02 setup-failure cleanup", cleanupError),
        ],
        "AC-02 fixture setup failed closed",
      );
    }
    throw setupError;
  }
}

async function cleanupFixture(state: CleanupState): Promise<void> {
  const failures: Error[] = [];
  let runtimeDemoPool: Pool | undefined;
  let runtimeScratchPool: Pool | undefined;
  if (state.database && state.temporaryTenant) {
    await collectCleanupFailure(failures, "AC-02 runtime Demo pool lookup", async () => {
      runtimeDemoPool = await state.database!.tenantPools.getPool(DEMO_TENANT_ID);
    });
    await collectCleanupFailure(failures, "AC-02 runtime scratch pool lookup", async () => {
      runtimeScratchPool = await state.database!.tenantPools.getPool(state.temporaryTenant!.tenantId);
    });
  }
  if (state.app) {
    await collectCleanupFailure(failures, "AC-02 API close", async () => state.app!.close());
  }
  if (state.database) {
    await collectCleanupFailure(failures, "AC-02 database runtime close", async () => {
      await closePoolOwnerAndConfirmDrained(
        [
          { pool: state.database!.controlPool, label: "AC-02 runtime control pool" },
          ...(runtimeDemoPool ? [{ pool: runtimeDemoPool, label: "AC-02 runtime Demo pool" }] : []),
          ...(runtimeScratchPool ? [{ pool: runtimeScratchPool, label: "AC-02 runtime scratch pool" }] : []),
        ],
        async () => state.database!.close(),
        "AC-02 database runtime close",
      );
    });
  }
  const keys = state.idempotencyKeys;
  if (state.demo) {
    await collectCleanupFailure(failures, "AC-02 Demo fixture cleanup", async () => {
      if (keys.length > 0) await state.demo!.query("DELETE FROM idempotency_records WHERE idempotency_key = ANY($1::uuid[])", [keys]);
      const remaining = await state.demo!.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM idempotency_records WHERE idempotency_key = ANY($1::uuid[])",
        [keys],
      );
      if (remaining.rows[0]?.count !== 0) throw new Error("Demo AC-02 idempotency cleanup is incomplete");
    });
  }
  if (state.scratch) {
    await collectCleanupFailure(failures, "AC-02 scratch fixture cleanup", async () => {
      if (keys.length > 0) await state.scratch!.query("DELETE FROM idempotency_records WHERE idempotency_key = ANY($1::uuid[])", [keys]);
      await state.scratch!.query("DELETE FROM outbox_events WHERE aggregate_id=$1", [state.scratchMemberId]);
      await state.scratch!.query("DELETE FROM members WHERE id=$1", [state.scratchMemberId]);
      await state.scratch!.query("DELETE FROM role_bindings WHERE identity_id=$1", [state.scratchIdentityId]);
      const remaining = await state.scratch!.query<{ count: number }>(
        `SELECT (
           (SELECT count(*) FROM idempotency_records WHERE idempotency_key = ANY($1::uuid[]))
           + (SELECT count(*) FROM outbox_events WHERE aggregate_id=$2)
           + (SELECT count(*) FROM members WHERE id=$2)
           + (SELECT count(*) FROM role_bindings WHERE identity_id=$3)
         )::int AS count`,
        [keys, state.scratchMemberId, state.scratchIdentityId],
      );
      if (remaining.rows[0]?.count !== 0) throw new Error("Scratch AC-02 tenant cleanup is incomplete");
    });
  }
  await collectCleanupFailure(failures, "AC-02 control-plane fixture cleanup", async () => {
    await state.control.query("DELETE FROM auth_sessions WHERE id = ANY($1::uuid[])", [[state.demoSessionId, state.scratchSessionId]]);
    await state.control.query("DELETE FROM tenant_memberships WHERE identity_id=$1", [state.scratchIdentityId]);
    await state.control.query("DELETE FROM platform_identities WHERE id=$1", [state.scratchIdentityId]);
    const remaining = await state.control.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM auth_sessions WHERE id = ANY($1::uuid[]))
         + (SELECT count(*) FROM tenant_memberships WHERE identity_id=$2)
         + (SELECT count(*) FROM platform_identities WHERE id=$2)
       )::int AS count`,
      [[state.demoSessionId, state.scratchSessionId], state.scratchIdentityId],
    );
    if (remaining.rows[0]?.count !== 0) throw new Error("AC-02 control-plane cleanup is incomplete");
  });
  if (state.demo) {
    await collectCleanupFailure(failures, "AC-02 Demo admin pool close", async () => {
      await endPoolAndConfirmDrained(state.demo!, "AC-02 Demo admin pool");
    });
  }
  if (state.scratch) {
    await collectCleanupFailure(failures, "AC-02 scratch admin pool close", async () => {
      await endPoolAndConfirmDrained(state.scratch!, "AC-02 scratch admin pool");
    });
  }
  if (state.temporaryTenant) {
    await collectCleanupFailure(failures, "AC-02 temporary tenant destroy", async () => {
      await destroyTemporaryActiveTenant(state.databaseAdminUrl, state.control, state.temporaryTenant!);
    });
  }
  await collectCleanupFailure(failures, "AC-02 canonical Ozama attestation", async () => {
    await assertCanonicalOzamaPendingAndEmpty(state.databaseAdminUrl, state.control);
  });
  await collectCleanupFailure(failures, "AC-02 control pool close", async () => {
    await endPoolAndConfirmDrained(state.control, "AC-02 control pool");
  });
  if (failures.length > 0) {
    throw new AggregateError(failures, "AC-02 temporary fixture cleanup failed closed");
  }
}

async function findDemoAdministrator(control: Pool, demo: Pool): Promise<string> {
  const memberships = await control.query<{ identity_id: string }>(
    "SELECT identity_id::text FROM tenant_memberships WHERE tenant_id=$1 AND status='active'",
    [DEMO_TENANT_ID],
  );
  const administrators = await demo.query<{ identity_id: string }>(
    `SELECT binding.identity_id::text
       FROM role_bindings binding
       JOIN roles role ON role.id=binding.role_id
      WHERE role.code='CHURCH_ADMIN' AND binding.revoked_at IS NULL`,
  );
  const eligible = new Set(administrators.rows.map((row) => row.identity_id));
  const identityId = memberships.rows.find((row) => eligible.has(row.identity_id))?.identity_id;
  if (!identityId) throw new Error("Demo has no active tenant administrator suitable for AC-02");
  return identityId;
}

async function findFirstDemoMember(demo: Pool): Promise<MemberSnapshot> {
  const result = await demo.query<MemberSnapshot>(
    `SELECT id::text,version,available
       FROM members
      WHERE archived_at IS NULL
      ORDER BY created_at,id
      LIMIT 1`,
  );
  const member = result.rows[0];
  if (!member) throw new Error("Demo has no member fixture available for AC-02");
  return member;
}

async function insertSession(control: Pool, session: TestSession): Promise<void> {
  await control.query(
    `INSERT INTO auth_sessions(
       id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,user_agent_hash,ip_prefix_hash,
       assurance_level,mfa_verified_at,auth_method,aal,idle_timeout_minutes,idle_expires_at
     ) VALUES (
       $1,$2,$3,$4,$5,clock_timestamp() + interval '10 minutes',$6,$7,
       'mfa',clock_timestamp(),'totp',2,10,clock_timestamp() + interval '10 minutes'
     )`,
    [
      session.id,
      sha256(session.sessionToken),
      sha256(session.csrfToken),
      session.identityId,
      session.tenantId,
      sha256(USER_AGENT),
      sha256("127.0.0"),
    ],
  );
}

function temporarySession(id: string, identityId: string, tenantId: string): TestSession {
  return {
    id,
    identityId,
    tenantId,
    sessionToken: randomBytes(32).toString("base64url"),
    csrfToken: randomBytes(32).toString("base64url"),
  };
}

function temporaryEnvelope(tenantId: string, memberId: string): Readonly<Record<string, string>> {
  return {
    algorithm: "AES-256-GCM",
    keyId: "ac02-temporary-envelope-key",
    nonce: randomBytes(12).toString("base64url"),
    ciphertext: randomBytes(24).toString("base64url"),
    aad: Buffer.from(JSON.stringify({ tenantId, memberId, purpose: "member-display", schemaVersion: 1 })).toString("base64url"),
  };
}

function envelopeContentHash(envelope: Readonly<Record<string, string>>): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(envelope)).digest("hex")}`;
}

function actorPairs(fixture: Ac02Fixture): readonly ActorPair[] {
  return [
    {
      session: fixture.demoSession,
      otherSession: fixture.scratchSession,
      ownMemberId: fixture.demoMember.id,
      ownMemberVersion: fixture.demoMember.version,
      foreignMemberId: fixture.scratchMember.id,
      foreignMemberVersion: fixture.scratchMember.version,
      foreignTenantId: fixture.scratchTenantId,
    },
    {
      session: fixture.scratchSession,
      otherSession: fixture.demoSession,
      ownMemberId: fixture.scratchMember.id,
      ownMemberVersion: fixture.scratchMember.version,
      foreignMemberId: fixture.demoMember.id,
      foreignMemberVersion: fixture.demoMember.version,
      foreignTenantId: DEMO_TENANT_ID,
    },
  ];
}

async function patchMember(
  fixture: Ac02Fixture,
  session: TestSession,
  memberId: string,
  expectedVersion: number,
  overrides: RequestOptions = {},
): Promise<JsonResponse> {
  return requestJson(fixture, `/v1/members/${memberId}${querySuffix(overrides.queryTenantHint)}`, {
    ...overrides,
    method: "PATCH",
    session,
    payload: {
      expectedVersion,
      available: false,
      ...(overrides.bodyTenantHint ? { tenantId: overrides.bodyTenantHint } : {}),
    },
  });
}

async function requestJson(fixture: Ac02Fixture, route: string, options: RequestOptions = {}): Promise<JsonResponse> {
  const headers: Record<string, string> = {
    origin: ORIGIN,
    "user-agent": USER_AGENT,
    ...options.headers,
  };
  if (options.cookie) {
    headers["cookie"] = options.cookie;
  } else if (options.session) {
    const csrfCookie = options.csrfCookieOverride ?? options.session.csrfToken;
    headers["cookie"] = `nom_session=${options.session.sessionToken}; nom_csrf=${csrfCookie}`
      + (options.cookieTenantHint ? `; nom_tenant=${options.cookieTenantHint}` : "");
  }
  if (options.method === "PATCH") {
    if (!options.session) throw new Error("Authenticated PATCH requests require a session");
    headers["content-type"] = "application/json";
    headers["x-csrf-token"] = options.csrfHeaderOverride ?? options.session.csrfToken;
    const idempotencyKey = randomUUID();
    fixture.cleanup.idempotencyKeys.push(idempotencyKey);
    headers["idempotency-key"] = idempotencyKey;
  }
  const response = await fetch(fixture.baseUrl + route, {
    method: options.method ?? "GET",
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

async function expectPristineMembers(fixture: Ac02Fixture): Promise<void> {
  const [demo, scratch, demoArtifacts, scratchArtifacts] = await Promise.all([
    memberSnapshot(fixture.demo, fixture.demoMember.id),
    memberSnapshot(fixture.scratch, fixture.scratchMember.id),
    fixture.demo.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM idempotency_records WHERE idempotency_key = ANY($1::uuid[]))
         + (SELECT count(*) FROM audit_events WHERE actor_identity_id=$2)
       )::int AS count`,
      [fixture.cleanup.idempotencyKeys, fixture.scratchSession.identityId],
    ),
    fixture.scratch.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM idempotency_records WHERE idempotency_key = ANY($1::uuid[]))
         + (SELECT count(*) FROM outbox_events WHERE aggregate_id=$2)
         + (SELECT count(*) FROM audit_events WHERE actor_identity_id=$3 OR entity_id=$2::text)
       )::int AS count`,
      [fixture.cleanup.idempotencyKeys, fixture.scratchMember.id, fixture.demoSession.identityId],
    ),
  ]);
  expect(isSameMemberState(demo, fixture.demoMember)).toBe(true);
  expect(isSameMemberState(scratch, fixture.scratchMember)).toBe(true);
  expect(demoArtifacts.rows[0]?.count === 0).toBe(true);
  expect(scratchArtifacts.rows[0]?.count === 0).toBe(true);
}

async function memberSnapshot(pool: Pool, memberId: string): Promise<MemberSnapshot | undefined> {
  const result = await pool.query<MemberSnapshot>(
    "SELECT id::text,version,available FROM members WHERE id=$1",
    [memberId],
  );
  return result.rows[0];
}

function isSameMemberState(actual: MemberSnapshot | undefined, expected: MemberSnapshot): boolean {
  return Boolean(
    actual
    && actual.id === expected.id
    && actual.version === expected.version
    && actual.available === expected.available,
  );
}

function containsOnlyExpectedFirstMember(body: unknown, ownMemberId: string, foreignMemberId: string): boolean {
  const items = apiDataRecord(body)?.["items"];
  if (!Array.isArray(items) || items.length !== 1) return false;
  const first = items[0];
  return Boolean(
    first
    && typeof first === "object"
    && "id" in first
    && first.id === ownMemberId
    && first.id !== foreignMemberId,
  );
}

function sessionTenantId(body: unknown): unknown {
  const tenant = apiDataRecord(body)?.["tenant"];
  return tenant && typeof tenant === "object" && "id" in tenant ? tenant.id : undefined;
}

function apiDataRecord(body: unknown): Record<string, unknown> | undefined {
  if (!body || typeof body !== "object" || !("data" in body)) return undefined;
  const data = body.data;
  return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : undefined;
}

function apiErrorCode(body: unknown): unknown {
  if (!body || typeof body !== "object" || !("error" in body)) return undefined;
  const error = body.error;
  return error && typeof error === "object" && "code" in error ? error.code : undefined;
}

function apiErrorMessage(body: unknown): unknown {
  if (!body || typeof body !== "object" || !("error" in body)) return undefined;
  const error = body.error;
  return error && typeof error === "object" && "message" in error ? error.message : undefined;
}

function samePublicError(left: JsonResponse, right: JsonResponse): boolean {
  return left.status === right.status
    && apiErrorCode(left.body) === apiErrorCode(right.body)
    && apiErrorMessage(left.body) === apiErrorMessage(right.body);
}

function memberListPath(tenantHint?: string): string {
  return `/v1/members?limit=1${tenantHint ? `&tenantId=${tenantHint}` : ""}`;
}

function querySuffix(tenantHint?: string): string {
  return tenantHint ? `?tenantId=${tenantHint}` : "";
}

function requireFixture(fixture: Ac02Fixture | undefined): Ac02Fixture {
  if (!fixture) throw new Error("AC-02 fixture is unavailable");
  return fixture;
}

async function assertTenantTarget(pool: Pool, tenantId: string, kind: "demo" | "real"): Promise<void> {
  const result = await pool.query<{ tenant_id: string; kind: string }>(
    "SELECT tenant_id::text,kind FROM tenant_settings WHERE singleton=true",
  );
  const row = result.rows[0];
  if (!row || row.tenant_id !== tenantId || row.kind !== kind) {
    throw new Error("AC-02 database target metadata does not match its control-plane tenant");
  }
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

async function canReachAc02Targets(databaseAdminUrl: string): Promise<boolean> {
  const pools: Pool[] = [];
  try {
    const control = new Pool({
      connectionString: databaseUrl(databaseAdminUrl, CONTROL_DATABASE),
      application_name: "nombramientos-ac02-prerequisite",
      connectionTimeoutMillis: 1_500,
      max: 1,
    });
    pools.push(control);
    const tenants = await control.query<TenantRecord>(
      `SELECT id::text,kind,status,database_name::text,runtime_secret_ref
         FROM tenants
        WHERE id = ANY($1::uuid[])`,
      [[DEMO_TENANT_ID, OZAMA_TENANT_ID]],
    );
    const demo = tenants.rows.find((row) => row.id === DEMO_TENANT_ID && row.kind === "demo");
    const ozama = tenants.rows.find((row) => row.id === OZAMA_TENANT_ID && row.kind === "real");
    if (!demo || demo.status !== "active" || !ozama || ozama.status !== "provisioning" || tenants.rowCount !== 2) return false;
    const demoPool = new Pool({ connectionString: databaseUrl(databaseAdminUrl, demo.database_name), connectionTimeoutMillis: 1_500, max: 1 });
    const ozamaPool = new Pool({ connectionString: databaseUrl(databaseAdminUrl, ozama.database_name), connectionTimeoutMillis: 1_500, max: 1 });
    pools.push(demoPool, ozamaPool);
    await Promise.all([
      assertTenantTarget(demoPool, DEMO_TENANT_ID, "demo"),
      assertTenantTarget(ozamaPool, OZAMA_TENANT_ID, "real"),
    ]);
    return true;
  } catch {
    return false;
  } finally {
    await closePoolOwnerAndConfirmDrained(
      pools.map((pool, index) => ({ pool, label: `AC-02 reachability pool ${index + 1}` })),
      async () => Promise.all(pools.map(async (pool) => pool.end())),
      "AC-02 reachability pool close",
    );
  }
}

async function assertCanonicalOzamaPendingAndEmpty(databaseAdminUrl: string, control: Pool): Promise<void> {
  const state = await control.query<{
    status: string; provisioning_state: string; database_name: string;
    invitations: number; memberships: number;
  }>(
    `SELECT tenant.status,job.state AS provisioning_state,tenant.database_name::text,
            (SELECT count(*)::int FROM tenant_invitations invitation WHERE invitation.tenant_id=tenant.id) AS invitations,
            (SELECT count(*)::int FROM tenant_memberships membership WHERE membership.tenant_id=tenant.id) AS memberships
       FROM tenants tenant
       JOIN provisioning_jobs job ON job.tenant_id=tenant.id
      WHERE tenant.id=$1`,
    [OZAMA_TENANT_ID],
  );
  const current = state.rows[0];
  if (!current
    || current.status !== "provisioning"
    || current.provisioning_state !== "pending_activation"
    || current.invitations !== 0
    || current.memberships !== 0) {
    throw new Error("Canonical Ozama control state is not untouched and pending activation");
  }
  const ozama = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, current.database_name),
    application_name: "nombramientos-ac02-ozama-readonly-guard",
    max: 1,
  });
  try {
    const operational = await ozama.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM members)
         + (SELECT count(*) FROM role_bindings)
         + (SELECT count(*) FROM election_cycles)
         + (SELECT count(*) FROM committee_memberships)
         + (SELECT count(*) FROM rounds)
         + (SELECT count(*) FROM encrypted_submissions)
         + (SELECT count(*) FROM assignments)
         + (SELECT count(*) FROM report_versions)
         + (SELECT count(*) FROM idempotency_records)
         + (SELECT count(*) FROM outbox_events)
         + (SELECT count(*) FROM audit_events)
       )::int AS count`,
    );
    if (operational.rows[0]?.count !== 0) {
      throw new Error("Canonical Ozama gained operational rows during AC-02");
    }
  } finally {
    await endPoolAndConfirmDrained(ozama, "AC-02 Ozama attestation pool");
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(databaseName)) {
    throw new Error("Refusing an invalid local PostgreSQL database name");
  }
  const value = new URL(databaseAdminUrl);
  value.pathname = `/${databaseName}`;
  return value.toString();
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
