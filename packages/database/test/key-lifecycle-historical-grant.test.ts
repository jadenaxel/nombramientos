import type { PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";

import { KeyLifecycleStore } from "../src/key-lifecycle-store.js";

const actorIdentityId = "11111111-1111-4111-8111-111111111111";
const actorDeviceId = "11111111-1111-4111-8111-111111111112";
const targetIdentityId = "22222222-2222-4222-8222-222222222221";
const targetDeviceId = "22222222-2222-4222-8222-222222222222";
const retiredGenerationId = "33333333-3333-4333-8333-333333333331";
const retiredTenantKeyId = "33333333-3333-4333-8333-333333333332";
const currentGenerationId = "44444444-4444-4444-8444-444444444441";
const currentTenantKeyId = "44444444-4444-4444-8444-444444444442";
const sessionId = "55555555-5555-4555-8555-555555555551";
const challengeId = "55555555-5555-4555-8555-555555555552";
const idempotencyKey = "55555555-5555-4555-8555-555555555553";
const requestHash = `sha256:${"a".repeat(64)}` as const;
const targetFingerprint = `sha256:${"b".repeat(64)}` as const;
const envelopeHash = `sha256:${"c".repeat(64)}` as const;

describe("historical tenant-key grant delegation", () => {
  it("locks exact retired authority and current target authority, persists retired, and replays exactly", async () => {
    const fixture = lifecycleFixture();
    const input = historicalInput();

    const first = await fixture.store.approveGrant(input);
    expect(first).toMatchObject({
      tenantKeyId: retiredTenantKeyId,
      generation: 1,
      identityId: targetIdentityId,
      deviceId: targetDeviceId,
      status: "retired",
    });
    expect(first.retiredAt).not.toBeNull();

    const actorGuard = fixture.query.mock.calls.find(([sql]) => String(sql).includes("key_grant.status=$3"));
    expect(actorGuard?.[1]).toEqual([retiredGenerationId, actorIdentityId, "retired", actorDeviceId]);
    expect(String(actorGuard?.[0])).toMatch(/FOR SHARE OF key_grant,device/u);

    const targetGuard = fixture.query.mock.calls.find(([sql]) => String(sql).includes("requireTargetCurrentGrant")
      || String(sql).includes("WHERE generation.status='active'"));
    expect(targetGuard?.[1]).toEqual([targetIdentityId, targetDeviceId]);
    expect(String(targetGuard?.[0])).toMatch(/FOR SHARE OF generation,key_grant,device/u);

    const insertion = fixture.query.mock.calls.find(([sql]) => String(sql).includes("INSERT INTO e2ee_key_grants"));
    expect(insertion?.[1]?.[8]).toBe("retired");
    expect(String(insertion?.[0])).toMatch(/status,retired_at[\s\S]*CASE WHEN \$9='retired'/u);
    expect(fixture.query.mock.calls.some(([sql]) => String(sql).includes("SET status='active',activated_at"))).toBe(false);

    const lifecycleLocks = () => fixture.query.mock.calls.filter(([sql]) => String(sql).includes("e2ee_key_lifecycle_v1")).length;
    const locksBeforeReplay = lifecycleLocks();
    const replay = await fixture.store.approveGrant(input);
    expect(replay).toEqual(first);
    expect(lifecycleLocks()).toBe(locksBeforeReplay);
  });

  it.each([
    {
      name: "an actor without the exact retired grant",
      configure: (fixture: FixtureState) => { fixture.grants = fixture.grants.filter((grant) => grant.identityId !== actorIdentityId || grant.status !== "retired"); },
      expected: { statusCode: 403, code: "AUTHORIZED_ADMIN_GRANT_REQUIRED" },
    },
    {
      name: "an actor whose historical device was revoked",
      configure: (fixture: FixtureState) => { fixture.devices.get(actorDeviceId)!.status = "revoked"; },
      expected: { code: "DEVICE_SESSION_REVOKED" },
    },
    {
      name: "an active target without a current-generation grant",
      configure: (fixture: FixtureState) => { fixture.grants = fixture.grants.filter((grant) => grant.generationId !== currentGenerationId || grant.identityId !== targetIdentityId); },
      expected: { statusCode: 409, code: "CURRENT_KEY_GRANT_REQUIRED" },
    },
    {
      name: "a target fingerprint that no longer matches",
      configure: () => undefined,
      mutate: (input: ReturnType<typeof historicalInput>) => ({ ...input, targetDeviceFingerprint: `sha256:${"d".repeat(64)}` as const }),
      expected: { statusCode: 409, code: "DEVICE_FINGERPRINT_MISMATCH" },
    },
  ])("rejects $name before inserting a historical envelope", async ({ configure, mutate, expected }) => {
    const fixture = lifecycleFixture();
    configure(fixture.state);
    await expect(fixture.store.approveGrant(mutate?.(historicalInput()) ?? historicalInput()))
      .rejects.toMatchObject(expected);
    expect(fixture.query.mock.calls.some(([sql]) => String(sql).includes("INSERT INTO e2ee_key_grants"))).toBe(false);
  });

  it("rejects lost, unknown, and mismatched generations without downgrade or fallback", async () => {
    const lost = lifecycleFixture();
    lost.state.generations.get(retiredTenantKeyId)!.status = "lost";
    await expect(lost.store.approveGrant(historicalInput())).rejects.toMatchObject({
      statusCode: 410,
      code: "TENANT_KEY_PERMANENTLY_LOST",
    });

    const unknown = lifecycleFixture();
    await expect(unknown.store.approveGrant({
      ...historicalInput(),
      tenantKeyId: "66666666-6666-4666-8666-666666666666",
    })).rejects.toMatchObject({ statusCode: 404, code: "KEY_GENERATION_NOT_FOUND" });

    const mismatched = lifecycleFixture();
    await expect(mismatched.store.approveGrant({ ...historicalInput(), generation: 2 }))
      .rejects.toMatchObject({ statusCode: 409, code: "KEY_GENERATION_CHANGED" });
    expect(mismatched.query.mock.calls.some(([sql]) => String(sql).includes("INSERT INTO e2ee_key_grants"))).toBe(false);
  });
});

function historicalInput() {
  return {
    actorIdentityId,
    sessionId,
    idempotencyKey,
    challengeId,
    requestHash,
    targetIdentityId,
    targetDeviceId,
    targetDeviceFingerprint: targetFingerprint,
    tenantKeyId: retiredTenantKeyId,
    generation: 1,
    envelope: { format: "opaque-test-envelope" },
    envelopeHash,
  } as const;
}

type GenerationState = {
  id: string;
  tenantKeyId: string;
  generation: number;
  status: "active" | "retired" | "lost";
};

type DeviceState = {
  deviceId: string;
  identityId: string;
  fingerprint: string;
  status: "pending" | "active" | "revoked";
};

type GrantState = {
  generationId: string;
  identityId: string;
  deviceId: string;
  status: "active" | "retired" | "revoked";
};

type FixtureState = {
  generations: Map<string, GenerationState>;
  devices: Map<string, DeviceState>;
  grants: GrantState[];
};

function lifecycleFixture(): FixtureState & {
  state: FixtureState;
  store: KeyLifecycleStore;
  query: ReturnType<typeof vi.fn>;
} {
  const state: FixtureState = {
    generations: new Map([
      [retiredTenantKeyId, { id: retiredGenerationId, tenantKeyId: retiredTenantKeyId, generation: 1, status: "retired" }],
      [currentTenantKeyId, { id: currentGenerationId, tenantKeyId: currentTenantKeyId, generation: 2, status: "active" }],
    ]),
    devices: new Map([
      [actorDeviceId, { deviceId: actorDeviceId, identityId: actorIdentityId, fingerprint: `sha256:${"e".repeat(64)}`, status: "active" }],
      [targetDeviceId, { deviceId: targetDeviceId, identityId: targetIdentityId, fingerprint: targetFingerprint, status: "active" }],
    ]),
    grants: [
      { generationId: retiredGenerationId, identityId: actorIdentityId, deviceId: actorDeviceId, status: "retired" },
      { generationId: currentGenerationId, identityId: actorIdentityId, deviceId: actorDeviceId, status: "active" },
      { generationId: currentGenerationId, identityId: targetIdentityId, deviceId: targetDeviceId, status: "active" },
    ],
  };
  const idempotency = new Map<string, { requestHash: string; response: unknown | null }>();
  let nextGrant = 1;

  const query = vi.fn(async (sqlValue: string, parametersValue?: readonly unknown[]) => {
    const sql = String(sqlValue);
    const parameters = parametersValue ?? [];
    if (sql.includes("current_setting('app.proven_device_id'")) return rows([{ device_id: actorDeviceId, session_id: sessionId }]);
    if (sql.startsWith("SELECT device_id FROM e2ee_key_devices")) {
      const device = state.devices.get(String(parameters[0]));
      return rows(device && device.identityId === parameters[1] && device.status !== "revoked" ? [{ device_id: device.deviceId }] : []);
    }
    if (sql.includes("SELECT binding.session_id FROM e2ee_http_session_bindings")) {
      const device = state.devices.get(actorDeviceId);
      const current = [...state.generations.values()].find((generation) => generation.status === "active");
      const grant = current && state.grants.some((entry) => entry.generationId === current.id && entry.identityId === actorIdentityId
        && entry.deviceId === actorDeviceId && entry.status === "active");
      return rows(parameters[0] === sessionId && parameters[1] === actorIdentityId && parameters[2] === actorDeviceId
        && device?.status === "active" && grant ? [{ session_id: sessionId }] : []);
    }
    if (sql.includes("INSERT INTO idempotency_records")) {
      const key = String(parameters[2]);
      if (idempotency.has(key)) return rows([]);
      idempotency.set(key, { requestHash: String(parameters[3]), response: null });
      return rows([{}]);
    }
    if (sql.includes("SELECT request_hash,response_body FROM idempotency_records")) {
      const record = idempotency.get(String(parameters[2]));
      return rows(record ? [{ request_hash: record.requestHash, response_body: record.response }] : []);
    }
    if (sql.includes("UPDATE idempotency_records SET response_status")) {
      const record = idempotency.get(String(parameters[2]));
      if (record) record.response = parameters[3];
      return rows([{}]);
    }
    if (sql.includes("UPDATE e2ee_key_challenges")) return rows([{}]);
    if (sql.includes("e2ee_key_lifecycle_v1")) return rows([{}]);
    if (sql.includes("FROM e2ee_key_generations") && sql.includes("WHERE tenant_key_id=$1")) {
      const generation = state.generations.get(String(parameters[0]));
      return rows(generation ? [generationRow(generation)] : []);
    }
    if (sql.includes("SELECT 1 FROM e2ee_key_grants key_grant")) {
      const [generationId, identityId, status, deviceId] = parameters.map(String);
      const match = state.grants.find((grant) => grant.generationId === generationId
        && grant.identityId === identityId
        && grant.deviceId === deviceId
        && grant.status === status
        && state.devices.get(grant.deviceId)?.status === "active");
      return rows(match ? [{}] : []);
    }
    if (sql.includes("FROM e2ee_key_devices") && sql.includes("FOR UPDATE")) {
      const device = state.devices.get(String(parameters[0]));
      if (!device || device.identityId !== parameters[1]) return rows([]);
      return rows([deviceRow(device)]);
    }
    if (sql.includes("WHERE generation.status='active'")) {
      const current = [...state.generations.values()].find((generation) => generation.status === "active");
      const match = current && state.grants.find((grant) => grant.generationId === current.id
        && grant.identityId === parameters[0]
        && grant.deviceId === parameters[1]
        && grant.status === "active"
        && state.devices.get(grant.deviceId)?.status === "active");
      return rows(match ? [{}] : []);
    }
    if (sql.includes("INSERT INTO e2ee_key_grants")) {
      const status = String(parameters[8]) as "active" | "retired";
      const retiredAt = status === "retired" ? new Date("2026-09-12T12:00:00.000Z") : null;
      return rows([{
        id: `77777777-7777-4777-8777-${String(nextGrant++).padStart(12, "0")}`,
        tenant_key_id: parameters[9],
        generation: parameters[10],
        identity_id: parameters[1],
        device_id: parameters[2],
        envelope: parameters[3],
        envelope_hash: parameters[4],
        grant_kind: parameters[5],
        status,
        version: 1,
        granted_by_identity_id: parameters[6],
        created_at: new Date("2026-09-12T12:00:00.000Z"),
        retired_at: retiredAt,
        revoked_at: null,
      }]);
    }
    if (sql.includes("INSERT INTO outbox_events")) return rows([{}]);
    if (sql.includes("tenant_audit_chain")) return rows([{}]);
    if (sql.includes("SELECT event_hash FROM audit_events")) return rows([]);
    if (sql.includes("current_setting('app.identity_id')")) {
      return rows([{ identity_id: actorIdentityId, request_id: "88888888-8888-4888-8888-888888888888" }]);
    }
    if (sql.includes("nextval(pg_get_serial_sequence")) {
      return rows([{ sequence: "1", id: "99999999-9999-4999-8999-999999999999", occurred_at: new Date("2026-09-12T12:00:00.000Z") }]);
    }
    if (sql.includes("INSERT INTO audit_events")) return rows([{}]);
    if (sql.includes("SET status='active',activated_at")) return rows([{}]);
    throw new Error(`Unexpected query: ${sql}`);
  });
  return Object.assign(state, { state, query, store: new KeyLifecycleStore({ query } as unknown as PoolClient) });
}

function generationRow(generation: GenerationState) {
  const retired = generation.status === "retired" ? new Date("2026-09-11T12:00:00.000Z") : null;
  const lost = generation.status === "lost" ? new Date("2026-09-11T12:00:00.000Z") : null;
  return {
    id: generation.id,
    tenant_key_id: generation.tenantKeyId,
    generation: generation.generation,
    status: generation.status,
    recovery_public_key: {},
    recovery_key_fingerprint: `sha256:${"f".repeat(64)}`,
    created_at: new Date("2026-09-10T12:00:00.000Z"),
    retired_at: retired,
    lost_at: lost,
  };
}

function deviceRow(device: DeviceState) {
  return {
    device_id: device.deviceId,
    identity_id: device.identityId,
    label: "Device",
    wrapping_public_key: {},
    wrapping_key_fingerprint: device.fingerprint,
    status: device.status,
    version: 1,
    registered_at: new Date("2026-09-10T12:00:00.000Z"),
    activated_at: device.status === "active" ? new Date("2026-09-10T12:00:00.000Z") : null,
    revoked_at: device.status === "revoked" ? new Date("2026-09-11T12:00:00.000Z") : null,
  };
}

function rows<T>(values: readonly T[]) {
  return { rows: values, rowCount: values.length };
}
