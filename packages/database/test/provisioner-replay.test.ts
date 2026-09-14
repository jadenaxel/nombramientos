import type { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import { tenantProvisionRequestHash } from "../src/control-store.js";
import { TenantProvisioner } from "../src/provisioner.js";
import type { TenantProvisionRequest, WritableSecretProvider } from "../src/types.js";

const request = {
  idempotencyKey: "40000000-0000-4000-8000-000000000001",
  tenantId: "40000000-0000-4000-8000-000000000002",
  slug: "tenant-replay-safe",
  displayName: "Original bootstrap name",
  kind: "real",
  timezone: "America/La_Paz",
  locale: "es",
} as const satisfies TenantProvisionRequest;

const suffix = request.tenantId.replaceAll("-", "");

describe("terminal tenant provisioning replay", () => {
  it.each(["active", "suspended", "decommission_pending"] as const)(
    "preserves an existing %s tenant without opening its database, secrets, or write paths",
    async (tenantStatus) => {
      const query = vi.fn(async (sql: string) => {
        if (sql.includes("FROM provisioning_jobs")) {
          return result([{
            id: "40000000-0000-4000-8000-000000000003",
            idempotency_key: request.idempotencyKey,
            tenant_id: request.tenantId,
            requested_slug: request.slug,
            request_hash: tenantProvisionRequestHash(request),
            state: "active",
          }]);
        }
        if (sql.includes("FROM tenants")) {
          return result([{
            id: request.tenantId,
            slug: request.slug,
            kind: request.kind,
            status: tenantStatus,
            database_host: "127.0.0.1",
            database_port: 55_432,
            database_name: `nom_t_${suffix}`,
            runtime_role: `nom_r_${suffix}`,
            runtime_secret_ref: `tenant-db/${request.tenantId}/runtime/v1`,
            credential_version: 1,
          }]);
        }
        throw new Error(`Unexpected control query: ${sql}`);
      });
      const secrets = unreachableSecrets();
      const provisioner = createProvisioner(query, secrets);
      try {
        await expect(provisioner.provision(request)).resolves.toEqual({
          tenantId: request.tenantId,
          database: `nom_t_${suffix}`,
          runtimeRole: `nom_r_${suffix}`,
          secretReference: `tenant-db/${request.tenantId}/runtime/v1`,
          tenantStatus,
          state: "active",
          reused: true,
        });
      } finally {
        await provisioner.close();
      }

      expect(query).toHaveBeenCalledTimes(2);
      for (const [sql] of query.mock.calls) expect(sql.trimStart()).toMatch(/^SELECT\b/u);
      expect(secrets.hasSecret).not.toHaveBeenCalled();
      expect(secrets.getSecret).not.toHaveBeenCalled();
      expect(secrets.putSecret).not.toHaveBeenCalled();
    },
  );

  it("keeps a pending-activation tenant pending on bootstrap replay", async () => {
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("FROM provisioning_jobs")) {
        return result([{
          id: "40000000-0000-4000-8000-000000000003",
          idempotency_key: request.idempotencyKey,
          tenant_id: request.tenantId,
          requested_slug: request.slug,
          request_hash: tenantProvisionRequestHash(request),
          state: "pending_activation",
        }]);
      }
      if (sql.includes("FROM tenants")) {
        return result([{
          id: request.tenantId,
          slug: request.slug,
          kind: request.kind,
          status: "provisioning",
          database_host: "127.0.0.1",
          database_port: 55_432,
          database_name: `nom_t_${suffix}`,
          runtime_role: `nom_r_${suffix}`,
          runtime_secret_ref: `tenant-db/${request.tenantId}/runtime/v1`,
          credential_version: 1,
        }]);
      }
      throw new Error(`Unexpected control query: ${sql}`);
    });
    const provisioner = createProvisioner(query, unreachableSecrets());
    try {
      await expect(provisioner.provision(request)).resolves.toMatchObject({
        state: "pending_activation",
        reused: true,
      });
    } finally {
      await provisioner.close();
    }
    expect(query).toHaveBeenCalledTimes(2);
  });

  it("preserves a rotated credential route and reports its current reference", async () => {
    const query = vi.fn(async (sql: string) => sql.includes("FROM provisioning_jobs")
      ? result([{
          id: "40000000-0000-4000-8000-000000000003",
          idempotency_key: request.idempotencyKey,
          tenant_id: request.tenantId,
          requested_slug: request.slug,
          request_hash: tenantProvisionRequestHash(request),
          state: "active",
        }])
      : result([{
          id: request.tenantId,
          slug: request.slug,
          kind: request.kind,
          status: "suspended",
          database_host: "127.0.0.1",
          database_port: 55_432,
          database_name: `nom_t_${suffix}`,
          runtime_role: `nom_r_${suffix}`,
          runtime_secret_ref: `tenant-db/${request.tenantId}/runtime/v7`,
          credential_version: 7,
        }]));
    const provisioner = createProvisioner(query, unreachableSecrets());
    try {
      await expect(provisioner.provision(request)).resolves.toMatchObject({
        secretReference: `tenant-db/${request.tenantId}/runtime/v7`,
        state: "active",
        reused: true,
      });
    } finally {
      await provisioner.close();
    }
  });

  it("fails closed on a terminal idempotency mismatch without changing the job", async () => {
    const query = vi.fn(async (_sql: string) => result([{
      id: "40000000-0000-4000-8000-000000000003",
      idempotency_key: request.idempotencyKey,
      tenant_id: request.tenantId,
      requested_slug: request.slug,
      request_hash: "0".repeat(64),
      state: "active",
    }]));
    const secrets = unreachableSecrets();
    const provisioner = createProvisioner(query, secrets);
    try {
      await expect(provisioner.provision(request)).rejects.toThrow(/reused with different input/u);
    } finally {
      await provisioner.close();
    }
    expect(query).toHaveBeenCalledTimes(1);
    expect(query.mock.calls[0]?.[0]?.trimStart()).toMatch(/^SELECT\b/u);
    expect(secrets.hasSecret).not.toHaveBeenCalled();
  });
});

function createProvisioner(
  query: ReturnType<typeof vi.fn>,
  secrets: WritableSecretProvider,
): TenantProvisioner {
  return new TenantProvisioner({
    admin: {
      host: "127.0.0.1",
      port: 55_432,
      user: "unused",
      password: "unused",
      database: "postgres",
      ssl: false,
    },
    catalog: { version: "test", departments: [], offices: [] },
    control: { query } as unknown as Pool,
    secrets,
  });
}

function unreachableSecrets(): WritableSecretProvider & {
  hasSecret: ReturnType<typeof vi.fn>;
  getSecret: ReturnType<typeof vi.fn>;
  putSecret: ReturnType<typeof vi.fn>;
} {
  return {
    hasSecret: vi.fn(async () => { throw new Error("secret access is forbidden on terminal replay"); }),
    getSecret: vi.fn(async () => { throw new Error("secret access is forbidden on terminal replay"); }),
    putSecret: vi.fn(async () => { throw new Error("secret access is forbidden on terminal replay"); }),
  };
}

function result<T>(rows: readonly T[]): { readonly rows: readonly T[]; readonly rowCount: number } {
  return { rows, rowCount: rows.length };
}
