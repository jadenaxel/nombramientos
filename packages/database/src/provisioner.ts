import { randomBytes } from "node:crypto";
import path from "node:path";
import { Pool, type PoolConfig } from "pg";
import { z } from "zod";
import { initialAdminInvitationRequestHash, tenantProvisionRequestHash } from "./control-store.js";
import {
  reconcileTenantCatalog,
  type VersionedTenantCatalog,
} from "./catalog-reconciliation.js";
import { runMigrations } from "./migrations.js";
import { ensureInitialAdminActivationCapability } from "./initial-admin-capability.js";
import {
  TENANT_RUNTIME_APPEND_ONLY_TABLES,
  TENANT_RUNTIME_FUNCTIONS,
  TENANT_RUNTIME_GRANT_CONTRACT,
  TENANT_RUNTIME_MUTABLE_TABLES,
  TENANT_RUNTIME_READ_ONLY_TABLES,
  TENANT_RUNTIME_SEQUENCES,
  TENANT_SETTINGS_RUNTIME_UPDATE_COLUMNS,
} from "./runtime-grant-contract.js";
import { assertCanonicalTenantTableInventory } from "./tenant-maintenance-policy.js";
import {
  TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT,
  TENANT_OWNER_ROLE_SECURITY_CONTRACT,
  TENANT_RUNTIME_ROLE_SECURITY_CONTRACT,
} from "./tenant-security-target.js";
import type {
  TenantProvisionRequest,
  TenantProvisionResult,
  TenantStatus,
  WritableSecretProvider,
} from "./types.js";

const requestSchema = z.object({
  idempotencyKey: z.string().uuid(),
  tenantId: z.string().uuid(),
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),
  displayName: z.string().trim().min(2).max(160),
  kind: z.enum(["demo", "real"]),
  timezone: z.string().trim().min(1).max(80).refine(isValidIanaTimezone, "Timezone must be a recognized IANA identifier"),
  locale: z.enum(["es", "en", "fr"]),
  initialAdmin: z.discriminatedUnion("mode", [
    z.object({ mode: z.literal("pending") }).strict(),
    z.object({ mode: z.literal("demo_seed") }).strict(),
    z.object({
      mode: z.literal("invitation"),
      email: z.string().email().max(320),
      normalizedEmail: z.string().email().max(320),
      expiresInHours: z.number().int().min(1).max(168),
      expiresAt: z.string().datetime({ offset: true }),
      tokenHash: z.string().regex(/^[0-9a-f]{64}$/),
      createdByIdentityId: z.string().uuid(),
    }).strict(),
  ]).optional(),
});

export interface ProvisionerOptions {
  readonly admin: PoolConfig;
  readonly catalog: ProvisioningCatalog;
  readonly control: Pool;
  readonly secrets: WritableSecretProvider;
  readonly migrationsRoot?: string;
  readonly requireLoopback?: boolean;
}

/**
 * Structural catalog contract kept local to the persistence package. The
 * executable provisioning script supplies and validates the versioned
 * `@nombramientos/catalog` package, while API consumers do not acquire that
 * build-time package as an eager runtime dependency.
 */
export type ProvisioningCatalog = VersionedTenantCatalog;

interface ProvisioningJobRecord {
  readonly id: string;
  readonly idempotency_key: string;
  readonly tenant_id: string;
  readonly requested_slug: string;
  readonly request_hash: string;
  readonly state: string;
}

interface TenantRouteRecord {
  readonly id: string;
  readonly slug: string;
  readonly kind: "demo" | "real";
  readonly status: TenantStatus;
  readonly database_host: string;
  readonly database_port: number;
  readonly database_name: string;
  readonly runtime_role: string;
  readonly runtime_secret_ref: string;
  readonly credential_version: number;
}

export class TenantProvisioner {
  private readonly admin: Pool;
  private readonly migrationsRoot: string;

  public constructor(private readonly options: ProvisionerOptions) {
    if (options.requireLoopback !== false && !isLoopbackHost(options.admin.host)) {
      throw new Error("Local provisioner refuses a non-loopback PostgreSQL host");
    }
    this.admin = new Pool({ ...options.admin, application_name: "nombramientos-provisioner", max: 1 });
    this.migrationsRoot = options.migrationsRoot ?? path.resolve(process.cwd(), "migrations");
  }

  public async provision(rawRequest: TenantProvisionRequest): Promise<TenantProvisionResult> {
    const parsedRequest = requestSchema.parse(rawRequest);
    const { initialAdmin, ...baseRequest } = parsedRequest;
    const request: TenantProvisionRequest = initialAdmin === undefined
      ? baseRequest
      : { ...baseRequest, initialAdmin };
    const suffix = request.tenantId.replaceAll("-", "");
    const database = `nom_t_${suffix}`;
    const ownerRole = `nom_o_${suffix}`;
    const runtimeRole = `nom_r_${suffix}`;
    const secretReference = `tenant-db/${request.tenantId}/runtime/v1`;
    const activation = request.initialAdmin ?? { mode: request.kind === "demo" ? "demo_seed" as const : "pending" as const };
    const requestHash = tenantProvisionRequestHash(request);

    const initialJob = await this.findProvisioningJob(request);
    if (initialJob && isTerminalProvisioningState(initialJob.state)) {
      this.assertMatchingJob(initialJob, request, requestHash);
      return this.preservedTenantResult(initialJob, request, database, runtimeRole);
    }

    const lockClient = await this.admin.connect();
    let provisioningStarted = false;
    try {
      await lockClient.query("SELECT pg_advisory_lock(hashtextextended($1, 0))", [request.tenantId]);
      const job = await this.claimProvisioningJob(request, requestHash);
      if (isTerminalProvisioningState(job.state)) {
        return await this.preservedTenantResult(job, request, database, runtimeRole);
      }
      provisioningStarted = true;
      let runtimePassword: string;
      if (await this.options.secrets.hasSecret(secretReference)) {
        runtimePassword = await this.options.secrets.getSecret(secretReference);
      } else {
        runtimePassword = randomBytes(32).toString("base64url");
        await this.options.secrets.putSecret(secretReference, runtimePassword);
      }
      await ensureDeterministicTenantRole(lockClient, ownerRole, false);
      await ensureDeterministicTenantRole(lockClient, runtimeRole, true, runtimePassword);
      await this.setJobState(request.tenantId, "roles_created");

      const databaseExists = await lockClient.query<{
        owner: string;
        is_template: boolean;
        allow_connections: boolean;
        connection_limit: number;
        encoding: string;
        template_exists: boolean;
        collation_matches_template: boolean;
        character_type_matches_template: boolean;
        locale_provider_matches_template: boolean;
        locale_matches_template: boolean;
        icu_rules_match_template: boolean;
        collation_version_matches_template: boolean;
        has_login_event: boolean;
        tablespace: string;
      }>(
        `SELECT owner.rolname AS owner,database.datistemplate AS is_template,
                database.datallowconn AS allow_connections,database.datconnlimit AS connection_limit,
                pg_catalog.pg_encoding_to_char(database.encoding) AS encoding,
                template.oid IS NOT NULL AS template_exists,
                database.datcollate IS NOT DISTINCT FROM template.datcollate AS collation_matches_template,
                database.datctype IS NOT DISTINCT FROM template.datctype AS character_type_matches_template,
                database.datlocprovider IS NOT DISTINCT FROM template.datlocprovider AS locale_provider_matches_template,
                database.datlocale IS NOT DISTINCT FROM template.datlocale AS locale_matches_template,
                database.daticurules IS NOT DISTINCT FROM template.daticurules AS icu_rules_match_template,
                database.datcollversion IS NOT DISTINCT FROM template.datcollversion AS collation_version_matches_template,
                database.dathasloginevt AS has_login_event,
                tablespace.spcname AS tablespace
           FROM pg_catalog.pg_database database
           JOIN pg_catalog.pg_roles owner ON owner.oid=database.datdba
           JOIN pg_catalog.pg_tablespace tablespace ON tablespace.oid=database.dattablespace
           LEFT JOIN pg_catalog.pg_database template ON template.datname='template0'
          WHERE database.datname=$1`,
        [database],
      );
      if (databaseExists.rowCount === 0) {
        await executeFormatted(
          lockClient,
          "SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L TABLESPACE pg_default CONNECTION LIMIT -1', $1::text, $2::text, 'UTF8') AS sql",
          [database, ownerRole],
        );
      } else {
        const existingDatabase = databaseExists.rows[0];
        if (databaseExists.rowCount !== 1
          || existingDatabase?.owner !== ownerRole
          || existingDatabase.is_template
          || !existingDatabase.allow_connections
          || existingDatabase.connection_limit !== -1
          || existingDatabase.encoding !== "UTF8"
          || !existingDatabase.template_exists
          || !existingDatabase.collation_matches_template
          || !existingDatabase.character_type_matches_template
          || !existingDatabase.locale_provider_matches_template
          || !existingDatabase.locale_matches_template
          || !existingDatabase.icu_rules_match_template
          || !existingDatabase.collation_version_matches_template
          || existingDatabase.has_login_event
          || existingDatabase.tablespace !== "pg_default") {
          throw new Error("A deterministic tenant database failed ownership and safety attestation");
        }
      }
      await executeFormatted(lockClient, "SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', $1::text) AS sql", [database]);
      await executeFormatted(lockClient, "SELECT format('GRANT CONNECT ON DATABASE %I TO %I', $1::text, $2::text) AS sql", [database, runtimeRole]);
      await this.setJobState(request.tenantId, "database_created");

      const tenantPool = new Pool({
        ...this.options.admin,
        database,
        application_name: `nombramientos-migrate-${request.tenantId.slice(0, 8)}`,
        max: 1,
      });
      try {
        await assertAdoptableTenantDatabase(tenantPool, request.tenantId, request.kind, database);
        await runMigrations(tenantPool, {
          scope: "tenant",
          directory: path.join(this.migrationsRoot, "tenant"),
          executionRole: ownerRole,
        });
        await tenantPool.query(
          `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale)
           VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT(singleton) DO UPDATE SET
             tenant_id=EXCLUDED.tenant_id,
             display_name=EXCLUDED.display_name,
             kind=EXCLUDED.kind,
             timezone=EXCLUDED.timezone,
             locale=EXCLUDED.locale,
             updated_at=clock_timestamp()`,
          [request.tenantId, request.displayName, request.kind, request.timezone, request.locale],
        );
        await ensureInitialAdminActivationCapability(
          tenantPool,
          this.options.secrets,
          request.tenantId,
          request.kind,
        );
        await reconcileTenantCatalog(tenantPool, this.options.catalog);
        await reconcileTenantOwnershipAndRuntimeGrants(
          tenantPool,
          ownerRole,
          runtimeRole,
          async (tenantClient) => {
            await assertProvisionedTenantDatabase(
              tenantClient,
              request.tenantId,
              request.kind,
              database,
            );
            await assertCanonicalTenantTableInventory(tenantClient, request.tenantId);
          },
        );
      } finally {
        await tenantPool.end();
      }
      await this.setJobState(request.tenantId, "migrated");
      await this.setJobState(request.tenantId, "seeded");

      const adminHost = this.options.admin.host ?? "127.0.0.1";
      const adminPort = this.options.admin.port ?? 5432;
      const controlClient = await this.options.control.connect();
      let finalState: "active" | "pending_activation" = "active";
      let finalTenantStatus: TenantStatus = "active";
      try {
        await controlClient.query("BEGIN");
        const tenant = await controlClient.query<{ version: number; status: string }>(
          `INSERT INTO tenants(
             id,slug,display_name,kind,status,timezone,locale,database_host,database_port,
             database_name,runtime_role,runtime_secret_ref,credential_version,ssl_mode,activated_at
           ) VALUES ($1,$2,$3,$4,'provisioning',$5,$6,$7,$8,$9,$10,$11,1,$12,NULL)
           ON CONFLICT(id) DO UPDATE SET
             display_name=EXCLUDED.display_name,
             timezone=EXCLUDED.timezone,
             locale=EXCLUDED.locale,
             updated_at=clock_timestamp()
           RETURNING version,status`,
          [
            request.tenantId,
            request.slug,
            request.displayName,
            request.kind,
            request.timezone,
            request.locale,
            adminHost,
            adminPort,
            database,
            runtimeRole,
            secretReference,
            sslModeFromConfig(this.options.admin),
          ],
        );
        const tenantState = tenant.rows[0];
        if (!tenantState) throw new Error("Provisioned tenant route was not returned");

        if (activation.mode === "demo_seed") {
          await controlClient.query(
            `UPDATE tenants SET
               status='active',activated_at=COALESCE(activated_at,clock_timestamp()),
               version=CASE WHEN status='active' THEN version ELSE version+1 END,
               updated_at=clock_timestamp()
             WHERE id=$1`,
            [request.tenantId],
          );
          await controlClient.query(
            `UPDATE provisioning_jobs SET state='active',updated_at=clock_timestamp(),completed_at=clock_timestamp(),last_error_code=NULL
              WHERE tenant_id=$1`,
            [request.tenantId],
          );
        } else if (activation.mode === "invitation") {
          const invitationHash = initialAdminInvitationRequestHash({
            tenantId: request.tenantId,
            normalizedEmail: activation.normalizedEmail,
            expiresInHours: activation.expiresInHours,
          });
          const activated = await controlClient.query(
            `SELECT * FROM activate_platform_tenant_initial_admin(
               $1,$2,$3,$4,$5,$6,$7,$8,$9
             )`,
            [
              request.tenantId,
              tenantState.version,
              activation.email,
              activation.normalizedEmail,
              activation.tokenHash,
              activation.expiresAt,
              request.idempotencyKey,
              invitationHash,
              activation.createdByIdentityId,
            ],
          );
          if (activated.rowCount !== 1) throw new Error("Initial administrator invitation was not activated");
        } else {
          finalState = "pending_activation";
          finalTenantStatus = "provisioning";
          await controlClient.query(
            `UPDATE provisioning_jobs SET state='pending_activation',updated_at=clock_timestamp(),completed_at=NULL,last_error_code=NULL
              WHERE tenant_id=$1`,
            [request.tenantId],
          );
        }
        await controlClient.query("COMMIT");
      } catch (error) {
        await controlClient.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        controlClient.release();
      }
      return {
        tenantId: request.tenantId,
        database,
        runtimeRole,
        secretReference,
        tenantStatus: finalTenantStatus,
        state: finalState,
        reused: false,
      };
    } catch (error) {
      if (provisioningStarted) {
        await this.options.control.query(
          `UPDATE provisioning_jobs SET state='failed',updated_at=clock_timestamp(),last_error_code=$2
            WHERE tenant_id=$1 AND state NOT IN ('active','pending_activation')`,
          [request.tenantId, safeErrorCode(error)],
        ).catch(() => undefined);
      }
      throw error;
    } finally {
      await lockClient.query("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [request.tenantId]).catch(() => undefined);
      lockClient.release();
    }
  }

  public async close(): Promise<void> {
    await this.admin.end();
  }

  private async setJobState(tenantId: string, state: string): Promise<void> {
    await this.options.control.query(
      "UPDATE provisioning_jobs SET state=$2,updated_at=clock_timestamp(),last_error_code=NULL WHERE tenant_id=$1",
      [tenantId, state],
    );
  }

  private async findProvisioningJob(request: TenantProvisionRequest): Promise<ProvisioningJobRecord | null> {
    const result = await this.options.control.query<ProvisioningJobRecord>(
      `SELECT id::text,idempotency_key::text,tenant_id::text,requested_slug,request_hash,state
         FROM provisioning_jobs
        WHERE idempotency_key=$1 OR tenant_id=$2
        ORDER BY (idempotency_key=$1) DESC,id
        LIMIT 2`,
      [request.idempotencyKey, request.tenantId],
    );
    if (result.rows.length > 1) {
      throw new Error("Provisioning idempotency key and tenant id resolve to different jobs");
    }
    return result.rows[0] ?? null;
  }

  private assertMatchingJob(
    job: ProvisioningJobRecord,
    request: TenantProvisionRequest,
    requestHash: string,
  ): void {
    if (
      job.idempotency_key !== request.idempotencyKey
      || job.tenant_id !== request.tenantId
      || job.requested_slug !== request.slug
      || job.request_hash !== requestHash
    ) {
      throw new Error("Provisioning idempotency key or tenant id was reused with different input");
    }
  }

  private async claimProvisioningJob(
    request: TenantProvisionRequest,
    requestHash: string,
  ): Promise<ProvisioningJobRecord> {
    let job = await this.findProvisioningJob(request);
    if (job) {
      this.assertMatchingJob(job, request, requestHash);
      if (isTerminalProvisioningState(job.state)) return job;
      await this.assertTenantRouteAbsent(request);
      const updated = await this.options.control.query<ProvisioningJobRecord>(
        `UPDATE provisioning_jobs
            SET attempt_count=attempt_count+1,updated_at=clock_timestamp()
          WHERE id=$1 AND state NOT IN ('active','pending_activation')
          RETURNING id::text,idempotency_key::text,tenant_id::text,requested_slug,request_hash,state`,
        [job.id],
      );
      job = updated.rows[0] ?? await this.findProvisioningJob(request);
      if (!job) throw new Error("Provisioning job disappeared while it was being claimed");
      this.assertMatchingJob(job, request, requestHash);
      return job;
    }

    await this.assertTenantRouteAbsent(request);
    const inserted = await this.options.control.query<ProvisioningJobRecord>(
      `INSERT INTO provisioning_jobs(
         idempotency_key,tenant_id,requested_slug,request_hash,state,attempt_count
       ) VALUES ($1,$2,$3,$4,'requested',1)
       ON CONFLICT DO NOTHING
       RETURNING id::text,idempotency_key::text,tenant_id::text,requested_slug,request_hash,state`,
      [request.idempotencyKey, request.tenantId, request.slug, requestHash],
    );
    job = inserted.rows[0] ?? await this.findProvisioningJob(request);
    if (!job) throw new Error("Provisioning job could not be created or recovered");
    this.assertMatchingJob(job, request, requestHash);
    return job;
  }

  private async assertTenantRouteAbsent(request: TenantProvisionRequest): Promise<void> {
    const existingTenant = await this.options.control.query<{ id: string }>(
      "SELECT id::text FROM tenants WHERE id=$1 OR slug=$2 LIMIT 1",
      [request.tenantId, request.slug],
    );
    if (existingTenant.rowCount !== 0) {
      throw new Error("Existing tenant routes cannot be repaired or reprovisioned implicitly");
    }
  }

  private async preservedTenantResult(
    job: ProvisioningJobRecord,
    request: TenantProvisionRequest,
    database: string,
    runtimeRole: string,
  ): Promise<TenantProvisionResult> {
    if (!isTerminalProvisioningState(job.state)) {
      throw new Error("Only terminal provisioning jobs can be preserved as idempotent replays");
    }
    const route = await this.options.control.query<TenantRouteRecord>(
      `SELECT id::text,slug,kind,status,database_host,database_port,database_name::text,
              runtime_role::text,runtime_secret_ref,credential_version
         FROM tenants
        WHERE id=$1`,
      [request.tenantId],
    );
    const tenant = route.rows[0];
    if (
      !tenant
      || tenant.id !== request.tenantId
      || tenant.slug !== request.slug
      || tenant.kind !== request.kind
      || tenant.database_name !== database
      || tenant.runtime_role !== runtimeRole
      || tenant.runtime_secret_ref !== `tenant-db/${request.tenantId}/runtime/v${tenant.credential_version}`
      || (this.options.requireLoopback !== false && (
        tenant.database_host !== (this.options.admin.host ?? "127.0.0.1")
        || tenant.database_port !== (this.options.admin.port ?? 5432)
      ))
    ) {
      throw new Error("Existing tenant route does not match its immutable provisioning identity");
    }
    return {
      tenantId: request.tenantId,
      database: tenant.database_name,
      runtimeRole: tenant.runtime_role,
      secretReference: tenant.runtime_secret_ref,
      tenantStatus: tenant.status,
      state: job.state,
      reused: true,
    };
  }
}

function isTerminalProvisioningState(state: string): state is TenantProvisionResult["state"] {
  return state === "active" || state === "pending_activation";
}

async function assertAdoptableTenantDatabase(
  pool: Pool,
  tenantId: string,
  kind: "demo" | "real",
  database: string,
): Promise<void> {
  const inventory = await pool.query<{ settings_exists: boolean }>(
    "SELECT to_regclass('public.tenant_settings') IS NOT NULL AS settings_exists",
  );
  if (!inventory.rows[0]?.settings_exists) return;
  const identity = await pool.query<{ tenant_id: string; kind: string; database_name: string }>(
    `SELECT tenant_id::text,kind,current_database() AS database_name
       FROM tenant_settings WHERE singleton=true`,
  );
  if (identity.rowCount === 0) return;
  const row = identity.rows[0];
  if (identity.rowCount !== 1
    || row?.tenant_id !== tenantId
    || row.kind !== kind
    || row.database_name !== database) {
    throw new Error("A preexisting tenant database failed tenant identity attestation");
  }
}

async function assertProvisionedTenantDatabase(
  client: Pick<import("pg").PoolClient, "query">,
  tenantId: string,
  kind: "demo" | "real",
  database: string,
): Promise<void> {
  const identity = await client.query<{ tenant_id: string; kind: string; database_name: string }>(
    `SELECT tenant_id::text,kind,current_database() AS database_name
       FROM tenant_settings WHERE singleton=true`,
  );
  const row = identity.rows[0];
  if (identity.rowCount !== 1
    || row?.tenant_id !== tenantId
    || row.kind !== kind
    || row.database_name !== database) {
    throw new Error("A provisioned tenant database failed exact tenant identity attestation");
  }
}

async function ensureDeterministicTenantRole(
  client: import("pg").PoolClient,
  role: string,
  login: boolean,
  password?: string,
): Promise<void> {
  const rolePattern = login ? /^nom_r_[0-9a-f]{32}$/u : /^nom_o_[0-9a-f]{32}$/u;
  if (!rolePattern.test(role) || (login && !password)) {
    throw new Error("Tenant role attestation requires an exact deterministic role contract");
  }
  const existing = await readTenantRoleAttestation(client, role);
  if (existing && existing.membership_count !== 0) {
    throw new Error("A deterministic tenant role has unexpected role memberships");
  }
  if (!existing) {
    const template = login
      ? "SELECT format('CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD %L', $1::text, $2::text) AS sql"
      : "SELECT format('CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 PASSWORD NULL', $1::text) AS sql";
    await executeFormatted(client, template, login ? [role, password] : [role]);
  } else {
    const template = login
      ? "SELECT format('ALTER ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL %L PASSWORD %L', $1::text, 'infinity', $2::text) AS sql"
      : "SELECT format('ALTER ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL %L PASSWORD NULL', $1::text, 'infinity') AS sql";
    await executeFormatted(client, template, login ? [role, password] : [role]);
  }
  await executeFormatted(client, "SELECT format('ALTER ROLE %I RESET ALL', $1::text) AS sql", [role]);
  const attested = await readTenantRoleAttestation(client, role);
  if (!attested || !tenantRoleMatchesExactContract(attested, login)) {
    throw new Error("A deterministic tenant role failed exact privilege attestation");
  }
}

interface TenantRoleAttestation {
  readonly can_login: boolean;
  readonly superuser: boolean;
  readonly create_database: boolean;
  readonly create_role: boolean;
  readonly replication: boolean;
  readonly bypass_rls: boolean;
  readonly inherit: boolean;
  readonly connection_limit: number;
  readonly has_password: boolean;
  readonly has_expiration: boolean;
  readonly configuration_count: number;
  readonly membership_count: number;
}

async function readTenantRoleAttestation(
  client: import("pg").PoolClient,
  role: string,
): Promise<TenantRoleAttestation | undefined> {
  const result = await client.query<TenantRoleAttestation>(
    `SELECT target.rolcanlogin AS can_login,target.rolsuper AS superuser,
            target.rolcreatedb AS create_database,target.rolcreaterole AS create_role,
            target.rolreplication AS replication,target.rolbypassrls AS bypass_rls,
            target.rolinherit AS inherit,target.rolconnlimit AS connection_limit,
            credential.rolpassword IS NOT NULL AS has_password,
            target.rolvaliduntil IS NOT NULL AND target.rolvaliduntil <> 'infinity'::timestamptz AS has_expiration,
            COALESCE(cardinality(target.rolconfig),0)::int AS configuration_count,
            (SELECT count(*)::int FROM pg_catalog.pg_auth_members membership
              WHERE membership.member=target.oid OR membership.roleid=target.oid) AS membership_count
       FROM pg_catalog.pg_roles target
       JOIN pg_catalog.pg_authid credential ON credential.oid=target.oid
      WHERE target.rolname=$1`,
    [role],
  );
  if (result.rows.length > 1) throw new Error("Deterministic tenant role identity is ambiguous");
  return result.rows[0];
}

function tenantRoleMatchesExactContract(
  attested: TenantRoleAttestation,
  login: boolean,
): boolean {
  const contract = login
    ? TENANT_RUNTIME_ROLE_SECURITY_CONTRACT
    : TENANT_OWNER_ROLE_SECURITY_CONTRACT;
  return attested.can_login === contract.canLogin
    && attested.superuser === contract.superuser
    && attested.create_database === contract.createDatabase
    && attested.create_role === contract.createRole
    && attested.replication === contract.replication
    && attested.bypass_rls === contract.bypassRls
    && attested.inherit === contract.inherit
    && attested.connection_limit === contract.connectionLimit
    && attested.has_password === contract.hasPassword
    && attested.has_expiration === contract.hasExpiration
    && attested.configuration_count === contract.configurationCount
    && attested.membership_count === contract.membershipCount;
}

async function normalizeOwnerRoleWithClient(
  client: import("pg").PoolClient,
  ownerRole: string,
): Promise<void> {
  const existing = await readTenantRoleAttestation(client, ownerRole);
  if (!existing) {
    throw new Error("Tenant object ownership requires an existing deterministic owner role");
  }
  if (existing.membership_count !== 0) {
    throw new Error("Tenant object ownership refuses an owner role with unexpected memberships");
  }
  await executeFormatted(
    client,
    "SELECT format('ALTER ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL %L PASSWORD NULL', $1::text, $2::text) AS sql",
    [ownerRole, "infinity"],
  );
  await executeFormatted(
    client,
    "SELECT format('ALTER ROLE %I RESET ALL', $1::text) AS sql",
    [ownerRole],
  );
  const attested = await readTenantRoleAttestation(client, ownerRole);
  if (!attested || !tenantRoleMatchesExactContract(attested, false)) {
    throw new Error("Tenant owner role failed exact non-login ownership attestation");
  }
}

async function normalizeRuntimeRoleWithClient(
  client: import("pg").PoolClient,
  runtimeRole: string,
): Promise<void> {
  const existing = await readTenantRoleAttestation(client, runtimeRole);
  if (!existing || !existing.has_password) {
    throw new Error("Tenant runtime grants require an existing password-authenticated runtime role");
  }
  if (existing.membership_count !== 0) {
    throw new Error("Tenant runtime grants refuse a runtime role with unexpected memberships");
  }
  await executeFormatted(
    client,
    "SELECT format('ALTER ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL %L', $1::text, $2::text) AS sql",
    [runtimeRole, "infinity"],
  );
  await executeFormatted(
    client,
    "SELECT format('ALTER ROLE %I RESET ALL', $1::text) AS sql",
    [runtimeRole],
  );
  const attested = await readTenantRoleAttestation(client, runtimeRole);
  if (!attested || !tenantRoleMatchesExactContract(attested, true)) {
    throw new Error("Tenant runtime role failed exact privilege attestation before grants");
  }
}

async function executeFormatted(
  client: import("pg").PoolClient,
  formatQuery: string,
  values: readonly unknown[],
): Promise<void> {
  const formatted = await client.query<{ sql: string }>(formatQuery, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the administrative statement");
  await client.query(sql);
}

export async function applyRuntimeGrants(pool: Pool, runtimeRole: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await applyRuntimeGrantsWithClient(client, runtimeRole);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function applyRuntimeGrantsWithClient(
  client: import("pg").PoolClient,
  runtimeRole: string,
): Promise<void> {
  if (!/^nom_r_[0-9a-f]{32}$/u.test(runtimeRole)) {
    throw new Error("Tenant runtime grants require a deterministic runtime role");
  }
  const databaseResult = await client.query<{ database_name: string }>(
    "SELECT current_database() AS database_name",
  );
  const databaseName = databaseResult.rows[0]?.database_name;
  if (databaseName !== runtimeRole.replace(/^nom_r_/u, "nom_t_")) {
    throw new Error("Tenant runtime role does not match the connected tenant database");
  }
  await normalizeRuntimeRoleWithClient(client, runtimeRole);
  await revokeExplicitTenantColumnPrivileges(client);
  await revokeForeignTenantPrivileges(client, runtimeRole, databaseName);
    await executeFormatted(
      client,
      "SELECT format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM PUBLIC', $1::text) AS sql",
      [databaseName],
    );
    await executeFormatted(
      client,
      "SELECT format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I', $1::text, $2::text) AS sql",
      [databaseName, runtimeRole],
    );
    if (TENANT_RUNTIME_GRANT_CONTRACT.database.runtime.length > 0) {
      await executeFormatted(
        client,
        `SELECT format('GRANT ${TENANT_RUNTIME_GRANT_CONTRACT.database.runtime.join(",")} ON DATABASE %I TO %I', $1::text, $2::text) AS sql`,
        [databaseName, runtimeRole],
      );
    }
    if (TENANT_RUNTIME_GRANT_CONTRACT.database.public.length > 0) {
      await executeFormatted(
        client,
        `SELECT format('GRANT ${TENANT_RUNTIME_GRANT_CONTRACT.database.public.join(",")} ON DATABASE %I TO PUBLIC', $1::text) AS sql`,
        [databaseName],
      );
    }
    await executeFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC') AS sql", []);
    await executeFormatted(
      client,
      "SELECT format('REVOKE ALL PRIVILEGES ON SCHEMA public FROM %I', $1::text) AS sql",
      [runtimeRole],
    );
    if (TENANT_RUNTIME_GRANT_CONTRACT.schema.runtime.length > 0) {
      await executeFormatted(
        client,
        `SELECT format('GRANT ${TENANT_RUNTIME_GRANT_CONTRACT.schema.runtime.join(",")} ON SCHEMA public TO %I', $1::text) AS sql`,
        [runtimeRole],
      );
    }
    if (TENANT_RUNTIME_GRANT_CONTRACT.schema.public.length > 0) {
      await executeFormatted(
        client,
        `SELECT format('GRANT ${TENANT_RUNTIME_GRANT_CONTRACT.schema.public.join(",")} ON SCHEMA public TO PUBLIC') AS sql`,
        [],
      );
    }
    await executeFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC') AS sql", []);
    await executeFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC') AS sql", []);
    await executeFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC') AS sql", []);
    await executeFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I', $1::text) AS sql", [runtimeRole]);
    await executeFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %I', $1::text) AS sql", [runtimeRole]);
    await executeFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM %I', $1::text) AS sql", [runtimeRole]);

    for (const table of TENANT_RUNTIME_READ_ONLY_TABLES) {
      await grantTablePrivileges(client, runtimeRole, table, "SELECT");
    }
    await executeFormatted(
      client,
      "SELECT format('GRANT UPDATE(%s) ON TABLE public.tenant_settings TO %I', $1::text, $2::text) AS sql",
      [TENANT_SETTINGS_RUNTIME_UPDATE_COLUMNS.join(","), runtimeRole],
    );
    for (const table of TENANT_RUNTIME_MUTABLE_TABLES) {
      await grantTablePrivileges(client, runtimeRole, table, "SELECT,INSERT,UPDATE");
    }
    for (const table of TENANT_RUNTIME_APPEND_ONLY_TABLES) {
      await grantTablePrivileges(client, runtimeRole, table, "SELECT,INSERT");
    }
    await executeFormatted(
      client,
      "SELECT format('GRANT USAGE,SELECT ON SEQUENCE %s TO %I', $1::text, $2::text) AS sql",
      [TENANT_RUNTIME_SEQUENCES.map((sequence) => `public.${sequence}`).join(","), runtimeRole],
    );
    for (const signature of TENANT_RUNTIME_FUNCTIONS) {
      await executeFormatted(
        client,
        "SELECT format('GRANT EXECUTE ON FUNCTION public.%s TO %I', $1::text, $2::text) AS sql",
        [signature, runtimeRole],
      );
    }
}

interface ExplicitTenantColumnPrivilege {
  readonly table_name: string;
  readonly column_name: string;
  readonly privilege_type: "SELECT" | "INSERT" | "UPDATE" | "REFERENCES";
  readonly grantee: string;
}

async function revokeExplicitTenantColumnPrivileges(
  client: import("pg").PoolClient,
): Promise<void> {
  const read = async (): Promise<readonly ExplicitTenantColumnPrivilege[]> => {
    const result = await client.query<ExplicitTenantColumnPrivilege>(
      `SELECT relation.relname AS table_name,column_record.attname AS column_name,
              acl.privilege_type::text AS privilege_type,
              COALESCE(grantee.rolname,'PUBLIC') AS grantee
         FROM pg_catalog.pg_attribute column_record
         JOIN pg_catalog.pg_class relation ON relation.oid=column_record.attrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         CROSS JOIN LATERAL pg_catalog.aclexplode(column_record.attacl) acl
         LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        WHERE namespace.nspname='public' AND relation.relkind IN ('r','p','v','m','f')
          AND column_record.attnum>0 AND NOT column_record.attisdropped
          AND column_record.attacl IS NOT NULL
        ORDER BY relation.relname,column_record.attnum,acl.privilege_type,acl.grantee`,
    );
    return result.rows;
  };
  const allowed = new Set(["SELECT", "INSERT", "UPDATE", "REFERENCES"]);
  for (const grant of await read()) {
    if (!allowed.has(grant.privilege_type)) {
      throw new Error("Unsupported explicit tenant column privilege");
    }
    if (grant.grantee === "PUBLIC") {
      await executeFormatted(
        client,
        `SELECT format('REVOKE ${grant.privilege_type} (%I) ON TABLE public.%I FROM PUBLIC CASCADE', $1::text, $2::text) AS sql`,
        [grant.column_name, grant.table_name],
      );
    } else {
      await executeFormatted(
        client,
        `SELECT format('REVOKE ${grant.privilege_type} (%I) ON TABLE public.%I FROM %I CASCADE', $1::text, $2::text, $3::text) AS sql`,
        [grant.column_name, grant.table_name, grant.grantee],
      );
    }
  }
  if ((await read()).length !== 0) {
    throw new Error("Explicit tenant column privileges remain after reconciliation");
  }
}

async function revokeForeignTenantPrivileges(
  client: import("pg").PoolClient,
  runtimeRole: string,
  databaseName: string,
): Promise<void> {
  const foreignGrants = await readForeignTenantPrivileges(client, runtimeRole);
  for (const grant of foreignGrants) {
    if (grant.object_kind === "database") {
      await executeFormatted(
        client,
        "SELECT format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I CASCADE', $1::text, $2::text) AS sql",
        [databaseName, grant.role_name],
      );
    } else if (grant.object_kind === "schema") {
      await executeFormatted(
        client,
        "SELECT format('REVOKE ALL PRIVILEGES ON SCHEMA public FROM %I CASCADE', $1::text) AS sql",
        [grant.role_name],
      );
    } else if (grant.object_kind === "table") {
      await executeFormatted(
        client,
        "SELECT format('REVOKE ALL PRIVILEGES ON TABLE public.%I FROM %I CASCADE', $1::text, $2::text) AS sql",
        [grant.object_name, grant.role_name],
      );
    } else if (grant.object_kind === "sequence") {
      await executeFormatted(
        client,
        "SELECT format('REVOKE ALL PRIVILEGES ON SEQUENCE public.%I FROM %I CASCADE', $1::text, $2::text) AS sql",
        [grant.object_name, grant.role_name],
      );
    } else if (grant.object_kind === "function" || grant.object_kind === "procedure") {
      if (grant.identity_arguments === null) {
        throw new Error("Foreign routine privilege is missing its identity");
      }
      const routineKind = grant.object_kind === "procedure" ? "PROCEDURE" : "FUNCTION";
      await executeFormatted(
        client,
        `SELECT format('REVOKE ALL PRIVILEGES ON ${routineKind} public.%I(%s) FROM %I CASCADE', $1::text, $2::text, $3::text) AS sql`,
        [grant.object_name, grant.identity_arguments, grant.role_name],
      );
    } else {
      throw new Error("Unsupported foreign tenant privilege kind");
    }
  }
  if ((await readForeignTenantPrivileges(client, runtimeRole)).length > 0) {
    throw new Error("Foreign tenant privileges remain after reconciliation");
  }
}

interface ForeignTenantPrivilege {
  readonly object_kind: "database" | "schema" | "table" | "sequence" | "function" | "procedure";
  readonly object_name: string;
  readonly identity_arguments: string | null;
  readonly role_name: string;
}

async function readForeignTenantPrivileges(
  client: import("pg").PoolClient,
  runtimeRole: string,
): Promise<readonly ForeignTenantPrivilege[]> {
  const result = await client.query<ForeignTenantPrivilege>(
    `SELECT DISTINCT explicit_grant.object_kind,explicit_grant.object_name,
            explicit_grant.identity_arguments,grantee.rolname AS role_name
       FROM (
         SELECT 'database'::text AS object_kind,database.datname AS object_name,
                NULL::text AS identity_arguments,acl.grantee,database.datdba AS owner_oid
           FROM pg_catalog.pg_database database
           CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(database.datacl,pg_catalog.acldefault('d',database.datdba))
           ) acl
          WHERE database.datname=current_database()
         UNION ALL
         SELECT 'schema'::text AS object_kind,namespace.nspname AS object_name,
                NULL::text AS identity_arguments,acl.grantee,namespace.nspowner AS owner_oid
           FROM pg_catalog.pg_namespace namespace
           CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner))
           ) acl
          WHERE namespace.nspname='public'
         UNION ALL
         SELECT CASE WHEN relation.relkind='S' THEN 'sequence' ELSE 'table' END::text AS object_kind,
                relation.relname AS object_name,NULL::text AS identity_arguments,
                acl.grantee,relation.relowner AS owner_oid
           FROM pg_catalog.pg_class relation
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
           CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(relation.relacl,pg_catalog.acldefault(
               CASE WHEN relation.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,
               relation.relowner
             ))
           ) acl
          WHERE namespace.nspname='public' AND relation.relkind IN ('r','p','v','m','f','S')
         UNION ALL
         SELECT 'table'::text AS object_kind,relation.relname AS object_name,
                NULL::text AS identity_arguments,acl.grantee,relation.relowner AS owner_oid
           FROM pg_catalog.pg_attribute column_record
           JOIN pg_catalog.pg_class relation ON relation.oid=column_record.attrelid
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
           CROSS JOIN LATERAL pg_catalog.aclexplode(column_record.attacl) acl
          WHERE namespace.nspname='public' AND relation.relkind IN ('r','p')
            AND column_record.attnum>0 AND NOT column_record.attisdropped
            AND column_record.attacl IS NOT NULL
         UNION ALL
         SELECT CASE WHEN routine.prokind='p' THEN 'procedure' ELSE 'function' END::text AS object_kind,
                routine.proname AS object_name,
                pg_catalog.pg_get_function_identity_arguments(routine.oid) AS identity_arguments,
                acl.grantee,routine.proowner AS owner_oid
           FROM pg_catalog.pg_proc routine
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
           CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))
           ) acl
          WHERE namespace.nspname='public'
       ) explicit_grant
       JOIN pg_catalog.pg_roles grantee ON grantee.oid=explicit_grant.grantee
      WHERE explicit_grant.grantee<>0
        AND explicit_grant.grantee<>explicit_grant.owner_oid
        AND grantee.rolname<>$1
      ORDER BY explicit_grant.object_kind,explicit_grant.object_name,
               explicit_grant.identity_arguments,grantee.rolname`,
    [runtimeRole],
  );
  return result.rows;
}

async function grantTablePrivileges(
  client: import("pg").PoolClient,
  runtimeRole: string,
  table: string,
  privileges: "SELECT" | "SELECT,INSERT" | "SELECT,UPDATE" | "SELECT,INSERT,UPDATE",
): Promise<void> {
  await executeFormatted(
    client,
    `SELECT format('GRANT ${privileges} ON TABLE public.%I TO %I', $1::text, $2::text) AS sql`,
    [table, runtimeRole],
  );
}

/**
 * Moves every application-owned object in a tenant database away from the
 * cluster administrator and onto the deterministic, non-login tenant owner.
 * Extension-owned objects are deliberately excluded because PostgreSQL owns
 * and upgrades them as a unit.
 */
export async function reconcileTenantObjectOwnership(pool: Pool, ownerRole: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await lockTenantReconciliationBoundary(client);
    await reconcileTenantObjectOwnershipWithClient(client, ownerRole);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function reconcileTenantOwnershipAndRuntimeGrants(
  pool: Pool,
  ownerRole: string,
  runtimeRole: string,
  validateBoundary: (client: import("pg").PoolClient) => Promise<void>,
  validateBeforeCommit?: () => Promise<void>,
): Promise<void> {
  if (ownerRole.replace(/^nom_o_/u, "") !== runtimeRole.replace(/^nom_r_/u, "")) {
    throw new Error("Tenant owner and runtime roles do not identify the same tenant");
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await lockTenantReconciliationBoundary(client);
    await validateBoundary(client);
    await reconcileTenantObjectOwnershipWithClient(client, ownerRole);
    await applyRuntimeGrantsWithClient(client, runtimeRole);
    await validateBoundary(client);
    if (validateBeforeCommit) await validateBeforeCommit();
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function lockTenantReconciliationBoundary(client: import("pg").PoolClient): Promise<void> {
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtextextended('nombramientos-schema-migrations:' || current_database(),0))",
  );
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtextextended('nombramientos-security-reconciliation:' || current_database(),0))",
  );
  await lockTenantApplicationTables(client);
}

async function lockTenantApplicationTables(client: import("pg").PoolClient): Promise<void> {
  const formatted = await client.query<{ sql: string | null }>(
    `SELECT format(
       'LOCK TABLE %s IN SHARE MODE NOWAIT',
       string_agg(format('public.%I',relation.relname),',' ORDER BY relation.relname)
     ) AS sql
       FROM pg_catalog.pg_class relation
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
      WHERE namespace.nspname='public' AND relation.relkind IN ('r','p')`,
  );
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("Tenant application table lock inventory is empty");
  await client.query(sql);
}

async function reconcileTenantObjectOwnershipWithClient(
  client: import("pg").PoolClient,
  ownerRole: string,
): Promise<void> {
  if (!/^nom_o_[0-9a-f]{32}$/u.test(ownerRole)) {
    throw new Error("Tenant object owner must be a deterministic tenant owner role");
  }
  const databaseIdentity = await client.query<{ database_name: string; database_owner: string }>(
      `SELECT database.datname AS database_name,owner.rolname AS database_owner
         FROM pg_database database
         JOIN pg_roles owner ON owner.oid=database.datdba
        WHERE database.datname=current_database()`,
    );
  const database = databaseIdentity.rows[0];
  if (databaseIdentity.rowCount !== 1
    || database?.database_name !== ownerRole.replace(/^nom_o_/u, "nom_t_")
    || database.database_owner !== ownerRole) {
    throw new Error("Tenant database does not satisfy the deterministic owner boundary");
  }
  await normalizeOwnerRoleWithClient(client, ownerRole);

    await client.query("ALTER SCHEMA public OWNER TO pg_database_owner");
    const publicSchema = await client.query<{ owner: string }>(
      `SELECT owner.rolname AS owner
         FROM pg_catalog.pg_namespace namespace
         JOIN pg_catalog.pg_roles owner ON owner.oid=namespace.nspowner
        WHERE namespace.nspname='public'`,
    );
    if (publicSchema.rowCount !== 1 || publicSchema.rows[0]?.owner !== "pg_database_owner") {
      throw new Error("Tenant public schema failed exact ownership attestation");
    }

    const relations = await client.query<{
      kind: "r" | "p" | "S" | "v" | "m" | "f";
      name: string;
    }>(
      `SELECT relation.relkind AS kind,relation.relname AS name
         FROM pg_class relation
         JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname='public'
          AND relation.relkind IN ('r','p','S','v','m','f')
          AND NOT EXISTS (
            SELECT 1 FROM pg_depend dependency
             WHERE dependency.classid='pg_class'::regclass
               AND dependency.objid=relation.oid
               AND dependency.deptype='e'
          )
        ORDER BY CASE relation.relkind WHEN 'r' THEN 1 WHEN 'p' THEN 1 WHEN 'v' THEN 2
                   WHEN 'm' THEN 2 WHEN 'f' THEN 2 WHEN 'S' THEN 3 ELSE 4 END,
                 relation.relname`,
    );
    const relationKinds: Readonly<Record<string, string>> = {
      r: "TABLE", p: "TABLE", S: "SEQUENCE", v: "VIEW", m: "MATERIALIZED VIEW", f: "FOREIGN TABLE",
    };
    for (const relation of relations.rows) {
      const kind = relationKinds[relation.kind];
      if (!kind) throw new Error(`Unsupported tenant relation kind ${relation.kind}`);
      await executeFormatted(
        client,
        `SELECT format('ALTER ${kind} public.%I OWNER TO %I', $1::text, $2::text) AS sql`,
        [relation.name, ownerRole],
      );
    }

    const routines = await client.query<{
      kind: "f" | "p" | "a" | "w";
      name: string;
      arguments: string;
      security_definer: boolean;
    }>(
      `SELECT routine.prokind AS kind,routine.proname AS name,
              pg_get_function_identity_arguments(routine.oid) AS arguments,
              routine.prosecdef AS security_definer
         FROM pg_proc routine
         JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
        WHERE namespace.nspname='public'
          AND NOT EXISTS (
            SELECT 1 FROM pg_depend dependency
             WHERE dependency.classid='pg_proc'::regclass
               AND dependency.objid=routine.oid
               AND dependency.deptype='e'
          )
        ORDER BY routine.proname,pg_get_function_identity_arguments(routine.oid)`,
    );
    const routineKinds: Readonly<Record<string, string>> = { f: "FUNCTION", w: "FUNCTION", p: "PROCEDURE", a: "AGGREGATE" };
    for (const routine of routines.rows) {
      const kind = routineKinds[routine.kind];
      if (!kind) throw new Error(`Unsupported tenant routine kind ${routine.kind}`);
      await executeFormatted(
        client,
        `SELECT format('ALTER ${kind} public.%I(%s) OWNER TO %I', $1::text, $2::text, $3::text) AS sql`,
        [routine.name, routine.arguments, ownerRole],
      );
      if (routine.security_definer) {
        await executeFormatted(
          client,
          `SELECT format('REVOKE ALL PRIVILEGES ON ${kind} public.%I(%s) FROM PUBLIC', $1::text, $2::text) AS sql`,
          [routine.name, routine.arguments],
        );
      }
    }

    const types = await client.query<{ kind: string; name: string }>(
      `SELECT type_record.typtype AS kind,type_record.typname AS name
         FROM pg_catalog.pg_type type_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type_record.typnamespace
         LEFT JOIN pg_catalog.pg_class type_relation ON type_relation.oid=type_record.typrelid
        WHERE namespace.nspname='public'
          AND type_record.typisdefined
          AND type_record.typcategory<>'A'
          AND (type_record.typrelid=0 OR type_relation.relkind='c')
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_depend dependency
             WHERE dependency.classid='pg_type'::regclass
               AND dependency.objid=type_record.oid
               AND dependency.deptype='e'
          )
        ORDER BY type_record.typname`,
    );
    for (const typeRecord of types.rows) {
      const objectKind = typeRecord.kind === "d" ? "DOMAIN" : "TYPE";
      await executeFormatted(
        client,
        `SELECT format('ALTER ${objectKind} public.%I OWNER TO %I', $1::text, $2::text) AS sql`,
        [typeRecord.name, ownerRole],
      );
    }
    if (TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT.schema !== "public"
      || TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT.objectKind !== "functions"
      || TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT.grantee !== "PUBLIC"
      || TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT.privileges.length !== 0) {
      throw new Error("Tenant owner default privilege target is unsupported");
    }
    await executeFormatted(
      client,
      "SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC', $1::text) AS sql",
      [ownerRole],
    );

    const remaining = await client.query<{ objects: number }>(
      `SELECT count(*)::int AS objects
         FROM (
           SELECT relation.oid
             FROM pg_class relation
             JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
            WHERE namespace.nspname='public'
              AND relation.relkind IN ('r','p','S','v','m','f')
              AND relation.relowner <> (SELECT oid FROM pg_roles WHERE rolname=$1)
              AND NOT EXISTS (
                SELECT 1 FROM pg_depend dependency
                 WHERE dependency.classid='pg_class'::regclass
                   AND dependency.objid=relation.oid
                   AND dependency.deptype='e'
              )
           UNION ALL
           SELECT routine.oid
             FROM pg_proc routine
             JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
            WHERE namespace.nspname='public'
              AND routine.proowner <> (SELECT oid FROM pg_roles WHERE rolname=$1)
              AND NOT EXISTS (
                SELECT 1 FROM pg_depend dependency
                 WHERE dependency.classid='pg_proc'::regclass
                   AND dependency.objid=routine.oid
               AND dependency.deptype='e'
              )
           UNION ALL
           SELECT type_record.oid
             FROM pg_catalog.pg_type type_record
             JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type_record.typnamespace
             LEFT JOIN pg_catalog.pg_class type_relation ON type_relation.oid=type_record.typrelid
            WHERE namespace.nspname='public'
              AND type_record.typisdefined
              AND type_record.typcategory<>'A'
              AND (type_record.typrelid=0 OR type_relation.relkind='c')
              AND type_record.typowner<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1)
              AND NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_depend dependency
                 WHERE dependency.classid='pg_type'::regclass
                   AND dependency.objid=type_record.oid
                   AND dependency.deptype='e'
              )
         ) outstanding`,
      [ownerRole],
    );
    if ((remaining.rows[0]?.objects ?? -1) !== 0) {
      throw new Error("One or more tenant objects remain owned by a different role");
    }
}

function isLoopbackHost(host: string | undefined): boolean {
  return host === undefined || host === "127.0.0.1" || host === "localhost" || host === "::1";
}

function isValidIanaTimezone(value: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value }).format(new Date(0));
    return true;
  } catch {
    return false;
  }
}

function sslModeFromConfig(config: PoolConfig): "disable" | "require" | "verify-full" {
  if (!config.ssl) return "disable";
  if (typeof config.ssl === "object" && config.ssl.rejectUnauthorized === false) return "require";
  return "verify-full";
}

function safeErrorCode(error: unknown): string {
  if (typeof error === "object" && error !== null && "code" in error && typeof error.code === "string") {
    return error.code.slice(0, 80);
  }
  return "PROVISIONING_FAILED";
}
