import { createHash } from "node:crypto";
import {
  TENANT_RUNTIME_GRANT_CONTRACT,
  TENANT_RUNTIME_SEQUENCES,
  TENANT_SECURITY_DEFINER_FUNCTIONS,
} from "./runtime-grant-contract.js";
import { TENANT_CANONICAL_TABLES } from "./tenant-maintenance-policy.js";

export const TENANT_SECURITY_TARGET_SCHEMA_VERSION = 1;

export interface TenantRoleSecurityContract {
  readonly canLogin: boolean;
  readonly superuser: false;
  readonly createDatabase: false;
  readonly createRole: false;
  readonly replication: false;
  readonly bypassRls: false;
  readonly inherit: true;
  readonly connectionLimit: -1;
  readonly hasPassword: boolean;
  readonly hasExpiration: false;
  readonly configurationCount: 0;
  readonly membershipCount: 0;
}

export const TENANT_OWNER_ROLE_SECURITY_CONTRACT: TenantRoleSecurityContract = Object.freeze({
  canLogin: false,
  superuser: false,
  createDatabase: false,
  createRole: false,
  replication: false,
  bypassRls: false,
  inherit: true,
  connectionLimit: -1,
  hasPassword: false,
  hasExpiration: false,
  configurationCount: 0,
  membershipCount: 0,
});

export const TENANT_RUNTIME_ROLE_SECURITY_CONTRACT: TenantRoleSecurityContract = Object.freeze({
  ...TENANT_OWNER_ROLE_SECURITY_CONTRACT,
  canLogin: true,
  hasPassword: true,
});

export const TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT = Object.freeze({
  schema: "public",
  objectKind: "functions",
  grantee: "PUBLIC",
  privileges: Object.freeze([] as string[]),
});

export interface TenantSecurityTarget {
  readonly schemaVersion: typeof TENANT_SECURITY_TARGET_SCHEMA_VERSION;
  readonly identities: {
    readonly database: string;
    readonly ownerRole: string;
    readonly runtimeRole: string;
  };
  readonly roles: {
    readonly owner: TenantRoleSecurityContract;
    readonly runtime: TenantRoleSecurityContract;
  };
  readonly ownership: {
    readonly databaseOwner: string;
    readonly publicSchemaOwner: "pg_database_owner";
    readonly nonExtensionPublicObjectOwner: string;
    readonly relationKinds: readonly string[];
    readonly routineKinds: readonly string[];
    readonly typeScope: string;
  };
  readonly grants: unknown;
  readonly defaultPrivileges: readonly {
    readonly grantorRole: string;
    readonly schema: string;
    readonly objectKind: string;
    readonly grantee: string;
    readonly privileges: readonly string[];
  }[];
  readonly inventory: {
    readonly exactTables: readonly string[];
    readonly runtimeGrantedSequences: readonly string[];
    readonly runtimeGrantedFunctions: readonly string[];
    readonly securityDefinerFunctions: readonly string[];
  };
}

export function buildTenantSecurityTarget(tenantId: string): TenantSecurityTarget {
  const suffix = canonicalTenantSuffix(tenantId);
  const ownerRole = `nom_o_${suffix}`;
  const runtimeRole = `nom_r_${suffix}`;
  return {
    schemaVersion: TENANT_SECURITY_TARGET_SCHEMA_VERSION,
    identities: {
      database: `nom_t_${suffix}`,
      ownerRole,
      runtimeRole,
    },
    roles: {
      owner: TENANT_OWNER_ROLE_SECURITY_CONTRACT,
      runtime: TENANT_RUNTIME_ROLE_SECURITY_CONTRACT,
    },
    ownership: {
      databaseOwner: ownerRole,
      publicSchemaOwner: "pg_database_owner",
      nonExtensionPublicObjectOwner: ownerRole,
      relationKinds: ["foreign_table", "materialized_view", "partitioned_table", "sequence", "table", "view"],
      routineKinds: ["aggregate", "function", "procedure", "window_function"],
      typeScope: "all-defined-non-array-public-types-and-composites-excluding-extension-members",
    },
    grants: normalizedGrantContract(),
    defaultPrivileges: [{
      grantorRole: ownerRole,
      schema: TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT.schema,
      objectKind: TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT.objectKind,
      grantee: TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT.grantee,
      privileges: TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT.privileges,
    }],
    inventory: {
      exactTables: [...TENANT_CANONICAL_TABLES],
      runtimeGrantedSequences: [...TENANT_RUNTIME_SEQUENCES].sort(),
      runtimeGrantedFunctions: [...TENANT_RUNTIME_GRANT_CONTRACT.functions].sort(),
      securityDefinerFunctions: [...TENANT_SECURITY_DEFINER_FUNCTIONS].sort(),
    },
  };
}

export function securityTargetSha256(target: TenantSecurityTarget): string {
  return `sha256:${createHash("sha256").update(canonicalJson(target), "utf8").digest("hex")}`;
}

export function tenantSecurityTargetSha256(tenantId: string): string {
  return securityTargetSha256(buildTenantSecurityTarget(tenantId));
}

function normalizedGrantContract(): unknown {
  return {
    database: {
      public: [...TENANT_RUNTIME_GRANT_CONTRACT.database.public].sort(),
      runtime: [...TENANT_RUNTIME_GRANT_CONTRACT.database.runtime].sort(),
    },
    schema: {
      public: [...TENANT_RUNTIME_GRANT_CONTRACT.schema.public].sort(),
      runtime: [...TENANT_RUNTIME_GRANT_CONTRACT.schema.runtime].sort(),
    },
    tables: sortedRecord(TENANT_RUNTIME_GRANT_CONTRACT.tables),
    columns: Object.fromEntries(Object.entries(TENANT_RUNTIME_GRANT_CONTRACT.columns)
      .sort(([left], [right]) => compareText(left, right))
      .map(([table, columns]) => [table, sortedRecord(columns)])),
    sequences: sortedRecord(TENANT_RUNTIME_GRANT_CONTRACT.sequences),
    functions: [...TENANT_RUNTIME_GRANT_CONTRACT.functions].sort(),
    foreignGrantees: [],
    publicObjectPrivileges: [],
    grantOptions: [],
  };
}

function sortedRecord(
  value: Readonly<Record<string, readonly string[]>>,
): Readonly<Record<string, readonly string[]>> {
  return Object.fromEntries(Object.entries(value)
    .sort(([left], [right]) => compareText(left, right))
    .map(([key, privileges]) => [key, [...privileges].sort()]));
}

function canonicalTenantSuffix(tenantId: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(tenantId)) {
    throw new Error("Tenant security target requires a canonical tenant UUID");
  }
  return tenantId.replaceAll("-", "");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Tenant security target must be JSON-compatible");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : Number(left > right);
}
