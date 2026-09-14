import { Pool } from "pg";

import {
  PROTECTED_DATABASES,
  PROTECTED_TENANTS,
  assertProtectedTenantRoutes,
  digestProtectedDatabaseSnapshot as digestCanonicalProtectedDatabaseSnapshot,
  observeUnroutedTenantResources,
  type RegisteredTenantResourceRoute,
} from "./real-browser-stack-guards.js";
import { exactLocalPostgresPoolConfig } from "./local-performance-database-guards.js";

export interface DatabaseFingerprint {
  readonly fingerprintVersion: "protected-db-v3-full-cluster-role-structure-and-content";
  readonly digest: string;
  readonly tables: number;
  readonly rows: number;
  readonly schemaObjects: number;
}

export type ProtectedDatabaseFingerprints = Readonly<
  Record<keyof typeof PROTECTED_DATABASES, DatabaseFingerprint>
>;

export interface EphemeralResourceInventory {
  readonly inspectedDatabases: number;
  readonly inspectedRoles: number;
  readonly globalDatabaseCount: number;
  readonly globalRoleCount: number;
  readonly globalMembershipCount: number;
  readonly globalSharedDescriptionCount: number;
  readonly globalSharedSecurityLabelCount: number;
  readonly globalInventoryDigest: string;
  readonly orphanDatabases: number;
  readonly orphanRoles: number;
  readonly pass: boolean;
}

type CatalogRow = Readonly<Record<string, unknown>>;

export interface ProtectedDatabaseSnapshot {
  readonly database: string;
  readonly databaseMetadata: readonly CatalogRow[];
  readonly associatedRoles: readonly CatalogRow[];
  readonly associatedRoleMemberships: readonly CatalogRow[];
  readonly schemas: readonly CatalogRow[];
  readonly relations: readonly CatalogRow[];
  readonly columns: readonly CatalogRow[];
  readonly constraints: readonly CatalogRow[];
  readonly indexes: readonly CatalogRow[];
  readonly views: readonly CatalogRow[];
  readonly routines: readonly CatalogRow[];
  readonly triggers: readonly CatalogRow[];
  readonly policies: readonly CatalogRow[];
  readonly types: readonly CatalogRow[];
  readonly sequences: readonly CatalogRow[];
  readonly defaultPrivileges: readonly CatalogRow[];
  readonly extensions: readonly CatalogRow[];
  readonly descriptions: readonly CatalogRow[];
  readonly sharedDescriptions: readonly CatalogRow[];
  readonly securityLabels: readonly CatalogRow[];
  readonly sharedSecurityLabels: readonly CatalogRow[];
  readonly eventTriggers: readonly CatalogRow[];
  readonly publications: readonly CatalogRow[];
  readonly publicationRelations: readonly CatalogRow[];
  readonly publicationNamespaces: readonly CatalogRow[];
  readonly subscriptions: readonly CatalogRow[];
  readonly subscriptionRelations: readonly CatalogRow[];
  readonly rewriteRules: readonly CatalogRow[];
  readonly tableFingerprints: readonly CatalogRow[];
}

export function digestProtectedDatabaseSnapshot(snapshot: ProtectedDatabaseSnapshot): string {
  return digestCanonicalProtectedDatabaseSnapshot(snapshot as unknown as Readonly<Record<string, unknown>>);
}

export async function fingerprintProtectedDatabases(
  databaseAdminUrl: string,
): Promise<ProtectedDatabaseFingerprints> {
  const control = new Pool({
    ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres", PROTECTED_DATABASES.control),
    application_name: "nombramientos-performance-protected-route-check",
    max: 1,
    connectionTimeoutMillis: 5_000,
  });
  try {
    const routes = await control.query<{
      id: string; slug: string; kind: string; status: string; database_name: string;
    }>(
      `SELECT id::text,slug,kind,status,database_name::text
         FROM tenants WHERE id=ANY($1::uuid[]) ORDER BY id`,
      [PROTECTED_TENANTS.map(({ id }) => id)],
    );
    assertProtectedTenantRoutes(routes.rows);
  } finally {
    await control.end();
  }

  const entries = await Promise.all(Object.entries(PROTECTED_DATABASES).map(async ([label, database]) => (
    [label, await fingerprintProtectedDatabase(databaseAdminUrl, database)] as const
  )));
  return Object.fromEntries(entries) as ProtectedDatabaseFingerprints;
}

export async function inspectGlobalEphemeralResources(
  databaseAdminUrl: string,
): Promise<EphemeralResourceInventory> {
  const control = new Pool({
    ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres", PROTECTED_DATABASES.control),
    application_name: "nombramientos-performance-route-inventory",
    max: 1,
    connectionTimeoutMillis: 5_000,
  });
  const cluster = new Pool({
    ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres"),
    application_name: "nombramientos-performance-cluster-inventory",
    max: 1,
    connectionTimeoutMillis: 5_000,
  });
  try {
    const routes = await control.query<RegisteredTenantResourceRoute>(
      "SELECT id::text,database_name::text,runtime_role::text FROM tenants ORDER BY id",
    );
    const databases = await cluster.query<{ name: string }>(
      `SELECT datname::text AS name FROM pg_database
        WHERE left(datname,6) IN ('nom_t_','nom_c_')
           OR left(datname,10)='nom_e2e_c_'
        ORDER BY datname`,
    );
    const roles = await cluster.query<{ name: string }>(
      `SELECT rolname::text AS name FROM pg_roles
        WHERE left(rolname,6) IN ('nom_o_','nom_r_')
           OR left(rolname,7)='nom_cr_'
        ORDER BY rolname`,
    );
    const tenantDatabases = databases.rows.map(({ name }) => name).filter((name) => name.startsWith("nom_t_"));
    const temporaryControlDatabases = databases.rows
      .filter(({ name }) => name.startsWith("nom_c_") || name.startsWith("nom_e2e_c_"))
      .length;
    const tenantRoles = roles.rows.map(({ name }) => name).filter((name) => (
      name.startsWith("nom_o_") || name.startsWith("nom_r_")
    ));
    const temporaryControlRoles = roles.rows.filter(({ name }) => name.startsWith("nom_cr_")).length;
    const unrouted = observeUnroutedTenantResources(routes.rows, {
      databases: tenantDatabases,
      roles: tenantRoles,
    });
    const orphanDatabases = temporaryControlDatabases + unrouted.databases;
    const globalDatabases = (await cluster.query<CatalogRow>(
      `SELECT database.datname::text AS database,
              pg_get_userbyid(database.datdba)::text AS owner,
              ARRAY(SELECT acl::text FROM unnest(COALESCE(database.datacl,'{}'::aclitem[])) acl ORDER BY acl::text)::text AS acl,
              database.encoding::int AS encoding,database.datcollate::text AS collation,
              database.datctype::text AS character_type,database.datlocprovider::text AS locale_provider,
              COALESCE(database.datlocale,'')::text AS locale,
              COALESCE(database.daticurules,'')::text AS icu_rules,
              COALESCE(database.datcollversion,'')::text AS collation_version,
              database.datistemplate AS is_template,database.datallowconn AS allows_connections,
              database.datconnlimit::int AS connection_limit,
              COALESCE(pg_catalog.shobj_description(database.oid,'pg_database'),'')::text AS comment
         FROM pg_catalog.pg_database database ORDER BY database.datname`,
    )).rows;
    const globalRoles = (await cluster.query<CatalogRow>(
      `SELECT role.rolname::text AS role,role.rolsuper AS superuser,role.rolinherit AS inherit,
              role.rolcreaterole AS create_role,role.rolcreatedb AS create_database,
              role.rolcanlogin AS login,role.rolreplication AS replication,
              role.rolbypassrls AS bypass_rls,role.rolconnlimit::int AS connection_limit,
              COALESCE(extract(epoch FROM role.rolvaliduntil)::text,'') AS valid_until_epoch,
              ARRAY(SELECT setting FROM unnest(COALESCE(role.rolconfig,'{}'::text[])) setting ORDER BY setting)::text AS configuration,
              credential.rolpassword IS NOT NULL AS password_present,
              COALESCE(pg_catalog.shobj_description(role.oid,'pg_authid'),'')::text AS comment
         FROM pg_catalog.pg_roles role
         JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid
        ORDER BY role.rolname`,
    )).rows;
    const globalMemberships = (await cluster.query<CatalogRow>(
      `SELECT granted.rolname::text AS granted_role,member.rolname::text AS member_role,
              grantor.rolname::text AS grantor_role,membership.admin_option,
              membership.inherit_option,membership.set_option
         FROM pg_catalog.pg_auth_members membership
         JOIN pg_catalog.pg_roles granted ON granted.oid=membership.roleid
         JOIN pg_catalog.pg_roles member ON member.oid=membership.member
         JOIN pg_catalog.pg_roles grantor ON grantor.oid=membership.grantor
        ORDER BY granted.rolname,member.rolname,grantor.rolname`,
    )).rows;
    const globalSharedDescriptions = (await cluster.query<CatalogRow>(
      `SELECT description.classoid::regclass::text AS catalog,description.objoid::text AS object_oid,
              description.description::text AS description
         FROM pg_catalog.pg_shdescription description
        ORDER BY description.classoid::regclass::text,description.objoid`,
    )).rows;
    const globalSharedSecurityLabels = (await cluster.query<CatalogRow>(
      `SELECT security_label.classoid::regclass::text AS catalog,
              security_label.objoid::text AS object_oid,
              security_label.provider::text AS provider,security_label.label::text AS label
         FROM pg_catalog.pg_shseclabel security_label
        ORDER BY security_label.classoid::regclass::text,security_label.objoid,security_label.provider`,
    )).rows;
    const globalInventoryDigest = digestCanonicalProtectedDatabaseSnapshot({
      databases: globalDatabases,
      roles: globalRoles,
      memberships: globalMemberships,
      sharedDescriptions: globalSharedDescriptions,
      sharedSecurityLabels: globalSharedSecurityLabels,
    });
    return {
      inspectedDatabases: databases.rows.length,
      inspectedRoles: roles.rows.length,
      globalDatabaseCount: globalDatabases.length,
      globalRoleCount: globalRoles.length,
      globalMembershipCount: globalMemberships.length,
      globalSharedDescriptionCount: globalSharedDescriptions.length,
      globalSharedSecurityLabelCount: globalSharedSecurityLabels.length,
      globalInventoryDigest,
      orphanDatabases,
      orphanRoles: temporaryControlRoles + unrouted.roles,
      pass: orphanDatabases === 0 && temporaryControlRoles + unrouted.roles === 0,
    };
  } finally {
    await Promise.allSettled([control.end(), cluster.end()]);
  }
}

export function globalInventorySetsEqual(
  before: EphemeralResourceInventory | null,
  after: EphemeralResourceInventory | null,
): boolean {
  return before !== null
    && after !== null
    && /^sha256:[0-9a-f]{64}$/u.test(before.globalInventoryDigest)
    && /^sha256:[0-9a-f]{64}$/u.test(after.globalInventoryDigest)
    && before.globalDatabaseCount === after.globalDatabaseCount
    && before.globalRoleCount === after.globalRoleCount
    && before.globalMembershipCount === after.globalMembershipCount
    && before.globalSharedDescriptionCount === after.globalSharedDescriptionCount
    && before.globalSharedSecurityLabelCount === after.globalSharedSecurityLabelCount
    && before.globalInventoryDigest === after.globalInventoryDigest;
}

export function protectedFingerprintSetsEqual(
  before: ProtectedDatabaseFingerprints | null,
  after: ProtectedDatabaseFingerprints | null,
): boolean {
  return before !== null
    && after !== null
    && completeProtectedFingerprintSet(before)
    && completeProtectedFingerprintSet(after)
    && JSON.stringify(before) === JSON.stringify(after);
}

export function completeProtectedFingerprintSet(value: ProtectedDatabaseFingerprints): boolean {
  const keys = Object.keys(value).sort();
  const expectedKeys = Object.keys(PROTECTED_DATABASES).sort();
  return JSON.stringify(keys) === JSON.stringify(expectedKeys)
    && Object.values(value).every((fingerprint) => (
      fingerprint.fingerprintVersion === "protected-db-v3-full-cluster-role-structure-and-content"
      && /^sha256:[0-9a-f]{64}$/u.test(fingerprint.digest)
      && Number.isSafeInteger(fingerprint.tables)
      && fingerprint.tables > 0
      && Number.isSafeInteger(fingerprint.rows)
      && fingerprint.rows >= 0
      && Number.isSafeInteger(fingerprint.schemaObjects)
      && fingerprint.schemaObjects > 0
    ));
}

async function fingerprintProtectedDatabase(
  databaseAdminUrl: string,
  database: string,
): Promise<DatabaseFingerprint> {
  const pool = new Pool({
    ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres", database),
    application_name: "nombramientos-performance-protected-readonly-fingerprint",
    max: 1,
    connectionTimeoutMillis: 5_000,
  });
  const client = await pool.connect();
  let transactionOpen = false;
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    transactionOpen = true;
    const identity = await client.query<{ database_name: string; port: number; loopback: boolean }>(
      `SELECT current_database() AS database_name,current_setting('port')::int AS port,
              COALESCE(
                inet_server_addr() <<= inet '127.0.0.0/8'
                OR inet_server_addr() = inet '::1'
                OR inet_server_addr() <<= inet '::ffff:127.0.0.0/104',
                false
              ) AS loopback`,
    );
    const identityRow = identity.rows[0];
    if (!identityRow || identityRow.database_name !== database || identityRow.port !== 55_432 || !identityRow.loopback) {
      throw new Error("Protected performance fingerprint target identity is invalid");
    }
    if (database === PROTECTED_DATABASES.demo || database === PROTECTED_DATABASES.ozama) {
      const expected = database === PROTECTED_DATABASES.demo ? PROTECTED_TENANTS[0] : PROTECTED_TENANTS[1];
      const tenant = await client.query<{ tenant_id: string; kind: string }>(
        "SELECT tenant_id::text,kind FROM tenant_settings WHERE singleton=true",
      );
      if (tenant.rows[0]?.tenant_id !== expected.id || tenant.rows[0]?.kind !== expected.kind) {
        throw new Error("Protected performance tenant fingerprint identity is invalid");
      }
    }
    const databaseMetadata = (await client.query<CatalogRow>(
      `SELECT database.datname::text AS database,
              pg_get_userbyid(database.datdba)::text AS owner,
              ARRAY(SELECT acl::text FROM unnest(COALESCE(database.datacl,'{}'::aclitem[])) acl ORDER BY acl::text)::text AS acl,
              database.encoding::int AS encoding,
              database.datcollate::text AS collation,
              database.datctype::text AS character_type,
              database.datlocprovider::text AS locale_provider,
              COALESCE(database.datlocale,'')::text AS locale,
              COALESCE(database.daticurules,'')::text AS icu_rules,
              COALESCE(database.datcollversion,'')::text AS collation_version,
              database.datistemplate AS is_template,
              database.datallowconn AS allows_connections,
              database.datconnlimit::int AS connection_limit,
              COALESCE(pg_catalog.shobj_description(database.oid,'pg_database'),'')::text AS comment
         FROM pg_catalog.pg_database database
        WHERE database.datname=current_database()`,
    )).rows;
    const associatedRoleNames = new Set(["nom_admin", "nom_control"]);
    const databaseOwner = databaseMetadata[0]?.["owner"];
    if (typeof databaseOwner !== "string" || databaseOwner.length === 0) {
      throw new Error("Protected performance database owner fingerprint is invalid");
    }
    associatedRoleNames.add(databaseOwner);
    if (database.startsWith("nom_t_") && /^nom_t_[0-9a-f]{32}$/u.test(database)) {
      const suffix = database.slice("nom_t_".length);
      associatedRoleNames.add(`nom_o_${suffix}`);
      associatedRoleNames.add(`nom_r_${suffix}`);
    }
    const expectedAssociatedRoles = [...associatedRoleNames].sort();
    const associatedRoles = (await client.query<CatalogRow>(
      `SELECT role.rolname::text AS role,role.rolsuper AS superuser,role.rolinherit AS inherit,
              role.rolcreaterole AS create_role,role.rolcreatedb AS create_database,
              role.rolcanlogin AS login,role.rolreplication AS replication,
              role.rolbypassrls AS bypass_rls,role.rolconnlimit::int AS connection_limit,
              COALESCE(extract(epoch FROM role.rolvaliduntil)::text,'') AS valid_until_epoch,
              ARRAY(SELECT setting FROM unnest(COALESCE(role.rolconfig,'{}'::text[])) setting ORDER BY setting)::text AS configuration,
              credential.rolpassword IS NOT NULL AS password_present,
              COALESCE(pg_catalog.shobj_description(role.oid,'pg_authid'),'')::text AS comment
         FROM pg_catalog.pg_roles role
         JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid
        WHERE role.rolname=ANY($1::text[])
        ORDER BY role.rolname`,
      [expectedAssociatedRoles],
    )).rows;
    const observedAssociatedRoles = associatedRoles.map((role) => role["role"]);
    if (JSON.stringify(observedAssociatedRoles) !== JSON.stringify(expectedAssociatedRoles)) {
      throw new Error("Protected performance associated-role fingerprint is incomplete");
    }
    const associatedRoleMemberships = (await client.query<CatalogRow>(
      `SELECT granted.rolname::text AS granted_role,member.rolname::text AS member_role,
              grantor.rolname::text AS grantor_role,membership.admin_option,
              membership.inherit_option,membership.set_option
         FROM pg_catalog.pg_auth_members membership
         JOIN pg_catalog.pg_roles granted ON granted.oid=membership.roleid
         JOIN pg_catalog.pg_roles member ON member.oid=membership.member
         JOIN pg_catalog.pg_roles grantor ON grantor.oid=membership.grantor
        WHERE granted.rolname=ANY($1::text[]) OR member.rolname=ANY($1::text[])
        ORDER BY granted.rolname,member.rolname,grantor.rolname`,
      [expectedAssociatedRoles],
    )).rows;
    const schemas = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              pg_get_userbyid(namespace.nspowner)::text AS owner,
              ARRAY(SELECT acl::text FROM unnest(COALESCE(namespace.nspacl,'{}'::aclitem[])) acl ORDER BY acl::text)::text AS acl
         FROM pg_catalog.pg_namespace namespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
        ORDER BY namespace.nspname`,
    )).rows;
    const relations = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              relation.relname::text AS relation,
              relation.relkind::text AS kind,
              pg_get_userbyid(relation.relowner)::text AS owner,
              ARRAY(SELECT acl::text FROM unnest(COALESCE(relation.relacl,'{}'::aclitem[])) acl ORDER BY acl::text)::text AS acl,
              relation.relpersistence::text AS persistence,
              relation.relrowsecurity AS row_security,
              relation.relforcerowsecurity AS force_row_security,
              relation.relreplident::text AS replica_identity,
              relation.relispartition AS is_partition,
              COALESCE(array_to_string(ARRAY(
                SELECT option FROM unnest(COALESCE(relation.reloptions,'{}'::text[])) option ORDER BY option
              ),E'\n'),'')::text AS options,
              COALESCE(pg_get_partkeydef(relation.oid),'')::text AS partition_key,
              COALESCE(pg_get_expr(relation.relpartbound,relation.oid,true),'')::text AS partition_bound,
              COALESCE(access_method.amname,'')::text AS access_method
         FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         LEFT JOIN pg_catalog.pg_am access_method ON access_method.oid=relation.relam
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
          AND relation.relkind IN ('r','p','v','m','S','f','i','I')
        ORDER BY namespace.nspname,relation.relname,relation.relkind`,
    )).rows;
    const columns = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              relation.relname::text AS relation,
              attribute.attnum::int AS ordinal,
              attribute.attname::text AS column,
              pg_catalog.format_type(attribute.atttypid,attribute.atttypmod)::text AS formatted_type,
              attribute.attnotnull AS not_null,
              attribute.atthasdef AS has_default,
              COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid,true),'')::text AS default_expression,
              attribute.attidentity::text AS identity_kind,
              attribute.attgenerated::text AS generated_kind,
              ARRAY(SELECT acl::text FROM unnest(COALESCE(attribute.attacl,'{}'::aclitem[])) acl ORDER BY acl::text)::text AS acl,
              COALESCE(collation_record.collname,'')::text AS collation,
              attribute.attstorage::text AS storage,
              attribute.attcompression::text AS compression,
              attribute.attstattarget::int AS statistics_target
         FROM pg_catalog.pg_attribute attribute
         JOIN pg_catalog.pg_class relation ON relation.oid=attribute.attrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         LEFT JOIN pg_catalog.pg_attrdef default_value
           ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
         LEFT JOIN pg_catalog.pg_collation collation_record ON collation_record.oid=attribute.attcollation
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
          AND relation.relkind IN ('r','p','v','m','f')
          AND attribute.attnum>0
          AND NOT attribute.attisdropped
        ORDER BY namespace.nspname,relation.relname,attribute.attnum`,
    )).rows;
    const constraints = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              COALESCE(relation.relname,type_record.typname,'')::text AS target,
              constraint_record.conname::text AS constraint,
              constraint_record.contype::text AS type,
              pg_get_constraintdef(constraint_record.oid,true)::text AS definition,
              constraint_record.condeferrable AS deferrable,
              constraint_record.condeferred AS initially_deferred,
              constraint_record.convalidated AS validated,
              constraint_record.connoinherit AS no_inherit
         FROM pg_catalog.pg_constraint constraint_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=constraint_record.connamespace
         LEFT JOIN pg_catalog.pg_class relation ON relation.oid=constraint_record.conrelid
         LEFT JOIN pg_catalog.pg_type type_record ON type_record.oid=constraint_record.contypid
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
        ORDER BY namespace.nspname,COALESCE(relation.relname,type_record.typname,''),constraint_record.conname`,
    )).rows;
    const indexes = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              table_relation.relname::text AS table,
              index_relation.relname::text AS index,
              pg_get_indexdef(index_relation.oid)::text AS definition,
              COALESCE(pg_get_expr(index.indpred,index.indrelid,true),'')::text AS predicate,
              COALESCE(pg_get_expr(index.indexprs,index.indrelid,true),'')::text AS expressions,
              index.indisunique AS is_unique,
              index.indisprimary AS is_primary,
              index.indisexclusion AS is_exclusion,
              index.indimmediate AS is_immediate,
              index.indisclustered AS is_clustered,
              index.indisvalid AS is_valid,
              index.indisready AS is_ready,
              index.indislive AS is_live,
              index.indisreplident AS is_replica_identity
         FROM pg_catalog.pg_index index
         JOIN pg_catalog.pg_class index_relation ON index_relation.oid=index.indexrelid
         JOIN pg_catalog.pg_class table_relation ON table_relation.oid=index.indrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=table_relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
        ORDER BY namespace.nspname,table_relation.relname,index_relation.relname`,
    )).rows;
    const views = (await client.query<CatalogRow>(
      `SELECT 'view'::text AS kind,schemaname::text AS schema,viewname::text AS name,
              viewowner::text AS owner,definition::text AS definition,NULL::boolean AS populated
         FROM pg_catalog.pg_views
        WHERE schemaname NOT IN ('pg_catalog','information_schema')
          AND schemaname !~ '^pg_(toast|temp)'
        UNION ALL
       SELECT 'materialized-view'::text AS kind,schemaname::text AS schema,matviewname::text AS name,
              matviewowner::text AS owner,definition::text AS definition,ispopulated AS populated
         FROM pg_catalog.pg_matviews
        WHERE schemaname NOT IN ('pg_catalog','information_schema')
          AND schemaname !~ '^pg_(toast|temp)'
        ORDER BY schema,name,kind`,
    )).rows;
    const routines = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              routine.proname::text AS name,
              pg_get_function_identity_arguments(routine.oid)::text AS identity_arguments,
              pg_get_function_result(routine.oid)::text AS result,
              routine.prokind::text AS kind,
              language.lanname::text AS language,
              pg_get_userbyid(routine.proowner)::text AS owner,
              ARRAY(SELECT acl::text FROM unnest(COALESCE(routine.proacl,'{}'::aclitem[])) acl ORDER BY acl::text)::text AS acl,
              routine.provolatile::text AS volatility,
              routine.proparallel::text AS parallel,
              routine.prosecdef AS security_definer,
              routine.proleakproof AS leakproof,
              routine.proisstrict AS strict,
              routine.proretset AS returns_set,
              routine.procost::text AS cost,
              routine.prorows::text AS estimated_rows,
              pg_get_function_arguments(routine.oid)::text AS arguments,
              COALESCE(routine.proconfig,'{}'::text[])::text AS configuration,
              COALESCE(routine.probin,'')::text AS binary,
              routine.prosrc::text AS source,
              pg_get_functiondef(routine.oid)::text AS definition
         FROM pg_catalog.pg_proc routine
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
         JOIN pg_catalog.pg_language language ON language.oid=routine.prolang
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
        ORDER BY namespace.nspname,routine.proname,pg_get_function_identity_arguments(routine.oid)`,
    )).rows;
    const triggers = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              relation.relname::text AS relation,
              trigger.tgname::text AS trigger,
              trigger.tgenabled::text AS enabled,
              trigger.tgisinternal AS internal,
              pg_get_triggerdef(trigger.oid,true)::text AS definition
         FROM pg_catalog.pg_trigger trigger
         JOIN pg_catalog.pg_class relation ON relation.oid=trigger.tgrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
        ORDER BY namespace.nspname,relation.relname,trigger.tgname`,
    )).rows;
    const policies = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              relation.relname::text AS relation,
              policy.polname::text AS policy,
              policy.polpermissive AS permissive,
              policy.polcmd::text AS command,
              ARRAY(SELECT role.rolname::text FROM unnest(policy.polroles) AS role_id(role_oid)
                      JOIN pg_catalog.pg_roles role ON role.oid=role_id.role_oid ORDER BY role.rolname)::text AS roles,
              COALESCE(pg_get_expr(policy.polqual,policy.polrelid,true),'')::text AS using_expression,
              COALESCE(pg_get_expr(policy.polwithcheck,policy.polrelid,true),'')::text AS check_expression
         FROM pg_catalog.pg_policy policy
         JOIN pg_catalog.pg_class relation ON relation.oid=policy.polrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
        ORDER BY namespace.nspname,relation.relname,policy.polname`,
    )).rows;
    const types = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,
              type.typname::text AS name,
              type.typtype::text AS kind,
              type.typcategory::text AS category,
              type.typisdefined AS is_defined,
              pg_get_userbyid(type.typowner)::text AS owner,
              ARRAY(SELECT acl::text FROM unnest(COALESCE(type.typacl,'{}'::aclitem[])) acl ORDER BY acl::text)::text AS acl,
              type.typnotnull AS not_null,
              COALESCE(type.typdefault,'')::text AS default_expression,
              COALESCE(pg_catalog.format_type(NULLIF(type.typbasetype,0),type.typtypmod),'')::text AS base_type,
              COALESCE(range_namespace.nspname,'')::text AS range_subtype_schema,
              COALESCE(range_type.typname,'')::text AS range_subtype,
              COALESCE(collation_record.collname,'')::text AS collation,
              ARRAY(SELECT enum.enumlabel::text FROM pg_catalog.pg_enum enum
                      WHERE enum.enumtypid=type.oid ORDER BY enum.enumsortorder)::text AS enum_labels
         FROM pg_catalog.pg_type type
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type.typnamespace
         LEFT JOIN pg_catalog.pg_collation collation_record ON collation_record.oid=type.typcollation
         LEFT JOIN pg_catalog.pg_range range ON range.rngtypid=type.oid
         LEFT JOIN pg_catalog.pg_type range_type ON range_type.oid=range.rngsubtype
         LEFT JOIN pg_catalog.pg_namespace range_namespace ON range_namespace.oid=range_type.typnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
        ORDER BY namespace.nspname,type.typname`,
    )).rows;
    const sequenceDefinitions = await client.query<{
      schema: string;
      sequence: string;
      qualified_name: string;
      owner: string;
      data_type: string;
      start_value: string;
      min_value: string;
      max_value: string;
      increment_by: string;
      cycle: boolean;
      cache_size: string;
    }>(
      `SELECT schemaname::text AS schema,sequencename::text AS sequence,
              format('%I.%I',schemaname,sequencename) AS qualified_name,
              sequenceowner::text AS owner,data_type::text AS data_type,
              start_value::text,min_value::text,max_value::text,
              increment_by::text,cycle,cache_size::text
         FROM pg_catalog.pg_sequences
        WHERE schemaname NOT IN ('pg_catalog','information_schema')
          AND schemaname !~ '^pg_(toast|temp)'
        ORDER BY schemaname,sequencename`,
    );
    const sequences: CatalogRow[] = [];
    for (const definition of sequenceDefinitions.rows) {
      // qualified_name is generated by PostgreSQL format(%I), never external input.
      // Reading the sequence relation is required because pg_sequences omits
      // is_called, even though toggling it changes the next value returned.
      const state = await client.query<{ last_value: string; is_called: boolean }>(
        `SELECT last_value::text,is_called FROM ${definition.qualified_name}`,
      );
      const row = state.rows[0];
      if (!row || !/^-?\d+$/u.test(row.last_value) || typeof row.is_called !== "boolean") {
        throw new Error("Protected performance sequence fingerprint is invalid");
      }
      const { qualified_name: _qualifiedName, ...publicDefinition } = definition;
      sequences.push({ ...publicDefinition, last_value: row.last_value, is_called: row.is_called });
    }
    const defaultPrivileges = (await client.query<CatalogRow>(
      `SELECT pg_get_userbyid(default_acl.defaclrole)::text AS owner,
              COALESCE(namespace.nspname,'')::text AS schema,
              default_acl.defaclobjtype::text AS object_type,
              ARRAY(SELECT acl::text FROM unnest(COALESCE(default_acl.defaclacl,'{}'::aclitem[])) acl ORDER BY acl::text)::text AS acl
         FROM pg_catalog.pg_default_acl default_acl
         LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid=default_acl.defaclnamespace
        WHERE default_acl.defaclnamespace=0
           OR (namespace.nspname NOT IN ('pg_catalog','information_schema')
               AND namespace.nspname !~ '^pg_(toast|temp)')
        ORDER BY owner,schema,object_type`,
    )).rows;
    const extensions = (await client.query<CatalogRow>(
      `SELECT extension.extname::text AS extension,extension.extversion::text AS version,
              namespace.nspname::text AS schema,pg_get_userbyid(extension.extowner)::text AS owner,
              extension.extrelocatable AS relocatable,
              COALESCE(extension.extconfig,'{}'::oid[])::text AS configuration_relations,
              COALESCE(extension.extcondition,'{}'::text[])::text AS configuration_conditions
         FROM pg_catalog.pg_extension extension
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=extension.extnamespace
        ORDER BY extension.extname`,
    )).rows;
    const descriptions = (await client.query<CatalogRow>(
      `SELECT description.classoid::regclass::text AS catalog,
              description.objoid::text AS object_oid,description.objsubid::int AS object_sub_id,
              pg_catalog.pg_describe_object(description.classoid,description.objoid,description.objsubid)::text AS object_identity,
              description.description::text AS description
         FROM pg_catalog.pg_description description
        ORDER BY description.classoid::regclass::text,description.objoid,description.objsubid`,
    )).rows;
    const sharedDescriptions = (await client.query<CatalogRow>(
      `SELECT description.classoid::regclass::text AS catalog,
              description.objoid::text AS object_oid,description.description::text AS description
         FROM pg_catalog.pg_shdescription description
        ORDER BY description.classoid::regclass::text,description.objoid`,
    )).rows;
    const securityLabels = (await client.query<CatalogRow>(
      `SELECT security_label.classoid::regclass::text AS catalog,
              security_label.objoid::text AS object_oid,security_label.objsubid::int AS object_sub_id,
              security_label.provider::text AS provider,security_label.label::text AS label
         FROM pg_catalog.pg_seclabel security_label
        ORDER BY security_label.classoid::regclass::text,security_label.objoid,
                 security_label.objsubid,security_label.provider`,
    )).rows;
    const sharedSecurityLabels = (await client.query<CatalogRow>(
      `SELECT security_label.classoid::regclass::text AS catalog,
              security_label.objoid::text AS object_oid,
              security_label.provider::text AS provider,security_label.label::text AS label
         FROM pg_catalog.pg_shseclabel security_label
        ORDER BY security_label.classoid::regclass::text,security_label.objoid,security_label.provider`,
    )).rows;
    const eventTriggers = (await client.query<CatalogRow>(
      `SELECT event_trigger.evtname::text AS name,event_trigger.evtevent::text AS event,
              pg_get_userbyid(event_trigger.evtowner)::text AS owner,
              event_trigger.evtfoid::regprocedure::text AS function,
              event_trigger.evtenabled::text AS enabled,
              ARRAY(SELECT tag::text FROM unnest(COALESCE(event_trigger.evttags,'{}'::text[])) tag ORDER BY tag)::text AS tags
         FROM pg_catalog.pg_event_trigger event_trigger ORDER BY event_trigger.evtname`,
    )).rows;
    const publications = (await client.query<CatalogRow>(
      `SELECT publication.pubname::text AS publication,
              pg_get_userbyid(publication.pubowner)::text AS owner,
              publication.puballtables AS all_tables,publication.pubinsert AS publish_insert,
              publication.pubupdate AS publish_update,publication.pubdelete AS publish_delete,
              publication.pubtruncate AS publish_truncate,publication.pubviaroot AS publish_via_partition_root,
              publication.pubgencols::text AS generated_columns
         FROM pg_catalog.pg_publication publication ORDER BY publication.pubname`,
    )).rows;
    const publicationRelations = (await client.query<CatalogRow>(
      `SELECT publication.pubname::text AS publication,namespace.nspname::text AS schema,
              relation.relname::text AS relation,
              COALESCE(publication_relation.prattrs::text,'')::text AS column_attributes,
              COALESCE(pg_get_expr(publication_relation.prqual,publication_relation.prrelid,true),'')::text AS row_filter
         FROM pg_catalog.pg_publication_rel publication_relation
         JOIN pg_catalog.pg_publication publication ON publication.oid=publication_relation.prpubid
         JOIN pg_catalog.pg_class relation ON relation.oid=publication_relation.prrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        ORDER BY publication.pubname,namespace.nspname,relation.relname`,
    )).rows;
    const publicationNamespaces = (await client.query<CatalogRow>(
      `SELECT publication.pubname::text AS publication,namespace.nspname::text AS schema
         FROM pg_catalog.pg_publication_namespace publication_namespace
         JOIN pg_catalog.pg_publication publication ON publication.oid=publication_namespace.pnpubid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=publication_namespace.pnnspid
        ORDER BY publication.pubname,namespace.nspname`,
    )).rows;
    const subscriptions = (await client.query<CatalogRow>(
      `SELECT subscription.subname::text AS subscription,
              pg_get_userbyid(subscription.subowner)::text AS owner,
              subscription.subenabled AS enabled,subscription.subbinary AS binary,
              subscription.substream::text AS streaming,
              subscription.subtwophasestate::text AS two_phase_state,
              subscription.subdisableonerr AS disable_on_error,
              subscription.subpasswordrequired AS password_required,
              subscription.subrunasowner AS run_as_owner,subscription.subfailover AS failover,
              encode(
                pg_catalog.sha256(pg_catalog.convert_to(COALESCE(subscription.subconninfo,''),'UTF8')),
                'hex'
              )::text AS connection_info_digest,
              COALESCE(subscription.subslotname::text,'')::text AS slot_name,
              subscription.subsynccommit::text AS synchronous_commit,
              ARRAY(SELECT publication::text FROM unnest(subscription.subpublications) publication ORDER BY publication)::text AS publications,
              subscription.suborigin::text AS origin,subscription.subskiplsn::text AS skip_lsn
         FROM pg_catalog.pg_subscription subscription
        WHERE subscription.subdbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
        ORDER BY subscription.subname`,
    )).rows;
    const subscriptionRelations = (await client.query<CatalogRow>(
      `SELECT subscription.subname::text AS subscription,namespace.nspname::text AS schema,
              relation.relname::text AS relation,subscription_relation.srsubstate::text AS state,
              COALESCE(subscription_relation.srsublsn::text,'')::text AS remote_lsn
         FROM pg_catalog.pg_subscription_rel subscription_relation
         JOIN pg_catalog.pg_subscription subscription ON subscription.oid=subscription_relation.srsubid
         JOIN pg_catalog.pg_class relation ON relation.oid=subscription_relation.srrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE subscription.subdbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
        ORDER BY subscription.subname,namespace.nspname,relation.relname`,
    )).rows;
    const rewriteRules = (await client.query<CatalogRow>(
      `SELECT namespace.nspname::text AS schema,relation.relname::text AS relation,
              rewrite.rulename::text AS rule,rewrite.ev_type::text AS event,
              rewrite.ev_enabled::text AS enabled,rewrite.is_instead AS instead,
              pg_catalog.pg_get_ruledef(rewrite.oid,true)::text AS definition
         FROM pg_catalog.pg_rewrite rewrite
         JOIN pg_catalog.pg_class relation ON relation.oid=rewrite.ev_class
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
          AND NOT (rewrite.rulename='_RETURN' AND relation.relkind IN ('v','m'))
        ORDER BY namespace.nspname,relation.relname,rewrite.rulename`,
    )).rows;
    const tables = await client.query<{ schema_name: string; table_name: string; qualified_name: string }>(
      `SELECT namespace.nspname AS schema_name,
              relation.relname AS table_name,
              format('%I.%I',namespace.nspname,relation.relname) AS qualified_name
         FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_(toast|temp)'
          AND relation.relkind IN ('r','p')
        ORDER BY namespace.nspname,relation.relname`,
    );
    const tableFingerprints: Array<CatalogRow & {
      readonly schema: string;
      readonly table: string;
      readonly rows: number;
      readonly digest: string;
    }> = [];
    for (const table of tables.rows) {
      // qualified_name is generated by PostgreSQL format(%I), never external input.
      const result = await client.query<{ row_count: string; row_digest: string }>(
        `SELECT count(*)::text AS row_count,
                md5(COALESCE(string_agg(md5(to_jsonb(source_row)::text),'' ORDER BY md5(to_jsonb(source_row)::text)),'')) AS row_digest
           FROM ${table.qualified_name} AS source_row`,
      );
      const row = result.rows[0];
      if (!row || !/^\d+$/u.test(row.row_count) || !/^[0-9a-f]{32}$/iu.test(row.row_digest)) {
        throw new Error("Protected performance database fingerprint is invalid");
      }
      tableFingerprints.push({
        schema: table.schema_name,
        table: table.table_name,
        rows: Number(row.row_count),
        digest: row.row_digest,
      });
    }
    await client.query("ROLLBACK");
    transactionOpen = false;
    const snapshot: ProtectedDatabaseSnapshot = {
      database,
      databaseMetadata,
      associatedRoles,
      associatedRoleMemberships,
      schemas,
      relations,
      columns,
      constraints,
      indexes,
      views,
      routines,
      triggers,
      policies,
      types,
      sequences,
      defaultPrivileges,
      extensions,
      descriptions,
      sharedDescriptions,
      securityLabels,
      sharedSecurityLabels,
      eventTriggers,
      publications,
      publicationRelations,
      publicationNamespaces,
      subscriptions,
      subscriptionRelations,
      rewriteRules,
      tableFingerprints,
    };
    const schemaObjects = schemas.length
      + associatedRoles.length
      + associatedRoleMemberships.length
      + relations.length
      + columns.length
      + constraints.length
      + indexes.length
      + views.length
      + routines.length
      + triggers.length
      + policies.length
      + types.length
      + sequences.length
      + defaultPrivileges.length
      + extensions.length
      + descriptions.length
      + sharedDescriptions.length
      + securityLabels.length
      + sharedSecurityLabels.length
      + eventTriggers.length
      + publications.length
      + publicationRelations.length
      + publicationNamespaces.length
      + subscriptions.length
      + subscriptionRelations.length
      + rewriteRules.length;
    return {
      fingerprintVersion: "protected-db-v3-full-cluster-role-structure-and-content",
      digest: digestProtectedDatabaseSnapshot(snapshot),
      tables: tableFingerprints.length,
      rows: tableFingerprints.reduce((total, table) => total + table.rows, 0),
      schemaObjects,
    };
  } finally {
    if (transactionOpen) await client.query("ROLLBACK").catch(() => undefined);
    client.release();
    await pool.end();
  }
}
