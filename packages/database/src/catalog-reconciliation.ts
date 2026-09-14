import { createHash } from "node:crypto";
import type { Pool, QueryResultRow } from "pg";

/**
 * Persistence-facing subset of the versioned catalog package. Keeping this
 * structural contract here lets provisioning tests use deliberately small
 * catalogs while production callers pass the validated package unchanged.
 */
export interface VersionedTenantCatalog {
  readonly version: string;
  readonly departments: readonly {
    readonly canonicalCode: string;
    readonly names: { readonly es: string; readonly en: string; readonly fr: string };
    readonly parentDepartmentCode: string | null;
  }[];
  readonly offices: readonly {
    readonly canonicalCode: string;
    readonly departmentCode: string;
    readonly names: { readonly es: string; readonly en: string; readonly fr: string };
    readonly mechanism: string;
    readonly cardinality: {
      readonly minimum: number;
      readonly maximum: number | null;
    };
  }[];
}

export interface TenantCatalogTarget {
  readonly version: string;
  readonly departmentCount: number;
  readonly officeCount: number;
  readonly catalogSha256: string;
}

export interface TenantCatalogEvidence {
  readonly targetVersion: string;
  readonly observedVersion: string | null;
  readonly expectedDepartmentCount: number;
  readonly observedDepartmentCount: number;
  readonly missingDepartmentCount: number;
  readonly unexpectedDepartmentCount: number;
  readonly expectedOfficeCount: number;
  readonly observedOfficeCount: number;
  readonly missingOfficeCount: number;
  readonly unexpectedOfficeCount: number;
  readonly targetCatalogSha256: string;
  readonly observedCatalogSha256: string;
  readonly localExtensionCollisionCount: number;
  readonly invalidRowVersionCount: number;
  readonly blockingMismatchCount: number;
  readonly mismatchCount: number;
}

export interface TenantCatalogReconciliationResult extends TenantCatalogEvidence {
  readonly mutationCount: number;
  readonly changed: boolean;
}

interface CatalogDepartmentSnapshot {
  readonly canonicalCode: string;
  readonly names: unknown;
  readonly parentDepartmentCode: string | null;
  readonly catalogMetadata: unknown;
  readonly active: boolean;
  readonly sortOrder: number;
}

interface CatalogOfficeSnapshot {
  readonly canonicalCode: string;
  readonly departmentCode: string;
  readonly names: unknown;
  readonly appointmentMechanism: string;
  readonly cardinality: number;
  readonly catalogMetadata: unknown;
  readonly active: boolean;
}

interface CatalogSnapshot {
  readonly version: string | null;
  readonly departments: readonly CatalogDepartmentSnapshot[];
  readonly offices: readonly CatalogOfficeSnapshot[];
}

interface DepartmentRow extends QueryResultRow {
  readonly canonical_code: string;
  readonly names: unknown;
  readonly parent_department_code: string | null;
  readonly catalog_metadata: unknown;
  readonly active: boolean;
  readonly sort_order: number;
  readonly version: number;
}

interface OfficeRow extends QueryResultRow {
  readonly canonical_code: string;
  readonly department_code: string | null;
  readonly names: unknown;
  readonly appointment_mechanism: string;
  readonly cardinality: number;
  readonly catalog_metadata: unknown;
  readonly active: boolean;
  readonly version: number;
}

export interface CatalogReadQueryClient {
  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<{ readonly rows: readonly Row[]; readonly rowCount: number | null }>;
}

export function tenantCatalogTarget(catalog: VersionedTenantCatalog): TenantCatalogTarget {
  const snapshot = expectedCatalogSnapshot(catalog);
  return {
    version: catalog.version,
    departmentCount: snapshot.departments.length,
    officeCount: snapshot.offices.length,
    catalogSha256: digestCatalogSnapshot(snapshot),
  };
}

/** Read-only exact attestation. Tenant-local extension rows are preserved but
 * cannot shadow a canonical code from the versioned package. */
export async function readTenantCatalogEvidence(
  client: CatalogReadQueryClient,
  catalog: VersionedTenantCatalog,
): Promise<TenantCatalogEvidence> {
  const expected = expectedCatalogSnapshot(catalog);
  const [settings, departments, offices, collisions] = await Promise.all([
    client.query<{ catalog_version: string }>(
      "SELECT catalog_version FROM tenant_settings WHERE singleton=true",
    ),
    client.query<DepartmentRow>(
      `SELECT child.canonical_code,child.names,parent.canonical_code AS parent_department_code,
              child.catalog_metadata,child.active,child.sort_order,child.version
         FROM departments child
         LEFT JOIN departments parent ON parent.id=child.parent_id
        WHERE NOT child.local_extension
        ORDER BY child.canonical_code`,
    ),
    client.query<OfficeRow>(
      `SELECT office.canonical_code,department.canonical_code AS department_code,
              office.names,office.appointment_mechanism,office.cardinality,
              office.catalog_metadata,office.active,office.version
         FROM offices office
         LEFT JOIN departments department ON department.id=office.department_id
        WHERE NOT office.local_extension
        ORDER BY office.canonical_code`,
    ),
    client.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM departments
           WHERE local_extension AND canonical_code=ANY($1::text[]))
         +
         (SELECT count(*) FROM offices
           WHERE local_extension AND canonical_code=ANY($2::text[]))
       )::int AS count`,
      [
        catalog.departments.map(({ canonicalCode }) => canonicalCode),
        catalog.offices.map(({ canonicalCode }) => canonicalCode),
      ],
    ),
  ]);
  const observed: CatalogSnapshot = {
    version: settings.rows.length === 1 ? settings.rows[0]!.catalog_version : null,
    departments: departments.rows.map((row) => ({
      canonicalCode: row.canonical_code,
      names: normalizeJson(row.names),
      parentDepartmentCode: row.parent_department_code,
      catalogMetadata: normalizeJson(row.catalog_metadata),
      active: row.active,
      sortOrder: row.sort_order,
    })),
    offices: offices.rows.map((row) => ({
      canonicalCode: row.canonical_code,
      departmentCode: row.department_code ?? "",
      names: normalizeJson(row.names),
      appointmentMechanism: row.appointment_mechanism,
      cardinality: row.cardinality,
      catalogMetadata: normalizeJson(row.catalog_metadata),
      active: row.active,
    })),
  };
  const targetCatalogSha256 = digestCatalogSnapshot(expected);
  const observedCatalogSha256 = digestCatalogSnapshot(observed);
  const expectedDepartmentCodes = new Set(expected.departments.map(({ canonicalCode }) => canonicalCode));
  const observedDepartmentCodes = new Set(observed.departments.map(({ canonicalCode }) => canonicalCode));
  const expectedOfficeCodes = new Set(expected.offices.map(({ canonicalCode }) => canonicalCode));
  const observedOfficeCodes = new Set(observed.offices.map(({ canonicalCode }) => canonicalCode));
  const missingDepartmentCount = differenceCount(expectedDepartmentCodes, observedDepartmentCodes);
  const unexpectedDepartmentCount = differenceCount(observedDepartmentCodes, expectedDepartmentCodes);
  const missingOfficeCount = differenceCount(expectedOfficeCodes, observedOfficeCodes);
  const unexpectedOfficeCount = differenceCount(observedOfficeCodes, expectedOfficeCodes);
  const localExtensionCollisionCount = collisions.rows[0]?.count ?? 0;
  const invalidRowVersionCount = departments.rows.filter(({ version }) => !Number.isInteger(version) || version < 1).length
    + offices.rows.filter(({ version }) => !Number.isInteger(version) || version < 1).length;
  const blockingMismatchCount = localExtensionCollisionCount
    + unexpectedDepartmentCount
    + unexpectedOfficeCount;
  const mismatchCount = Number(settings.rows.length !== 1)
    + Number(observed.version !== expected.version)
    + Number(observed.departments.length !== expected.departments.length)
    + Number(observed.offices.length !== expected.offices.length)
    + Number(observedCatalogSha256 !== targetCatalogSha256)
    + localExtensionCollisionCount
    + invalidRowVersionCount;
  return {
    targetVersion: catalog.version,
    observedVersion: observed.version,
    expectedDepartmentCount: expected.departments.length,
    observedDepartmentCount: observed.departments.length,
    missingDepartmentCount,
    unexpectedDepartmentCount,
    expectedOfficeCount: expected.offices.length,
    observedOfficeCount: observed.offices.length,
    missingOfficeCount,
    unexpectedOfficeCount,
    targetCatalogSha256,
    observedCatalogSha256,
    localExtensionCollisionCount,
    invalidRowVersionCount,
    blockingMismatchCount,
    mismatchCount,
  };
}

export function assertTenantCatalogReconciliationSafe(evidence: TenantCatalogEvidence): void {
  if (evidence.blockingMismatchCount !== 0) {
    throw new Error("Tenant catalog is not safely reconcilable without an explicit canonical retirement or collision decision");
  }
}

/**
 * Installs or upgrades only canonical configuration rows. IDs are never
 * replaced, local extensions are never mutated, and an unexpected canonical
 * row causes rollback instead of an implicit destructive retirement.
 */
export async function reconcileTenantCatalog(
  pool: Pick<Pool, "connect">,
  catalog: VersionedTenantCatalog,
): Promise<TenantCatalogReconciliationResult> {
  assertVersionedTenantCatalog(catalog);
  const client = await pool.connect();
  let mutationCount = 0;
  try {
    await client.query("BEGIN");
    await client.query("SET LOCAL lock_timeout='5s'");
    await client.query("SET LOCAL statement_timeout='30s'");
    const advisoryLock = await client.query<{ acquired: boolean }>(
      "SELECT pg_try_advisory_xact_lock(hashtextextended('nombramientos-catalog-reconciliation:' || current_database(), 0)) AS acquired",
    );
    if (!advisoryLock.rows[0]?.acquired) {
      throw new Error("Tenant catalog reconciliation boundary is already held");
    }
    await client.query("LOCK TABLE tenant_settings,departments,offices IN SHARE ROW EXCLUSIVE MODE");
    const before = await readTenantCatalogEvidence({
      query: async <Row extends QueryResultRow>(text: string, values?: readonly unknown[]) =>
        values === undefined
          ? await client.query<Row>(text)
          : await client.query<Row>(text, [...values]),
    }, catalog);
    assertTenantCatalogReconciliationSafe(before);

    for (const [index, department] of catalog.departments.entries()) {
      const result = await client.query(
        `INSERT INTO departments AS target(
           canonical_code,names,parent_id,local_extension,catalog_metadata,active,sort_order,version
         ) VALUES ($1,$2,NULL,false,$3,true,$4,1)
         ON CONFLICT(canonical_code) DO UPDATE SET
           names=EXCLUDED.names,
           catalog_metadata=EXCLUDED.catalog_metadata,
           active=true,
           sort_order=EXCLUDED.sort_order,
           version=CASE WHEN target.version < 1 THEN 1 ELSE target.version+1 END,
           updated_at=clock_timestamp()
         WHERE NOT target.local_extension AND (
           target.names IS DISTINCT FROM EXCLUDED.names
           OR target.catalog_metadata IS DISTINCT FROM EXCLUDED.catalog_metadata
           OR NOT target.active
           OR target.sort_order IS DISTINCT FROM EXCLUDED.sort_order
           OR target.version < 1
         )`,
        [department.canonicalCode, department.names, normalizeJson(department), index],
      );
      mutationCount += result.rowCount ?? 0;
    }

    for (const department of catalog.departments) {
      const result = department.parentDepartmentCode === null
        ? await client.query(
          `UPDATE departments
              SET parent_id=NULL,version=version+1,updated_at=clock_timestamp()
            WHERE canonical_code=$1 AND NOT local_extension AND parent_id IS NOT NULL`,
          [department.canonicalCode],
        )
        : await client.query(
          `UPDATE departments child
              SET parent_id=parent.id,version=child.version+1,updated_at=clock_timestamp()
             FROM departments parent
            WHERE child.canonical_code=$1 AND NOT child.local_extension
              AND parent.canonical_code=$2 AND NOT parent.local_extension
              AND child.parent_id IS DISTINCT FROM parent.id`,
          [department.canonicalCode, department.parentDepartmentCode],
        );
      mutationCount += result.rowCount ?? 0;
    }

    for (const office of catalog.offices) {
      const cardinality = office.cardinality.maximum ?? Math.max(1, office.cardinality.minimum);
      const result = await client.query(
        `INSERT INTO offices AS target(
           department_id,canonical_code,names,appointment_mechanism,cardinality,
           local_extension,catalog_metadata,active,version
         ) SELECT department.id,$1,$2,$3,$4,false,$5,true,1
             FROM departments department
            WHERE department.canonical_code=$6 AND NOT department.local_extension
         ON CONFLICT(canonical_code) DO UPDATE SET
           department_id=EXCLUDED.department_id,
           names=EXCLUDED.names,
           appointment_mechanism=EXCLUDED.appointment_mechanism,
           cardinality=EXCLUDED.cardinality,
           catalog_metadata=EXCLUDED.catalog_metadata,
           active=true,
           version=CASE WHEN target.version < 1 THEN 1 ELSE target.version+1 END,
           updated_at=clock_timestamp()
         WHERE NOT target.local_extension AND (
           target.department_id IS DISTINCT FROM EXCLUDED.department_id
           OR target.names IS DISTINCT FROM EXCLUDED.names
           OR target.appointment_mechanism IS DISTINCT FROM EXCLUDED.appointment_mechanism
           OR target.cardinality IS DISTINCT FROM EXCLUDED.cardinality
           OR target.catalog_metadata IS DISTINCT FROM EXCLUDED.catalog_metadata
           OR NOT target.active
           OR target.version < 1
         )`,
        [
          office.canonicalCode,
          office.names,
          office.mechanism,
          cardinality,
          normalizeJson(office),
          office.departmentCode,
        ],
      );
      mutationCount += result.rowCount ?? 0;
    }

    const settings = await client.query(
      `UPDATE tenant_settings
          SET catalog_version=$1,version=version+1,updated_at=clock_timestamp()
        WHERE singleton=true AND catalog_version IS DISTINCT FROM $1`,
      [catalog.version],
    );
    mutationCount += settings.rowCount ?? 0;

    const evidence = await readTenantCatalogEvidence({
      query: async <Row extends QueryResultRow>(text: string, values?: readonly unknown[]) =>
        values === undefined
          ? await client.query<Row>(text)
          : await client.query<Row>(text, [...values]),
    }, catalog);
    if (evidence.mismatchCount !== 0) {
      throw new Error("Tenant canonical catalog failed exact post-reconciliation attestation");
    }
    await client.query("COMMIT");
    return { ...evidence, mutationCount, changed: mutationCount > 0 };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function assertVersionedTenantCatalog(catalog: VersionedTenantCatalog): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(catalog.version)) {
    throw new Error("Versioned tenant catalog has an invalid version identifier");
  }
  if (catalog.departments.length === 0 || catalog.offices.length === 0) {
    throw new Error("Versioned tenant catalog must contain departments and offices");
  }
  const departmentCodes = new Set<string>();
  for (const department of catalog.departments) {
    assertCanonicalCode(department.canonicalCode);
    assertLocalizedNames(department.names);
    if (departmentCodes.has(department.canonicalCode)) {
      throw new Error("Versioned tenant catalog has a duplicate department code");
    }
    departmentCodes.add(department.canonicalCode);
  }
  for (const department of catalog.departments) {
    if (department.parentDepartmentCode !== null && !departmentCodes.has(department.parentDepartmentCode)) {
      throw new Error("Versioned tenant catalog references an unknown parent department");
    }
  }
  const officeCodes = new Set<string>();
  for (const office of catalog.offices) {
    assertCanonicalCode(office.canonicalCode);
    assertLocalizedNames(office.names);
    if (officeCodes.has(office.canonicalCode)) {
      throw new Error("Versioned tenant catalog has a duplicate office code");
    }
    officeCodes.add(office.canonicalCode);
    if (!departmentCodes.has(office.departmentCode)) {
      throw new Error("Versioned tenant catalog references an unknown office department");
    }
    if (!/^[a-z][a-z0-9_]{0,126}$/u.test(office.mechanism)) {
      throw new Error("Versioned tenant catalog has an invalid appointment mechanism");
    }
    if (!Number.isInteger(office.cardinality.minimum) || office.cardinality.minimum < 0) {
      throw new Error("Versioned tenant catalog has an invalid minimum cardinality");
    }
    if (office.cardinality.maximum !== null
      && (!Number.isInteger(office.cardinality.maximum) || office.cardinality.maximum < 1)) {
      throw new Error("Versioned tenant catalog has an invalid maximum cardinality");
    }
    if (office.cardinality.maximum !== null
      && office.cardinality.maximum < office.cardinality.minimum) {
      throw new Error("Versioned tenant catalog maximum cardinality is below its minimum");
    }
  }
}

function assertLocalizedNames(names: { readonly es: string; readonly en: string; readonly fr: string }): void {
  if ([names.es, names.en, names.fr].some((name) => name.trim().length === 0 || name.length > 240)) {
    throw new Error("Versioned tenant catalog has an invalid localized name");
  }
}

function assertCanonicalCode(code: string): void {
  if (!/^[a-z][a-z0-9_]{0,126}$/u.test(code)) {
    throw new Error("Versioned tenant catalog has an invalid canonical code");
  }
}

function expectedCatalogSnapshot(catalog: VersionedTenantCatalog): CatalogSnapshot {
  assertVersionedTenantCatalog(catalog);
  return {
    version: catalog.version,
    departments: catalog.departments.map((department, index) => ({
      canonicalCode: department.canonicalCode,
      names: normalizeJson(department.names),
      parentDepartmentCode: department.parentDepartmentCode,
      catalogMetadata: normalizeJson(department),
      active: true,
      sortOrder: index,
    })).sort(compareCanonicalCode),
    offices: catalog.offices.map((office) => ({
      canonicalCode: office.canonicalCode,
      departmentCode: office.departmentCode,
      names: normalizeJson(office.names),
      appointmentMechanism: office.mechanism,
      cardinality: office.cardinality.maximum ?? Math.max(1, office.cardinality.minimum),
      catalogMetadata: normalizeJson(office),
      active: true,
    })).sort(compareCanonicalCode),
  };
}

function compareCanonicalCode(
  left: { readonly canonicalCode: string },
  right: { readonly canonicalCode: string },
): number {
  return left.canonicalCode < right.canonicalCode ? -1 : Number(left.canonicalCode > right.canonicalCode);
}

function digestCatalogSnapshot(snapshot: CatalogSnapshot): string {
  return `sha256:${createHash("sha256").update(canonicalJson(snapshot), "utf8").digest("hex")}`;
}

function normalizeJson(value: unknown): unknown {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new Error("Versioned tenant catalog contains a non-JSON value");
  return JSON.parse(serialized) as unknown;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

function differenceCount(left: ReadonlySet<string>, right: ReadonlySet<string>): number {
  let count = 0;
  for (const value of left) count += Number(!right.has(value));
  return count;
}
