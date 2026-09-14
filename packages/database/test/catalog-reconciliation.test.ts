import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assertTenantCatalogReconciliationSafe,
  readTenantCatalogEvidence,
  tenantCatalogTarget,
  type CatalogReadQueryClient,
  type VersionedTenantCatalog,
} from "../src/catalog-reconciliation.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const reconciliationSource = readFileSync(path.join(packageRoot, "src", "catalog-reconciliation.ts"), "utf8");

const catalog = {
  version: "2025.1.0",
  departments: [
    {
      canonicalCode: "leadership",
      names: { es: "Liderazgo", en: "Leadership", fr: "Direction" },
      parentDepartmentCode: null,
      purpose: { es: "Dirigir", en: "Lead", fr: "Diriger" },
    },
    {
      canonicalCode: "youth",
      names: { es: "Jóvenes", en: "Youth", fr: "Jeunesse" },
      parentDepartmentCode: "leadership",
      purpose: { es: "Acompañar", en: "Support", fr: "Accompagner" },
    },
  ],
  offices: [
    {
      canonicalCode: "elder",
      departmentCode: "leadership",
      names: { es: "Anciano", en: "Elder", fr: "Ancien" },
      mechanism: "church_election",
      cardinality: { minimum: 1, maximum: null },
      conditions: [],
    },
  ],
} as const;

describe("versioned tenant catalog reconciliation evidence", () => {
  it("derives a deterministic target from all persisted metadata without hardcoded counts", () => {
    const target = tenantCatalogTarget(catalog);
    expect(target).toMatchObject({ version: "2025.1.0", departmentCount: 2, officeCount: 1 });
    expect(target.catalogSha256).toMatch(/^sha256:[0-9a-f]{64}$/u);

    const reorderedObjectKeys = {
      ...catalog,
      departments: catalog.departments.map((department) => ({
        purpose: department.purpose,
        parentDepartmentCode: department.parentDepartmentCode,
        names: department.names,
        canonicalCode: department.canonicalCode,
      })),
      offices: catalog.offices.map((office) => ({
        conditions: office.conditions,
        cardinality: office.cardinality,
        mechanism: office.mechanism,
        names: office.names,
        departmentCode: office.departmentCode,
        canonicalCode: office.canonicalCode,
      })),
    } as const;
    expect(tenantCatalogTarget(reorderedObjectKeys)).toEqual(target);
  });

  it("attests exact version, counts, relationships and complete JSON metadata", async () => {
    const evidence = await readTenantCatalogEvidence(catalogReader(), catalog);
    expect(evidence).toMatchObject({
      targetVersion: "2025.1.0",
      observedVersion: "2025.1.0",
      expectedDepartmentCount: 2,
      observedDepartmentCount: 2,
      expectedOfficeCount: 1,
      observedOfficeCount: 1,
      localExtensionCollisionCount: 0,
      invalidRowVersionCount: 0,
      mismatchCount: 0,
    });
    expect(evidence.observedCatalogSha256).toBe(evidence.targetCatalogSha256);
  });

  it("detects metadata drift and canonical-code collisions without returning catalog content", async () => {
    const metadataDrift = await readTenantCatalogEvidence(catalogReader({ metadataDrift: true }), catalog);
    expect(metadataDrift.mismatchCount).toBeGreaterThan(0);
    expect(metadataDrift.blockingMismatchCount).toBe(0);
    expect(() => assertTenantCatalogReconciliationSafe(metadataDrift)).not.toThrow();
    expect(metadataDrift.observedCatalogSha256).not.toBe(metadataDrift.targetCatalogSha256);

    const collision = await readTenantCatalogEvidence(catalogReader({ collisionCount: 1 }), catalog);
    expect(collision).toMatchObject({
      localExtensionCollisionCount: 1,
      blockingMismatchCount: 1,
      mismatchCount: 1,
    });
    expect(() => assertTenantCatalogReconciliationSafe(collision)).toThrow(/not safely reconcilable/u);
    expect(JSON.stringify(collision)).not.toContain("Liderazgo");
    expect(JSON.stringify(collision)).not.toContain("elder");
  });

  it("uses non-blocking advisory acquisition and bounded PostgreSQL lock waits", () => {
    const transaction = reconciliationSource.indexOf('await client.query("BEGIN")');
    const lockTimeout = reconciliationSource.indexOf("SET LOCAL lock_timeout='5s'", transaction);
    const statementTimeout = reconciliationSource.indexOf("SET LOCAL statement_timeout='30s'", transaction);
    const advisory = reconciliationSource.indexOf("pg_try_advisory_xact_lock", transaction);
    const tableLock = reconciliationSource.indexOf("LOCK TABLE tenant_settings,departments,offices", transaction);
    expect(lockTimeout).toBeGreaterThan(transaction);
    expect(statementTimeout).toBeGreaterThan(lockTimeout);
    expect(advisory).toBeGreaterThan(statementTimeout);
    expect(tableLock).toBeGreaterThan(advisory);
    expect(reconciliationSource).not.toContain("SELECT pg_advisory_xact_lock(");
  });

  it("rejects dangling references and duplicate canonical codes before hashing or writing", () => {
    expect(() => tenantCatalogTarget({
      ...catalog,
      offices: [{ ...catalog.offices[0], departmentCode: "missing" }],
    })).toThrow(/unknown office department/u);
    expect(() => tenantCatalogTarget({
      ...catalog,
      departments: [...catalog.departments, catalog.departments[0]],
    })).toThrow(/duplicate department/u);
  });
});

function catalogReader(options: {
  readonly metadataDrift?: boolean;
  readonly collisionCount?: number;
} = {}): CatalogReadQueryClient {
  return {
    query: async <Row>(text: string) => {
      if (text.includes("SELECT catalog_version")) {
        return result<Row>([{ catalog_version: catalog.version }]);
      }
      if (text.includes("FROM departments child")) {
        return result<Row>(catalog.departments.map((department, index) => ({
          canonical_code: department.canonicalCode,
          names: department.names,
          parent_department_code: department.parentDepartmentCode,
          catalog_metadata: options.metadataDrift && index === 0
            ? { ...department, purpose: { ...department.purpose, es: "Alterado" } }
            : department,
          active: true,
          sort_order: index,
          version: 1,
        })).sort((left, right) => left.canonical_code.localeCompare(right.canonical_code)));
      }
      if (text.includes("FROM offices office")) {
        return result<Row>(catalog.offices.map((office) => ({
          canonical_code: office.canonicalCode,
          department_code: office.departmentCode,
          names: office.names,
          appointment_mechanism: office.mechanism,
          cardinality: office.cardinality.maximum ?? Math.max(1, office.cardinality.minimum),
          catalog_metadata: office,
          active: true,
          version: 1,
        })));
      }
      if (text.includes("local_extension AND canonical_code=ANY")) {
        return result<Row>([{ count: options.collisionCount ?? 0 }]);
      }
      throw new Error("Unexpected catalog evidence query");
    },
  } as CatalogReadQueryClient;
}

function result<Row>(rows: readonly unknown[]): { readonly rows: readonly Row[]; readonly rowCount: number } {
  return { rows: rows as readonly Row[], rowCount: rows.length };
}
