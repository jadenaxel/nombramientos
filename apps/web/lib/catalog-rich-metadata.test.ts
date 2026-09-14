import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  CATALOG_PACKAGE_VERSION,
  catalogPackage2025,
  churchManualSampleOfficeCodes2025,
  type CatalogPackage,
  validateCatalogPackage,
} from "@nombramientos/catalog";

import { localizedCatalogText, readCatalogRichMetadata } from "./catalog-metadata.ts";

const repositoryRoot = path.resolve(import.meta.dirname, "../../..");

test("localiza metadatos del catálogo con fallback sin inventar traducciones", () => {
  assert.equal(localizedCatalogText({ es: "Propósito", en: "Purpose", fr: "But" }, "fr"), "But");
  assert.equal(localizedCatalogText({ es: "Propósito" }, "en"), "Propósito");
  assert.equal(localizedCatalogText({ de: "Zweck" }, "es"), null);
});

test("proyecta la ficha normativa existente y conserva la versión del paquete", () => {
  const metadata = readCatalogRichMetadata({
    purpose: { es: "Servir", en: "Serve", fr: "Servir" },
    responsibilities: [{ es: "Coordinar", en: "Coordinate", fr: "Coordonner" }],
    conditions: [{ es: "Revisión local", en: "Local review", fr: "Examen local" }],
    notes: { es: "Resumen operativo", en: "Operating summary", fr: "Résumé opérationnel" },
    aliases: [{ es: "Alias", en: "Alias", fr: "Alias" }],
    sourceRuleIds: ["NM-001", "NM-009", 42],
    reviewStatus: "verified_primary_source",
    catalogVersion: "catalog-v2025.1.0",
    territory: "worldwide_manual_subject_to_applicable_regional_supplements",
    linkedBaseOfficeCode: "elder",
    applicableByDefault: true,
  }, "es", "fallback-version");

  assert.equal(metadata.purpose, "Servir");
  assert.deepEqual(metadata.responsibilities, ["Coordinar"]);
  assert.deepEqual(metadata.conditions, ["Revisión local"]);
  assert.deepEqual(metadata.sourceRuleIds, ["NM-001", "NM-009"]);
  assert.equal(metadata.reviewStatus, "verified_primary_source");
  assert.equal(metadata.catalogVersion, "catalog-v2025.1.0");
  assert.equal(metadata.linkedBaseOfficeCode, "elder");
  assert.equal(metadata.applicableByDefault, true);
});

test("solo materializa referencias HTTPS bien formadas y descarta metadatos inesperados", () => {
  const metadata = readCatalogRichMetadata({
    sourceLocators: [
      {
        sourceId: "SDA_CM_2025_EN",
        chapter: "Chapter 8",
        section: "Elders",
        printedPages: [80, 81, -1, "82"],
        sourceLanguage: "en",
        url: "https://example.test/manual.pdf",
      },
      { sourceId: "BAD_JS", url: "javascript:alert(1)" },
      { sourceId: 4, url: "https://example.test/ignored" },
    ],
    responsibilities: "not-an-array",
    reviewStatus: "official_translation",
  }, "en", "tenant-catalog-v1");

  assert.equal(metadata.sourceLocators.length, 2);
  assert.equal(metadata.sourceLocators[0]?.url, "https://example.test/manual.pdf");
  assert.deepEqual(metadata.sourceLocators[0]?.printedPages, [80, 81]);
  assert.equal(metadata.sourceLocators[1]?.url, null);
  assert.deepEqual(metadata.responsibilities, []);
  assert.equal(metadata.reviewStatus, null);
  assert.equal(metadata.catalogVersion, "tenant-catalog-v1");
});

test("el paquete 2025 cubre la lista oficial de cargos y mantiene trazabilidad estructurada", () => {
  assert.deepEqual(validateCatalogPackage(catalogPackage2025), []);
  assert.equal(CATALOG_PACKAGE_VERSION, "2025.1.0");
  assert.equal(catalogPackage2025.version, CATALOG_PACKAGE_VERSION);
  assert.equal(catalogPackage2025.status, "draft", "la revisión estable no suplanta la validación territorial pendiente");

  const byCode = new Map(catalogPackage2025.offices.map((office) => [office.canonicalCode, office]));
  for (const code of churchManualSampleOfficeCodes2025) {
    assert.ok(byCode.has(code), `falta el cargo oficial ${code}`);
  }

  const investment = byCode.get("sabbath_school_investment_secretary");
  assert.equal(investment?.names.en, "Sabbath School Investment secretary");
  assert.deepEqual(investment?.sourceLocators.map(({ chapter, section, printedPages }) => ({ chapter, section, printedPages })), [
    {
      chapter: "Chapter 9 — Local Church Officers and Organizations",
      section: "Officers of the Sabbath School Council; Sabbath School Superintendent and Other Sabbath School Officers",
      printedPages: [107, 108],
    },
    {
      chapter: "Chapter 10 Notes",
      section: "1. Sample List of Church Leaders (see p. 122).",
      printedPages: [191, 192],
    },
  ]);
  assert.equal(investment?.reportsToOfficeCode, "sabbath_school_superintendent");

  const prayer = byCode.get("prayer_ministries_coordinator");
  assert.equal(prayer?.names.en, "Prayer Ministries director");
  assert.equal(prayer?.reviewStatus, "verified_primary_source");
  assert.deepEqual(prayer?.sourceLocators[0]?.printedPages, [191, 192]);
  assert.equal(prayer?.sourceLocators[0]?.chapter, "Chapter 10 Notes");
  assert.equal(prayer?.sourceLocators[0]?.section, "1. Sample List of Church Leaders (see p. 122).");

  const pastor = byCode.get("pastor");
  assert.equal(pastor?.sourceLocators[0]?.chapter, "Chapter 10 — Elections");
  assert.deepEqual(pastor?.sourceLocators[0]?.printedPages, [122]);

  for (const office of catalogPackage2025.offices) {
    for (const locator of office.sourceLocators) {
      assert.notEqual(locator.chapter, "Chapter 8 — Local Church Officers and Organizations");
      assert.notEqual(locator.chapter, "Church Manual Notes");
    }
  }
});

test("cada ficha tiene responsabilidad localizada y las dependencias apuntan a cargos existentes", () => {
  const officeCodes = new Set(catalogPackage2025.offices.map((office) => office.canonicalCode));
  const obsoleteGeneric = "Carry out responsibilities described by the applicable source and the tenant's approved configuration.";

  for (const office of catalogPackage2025.offices) {
    assert.ok(office.responsibilities.length >= 2, `${office.canonicalCode} no tiene una lista verificable de responsabilidades`);
    for (const responsibility of office.responsibilities) {
      assert.ok(responsibility.es.trim());
      assert.ok(responsibility.en.trim());
      assert.ok(responsibility.fr.trim());
      assert.notEqual(responsibility.en, obsoleteGeneric);
      assert.notDeepEqual(responsibility, office.purpose, `${office.canonicalCode} copia el propósito como responsabilidad`);
    }
    if (!office.applicableByDefault) assert.ok(office.conditions.length > 0, `${office.canonicalCode} no limita su aplicabilidad opcional`);
    if (office.reportsToOfficeCode) {
      assert.ok(officeCodes.has(office.reportsToOfficeCode), `${office.canonicalCode} depende de un cargo desconocido`);
      assert.notEqual(office.reportsToOfficeCode, office.canonicalCode);
    }
  }
});

test("los validadores rechazan regresiones de responsabilidad y capítulo", () => {
  const elderIndex = catalogPackage2025.offices.findIndex(({ canonicalCode }) => canonicalCode === "elder");
  assert.ok(elderIndex >= 0);
  const elder = catalogPackage2025.offices[elderIndex]!;
  const repeatedPurpose = {
    ...catalogPackage2025,
    offices: catalogPackage2025.offices.map((office, index) => index === elderIndex
      ? { ...office, responsibilities: [office.purpose] }
      : office),
  } as CatalogPackage;
  assert.ok(validateCatalogPackage(repeatedPurpose).some((error) => error.includes("repeats its purpose")));

  const purposeAsLead = {
    ...catalogPackage2025,
    offices: catalogPackage2025.offices.map((office, index) => index === elderIndex
      ? {
          ...office,
          responsibilities: [{
            es: `${office.purpose.es} Alcance adicional.`,
            en: `${office.purpose.en} Additional scope.`,
            fr: `${office.purpose.fr} Portée supplémentaire.`,
          }],
        }
      : office),
  } as CatalogPackage;
  assert.ok(validateCatalogPackage(purposeAsLead).some((error) => error.includes("prefixes a responsibility")));

  const falseChapter = {
    ...catalogPackage2025,
    offices: catalogPackage2025.offices.map((office, index) => index === elderIndex
      ? { ...office, sourceLocators: [{ ...elder.sourceLocators[0]!, chapter: "Chapter 8 — Local Church Officers and Organizations" }] }
      : office),
  } as CatalogPackage;
  assert.ok(validateCatalogPackage(falseChapter).some((error) => error.includes("False chapter locator")));

  const prayerIndex = catalogPackage2025.offices.findIndex(({ canonicalCode }) => canonicalCode === "prayer_ministries_coordinator");
  assert.ok(prayerIndex >= 0);
  const prayer = catalogPackage2025.offices[prayerIndex]!;
  const falseNotesChapter = {
    ...catalogPackage2025,
    offices: catalogPackage2025.offices.map((office, index) => index === prayerIndex
      ? { ...office, sourceLocators: [{ ...prayer.sourceLocators[0]!, chapter: "Church Manual Notes" }] }
      : office),
  } as CatalogPackage;
  assert.ok(validateCatalogPackage(falseNotesChapter).some((error) => error.includes("False chapter locator")));
});

test("la matriz marca la evidencia local sin cerrar validaciones denominacionales", () => {
  const locallyVerifiable = catalogPackage2025.normativeRules.filter(({ classification }) => classification !== "pendiente_validacion");
  assert.ok(locallyVerifiable.length > 0);
  for (const rule of locallyVerifiable) {
    assert.equal(rule.implementationStatus, "verified_with_evidence", `${rule.id} conserva un estado local obsoleto`);
    for (const reference of rule.implementationRefs.filter((value) => value.includes("/"))) {
      assert.ok(existsSync(path.resolve(repositoryRoot, reference)), `${rule.id} referencia implementación inexistente: ${reference}`);
    }
    const concreteTests = rule.testRefs.filter((reference) => /\.(?:test|spec)\.[cm]?[jt]sx?$/u.test(reference));
    assert.ok(concreteTests.length > 0, `${rule.id} no declara prueba automatizada concreta`);
    for (const reference of concreteTests) {
      assert.ok(existsSync(path.resolve(repositoryRoot, reference)), `${rule.id} referencia prueba inexistente: ${reference}`);
    }
  }

  const external = catalogPackage2025.normativeRules.find(({ id }) => id === "PEND-001");
  assert.equal(external?.implementationStatus, "blocked_pending_validation");
  assert.equal(external?.classification, "pendiente_validacion");
  assert.ok(catalogPackage2025.externalValidationRequired.length > 0);
});

test("el aprovisionamiento consume el paquete estable y no el alias heredado", () => {
  for (const reference of [
    "packages/database/scripts/process-provisioning-jobs.ts",
    "packages/database/scripts/provision-tenants.ts",
  ]) {
    const source = readFileSync(path.resolve(repositoryRoot, reference), "utf8");
    assert.match(source, /catalogPackage2025/u);
    assert.doesNotMatch(source, /catalogPackage2025Draft/u);
  }
});
