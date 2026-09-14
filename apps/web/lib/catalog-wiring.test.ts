import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const webRoot = path.resolve(import.meta.dirname, "..");
const source = readFileSync(path.join(webRoot, "components/nombramientos/catalog-view.tsx"), "utf8");

test("el catálogo conecta lectura, extensiones locales y configuración persistida", () => {
  for (const endpoint of [
    '"/v1/catalog/manage"',
    '"/v1/catalog"',
    '"/v1/catalog/departments"',
    '"/v1/catalog/offices"',
    '"/v1/tenant/settings"',
  ]) assert.ok(source.includes(endpoint), `falta ${endpoint}`);
  assert.match(source, /method: "POST", idempotent: true, idempotencyKey:/);
  assert.match(source, /method: "PATCH", idempotent: true, idempotencyKey:/);
  assert.match(source, /expectedVersion: item\.version/);
  assert.match(source, /expectedVersion: settingsQuery\.data!\.version/);
});

test("las fichas canónicas permanecen de solo lectura en la interfaz", () => {
  assert.match(source, /canManage=\{mayManageCatalog\}/);
  assert.match(source, /item\.localExtension && canManage \? <></);
  assert.match(source, /item\.localExtension \? labels\.local : labels\.canonical/);
  assert.match(source, /pattern="local\\\./);
  assert.doesNotMatch(source, /method: "DELETE"/);
});

test("un lector ve las extensiones locales sin controles de mutación", () => {
  assert.match(source, /function CatalogList\(\{ canManage,/);
  assert.match(source, /item\.localExtension && canManage/);
});

test("la superficie está localizada y no expone mensajes crudos del servidor", () => {
  assert.match(source, /const copy = \{/);
  assert.match(source, /\n  es: \{/);
  assert.match(source, /\n  en: \{/);
  assert.match(source, /\n  fr: \{/);
  assert.match(source, /localizedApiError\(error, locale\)/);
  assert.doesNotMatch(source, /error\.message|String\(error\)/);
});

test("las fichas exponen narrativa, procedencia y control normativo existentes", () => {
  assert.match(source, /readCatalogRichMetadata\(item, locale, normativeVersion\)/);
  assert.match(source, /details\.purpose/);
  assert.match(source, /details\.responsibilities/);
  assert.match(source, /details\.conditions/);
  assert.match(source, /details\.sourceRuleIds/);
  assert.match(source, /details\.sourceLocators/);
  assert.match(source, /details\.reviewStatus/);
  assert.match(source, /details\.catalogVersion/);
  assert.match(source, /rel="noreferrer noopener"/);
  assert.match(source, /workingTranslation/);
});

test("la interfaz no escribe metadatos normativos desde el contenedor abierto del backend", () => {
  const mutationArea = source.slice(source.indexOf("const createMutation"), source.indexOf("const catalog ="));
  assert.doesNotMatch(mutationArea, /purpose:|responsibilities:|conditions:|sourceLocators:|reviewStatus:|catalogVersion:/);
});

test("búsqueda y detalle son operables con teclado y responden en móvil", () => {
  assert.match(source, /htmlFor="catalog-search"/);
  assert.match(source, /aria-live="polite"/);
  assert.match(source, /<details className="group/);
  assert.match(source, /<summary aria-label=\{`\$\{labels\.details\}: \$\{displayName\}`\}/);
  assert.match(source, /focus-visible:ring-2/);
  assert.match(source, /sm:grid-cols-2/);
  assert.match(source, /min-w-0/);
});
