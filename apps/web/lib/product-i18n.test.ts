import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import path from "node:path";
import ts from "typescript";

import { getMessage, messages } from "@nombramientos/i18n";

import { formatIcuMessage } from "./icu-message.ts";

const message = (locale: "es" | "en" | "fr", key: Parameters<typeof getMessage>[1], values: Readonly<Record<string, string | number>>) =>
  formatIcuMessage(locale, getMessage(locale, key), values);

test("formats ICU plural branches in Spanish, English and French", () => {
  assert.equal(message("es", "participation.pendingCount", { count: 1 }), "1 persona pendiente");
  assert.equal(message("es", "participation.pendingCount", { count: 2 }), "2 personas pendientes");
  assert.equal(message("en", "participation.pendingCount", { count: 1 }), "1 person pending");
  assert.equal(message("en", "participation.pendingCount", { count: 2 }), "2 people pending");
  assert.equal(message("fr", "participation.pendingCount", { count: 1 }), "1 personne en attente");
  assert.equal(message("fr", "participation.pendingCount", { count: 2 }), "2 personnes en attente");
});

test("formats plurals embedded in surrounding prose", () => {
  assert.equal(message("es", "a11y.errorSummary", { count: 1 }), "Hay 1 error en el formulario");
  assert.equal(message("es", "a11y.errorSummary", { count: 3 }), "Hay 3 errores en el formulario");
});

test("formats ordinary named ICU arguments without altering localized content", () => {
  assert.equal(
    message("fr", "participation.progress", { received: 4, required: 7, percent: 57 }),
    "4 réponses finales sur 7 · 57%",
  );
});

test("keeps the skip link inside the locale segment so client-side locale navigation updates it", () => {
  const rootLayout = readFileSync(path.resolve(import.meta.dirname, "../app/layout.tsx"), "utf8");
  const localeLayout = readFileSync(path.resolve(import.meta.dirname, "../app/[locale]/layout.tsx"), "utf8");
  const localeSync = readFileSync(path.resolve(import.meta.dirname, "../components/nombramientos/locale-sync.tsx"), "utf8");
  assert.doesNotMatch(rootLayout, /className="skip-link"/u);
  assert.match(localeLayout, /skipToContent=\{getMessage\(locale, "a11y\.skipToContent"\)\}/u);
  assert.match(localeSync, /<a className="skip-link" href="#main-content">\{skipToContent\}<\/a>/u);
  assert.notEqual(getMessage("es", "a11y.skipToContent"), getMessage("en", "a11y.skipToContent"));
  assert.notEqual(getMessage("en", "a11y.skipToContent"), getMessage("fr", "a11y.skipToContent"));
});

test("formats the workflow-pause notice with real ICU plural selection in every locale", () => {
  assert.equal(message("es", "members.workflowsPaused", { count: 1 }), "1 proceso electoral afectado quedó pausado para revisión.");
  assert.equal(message("es", "members.workflowsPaused", { count: 2 }), "2 procesos electorales afectados quedaron pausados para revisión.");
  assert.equal(message("en", "members.workflowsPaused", { count: 1 }), "1 affected electoral workflow was paused for review.");
  assert.equal(message("fr", "members.workflowsPaused", { count: 2 }), "2 processus électoraux affectés ont été suspendus pour examen.");
});

test("keeps the three compile-time catalogs aligned and removes component-local tr helpers", () => {
  const spanishKeys = Object.keys(messages.es).sort();
  assert.deepEqual(Object.keys(messages.en).sort(), spanishKeys);
  assert.deepEqual(Object.keys(messages.fr).sort(), spanishKeys);
  assert.equal(getMessage("es", "common.close"), "Cerrar");
  assert.equal(getMessage("en", "common.close"), "Close");
  assert.equal(getMessage("fr", "common.close"), "Fermer");
  const roots = [path.resolve(import.meta.dirname, "../components"), path.resolve(import.meta.dirname)];
  const sourceFiles = roots.flatMap((root) => readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.(?:ts|tsx)$/u.test(entry.name))
    .map((entry) => path.join(entry.parentPath, entry.name)));
  for (const filename of sourceFiles) {
    assert.doesNotMatch(readFileSync(filename, "utf8"), /\bfunction\s+tr\s*\(|\bconst\s+tr\s*=/u, filename);
  }
});

test("resolves every known tenant permission from the catalogs instead of backend prose", () => {
  const permissionKeys = Object.keys(messages.es).filter((key) => key.startsWith("permission."));
  assert.equal(permissionKeys.length, 36);
  assert.equal(getMessage("en", "permission.memberContactRead"), "Read separately encrypted member contact envelopes");
  assert.equal(getMessage("fr", "permission.memberContactManage"), "Créer, remplacer ou supprimer les enveloppes de contact des membres");
  const helperSource = readFileSync(path.resolve(import.meta.dirname, "product-i18n.ts"), "utf8");
  const consoleSource = readFileSync(path.resolve(import.meta.dirname, "../components/nombramientos/access-console.tsx"), "utf8");
  assert.match(helperSource, /Readonly<Record<TenantPermission, MessageKey>>/u);
  assert.doesNotMatch(consoleSource, /permissionDescriptions|locale === "en"/u);
});

test("does not keep partial locale maps in production web sources", () => {
  const localeKeys = new Set(["es", "en", "fr"]);
  const roots = ["app", "components", "i18n", "lib", "workers"]
    .map((directory) => path.resolve(import.meta.dirname, "..", directory));
  const sourceFiles = roots.flatMap((root) => readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.(?:ts|tsx)$/u.test(entry.name) && !/\.(?:test|spec)\.(?:ts|tsx)$/u.test(entry.name))
    .map((entry) => path.join(entry.parentPath, entry.name)));
  const partialMaps: string[] = [];

  for (const filename of sourceFiles) {
    const sourceFile = ts.createSourceFile(filename, readFileSync(filename, "utf8"), ts.ScriptTarget.Latest, true, filename.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    const visit = (node: ts.Node): void => {
      if (ts.isObjectLiteralExpression(node)) {
        const present = node.properties.flatMap((property) => {
          if (!("name" in property) || !property.name) return [];
          const name = ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)
            ? property.name.text
            : undefined;
          return name && localeKeys.has(name) ? [name] : [];
        });
        if (present.length > 1 && present.length < localeKeys.size) {
          const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
          partialMaps.push(`${path.relative(path.resolve(import.meta.dirname, ".."), filename)}:${line + 1} (${present.sort().join(", ")})`);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
  }

  assert.deepEqual(partialMaps, []);
});
