import assert from "node:assert/strict";
import test from "node:test";
import {
  buildImportPreview,
  createImportErrorCsv,
  normalizeSearchText,
  parseUtf8Csv,
  suggestColumnMapping,
} from "./member-import.ts";

const encoder = new TextEncoder();
const tenantId = "d0000000-0000-4000-8000-000000000001";
const fingerprint = `sha256:${"a".repeat(64)}`;

test("CSV accepts fatal UTF-8, quoted values and common delimiters", () => {
  const bytes = encoder.encode('\uFEFFCódigo;Nombre;Correo\r\nA-1;"Díaz, Ana";ANA@example.org').buffer;
  assert.deepEqual(parseUtf8Csv(bytes), [
    ["Código", "Nombre", "Correo"],
    ["A-1", "Díaz, Ana", "ANA@example.org"],
  ]);
  assert.throws(() => parseUtf8Csv(Uint8Array.from([0xc3, 0x28]).buffer), /encoded data/i);
});

test("mapping is multilingual and accent-insensitive without changing display text", () => {
  assert.deepEqual(suggestColumnMapping(["Código", "Nombre completo", "Éligible"]), {
    sourceId: 0,
    displayName: 1,
    eligible: 2,
  });
  assert.equal(normalizeSearchText("  ÁDRIANA   Acósta "), "adriana acosta");
});

test("stable ids suggest update while homonyms remain a distinct create decision", async () => {
  const existing = [{ id: "d2000000-0000-4000-8000-000000000001", shortId: "A-1", version: 4, displayName: "Ana Díaz", email: "ana@old.test" }];
  const rows = await buildImportPreview({
    rows: [
      ["ID", "Nombre", "Correo", "Elegible"],
      ["A-1", "Ana Díaz", "ana@new.test", "sí"],
      ["A-2", "Ána Diaz", "other@example.test", "no"],
    ],
    mapping: { sourceId: 0, displayName: 1, email: 2, eligible: 3 },
    existingMembers: existing,
    tenantId,
    sourceFingerprint: fingerprint,
    sheetName: "Padrón",
  });
  assert.equal(rows[0]?.suggestedAction, "update");
  assert.equal(rows[0]?.targetId, existing[0]?.id);
  assert.equal(rows[1]?.suggestedAction, "create");
  assert.equal(rows[1]?.action, "undecided");
  assert.ok(rows[1]?.issues.some(({ code }) => code === "HOMONYM_RETAINED"));
});

test("deterministic ids make retries stable and unsafe input stays skipped for review", async () => {
  const input = {
    rows: [["Nombre", "Foto"], ["=cmd", "https://example.test/a.jpg"]],
    mapping: { displayName: 0, photoReference: 1 },
    existingMembers: [],
    tenantId,
    sourceFingerprint: fingerprint,
    sheetName: "CSV",
  } as const;
  const first = await buildImportPreview(input);
  const retried = await buildImportPreview(input);
  assert.equal(first[0]?.generatedId, retried[0]?.generatedId);
  assert.equal(first[0]?.suggestedAction, "skip");
  assert.deepEqual(first[0]?.issues.map(({ code }) => code), ["UNSAFE_FORMULA_PREFIX", "UNSAFE_PHOTO_REFERENCE"]);
  assert.match(createImportErrorCsv(first), /^\uFEFF"Fila","Nombre"/);
  assert.ok(createImportErrorCsv(first).includes("'=cmd"));
});

test("import parsing, preview validation and incident exports honor the selected locale", async () => {
  const controlCharacters = encoder.encode("Name\u0000\nAda").buffer;
  assert.throws(() => parseUtf8Csv(controlCharacters, "en"), /control characters/i);
  assert.throws(() => parseUtf8Csv(encoder.encode('Nom\n"Ada').buffer, "fr"), /guillemet non fermé/i);
  await assert.rejects(
    () => buildImportPreview({
      rows: [["Name"], ["Ada"]], mapping: {}, existingMembers: [], tenantId,
      sourceFingerprint: fingerprint, sheetName: "Roster", locale: "en",
    }),
    /Map Full name/,
  );
  const rows = await buildImportPreview({
    rows: [["Name"], ["=cmd"]], mapping: { displayName: 0 }, existingMembers: [], tenantId,
    sourceFingerprint: fingerprint, sheetName: "Roster", locale: "en",
  });
  assert.match(createImportErrorCsv(rows, new Map(), "en"), /^\uFEFF"Row","Name"/);
  assert.match(createImportErrorCsv(rows, new Map(), "fr"), /^\uFEFF"Ligne","Nom"/);
});
