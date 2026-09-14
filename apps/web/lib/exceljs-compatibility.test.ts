import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { PassThrough, Readable } from "node:stream";
import test from "node:test";

import { loadExcelJsBrowser } from "./exceljs-browser.ts";

const require = createRequire(import.meta.url);

test("ExcelJS CommonJS, ESM, buffer round-trip and streaming reader stay compatible", async () => {
  const required = require("exceljs") as typeof import("exceljs");
  const imported = await import("exceljs");
  const excelJsRequire = createRequire(require.resolve("exceljs"));
  const unzipperManifest = excelJsRequire("unzipper/package.json") as { license?: string; version?: string };

  assert.equal(typeof required.Workbook, "function");
  assert.equal(typeof imported.default.Workbook, "function");
  assert.equal(unzipperManifest.version, "0.12.5");
  assert.equal(unzipperManifest.license, "MIT");

  const workbook = new required.Workbook();
  const worksheet = workbook.addWorksheet("Padrón");
  worksheet.addRow(["Nombre", "Puntaje"]);
  worksheet.addRow(["Ángela Núñez", 42]);

  const serialized = await workbook.xlsx.writeBuffer();
  const bytes = Buffer.from(serialized as ArrayBuffer);
  assert.ok(bytes.byteLength > 0);

  const loaded = new imported.default.Workbook();
  await loaded.xlsx.load(bytes as unknown as Parameters<typeof loaded.xlsx.load>[0]);
  assert.equal(loaded.getWorksheet("Padrón")?.getCell("A2").value, "Ángela Núñez");
  assert.equal(loaded.getWorksheet("Padrón")?.getCell("B2").value, 42);

  const output = new PassThrough();
  const chunks: Buffer[] = [];
  output.on("data", (chunk: Buffer) => chunks.push(chunk));
  const streamingWriter = new required.stream.xlsx.WorkbookWriter({ stream: output, useSharedStrings: false });
  const streamingSheet = streamingWriter.addWorksheet("Padrón");
  streamingSheet.addRow(["Nombre", "Puntaje"]).commit();
  streamingSheet.addRow(["Ángela Núñez", 42]).commit();
  streamingSheet.commit();
  await streamingWriter.commit();

  const streaming = new required.stream.xlsx.WorkbookReader(Readable.from([Buffer.concat(chunks)]), {
    entries: "emit",
    sharedStrings: "cache",
    styles: "cache",
    hyperlinks: "ignore",
    worksheets: "emit",
  });
  const streamedRows: unknown[][] = [];
  for await (const streamedWorksheet of streaming) {
    for await (const row of streamedWorksheet) {
      streamedRows.push(row.values as unknown[]);
    }
  }

  assert.deepEqual(streamedRows[0]?.slice(1), ["Nombre", "Puntaje"]);
  assert.deepEqual(streamedRows[1]?.slice(1), ["Ángela Núñez", 42]);
});

test("the explicit browser build writes and reads the client-side XLSX format", async () => {
  const ExcelJS = await loadExcelJsBrowser();
  const workbook = new ExcelJS.Workbook();
  workbook.addWorksheet("Reporte").addRow(["Estado", "Completo"]);
  const bytes = await workbook.xlsx.writeBuffer();

  const loaded = new ExcelJS.Workbook();
  await loaded.xlsx.load(bytes);
  const rowValues = loaded.getWorksheet("Reporte")?.getRow(1).values;
  assert.ok(Array.isArray(rowValues));
  assert.deepEqual(rowValues.slice(1), ["Estado", "Completo"]);
});
