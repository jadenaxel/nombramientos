/// <reference lib="webworker" />

import { getMessage, type MessageKey } from "@nombramientos/i18n";

import { loadExcelJsBrowser } from "../lib/exceljs-browser";
import { buildImportPreview, parseUtf8Csv, type ImportLocale } from "../lib/member-import";
import type {
  ImportSheetDescriptor,
  InspectImportFileRequest,
  MemberImportWorkerRequest,
  MemberImportWorkerResponse,
} from "../lib/member-import-worker-protocol";

type ImportDataset = {
  readonly sourceFingerprint: `sha256:${string}`;
  readonly sheets: ReadonlyMap<string, readonly string[][]>;
};

const workerScope = self as unknown as DedicatedWorkerGlobalScope;
const datasets = new Map<string, ImportDataset>();
let queue = Promise.resolve();

workerScope.addEventListener("message", (event: MessageEvent<MemberImportWorkerRequest>) => {
  queue = queue.then(() => handleRequest(event.data)).catch(() => undefined);
});

async function handleRequest(request: MemberImportWorkerRequest): Promise<void> {
  try {
    if (request.type === "inspect") {
      const result = await inspectImportFile(request);
      respond({ requestId: request.requestId, ok: true, type: "inspect", result });
      return;
    }
    const dataset = datasets.get(request.datasetId);
    const rows = dataset?.sheets.get(request.sheetName);
    if (!dataset || !rows) throw new Error(workerMessage(request.locale, "import.worker.datasetChanged"));
    const preview = await buildImportPreview({
      rows,
      mapping: request.mapping,
      existingMembers: request.existingMembers,
      tenantId: request.tenantId,
      sourceFingerprint: dataset.sourceFingerprint,
      sheetName: request.sheetName,
      locale: request.locale,
    });
    respond({ requestId: request.requestId, ok: true, type: "preview", result: { rows: preview } });
  } catch (error) {
    respond({
      requestId: request.requestId,
      ok: false,
      message: error instanceof Error ? error.message : workerMessage(request.locale, "import.worker.genericFailure"),
    });
  }
}

async function inspectImportFile(request: InspectImportFileRequest) {
  if (request.bytes.byteLength > 5 * 1024 * 1024) {
    throw new Error(workerMessage(request.locale, "import.worker.fileTooLarge"));
  }
  const sourceFingerprint = await sha256Bytes(request.bytes);
  const sheets: Array<{ readonly name: string; readonly rows: readonly string[][] }> = [];

  if (request.extension === "csv") {
    sheets.push({ name: "CSV", rows: parseUtf8Csv(request.bytes, request.locale) });
  } else {
    validateXlsxContainer(request.bytes, request.locale);
    const ExcelJS = await loadExcelJsBrowser();
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(request.bytes);
    if (workbook.worksheets.length > 50) {
      throw new Error(workerMessage(request.locale, "import.worker.tooManyWorksheets"));
    }
    let inspectedCells = 0;
    for (const worksheet of workbook.worksheets) {
      assertSheetLimits(worksheet.name, worksheet.rowCount, worksheet.columnCount, request.locale);
      inspectedCells += worksheet.rowCount * Math.max(worksheet.columnCount, 1);
      assertCellLimit(inspectedCells, request.locale);
      const rows: string[][] = [];
      for (let rowNumber = 1; rowNumber <= worksheet.rowCount; rowNumber += 1) {
        const row = worksheet.getRow(rowNumber);
        const values: string[] = [];
        for (let column = 1; column <= Math.max(worksheet.columnCount, 1); column += 1) {
          const cell = row.getCell(column);
          if (cell.type === ExcelJS.ValueType.Formula || (typeof cell.value === "object" && cell.value !== null && "formula" in cell.value)) {
            throw new Error(workerMessage(request.locale, "import.worker.formulaCell", {
              address: `${worksheet.name}!${cell.address}`,
            }));
          }
          if (typeof cell.value === "object" && cell.value !== null && "hyperlink" in cell.value) {
            throw new Error(workerMessage(request.locale, "import.worker.linkCell", {
              address: `${worksheet.name}!${cell.address}`,
            }));
          }
          values.push(cell.text.trim());
        }
        rows.push(values);
      }
      if (worksheet.state === "visible" && rows.length > 0) sheets.push({ name: worksheet.name, rows });
    }
  }

  let totalCells = 0;
  for (const sheet of sheets) {
    const widestRow = sheet.rows.reduce((width, row) => Math.max(width, row.length), 0);
    assertSheetLimits(sheet.name, sheet.rows.length, widestRow, request.locale);
    totalCells += sheet.rows.length * Math.max(widestRow, 1);
  }
  assertCellLimit(totalCells, request.locale);
  const usable = sheets.filter(({ rows }) => rows.length >= 2 && rows.length <= 10_001);
  if (usable.length === 0) {
    throw new Error(workerMessage(request.locale, "import.worker.noUsableWorksheet"));
  }

  const datasetId = crypto.randomUUID();
  datasets.clear();
  datasets.set(datasetId, {
    sourceFingerprint,
    sheets: new Map(usable.map(({ name, rows }) => [name, rows])),
  });
  const descriptors: ImportSheetDescriptor[] = usable.map(({ name, rows }) => ({
    name,
    rowCount: Math.max(0, rows.length - 1),
    headers: rows[0] ?? [],
  }));
  return { datasetId, sourceFingerprint, sheets: descriptors };
}

function assertSheetLimits(name: string, rowCount: number, columnCount: number, locale: ImportLocale): void {
  if (rowCount > 10_001) {
    throw new Error(workerMessage(locale, "import.worker.tooManyPeople", { name }));
  }
  if (columnCount > 50) {
    throw new Error(workerMessage(locale, "import.worker.tooManyColumns", { name }));
  }
}

function assertCellLimit(cellCount: number, locale: ImportLocale): void {
  if (cellCount > 500_000) {
    throw new Error(workerMessage(locale, "import.worker.tooManyCells"));
  }
}

async function sha256Bytes(value: ArrayBuffer): Promise<`sha256:${string}`> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return `sha256:${Array.from(new Uint8Array(digest), (part) => part.toString(16).padStart(2, "0")).join("")}`;
}

function validateXlsxContainer(value: ArrayBuffer, locale: ImportLocale): void {
  const entryLimit = 2_000;
  const expandedByteLimit = 25 * 1024 * 1024;
  const compressionRatioLimit = 200;
  if (value.byteLength < 22) throw new Error(workerMessage(locale, "import.worker.xlsxTruncated"));
  const view = new DataView(value);
  const endSearchAt = Math.max(0, value.byteLength - 65_557);
  let endOfDirectory = -1;
  for (let offset = value.byteLength - 22; offset >= endSearchAt; offset -= 1) {
    if (view.getUint32(offset, true) === 0x06054b50) { endOfDirectory = offset; break; }
  }
  if (endOfDirectory < 0) throw new Error(workerMessage(locale, "import.worker.xlsxInvalidDirectory"));
  const entryCount = view.getUint16(endOfDirectory + 10, true);
  const directorySize = view.getUint32(endOfDirectory + 12, true);
  const directoryOffset = view.getUint32(endOfDirectory + 16, true);
  if (entryCount === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff) {
    throw new Error(workerMessage(locale, "import.worker.xlsxZip64"));
  }
  if (entryCount === 0 || entryCount > entryLimit || directoryOffset + directorySize > value.byteLength) {
    throw new Error(workerMessage(locale, "import.worker.xlsxUnsafeStructure"));
  }
  let cursor = directoryOffset;
  let expandedBytes = 0;
  const decoder = new TextDecoder("utf-8", { fatal: false });
  for (let entry = 0; entry < entryCount; entry += 1) {
    if (cursor + 46 > value.byteLength || view.getUint32(cursor, true) !== 0x02014b50) {
      throw new Error(workerMessage(locale, "import.worker.xlsxDamagedDirectory"));
    }
    const flags = view.getUint16(cursor + 8, true);
    const compressedBytes = view.getUint32(cursor + 20, true);
    const uncompressedBytes = view.getUint32(cursor + 24, true);
    const nameLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const commentLength = view.getUint16(cursor + 32, true);
    if ((flags & 0x1) !== 0 || compressedBytes === 0xffffffff || uncompressedBytes === 0xffffffff) {
      throw new Error(workerMessage(locale, "import.worker.xlsxUnsupportedEncryption"));
    }
    expandedBytes += uncompressedBytes;
    if (expandedBytes > expandedByteLimit || (uncompressedBytes > 0 && compressedBytes === 0)
      || (compressedBytes > 0 && uncompressedBytes / compressedBytes > compressionRatioLimit)) {
      throw new Error(workerMessage(locale, "import.worker.xlsxExpandedTooLarge"));
    }
    const nameStart = cursor + 46;
    const nextCursor = nameStart + nameLength + extraLength + commentLength;
    if (nextCursor > value.byteLength) throw new Error(workerMessage(locale, "import.worker.xlsxTruncatedDirectory"));
    const entryName = decoder.decode(new Uint8Array(value, nameStart, nameLength)).replaceAll("\\", "/").toLocaleLowerCase();
    if (entryName.startsWith("/") || entryName.split("/").includes("..")) {
      throw new Error(workerMessage(locale, "import.worker.xlsxUnsafePath"));
    }
    if (entryName.includes("vbaproject.bin") || entryName.startsWith("xl/embeddings/") || entryName.startsWith("xl/externallinks/")) {
      throw new Error(workerMessage(locale, "import.worker.xlsxForbiddenContent"));
    }
    cursor = nextCursor;
  }
}

function workerMessage(
  locale: ImportLocale,
  key: MessageKey,
  values: Readonly<Record<string, string | number>> = {},
): string {
  let result = getMessage(locale, key);
  for (const [name, value] of Object.entries(values)) {
    result = result.replaceAll(`{${name}}`, String(value));
  }
  return result;
}

function respond(response: MemberImportWorkerResponse): void {
  workerScope.postMessage(response);
}
