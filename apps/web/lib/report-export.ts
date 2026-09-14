import type { Locale, PendingReport, ReportFilters, ReportFormat } from "./api.ts";
import { loadExcelJsBrowser } from "./exceljs-browser.ts";
import { assignmentLabel, message, phaseLabel } from "./product-i18n.ts";
import { neutralizeSpreadsheetCell } from "./spreadsheet-cell.ts";

export type ReportRow = readonly [string, string | number];

export type ReportArtifactFontBytes = {
  readonly regular: Uint8Array;
  readonly bold: Uint8Array;
};

function formatTenantDate(
  value: string | Date,
  locale: Locale,
  timeZone: string,
  options: Intl.DateTimeFormatOptions,
): string {
  return new Intl.DateTimeFormat(locale, { ...options, timeZone }).format(new Date(value));
}

function safeSpreadsheetHeader(value: string): string {
  return value.normalize("NFC").replace(/[\r\n\u0000-\u001f]/gu, " ").replaceAll("&", "&&").slice(0, 120);
}

function pdfText(value: string): string {
  return value.normalize("NFC").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ");
}

function expectedReportMediaType(format: ReportFormat): string {
  const mediaTypes: Record<ReportFormat, string> = {
    pdf: "application/pdf",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    csv: "text/csv; charset=utf-8",
  };
  return mediaTypes[format];
}

function reportFilterSummary(filters: ReportFilters, locale: Locale): string {
  const labels: Record<Exclude<keyof ReportFilters, "snapshotSha256" | "snapshotAt">, Parameters<typeof message>[1]> = {
    cycleId: "screen.reportsView.e5992ae2b006",
    term: "screen.reportsView.b9863bfbe89a",
    sessionId: "screen.reportsView.bba4234f0ca5",
    department: "screen.reportsView.a9c1f5f4089f",
    office: "screen.reportsView.94977dfd3c65",
    personId: "screen.reportsView.b792923baa6a",
    phase: "screen.reportsView.21c749ea4cb9",
    assignmentState: "screen.reportsView.d0e61926d1e3",
  };
  const parts = (Object.keys(labels) as (keyof typeof labels)[]).flatMap((key) => {
    const value = filters[key];
    if (value === null || value === undefined || value === "") return [];
    const label = labels[key];
    const rendered = key === "phase"
      ? phaseLabel(locale, value)
      : key === "assignmentState" && value === "proposal"
        ? message(locale, "screen.reportsView.07a0dacbeb7f")
        : key === "assignmentState" ? assignmentLabel(locale, value) : value;
    return [`${message(locale, label)}: ${rendered}`];
  });
  return parts.join(" · ") || message(locale, "screen.reportsView.e49424718bbf");
}

function wrapMeasuredText(value: string, maxWidth: number, measure: (text: string) => number): string[] {
  const sanitized = pdfText(value).trim() || "—";
  const lines: string[] = [];
  let current = "";
  const pushToken = (token: string) => {
    const candidate = current ? `${current} ${token}` : token;
    if (measure(candidate) <= maxWidth) { current = candidate; return; }
    if (current) { lines.push(current); current = ""; }
    if (measure(token) <= maxWidth) { current = token; return; }
    let fragment = "";
    for (const character of Array.from(token)) {
      if (fragment && measure(`${fragment}${character}`) > maxWidth) {
        lines.push(fragment);
        fragment = character;
      } else fragment += character;
    }
    current = fragment;
  };
  for (const token of sanitized.split(/\s+/u)) pushToken(token);
  if (current) lines.push(current);
  return lines.length ? lines : ["—"];
}

export async function buildLocalArtifact(
  report: PendingReport,
  rows: readonly ReportRow[],
  tenantName: string,
  title: string,
  audience: string,
  timeZone: string,
  fontBytes?: ReportArtifactFontBytes,
): Promise<Uint8Array<ArrayBuffer>> {
  if (report.mediaType !== expectedReportMediaType(report.format) || !report.filename.toLowerCase().endsWith(`.${report.format}`)) {
    throw new Error(message(report.locale, "screen.reportsView.4d312d1d2cec"));
  }
  const issued = formatTenantDate(report.createdAt, report.locale, timeZone, { dateStyle: "long", timeStyle: "short" });
  const issuedLabel = message(report.locale, "screen.reportsView.684c3d37a65e");
  const audienceLabel = message(report.locale, "screen.reportsView.1840ea7a62ac");
  const filtersLabel = message(report.locale, "screen.reportsView.fd72c1b1c064");
  const snapshotLabel = message(report.locale, "screen.reportsView.56a171238bfe");
  const fieldLabel = message(report.locale, "screen.reportsView.fdfdec3ee967");
  const valueLabel = message(report.locale, "screen.reportsView.8abd1ccf278d");
  const filterSummary = reportFilterSummary(report.filters, report.locale);
  const metadataRows: readonly ReportRow[] = [
    [message(report.locale, "screen.reportsView.dd287562c7af"), tenantName],
    [issuedLabel, issued],
    [audienceLabel, audience],
    [filtersLabel, filterSummary],
    [snapshotLabel, report.filters.snapshotSha256],
    [message(report.locale, "screen.reportsView.7ea14aef1c61"), `v${report.lineageRevision}`],
    ...(report.supersedesReportId ? [[
      message(report.locale, "screen.reportsView.7260fcc599e0"),
      report.supersedesReportId,
    ] as const] : []),
  ];
  if (report.format === "csv") {
    const quote = (value: string | number) => `"${neutralizeSpreadsheetCell(String(value)).replaceAll('"', '""')}"`;
    const csv = [[title], ...metadataRows, [], [fieldLabel, valueLabel], ...rows].map((row) => row.map(quote).join(",")).join("\r\n");
    return new TextEncoder().encode(`\uFEFF${csv}`);
  }
  if (report.format === "xlsx") {
    const ExcelJS = await loadExcelJsBrowser();
    const workbook = new ExcelJS.Workbook();
    workbook.creator = "Nombramientos";
    workbook.lastModifiedBy = "Nombramientos";
    workbook.created = new Date(report.createdAt);
    workbook.modified = new Date(report.createdAt);
    workbook.subject = `${audience} · ${tenantName}`;
    const sheet = workbook.addWorksheet(message(report.locale, "screen.reportsView.5bb5a3ced508"));
    sheet.columns = [{ key: "label", width: 46 }, { key: "value", width: 38 }];
    sheet.addRow([neutralizeSpreadsheetCell(title)]);
    for (const [label, value] of metadataRows) sheet.addRow([
      neutralizeSpreadsheetCell(label),
      typeof value === "number" ? value : neutralizeSpreadsheetCell(value),
    ]);
    sheet.addRow([]);
    const tableHeader = sheet.addRow([fieldLabel, valueLabel]);
    rows.forEach(([label, value]) => sheet.addRow([
      neutralizeSpreadsheetCell(label),
      typeof value === "number" ? value : neutralizeSpreadsheetCell(value),
    ]));
    sheet.mergeCells("A1:B1");
    sheet.getRow(1).height = 28;
    for (const cell of [sheet.getCell("A1"), sheet.getCell("B1")]) {
      cell.font = { bold: true, size: 15, color: { argb: "FFFFFFFF" } };
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF0A5268" } };
    }
    for (const cell of [tableHeader.getCell(1), tableHeader.getCell(2)]) {
      cell.font = { bold: true, color: { argb: "FFFFFFFF" } };
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF127481" } };
      cell.alignment = { vertical: "middle" };
    }
    for (const row of sheet.getRows(2, sheet.rowCount - 1) ?? []) row.eachCell((cell) => { cell.alignment = { vertical: "top", wrapText: true }; });
    sheet.views = [{ state: "frozen", ySplit: tableHeader.number }];
    sheet.autoFilter = `A${tableHeader.number}:B${tableHeader.number}`;
    sheet.pageSetup = { orientation: "portrait", fitToPage: true, fitToWidth: 1, fitToHeight: 0 };
    sheet.headerFooter.oddFooter = `&L${safeSpreadsheetHeader(tenantName)}&C${safeSpreadsheetHeader(audience)}&R${message(report.locale, "screen.reportsView.be29af45774e")} &P / &N`;
    const buffer = await workbook.xlsx.writeBuffer();
    const bytes = new Uint8Array(buffer.byteLength);
    bytes.set(new Uint8Array(buffer));
    return bytes;
  }
  const [{ PDFDocument, rgb }, { default: fontkit }] = await Promise.all([
    import("pdf-lib"),
    import("@pdf-lib/fontkit"),
  ]);
  const document = await PDFDocument.create();
  document.registerFontkit(fontkit);
  document.setTitle(title);
  document.setAuthor("Nombramientos");
  document.setSubject(`${audience} · ${tenantName}`);
  document.setLanguage(report.locale === "es" ? "es-DO" : report.locale === "fr" ? "fr-FR" : "en-US");
  document.setCreator("Nombramientos");
  document.setProducer("Nombramientos · pdf-lib");
  document.setKeywords(["nombramientos", "reporte", report.reportType, report.locale, report.audience]);
  document.setCreationDate(new Date(report.createdAt));
  const [regularBytes, boldBytes] = fontBytes
    ? [fontBytes.regular, fontBytes.bold]
    : await (async () => {
      const [regularResponse, boldResponse] = await Promise.all([
        fetch("/fonts/report-sans-regular.ttf", { cache: "force-cache" }),
        fetch("/fonts/report-sans-bold.ttf", { cache: "force-cache" }),
      ]);
      if (!regularResponse.ok || !boldResponse.ok) throw new Error(message(report.locale, "screen.reportsView.314f700033b2"));
      return Promise.all([regularResponse.arrayBuffer(), boldResponse.arrayBuffer()]);
    })();
  // Static TrueType subsets produce portable FontFile2 streams. Embedding the
  // browser WOFF2 directly can look valid to pdf-lib while external renderers
  // reject the font and display an empty report.
  const regular = await document.embedFont(regularBytes, { subset: true, customName: "Bitstream Vera Sans" });
  const bold = await document.embedFont(boldBytes, { subset: true, customName: "Bitstream Vera Sans Bold" });
  const printableRows: readonly ReportRow[] = [
    [filtersLabel, filterSummary],
    [snapshotLabel, report.filters.snapshotSha256],
    ...rows,
  ];
  const laidOutRows = printableRows.map(([label, value]) => {
    const labelLines = wrapMeasuredText(String(label), 265, (text) => regular.widthOfTextAtSize(text, 8.5));
    const valueLines = wrapMeasuredText(String(value), 185, (text) => bold.widthOfTextAtSize(text, 9));
    return { labelLines, valueLines, height: Math.max(48, Math.max(labelLines.length, valueLines.length) * 12 + 22) };
  });
  const pages: (typeof laidOutRows)[] = [];
  let pageRows: typeof laidOutRows = [];
  let usedHeight = 0;
  for (const row of laidOutRows) {
    if (pageRows.length && usedHeight + row.height + 8 > 570) {
      pages.push(pageRows);
      pageRows = [];
      usedHeight = 0;
    }
    pageRows.push(row);
    usedHeight += row.height + 8;
  }
  pages.push(pageRows);
  pages.forEach((pageRows, pageIndex) => {
    const page = document.addPage([595.28, 841.89]);
    page.drawRectangle({ x: 0, y: 742, width: 595.28, height: 100, color: rgb(0.035, 0.14, 0.23) });
    page.drawText("N", { x: 42, y: 778, size: 28, font: bold, color: rgb(0.36, 0.86, 0.82) });
    wrapMeasuredText(title, 455, (text) => bold.widthOfTextAtSize(text, 14)).slice(0, 2).forEach((line, index) => page.drawText(line, { x: 83, y: 795 - index * 17, size: 14, font: bold, color: rgb(1, 1, 1) }));
    page.drawText(pdfText(tenantName), { x: 83, y: 758, size: 8.5, font: regular, color: rgb(0.74, 0.82, 0.86), maxWidth: 455 });
    page.drawText(pdfText(`${audienceLabel}: ${audience} · ${issuedLabel}: ${issued}`), { x: 42, y: 714, size: 8.5, font: regular, color: rgb(0.35, 0.43, 0.5), maxWidth: 511 });
    let cursor = 685;
    pageRows.forEach((row) => {
      page.drawRectangle({ x: 42, y: cursor - row.height, width: 511, height: row.height, borderColor: rgb(0.82, 0.87, 0.9), borderWidth: 1, color: rgb(0.97, 0.98, 0.985) });
      row.labelLines.forEach((line, index) => page.drawText(line, { x: 57, y: cursor - 20 - index * 12, size: 8.5, font: regular, color: rgb(0.23, 0.31, 0.38) }));
      row.valueLines.forEach((line, index) => page.drawText(line, { x: 352, y: cursor - 20 - index * 12, size: 9, font: bold, color: rgb(0.03, 0.36, 0.42) }));
      cursor -= row.height + 8;
    });
    page.drawText(`ID: ${report.id}`, { x: 42, y: 54, size: 7, font: regular, color: rgb(0.48, 0.54, 0.59) });
    page.drawText(`${pageIndex + 1} / ${pages.length}`, { x: 520, y: 54, size: 7, font: regular, color: rgb(0.48, 0.54, 0.59) });
    page.drawText(pdfText(message(report.locale, "screen.reportsView.a8fffbd02184")), { x: 42, y: 39, size: 7, font: regular, color: rgb(0.48, 0.54, 0.59) });
  });
  const bytes = await document.save();
  const copyBytes = new Uint8Array(bytes.byteLength);
  copyBytes.set(bytes);
  return copyBytes;
}
