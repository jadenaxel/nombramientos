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
  return value.normalize("NFC").replace(/[\u2010-\u2015]/gu, "-").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ");
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
  const navy = rgb(0.035, 0.14, 0.23);
  const teal = rgb(0.03, 0.43, 0.43);
  const gold = rgb(0.79, 0.58, 0.24);
  const ink = rgb(0.11, 0.2, 0.28);
  const muted = rgb(0.4, 0.48, 0.55);
  const cloud = rgb(0.94, 0.955, 0.965);
  const directoryReport = new Set<string>(["department", "elected_board", "general_recommendations"]).has(report.reportType);
  const cover = document.addPage([595.28, 841.89]);
  cover.drawText("N", { x: 44, y: 778, size: 30, font: bold, color: teal });
  cover.drawText("NOMBRAMIENTOS", { x: 83, y: 793, size: 9, font: bold, color: navy });
  wrapMeasuredText(tenantName, 360, (text) => regular.widthOfTextAtSize(text, 8.5)).slice(0, 2).forEach((line, index) => cover.drawText(line, { x: 83, y: 776 - index * 11, size: 8.5, font: regular, color: muted }));
  cover.drawText(report.locale.toUpperCase(), { x: 510, y: 793, size: 9, font: bold, color: navy });
  cover.drawRectangle({ x: 0, y: 215, width: 595.28, height: 490, color: navy });
  cover.drawRectangle({ x: 44, y: 638, width: 46, height: 5, color: gold });
  cover.drawText(pdfText(message(report.locale, "reports.studio.eyebrow")), { x: 44, y: 602, size: 9.5, font: bold, color: gold });
  const coverTitle = wrapMeasuredText(title, 500, (text) => bold.widthOfTextAtSize(text, 31)).slice(0, 4);
  coverTitle.forEach((line, index) => cover.drawText(line, { x: 44, y: 550 - index * 38, size: 31, font: bold, color: rgb(1, 1, 1) }));
  const subtitleY = Math.min(400, 550 - coverTitle.length * 38 - 12);
  cover.drawText(pdfText(`${audienceLabel}: ${audience}`), { x: 44, y: subtitleY, size: 11, font: regular, color: rgb(0.78, 0.86, 0.88) });
  cover.drawText(pdfText(`${issuedLabel}: ${issued}`), { x: 44, y: subtitleY - 22, size: 9, font: regular, color: rgb(0.68, 0.77, 0.81) });
  const numericRows = rows.filter((row) => typeof row[1] === "number").slice(0, 3);
  const coverStats: readonly ReportRow[] = numericRows.length >= 3 ? numericRows : [
    [message(report.locale, "screen.reportsView.7a4c2c0357fd"), rows.length],
    [message(report.locale, "screen.reportsView.cd98527c436d"), report.locale.toUpperCase()],
    [message(report.locale, "screen.reportsView.7ea14aef1c61"), `v${report.lineageRevision}`],
  ];
  coverStats.slice(0, 3).forEach(([label, value], index) => {
    const x = 44 + index * 171;
    cover.drawText(pdfText(String(value)), { x, y: 276, size: 24, font: bold, color: rgb(1, 1, 1) });
    wrapMeasuredText(String(label), 145, (text) => regular.widthOfTextAtSize(text, 7.5)).slice(0, 2).forEach((line, lineIndex) => cover.drawText(line, { x, y: 254 - lineIndex * 10, size: 7.5, font: regular, color: rgb(0.7, 0.8, 0.83) }));
  });
  cover.drawText(pdfText(filtersLabel.toUpperCase()), { x: 44, y: 166, size: 7.5, font: bold, color: gold });
  wrapMeasuredText(filterSummary, 507, (text) => regular.widthOfTextAtSize(text, 8)).slice(0, 3).forEach((line, index) => cover.drawText(line, { x: 44, y: 145 - index * 11, size: 8, font: regular, color: ink }));
  cover.drawText(pdfText(`${snapshotLabel}: ${report.filters.snapshotSha256}`), { x: 44, y: 72, size: 6.5, font: regular, color: muted, maxWidth: 507 });

  const addDetailPage = (section: string) => {
    const page = document.addPage([595.28, 841.89]);
    page.drawText("N", { x: 42, y: 790, size: 22, font: bold, color: teal });
    page.drawText("NOMBRAMIENTOS", { x: 72, y: 800, size: 8, font: bold, color: navy });
    page.drawText(pdfText(section.toUpperCase()), { x: 428, y: 800, size: 7.5, font: bold, color: muted, maxWidth: 125 });
    page.drawRectangle({ x: 42, y: 756, width: 511, height: 1.5, color: gold });
    wrapMeasuredText(title, 500, (text) => bold.widthOfTextAtSize(text, 20)).slice(0, 2).forEach((line, index) => page.drawText(line, { x: 42, y: 718 - index * 24, size: 20, font: bold, color: navy }));
    page.drawText(pdfText(tenantName), { x: 42, y: 671, size: 8.5, font: regular, color: muted, maxWidth: 500 });
    return { page, cursor: 642 };
  };

  let detail = addDetailPage(directoryReport ? message(report.locale, "reports.studio.departments.title") : title);
  let currentDepartment = "";
  let rowIndex = 0;
  const beginDepartment = (department: string, continuation = false) => {
    if (detail.cursor < 128) detail = addDetailPage(department);
    detail.page.drawRectangle({ x: 42, y: detail.cursor - 35, width: 511, height: 35, color: navy });
    const heading = continuation ? `${department} - cont.` : department;
    detail.page.drawText(pdfText(heading), { x: 55, y: detail.cursor - 22, size: 10.5, font: bold, color: rgb(1, 1, 1), maxWidth: 480 });
    detail.cursor -= 52;
    detail.page.drawText(pdfText(fieldLabel.toUpperCase()), { x: 55, y: detail.cursor, size: 7, font: bold, color: muted });
    detail.page.drawText(pdfText(valueLabel.toUpperCase()), { x: 302, y: detail.cursor, size: 7, font: bold, color: muted });
    detail.cursor -= 15;
    rowIndex = 0;
  };

  for (const [rawLabel, rawValue] of rows) {
    const label = pdfText(String(rawLabel));
    const value = pdfText(String(rawValue));
    const labelParts = label.split(" · ");
    const department = directoryReport && labelParts.length > 1 ? labelParts.shift()! : "";
    const visibleLabel = directoryReport && department ? labelParts.join(" · ") : label;
    const labelLines = wrapMeasuredText(visibleLabel, directoryReport ? 220 : 270, (text) => regular.widthOfTextAtSize(text, 8.3));
    const valueLines = wrapMeasuredText(value, directoryReport ? 235 : 180, (text) => regular.widthOfTextAtSize(text, 8.3));
    const height = Math.max(directoryReport ? 31 : 43, Math.max(labelLines.length, valueLines.length) * 11 + 17);
    if (directoryReport && department !== currentDepartment) {
      if (detail.cursor < height + 100) detail = addDetailPage(department);
      currentDepartment = department;
      beginDepartment(department);
    } else if (detail.cursor < height + 72) {
      detail = addDetailPage(currentDepartment || title);
      if (directoryReport && currentDepartment) beginDepartment(currentDepartment, true);
    }
    const progress = report.reportType === "progress" ? value.match(/(\d+)\s*\/\s*(\d+).*?(\d+)\s*%/u) : null;
    const rowBottom = detail.cursor - height;
    detail.page.drawRectangle({ x: 42, y: rowBottom, width: 511, height, color: rowIndex % 2 === 0 ? cloud : rgb(1, 1, 1) });
    if (directoryReport && rowIndex === 0) detail.page.drawRectangle({ x: 42, y: rowBottom, width: 3, height, color: gold });
    labelLines.forEach((line, index) => detail.page.drawText(line, { x: 55, y: detail.cursor - 18 - index * 11, size: 8.3, font: directoryReport && rowIndex === 0 ? bold : regular, color: ink }));
    if (progress) {
      const percent = Math.max(0, Math.min(100, Number(progress[3])));
      detail.page.drawRectangle({ x: 322, y: detail.cursor - 25, width: 175, height: 7, color: rgb(0.84, 0.88, 0.89) });
      detail.page.drawRectangle({ x: 322, y: detail.cursor - 25, width: 175 * percent / 100, height: 7, color: teal });
      detail.page.drawText(`${percent}%`, { x: 507, y: detail.cursor - 27, size: 8.3, font: bold, color: teal });
      detail.page.drawText(pdfText(`${progress[1]} / ${progress[2]}`), { x: 252, y: detail.cursor - 27, size: 8.3, font: bold, color: ink });
    } else valueLines.forEach((line, index) => detail.page.drawText(line, { x: directoryReport ? 302 : 347, y: detail.cursor - 18 - index * 11, size: 8.3, font: directoryReport && rowIndex === 0 ? bold : regular, color: directoryReport && rowIndex === 0 ? navy : muted }));
    detail.cursor -= height;
    rowIndex += 1;
  }

  if (!rows.length) {
    detail.page.drawRectangle({ x: 42, y: 535, width: 511, height: 70, color: cloud });
    detail.page.drawText(pdfText(message(report.locale, "screen.reportsView.4d6140b354ec")), { x: 58, y: 568, size: 10, font: bold, color: muted });
  }
  const allPages = document.getPages();
  allPages.forEach((page, pageIndex) => {
    page.drawText(pdfText(tenantName.toUpperCase()), { x: 42, y: 39, size: 6.8, font: bold, color: muted, maxWidth: 220 });
    page.drawText(pdfText(title), { x: 235, y: 39, size: 6.8, font: regular, color: muted, maxWidth: 250 });
    page.drawText(`${pageIndex + 1} / ${allPages.length}`, { x: 518, y: 39, size: 6.8, font: bold, color: navy });
    page.drawText(`ID: ${report.id}`, { x: 42, y: 24, size: 5.8, font: regular, color: muted, maxWidth: 270 });
    page.drawText(pdfText(message(report.locale, "screen.reportsView.a8fffbd02184")), { x: 318, y: 24, size: 5.8, font: regular, color: muted, maxWidth: 235 });
  });
  const bytes = await document.save();
  const copyBytes = new Uint8Array(bytes.byteLength);
  copyBytes.set(bytes);
  return copyBytes;
}
