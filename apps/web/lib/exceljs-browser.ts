export async function loadExcelJsBrowser(): Promise<typeof import("exceljs")> {
  const excelJsModule = await import("exceljs/dist/exceljs.min.js");
  return excelJsModule.default;
}
