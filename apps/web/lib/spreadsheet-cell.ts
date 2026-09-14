const DANGEROUS_SPREADSHEET_PREFIX = /^[\p{White_Space}]*[=+\-@\t\r\n]/u;

export function hasDangerousSpreadsheetPrefix(value: string): boolean {
  return DANGEROUS_SPREADSHEET_PREFIX.test(value);
}

export function neutralizeSpreadsheetCell(value: string): string {
  return hasDangerousSpreadsheetPrefix(value) ? `'${value}` : value;
}
