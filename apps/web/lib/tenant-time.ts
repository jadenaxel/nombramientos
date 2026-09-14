import type { Locale } from "./api";

const localeTags: Readonly<Record<Locale, string>> = {
  es: "es-DO",
  en: "en-US",
  fr: "fr-FR",
};

export function formatInTenantTimeZone(
  value: string | number | Date,
  locale: Locale,
  timeZone: string,
  options: Intl.DateTimeFormatOptions,
): string {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("DATE_TIME_INVALID");
  return new Intl.DateTimeFormat(localeTags[locale], { ...options, timeZone }).format(date);
}

export function currentYearInTimeZone(timeZone: string, now = new Date()): number {
  if (!Number.isFinite(now.getTime())) throw new Error("DATE_TIME_INVALID");
  const year = new Intl.DateTimeFormat("en-US", { year: "numeric", timeZone })
    .formatToParts(now)
    .find((part) => part.type === "year")?.value;
  const parsed = Number(year);
  if (!Number.isInteger(parsed)) throw new Error("TIME_ZONE_CONVERSION_FAILED");
  return parsed;
}

export function formatCalendarDate(
  value: string,
  locale: Locale,
  options: Intl.DateTimeFormatOptions = { dateStyle: "medium" },
): string {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) throw new Error("CALENDAR_DATE_INVALID");
  const date = new Date(`${value}T12:00:00.000Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value) {
    throw new Error("CALENDAR_DATE_INVALID");
  }
  return new Intl.DateTimeFormat(localeTags[locale], { ...options, timeZone: "UTC" }).format(date);
}
