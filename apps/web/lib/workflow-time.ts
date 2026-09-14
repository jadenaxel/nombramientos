type ZonedParts = {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
};

function zonedParts(value: Date, timeZone: string): ZonedParts {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(value);
  const part = (type: Intl.DateTimeFormatPartTypes) => Number(parts.find((item) => item.type === type)?.value);
  const result = {
    year: part("year"), month: part("month"), day: part("day"),
    hour: part("hour"), minute: part("minute"), second: part("second"),
  };
  if (Object.values(result).some((item) => !Number.isInteger(item))) throw new Error("TIME_ZONE_CONVERSION_FAILED");
  return result;
}

function offsetAt(instant: number, timeZone: string): number {
  const parts = zonedParts(new Date(instant), timeZone);
  const renderedAsUtc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
  return renderedAsUtc - Math.floor(instant / 1_000) * 1_000;
}

export function isoToLocalDateTimeInZone(value: string, timeZone: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("DATE_TIME_INVALID");
  const parts = zonedParts(date, timeZone);
  return `${parts.year.toString().padStart(4, "0")}-${parts.month.toString().padStart(2, "0")}-${parts.day.toString().padStart(2, "0")}T${parts.hour.toString().padStart(2, "0")}:${parts.minute.toString().padStart(2, "0")}`;
}

export function localDateTimeInZoneToIso(value: string, timeZone: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/u.exec(value);
  if (!match) throw new Error("DATE_TIME_INVALID");
  const expected: ZonedParts = {
    year: Number(match[1]), month: Number(match[2]), day: Number(match[3]),
    hour: Number(match[4]), minute: Number(match[5]), second: Number(match[6] ?? 0),
  };
  const wallClockUtc = Date.UTC(expected.year, expected.month - 1, expected.day, expected.hour, expected.minute, expected.second);
  let instant = wallClockUtc - offsetAt(wallClockUtc, timeZone);
  instant = wallClockUtc - offsetAt(instant, timeZone);
  const resolved = zonedParts(new Date(instant), timeZone);
  if (Object.keys(expected).some((key) => expected[key as keyof ZonedParts] !== resolved[key as keyof ZonedParts])) {
    throw new Error("DATE_TIME_NOT_VALID_IN_TIME_ZONE");
  }
  return new Date(instant).toISOString();
}
