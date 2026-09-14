import assert from "node:assert/strict";
import test from "node:test";

import { currentYearInTimeZone, formatCalendarDate, formatInTenantTimeZone } from "./tenant-time.ts";

test("formats the same instant in the authenticated tenant timezone", () => {
  const instant = "2026-01-01T02:30:00.000Z";
  assert.match(formatInTenantTimeZone(instant, "es", "America/Santo_Domingo", {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }), /31\/12\/2025, 22:30/u);
  assert.match(formatInTenantTimeZone(instant, "en", "America/La_Paz", {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }), /12\/31\/2025, 22:30/u);
});

test("derives calendar defaults from the tenant timezone instead of the browser", () => {
  const instant = new Date("2026-01-01T02:30:00.000Z");
  assert.equal(currentYearInTimeZone("America/Santo_Domingo", instant), 2025);
  assert.equal(currentYearInTimeZone("Europe/Paris", instant), 2026);
});

test("refuses invalid date input", () => {
  assert.throws(() => formatInTenantTimeZone("invalid", "fr", "Europe/Paris", { dateStyle: "medium" }), /DATE_TIME_INVALID/u);
});

test("renders a civil term date without shifting it through a device timezone", () => {
  assert.match(formatCalendarDate("2026-01-01", "en"), /Jan 1, 2026/u);
  assert.throws(() => formatCalendarDate("2026-02-30", "es"), /CALENDAR_DATE_INVALID/u);
});
