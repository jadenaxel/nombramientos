import { z } from "zod";

const IANA_TIMEZONE_PATTERN = /^[A-Za-z_+-]+(?:\/[A-Za-z0-9_+-]+)+$/;

export function isValidIanaTimezone(value: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value }).format(new Date(0));
    return true;
  } catch {
    return false;
  }
}

export const ianaTimezoneSchema = z.string()
  .trim()
  .min(1)
  .max(80)
  .regex(IANA_TIMEZONE_PATTERN, "Timezone must be a regional IANA identifier")
  .refine(isValidIanaTimezone, "Timezone must be a recognized IANA identifier");
