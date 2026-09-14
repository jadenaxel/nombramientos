import type { PoolConfig } from "pg";
import { z } from "zod";

const postgresUrl = z
  .string()
  .min(1)
  .superRefine((value, context) => {
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
        context.addIssue({ code: "custom", message: "Expected a PostgreSQL URL" });
      }
    } catch {
      context.addIssue({ code: "custom", message: "Expected a valid PostgreSQL URL" });
    }
  });

const environmentSchema = z.object({
  DATABASE_CONTROL_URL: postgresUrl,
  DATABASE_SECRET_MAP_JSON: z.string().default("{}"),
  DATABASE_POOL_MAX_PER_TENANT: z.coerce.number().int().min(1).max(20).default(3),
  DATABASE_POOL_IDLE_MS: z.coerce.number().int().min(1_000).max(600_000).default(60_000),
  DATABASE_SSL_MODE: z.enum(["disable", "require", "verify-full"]).default("disable")
});

export interface DatabaseEnvironment {
  readonly control: PoolConfig;
  readonly secretMap: Readonly<Record<string, string>>;
  readonly tenantPoolMax: number;
  readonly tenantPoolIdleMs: number;
}

export function parseDatabaseEnvironment(
  source: NodeJS.ProcessEnv = process.env,
): DatabaseEnvironment {
  const value = environmentSchema.parse(source);
  const parsedSecrets: unknown = JSON.parse(value.DATABASE_SECRET_MAP_JSON);
  const secretMap = z.record(z.string(), z.string().min(1)).parse(parsedSecrets);

  return {
    control: {
      connectionString: value.DATABASE_CONTROL_URL,
      application_name: "nombramientos-control",
      max: 5,
      ssl: sslForMode(value.DATABASE_SSL_MODE),
    },
    secretMap,
    tenantPoolMax: value.DATABASE_POOL_MAX_PER_TENANT,
    tenantPoolIdleMs: value.DATABASE_POOL_IDLE_MS,
  };
}

export function sslForMode(
  mode: "disable" | "require" | "verify-full",
): PoolConfig["ssl"] {
  if (mode === "disable") return false;
  if (mode === "require") return { rejectUnauthorized: false };
  return { rejectUnauthorized: true };
}

export function redactConnectionString(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.username) parsed.username = "[redacted]";
    if (parsed.password) parsed.password = "[redacted]";
    return parsed.toString();
  } catch {
    return "[invalid PostgreSQL URL]";
  }
}
