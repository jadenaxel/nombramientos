import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const postgresAdminUrl = workspacePostgresUrl("nom_admin", "postgres");
const postgresControlUrl = workspacePostgresUrl("nom_control", "nombramientos_control");

export const localScriptEnvironment = z.object({
  DATABASE_ADMIN_URL: postgresAdminUrl,
  DATABASE_CONTROL_URL: postgresControlUrl.optional(),
  DATABASE_SECRET_MASTER_KEY_B64: z.string().optional(),
});

export type LocalScriptEnvironment = z.infer<typeof localScriptEnvironment>;

export function loadLocalScriptValues(source: NodeJS.ProcessEnv = process.env): Record<string, string | undefined> {
  const packageRoot = resolveDatabasePackageRoot(import.meta.url);
  const installFile = source["DATABASE_LOCAL_INSTALL_FILE"] ?? path.join(packageRoot, ".local", "install.json");
  let installed: Record<string, string> = {};
  try {
    const raw: unknown = JSON.parse(readFileSync(installFile, "utf8"));
    const record = z.record(z.string(), z.union([z.string(), z.number()])).parse(raw);
    installed = Object.fromEntries(Object.entries(record).map(([key, value]) => [key, String(value)]));
  } catch (error) {
    if (!isMissingFile(error)) throw error;
  }
  return { ...installed, ...source };
}

export function resolveDatabasePackageRoot(moduleUrl: string): string {
  const parent = path.resolve(path.dirname(fileURLToPath(moduleUrl)), "..");
  return path.basename(parent).toLowerCase() === "dist" ? path.dirname(parent) : parent;
}

export function loadLocalScriptEnvironment(source: NodeJS.ProcessEnv = process.env): LocalScriptEnvironment {
  return localScriptEnvironment.parse(loadLocalScriptValues(source));
}

export function requireMasterKey(encoded: string | undefined): Buffer {
  if (!encoded) throw new Error("DATABASE_SECRET_MASTER_KEY_B64 is required");
  const value = Buffer.from(encoded, "base64url");
  if (value.byteLength !== 32) throw new Error("DATABASE_SECRET_MASTER_KEY_B64 must encode 32 bytes");
  return value;
}

export function withoutDatabase(connectionString: string, database = "postgres"): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(database)) {
    throw new Error("Local PostgreSQL database target is invalid");
  }
  const url = assertWorkspacePostgresUrl(connectionString, "nom_admin", "postgres");
  url.pathname = `/${database}`;
  return url.toString();
}

export function assertWorkspacePostgresUrl(value: string, user: string, database: string): URL {
  const parsed = new URL(value);
  const schemeEnd = value.indexOf("://");
  const remainder = schemeEnd < 0 ? "" : value.slice(schemeEnd + 3);
  const authorityEnd = remainder.search(/[/?#]/u);
  const authority = authorityEnd < 0 ? remainder : remainder.slice(0, authorityEnd);
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  if (
    value !== value.trim()
    || !["postgres:", "postgresql:"].includes(parsed.protocol)
    || hostPort !== "127.0.0.1:55432"
    || parsed.hostname !== "127.0.0.1"
    || parsed.port !== "55432"
    || decodeURIComponent(parsed.username) !== user
    || decodeURIComponent(parsed.password).length < 1
    || parsed.pathname !== `/${database}`
    || parsed.search !== ""
    || parsed.hash !== ""
  ) {
    throw new Error("Local PostgreSQL URLs must match the exact workspace endpoint and role contract");
  }
  return parsed;
}

function workspacePostgresUrl(user: string, database: string): z.ZodType<string> {
  return z.string().url().superRefine((value, context) => {
    try {
      assertWorkspacePostgresUrl(value, user, database);
    } catch {
      context.addIssue({
        code: "custom",
        message: "Expected the exact protected workspace PostgreSQL endpoint",
      });
    }
  });
}

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
