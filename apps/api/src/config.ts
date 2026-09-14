import path from "node:path";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const booleanString = z.enum(["true", "false"]).transform((value) => value === "true");

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_HOST: z.string().default("127.0.0.1"),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  API_CORS_ORIGINS: z.string().default("http://localhost:3000"),
  API_TRUSTED_PROXY_CIDRS: z.string().max(4_096).optional(),
  API_COOKIE_SECURE: booleanString.default("false"),
  API_SESSION_TTL_SECONDS: z.coerce.number().int().min(900).max(86_400).default(28_800),
  WEBAUTHN_RP_NAME: z.string().trim().min(1).max(100).default("Nombramientos"),
  WEBAUTHN_RP_ID: z.string().trim().min(1).max(253).default("localhost"),
  WEBAUTHN_EXPECTED_ORIGINS: z.string().default("http://localhost:3000"),
  WEBAUTHN_CHALLENGE_TTL_SECONDS: z.coerce.number().int().min(60).max(600).default(300),
  WEBAUTHN_STEP_UP_TTL_SECONDS: z.coerce.number().int().min(60).max(300).default(120),
  AUTH_ENCRYPTION_KEY_B64: z.string(),
  DATABASE_CONTROL_URL: z.string().url(),
  DATABASE_SECRET_MASTER_KEY_B64: z.string(),
  DATABASE_SECRET_FILE: z.string().optional(),
  DATABASE_POOL_MAX_PER_TENANT: z.coerce.number().int().min(1).max(20).default(3),
  DATABASE_POOL_IDLE_MS: z.coerce.number().int().min(1_000).max(600_000).default(60_000),
});

export interface ApiConfig {
  readonly environment: "development" | "test" | "production";
  readonly host: string;
  readonly port: number;
  readonly corsOrigins: ReadonlySet<string>;
  /** Exact socket-peer IPs/CIDRs whose forwarding headers Fastify may honor. */
  readonly trustedProxyCidrs?: readonly string[];
  readonly secureCookies: boolean;
  readonly sessionTtlSeconds: number;
  readonly webauthn: {
    readonly rpName: string;
    readonly rpId: string;
    readonly expectedOrigins: readonly string[];
    readonly challengeTtlSeconds: number;
    readonly stepUpTtlSeconds: number;
  };
  readonly authEncryptionKey: Buffer;
  readonly controlDatabaseUrl: string;
  readonly secretMasterKey: Buffer;
  readonly secretFile: string;
  readonly tenantPoolMax: number;
  readonly tenantPoolIdleMs: number;
}

export function parseApiConfig(source: NodeJS.ProcessEnv = process.env): ApiConfig {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const apiRoot = path.basename(path.dirname(moduleDirectory)).toLowerCase() === "dist"
    ? path.resolve(moduleDirectory, "../..")
    : path.resolve(moduleDirectory, "..");
  const localRoot = path.resolve(apiRoot, "../../packages/database/.local");
  const merged = source === process.env
    ? { ...readLocalInstall(source["DATABASE_LOCAL_INSTALL_FILE"] ?? path.join(localRoot, "install.json")), ...source }
    : source;
  const value = schema.parse(merged);
  const authEncryptionKey = Buffer.from(value.AUTH_ENCRYPTION_KEY_B64, "base64url");
  const secretMasterKey = Buffer.from(value.DATABASE_SECRET_MASTER_KEY_B64, "base64url");
  if (authEncryptionKey.byteLength !== 32) throw new Error("AUTH_ENCRYPTION_KEY_B64 must encode 32 bytes");
  if (secretMasterKey.byteLength !== 32) throw new Error("DATABASE_SECRET_MASTER_KEY_B64 must encode 32 bytes");
  const controlDatabaseUrl = canonicalWorkspaceControlUrl(value.DATABASE_CONTROL_URL);
  if (!isLoopbackHost(value.API_HOST)) throw new Error("API_HOST must remain on a loopback interface");
  const corsOrigins = value.API_CORS_ORIGINS.split(",").map((item) => item.trim()).filter(Boolean);
  if (corsOrigins.length === 0) throw new Error("API_CORS_ORIGINS must contain at least one explicit origin");
  for (const origin of corsOrigins) assertOrigin(origin);
  const trustedProxyCidrs = parseTrustedProxyCidrs(value.API_TRUSTED_PROXY_CIDRS);
  const webauthnOrigins = value.WEBAUTHN_EXPECTED_ORIGINS.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (webauthnOrigins.length === 0) {
    throw new Error("WEBAUTHN_EXPECTED_ORIGINS must contain at least one exact origin");
  }
  assertRpId(value.WEBAUTHN_RP_ID);
  for (const origin of webauthnOrigins) {
    assertWebAuthnOrigin(origin, value.WEBAUTHN_RP_ID, value.NODE_ENV, corsOrigins);
  }
  if (value.NODE_ENV === "production") {
    if (!value.API_COOKIE_SECURE) throw new Error("Production requires API_COOKIE_SECURE=true");
    if (corsOrigins.some((origin) => new URL(origin).protocol !== "https:")) {
      throw new Error("Production CORS origins must use HTTPS");
    }
    if (isLoopbackHost(value.WEBAUTHN_RP_ID)) {
      throw new Error("Production WebAuthn RP ID cannot be a loopback host");
    }
    if (trustedProxyCidrs.length === 0) {
      throw new Error("Production requires an explicit non-empty API_TRUSTED_PROXY_CIDRS allowlist");
    }
  }
  return {
    environment: value.NODE_ENV,
    host: value.API_HOST,
    port: value.API_PORT,
    corsOrigins: new Set(corsOrigins),
    trustedProxyCidrs,
    secureCookies: value.API_COOKIE_SECURE,
    sessionTtlSeconds: value.API_SESSION_TTL_SECONDS,
    webauthn: {
      rpName: value.WEBAUTHN_RP_NAME,
      rpId: value.WEBAUTHN_RP_ID.toLowerCase(),
      expectedOrigins: Object.freeze([...webauthnOrigins]),
      challengeTtlSeconds: value.WEBAUTHN_CHALLENGE_TTL_SECONDS,
      stepUpTtlSeconds: value.WEBAUTHN_STEP_UP_TTL_SECONDS,
    },
    authEncryptionKey,
    controlDatabaseUrl,
    secretMasterKey,
    secretFile: value.DATABASE_SECRET_FILE ?? path.join(localRoot, "secrets.enc.json"),
    tenantPoolMax: value.DATABASE_POOL_MAX_PER_TENANT,
    tenantPoolIdleMs: value.DATABASE_POOL_IDLE_MS,
  };
}

function parseTrustedProxyCidrs(value: string | undefined): readonly string[] {
  if (value === undefined || value.trim() === "") return Object.freeze([]);
  const entries = value.split(",").map((entry) => entry.trim());
  if (entries.some((entry) => entry === "")) {
    throw new Error("API_TRUSTED_PROXY_CIDRS must be a comma-separated list without empty entries");
  }
  if (entries.length > 64) throw new Error("API_TRUSTED_PROXY_CIDRS accepts at most 64 entries");

  const unique = new Set<string>();
  for (const entry of entries) {
    const slash = entry.indexOf("/");
    if (slash !== entry.lastIndexOf("/")) {
      throw new Error(`Invalid trusted proxy IP/CIDR: ${entry}`);
    }
    const address = slash < 0 ? entry : entry.slice(0, slash);
    const family = isIP(address);
    if (family === 0 || address === "0.0.0.0" || address === "::") {
      throw new Error(`Invalid trusted proxy IP/CIDR: ${entry}`);
    }
    if (slash >= 0) {
      const prefixText = entry.slice(slash + 1);
      if (!/^(?:0|[1-9][0-9]*)$/u.test(prefixText)) {
        throw new Error(`Invalid trusted proxy IP/CIDR: ${entry}`);
      }
      const prefix = Number(prefixText);
      const maximum = family === 4 ? 32 : 128;
      if (prefix < 1 || prefix > maximum) {
        throw new Error(`Trusted proxy CIDR prefix must be between 1 and ${maximum}: ${entry}`);
      }
    }
    unique.add(entry);
  }
  return Object.freeze([...unique]);
}

function assertOrigin(origin: string): void {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error(`Invalid CORS origin: ${origin}`);
  }
  if (
    parsed.origin !== origin
    || !["http:", "https:"].includes(parsed.protocol)
    || parsed.username
    || parsed.password
  ) {
    throw new Error(`CORS entries must be exact HTTP(S) origins: ${origin}`);
  }
}

function assertRpId(value: string): void {
  if (
    value !== value.toLowerCase()
    || value.includes("://")
    || value.includes(":")
    || value.includes("/")
    || value.startsWith(".")
    || value.endsWith(".")
    || /\s/u.test(value)
  ) {
    throw new Error("WEBAUTHN_RP_ID must be localhost or a lower-case DNS domain without scheme, port, or path");
  }
  if (value !== "localhost" && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value)) {
    throw new Error("WEBAUTHN_RP_ID is invalid");
  }
}

function assertWebAuthnOrigin(
  origin: string,
  rpId: string,
  environment: "development" | "test" | "production",
  corsOrigins: readonly string[],
): void {
  assertOrigin(origin);
  const parsed = new URL(origin);
  const hostname = parsed.hostname.toLowerCase();
  const relatedToRp = hostname === rpId || hostname.endsWith(`.${rpId}`);
  if (!relatedToRp) {
    throw new Error(`WebAuthn origin ${origin} is not within RP ID ${rpId}`);
  }
  if (!corsOrigins.includes(origin)) {
    throw new Error(`WebAuthn origin ${origin} must also be an allowed CORS origin`);
  }
  if (environment === "production" && parsed.protocol !== "https:") {
    throw new Error("Production WebAuthn origins must use HTTPS");
  }
  if (parsed.protocol === "http:" && hostname !== "localhost") {
    throw new Error("HTTP WebAuthn origins are allowed only on localhost during development or tests");
  }
}

function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
}

function canonicalWorkspaceControlUrl(value: string): string {
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
    || decodeURIComponent(parsed.username) !== "nom_control"
    || decodeURIComponent(parsed.password).length < 1
    || parsed.pathname !== "/nombramientos_control"
    || parsed.search !== ""
    || parsed.hash !== ""
  ) {
    throw new Error("DATABASE_CONTROL_URL must match the exact protected loopback control database contract");
  }

  const canonical = new URL("postgresql://127.0.0.1:55432/nombramientos_control");
  canonical.username = "nom_control";
  canonical.password = decodeURIComponent(parsed.password);
  return canonical.toString();
}

function readLocalInstall(file: string): Readonly<Record<string, string>> {
  try {
    const value: unknown = JSON.parse(readFileSync(file, "utf8"));
    const parsed = z.record(z.string(), z.union([z.string(), z.number()])).parse(value);
    return Object.fromEntries(Object.entries(parsed).map(([key, item]) => [key, String(item)]));
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") return {};
    throw error;
  }
}
