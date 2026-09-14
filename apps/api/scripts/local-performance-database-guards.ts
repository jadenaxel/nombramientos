import type { PoolConfig } from "pg";

export const LOCAL_PERFORMANCE_POSTGRES_HOST = "127.0.0.1";
export const LOCAL_PERFORMANCE_POSTGRES_PORT = 55_432;

interface ExactLocalPostgresTarget {
  readonly database: string;
  readonly user: string;
  readonly password: string;
}

export function assertExactLocalPostgresUrl(
  value: string,
  expectedDatabase: string,
): ExactLocalPostgresTarget {
  assertDatabaseName(expectedDatabase);
  const expectedUser = expectedSourceUser(expectedDatabase);
  if (value.trim() !== value) {
    throw new Error("The performance runner PostgreSQL URL must not contain surrounding whitespace");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("The performance runner PostgreSQL URL is malformed");
  }

  if (
    !["postgres:", "postgresql:"].includes(parsed.protocol)
    || parsed.hostname !== LOCAL_PERFORMANCE_POSTGRES_HOST
    || parsed.port !== String(LOCAL_PERFORMANCE_POSTGRES_PORT)
    || parsed.host !== `${LOCAL_PERFORMANCE_POSTGRES_HOST}:${LOCAL_PERFORMANCE_POSTGRES_PORT}`
    || parsed.pathname !== `/${expectedDatabase}`
    || parsed.search !== ""
    || parsed.hash !== ""
    || parsed.username !== expectedUser
    || parsed.password === ""
  ) {
    throw new Error("The performance runner requires exact local PostgreSQL on 127.0.0.1:55432 without URL options");
  }

  let user: string;
  let password: string;
  try {
    user = decodeURIComponent(parsed.username);
    password = decodeURIComponent(parsed.password);
  } catch {
    throw new Error("The performance runner PostgreSQL credentials are malformed");
  }
  if (user !== expectedUser || !isSafeCredential(password)) {
    throw new Error("The performance runner requires explicit bounded PostgreSQL credentials");
  }

  return { database: expectedDatabase, user, password };
}

export function exactLocalPostgresPoolConfig(
  sourceUrl: string,
  expectedSourceDatabase: string,
  targetDatabase = expectedSourceDatabase,
): PoolConfig {
  const target = assertExactLocalPostgresUrl(sourceUrl, expectedSourceDatabase);
  assertDatabaseName(targetDatabase);
  return {
    host: LOCAL_PERFORMANCE_POSTGRES_HOST,
    port: LOCAL_PERFORMANCE_POSTGRES_PORT,
    database: targetDatabase,
    user: target.user,
    password: target.password,
    ssl: false,
  };
}

export function exactLocalPostgresUrlForDatabase(
  sourceUrl: string,
  expectedSourceDatabase: string,
  targetDatabase: string,
): string {
  const target = assertExactLocalPostgresUrl(sourceUrl, expectedSourceDatabase);
  assertDatabaseName(targetDatabase);
  const parsed = new URL(`postgresql://${LOCAL_PERFORMANCE_POSTGRES_HOST}:${LOCAL_PERFORMANCE_POSTGRES_PORT}/${targetDatabase}`);
  parsed.username = target.user;
  parsed.password = target.password;
  return parsed.toString();
}

export function assertSameExactLocalPostgresCluster(
  leftUrl: string,
  leftDatabase: string,
  rightUrl: string,
  rightDatabase: string,
): void {
  assertExactLocalPostgresUrl(leftUrl, leftDatabase);
  assertExactLocalPostgresUrl(rightUrl, rightDatabase);
}

function assertDatabaseName(value: string): void {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(value)) {
    throw new Error("The performance runner PostgreSQL database name is invalid");
  }
}

function expectedSourceUser(database: string): "nom_admin" | "nom_control" {
  if (database === "postgres") return "nom_admin";
  if (database === "nombramientos_control") return "nom_control";
  throw new Error("The performance runner source database is not an authorized workspace route");
}

function isSafeCredential(value: string): boolean {
  return value.length >= 1 && value.length <= 1_024 && !/[\u0000-\u001f\u007f]/u.test(value);
}
