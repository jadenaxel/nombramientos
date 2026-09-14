import { describe, expect, it } from "vitest";

import {
  assertExactLocalPostgresUrl,
  assertSameExactLocalPostgresCluster,
  exactLocalPostgresPoolConfig,
  exactLocalPostgresUrlForDatabase,
} from "../scripts/local-performance-database-guards.js";

const ADMIN_URL = "postgresql://nom_admin:fixture@127.0.0.1:55432/postgres";
const CONTROL_URL = "postgresql://nom_control:fixture@127.0.0.1:55432/nombramientos_control";

describe("local performance PostgreSQL guard", () => {
  it("materializes explicit PoolConfig for the one authorized local cluster", () => {
    expect(exactLocalPostgresPoolConfig(ADMIN_URL, "postgres", "nom_t_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).toEqual({
      host: "127.0.0.1",
      port: 55_432,
      database: "nom_t_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      user: "nom_admin",
      password: "fixture",
      ssl: false,
    });
    expect(exactLocalPostgresPoolConfig(ADMIN_URL, "postgres")).not.toHaveProperty("connectionString");
    expect(() => assertSameExactLocalPostgresCluster(ADMIN_URL, "postgres", CONTROL_URL, "nombramientos_control")).not.toThrow();
  });

  it("builds a canonical option-free URL only when a string is required by ApiConfig", () => {
    const value = exactLocalPostgresUrlForDatabase(ADMIN_URL, "postgres", "nom_c_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(value).toBe("postgresql://nom_admin:fixture@127.0.0.1:55432/nom_c_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(new URL(value).search).toBe("");
    expect(new URL(value).hash).toBe("");
  });

  it.each([
    "postgresql://nom_admin:fixture@remote.example:55432/postgres",
    "postgresql://nom_admin:fixture@localhost:55432/postgres",
    "postgresql://nom_admin:fixture@[::1]:55432/postgres",
    "postgresql://nom_admin:fixture@127.0.0.1:5432/postgres",
    "postgresql://nom_admin:fixture@127.0.0.1:5433/postgres",
    "postgresql://nom_admin:fixture@127.0.0.1:55433/postgres",
    "postgresql://nom_admin:fixture@127.0.0.1:55432/nombramientos_control",
    "postgresql://nom_admin@127.0.0.1:55432/postgres",
    "postgresql://127.0.0.1:55432/postgres",
    "postgresql://nom_admin:fixture@127.0.0.1:55432/postgres?host=remote.example&port=5432",
    "postgresql://nom_admin:fixture@127.0.0.1:55432/postgres?host=%2Ftmp",
    "postgresql://nom_admin:fixture@127.0.0.1:55432/postgres?sslmode=require",
    "postgresql://nom_admin:fixture@127.0.0.1:55432/postgres#remote",
    "postgresql://nom_admin:fixture@2130706433:55432/postgres",
    "postgresql://nom_admin:fixture@127.0.0.1.:55432/postgres",
    "postgresql://runner:fixture@127.0.0.1:55432/postgres",
    "postgresql://nom_control:fixture@127.0.0.1:55432/postgres",
    " postgresql://nom_admin:fixture@127.0.0.1:55432/postgres",
    "postgresql://nom_admin:fixture@127.0.0.1:55432/postgres ",
  ])("rejects ambiguous or non-local target %s", (value) => {
    expect(() => assertExactLocalPostgresUrl(value, "postgres")).toThrow(/exact local PostgreSQL|explicit bounded|surrounding whitespace/u);
  });
});
