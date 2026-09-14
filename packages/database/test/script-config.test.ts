import { describe, expect, it } from "vitest";

import {
  assertWorkspacePostgresUrl,
  localScriptEnvironment,
  withoutDatabase,
} from "../scripts/script-config.js";

const adminUrl = "postgresql://nom_admin:fixture@127.0.0.1:55432/postgres";
const controlUrl = "postgresql://nom_control:fixture@127.0.0.1:55432/nombramientos_control";

describe("local script PostgreSQL boundary", () => {
  it("accepts and rewrites only the exact protected workspace administrator URL", () => {
    expect(localScriptEnvironment.parse({
      DATABASE_ADMIN_URL: adminUrl,
      DATABASE_CONTROL_URL: controlUrl,
    })).toMatchObject({ DATABASE_ADMIN_URL: adminUrl, DATABASE_CONTROL_URL: controlUrl });
    const tenant = new URL(withoutDatabase(adminUrl, "nom_t_0123456789abcdef0123456789abcdef"));
    expect({
      hostname: tenant.hostname,
      port: tenant.port,
      pathname: tenant.pathname,
      search: tenant.search,
      hash: tenant.hash,
      username: decodeURIComponent(tenant.username),
    }).toEqual({
      hostname: "127.0.0.1",
      port: "55432",
      pathname: "/nom_t_0123456789abcdef0123456789abcdef",
      search: "",
      hash: "",
      username: "nom_admin",
    });
  });

  it("rejects query precedence, fragments, aliases, external hosts and wrong identities", () => {
    for (const value of [
      `${adminUrl}?host=db.example.invalid`,
      `${adminUrl}?port=5432`,
      `${adminUrl}#host=db.example.invalid`,
      "postgresql://nom_admin:fixture@localhost:55432/postgres",
      "postgresql://nom_admin:fixture@[::1]:55432/postgres",
      "postgresql://nom_admin:fixture@2130706433:55432/postgres",
      "postgresql://nom_admin:fixture@127.0.0.1.:55432/postgres",
      "postgresql://nom_admin:fixture@127.0.0.1:5432/postgres",
      "postgresql://other:fixture@127.0.0.1:55432/postgres",
      "postgresql://nom_admin@127.0.0.1:55432/postgres",
      "postgresql://nom_admin:fixture@127.0.0.1:55432/nombramientos_control",
      ` ${adminUrl}`,
    ]) {
      expect(() => assertWorkspacePostgresUrl(value, "nom_admin", "postgres"), value).toThrow();
      expect(() => localScriptEnvironment.parse({ DATABASE_ADMIN_URL: value }), value).toThrow();
    }
  });

  it("requires the exact control role and database when supplied", () => {
    expect(() => localScriptEnvironment.parse({
      DATABASE_ADMIN_URL: adminUrl,
      DATABASE_CONTROL_URL: controlUrl.replace("nom_control", "nom_admin"),
    })).toThrow();
    expect(() => withoutDatabase(adminUrl, "../postgres")).toThrow(/target/u);
  });
});
