import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const workspaceRoot = path.resolve(import.meta.dirname, "../../..");
const read = (relative: string): string => readFileSync(path.join(workspaceRoot, relative), "utf8");

const compose = read("compose.yaml");
const dockerfile = read("Dockerfile");
const dockerignore = read(".dockerignore");
const gitignore = read(".gitignore");
const entrypoint = read("scripts/container-entrypoint.mjs");
const secretInitializer = read("scripts/container-secrets.mjs");
const provisionTenants = read("packages/database/scripts/provision-tenants.ts");
const provisioningWorker = read("packages/database/scripts/process-provisioning-jobs.ts");
const localCluster = read("packages/database/scripts/local-cluster.ps1");
const development = read("config/container/development.compose.env");
const test = read("config/container/test.compose.env");

describe("local container runtime contract", () => {
  it("pins PostgreSQL 18 and preserves the existing loopback-only runtime boundary", () => {
    expect(compose).toContain("image: postgres:18.6-bookworm");
    expect(compose).toContain('network_mode: "service:postgres"');
    expect((compose.match(/network_mode: "service:postgres"/gu) ?? [])).toHaveLength(1);
    expect(entrypoint).toContain('NOMBRAMIENTOS_POSTGRES_HOST ?? "127.0.0.1"');
    expect(entrypoint).toContain('!== "127.0.0.1"');
    expect(entrypoint).toContain('!== 55_432');
    expect(entrypoint).toContain("version >= 190_000");
    expect(compose).toContain('API_HOST: "127.0.0.1"');
    expect(compose).toContain('NOMBRAMIENTOS_WEB_HOST: "127.0.0.1"');
  });

  it("publishes only loopback gateway ports and has health checks for every long-running service", () => {
    expect(compose).toContain('"127.0.0.1:${NOMBRAMIENTOS_HOST_DATABASE_PORT:?Set NOMBRAMIENTOS_HOST_DATABASE_PORT}:55432"');
    expect(compose).toContain('"127.0.0.1:${NOMBRAMIENTOS_HOST_WEB_PORT:?Set NOMBRAMIENTOS_HOST_WEB_PORT}:${NOMBRAMIENTOS_HOST_WEB_PORT}"');
    expect(compose).toContain('"127.0.0.1:${NOMBRAMIENTOS_HOST_API_PORT:?Set NOMBRAMIENTOS_HOST_API_PORT}:${NOMBRAMIENTOS_HOST_API_PORT}"');
    expect((compose.match(/healthcheck:/gu) ?? [])).toHaveLength(5);
    expect(compose).toContain("condition: service_completed_successfully");
    expect(compose).toContain("condition: service_healthy");
  });

  it("uses mounted secrets and excludes every local secret/build directory from the image context", () => {
    expect(compose).toContain("POSTGRES_PASSWORD_FILE: /run/secrets/postgres_admin_password");
    expect(compose).not.toMatch(/^\s*POSTGRES_PASSWORD:\s*.+$/mu);
    expect(compose).not.toMatch(/postgresql:\/\/[^\s]+:[^$\s]+@/u);
    expect(entrypoint).not.toMatch(/(?:password|key)\s*=\s*["'][A-Za-z0-9_-]{43}["']/iu);
    expect(secretInitializer).toContain("randomBytes(32).toString(\"base64url\")");
    for (const ignored of [".local", "**/.local", "node_modules", "**/node_modules", ".env", "artifacts"]) {
      expect(dockerignore).toContain(ignored);
    }
    expect(gitignore).toContain("**/.local/");
  });

  it("runs as an unprivileged application user with a persistent, project-scoped database volume", () => {
    expect(dockerfile).toContain("USER nombramientos");
    expect(compose).toContain("no-new-privileges:true");
    expect(compose).toContain("cap_drop:");
    expect((compose.match(/read_only: true/gu) ?? [])).toHaveLength(5);
    expect(compose).toContain("postgres-data:/var/lib/postgresql");
    expect(compose).toContain("postgres-data:");
    for (const volume of ["bootstrap-private:", "runtime-secrets:", "worker-state:"]) {
      expect(compose).toContain(volume);
    }
  });

  it("does not expose bootstrap, administrator, backup, or demo state to the API", () => {
    const api = serviceBlock("api", "worker");
    const bootstrap = serviceBlock("bootstrap", "api");
    const worker = serviceBlock("worker", "web");
    expect(api).toContain("runtime-secrets:/workspace/packages/database/.local/runtime:ro");
    expect(api).not.toContain("bootstrap-private");
    expect(api).not.toContain("postgres_admin_password");
    expect(bootstrap).toContain("bootstrap-private:/workspace/packages/database/.local");
    expect(worker).toContain("bootstrap-private:/workspace/packages/database/.local");
    expect(compose).toContain("DATABASE_SECRET_FILE: /workspace/packages/database/.local/runtime/secrets.enc.json");
    expect(provisionTenants).toContain('process.env["DATABASE_SECRET_FILE"] ??');
    expect(provisioningWorker).toContain('process.env["DATABASE_SECRET_FILE"] ??');
  });

  it("keeps development and test state, images, projects and host ports independent", () => {
    expect(development).toContain("COMPOSE_PROJECT_NAME=nombramientos-dev");
    expect(test).toContain("COMPOSE_PROJECT_NAME=nombramientos-test");
    expect(development).toContain("NOMBRAMIENTOS_CONTAINER_STATE_DIR=./.local/container/development");
    expect(test).toContain("NOMBRAMIENTOS_CONTAINER_STATE_DIR=./.local/container/test");
    expect(development).toContain("NOMBRAMIENTOS_HOST_WEB_PORT=3300");
    expect(test).toContain("NOMBRAMIENTOS_HOST_WEB_PORT=3301");
    expect(development).not.toBe(test);
    expect(canonicalBrowserEntries(development)).toEqual([
      "NOMBRAMIENTOS_BROWSER_API_URL=http://localhost:4400",
      "NOMBRAMIENTOS_BROWSER_ORIGINS=http://localhost:3300",
    ]);
    expect(canonicalBrowserEntries(test)).toEqual([
      "NOMBRAMIENTOS_BROWSER_API_URL=http://localhost:4401",
      "NOMBRAMIENTOS_BROWSER_ORIGINS=http://localhost:3301",
    ]);
  });

  it("reconciles existing local installs to the canonical browser origin without regenerating credentials", () => {
    expect(localCluster).toContain("function Update-NomInstallBrowserOrigin");
    expect(localCluster).toContain("[System.IO.File]::Replace($NomTemporaryInstall, $NomInstallFile, $null)");
    expect(localCluster).toContain("Update-NomInstallBrowserOrigin");
    expect(localCluster).toContain("API_CORS_ORIGINS = 'http://localhost:3000'");
    expect(localCluster).not.toContain("API_CORS_ORIGINS = 'http://127.0.0.1:3000");
    expect(localCluster).toContain("without changing credentials");
  });

  function canonicalBrowserEntries(source: string): string[] {
    return source.split(/\r?\n/u).filter((line) => line.includes("localhost:"));
  }

  it("never auto-adopts or trusts an existing database without complete re-attestation", () => {
    expect(entrypoint).toContain("Control database exists without the matching container bootstrap marker");
    expect(entrypoint).toContain('status: "in_progress"');
    expect(entrypoint).toContain('status: "completed"');
    expect(entrypoint).toContain("await attestBootstrapState();");
    expect(entrypoint).toContain("await attestMigrationLedger(route.databaseName, \"tenant\", adminPassword);");
    expect(entrypoint).toContain("runtimeFingerprint");
    expect(entrypoint).toContain("A tenant runtime credential connected to another tenant database");
    expect(entrypoint).toContain("await runBootstrapIssuer();");
  });

  it("rejects symlinked state ancestors before creating or reading host-side secrets", () => {
    expect(secretInitializer).toContain("for (const segment of relative.split(path.sep))");
    expect(secretInitializer).toContain("info.isSymbolicLink()");
    expect(secretInitializer).toContain("Unsafe container state ancestor");
  });
});

function serviceBlock(service: string, nextService: string): string {
  const match = compose.match(new RegExp(`^  ${service}:([\\s\\S]*?)(?=^  ${nextService}:)`, "mu"));
  if (!match?.[1]) throw new Error(`Compose service block is unavailable: ${service}`);
  return match[1];
}
