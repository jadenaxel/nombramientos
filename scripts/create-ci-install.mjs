import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomBytes, randomUUID } from "node:crypto";
import { appendFile, chmod, mkdir, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";

if (process.env.CI !== "true") throw new Error("This helper only creates ephemeral CI configuration");

const workspaceRoot = path.resolve(import.meta.dirname, "..");
const localRoot = path.join(workspaceRoot, "packages", "database", ".local");
const installFile = path.join(localRoot, "install.json");
const backupKeyFile = path.join(localRoot, "backup-keys.json");
const githubEnvironment = process.env.GITHUB_ENV;
if (!githubEnvironment) throw new Error("GITHUB_ENV is required");
const configuredPostgresBin = process.env.POSTGRES_BIN;
if (!configuredPostgresBin || !path.isAbsolute(configuredPostgresBin)) {
  throw new Error("POSTGRES_BIN must be the absolute portable PostgreSQL 18 client directory");
}
const postgresBin = await realpath(configuredPostgresBin);
for (const tool of ["pg_dump", "pg_restore"]) await assertPg18(postgresBin, tool);

const controlPassword = secret(36);
const activeBackupKeyId = randomUUID();
const backupKeys = {
  version: 1,
  activeKeyId: activeBackupKeyId,
  keys: [{
    id: activeBackupKeyId,
    createdAt: new Date().toISOString(),
    status: "active",
    keyB64: secret(32),
  }],
};
const payload = {
  version: 1,
  DATABASE_ADMIN_URL: "postgresql://postgres@127.0.0.1:55432/postgres",
  DATABASE_CONTROL_URL: `postgresql://nom_control:${controlPassword}@127.0.0.1:55432/nombramientos_control`,
  DATABASE_SECRET_MASTER_KEY_B64: secret(32),
  AUTH_ENCRYPTION_KEY_B64: secret(32),
  DEMO_INITIAL_PASSWORD: secret(32),
  DATABASE_SECRET_FILE: path.join(localRoot, "secrets.enc.json"),
  DATABASE_BACKUP_KEY_FILE: backupKeyFile,
  POSTGRES_BIN: postgresBin,
  API_HOST: "127.0.0.1",
  API_PORT: "4000",
  API_CORS_ORIGINS: "http://localhost:3000",
  API_COOKIE_SECURE: "false",
};

await mkdir(localRoot, { recursive: true, mode: 0o700 });
await writeFile(backupKeyFile, `${JSON.stringify(backupKeys)}\n`, { encoding: "utf8", mode: 0o600 });
await writeFile(installFile, `${JSON.stringify(payload)}\n`, { encoding: "utf8", mode: 0o600 });
await chmod(backupKeyFile, 0o600);
await chmod(installFile, 0o600);
await appendFile(
  githubEnvironment,
  [
    `DATABASE_LOCAL_INSTALL_FILE=${installFile}`,
    `DATABASE_BACKUP_KEY_FILE=${backupKeyFile}`,
    `POSTGRES_BIN=${postgresBin}`,
    "NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true",
    "NOMBRAMIENTOS_PRIVILEGE_LIVE=true",
    "",
  ].join("\n"),
  "utf8",
);
console.log("Created ephemeral CI install and backup-key configuration without printing credentials.");

function secret(bytes) {
  return randomBytes(bytes).toString("base64url");
}

async function assertPg18(directory, tool) {
  const executable = path.join(directory, process.platform === "win32" ? `${tool}.exe` : tool);
  const info = await stat(executable);
  if (!info.isFile()) throw new Error(`${tool} is unavailable in POSTGRES_BIN`);
  const { stdout } = await promisify(execFile)(executable, ["--version"], {
    windowsHide: true,
    encoding: "utf8",
  });
  if (!/\b18\.\d+\b/u.test(stdout)) throw new Error(`${tool} must be from PostgreSQL 18`);
}
