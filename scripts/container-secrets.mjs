import { randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const supportedEnvironments = new Set(["development", "test"]);
const command = process.argv[2] ?? "check";
const environment = process.argv[3] ?? "development";

if (!new Set(["init", "check"]).has(command)) {
  throw new Error("Usage: node scripts/container-secrets.mjs <init|check> <development|test>");
}
if (!supportedEnvironments.has(environment)) {
  throw new Error("Container secrets are limited to the isolated development and test environments");
}

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const localStateRoot = path.join(workspaceRoot, ".local");
const stateRoot = path.join(localStateRoot, "container", environment);
const secretsRoot = path.join(stateRoot, "secrets");
const secretNames = [
  "postgres_admin_password",
  "control_password",
  "database_master_key",
  "auth_key",
];

await ensureLocalStateRoot();
await ensureDirectory(stateRoot);
await ensureDirectory(secretsRoot);
await ensureDirectory(path.join(stateRoot, "database"));
await ensureDirectory(path.join(stateRoot, "worker"));

let created = 0;
let preserved = 0;
for (const name of secretNames) {
  const destination = path.join(secretsRoot, name);
  const existing = await readExistingSecret(destination);
  if (existing !== null) {
    validateSecret(name, existing);
    await protectPath(destination, false);
    preserved += 1;
    continue;
  }
  if (command === "check") {
    throw new Error(`Container secret is missing: ${name}`);
  }
  const value = randomBytes(32).toString("base64url");
  const handle = await open(destination, "wx", 0o600);
  try {
    await handle.writeFile(`${value}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await protectPath(destination, false);
  created += 1;
}

process.stdout.write(`${JSON.stringify({
  status: "ready",
  environment,
  stateDirectory: path.relative(workspaceRoot, stateRoot).split(path.sep).join("/"),
  created,
  preserved,
  secretsPrinted: false,
})}\n`);

async function ensureDirectory(directory) {
  const resolved = path.resolve(directory);
  const relative = path.relative(localStateRoot, resolved);
  if (!relative || relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) {
    throw new Error("Container state must remain inside the ignored .local directory");
  }
  let current = localStateRoot;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    try {
      const info = await lstat(current);
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`Unsafe container state ancestor: ${current}`);
    } catch (error) {
      if (!isMissing(error)) throw error;
      await mkdir(current, { recursive: false, mode: 0o700 });
    }
    await protectPath(current, true);
  }
}

async function ensureLocalStateRoot() {
  try {
    const info = await lstat(localStateRoot);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`Unsafe local state root: ${localStateRoot}`);
  } catch (error) {
    if (!isMissing(error)) throw error;
    await mkdir(localStateRoot, { recursive: false, mode: 0o700 });
  }
  await protectPath(localStateRoot, true);
}

async function readExistingSecret(file) {
  try {
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Unsafe container secret path: ${file}`);
    return (await readFile(file, "utf8")).trim();
  } catch (error) {
    if (isMissing(error)) return null;
    throw error;
  }
}

function validateSecret(name, value) {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error(`Container secret has invalid encoding: ${name}`);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== 32 || decoded.toString("base64url") !== value) {
    throw new Error(`Container secret must encode exactly 32 random bytes: ${name}`);
  }
  decoded.fill(0);
}

async function protectPath(target, directory) {
  if (process.platform !== "win32") {
    await chmod(target, directory ? 0o700 : 0o600);
    return;
  }
  const username = process.env.USERNAME;
  const domain = process.env.USERDOMAIN;
  if (!username) throw new Error("USERNAME is required to protect local container secrets on Windows");
  const identity = domain ? `${domain}\\${username}` : username;
  const rights = directory ? "(OI)(CI)F" : "F";
  const result = spawnSync("icacls.exe", [
    target,
    "/inheritance:r",
    "/grant:r",
    `${identity}:${rights}`,
    "/grant:r",
    `*S-1-5-18:${rights}`,
  ], { stdio: "ignore", windowsHide: true });
  if (result.status !== 0) throw new Error(`Could not restrict ACL for ${path.basename(target)}`);
}

function isMissing(error) {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
