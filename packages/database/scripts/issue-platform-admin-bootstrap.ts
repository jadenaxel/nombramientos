import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { z } from "zod";
import { loadLocalScriptEnvironment, resolveDatabasePackageRoot, withoutDatabase } from "./script-config.js";

const bootstrapFileSchema = z.object({
  version: z.literal(1),
  bootstrapId: z.string().uuid(),
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  expiresAt: z.string().datetime({ offset: true }),
  activationPath: z.literal("/es/auth/platform-bootstrap"),
  purpose: z.enum(["bootstrap", "recovery"]),
}).strict();

const DEMO_TENANT_ID = "d0000000-0000-4000-8000-000000000001";
const lifetimeMinutes = 60;
const recovery = process.argv.slice(2).includes("--recovery");
const recoveryReasonCodeSchema = z.enum([
  "SECURITY_RESPONSE",
  "ADMIN_ACCESS_LOSS",
  "AUTHORIZED_RECOVERY",
]);
const recoveryReasonCode = recoveryReasonCodeSchema.safeParse(
  process.env["NOMBRAMIENTOS_PLATFORM_RECOVERY_REASON_CODE"]?.trim(),
);
const externalIncidentReference = z.string().uuid().safeParse(
  process.env["NOMBRAMIENTOS_PLATFORM_RECOVERY_INCIDENT_REF"]?.trim(),
);
if (recovery) {
  if (process.env["NOMBRAMIENTOS_PLATFORM_RECOVERY_CONFIRM"] !== "ROTATE_PLATFORM_ADMIN_BOOTSTRAP") {
    throw new Error("Explicit platform recovery confirmation is required");
  }
  if (!recoveryReasonCode.success) {
    throw new Error("An allowed non-sensitive platform recovery reason code is required");
  }
  if (!externalIncidentReference.success) {
    throw new Error("An opaque UUID external incident reference is required");
  }
}

const environment = loadLocalScriptEnvironment();
const packageRoot = resolveDatabasePackageRoot(import.meta.url);
const localRoot = path.join(packageRoot, ".local");
const destination = path.join(localRoot, "platform-admin-bootstrap.json");
const control = new Pool({
  connectionString: withoutDatabase(environment.DATABASE_ADMIN_URL, "nombramientos_control"),
  application_name: "nombramientos-platform-bootstrap-issuer",
  max: 1,
});

try {
  const client = await control.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('platform-admin-bootstrap-issuer', 0))");
    await client.query(
      `UPDATE platform_admin_bootstrap_tokens
          SET status='expired',version=version+1
        WHERE status='pending' AND expires_at <= clock_timestamp()`,
    );
    const active = await client.query<{ active: boolean }>(
      `SELECT EXISTS(
         SELECT 1 FROM platform_role_bindings binding
         JOIN platform_identities identity ON identity.id=binding.identity_id
        WHERE binding.role_code='platform_admin' AND identity.status='active'
       ) AS active`,
    );
    if (!recovery && active.rows[0]?.active) {
      await client.query("COMMIT");
      process.stdout.write("Platform administrator bootstrap is already complete; no activation material was issued.\n");
    } else {
      const pending = await client.query<{
        id: string;
        token_hash: string;
        expires_at: Date;
        purpose: "bootstrap" | "recovery";
      }>(
        `SELECT id,token_hash,expires_at,purpose
           FROM platform_admin_bootstrap_tokens
          WHERE status='pending'
          FOR UPDATE`,
      );
      const existing = pending.rows[0];
      if (existing && !recovery) {
        const local = await readBootstrapFile(destination);
        if (!local || local.bootstrapId !== existing.id || sha256(local.token) !== existing.token_hash
            || Date.parse(local.expiresAt) <= Date.now()) {
          throw new Error("Pending bootstrap material is unavailable; use the explicit guarded recovery command");
        }
        await client.query("COMMIT");
        process.stdout.write("Platform administrator bootstrap material remains ready in protected local state.\n");
      } else {
        if (existing) {
          await client.query(
            "UPDATE platform_admin_bootstrap_tokens SET status='revoked',version=version+1 WHERE id=$1",
            [existing.id],
          );
        }
        const anchor = await client.query(
          "SELECT 1 FROM tenants WHERE id=$1 AND kind='demo' AND status='active' FOR UPDATE",
          [DEMO_TENANT_ID],
        );
        if (anchor.rowCount !== 1) throw new Error("The isolated demo authentication anchor is not active");
        const token = randomBytes(32).toString("base64url");
        const expiresAt = new Date(Date.now() + lifetimeMinutes * 60_000);
        const inserted = await client.query<{ id: string }>(
          `INSERT INTO platform_admin_bootstrap_tokens(
             token_hash,purpose,anchor_tenant_id,recovery_reason_code,external_incident_ref_hash,expires_at
           ) VALUES ($1,$2,$3,$4,$5,$6)
           RETURNING id`,
          [
            sha256(token),
            recovery ? "recovery" : "bootstrap",
            DEMO_TENANT_ID,
            recovery && recoveryReasonCode.success ? recoveryReasonCode.data : null,
            recovery && externalIncidentReference.success ? sha256(externalIncidentReference.data) : null,
            expiresAt,
          ],
        );
        const bootstrapId = inserted.rows[0]?.id;
        if (!bootstrapId) throw new Error("Platform administrator bootstrap issuance failed");
        await writeBootstrapFile(destination, {
          version: 1,
          bootstrapId,
          token,
          expiresAt: expiresAt.toISOString(),
          activationPath: "/es/auth/platform-bootstrap",
          purpose: recovery ? "recovery" : "bootstrap",
        });
        await client.query("COMMIT");
        process.stdout.write("Platform administrator bootstrap material was created in protected local state.\n");
      }
    }
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
} finally {
  await control.end();
}

async function readBootstrapFile(filePath: string): Promise<z.infer<typeof bootstrapFileSchema> | null> {
  try {
    return bootstrapFileSchema.parse(JSON.parse(await readFile(filePath, "utf8")));
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") return null;
    return null;
  }
}

async function writeBootstrapFile(
  filePath: string,
  material: z.infer<typeof bootstrapFileSchema>,
): Promise<void> {
  const temporary = `${filePath}.${process.pid}.tmp`;
  await mkdir(path.dirname(filePath), { recursive: true });
  try {
    await writeFile(temporary, `${JSON.stringify(material)}\n`, { encoding: "utf8", mode: 0o600 });
    await restrictFile(temporary);
    await rename(temporary, filePath);
    await restrictFile(filePath);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

async function restrictFile(filePath: string): Promise<void> {
  await chmod(filePath, 0o600).catch(() => undefined);
  if (process.platform !== "win32") return;
  const identity = execFileSync("whoami.exe", { encoding: "utf8", windowsHide: true }).trim();
  if (!identity) throw new Error("Could not resolve the local identity for bootstrap ACLs");
  execFileSync("icacls.exe", [
    filePath,
    "/inheritance:r",
    "/grant:r",
    `${identity}:F`,
    "/grant:r",
    "*S-1-5-18:F",
  ], { stdio: "ignore", windowsHide: true });
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
