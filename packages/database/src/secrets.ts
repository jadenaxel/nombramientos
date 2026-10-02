import type { SecretProvider, WritableSecretProvider } from "./types.js";
import { execFileSync } from "node:child_process";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as waitForLock } from "node:timers/promises";

export class MemorySecretProvider implements WritableSecretProvider {
  readonly #values = new Map<string, string>();

  public constructor(initial: Readonly<Record<string, string>> = {}) {
    for (const [key, value] of Object.entries(initial)) this.#values.set(key, value);
  }

  public async getSecret(reference: string): Promise<string> {
    const value = this.#values.get(reference);
    if (!value) throw new Error(`Secret reference is unavailable: ${reference}`);
    return value;
  }

  public async hasSecret(reference: string): Promise<boolean> {
    return this.#values.has(reference);
  }

  public async putSecret(reference: string, value: string): Promise<void> {
    if (!value) throw new Error("Refusing to store an empty secret");
    this.#values.set(reference, value);
  }
}

export class ReadonlyMapSecretProvider implements SecretProvider {
  public constructor(private readonly values: Readonly<Record<string, string>>) {}

  public async getSecret(reference: string): Promise<string> {
    const value = this.values[reference];
    if (!value) throw new Error(`Secret reference is unavailable: ${reference}`);
    return value;
  }
}

interface EncryptedSecretFile {
  readonly version: 1;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

/**
 * Local-development secret storage. The encryption key must be supplied out of band.
 * Production deployments should implement WritableSecretProvider using their secret manager.
 */
export class EncryptedFileSecretProvider implements WritableSecretProvider {
  public constructor(
    private readonly filePath: string,
    private readonly key: Uint8Array,
  ) {
    if (key.byteLength !== 32) throw new Error("Secret file key must be exactly 32 bytes");
  }

  public async getSecret(reference: string): Promise<string> {
    const values = await this.readAll();
    const value = values[reference];
    if (!value) throw new Error(`Secret reference is unavailable: ${reference}`);
    return value;
  }

  public async hasSecret(reference: string): Promise<boolean> {
    const values = await this.readAll();
    return Object.prototype.hasOwnProperty.call(values, reference);
  }

  public async putSecret(reference: string, value: string): Promise<void> {
    if (!value) throw new Error("Refusing to store an empty secret");
    await this.withWriteLock(async () => {
      const values = await this.readAll();
      const preserved = { ...values }; delete preserved[reference];
      const expectedInventoryHash = secretInventoryHash(preserved);
      values[reference] = value;
      await this.writeAll(values);
      const stored = await this.readAll(); delete stored[reference];
      if (secretInventoryHash(stored) !== expectedInventoryHash) {
        throw new Error("Unrelated secret entries changed during scoped update");
      }
    });
  }

  /** Maintenance callers must establish ownership before removing a reference. */
  public async removeSecret(reference: string): Promise<void> {
    await this.withWriteLock(async () => {
      const values = await this.readAll();
      if (!Object.hasOwn(values, reference)) throw new Error("Secret reference is unavailable for removal");
      delete values[reference];
      const expectedInventoryHash = secretInventoryHash(values);
      await this.writeAll(values);
      if (secretInventoryHash(await this.readAll()) !== expectedInventoryHash) {
        throw new Error("Unrelated secret entries changed during scoped removal");
      }
    });
  }

  private async withWriteLock<T>(operation: () => Promise<T>): Promise<T> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    const lockPath = `${this.filePath}.write-lock`;
    const startedAt = Date.now();
    let lock;
    while (!lock) {
      try { lock = await open(lockPath, "wx", 0o600); }
      catch (error) {
        if (!(typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST")) throw error;
        if (Date.now() - startedAt >= 10_000) throw new Error("Secret inventory write lock is unavailable");
        await waitForLock(50);
      }
    }
    try { return await operation(); }
    finally { await lock.close(); await rm(lockPath); }
  }

  private async writeAll(values: Readonly<Record<string, string>>): Promise<void> {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(Buffer.from("nombramientos-local-secrets:v1", "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(values), "utf8"),
      cipher.final(),
    ]);
    const output: EncryptedSecretFile = {
      version: 1,
      nonce: nonce.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    };
    await mkdir(path.dirname(this.filePath), { recursive: true });
    const temporary = `${this.filePath}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(output)}\n`, { encoding: "utf8", mode: 0o600 });
    await chmod(temporary, 0o600).catch(() => undefined);
    if (process.platform === "win32") {
      // Atomic replacement must not discard a previously restricted Windows
      // ACL. Only security metadata is copied; no secret content is exposed.
      const aclScript = "$ErrorActionPreference = 'Stop'; $sourceFile = $env:NOM_SECRET_SOURCE_FILE; $temporaryFile = $env:NOM_SECRET_TMP_FILE; if ([System.IO.File]::Exists($sourceFile)) { $acl = ([System.IO.FileInfo]::new($sourceFile)).GetAccessControl() } else { $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User; $acl = [System.Security.AccessControl.FileSecurity]::new(); $acl.SetAccessRuleProtection($true,$false); $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity,[System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write,[System.Security.AccessControl.AccessControlType]::Allow); $acl.SetAccessRule($rule) }; ([System.IO.FileInfo]::new($temporaryFile)).SetAccessControl($acl)";
      try {
        execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", aclScript], { windowsHide: true, stdio: "pipe", env: { ...process.env, NOM_SECRET_SOURCE_FILE: this.filePath, NOM_SECRET_TMP_FILE: temporary } });
      } catch { throw new Error("Secret inventory ACL preservation failed"); }
    }
    await rename(temporary, this.filePath);
  }

  private async readAll(): Promise<Record<string, string>> {
    let source: string;
    try {
      source = await readFile(this.filePath, "utf8");
    } catch (error) {
      if (isMissingFile(error)) return {};
      throw error;
    }
    const parsed = JSON.parse(source) as EncryptedSecretFile;
    if (parsed.version !== 1) throw new Error("Unsupported local secret file version");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(parsed.nonce, "base64url"),
    );
    decipher.setAAD(Buffer.from("nombramientos-local-secrets:v1", "utf8"));
    decipher.setAuthTag(Buffer.from(parsed.tag, "base64url"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(parsed.ciphertext, "base64url")),
      decipher.final(),
    ]).toString("utf8");
    const value: unknown = JSON.parse(plaintext);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("Local secret file payload is invalid");
    }
    return value as Record<string, string>;
  }
}

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function secretInventoryHash(values: Readonly<Record<string, string>>): string {
  return createHash("sha256").update(JSON.stringify(Object.entries(values).sort(([left], [right]) => left.localeCompare(right)))).digest("hex");
}
