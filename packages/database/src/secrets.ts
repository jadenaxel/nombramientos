import type { SecretProvider, WritableSecretProvider } from "./types.js";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

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
    const values = await this.readAll();
    values[reference] = value;
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
