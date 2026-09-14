import { randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

type RenameFile = (source: string, destination: string) => void;

export function writeBrowserJsonEvidenceAtomic(
  filename: string,
  value: unknown,
  renameFile: RenameFile = renameSync,
): void {
  const directory = path.dirname(filename);
  mkdirSync(directory, { recursive: true });
  const temporary = path.join(directory, `.${path.basename(filename)}.${process.pid}.${randomUUID()}.tmp`);
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, payload, { encoding: "utf8" });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    replaceBrowserEvidenceFileFailClosed(temporary, filename, renameFile);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(temporary)) {
      try {
        unlinkSync(temporary);
      } catch {
        // An unpublished uniquely named temporary is not authoritative evidence.
      }
    }
  }
}

export function replaceBrowserEvidenceFileFailClosed(
  temporary: string,
  filename: string,
  renameFile: RenameFile = renameSync,
): void {
  try {
    renameFile(temporary, filename);
    return;
  } catch (cause) {
    if (!existsSync(filename)) throw cause;
  }
  // Windows can reject rename-over-existing. Invalidate the destination before
  // unlink+rename so an interruption can only leave empty or absent evidence.
  let invalidationDescriptor: number | undefined;
  try {
    invalidationDescriptor = openSync(filename, "w", 0o600);
    fsyncSync(invalidationDescriptor);
  } finally {
    if (invalidationDescriptor !== undefined) closeSync(invalidationDescriptor);
  }
  unlinkSync(filename);
  renameFile(temporary, filename);
}
