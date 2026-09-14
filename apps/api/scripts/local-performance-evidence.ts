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

export function writeJsonEvidenceAtomic(
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
    replaceJsonEvidenceFileFailClosed(temporary, filename, renameFile);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(temporary)) {
      try {
        unlinkSync(temporary);
      } catch {
        // Failure to remove an unpublished temporary must not mask the report
        // result; the authoritative fixed path remains fail-closed.
      }
    }
  }
}

export function replaceJsonEvidenceFileFailClosed(
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
  // Some Windows filesystems reject rename-over-existing. Truncate and sync
  // the red pre-run sentinel before unlinking it; a crash from here leaves
  // empty/absent evidence, never a stale green report.
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
