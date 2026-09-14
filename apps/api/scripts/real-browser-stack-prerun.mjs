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
import { randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MARKER = "nombramientos-real-browser-stack-v1";
const CHECK_FLAG = "--check";
const RUN_FLAG = "--ephemeral-only";
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const artifactDirectory = path.join(workspaceRoot, "artifacts");

const targetByFlag = Object.freeze({
  [CHECK_FLAG]: {
    file: path.join(artifactDirectory, "real-browser-stack-preflight.json"),
    mode: "read-only-preflight",
    failureFlags: { pass: false },
  },
  [RUN_FLAG]: {
    file: path.join(artifactDirectory, "real-browser-stack-local.json"),
    mode: "ephemeral-control-and-tenant",
    failureFlags: { scenarioPass: false, cleanupPass: false },
  },
});

const args = process.argv.slice(2);
if (args.length !== 1 || !Object.hasOwn(targetByFlag, args[0])) {
  throw new Error("Expected exactly --check or --ephemeral-only");
}
const target = targetByFlag[args[0]];
const sentinel = {
  schemaVersion: 1,
  marker: MARKER,
  mode: target.mode,
  startedAt: new Date().toISOString(),
  status: "in-progress",
  inProgress: true,
  invalidatedBeforeBuild: true,
  ...target.failureFlags,
};
publishFailClosedSentinel(target.file, sentinel);

function publishFailClosedSentinel(destinationFile, value) {
  mkdirSync(path.dirname(destinationFile), { recursive: true });
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  JSON.parse(payload);

  // Invalidate historical evidence first. If this process is interrupted at
  // any later instruction, the destination is empty, absent, or explicitly red.
  const invalidationDescriptor = openSync(destinationFile, "w");
  try {
    fsyncSync(invalidationDescriptor);
  } finally {
    closeSync(invalidationDescriptor);
  }

  const temporaryFile = `${destinationFile}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    writeFileSync(temporaryFile, payload, { encoding: "utf8", flag: "wx" });
    const temporaryDescriptor = openSync(temporaryFile, "r+");
    try {
      fsyncSync(temporaryDescriptor);
    } finally {
      closeSync(temporaryDescriptor);
    }

    // Destination is already invalid. Removing it makes the same-directory
    // rename atomic on Windows too; a failed rename leaves no green evidence.
    unlinkSync(destinationFile);
    renameSync(temporaryFile, destinationFile);
    // Windows requires a writable handle for fsync; the data was already
    // synchronized in the temporary file before this atomic rename.
    const destinationDescriptor = openSync(destinationFile, "r+");
    try {
      fsyncSync(destinationDescriptor);
    } finally {
      closeSync(destinationDescriptor);
    }
  } finally {
    if (existsSync(temporaryFile)) unlinkSync(temporaryFile);
  }
}
