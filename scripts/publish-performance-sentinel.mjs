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
import { pathToFileURL } from "node:url";

const DEFINITIONS = Object.freeze({
  "api-local": Object.freeze({
    artifact: "performance-local.json",
    schemaVersion: 3,
    acceptanceCriterion: "AC-37",
  }),
  "api-scale": Object.freeze({
    artifact: "performance-scale-local.json",
    schemaVersion: 3,
    acceptanceCriterion: "AC-37",
  }),
  browser: Object.freeze({
    artifact: "performance-browser-local.json",
    schemaVersion: 2,
    acceptanceCriterion: "AC-37-browser",
  }),
});

export function buildPerformanceSentinel(mode, now = new Date()) {
  const definition = DEFINITIONS[mode];
  if (!definition) throw new Error("Unknown performance sentinel mode");
  const timestamp = now.toISOString();
  return {
    schemaVersion: definition.schemaVersion,
    acceptanceCriterion: definition.acceptanceCriterion,
    startedAtUtc: timestamp,
    completedAtUtc: timestamp,
    status: "in-progress",
    inProgress: true,
    closureEligible: false,
    environment: { state: "pending-before-build-and-runner-import" },
    dataset: { state: "pending-before-build-and-runner-import" },
    thresholds: {},
    cleanup: { pass: false },
    overallPass: false,
    deviations: ["run-in-progress-before-build-and-runner-import"],
  };
}

export function writePerformanceSentinelAtomic(filename, value, renameFile = renameSync) {
  const directory = path.dirname(filename);
  mkdirSync(directory, { recursive: true });
  const temporary = path.join(directory, `.${path.basename(filename)}.${process.pid}.${randomUUID()}.tmp`);
  // Invalidate the authoritative path before any serialization or temporary
  // publication work. An interruption from this point can leave an empty,
  // absent, or red file, but can never preserve historical green evidence.
  let invalidationDescriptor;
  try {
    invalidationDescriptor = openSync(filename, "w", 0o600);
    fsyncSync(invalidationDescriptor);
  } finally {
    if (invalidationDescriptor !== undefined) closeSync(invalidationDescriptor);
  }
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, payload, { encoding: "utf8" });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    // Windows does not guarantee rename-over-existing. Removing the already
    // invalidated destination first also makes every interruption fail-closed.
    if (existsSync(filename)) unlinkSync(filename);
    renameFile(temporary, filename);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(temporary)) {
      try {
        unlinkSync(temporary);
      } catch {
        // The fixed artifact path is the only authoritative evidence path.
      }
    }
  }
}

export function publishPerformanceSentinel(mode, workspaceRoot = path.resolve(import.meta.dirname, "..")) {
  const definition = DEFINITIONS[mode];
  if (!definition) throw new Error("Unknown performance sentinel mode");
  const filename = path.join(workspaceRoot, "artifacts", definition.artifact);
  const sentinel = buildPerformanceSentinel(mode);
  writePerformanceSentinelAtomic(filename, sentinel);
  return { filename, sentinel };
}

const invokedDirectly = process.argv[1]
  && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (invokedDirectly) {
  if (process.argv.length !== 3) throw new Error("Performance sentinel requires exactly one mode");
  publishPerformanceSentinel(process.argv[2]);
}
