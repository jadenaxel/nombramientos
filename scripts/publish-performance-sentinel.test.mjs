import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildPerformanceSentinel,
  writePerformanceSentinelAtomic,
} from "./publish-performance-sentinel.mjs";

test("pre-run sentinel atomically invalidates a prior green artifact", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "nom-performance-sentinel-"));
  try {
    const filename = path.join(directory, "performance.json");
    writePerformanceSentinelAtomic(filename, { status: "passed", overallPass: true });
    const sentinel = buildPerformanceSentinel("api-local", new Date("2026-09-12T00:00:00.000Z"));
    writePerformanceSentinelAtomic(filename, sentinel);
    assert.deepEqual(JSON.parse(readFileSync(filename, "utf8")), sentinel);
    assert.equal(sentinel.status, "in-progress");
    assert.equal(sentinel.inProgress, true);
    assert.equal(sentinel.closureEligible, false);
    assert.equal(sentinel.cleanup.pass, false);
    assert.equal(sentinel.overallPass, false);
    assert.deepEqual(readdirSync(directory), ["performance.json"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("sentinel modes have the expected immutable evidence identities", () => {
  assert.equal(buildPerformanceSentinel("api-local").acceptanceCriterion, "AC-37");
  assert.equal(buildPerformanceSentinel("api-scale").schemaVersion, 3);
  assert.equal(buildPerformanceSentinel("browser").acceptanceCriterion, "AC-37-browser");
  assert.throws(() => buildPerformanceSentinel("unknown"), /Unknown performance sentinel mode/u);
});

test("replacement interruption cannot preserve a prior green artifact", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "nom-performance-sentinel-failure-"));
  try {
    const filename = path.join(directory, "performance.json");
    writePerformanceSentinelAtomic(filename, { status: "passed", overallPass: true });
    assert.throws(() => writePerformanceSentinelAtomic(
      filename,
      buildPerformanceSentinel("browser"),
      () => { throw new Error("simulated rename interruption"); },
    ), /simulated rename interruption/u);
    assert.equal(existsSync(filename), false);
    assert.deepEqual(readdirSync(directory), []);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("authoritative invalidation and fsync precede temporary publication", () => {
  const source = readFileSync(new URL("./publish-performance-sentinel.mjs", import.meta.url), "utf8");
  const invalidation = source.indexOf('openSync(filename, "w", 0o600)');
  const temporary = source.indexOf('openSync(temporary, "wx", 0o600)');
  assert.ok(invalidation >= 0 && temporary > invalidation);
  assert.match(source.slice(invalidation, temporary), /fsyncSync\(invalidationDescriptor\)/u);
  assert.match(source, /unlinkSync\(filename\);\s*renameFile\(temporary, filename\)/u);
});

test("every package command publishes before build or runner import", () => {
  const workspaceRoot = path.resolve(import.meta.dirname, "..");
  const api = JSON.parse(readFileSync(path.join(workspaceRoot, "apps", "api", "package.json"), "utf8"));
  const web = JSON.parse(readFileSync(path.join(workspaceRoot, "apps", "web", "package.json"), "utf8"));
  assert.match(api.scripts["performance:local"], /^node \.\.\/\.\.\/scripts\/publish-performance-sentinel\.mjs api-local && pnpm build && node /u);
  assert.match(api.scripts["performance:scale:local"], /^node \.\.\/\.\.\/scripts\/publish-performance-sentinel\.mjs api-scale && pnpm build && node /u);
  assert.match(web.scripts["performance:browser:local"], /^node \.\.\/\.\.\/scripts\/publish-performance-sentinel\.mjs browser && node /u);
});
