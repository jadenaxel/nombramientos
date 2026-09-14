import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { writeBrowserJsonEvidenceAtomic } from "./performance-browser-evidence.ts";
import {
  assertExactLocalWebBaseUrl,
  isExactPublicSignInUrl,
} from "./performance-browser-guards.ts";

test("accepts only the exact local browser benchmark origin", () => {
  assert.equal(assertExactLocalWebBaseUrl("http://localhost:3000"), "http://localhost:3000");
  assert.equal(assertExactLocalWebBaseUrl("http://localhost:3000/"), "http://localhost:3000");
});

test("rejects ambiguous or non-local browser benchmark destinations", () => {
  for (const value of [
    "https://localhost:3000",
    "http://127.0.0.1:3000",
    "http://[::1]:3000",
    "http://localhost:3001",
    "http://user:password@localhost:3000",
    "http://localhost:3000/es",
    "http://localhost:3000?destination=external",
    "http://localhost:3000#external",
    "http://2130706433:3000",
    "http://localhost.:3000",
    " http://localhost:3000",
    "http://localhost:3000 ",
    "http://example.invalid:3000",
  ]) {
    assert.throws(
      () => assertExactLocalWebBaseUrl(value),
      /requires the exact local web origin/u,
      value,
    );
  }
});

test("accepts only the exact public sign-in URL as the final vitals route", () => {
  assert.equal(
    isExactPublicSignInUrl("http://localhost:3000/es/auth/sign-in", "http://localhost:3000"),
    true,
  );
  for (const value of [
    "http://localhost:3000/es/auth/sign-in/",
    "http://localhost:3000/es/auth/sign-in?next=/es/members",
    "http://localhost:3000/es/auth/sign-in#probe",
    "http://localhost:3000/es/members",
    "http://127.0.0.1:3000/es/auth/sign-in",
    "https://localhost:3000/es/auth/sign-in",
  ]) {
    assert.equal(isExactPublicSignInUrl(value, "http://localhost:3000"), false, value);
  }
});

test("publishes browser JSON evidence through a same-directory atomic replacement", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "nom-browser-evidence-"));
  try {
    const filename = path.join(directory, "report.json");
    writeBrowserJsonEvidenceAtomic(filename, { status: "in-progress", overallPass: false });
    writeBrowserJsonEvidenceAtomic(filename, { status: "passed", overallPass: true });
    assert.deepEqual(JSON.parse(readFileSync(filename, "utf8")), { status: "passed", overallPass: true });
    assert.deepEqual(readdirSync(directory), ["report.json"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("browser evidence replacement is Windows-safe and fail-closed", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "nom-browser-evidence-replace-"));
  try {
    const filename = path.join(directory, "report.json");
    writeBrowserJsonEvidenceAtomic(filename, { status: "in-progress", overallPass: false });
    let attempts = 0;
    writeBrowserJsonEvidenceAtomic(filename, { status: "passed", overallPass: true }, (source, destination) => {
      attempts += 1;
      if (attempts === 1) throw new Error("simulated Windows replace denial");
      renameSync(source, destination);
    });
    assert.equal(attempts, 2);
    assert.deepEqual(JSON.parse(readFileSync(filename, "utf8")), { status: "passed", overallPass: true });
    assert.throws(() => writeBrowserJsonEvidenceAtomic(filename, { status: "failed" }, () => {
      throw new Error("simulated persistent rename failure");
    }), /simulated persistent rename failure/u);
    assert.equal(existsSync(filename), false);
    assert.deepEqual(readdirSync(directory), []);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("publishes a sentinel before validation and never loads Demo credentials", () => {
  const source = readFileSync(new URL("./performance-browser-local.ts", import.meta.url), "utf8");
  const sentinelOffset = source.indexOf('status: "in-progress"');
  const guardOffset = source.indexOf("assertExactLocalWebBaseUrl(process.env.WEB_BASE_URL");
  const datasetOffset = source.indexOf("await buildEncryptedDataset(");
  const launchOffset = source.indexOf("await chromium.launch(");
  const animationFrameWarmupOffset = source.indexOf("await nextAnimationFrame();");
  const animationFrameMeasurementOffset = source.indexOf("let lastFrame = performance.now();");
  const workerDispatchOffset = source.indexOf("worker.postMessage(");

  assert.ok(sentinelOffset >= 0, "runner must publish an in-progress sentinel");
  assert.ok(guardOffset > sentinelOffset, "the sentinel must replace prior green evidence before validation");
  assert.ok(guardOffset >= 0, "runner must validate WEB_BASE_URL");
  assert.ok(datasetOffset > guardOffset, "destination validation must run before dataset generation");
  assert.ok(launchOffset > guardOffset, "destination validation must run before Chromium launch");
  assert.match(source, /await nextAnimationFrame\(\);\s*await nextAnimationFrame\(\);/u);
  assert.ok(animationFrameWarmupOffset >= 0, "runner must warm Chromium's compositor before measuring gaps");
  assert.ok(animationFrameMeasurementOffset > animationFrameWarmupOffset, "frame-gap measurement must exclude compositor cold start");
  assert.ok(workerDispatchOffset > animationFrameMeasurementOffset, "worker workload must begin after frame-gap measurement starts");
  assert.doesNotMatch(source, /signInDemo|demo-auth|demo-access/u);
  assert.match(source, /\/es\/auth\/sign-in/u);
  assert.match(source, /exercisesProductionMembersRoute:\s*false/u);
  assert.match(source, /animationFrameMeasurementHasSamples:\s*Number\.isSafeInteger\(pipeline\.animationFrameCount\)/u);
  assert.match(source, /SEARCH_SAMPLE_COUNT\s*=\s*SEARCH_QUERY_COUNT\s*\+\s*1/u);
  assert.match(source, /pipeline\.searchSamples\s*===\s*SEARCH_SAMPLE_COUNT/u);
  assert.match(source, /exactPipelineMetricCardinality/u);
  assert.match(source, /pipelineMetricsFinite/u);
  assert.match(source, /vitalsMetricsFinite/u);
  assert.match(source, /observerEntryTypesUniqueAndConsistent/u);
  assert.match(source, /exactInteractionMetricCardinality/u);
  assert.match(source, /clsSupported:\s*vitals\.layoutShiftSupported\s*===\s*true/u);
  assert.match(source, /exactPublicSignInFinalUrl:\s*exactFinalAppUrl/u);
  assert.match(source, /routeWebSocket/u);
  assert.match(source, /serverSideDatabaseAccessMeasured:\s*false/u);
});

test("closes every browser resource before a green artifact can be published", () => {
  const source = readFileSync(new URL("./performance-browser-local.ts", import.meta.url), "utf8");
  const browserCloseOffset = source.indexOf("await launchedBrowser.close()");
  const serverCloseOffset = source.indexOf("await close(server)", browserCloseOffset);
  const finalPublicationOffset = source.indexOf("writeArtifact(artifact)");

  assert.ok(browserCloseOffset >= 0, "browser close must be explicit");
  assert.ok(serverCloseOffset > browserCloseOffset, "synthetic server must close after browser use");
  assert.ok(finalPublicationOffset > serverCloseOffset, "green publication must happen only after resource closure");
});
