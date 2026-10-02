import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { assertCanonicalBrowserOriginBundle } from "./assert-browser-origin-bundle.mjs";

test("accepts a browser bundle wired only to the canonical localhost API", () => {
  const directory = fixtureDirectory();
  try {
    writeFileSync(path.join(directory, "app.js"), 'const api="http://localhost:4000";\n', "utf8");
    assert.deepEqual(assertCanonicalBrowserOriginBundle(directory), {
      chunkCount: 1,
      canonicalOriginPresent: true,
      forbiddenFiles: [],
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("accepts the dedicated GestionChurch module API origin", () => {
  const directory = fixtureDirectory();
  try {
    writeFileSync(path.join(directory, "app.js"), 'const api="http://localhost:4100";\n', "utf8");
    assert.equal(assertCanonicalBrowserOriginBundle(directory, {
      requiredOrigin: "http://localhost:4100",
      forbiddenOrigins: ["http://127.0.0.1:4100"],
    }).canonicalOriginPresent, true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("fails closed when a build bakes an IP API origin into any nested browser chunk", () => {
  const directory = fixtureDirectory();
  try {
    const nested = path.join(directory, "nested");
    mkdirSync(nested);
    writeFileSync(path.join(directory, "canonical.js"), 'const api="http://localhost:4000";\n', "utf8");
    writeFileSync(path.join(nested, "poisoned.js"), 'const api="http://127.0.0.1:4000";\n', "utf8");
    assert.throws(
      () => assertCanonicalBrowserOriginBundle(directory),
      /non-canonical API origin.*nested\/poisoned\.js/u,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("fails closed for an empty bundle or one missing the canonical API origin", () => {
  const directory = fixtureDirectory();
  try {
    assert.throws(() => assertCanonicalBrowserOriginBundle(directory), /no JavaScript chunks/u);
    writeFileSync(path.join(directory, "app.js"), "const ready=true;\n", "utf8");
    assert.throws(() => assertCanonicalBrowserOriginBundle(directory), /does not contain the canonical/u);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixtureDirectory(): string {
  return mkdtempSync(path.join(os.tmpdir(), "nom-browser-origin-bundle-"));
}
