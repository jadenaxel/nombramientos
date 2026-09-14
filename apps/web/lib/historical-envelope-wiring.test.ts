import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const consumers = [
  "components/nombramientos/member-photo-editor.tsx",
  "components/nombramientos/members-view.tsx",
  "components/nombramientos/organization-view.tsx",
  "components/nombramientos/reports-view.tsx",
  "components/nombramientos/round-view.tsx",
  "components/nombramientos/workflow-console.tsx",
  "components/nombramientos/workflow-session-console.tsx",
  "components/nombramientos/workspace-view.tsx",
] as const;

test("historical tenant-content readers resolve the exact envelope generation", () => {
  const sources = consumers.map((relativePath) => ({
    relativePath,
    source: readFileSync(path.join(root, relativePath), "utf8"),
  }));
  for (const { relativePath, source } of sources) {
    assert.match(source, /keyForEnvelope|openJsonEnvelope|vaultKeyFor/u, `${relativePath} must select keys by envelope`);
    assert.doesNotMatch(source, /decryptJson[^\n]*vault\.key/u, `${relativePath} must not force the current key for reads`);
    assert.doesNotMatch(source, /open(?:Session|Agenda)Title\(vault\.key/u, `${relativePath} must not force the current key for historical titles`);
  }
  const reports = sources.find(({ relativePath }) => relativePath.endsWith("reports-view.tsx"))!.source;
  assert.match(reports, /keyForEnvelope\(vault, session\.tenant\.id, verified\.encrypted\.envelope\)/u);
  assert.match(reports, /keyId: verified\.encrypted\.envelope\.keyId/u);
});
