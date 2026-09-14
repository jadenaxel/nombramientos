import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const webRoot = path.resolve(import.meta.dirname, "..");
const apiSource = readFileSync(path.join(webRoot, "lib/api.ts"), "utf8");
const workflowSource = readFileSync(path.join(webRoot, "lib/workflow-api.ts"), "utf8");
const membersSource = readFileSync(path.join(webRoot, "components/nombramientos/members-view.tsx"), "utf8");
const custodySource = readFileSync(path.join(webRoot, "components/nombramientos/custody-view.tsx"), "utf8");
const lifecycleSource = readFileSync(path.join(webRoot, "components/nombramientos/key-lifecycle-view.tsx"), "utf8");
const invitationsSource = readFileSync(path.join(webRoot, "components/nombramientos/invitations-view.tsx"), "utf8");
const workflowConsoleSource = readFileSync(path.join(webRoot, "components/nombramientos/workflow-console.tsx"), "utf8");
const workflowSessionSource = readFileSync(path.join(webRoot, "components/nombramientos/workflow-session-console.tsx"), "utf8");

test("member and key lifecycle surfaces submit selected non-sensitive reason codes", () => {
  assert.match(membersSource, /memberLifecycleReasonCodes[\s\S]*<select id="member-lifecycle-reason"/u);
  assert.match(membersSource, /JSON\.stringify\(\{ expectedVersion: lifecycle\.member\.version, reasonCode: lifecycleReasonCode \}\)/u);
  assert.match(lifecycleSource, /const revokeReasonCodes =[\s\S]*const rotationReasonCodes =[\s\S]*const lossReasonCodes =/u);
  assert.match(lifecycleSource, /<select id=\{`revoke-reason-/u);
  assert.match(lifecycleSource, /<select id="rotation-reason"/u);
  assert.match(lifecycleSource, /<select id="loss-reason"/u);
  assert.doesNotMatch(lifecycleSource, /reason:\s*(revokeReason|rotationReason|lossReason)/u);
});

test("workflow decisions derive closed codes and expose no free-text code input", () => {
  assert.match(workflowConsoleSource, /eligibilityReasonCodeByResolution[\s\S]*ELIGIBILITY_REPLACEMENT_COMPLETED/u);
  assert.match(workflowConsoleSource, /assignmentLifecycleReasonCodes[\s\S]*<select[\s\S]*assignmentReasonCodeLabel/u);
  assert.match(workflowConsoleSource, /CANDIDATE_WITHDREW/u);
  assert.match(workflowConsoleSource, /options\.find\(\(option\) => option\.state === toState\)\?\.reasonCode/u);
  assert.doesNotMatch(workflowConsoleSource, /pattern="\[A-Z\]\[A-Z0-9_\]/u);
  assert.match(workflowSessionSource, /decisionCodesByOutcome[\s\S]*INFORMATION_NOTED[\s\S]*ITEM_REJECTED/u);
  assert.match(workflowSessionSource, /decisionCodeLabel[\s\S]*<select[\s\S]*decisionCodesByOutcome\[decisionForm\.outcome\]/u);
  assert.doesNotMatch(workflowSessionSource, /decisionCode\.trim\(\)\.toUpperCase/u);
  assert.doesNotMatch(workflowSessionSource, /pattern="\[A-Z\]\[A-Z0-9_\]/u);
});

test("round and custody clients send stable codes instead of localized prose", () => {
  assert.match(apiSource, /reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED"/u);
  assert.match(custodySource, /custodyRevokeReasonCodes[\s\S]*<select[\s\S]*custodyRevokeReasonLabel/u);
  assert.match(custodySource, /revokeCustodyKey\(key\.keyId, key\.version, revokeReasonCode\)/u);
  assert.match(workflowSource, /reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED"/u);
  assert.match(invitationsSource, /reasonCode: "ADMIN_ACCESS_REVOCATION"/u);
  assert.doesNotMatch(workflowSource, /reason: "Cierre confirmado/u);
});
