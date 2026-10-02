import assert from "node:assert/strict";
import test from "node:test";
import { confirmUnsavedNavigation, hasUnsavedChanges, isLeavingDocument, registerUnsavedChanges } from "./unsaved-changes.ts";

test("unsaved registry blocks navigation until each dirty form approves, then cleans up", () => {
  let allowed = false;
  const unregister = registerUnsavedChanges(() => allowed);
  assert.equal(hasUnsavedChanges(), true);
  assert.equal(confirmUnsavedNavigation(), false);
  allowed = true;
  assert.equal(confirmUnsavedNavigation(), true);
  unregister();
  assert.equal(hasUnsavedChanges(), false);
  assert.equal(confirmUnsavedNavigation(), true);
});
test("same-page anchors preserve drafts but locale, route and filter navigation can lose them", () => {
  const current = "http://localhost:3300/es/app/workflow";
  assert.equal(isLeavingDocument("#configuration", current), false);
  assert.equal(isLeavingDocument("/es/app/workflow", current), false);
  for (const href of ["/fr/app/workflow", "/es/app/members", "?cycle=other", "http://other.test/"]) assert.equal(isLeavingDocument(href, current), true);
});
