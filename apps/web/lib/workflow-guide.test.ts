import assert from "node:assert/strict";
import test from "node:test";
import type { CycleWorkflow } from "./workflow-api.ts";
import { workflowGuide } from "./workflow-guide.ts";

const draft = () => ({ cycle: { id: "synthetic", status: "draft" }, processes: [], committee: [], electorate: [], sessions: [], assignments: [] }) as unknown as CycleWorkflow;
const input = () => ({ cycle: draft(), realTenant: true, keyState: "unlocked" as const, memberTotal: 3 });
test("creating a draft does not imply keys, imported roster, committee or completion", () => {
  const guide = workflowGuide({ cycle: draft(), realTenant: true, keyState: "uninitialized", memberTotal: 0 });
  assert.equal(guide.next, "key");
  assert.equal(guide.steps.filter((step) => step.state === "complete").length, 1);
});
test("unknown data stays unknown, never a false empty directory", () => {
  const guide = workflowGuide({ cycle: undefined, realTenant: true, keyState: "unknown" });
  assert.equal(guide.steps.find((step) => step.id === "directory")?.state, "unknown");
  assert.equal(guide.steps.find((step) => step.id === "cycle")?.state, "unknown");
});
test("missing cycle precedes security enrollment and lost keys remain blocked", () => {
  assert.equal(workflowGuide({ cycle: null, realTenant: true, keyState: "uninitialized" }).next, "cycle");
  assert.equal(workflowGuide({ ...input(), keyState: "lost" }).steps[1]?.state, "blocked");
  assert.equal(workflowGuide({ ...input(), keyState: "locked" }).next, "key");
});
test("existing directory does not substitute for committee and electorate", () => {
  assert.equal(workflowGuide(input()).next, "configuration");
  const item = input();
  item.cycle.processes = [{ enabled: true, procedure_sequence: 1 }] as CycleWorkflow["processes"];
  item.cycle.committee = [{ status: "active", voting_right: true }, { status: "active", voting_right: true }] as CycleWorkflow["committee"];
  item.cycle.electorate = [{ can_propose: true, can_vote: true, recused: true }] as CycleWorkflow["electorate"];
  assert.equal(workflowGuide(item).next, "configuration");
  item.cycle.electorate[0]!.recused = false;
  assert.equal(workflowGuide(item).next, "session");
});
test("closed cycle metadata alone never proves completed process or assignment", () => {
  const item = input();
  item.cycle.cycle.status = "closed";
  const guide = workflowGuide(item);
  assert.equal(guide.steps.find((step) => step.id === "process")?.state, "pending");
  assert.equal(guide.steps.find((step) => step.id === "assignments")?.state, "pending");
  assert.equal(guide.steps.find((step) => step.id === "outputs")?.state, "pending");
});
test("all persisted phases must finish, not just the first office", () => {
  const item = input();
  item.cycle.processes = [{ enabled: true, procedure_sequence: 1, phase: "CERRADO" }, { enabled: true, phase: "VOTACION_ABIERTA" }] as CycleWorkflow["processes"];
  assert.equal(workflowGuide(item).steps.find((step) => step.id === "process")?.state, "pending");
  item.cycle.processes[1]!.phase = "RECOMENDACION_CONFIRMADA";
  assert.equal(workflowGuide(item).steps.find((step) => step.id === "process")?.state, "complete");
  item.cycle.assignments = [{ state: "VIGENTE" }, { state: "ACEPTACION_PENDIENTE" }] as CycleWorkflow["assignments"];
  assert.equal(workflowGuide(item).steps.find((step) => step.id === "assignments")?.state, "pending");
});
