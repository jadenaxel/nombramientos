import type { CycleWorkflow } from "./workflow-api.ts";

export const WORKFLOW_GUIDE_STEPS = ["cycle", "key", "directory", "configuration", "session", "process", "assignments", "outputs"] as const;
export type WorkflowGuideStep = typeof WORKFLOW_GUIDE_STEPS[number];
export type WorkflowGuideState = "complete" | "pending" | "unknown" | "blocked";

/** Guidance is derived from persisted facts, never from having clicked Create. */
export function workflowGuide(input: {
  cycle: CycleWorkflow | null | undefined;
  realTenant: boolean;
  keyState: "unknown" | "uninitialized" | "locked" | "unlocked" | "lost";
  memberTotal?: number;
}): { steps: Array<{ id: WorkflowGuideStep; state: WorkflowGuideState }>; next: WorkflowGuideStep } {
  const workflow = input.cycle;
  const configured = workflow && workflow.processes.some((process) => process.enabled && process.procedure_sequence === 1)
    && workflow.committee.filter((member) => member.voting_right && member.status === "active").length >= 2
    && workflow.electorate.some((item) => item.can_propose && !item.recused)
    && workflow.electorate.some((item) => item.can_vote && !item.recused);
  const voting = workflow?.processes.filter((process) => process.enabled);
  const completedProcesses = Boolean(voting?.length) && voting!.every((process) => ["CERRADO", "RECOMENDACION_CONFIRMADA"].includes(process.phase));
  const assignments = workflow?.assignments;
  const completedAssignments = Boolean(assignments?.length) && assignments!.every((item) => ["VIGENTE", "FINALIZADA", "SUSTITUIDA"].includes(item.state));
  const known = (complete: boolean | undefined): WorkflowGuideState => workflow === undefined ? "unknown" : complete ? "complete" : "pending";
  const steps: Array<{ id: WorkflowGuideStep; state: WorkflowGuideState }> = [
    { id: "cycle", state: known(Boolean(workflow)) },
    { id: "key", state: !input.realTenant || input.keyState === "unlocked" ? "complete" : input.keyState === "lost" ? "blocked" : input.keyState === "unknown" ? "unknown" : "pending" },
    { id: "directory", state: input.memberTotal === undefined ? "unknown" : input.memberTotal > 0 ? "complete" : "pending" },
    { id: "configuration", state: known(Boolean(configured)) },
    { id: "session", state: known(Boolean(workflow?.sessions.length)) },
    { id: "process", state: known(completedProcesses) },
    { id: "assignments", state: known(completedAssignments) },
    // Results and exported artifacts need their own review, including closed cycles.
    { id: "outputs", state: "pending" },
  ];
  return { steps, next: steps.find((step) => step.state !== "complete")!.id };
}
