import type { AppointmentMechanism } from "./types.js";

export const ORDINARY_PROPOSAL_BALLOT_MECHANISMS = [
  "church_election_after_nominating_report",
  "church_election",
] as const satisfies readonly AppointmentMechanism[];

export const CONFIGURABLE_NON_BALLOT_MECHANISMS = [
  "linked_designation",
] as const satisfies readonly AppointmentMechanism[];

export const SEPARATE_PROCEDURE_APPOINTMENT_MECHANISMS = [
  "board_appointment",
  "council_recommendation_board_approval",
  "conference_appointment",
  "ex_officio",
] as const satisfies readonly AppointmentMechanism[];

export const PENDING_CONFIGURATION_APPOINTMENT_MECHANISMS = [
  "local_configuration_pending",
] as const satisfies readonly AppointmentMechanism[];

export const CONFIGURABLE_VACANCY_PROCESS_MECHANISMS = [
  ...ORDINARY_PROPOSAL_BALLOT_MECHANISMS,
  ...CONFIGURABLE_NON_BALLOT_MECHANISMS,
] as const satisfies readonly AppointmentMechanism[];

export const BLOCKED_ORDINARY_WORKFLOW_MECHANISMS = [
  ...CONFIGURABLE_NON_BALLOT_MECHANISMS,
  ...SEPARATE_PROCEDURE_APPOINTMENT_MECHANISMS,
  ...PENDING_CONFIGURATION_APPOINTMENT_MECHANISMS,
] as const satisfies readonly AppointmentMechanism[];

export type AppointmentWorkflowLane =
  | "ordinary_proposal_ballot"
  | "linked_designation"
  | "separate_procedure"
  | "configuration_pending"
  | "unsupported";

const ordinaryProposalBallotMechanisms = new Set<string>(ORDINARY_PROPOSAL_BALLOT_MECHANISMS);
const configurableVacancyProcessMechanisms = new Set<string>(CONFIGURABLE_VACANCY_PROCESS_MECHANISMS);

const workflowLaneByMechanism: Readonly<Record<AppointmentMechanism, Exclude<AppointmentWorkflowLane, "unsupported">>> = {
  church_election_after_nominating_report: "ordinary_proposal_ballot",
  church_election: "ordinary_proposal_ballot",
  linked_designation: "linked_designation",
  board_appointment: "separate_procedure",
  council_recommendation_board_approval: "separate_procedure",
  conference_appointment: "separate_procedure",
  ex_officio: "separate_procedure",
  local_configuration_pending: "configuration_pending",
};

export function isOrdinaryProposalBallotMechanism(
  mechanism: string,
): mechanism is (typeof ORDINARY_PROPOSAL_BALLOT_MECHANISMS)[number] {
  return ordinaryProposalBallotMechanisms.has(mechanism);
}

export function isConfigurableVacancyProcessMechanism(
  mechanism: string,
): mechanism is (typeof CONFIGURABLE_VACANCY_PROCESS_MECHANISMS)[number] {
  return configurableVacancyProcessMechanisms.has(mechanism);
}

export function classifyAppointmentWorkflow(mechanism: string): AppointmentWorkflowLane {
  if (!Object.hasOwn(workflowLaneByMechanism, mechanism)) return "unsupported";
  return workflowLaneByMechanism[mechanism as AppointmentMechanism];
}
