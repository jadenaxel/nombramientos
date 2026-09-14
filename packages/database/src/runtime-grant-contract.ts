export const TENANT_RUNTIME_READ_ONLY_TABLES = [
  "tenant_settings",
  "permissions",
  "roles",
  "role_permissions",
  "system_role_assignment_matrix",
  "role_bindings",
  "device_key_grants",
] as const;

export const TENANT_RUNTIME_MUTABLE_TABLES = [
  "departments",
  "offices",
  "members",
  "member_import_jobs",
  "idempotency_records",
  "election_cycles",
  "cycle_sessions",
  "session_attendance",
  "session_agenda_items",
  "cycle_elector_roster",
  "office_processes",
  "vacancies",
  "committee_memberships",
  "candidacies",
  "member_eligibility_workflow_pauses",
  "member_photo_assets",
  "e2ee_key_devices",
  "e2ee_key_generations",
  "e2ee_key_grants",
  "e2ee_key_challenges",
  "report_versions",
  "custodian_device_keys",
  "tally_manifests",
  "rounds",
  "assignments",
] as const;

export const TENANT_RUNTIME_APPEND_ONLY_TABLES = [
  "encrypted_submissions",
  "participation_receipts",
  "outbox_events",
  "audit_events",
  "round_custody_sets",
  "round_custodian_key_snapshots",
  "tally_manifest_entries",
  "custodian_attestations",
  "proposal_manifests",
  "proposal_manifest_entries",
  "proposal_aggregates",
  "candidacy_reviews",
  "candidate_list_versions",
  "candidate_list_entries",
  "assignment_transitions",
  "session_decisions",
  "member_qualification_versions",
  "round_elector_snapshots",
  "candidate_snapshots",
  "cycle_member_snapshots",
] as const;

export const TENANT_SETTINGS_RUNTIME_UPDATE_COLUMNS = [
  "display_name",
  "timezone",
  "locale",
  "jurisdiction",
  "version",
  "updated_at",
] as const;

export const TENANT_RUNTIME_SEQUENCES = [
  "outbox_events_sequence_seq",
  "audit_events_sequence_seq",
] as const;

export const TENANT_RUNTIME_PURE_FUNCTIONS = [
  "is_valid_tally_decision_rule(jsonb)",
] as const;

const TENANT_RUNTIME_SECURITY_DEFINER_FUNCTIONS = [
  "apply_tenant_invitation_roles(uuid,uuid,text[],uuid,integer)",
  "assert_tenant_invitation_role_delegation_allowed(uuid,text[])",
  "cleanup_tenant_invitation_roles(uuid,uuid,uuid,integer)",
  "apply_tenant_initial_admin_role(uuid,uuid,uuid,bigint,integer,text)",
  "rollback_tenant_initial_admin_role(uuid,uuid,uuid,uuid,bigint,integer,text)",
  "consume_tenant_initial_admin_role(uuid,uuid,uuid,bigint,integer,text)",
  "create_local_role(uuid,uuid,text,jsonb,text[],text[])",
  "update_local_role(uuid,uuid,integer,jsonb,text[],text[])",
  "grant_tenant_role_binding(uuid,uuid,uuid)",
  "revoke_tenant_role_binding(uuid,uuid,uuid,integer)",
] as const;

export const TENANT_RUNTIME_FUNCTIONS = [
  ...TENANT_RUNTIME_PURE_FUNCTIONS,
  ...TENANT_RUNTIME_SECURITY_DEFINER_FUNCTIONS,
] as const;

export const TENANT_SECURITY_DEFINER_FUNCTIONS = [
  ...TENANT_RUNTIME_SECURITY_DEFINER_FUNCTIONS,
  "guard_applied_initial_admin_binding()",
  "assert_local_role_definition_allowed(uuid,text[],text[])",
  "assert_role_binding_allowed(uuid,uuid,uuid)",
] as const;

export type RuntimePrivilege =
  | "CONNECT"
  | "CREATE"
  | "TEMPORARY"
  | "USAGE"
  | "SELECT"
  | "INSERT"
  | "UPDATE"
  | "EXECUTE";

export interface RuntimeGrantContract {
  readonly database: {
    readonly runtime: readonly RuntimePrivilege[];
    readonly public: readonly RuntimePrivilege[];
  };
  readonly schema: {
    readonly runtime: readonly RuntimePrivilege[];
    readonly public: readonly RuntimePrivilege[];
  };
  readonly tables: Readonly<Record<string, readonly RuntimePrivilege[]>>;
  readonly columns: Readonly<Record<string, Readonly<Record<string, readonly RuntimePrivilege[]>>>>;
  readonly sequences: Readonly<Record<string, readonly RuntimePrivilege[]>>;
  readonly functions: readonly string[];
}

/**
 * Canonical privilege allowlist shared by the mutating reconciler and every
 * read-only verifier. Do not create a second runtime privilege inventory.
 */
export const TENANT_RUNTIME_GRANT_CONTRACT: RuntimeGrantContract = {
  database: Object.freeze({ runtime: ["CONNECT"] as const, public: [] as const }),
  schema: Object.freeze({ runtime: ["USAGE"] as const, public: [] as const }),
  tables: Object.freeze(Object.fromEntries([
    ...TENANT_RUNTIME_READ_ONLY_TABLES.map((table) => [table, ["SELECT"]] as const),
    ...TENANT_RUNTIME_MUTABLE_TABLES.map((table) => [table, ["INSERT", "SELECT", "UPDATE"]] as const),
    ...TENANT_RUNTIME_APPEND_ONLY_TABLES.map((table) => [table, ["INSERT", "SELECT"]] as const),
  ])),
  columns: Object.freeze({
    tenant_settings: Object.freeze(Object.fromEntries(
      TENANT_SETTINGS_RUNTIME_UPDATE_COLUMNS.map((column) => [column, ["UPDATE"]] as const),
    )),
  }),
  sequences: Object.freeze(Object.fromEntries(
    TENANT_RUNTIME_SEQUENCES.map((sequence) => [sequence, ["SELECT", "USAGE"]] as const),
  )),
  functions: Object.freeze([...TENANT_RUNTIME_FUNCTIONS]),
};
