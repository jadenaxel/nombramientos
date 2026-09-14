import { DomainError, invariant } from "./errors.js";

export const PERMISSIONS = {
  PLATFORM_TENANT_PROVISION: "platform.tenant.provision",
  PLATFORM_TENANT_SUSPEND: "platform.tenant.suspend",
  PLATFORM_TENANT_REACTIVATE: "platform.tenant.reactivate",
  PLATFORM_OPERATION_READ: "platform.operation.read",
  PLATFORM_SECURITY_MANAGE: "platform.security.manage",
  TENANT_SETTINGS_MANAGE: "tenant.settings.manage",
  MEMBER_READ: "member.read",
  MEMBER_MANAGE: "member.manage",
  MEMBER_CONTACT_READ: "member.contact.read",
  MEMBER_CONTACT_MANAGE: "member.contact.manage",
  MEMBER_ELIGIBILITY_MANAGE: "member.eligibility.manage",
  MEMBER_QUALIFICATION_READ: "member.qualification.read",
  MEMBER_QUALIFICATION_MANAGE: "member.qualification.manage",
  MEMBER_PHOTO_MANAGE: "member.photo.manage",
  MEMBER_IMPORT: "member.import",
  COMMITTEE_MANAGE: "committee.manage",
  CATALOG_MANAGE: "catalog.manage",
  CYCLE_MANAGE: "cycle.manage",
  WORKFLOW_ELIGIBILITY_RESOLVE: "workflow.eligibility.resolve",
  PROPOSAL_OPEN: "proposal.open",
  PROPOSAL_CLOSE: "proposal.close",
  PROPOSAL_SUBMIT: "proposal.submit",
  PARTICIPATION_NOMINAL_READ: "participation.nominal.read",
  CANDIDATE_REVIEW: "candidate.review",
  BALLOT_OPEN: "ballot.open",
  BALLOT_CLOSE: "ballot.close",
  BALLOT_SUBMIT: "ballot.submit",
  TALLY_CUSTODY: "tally.custody",
  TALLY_RECOUNT: "tally.recount",
  AGGREGATE_PUBLISH: "aggregate.publish",
  AGGREGATE_READ: "aggregate.read",
  LINKED_DESIGNATION_RECORD: "linked-designation.record",
  CONSENT_RECORD: "consent.record",
  CONGREGATIONAL_DECISION_RECORD: "congregational-decision.record",
  ORGANIGRAM_READ: "organigram.read",
  REPORT_READ: "report.read",
  REPORT_EXPORT: "report.export",
  PRIVATE_NOTE_READ: "private-note.read",
  AUDIT_READ: "audit.read",
  ROLE_MANAGE: "role.manage",
  RECOVERY_ACTIVATE: "recovery.activate"
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export const DEFAULT_ROLES = [
  "GLOBAL_ADMIN",
  "CHURCH_ADMIN",
  "COMMITTEE_CHAIR",
  "COMMITTEE_SECRETARY",
  "COMMITTEE_MEMBER",
  "TALLY_CUSTODIAN",
  "AUDITOR"
] as const;

export type DefaultRole = (typeof DEFAULT_ROLES)[number];

const GLOBAL_PERMISSIONS = new Set<Permission>([
  PERMISSIONS.PLATFORM_TENANT_PROVISION,
  PERMISSIONS.PLATFORM_TENANT_SUSPEND,
  PERMISSIONS.PLATFORM_TENANT_REACTIVATE,
  PERMISSIONS.PLATFORM_OPERATION_READ,
  PERMISSIONS.PLATFORM_SECURITY_MANAGE
]);

export const DEFAULT_ROLE_PERMISSIONS: Readonly<
  Record<DefaultRole, readonly Permission[]>
> = {
  GLOBAL_ADMIN: [...GLOBAL_PERMISSIONS],
  CHURCH_ADMIN: [
    PERMISSIONS.TENANT_SETTINGS_MANAGE,
    PERMISSIONS.MEMBER_READ,
    PERMISSIONS.MEMBER_MANAGE,
    PERMISSIONS.MEMBER_CONTACT_READ,
    PERMISSIONS.MEMBER_CONTACT_MANAGE,
    PERMISSIONS.MEMBER_ELIGIBILITY_MANAGE,
    PERMISSIONS.MEMBER_QUALIFICATION_READ,
    PERMISSIONS.MEMBER_QUALIFICATION_MANAGE,
    PERMISSIONS.MEMBER_PHOTO_MANAGE,
    PERMISSIONS.MEMBER_IMPORT,
    PERMISSIONS.COMMITTEE_MANAGE,
    PERMISSIONS.CATALOG_MANAGE,
    PERMISSIONS.CYCLE_MANAGE,
    PERMISSIONS.WORKFLOW_ELIGIBILITY_RESOLVE,
    PERMISSIONS.PROPOSAL_OPEN,
    PERMISSIONS.PROPOSAL_CLOSE,
    PERMISSIONS.PARTICIPATION_NOMINAL_READ,
    PERMISSIONS.CANDIDATE_REVIEW,
    PERMISSIONS.BALLOT_OPEN,
    PERMISSIONS.BALLOT_CLOSE,
    PERMISSIONS.AGGREGATE_READ,
    PERMISSIONS.LINKED_DESIGNATION_RECORD,
    PERMISSIONS.CONSENT_RECORD,
    PERMISSIONS.CONGREGATIONAL_DECISION_RECORD,
    PERMISSIONS.ORGANIGRAM_READ,
    PERMISSIONS.REPORT_READ,
    PERMISSIONS.REPORT_EXPORT,
    PERMISSIONS.PRIVATE_NOTE_READ,
    PERMISSIONS.AUDIT_READ,
    PERMISSIONS.ROLE_MANAGE,
    PERMISSIONS.RECOVERY_ACTIVATE
  ],
  COMMITTEE_CHAIR: [
    PERMISSIONS.MEMBER_READ,
    PERMISSIONS.MEMBER_QUALIFICATION_READ,
    PERMISSIONS.CYCLE_MANAGE,
    PERMISSIONS.WORKFLOW_ELIGIBILITY_RESOLVE,
    PERMISSIONS.PROPOSAL_OPEN,
    PERMISSIONS.PROPOSAL_CLOSE,
    PERMISSIONS.PARTICIPATION_NOMINAL_READ,
    PERMISSIONS.CANDIDATE_REVIEW,
    PERMISSIONS.BALLOT_OPEN,
    PERMISSIONS.BALLOT_CLOSE,
    PERMISSIONS.AGGREGATE_READ,
    PERMISSIONS.LINKED_DESIGNATION_RECORD,
    PERMISSIONS.CONSENT_RECORD,
    PERMISSIONS.ORGANIGRAM_READ,
    PERMISSIONS.REPORT_READ
  ],
  COMMITTEE_SECRETARY: [
    PERMISSIONS.MEMBER_READ,
    PERMISSIONS.MEMBER_QUALIFICATION_READ,
    PERMISSIONS.CYCLE_MANAGE,
    PERMISSIONS.WORKFLOW_ELIGIBILITY_RESOLVE,
    PERMISSIONS.PROPOSAL_OPEN,
    PERMISSIONS.PROPOSAL_CLOSE,
    PERMISSIONS.PARTICIPATION_NOMINAL_READ,
    PERMISSIONS.CANDIDATE_REVIEW,
    PERMISSIONS.BALLOT_OPEN,
    PERMISSIONS.BALLOT_CLOSE,
    PERMISSIONS.AGGREGATE_READ,
    PERMISSIONS.LINKED_DESIGNATION_RECORD,
    PERMISSIONS.CONSENT_RECORD,
    PERMISSIONS.ORGANIGRAM_READ,
    PERMISSIONS.REPORT_READ,
    PERMISSIONS.REPORT_EXPORT
  ],
  COMMITTEE_MEMBER: [
    PERMISSIONS.MEMBER_READ,
    PERMISSIONS.PROPOSAL_SUBMIT,
    PERMISSIONS.BALLOT_SUBMIT,
    PERMISSIONS.AGGREGATE_READ,
    PERMISSIONS.ORGANIGRAM_READ,
    PERMISSIONS.REPORT_READ
  ],
  TALLY_CUSTODIAN: [
    PERMISSIONS.TALLY_CUSTODY,
    PERMISSIONS.TALLY_RECOUNT,
    PERMISSIONS.AGGREGATE_PUBLISH,
    PERMISSIONS.AGGREGATE_READ,
    PERMISSIONS.AUDIT_READ
  ],
  AUDITOR: [
    PERMISSIONS.AGGREGATE_READ,
    PERMISSIONS.ORGANIGRAM_READ,
    PERMISSIONS.REPORT_READ,
    PERMISSIONS.AUDIT_READ
  ]
};

const KNOWN_PERMISSION_SET = new Set<Permission>(Object.values(PERMISSIONS));

export function permissionsForRole(role: DefaultRole): ReadonlySet<Permission> {
  return new Set(DEFAULT_ROLE_PERMISSIONS[role]);
}

export function hasPermission(
  granted: ReadonlySet<Permission> | readonly Permission[],
  required: Permission
): boolean {
  return new Set<Permission>(granted).has(required);
}

export function assertPermission(
  granted: ReadonlySet<Permission> | readonly Permission[],
  required: Permission
): void {
  invariant(
    hasPermission(granted, required),
    "PERMISSION_DENIED",
    `Falta el permiso ${required}.`,
    { required }
  );
}

export function assertTenantRoleGrantAllowed(
  requestedPermissions: readonly string[],
  actorDelegablePermissions: ReadonlySet<Permission> | readonly Permission[]
): readonly Permission[] {
  const actorPermissions = new Set<Permission>(actorDelegablePermissions);
  const unique = new Set<Permission>();

  for (const requested of requestedPermissions) {
    if (!KNOWN_PERMISSION_SET.has(requested as Permission)) {
      throw new DomainError(
        "INVALID_PERMISSION",
        `El permiso ${requested} no forma parte del contrato de dominio.`,
        { requested }
      );
    }

    const permission = requested as Permission;
    invariant(
      !GLOBAL_PERMISSIONS.has(permission),
      "PERMISSION_ESCALATION",
      "Un rol local no puede conceder privilegios globales.",
      { requested: permission }
    );
    invariant(
      actorPermissions.has(permission),
      "PERMISSION_ESCALATION",
      "El actor no puede delegar un permiso que no posee como delegable.",
      { requested: permission }
    );
    unique.add(permission);
  }

  return [...unique].sort();
}
