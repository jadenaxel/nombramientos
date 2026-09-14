import { createHash, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { isOrdinaryProposalBallotMechanism } from "@nombramientos/catalog";
import { appendTenantAuditEventV2 } from "./audit-event-chain.js";
import { verifyTenantAuditEventChain, type TenantAuditEventRecord } from "./audit-anchors.js";
import { assertWritableTenantContentKey } from "./content-key-write-guard.js";
import type { TenantInvitationRole } from "./invitation-store.js";
import {
  evaluateMemberImportPlan,
  normalizeStableCode,
  type MemberImportRow,
} from "./member-import.js";
import {
  acquireMemberEligibilityPolicyExclusiveLock,
  acquireMemberEligibilityPolicySharedLock,
  MemberEligibilityGuardError,
  requireRoundCandidatesOperationallyEligible,
} from "./member-eligibility-guard.js";
import type { EncryptedEnvelope } from "./types.js";
import {
  appendSensitiveReadAuditEvent,
  SENSITIVE_READ_AUDIT_ACTIONS,
} from "./sensitive-read-audit.js";
import {
  MEMBER_ARCHIVE_REASON_CODES,
  MEMBER_REACTIVATE_REASON_CODES,
  REPORT_CORRECTION_REASON_CODES,
  ROUND_CLOSE_REASON_CODES,
  normalizeAllowedReasonCode,
  type ReportCorrectionReasonCode,
} from "./reason-code.js";

export class DataConflictError extends Error {
  public constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "DataConflictError";
  }
}

export interface KeyGrant {
  readonly version: number;
  readonly tenantKeyId: string;
  readonly deviceId: string;
  readonly kdf: Readonly<Record<string, unknown>>;
  readonly wrap: Readonly<Record<string, unknown>>;
}

export interface SubmissionInput {
  readonly idempotencyKey: string;
  readonly roundId: string;
  readonly identityId: string;
  readonly kind: "proposal" | "vote";
  readonly expectedVersion: number;
  readonly envelope: EncryptedEnvelope;
  readonly contentHash: string;
}

export interface SubmissionReceipt {
  readonly receiptId: string;
  readonly receivedAt: Date;
  readonly roundId: string;
  readonly roundVersion: number;
  readonly contentHash: string;
  readonly status: "received";
}

export interface LocalizedAccessName {
  readonly es: string;
  readonly en: string;
  readonly fr: string;
}

export interface TenantPermissionCapability {
  readonly code: string;
  readonly description: string;
  readonly possessed: boolean;
  readonly delegable: boolean;
}

export interface TenantAccessRole {
  readonly id: string;
  readonly code: string;
  readonly name: LocalizedAccessName;
  readonly system: boolean;
  readonly version: number;
  readonly permissions: readonly {
    readonly code: string;
    readonly delegable: boolean;
  }[];
}

export interface TenantRoleBinding {
  readonly identityId: string;
  readonly roleId: string;
  readonly roleCode: string;
  readonly version: number;
  readonly grantedAt: Date;
  readonly grantedByIdentityId: string | null;
}

export interface AccessRoleMutationResult {
  readonly roleId: string;
  readonly version: number;
  readonly affectedIdentityIds: readonly string[];
}

export interface AccessBindingMutationResult {
  readonly roleId: string;
  readonly identityId: string;
  readonly version: number;
  readonly active: boolean;
}

export interface ReportCorrectionInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly previousReportId: string;
  readonly expectedPreviousVersion: number;
  readonly filters: Readonly<Record<string, unknown>>;
  readonly reasonCode: string;
}

export interface PendingReportIssuance {
  readonly id: string;
  readonly reportType: string;
  readonly audience: "committee" | "auditor" | "church";
  readonly locale: "es" | "en" | "fr";
  readonly format: "pdf" | "xlsx" | "csv";
  readonly filters: Readonly<Record<string, unknown>>;
  readonly filename: string;
  readonly mediaType: string;
  readonly state: "pending";
  readonly version: number;
  readonly artifactSha256: null;
  readonly ciphertextSha256: null;
  readonly ciphertextBytes: null;
  readonly plaintextBytes: null;
  readonly manifest: null;
  readonly errorCode: null;
  readonly supersedesReportId: string | null;
  readonly correctedByReportId: null;
  readonly correctionReasonCode: ReportCorrectionReasonCode | null;
  readonly lineageRootId: string;
  readonly lineageRevision: number;
  readonly createdAt: Date;
  readonly readyAt: null;
  readonly failedAt: null;
}

export class TenantStore {
  public constructor(private readonly client: PoolClient) {}

  public async getPermissions(identityId: string): Promise<readonly string[]> {
    const result = await this.client.query<{ code: string }>(
      `SELECT DISTINCT p.code
         FROM role_bindings rb
         JOIN role_permissions rp ON rp.role_id = rb.role_id
         JOIN permissions p ON p.code = rp.permission_code
        WHERE rb.identity_id = $1 AND rb.revoked_at IS NULL
        ORDER BY p.code`,
      [identityId],
    );
    return result.rows.map(({ code }) => code);
  }

  public async listPermissionCapabilities(identityId: string): Promise<readonly TenantPermissionCapability[]> {
    const result = await this.client.query<{
      code: string;
      description: string;
      possessed: boolean;
      delegable: boolean;
    }>(
      `SELECT permission.code, permission.description,
              EXISTS (
                SELECT 1
                  FROM role_bindings binding
                  JOIN role_permissions granted ON granted.role_id = binding.role_id
                 WHERE binding.identity_id = $1
                   AND binding.revoked_at IS NULL
                   AND granted.permission_code = permission.code
              ) AS possessed,
              EXISTS (
                SELECT 1
                  FROM role_bindings binding
                  JOIN role_permissions granted ON granted.role_id = binding.role_id
                 WHERE binding.identity_id = $1
                   AND binding.revoked_at IS NULL
                   AND granted.permission_code = permission.code
                   AND granted.delegable
              ) AS delegable
         FROM permissions permission
        WHERE permission.code NOT LIKE 'platform.%'
        ORDER BY permission.code`,
      [identityId],
    );
    return result.rows;
  }

  public async authorizeMemberExport(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly format: "csv" | "xlsx";
    readonly rowCount: number;
    readonly includeContact: boolean;
    readonly filters: { readonly status: "all" | "active" | "archived"; readonly queryApplied: boolean };
    readonly selectionSha256: string;
  }): Promise<{
    readonly authorizationId: string;
    readonly format: "csv" | "xlsx";
    readonly rowCount: number;
    readonly includeContact: boolean;
    readonly selectionSha256: string;
    readonly authorizedAt: string;
    readonly expiresAt: string;
  }> {
    return this.executeIdempotent(input.identityId, "member.export.authorize", input.idempotencyKey, input, async () => {
      const authorizationId = randomUUID();
      const clock = await this.client.query<{ authorized_at: Date }>("SELECT clock_timestamp() AS authorized_at");
      const authorizedAt = clock.rows[0]?.authorized_at;
      if (!(authorizedAt instanceof Date) || !Number.isFinite(authorizedAt.getTime())) {
        throw new Error("Roster export authorization clock is unavailable");
      }
      const expiresAt = new Date(authorizedAt.getTime() + 5 * 60_000);
      await this.appendAudit("member.roster_export.authorized", "export_authorization", authorizationId, "success", {
        format: input.format,
        rowCount: input.rowCount,
        includeContact: input.includeContact,
        filters: input.filters,
        selectionSha256: input.selectionSha256,
        authorizedAt: authorizedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
      });
      return {
        authorizationId,
        format: input.format,
        rowCount: input.rowCount,
        includeContact: input.includeContact,
        selectionSha256: input.selectionSha256,
        authorizedAt: authorizedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
      };
    });
  }

  public async listAccessRoles(): Promise<readonly TenantAccessRole[]> {
    const result = await this.client.query<{
      id: string;
      code: string;
      name_i18n: LocalizedAccessName;
      system_role: boolean;
      version: number;
      permissions: Array<{ code: string; delegable: boolean }>;
    }>(
      `SELECT role.id, role.code, role.name_i18n, role.system_role, role.version,
              COALESCE(
                jsonb_agg(
                  jsonb_build_object('code', role_permission.permission_code, 'delegable', role_permission.delegable)
                  ORDER BY role_permission.permission_code
                ) FILTER (WHERE role_permission.permission_code IS NOT NULL),
                '[]'::jsonb
              ) AS permissions
         FROM roles role
         LEFT JOIN role_permissions role_permission ON role_permission.role_id = role.id
        GROUP BY role.id
        ORDER BY role.system_role DESC, role.code`,
    );
    return result.rows.map((row) => ({
      id: row.id,
      code: row.code,
      name: row.name_i18n,
      system: row.system_role,
      version: row.version,
      permissions: row.permissions,
    }));
  }

  public async listRoleBindings(): Promise<readonly TenantRoleBinding[]> {
    const result = await this.client.query<{
      identity_id: string;
      role_id: string;
      role_code: string;
      version: number;
      granted_at: Date;
      granted_by_identity_id: string | null;
    }>(
      `SELECT binding.identity_id, binding.role_id, role.code AS role_code,
              binding.version, binding.granted_at, binding.granted_by_identity_id
         FROM role_bindings binding
         JOIN roles role ON role.id = binding.role_id
        WHERE binding.revoked_at IS NULL
        ORDER BY binding.identity_id, role.code`,
    );
    return result.rows.map((row) => ({
      identityId: row.identity_id,
      roleId: row.role_id,
      roleCode: row.role_code,
      version: row.version,
      grantedAt: row.granted_at,
      grantedByIdentityId: row.granted_by_identity_id,
    }));
  }

  public async createLocalRole(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly roleId: string;
    readonly code: string;
    readonly name: LocalizedAccessName;
    readonly permissionCodes: readonly string[];
    readonly delegablePermissionCodes: readonly string[];
  }): Promise<AccessRoleMutationResult> {
    return this.executeIdempotent(input.identityId, "access.role.create", input.idempotencyKey, input, async () => {
      await this.queryAccessMutation(
        "SELECT create_local_role($1,$2,$3,$4,$5::text[],$6::text[])",
        [input.identityId, input.roleId, input.code, input.name, [...input.permissionCodes], [...input.delegablePermissionCodes]],
      );
      await this.emit("access.role.changed", "role", input.roleId, { roleId: input.roleId, version: 1 });
      await this.appendAudit("access.role.created", "role", input.roleId, "success", {
        code: input.code,
        permissionCodes: [...input.permissionCodes].sort(),
        delegablePermissionCodes: [...input.delegablePermissionCodes].sort(),
        version: 1,
      });
      return { roleId: input.roleId, version: 1, affectedIdentityIds: [] };
    });
  }

  public async updateLocalRole(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly roleId: string;
    readonly expectedVersion: number;
    readonly name: LocalizedAccessName;
    readonly permissionCodes: readonly string[];
    readonly delegablePermissionCodes: readonly string[];
  }): Promise<AccessRoleMutationResult> {
    return this.executeIdempotent(input.identityId, "access.role.update", input.idempotencyKey, input, async () => {
      const result = await this.queryAccessMutation<{
        next_version: number;
        affected_identity_ids: string[];
      }>(
        "SELECT * FROM update_local_role($1,$2,$3,$4,$5::text[],$6::text[])",
        [
          input.identityId,
          input.roleId,
          input.expectedVersion,
          input.name,
          [...input.permissionCodes],
          [...input.delegablePermissionCodes],
        ],
      );
      const row = result.rows[0];
      if (!row) throw new Error("Local role update did not return a result");
      await this.emit("access.role.changed", "role", input.roleId, { roleId: input.roleId, version: row.next_version });
      await this.appendAudit("access.role.updated", "role", input.roleId, "success", {
        previousVersion: input.expectedVersion,
        version: row.next_version,
        permissionCodes: [...input.permissionCodes].sort(),
        delegablePermissionCodes: [...input.delegablePermissionCodes].sort(),
        affectedIdentityCount: row.affected_identity_ids.length,
      });
      return {
        roleId: input.roleId,
        version: row.next_version,
        affectedIdentityIds: row.affected_identity_ids,
      };
    });
  }

  public async grantRoleBinding(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly targetIdentityId: string;
    readonly roleId: string;
  }): Promise<AccessBindingMutationResult> {
    return this.executeIdempotent(input.identityId, "access.binding.grant", input.idempotencyKey, input, async () => {
      const result = await this.queryAccessMutation<{ version: number }>(
        "SELECT grant_tenant_role_binding($1,$2,$3)::int AS version",
        [input.identityId, input.targetIdentityId, input.roleId],
      );
      const version = result.rows[0]?.version;
      if (!version) throw new Error("Role binding grant did not return a version");
      await this.emit("access.binding.changed", "identity", input.targetIdentityId, {
        identityId: input.targetIdentityId, roleId: input.roleId, active: true, version,
      });
      await this.appendAudit("access.binding.granted", "identity", input.targetIdentityId, "success", {
        roleId: input.roleId, version,
      });
      return { roleId: input.roleId, identityId: input.targetIdentityId, version, active: true };
    });
  }

  public async revokeRoleBinding(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly targetIdentityId: string;
    readonly roleId: string;
    readonly expectedVersion: number;
  }): Promise<AccessBindingMutationResult> {
    return this.executeIdempotent(input.identityId, "access.binding.revoke", input.idempotencyKey, input, async () => {
      const result = await this.queryAccessMutation<{ version: number }>(
        "SELECT revoke_tenant_role_binding($1,$2,$3,$4)::int AS version",
        [input.identityId, input.targetIdentityId, input.roleId, input.expectedVersion],
      );
      const version = result.rows[0]?.version;
      if (!version) throw new Error("Role binding revocation did not return a version");
      await this.emit("access.binding.changed", "identity", input.targetIdentityId, {
        identityId: input.targetIdentityId, roleId: input.roleId, active: false, version,
      });
      await this.appendAudit("access.binding.revoked", "identity", input.targetIdentityId, "success", {
        roleId: input.roleId, previousVersion: input.expectedVersion, version,
      });
      return { roleId: input.roleId, identityId: input.targetIdentityId, version, active: false };
    });
  }

  public async activateInvitationRoles(input: {
    invitationId: string;
    identityId: string;
    roles: readonly TenantInvitationRole[];
    grantedByIdentityId: string;
    acceptanceAttempt: number;
  }): Promise<number> {
    const result = await this.client.query<{ bound_count: number }>(
      `SELECT apply_tenant_invitation_roles($1,$2,$3::text[],$4,$5)::int AS bound_count`,
      [
        input.invitationId,
        input.identityId,
        [...input.roles],
        input.grantedByIdentityId,
        input.acceptanceAttempt,
      ],
    );
    const count = result.rows[0]?.bound_count;
    if (count !== input.roles.length) {
      throw new Error("Invitation tenant roles were not bound exactly");
    }
    return count;
  }

  public async assertInvitationRoleDelegation(input: {
    actorIdentityId: string;
    roles: readonly TenantInvitationRole[];
  }): Promise<void> {
    await this.queryAccessMutation(
      "SELECT assert_tenant_invitation_role_delegation_allowed($1,$2::text[])",
      [input.actorIdentityId, [...input.roles]],
    );
  }

  public async cleanupInvitationRoles(input: {
    invitationId: string;
    acceptanceId: string;
    identityId: string;
    acceptanceAttempt: number;
  }): Promise<number> {
    const result = await this.client.query<{ removed_count: number }>(
      "SELECT cleanup_tenant_invitation_roles($1,$2,$3,$4)::int AS removed_count",
      [input.invitationId, input.acceptanceId, input.identityId, input.acceptanceAttempt],
    );
    return result.rows[0]?.removed_count ?? 0;
  }

  public async activateInitialAdminInvitationRole(input: {
    invitationId: string;
    identityId: string;
    grantedByIdentityId: string;
    authorityEpoch: number;
    acceptanceAttempt: number;
    capabilitySecret: string;
  }): Promise<void> {
    const result = await this.client.query<{ bound_count: number }>(
      `SELECT apply_tenant_initial_admin_role($1,$2,$3,$4,$5,$6)::int AS bound_count`,
      [
        input.invitationId,
        input.identityId,
        input.grantedByIdentityId,
        input.authorityEpoch,
        input.acceptanceAttempt,
        input.capabilitySecret,
      ],
    );
    if (result.rows[0]?.bound_count !== 1) {
      throw new Error("Initial administrator invitation role was not bound exactly");
    }
  }

  public async rollbackInitialAdminInvitationRole(input: {
    invitationId: string;
    acceptanceId: string;
    identityId: string;
    grantedByIdentityId: string;
    authorityEpoch: number;
    acceptanceAttempt: number;
    capabilitySecret: string;
  }): Promise<boolean> {
    const result = await this.client.query<{ rolled_back: boolean }>(
      `SELECT rollback_tenant_initial_admin_role($1,$2,$3,$4,$5,$6,$7) AS rolled_back`,
      [
        input.invitationId,
        input.acceptanceId,
        input.identityId,
        input.grantedByIdentityId,
        input.authorityEpoch,
        input.acceptanceAttempt,
        input.capabilitySecret,
      ],
    );
    return result.rows[0]?.rolled_back === true;
  }

  public async consumeInitialAdminInvitationRole(input: {
    invitationId: string;
    acceptanceId: string;
    identityId: string;
    authorityEpoch: number;
    acceptanceAttempt: number;
    capabilitySecret: string;
  }): Promise<boolean> {
    const result = await this.client.query<{ consumed: boolean }>(
      `SELECT consume_tenant_initial_admin_role($1,$2,$3,$4,$5,$6) AS consumed`,
      [
        input.invitationId,
        input.acceptanceId,
        input.identityId,
        input.authorityEpoch,
        input.acceptanceAttempt,
        input.capabilitySecret,
      ],
    );
    return result.rows[0]?.consumed === true;
  }

  public async getKeyGrant(identityId: string): Promise<KeyGrant | null> {
    const result = await this.client.query<{
      version: number; tenant_key_id: string; device_id: string;
      kdf: Record<string, unknown>; wrap: Record<string, unknown>;
    }>(
      `SELECT version, tenant_key_id, device_id, kdf, wrap
         FROM device_key_grants
        WHERE identity_id = $1 AND status = 'active'
        ORDER BY created_at DESC LIMIT 1`,
      [identityId],
    );
    const row = result.rows[0];
    return row
      ? {
          version: row.version,
          tenantKeyId: row.tenant_key_id,
          deviceId: row.device_id,
          kdf: row.kdf,
          wrap: row.wrap,
        }
      : null;
  }

  public async getDashboard(): Promise<Record<string, unknown>> {
    const result = await this.client.query<{
      tenant_id: string; tenant_name: string; tenant_kind: string;
      cycle_id: string | null; cycle_name: string | null; cycle_status: string | null;
      term_start: string | null; term_end: string | null; cycle_version: number | null;
      cycle_updated_at: Date | null; eligible_reference_count: number | null;
      members_total: number; vacancies_total: number; recommended: number;
      accepted: number; elected: number; dashboard_updated_at: Date;
    }>(`
      SELECT ts.tenant_id, ts.display_name AS tenant_name, ts.kind AS tenant_kind,
             c.id AS cycle_id, c.name AS cycle_name, c.status AS cycle_status,
             c.term_start::text, c.term_end::text, c.version AS cycle_version,
             c.updated_at AS cycle_updated_at, c.eligible_reference_count,
             GREATEST(
               ts.updated_at,
               c.updated_at,
               (SELECT max(member.updated_at) FROM members member),
               (SELECT max(department.updated_at) FROM departments department),
               (SELECT max(office.updated_at) FROM offices office),
               (SELECT max(process.updated_at) FROM office_processes process WHERE process.cycle_id=c.id),
               (SELECT max(COALESCE(round_state.closed_at,round_state.opened_at,round_state.created_at))
                  FROM rounds round_state WHERE round_state.cycle_id=c.id),
               (SELECT max(receipt.received_at) FROM participation_receipts receipt
                  JOIN rounds receipt_round ON receipt_round.id=receipt.round_id
                 WHERE receipt_round.cycle_id=c.id),
               (SELECT max(assignment.updated_at) FROM assignments assignment WHERE assignment.cycle_id=c.id),
               (SELECT max(session.updated_at) FROM cycle_sessions session WHERE session.cycle_id=c.id),
               (SELECT max(agenda.updated_at) FROM session_agenda_items agenda
                  JOIN cycle_sessions agenda_session ON agenda_session.id=agenda.session_id
                 WHERE agenda_session.cycle_id=c.id),
               (SELECT max(decision.created_at) FROM session_decisions decision
                  JOIN cycle_sessions decision_session ON decision_session.id=decision.session_id
                 WHERE decision_session.cycle_id=c.id)
             ) AS dashboard_updated_at,
             (SELECT count(*)::int FROM members m WHERE m.archived_at IS NULL) AS members_total,
             (SELECT count(*)::int FROM vacancies v WHERE v.cycle_id = c.id AND (
               v.process_id IS NULL OR EXISTS (
                 SELECT 1 FROM office_processes applicable
                  WHERE applicable.cycle_id=v.cycle_id AND applicable.enabled
                    AND (applicable.id=v.process_id OR applicable.reused_vacancy_id=v.id)
               )
             )) AS vacancies_total,
             (SELECT count(*)::int FROM vacancies v WHERE v.cycle_id = c.id
               AND v.status IN ('recommended','accepted','elected') AND (
                 v.process_id IS NULL OR EXISTS (
                   SELECT 1 FROM office_processes applicable
                    WHERE applicable.cycle_id=v.cycle_id AND applicable.enabled
                      AND (applicable.id=v.process_id OR applicable.reused_vacancy_id=v.id)
                 )
               )) AS recommended,
             (SELECT count(*)::int FROM vacancies v WHERE v.cycle_id = c.id
               AND v.status IN ('accepted','elected') AND (
                 v.process_id IS NULL OR EXISTS (
                   SELECT 1 FROM office_processes applicable
                    WHERE applicable.cycle_id=v.cycle_id AND applicable.enabled
                      AND (applicable.id=v.process_id OR applicable.reused_vacancy_id=v.id)
                 )
               )) AS accepted,
             (SELECT count(*)::int FROM vacancies v WHERE v.cycle_id = c.id
               AND v.status = 'elected' AND (
                 v.process_id IS NULL OR EXISTS (
                   SELECT 1 FROM office_processes applicable
                    WHERE applicable.cycle_id=v.cycle_id AND applicable.enabled
                      AND (applicable.id=v.process_id OR applicable.reused_vacancy_id=v.id)
                 )
               )) AS elected
        FROM tenant_settings ts
        LEFT JOIN LATERAL (
          SELECT * FROM election_cycles
           WHERE status IN ('active','draft')
           ORDER BY (status = 'active') DESC, created_at DESC LIMIT 1
        ) c ON true
       WHERE ts.singleton = true
    `);
    const row = result.rows[0];
    if (!row) throw new Error("Tenant settings are missing");
    const [activeRound, roundParticipation, departments, sessions] = await Promise.all([
      this.getActiveRound(false),
      this.client.query<{
        round_id: string; kind: "proposal" | "vote"; office_name: string;
        office_names: Record<string, string>; phase: string; version: number;
        required: number; received: number; recorded_at: Date;
      }>(`
        SELECT DISTINCT ON (round_state.submission_kind)
               round_state.id AS round_id,round_state.submission_kind AS kind,
               COALESCE(office.names->>settings.locale,office.names->>'es',office.canonical_code) AS office_name,
               office.names AS office_names,round_state.phase,round_state.version,
               (SELECT count(*)::int FROM round_elector_snapshots electorate
                 WHERE electorate.round_id=round_state.id AND electorate.can_submit AND NOT electorate.recused) AS required,
               (SELECT count(*)::int FROM participation_receipts receipt
                 WHERE receipt.round_id=round_state.id AND receipt.kind=round_state.submission_kind) AS received,
               COALESCE(round_state.closed_at,round_state.opened_at,round_state.created_at) AS recorded_at
          FROM rounds round_state
          JOIN offices office ON office.id=round_state.office_id
          JOIN tenant_settings settings ON settings.singleton=true
          WHERE round_state.cycle_id=$1
            AND round_state.phase <> 'ANULADO'
            AND (round_state.process_id IS NULL OR EXISTS (
             SELECT 1 FROM office_processes applicable
              WHERE applicable.id=round_state.process_id AND applicable.cycle_id=round_state.cycle_id
                AND applicable.enabled
           ))
         ORDER BY round_state.submission_kind,round_state.created_at DESC,round_state.id DESC`,
        [row.cycle_id],
      ),
      this.client.query<{
        department_id: string | null; department_name: string | null;
        department_names: Record<string, string> | null; vacancies_total: number;
        recommended: number; accepted: number; elected: number;
      }>(`
        SELECT department.id AS department_id,
               COALESCE(department.names->>settings.locale,department.names->>'es',department.canonical_code) AS department_name,
               department.names AS department_names,
               count(*)::int AS vacancies_total,
               count(*) FILTER (WHERE vacancy.status IN ('recommended','accepted','elected'))::int AS recommended,
               count(*) FILTER (WHERE vacancy.status IN ('accepted','elected'))::int AS accepted,
               count(*) FILTER (WHERE vacancy.status='elected')::int AS elected
          FROM vacancies vacancy
          JOIN offices office ON office.id=vacancy.office_id
          LEFT JOIN departments department ON department.id=office.department_id
          JOIN tenant_settings settings ON settings.singleton=true
         WHERE vacancy.cycle_id=$1
           AND (vacancy.process_id IS NULL OR EXISTS (
             SELECT 1 FROM office_processes applicable
              WHERE applicable.cycle_id=vacancy.cycle_id AND applicable.enabled
                AND (applicable.id=vacancy.process_id OR applicable.reused_vacancy_id=vacancy.id)
           ))
         GROUP BY department.id,department.names,department.canonical_code,department.sort_order,settings.locale
         ORDER BY department.sort_order NULLS LAST,department.canonical_code NULLS LAST`,
        [row.cycle_id],
      ),
      this.client.query<{
        session_id: string; sequence: number; status: string; version: number;
        starts_at: Date; updated_at: Date; agenda_count: number; decision_count: number;
      }>(`
        SELECT session.id AS session_id,session.sequence,session.status,session.version,
               session.starts_at,session.updated_at,
               (SELECT count(*)::int FROM session_agenda_items agenda
                 WHERE agenda.session_id=session.id) AS agenda_count,
               (SELECT count(*)::int FROM session_decisions decision
                 WHERE decision.session_id=session.id) AS decision_count
          FROM cycle_sessions session
         WHERE session.cycle_id=$1 AND session.status <> 'cancelled'
         ORDER BY session.sequence,session.id`,
        [row.cycle_id],
      ),
    ]);
    const vacanciesTotal = row.vacancies_total ?? 0;
    return {
      tenant: { id: row.tenant_id, name: row.tenant_name, kind: row.tenant_kind },
      cycle: row.cycle_id
        ? {
            id: row.cycle_id,
            name: row.cycle_name,
            status: row.cycle_status,
            termStart: row.term_start,
            termEnd: row.term_end,
            version: row.cycle_version,
            updatedAt: row.cycle_updated_at,
          }
        : null,
      metrics: {
        membersTotal: row.members_total,
        eligibleReference: row.eligible_reference_count ?? 0,
        vacanciesTotal,
        recommended: row.recommended ?? 0,
        accepted: row.accepted ?? 0,
        congregationallyElected: row.elected ?? 0,
        coveragePercent:
          vacanciesTotal === 0
            ? null
            : Number((((row.recommended ?? 0) / vacanciesTotal) * 100).toFixed(2)),
      },
      activeRound: activeRound
        ? {
            id: (activeRound["round"] as { id: string }).id,
            phase: (activeRound["round"] as { phase: string }).phase,
            version: (activeRound["round"] as { version: number }).version,
            officeName: (activeRound["round"] as { officeName: unknown }).officeName,
            officeNames: (activeRound["round"] as { officeNames: unknown }).officeNames,
            responsesRequired: (activeRound["participation"] as { required: number }).required,
            responsesReceived: (activeRound["participation"] as { received: number }).received,
          }
        : null,
      analytics: {
        roundParticipation: roundParticipation.rows.map((item) => ({
          roundId: item.round_id,
          kind: item.kind,
          officeName: item.office_name,
          officeNames: item.office_names,
          phase: item.phase,
          version: item.version,
          required: item.required,
          received: item.received,
          recordedAt: item.recorded_at,
        })),
        departments: departments.rows.map((item) => ({
          departmentId: item.department_id,
          departmentName: item.department_name,
          departmentNames: item.department_names,
          vacanciesTotal: item.vacancies_total,
          recommended: item.recommended,
          accepted: item.accepted,
          elected: item.elected,
          coveragePercent: item.vacancies_total === 0
            ? null
            : Number(((item.recommended / item.vacancies_total) * 100).toFixed(2)),
        })),
        sessions: sessions.rows.map((item) => ({
          sessionId: item.session_id,
          sequence: item.sequence,
          status: item.status,
          version: item.version,
          startsAt: item.starts_at,
          updatedAt: item.updated_at,
          agendaItems: item.agenda_count,
          decisions: item.decision_count,
        })),
      },
      updatedAt: row.dashboard_updated_at.toISOString(),
    };
  }

  public async listMembers(
    limit: number,
    cursor?: string,
    includeArchived = false,
    includeEligibilityEnvelope = false,
    includeContactEnvelope = false,
  ): Promise<Record<string, unknown>> {
    const values: unknown[] = [limit + 1, includeArchived];
    const eligibilityProjection = includeEligibilityEnvelope ? ", m.eligibility_envelope" : "";
    const contactProjection = includeContactEnvelope ? ", m.contact_envelope" : "";
    let cursorClause = "";
    if (cursor) {
      values.push(cursor);
      cursorClause = `AND (member_key.created_at, member_key.id) > (
        SELECT created_at, id FROM members WHERE id = $3
      )`;
    }
    const result = await this.client.query<{
      id: string; stable_code: string; display_envelope: EncryptedEnvelope | null;
      contact_envelope?: EncryptedEnvelope | null; profile_migration_required: boolean;
      eligibility_envelope?: EncryptedEnvelope | null; eligibility_status: string;
      eligibility_department_id: string | null; eligibility_valid_until: string | null;
      eligibility_evaluated_on: string; eligibility_effective: boolean;
      available: boolean; version: number; archived_at: Date | null; created_at: Date; updated_at: Date;
      current_responsibilities: number; total_count: number;
    }>(
      `WITH filtered_member_keys AS MATERIALIZED (
         SELECT member_key.id,member_key.created_at
           FROM members member_key
          WHERE ($2::boolean OR member_key.archived_at IS NULL) ${cursorClause}
       ), page_keys AS MATERIALIZED (
         SELECT id,created_at
           FROM filtered_member_keys
          ORDER BY created_at,id LIMIT $1
       ), member_total AS (
         SELECT count(*)::int AS total_count FROM filtered_member_keys
       )
       SELECT m.id, m.stable_code, m.display_envelope, m.profile_migration_required${eligibilityProjection}${contactProjection},
              m.eligibility_status,m.eligibility_department_id,
              to_char(m.eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until,
              to_char((clock_timestamp() AT TIME ZONE settings.timezone)::date,'YYYY-MM-DD') AS eligibility_evaluated_on,
              (m.archived_at IS NULL AND m.eligibility_status='eligible' AND m.available
                AND (m.eligibility_valid_until IS NULL
                  OR m.eligibility_valid_until >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
                AND (m.eligibility_department_id IS NULL OR EXISTS (
                  SELECT 1 FROM departments restriction
                   WHERE restriction.id=m.eligibility_department_id AND restriction.active
                ))) AS eligibility_effective,
              m.available, m.version, m.archived_at, m.created_at, m.updated_at,
              (SELECT count(*)::int FROM assignments a
                WHERE a.member_id=m.id AND a.effective AND a.independent) AS current_responsibilities,
              member_total.total_count
         FROM page_keys
         JOIN members m ON m.id=page_keys.id
         CROSS JOIN tenant_settings settings
         CROSS JOIN member_total
        WHERE settings.singleton=true
        ORDER BY page_keys.created_at,page_keys.id`,
      values,
    );
    const hasMore = result.rows.length > limit;
    const rows = result.rows.slice(0, limit);
    const contactRecordCount = includeContactEnvelope
      ? rows.filter((row) => row.contact_envelope !== null && row.contact_envelope !== undefined).length
      : 0;
    const privateNoteRecordCount = includeEligibilityEnvelope
      ? rows.filter((row) => row.eligibility_envelope !== null && row.eligibility_envelope !== undefined).length
      : 0;
    if (contactRecordCount > 0) {
      await appendSensitiveReadAuditEvent(this.client, {
        action: SENSITIVE_READ_AUDIT_ACTIONS.memberContact,
        entityType: "member_roster",
        entityId: "members",
        metadata: { recordCount: contactRecordCount },
      });
    }
    if (privateNoteRecordCount > 0) {
      await appendSensitiveReadAuditEvent(this.client, {
        action: SENSITIVE_READ_AUDIT_ACTIONS.memberPrivateNote,
        entityType: "member_roster",
        entityId: "members",
        metadata: { recordCount: privateNoteRecordCount },
      });
    }
    return {
      items: rows.map((row) => ({
        id: row.id,
        shortId: row.stable_code,
        displayEnvelope: row.display_envelope,
        profileMigrationRequired: row.profile_migration_required,
        ...(includeContactEnvelope && row.contact_envelope
          ? { contactEnvelope: row.contact_envelope }
          : {}),
        ...(includeEligibilityEnvelope && row.eligibility_envelope
          ? { eligibilityEnvelope: row.eligibility_envelope }
          : {}),
        eligible: row.eligibility_effective,
        departmentRestriction: row.eligibility_department_id,
        validUntil: row.eligibility_valid_until,
        eligibilityEvaluatedOn: row.eligibility_evaluated_on,
        archived: row.archived_at !== null,
        ...(includeArchived ? {
          eligibilityStatus: row.eligibility_status,
          available: row.available,
          archivedAt: row.archived_at,
        } : {}),
        currentResponsibilities: row.current_responsibilities,
        version: row.version,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
      total: rows[0]?.total_count ?? 0,
      nextCursor: hasMore ? rows.at(-1)?.id ?? null : null,
    };
  }

  public async createMember(input: {
    identityId: string; idempotencyKey: string; memberId: string; stableCode: string;
    displayEnvelope: EncryptedEnvelope; displayContentHash?: string;
    contactEnvelope?: EncryptedEnvelope; contactContentHash?: string;
    eligibilityEnvelope?: EncryptedEnvelope;
    eligibilityStatus: "eligible" | "ineligible" | "review"; available: boolean;
    departmentRestriction?: string | null; validUntil?: string | null;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "member.create", input.idempotencyKey, input, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.displayEnvelope, input.contactEnvelope, input.eligibilityEnvelope],
      });
      if (input.departmentRestriction) await this.requireActiveDepartment(input.departmentRestriction);
      const evaluatedOn = await this.tenantCivilDate();
      const result = await this.client.query<{ id: string; version: number; created_at: Date }>(
        `INSERT INTO members(
           id,stable_code,profile_envelope,display_envelope,display_content_hash,
           contact_envelope,contact_content_hash,profile_migration_required,
           eligibility_envelope,eligibility_status,available,eligibility_department_id,eligibility_valid_until
         ) VALUES ($1,$2,NULL,$3,$4,$5,$6,false,$7,$8,$9,$10,$11)
         RETURNING id,version,created_at`,
        [
          input.memberId,
          input.stableCode,
          input.displayEnvelope,
          input.displayContentHash ?? encryptedEnvelopeHash(input.displayEnvelope),
          input.contactEnvelope ?? null,
          input.contactContentHash ?? null,
          input.eligibilityEnvelope ?? null,
          input.eligibilityStatus,
          input.available,
          input.departmentRestriction ?? null,
          input.validUntil ?? null,
        ],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw new DataConflictError("MEMBER_EXISTS", "Member id or short id already exists");
        throw error;
      });
      const row = result.rows[0];
      if (!row) throw new Error("Member creation did not return a row");
      await this.emit("member.changed", "member", row.id, { memberId: row.id, version: row.version });
      await this.appendAudit("member.created", "member", row.id, "success", {
        eligibilityStatus: input.eligibilityStatus,
        available: input.available,
        version: row.version,
      });
      return {
        id: row.id,
        shortId: input.stableCode,
        displayEnvelope: input.displayEnvelope,
        profileMigrationRequired: false,
        eligible: input.eligibilityStatus === "eligible" && input.available
          && (input.validUntil === undefined || input.validUntil === null || input.validUntil >= evaluatedOn),
        eligibilityStatus: input.eligibilityStatus,
        available: input.available,
        departmentRestriction: input.departmentRestriction ?? null,
        validUntil: input.validUntil ?? null,
        eligibilityEvaluatedOn: evaluatedOn,
        archived: false,
        archivedAt: null,
        currentResponsibilities: 0,
        version: row.version,
        createdAt: row.created_at,
      };
    });
  }

  public async updateMember(input: {
    identityId: string; idempotencyKey: string; memberId: string; expectedVersion: number;
    displayEnvelope?: EncryptedEnvelope; displayContentHash?: string;
    contactEnvelope?: EncryptedEnvelope | null; contactContentHash?: string;
    resolveLegacyProfile?: boolean;
    eligibilityEnvelope?: EncryptedEnvelope | null;
    eligibilityStatus?: "eligible" | "ineligible" | "review"; available?: boolean;
    departmentRestriction?: string | null; validUntil?: string | null;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicyExclusiveLock(this.client);
    return this.executeIdempotent(input.identityId, "member.update", input.idempotencyKey, input, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.displayEnvelope, input.contactEnvelope, input.eligibilityEnvelope],
      });
      if (input.departmentRestriction) await this.requireActiveDepartment(input.departmentRestriction);
      const evaluatedOn = await this.tenantCivilDate();
      const previousResult = await this.client.query<{
        eligibility_status: "eligible" | "ineligible" | "review";
        available: boolean;
        eligibility_department_id: string | null;
        eligibility_valid_until: string | null;
      }>(
        `SELECT eligibility_status,available,eligibility_department_id,
                to_char(eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until
           FROM members
          WHERE id=$1 AND version=$2 AND archived_at IS NULL
          FOR UPDATE`,
        [input.memberId, input.expectedVersion],
      );
      const previous = previousResult.rows[0];
      if (!previous) throw new DataConflictError("VERSION_CONFLICT", "Member version is stale or unavailable");
      const result = await this.client.query<{
        version: number; updated_at: Date; eligibility_status: "eligible" | "ineligible" | "review"; available: boolean;
        eligibility_department_id: string | null; eligibility_valid_until: string | null;
      }>(
        `UPDATE members SET
           display_envelope = COALESCE($3, display_envelope),
           display_content_hash = COALESCE($4, display_content_hash),
           contact_envelope = CASE WHEN $5::boolean THEN $6 ELSE contact_envelope END,
           contact_content_hash = CASE WHEN $5::boolean THEN $7 ELSE contact_content_hash END,
           profile_envelope = CASE WHEN $8::boolean THEN NULL ELSE profile_envelope END,
           profile_migration_required = CASE WHEN $8::boolean THEN false ELSE profile_migration_required END,
           eligibility_envelope = CASE WHEN $9::boolean THEN $10 ELSE eligibility_envelope END,
           eligibility_status = COALESCE($11, eligibility_status),
           available = COALESCE($12, available),
           eligibility_department_id = CASE WHEN $13::boolean THEN $14::uuid ELSE eligibility_department_id END,
           eligibility_valid_until = CASE WHEN $15::boolean THEN $16::date ELSE eligibility_valid_until END,
           version = version + 1,
           updated_at = clock_timestamp()
         WHERE id = $1 AND version = $2 AND archived_at IS NULL
           AND (NOT profile_migration_required OR $8::boolean OR ($3::jsonb IS NULL AND NOT $5::boolean))
         RETURNING version,updated_at,eligibility_status,available,eligibility_department_id,
                   to_char(eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until`,
        [
          input.memberId,
          input.expectedVersion,
          input.displayEnvelope ?? null,
          input.displayContentHash ?? null,
          Object.prototype.hasOwnProperty.call(input, "contactEnvelope"),
          input.contactEnvelope ?? null,
          input.contactContentHash ?? null,
          input.resolveLegacyProfile ?? false,
          Object.prototype.hasOwnProperty.call(input, "eligibilityEnvelope"),
          input.eligibilityEnvelope ?? null,
          input.eligibilityStatus ?? null,
          input.available ?? null,
          Object.prototype.hasOwnProperty.call(input, "departmentRestriction"),
          input.departmentRestriction ?? null,
          Object.prototype.hasOwnProperty.call(input, "validUntil"),
          input.validUntil ?? null,
        ],
      );
      const row = result.rows[0];
      if (!row) throw new DataConflictError("VERSION_CONFLICT", "Member version is stale or unavailable");
      const scopeMutation = (Object.prototype.hasOwnProperty.call(input, "departmentRestriction")
          && (input.departmentRestriction ?? null) !== previous.eligibility_department_id)
        || (Object.prototype.hasOwnProperty.call(input, "validUntil")
          && (input.validUntil ?? null) !== previous.eligibility_valid_until);
      const eligibilityMutation = (input.eligibilityStatus !== undefined
          && input.eligibilityStatus !== previous.eligibility_status)
        || (input.available !== undefined && input.available !== previous.available)
        || scopeMutation;
      const currentlyEffective = row.eligibility_status === "eligible" && row.available
        && (row.eligibility_valid_until === null || row.eligibility_valid_until >= evaluatedOn);
      const pausedWorkflows = eligibilityMutation && (scopeMutation || !currentlyEffective)
        ? await this.pauseAffectedMemberWorkflows({
            identityId: input.identityId,
            memberId: input.memberId,
            memberVersion: row.version,
            reasonCode: "MEMBER_ELIGIBILITY_CHANGED",
          })
        : [];
      await this.emit("member.changed", "member", input.memberId, { memberId: input.memberId, version: row.version });
      await this.appendAudit("member.updated", "member", input.memberId, "success", {
        fields: [
          ...(input.displayEnvelope ? ["displayEnvelope"] : []),
          ...(Object.prototype.hasOwnProperty.call(input, "contactEnvelope") ? ["contactEnvelope"] : []),
          ...(input.resolveLegacyProfile ? ["legacyProfileResolved"] : []),
          ...(Object.prototype.hasOwnProperty.call(input, "eligibilityEnvelope") ? ["eligibilityEnvelope"] : []),
          ...(input.eligibilityStatus !== undefined ? ["eligibilityStatus"] : []),
           ...(input.available !== undefined ? ["available"] : []),
          ...(Object.prototype.hasOwnProperty.call(input, "departmentRestriction") ? ["departmentRestriction"] : []),
          ...(Object.prototype.hasOwnProperty.call(input, "validUntil") ? ["validUntil"] : []),
        ],
        version: row.version,
        pausedProcessIds: pausedWorkflows.map(({ processId }) => processId),
      });
      return {
        id: input.memberId,
        version: row.version,
        updatedAt: row.updated_at,
        departmentRestriction: row.eligibility_department_id,
        validUntil: row.eligibility_valid_until,
        eligibilityEvaluatedOn: evaluatedOn,
        eligible: currentlyEffective,
        pausedWorkflows,
      };
    });
  }

  public async archiveMember(input: {
    identityId: string; idempotencyKey: string; memberId: string; expectedVersion: number; reasonCode: string;
  }): Promise<Record<string, unknown>> {
    const reasonCode = requireReasonCode(input.reasonCode, MEMBER_ARCHIVE_REASON_CODES);
    await acquireMemberEligibilityPolicyExclusiveLock(this.client);
    return this.executeIdempotent(input.identityId, "member.archive", input.idempotencyKey, { ...input, reasonCode }, async () => {
      const current = await this.client.query<{
        version: number; archived_at: Date | null; available: boolean;
      }>("SELECT version,archived_at,available FROM members WHERE id=$1 FOR UPDATE", [input.memberId]);
      const member = current.rows[0];
      if (!member) throw new DataConflictError("MEMBER_UNAVAILABLE", "Member is unavailable");
      if (member.version !== input.expectedVersion) throw new DataConflictError("VERSION_CONFLICT", "Member version is stale");
      if (member.archived_at !== null) throw new DataConflictError("MEMBER_ALREADY_ARCHIVED", "Member is already archived");

      const assignments = await this.client.query<{ total: number }>(
        "SELECT count(*)::int AS total FROM assignments WHERE member_id=$1 AND effective",
        [input.memberId],
      );
      if ((assignments.rows[0]?.total ?? 0) > 0) {
        throw new DataConflictError(
          "MEMBER_HAS_EFFECTIVE_ASSIGNMENTS",
          "Member cannot be archived while an effective assignment exists",
        );
      }

      const updated = await this.client.query<{ version: number; archived_at: Date; updated_at: Date }>(
        `UPDATE members
            SET archived_at=clock_timestamp(),available=false,version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 AND archived_at IS NULL
        RETURNING version,archived_at,updated_at`,
        [input.memberId, input.expectedVersion],
      );
      const row = updated.rows[0];
      if (!row) throw new DataConflictError("VERSION_CONFLICT", "Member version changed while archiving");
      const pausedWorkflows = await this.pauseAffectedMemberWorkflows({
        identityId: input.identityId,
        memberId: input.memberId,
        memberVersion: row.version,
        reasonCode: "MEMBER_ARCHIVED",
      });
      await this.emit("member.changed", "member", input.memberId, {
        memberId: input.memberId, version: row.version, operation: "archived", archived: true, available: false,
      });
      await this.appendAudit("member.archived", "member", input.memberId, "success", {
        reasonCode, previousAvailable: member.available, version: row.version,
        pausedProcessIds: pausedWorkflows.map(({ processId }) => processId),
      });
      return {
        id: input.memberId,
        version: row.version,
        archived: true,
        archivedAt: row.archived_at,
        available: false,
        updatedAt: row.updated_at,
        pausedWorkflows,
      };
    });
  }

  public async reactivateMember(input: {
    identityId: string; idempotencyKey: string; memberId: string; expectedVersion: number; reasonCode: string;
  }): Promise<Record<string, unknown>> {
    const reasonCode = requireReasonCode(input.reasonCode, MEMBER_REACTIVATE_REASON_CODES);
    return this.executeIdempotent(input.identityId, "member.reactivate", input.idempotencyKey, { ...input, reasonCode }, async () => {
      const current = await this.client.query<{
        version: number; archived_at: Date | null; available: boolean;
      }>("SELECT version,archived_at,available FROM members WHERE id=$1 FOR UPDATE", [input.memberId]);
      const member = current.rows[0];
      if (!member) throw new DataConflictError("MEMBER_UNAVAILABLE", "Member is unavailable");
      if (member.version !== input.expectedVersion) throw new DataConflictError("VERSION_CONFLICT", "Member version is stale");
      if (member.archived_at === null) throw new DataConflictError("MEMBER_NOT_ARCHIVED", "Member is not archived");

      const updated = await this.client.query<{ version: number; updated_at: Date }>(
        `UPDATE members
            SET archived_at=NULL,available=false,version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 AND archived_at IS NOT NULL
        RETURNING version,updated_at`,
        [input.memberId, input.expectedVersion],
      );
      const row = updated.rows[0];
      if (!row) throw new DataConflictError("VERSION_CONFLICT", "Member version changed while reactivating");
      await this.emit("member.changed", "member", input.memberId, {
        memberId: input.memberId, version: row.version, operation: "reactivated", archived: false, available: false,
      });
      await this.appendAudit("member.reactivated", "member", input.memberId, "success", {
        reasonCode, previousAvailable: member.available, version: row.version,
      });
      return {
        id: input.memberId,
        version: row.version,
        archived: false,
        archivedAt: null,
        available: false,
        updatedAt: row.updated_at,
      };
    });
  }

  public async getCatalog(includeInactive = false): Promise<Record<string, unknown>> {
    const activePredicate = includeInactive ? "" : "WHERE active";
    const [departments, offices, settings] = await Promise.all([
      this.client.query<{
        id: string; canonical_code: string; names: Record<string, string>; parent_id: string | null;
        local_extension: boolean; active: boolean; sort_order: number; version: number; catalog_metadata: Record<string, unknown>;
      }>(`SELECT id, canonical_code, names, parent_id, local_extension, active, sort_order, version, catalog_metadata FROM departments ${activePredicate} ORDER BY sort_order, canonical_code`),
      this.client.query<{
        id: string; department_id: string; canonical_code: string; names: Record<string, string>;
        appointment_mechanism: string; cardinality: number; local_extension: boolean;
        active: boolean; version: number; catalog_metadata: Record<string, unknown>;
      }>(`SELECT id, department_id, canonical_code, names, appointment_mechanism, cardinality, local_extension, active, version, catalog_metadata FROM offices ${activePredicate} ORDER BY canonical_code`),
      this.client.query<{ catalog_version: string; locale: "es" | "en" | "fr" }>("SELECT catalog_version,locale FROM tenant_settings WHERE singleton = true"),
    ]);
    return {
      normativeVersion: settings.rows[0]?.catalog_version ?? "unknown",
      departments: departments.rows.map((row) => ({
        ...row.catalog_metadata,
        id: row.id,
        canonicalCode: row.canonical_code,
        name: row.names[settings.rows[0]?.locale ?? "es"] ?? row.names["es"] ?? row.canonical_code,
        names: row.names,
        parentId: row.parent_id,
        localExtension: row.local_extension,
        active: row.active,
        sortOrder: row.sort_order,
        version: row.version,
      })),
      offices: offices.rows.map((row) => ({
        ...row.catalog_metadata,
        id: row.id,
        departmentId: row.department_id,
        canonicalCode: row.canonical_code,
        name: row.names[settings.rows[0]?.locale ?? "es"] ?? row.names["es"] ?? row.canonical_code,
        names: row.names,
        appointmentMechanism: row.appointment_mechanism,
        cardinality: row.cardinality,
        localExtension: row.local_extension,
        active: row.active,
        version: row.version,
      })),
    };
  }

  public async getTenantSettings(): Promise<Record<string, unknown>> {
    const result = await this.client.query<{
      tenant_id: string; display_name: string; kind: "demo" | "real"; timezone: string;
      locale: "es" | "en" | "fr"; jurisdiction: string; setup_state: string;
      catalog_version: string; version: number; created_at: Date; updated_at: Date;
    }>(
      `SELECT tenant_id,display_name,kind,timezone,locale,jurisdiction,setup_state,
              catalog_version,version,created_at,updated_at
         FROM tenant_settings WHERE singleton=true`,
    );
    const row = result.rows[0];
    if (!row) throw new DataConflictError("TENANT_SETTINGS_UNAVAILABLE", "Tenant settings are unavailable");
    return {
      tenantId: row.tenant_id,
      displayName: row.display_name,
      kind: row.kind,
      timezone: row.timezone,
      locale: row.locale,
      jurisdiction: row.jurisdiction,
      setupState: row.setup_state,
      catalogVersion: row.catalog_version,
      version: row.version,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  public async updateTenantSettings(input: {
    identityId: string; idempotencyKey: string; expectedVersion: number;
    displayName?: string; timezone?: string; locale?: "es" | "en" | "fr"; jurisdiction?: string;
  }): Promise<Record<string, unknown>> {
    if (input.timezone !== undefined && !isValidIanaTimezone(input.timezone)) {
      throw new DataConflictError("INVALID_TIMEZONE", "Timezone must be a recognized IANA identifier");
    }
    if (input.timezone !== undefined) await acquireMemberEligibilityPolicyExclusiveLock(this.client);
    return this.executeIdempotent(input.identityId, "tenant.settings.update", input.idempotencyKey, input, async () => {
      const current = await this.client.query<{ timezone: string; version: number }>(
        "SELECT timezone,version FROM tenant_settings WHERE singleton=true FOR UPDATE",
      );
      const previous = current.rows[0];
      if (!previous || previous.version !== input.expectedVersion) {
        throw new DataConflictError("VERSION_CONFLICT", "Tenant settings version is stale");
      }
      if (input.timezone !== undefined && input.timezone !== previous.timezone) {
        await this.assertTenantTimezoneMutationSafe();
      }
      const result = await this.client.query<{
        tenant_id: string; display_name: string; kind: "demo" | "real"; timezone: string;
        locale: "es" | "en" | "fr"; jurisdiction: string; setup_state: string;
        catalog_version: string; version: number; created_at: Date; updated_at: Date;
      }>(
        `UPDATE tenant_settings SET
           display_name=COALESCE($2,display_name),
           timezone=COALESCE($3,timezone),
           locale=COALESCE($4,locale),
           jurisdiction=COALESCE($5,jurisdiction),
           version=version+1,updated_at=clock_timestamp()
         WHERE singleton=true AND version=$1
         RETURNING tenant_id,display_name,kind,timezone,locale,jurisdiction,setup_state,
                   catalog_version,version,created_at,updated_at`,
        [input.expectedVersion, input.displayName ?? null, input.timezone ?? null, input.locale ?? null, input.jurisdiction ?? null],
      );
      const row = result.rows[0];
      if (!row) throw new DataConflictError("VERSION_CONFLICT", "Tenant settings version is stale");
      const changedFields = [
        ...(input.displayName !== undefined ? ["displayName"] : []),
        ...(input.timezone !== undefined ? ["timezone"] : []),
        ...(input.locale !== undefined ? ["locale"] : []),
        ...(input.jurisdiction !== undefined ? ["jurisdiction"] : []),
      ];
      await this.emit("tenant.settings.updated", "tenant", row.tenant_id, { tenantId: row.tenant_id, version: row.version, changedFields });
      await this.appendAudit("tenant.settings.updated", "tenant", row.tenant_id, "success", { version: row.version, changedFields });
      return {
        tenantId: row.tenant_id, displayName: row.display_name, kind: row.kind, timezone: row.timezone,
        locale: row.locale, jurisdiction: row.jurisdiction, setupState: row.setup_state,
        catalogVersion: row.catalog_version, version: row.version, createdAt: row.created_at, updatedAt: row.updated_at,
      };
    });
  }

  public async createLocalDepartment(input: {
    identityId: string; idempotencyKey: string; canonicalCode: string;
    names: Readonly<Record<"es" | "en" | "fr", string>>; parentId?: string;
    sortOrder: number; metadata: Readonly<Record<string, unknown>>;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "catalog.department.create", input.idempotencyKey, input, async () => {
      if (input.parentId) await this.requireActiveDepartment(input.parentId);
      const id = randomUUID();
      const result = await this.client.query<{ version: number; updated_at: Date }>(
        `INSERT INTO departments(id,canonical_code,names,parent_id,local_extension,catalog_metadata,active,sort_order,version,updated_at)
         VALUES ($1,$2,$3,$4,true,$5,true,$6,1,clock_timestamp()) RETURNING version,updated_at`,
        [id, input.canonicalCode, input.names, input.parentId ?? null, input.metadata, input.sortOrder],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw new DataConflictError("CATALOG_CODE_EXISTS", "Catalog code already exists");
        throw error;
      });
      const row = result.rows[0];
      if (!row) throw new Error("Local department creation did not return a row");
      await this.emit("catalog.department.created", "department", id, { departmentId: id, version: row.version });
      await this.appendAudit("catalog.department.created", "department", id, "success", { canonicalCode: input.canonicalCode, version: row.version });
      return { id, canonicalCode: input.canonicalCode, names: input.names, parentId: input.parentId ?? null, localExtension: true, active: true, sortOrder: input.sortOrder, metadata: input.metadata, version: row.version, updatedAt: row.updated_at };
    });
  }

  public async updateLocalDepartment(input: {
    identityId: string; idempotencyKey: string; departmentId: string; expectedVersion: number;
    names?: Readonly<Record<"es" | "en" | "fr", string>>; parentId?: string | null;
    sortOrder?: number; active?: boolean; metadata?: Readonly<Record<string, unknown>>;
  }): Promise<Record<string, unknown>> {
    if (input.active !== undefined) await acquireMemberEligibilityPolicyExclusiveLock(this.client);
    return this.executeIdempotent(input.identityId, "catalog.department.update", input.idempotencyKey, input, async () => {
      if (input.parentId === input.departmentId) throw new DataConflictError("CATALOG_PARENT_INVALID", "A department cannot be its own parent");
      if (input.parentId) await this.requireActiveDepartment(input.parentId);
      const current = await this.client.query<{ active: boolean; version: number; local_extension: boolean }>(
        "SELECT active,version,local_extension FROM departments WHERE id=$1 FOR UPDATE",
        [input.departmentId],
      );
      const previous = current.rows[0];
      if (!previous || previous.version !== input.expectedVersion || !previous.local_extension) {
        await this.throwCatalogMutationConflict("departments", input.departmentId, input.expectedVersion);
      }
      const lockedDepartment = previous!;
      if (input.active === false && lockedDepartment.active) {
        await this.assertDepartmentDeactivationSafe(input.departmentId);
      }
      const result = await this.client.query<{
        canonical_code: string; names: Record<"es" | "en" | "fr", string>; parent_id: string | null;
        sort_order: number; active: boolean; catalog_metadata: Record<string, unknown>; version: number; updated_at: Date;
      }>(
        `UPDATE departments SET
           names=COALESCE($3,names),
           parent_id=CASE WHEN $4::boolean THEN $5 ELSE parent_id END,
           sort_order=COALESCE($6,sort_order),active=COALESCE($7,active),
           catalog_metadata=COALESCE($8,catalog_metadata),version=version+1,updated_at=clock_timestamp()
         WHERE id=$1 AND version=$2 AND local_extension
         RETURNING canonical_code,names,parent_id,sort_order,active,catalog_metadata,version,updated_at`,
        [input.departmentId, input.expectedVersion, input.names ?? null,
          Object.prototype.hasOwnProperty.call(input, "parentId"), input.parentId ?? null,
          input.sortOrder ?? null, input.active ?? null, input.metadata ?? null],
      );
      const row = result.rows[0];
      if (!row) await this.throwCatalogMutationConflict("departments", input.departmentId, input.expectedVersion);
      const updated = result.rows[0]!;
      await this.emit("catalog.department.updated", "department", input.departmentId, { departmentId: input.departmentId, version: updated.version });
      await this.appendAudit("catalog.department.updated", "department", input.departmentId, "success", { version: updated.version, active: updated.active });
      return { id: input.departmentId, canonicalCode: updated.canonical_code, names: updated.names, parentId: updated.parent_id, localExtension: true, active: updated.active, sortOrder: updated.sort_order, metadata: updated.catalog_metadata, version: updated.version, updatedAt: updated.updated_at };
    });
  }

  public async createLocalOffice(input: {
    identityId: string; idempotencyKey: string; departmentId: string; canonicalCode: string;
    names: Readonly<Record<"es" | "en" | "fr", string>>; appointmentMechanism: string;
    cardinality: number; metadata: Readonly<Record<string, unknown>>;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicySharedLock(this.client);
    return this.executeIdempotent(input.identityId, "catalog.office.create", input.idempotencyKey, input, async () => {
      await this.requireActiveDepartment(input.departmentId);
      const id = randomUUID();
      const result = await this.client.query<{ version: number; updated_at: Date }>(
        `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality,local_extension,catalog_metadata,active,version,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,true,$7,true,1,clock_timestamp()) RETURNING version,updated_at`,
        [id, input.departmentId, input.canonicalCode, input.names, input.appointmentMechanism, input.cardinality, input.metadata],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw new DataConflictError("CATALOG_CODE_EXISTS", "Catalog code already exists");
        throw error;
      });
      const row = result.rows[0];
      if (!row) throw new Error("Local office creation did not return a row");
      await this.emit("catalog.office.created", "office", id, { officeId: id, version: row.version });
      await this.appendAudit("catalog.office.created", "office", id, "success", { canonicalCode: input.canonicalCode, departmentId: input.departmentId, version: row.version });
      return { id, departmentId: input.departmentId, canonicalCode: input.canonicalCode, names: input.names, appointmentMechanism: input.appointmentMechanism, cardinality: input.cardinality, localExtension: true, active: true, metadata: input.metadata, version: row.version, updatedAt: row.updated_at };
    });
  }

  public async updateLocalOffice(input: {
    identityId: string; idempotencyKey: string; officeId: string; expectedVersion: number;
    departmentId?: string; names?: Readonly<Record<"es" | "en" | "fr", string>>;
    appointmentMechanism?: string; cardinality?: number; active?: boolean;
    metadata?: Readonly<Record<string, unknown>>;
  }): Promise<Record<string, unknown>> {
    if (input.departmentId !== undefined || input.active !== undefined) {
      await acquireMemberEligibilityPolicyExclusiveLock(this.client);
    }
    return this.executeIdempotent(input.identityId, "catalog.office.update", input.idempotencyKey, input, async () => {
      if (input.departmentId) await this.requireActiveDepartment(input.departmentId);
      const current = await this.client.query<{
        department_id: string; active: boolean; version: number; local_extension: boolean;
      }>(
        "SELECT department_id,active,version,local_extension FROM offices WHERE id=$1 FOR UPDATE",
        [input.officeId],
      );
      const previous = current.rows[0];
      if (!previous || previous.version !== input.expectedVersion || !previous.local_extension) {
        await this.throwCatalogMutationConflict("offices", input.officeId, input.expectedVersion);
      }
      const lockedOffice = previous!;
      const eligibilityStructureChanged = (input.departmentId !== undefined && input.departmentId !== lockedOffice.department_id)
        || (input.active === false && lockedOffice.active);
      if (eligibilityStructureChanged) await this.assertOfficeEligibilityMutationSafe(input.officeId);
      const result = await this.client.query<{
        department_id: string; canonical_code: string; names: Record<"es" | "en" | "fr", string>;
        appointment_mechanism: string; cardinality: number; active: boolean;
        catalog_metadata: Record<string, unknown>; version: number; updated_at: Date;
      }>(
        `UPDATE offices SET department_id=COALESCE($3,department_id),names=COALESCE($4,names),
           appointment_mechanism=COALESCE($5,appointment_mechanism),cardinality=COALESCE($6,cardinality),
           active=COALESCE($7,active),catalog_metadata=COALESCE($8,catalog_metadata),
           version=version+1,updated_at=clock_timestamp()
         WHERE id=$1 AND version=$2 AND local_extension
         RETURNING department_id,canonical_code,names,appointment_mechanism,cardinality,active,catalog_metadata,version,updated_at`,
        [input.officeId, input.expectedVersion, input.departmentId ?? null, input.names ?? null,
          input.appointmentMechanism ?? null, input.cardinality ?? null, input.active ?? null, input.metadata ?? null],
      );
      const row = result.rows[0];
      if (!row) await this.throwCatalogMutationConflict("offices", input.officeId, input.expectedVersion);
      const updated = result.rows[0]!;
      await this.emit("catalog.office.updated", "office", input.officeId, { officeId: input.officeId, version: updated.version });
      await this.appendAudit("catalog.office.updated", "office", input.officeId, "success", { version: updated.version, active: updated.active, departmentId: updated.department_id });
      return { id: input.officeId, departmentId: updated.department_id, canonicalCode: updated.canonical_code, names: updated.names, appointmentMechanism: updated.appointment_mechanism, cardinality: updated.cardinality, localExtension: true, active: updated.active, metadata: updated.catalog_metadata, version: updated.version, updatedAt: updated.updated_at };
    });
  }

  public async getActiveRound(includeCandidates = true, viewerIdentityId?: string): Promise<Record<string, unknown> | null> {
    const result = await this.client.query<{
      id: string; cycle_id: string; office_id: string; process_id: string | null; office_code: string;
      office_name: string; office_names: Record<string, string>;
      phase: string; version: number; vacancies: number; max_selections: number;
      submission_kind: "proposal" | "vote"; candidate_set_hash: string; rules_hash: string; opened_at: Date | null;
      required: number; received: number; viewer_can_submit: boolean;
    }>(`
      SELECT r.id, r.cycle_id, r.office_id, r.process_id, o.canonical_code AS office_code,
             COALESCE(o.names->>ts.locale,o.names->>'es',o.canonical_code) AS office_name,
             o.names AS office_names,
             r.phase, r.version, r.vacancies, r.max_selections, r.submission_kind,
             r.candidate_set_hash, r.rules_hash, r.opened_at,
             (SELECT count(*)::int FROM round_elector_snapshots e WHERE e.round_id=r.id AND e.can_submit AND NOT e.recused) AS required,
             (SELECT count(*)::int FROM participation_receipts p
               WHERE p.round_id=r.id AND p.kind=r.submission_kind) AS received,
             CASE WHEN $1::uuid IS NULL THEN false ELSE EXISTS (
               SELECT 1 FROM round_elector_snapshots viewer
                WHERE viewer.round_id=r.id AND viewer.identity_id=$1::uuid
                  AND viewer.can_submit AND NOT viewer.recused
             ) END AS viewer_can_submit
        FROM rounds r
        JOIN offices o ON o.id=r.office_id
        JOIN tenant_settings ts ON ts.singleton=true
       WHERE r.phase IN (
         'PROPUESTAS_ABIERTAS','PROPUESTAS_CERRADAS','DEPURACION','LISTA_CONFIRMADA',
         'VOTACION_ABIERTA','VOTACION_CERRADA','ESCRUTINIO','RESULTADO_INTERNO',
         'RECOMENDACION_CONFIRMADA','PAUSADO'
       )
       ORDER BY r.created_at DESC LIMIT 1
    `, [viewerIdentityId ?? null]);
    const row = result.rows[0];
    if (!row) return null;
    const candidates = includeCandidates
      ? await this.client.query<{
          candidate_id: string; member_id: string; display_envelope: EncryptedEnvelope;
          eligible: boolean; eligibility_effective: boolean; already_assigned_count: number; stable_code: string;
        }>(
          `SELECT candidate.candidate_id,candidate.member_id,candidate.display_envelope,
                  candidate.eligible,
                  (candidate.eligibility_effective
                    AND (candidate.eligibility_valid_until_snapshot IS NULL
                      OR candidate.eligibility_valid_until_snapshot >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
                    AND (candidate.eligibility_department_id_snapshot IS NULL
                      OR (candidate.eligibility_department_id_snapshot=office.department_id AND EXISTS (
                        SELECT 1 FROM departments frozen_department
                         WHERE frozen_department.id=candidate.eligibility_department_id_snapshot AND frozen_department.active
                      )))
                    AND member.archived_at IS NULL AND member.eligibility_status='eligible' AND member.available
                    AND (member.eligibility_valid_until IS NULL
                      OR member.eligibility_valid_until >= (clock_timestamp() AT TIME ZONE settings.timezone)::date)
                    AND (member.eligibility_department_id IS NULL
                      OR (member.eligibility_department_id=office.department_id AND EXISTS (
                        SELECT 1 FROM departments current_department
                         WHERE current_department.id=member.eligibility_department_id AND current_department.active
                      )))
                  ) AS eligibility_effective,
                  candidate.already_assigned_count,member.stable_code
             FROM candidate_snapshots candidate
             JOIN members member ON member.id=candidate.member_id
             JOIN rounds round_state ON round_state.id=candidate.round_id
             JOIN offices office ON office.id=round_state.office_id
             CROSS JOIN tenant_settings settings
             WHERE settings.singleton=true AND candidate.round_id=$1 ORDER BY candidate.visible_order`,
          [row.id],
        )
      : { rows: [] };
    return {
      round: {
        id: row.id,
        cycleId: row.cycle_id,
        officeProcessId: row.process_id ?? row.office_id,
        officeCode: row.office_code,
        officeName: row.office_name,
        officeNames: row.office_names,
        phase: row.phase,
        version: row.version,
        vacancies: row.vacancies,
        maxSelections: row.max_selections,
        submissionKind: row.submission_kind,
        candidateSetHash: row.candidate_set_hash,
        rulesHash: row.rules_hash,
        openedAt: row.opened_at,
      },
      participation: {
        required: row.required,
        received: row.received,
        pending: Math.max(0, row.required - row.received),
      },
      viewerCanSubmit: row.viewer_can_submit && candidates.rows.every((candidate) => candidate.eligibility_effective),
      candidates: candidates.rows.map((candidate) => ({
        id: candidate.candidate_id,
        memberId: candidate.member_id,
        shortId: candidate.stable_code,
        displayEnvelope: candidate.display_envelope,
        eligible: candidate.eligible && candidate.eligibility_effective,
        alreadyAssignedCount: candidate.already_assigned_count,
      })),
    };
  }

  public async submit(input: SubmissionInput): Promise<SubmissionReceipt> {
    return this.executeIdempotent(input.identityId, `round.${input.kind}.submit`, input.idempotencyKey, input, async () => {
      const roundResult = await this.client.query<{
        version: number; phase: string; submission_kind: "proposal" | "vote";
        cycle_id: string; office_id: string; candidate_set_hash: string; rules_hash: string; appointment_mechanism: string;
      }>(
        `WITH eligibility_policy_lock AS MATERIALIZED (
           SELECT pg_advisory_xact_lock_shared(1853121029,30)
         )
         SELECT round_state.version,round_state.phase,round_state.submission_kind,round_state.cycle_id,round_state.office_id,
                round_state.candidate_set_hash,round_state.rules_hash,office.appointment_mechanism
           FROM rounds round_state
           JOIN offices office ON office.id=round_state.office_id
          CROSS JOIN eligibility_policy_lock
          WHERE round_state.id=$1 FOR UPDATE OF round_state`,
        [input.roundId],
      );
      const round = roundResult.rows[0];
      if (!round) throw new DataConflictError("ROUND_UNAVAILABLE", "Round is unavailable");
      assertOrdinaryRoundMechanism(round.appointment_mechanism);
      if (round.version !== input.expectedVersion) throw new DataConflictError("VERSION_CONFLICT", "Round version is stale");
      if (round.submission_kind !== input.kind) throw new DataConflictError("SUBMISSION_KIND_MISMATCH", "Submission kind does not match round");
      const expectedPhase = input.kind === "proposal" ? "PROPUESTAS_ABIERTAS" : "VOTACION_ABIERTA";
      if (round.phase !== expectedPhase) throw new DataConflictError("ROUND_CLOSED", "Round is not accepting submissions");
      await this.assertRoundCandidatesCurrentlyEligible(input.roundId, round.office_id);
      const settings = await this.client.query<{ tenant_id: string }>(
        "SELECT tenant_id FROM tenant_settings WHERE singleton=true",
      );
      const tenantId = settings.rows[0]?.tenant_id;
      if (!tenantId) throw new Error("Tenant settings are missing");
      validateSubmissionEnvelope(input, {
        tenantId,
        cycleId: round.cycle_id,
        candidateSetHash: round.candidate_set_hash,
        rulesHash: round.rules_hash,
      });
      const elector = await this.client.query(
        `SELECT 1 FROM round_elector_snapshots
          WHERE round_id=$1 AND identity_id=$2 AND can_submit AND NOT recused`,
        [input.roundId, input.identityId],
      );
      if (elector.rowCount !== 1) throw new DataConflictError("NOT_AN_ELECTOR", "Identity is not in the frozen electorate");
      const submission = await this.client.query<{ id: string; received_at: Date }>(
        `INSERT INTO encrypted_submissions(
           round_id, elector_identity_id, kind, envelope, content_hash, round_version
         ) VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING id, received_at`,
        [input.roundId, input.identityId, input.kind, input.envelope, input.contentHash, round.version],
      ).catch((error: unknown) => {
        if (isUniqueViolation(error)) throw new DataConflictError("ALREADY_SUBMITTED", "A final response already exists");
        throw error;
      });
      const row = submission.rows[0];
      if (!row) throw new Error("Submission insertion did not return a row");
      const receipt = await this.client.query<{ id: string }>(
        `INSERT INTO participation_receipts(
           submission_id, round_id, elector_identity_id, kind, content_hash, received_at
         ) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
        [row.id, input.roundId, input.identityId, input.kind, input.contentHash, row.received_at],
      );
      const receiptId = receipt.rows[0]?.id;
      if (!receiptId) throw new Error("Receipt insertion did not return a row");
      await this.emit("round.participation", "round", input.roundId, { roundId: input.roundId });
      await this.appendAudit("round.submission.received", "round", input.roundId, "success", {
        kind: input.kind,
        receiptId,
      });
      return {
        receiptId,
        receivedAt: row.received_at,
        roundId: input.roundId,
        roundVersion: round.version,
        contentHash: input.contentHash,
        status: "received" as const,
      };
    });
  }

  public async getOwnSubmissionReceipt(
    roundId: string,
    identityId: string,
  ): Promise<SubmissionReceipt | null> {
    const result = await this.client.query<{
      receipt_id: string; received_at: Date; round_id: string;
      round_version: number; content_hash: string;
    }>(
      `SELECT receipt.id AS receipt_id,receipt.received_at,receipt.round_id,
              submission.round_version,receipt.content_hash
         FROM round_elector_snapshots elector
         JOIN rounds round_state ON round_state.id=elector.round_id
         JOIN participation_receipts receipt
           ON receipt.round_id=elector.round_id
          AND receipt.elector_identity_id=elector.identity_id
          AND receipt.kind=round_state.submission_kind
         JOIN encrypted_submissions submission ON submission.id=receipt.submission_id
        WHERE elector.round_id=$1 AND elector.identity_id=$2
        ORDER BY receipt.received_at DESC,receipt.id DESC LIMIT 1`,
      [roundId, identityId],
    );
    const row = result.rows[0];
    return row
      ? {
          receiptId: row.receipt_id,
          receivedAt: row.received_at,
          roundId: row.round_id,
          roundVersion: row.round_version,
          contentHash: row.content_hash,
          status: "received",
        }
      : null;
  }

  public async getRoundSubmissionKind(roundId: string): Promise<"proposal" | "vote" | null> {
    const result = await this.client.query<{ submission_kind: "proposal" | "vote" }>(
      "SELECT submission_kind FROM rounds WHERE id=$1",
      [roundId],
    );
    return result.rows[0]?.submission_kind ?? null;
  }

  public async closeRound(input: {
    identityId: string; idempotencyKey: string; roundId: string;
    expectedVersion: number; reasonCode: string;
  }): Promise<Record<string, unknown>> {
    const reasonCode = requireReasonCode(input.reasonCode, ROUND_CLOSE_REASON_CODES);
    return this.executeIdempotent(input.identityId, "round.close", input.idempotencyKey, { ...input, reasonCode }, async () => {
      const result = await this.client.query<{ phase: string; version: number; appointment_mechanism: string }>(
        `SELECT round_state.phase,round_state.version,office.appointment_mechanism
           FROM rounds round_state
           JOIN offices office ON office.id=round_state.office_id
          WHERE round_state.id=$1 FOR UPDATE OF round_state`,
        [input.roundId],
      );
      const round = result.rows[0];
      if (!round) throw new DataConflictError("ROUND_UNAVAILABLE", "Round is unavailable");
      assertOrdinaryRoundMechanism(round.appointment_mechanism);
      if (round.version !== input.expectedVersion) throw new DataConflictError("VERSION_CONFLICT", "Round version is stale");
      const nextPhase = round.phase === "PROPUESTAS_ABIERTAS"
        ? "PROPUESTAS_CERRADAS"
        : round.phase === "VOTACION_ABIERTA"
          ? "VOTACION_CERRADA"
          : null;
      if (!nextPhase) throw new DataConflictError("PHASE_CONFLICT", "Round cannot close from its current phase");
      const counts = await this.client.query<{ required: number; received: number }>(
        `SELECT
           (SELECT count(*)::int FROM round_elector_snapshots WHERE round_id=$1 AND can_submit AND NOT recused) AS required,
           (SELECT count(*)::int FROM participation_receipts
             WHERE round_id=$1 AND kind=(SELECT submission_kind FROM rounds WHERE id=$1)) AS received`,
        [input.roundId],
      );
      const count = counts.rows[0];
      if (!count || count.received !== count.required) {
        throw new DataConflictError("PARTICIPATION_INCOMPLETE", "Frozen electorate has pending responses");
      }
      const closed = await this.client.query<{ version: number; closed_at: Date }>(
        `UPDATE rounds SET phase=$2, version=version+1, closed_at=clock_timestamp()
          WHERE id=$1 RETURNING version, closed_at`,
        [input.roundId, nextPhase],
      );
      const updated = closed.rows[0];
      if (!updated) throw new Error("Round close did not return a row");
      await this.emit("round.phase", "round", input.roundId, { roundId: input.roundId, phase: nextPhase, version: updated.version });
      await this.emit("round.closed", "round", input.roundId, {
        roundId: input.roundId,
        previousPhase: round.phase,
        newPhase: nextPhase,
        version: updated.version,
        closedAt: updated.closed_at,
      });
      await this.appendAudit("round.closed", "round", input.roundId, "success", { previousPhase: round.phase, nextPhase, reasonCode });
      return {
        roundId: input.roundId,
        previousPhase: round.phase,
        newPhase: nextPhase,
        version: updated.version,
        closedAt: updated.closed_at,
        manifestPending: true,
      };
    });
  }

  public async previewImport(input: {
    identityId: string; idempotencyKey: string; sourceFingerprint: string;
    sourceFileName?: string | undefined; sourceSheetName: string;
    columnMapping: Readonly<Record<string, number | undefined>>;
    rows: readonly MemberImportRow[];
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "member.import.preview", input.idempotencyKey, input, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: input.rows.flatMap(({ displayEnvelope, contactEnvelope }) => [displayEnvelope, contactEnvelope]),
      });
      const targetIds = input.rows
        .filter(({ decision }) => decision.action !== "skip")
        .map(({ id }) => id);
      const stableCodes = input.rows
        .filter(({ decision, shortId }) => decision.action !== "skip" && shortId !== undefined)
        .map(({ shortId }) => normalizeStableCode(shortId!));
      const existing = await this.client.query<{
        id: string; stable_code: string; version: number; profile_migration_required: boolean;
      }>(
        `SELECT id,stable_code,version,profile_migration_required FROM members
          WHERE id=ANY($1::uuid[]) OR lower(stable_code)=ANY($2::text[])`,
        [targetIds, stableCodes],
      );
      const plan = evaluateMemberImportPlan(input.rows, existing.rows.map((row) => ({
        id: row.id,
        stableCode: row.stable_code,
        version: row.version,
        profileMigrationRequired: row.profile_migration_required,
      })));
      const errors = plan.rows.filter(({ status }) => status === "error");
      const result = await this.client.query<{
        id: string; created_at: Date; state: string; summary: Record<string, unknown> | null; revision: number;
      }>(
        `INSERT INTO member_import_jobs(
           identity_id,source_fingerprint,source_file_name,source_sheet_name,column_mapping,
           state,row_count,preview_envelopes,error_report
         ) VALUES ($1,$2,$3,$4,$5,'previewed',$6,$7,$8)
         ON CONFLICT(identity_id,source_fingerprint,source_sheet_name) DO UPDATE
           SET source_file_name=EXCLUDED.source_file_name,
               column_mapping=EXCLUDED.column_mapping,
               state='previewed',row_count=EXCLUDED.row_count,
               preview_envelopes=EXCLUDED.preview_envelopes,
               error_report=EXCLUDED.error_report,summary=NULL,completed_at=NULL,
               revision=member_import_jobs.revision+1
           WHERE member_import_jobs.state IN ('previewed','failed')
         RETURNING id,created_at,state,summary,revision`,
        [
          input.identityId,
          input.sourceFingerprint,
          input.sourceFileName ?? null,
          input.sourceSheetName,
          JSON.stringify(input.columnMapping),
          input.rows.length,
          JSON.stringify(input.rows),
          JSON.stringify(errors),
        ],
      );
      let job = result.rows[0];
      if (!job) {
        const completed = await this.client.query<{
          id: string; created_at: Date; state: string; summary: Record<string, unknown> | null; revision: number;
        }>(
          `SELECT id,created_at,state,summary,revision FROM member_import_jobs
            WHERE identity_id=$1 AND source_fingerprint=$2 AND source_sheet_name=$3
            FOR UPDATE`,
          [input.identityId, input.sourceFingerprint, input.sourceSheetName],
        );
        job = completed.rows[0];
      }
      if (!job) throw new Error("Import preview did not return a row");
      if (job.state === "completed") {
        return {
          importId: job.id,
          rowCount: input.rows.length,
          state: "completed",
          createdAt: job.created_at,
          revision: job.revision,
          summary: job.summary,
          rows: [],
        };
      }
      return {
        importId: job.id,
        rowCount: input.rows.length,
        state: "previewed",
        createdAt: job.created_at,
        revision: job.revision,
        counts: plan.counts,
        rows: plan.rows,
      };
    });
  }

  public async listMemberImports(limit: number): Promise<readonly Record<string, unknown>[]> {
    const result = await this.client.query<{
      id: string;
      source_file_name: string | null;
      source_sheet_name: string;
      state: string;
      row_count: number;
      summary: Record<string, unknown> | null;
      error_report: unknown;
      revision: number;
      created_at: Date;
      completed_at: Date | null;
    }>(
      `SELECT id,source_file_name,source_sheet_name,state,row_count,summary,error_report,revision,created_at,completed_at
         FROM member_import_jobs
        ORDER BY created_at DESC,id DESC
        LIMIT $1`,
      [limit],
    );
    return result.rows.map((row) => {
      const rawErrors = Array.isArray(row.error_report) ? row.error_report : [];
      const errors = rawErrors.slice(0, 100).flatMap((value) => {
        if (!value || typeof value !== "object" || Array.isArray(value)) return [];
        const candidate = value as Record<string, unknown>;
        const sourceRow = candidate["sourceRow"];
        const action = candidate["action"];
        const codes = candidate["codes"];
        if (!Number.isSafeInteger(sourceRow) || typeof action !== "string" || !Array.isArray(codes)) return [];
        return [{
          sourceRow,
          action,
          codes: codes.filter((code): code is string => typeof code === "string").slice(0, 16),
        }];
      });
      return {
        id: row.id,
        sourceFileName: row.source_file_name,
        sourceSheetName: row.source_sheet_name,
        state: row.state,
        rowCount: row.row_count,
        summary: row.summary,
        errorCount: rawErrors.length,
        errors,
        errorsTruncated: rawErrors.length > errors.length,
        revision: row.revision,
        createdAt: row.created_at,
        completedAt: row.completed_at,
      };
    });
  }

  /**
   * Returns only the authorization fact required by the commit route. The
   * encrypted contact payload itself never leaves the store through this
   * check. FOR UPDATE makes the subsequent commit in the same transaction
   * immune to a preview replacement race.
   */
  public async memberImportRequiresContact(importId: string, identityId: string): Promise<boolean> {
    const result = await this.client.query<{ requires_contact: boolean }>(
      `SELECT (
          column_mapping ? 'email'
          OR EXISTS (
            SELECT 1
              FROM jsonb_array_elements(preview_envelopes) AS preview(row_data)
             WHERE preview.row_data->'decision'->>'action' <> 'skip'
               AND preview.row_data ? 'contactEnvelope'
          )
        ) AS requires_contact
         FROM member_import_jobs
        WHERE id=$1 AND identity_id=$2
        FOR UPDATE`,
      [importId, identityId],
    );
    return result.rows[0]?.requires_contact === true;
  }

  public async commitImport(input: {
    identityId: string; idempotencyKey: string; importId: string; expectedRevision: number;
  }): Promise<Record<string, unknown>> {
    await acquireMemberEligibilityPolicyExclusiveLock(this.client);
    return this.executeIdempotent(input.identityId, "member.import.commit", input.idempotencyKey, input, async () => {
      const jobResult = await this.client.query<{
        preview_envelopes: MemberImportRow[]; state: string;
        summary: Record<string, unknown> | null; error_report: readonly unknown[]; revision: number;
      }>(
        `SELECT preview_envelopes,state,summary,error_report,revision
           FROM member_import_jobs WHERE id=$1 AND identity_id=$2 FOR UPDATE`,
        [input.importId, input.identityId],
      );
      const job = jobResult.rows[0];
      if (!job) throw new DataConflictError("IMPORT_UNAVAILABLE", "Import preview is unavailable");
      if (job.state === "completed") {
        if (!job.summary) throw new DataConflictError("IMPORT_STATE_INVALID", "Completed import has no summary");
        return { importId: input.importId, state: "completed", ...job.summary, replayed: true };
      }
      if (job.state !== "previewed") throw new DataConflictError("IMPORT_UNAVAILABLE", "Import is not ready to commit");
      if (job.revision !== input.expectedRevision) {
        throw new DataConflictError("IMPORT_PREVIEW_STALE", "Import preview changed; review the latest revision before committing");
      }
      if (job.error_report.length > 0) {
        throw new DataConflictError("IMPORT_PREVIEW_HAS_ERRORS", "Resolve import preview errors before committing");
      }
      const actionableRows = job.preview_envelopes.filter(({ decision }) => decision.action !== "skip");
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: actionableRows.flatMap(({ displayEnvelope, contactEnvelope }) => [displayEnvelope, contactEnvelope]),
      });
      const claimed = await this.client.query(
        "UPDATE member_import_jobs SET state='committing' WHERE id=$1 AND revision=$2 AND state='previewed'",
        [input.importId, input.expectedRevision],
      );
      if (claimed.rowCount !== 1) throw new DataConflictError("IMPORT_PREVIEW_STALE", "Import preview is no longer current");
      let created = 0;
      let updated = 0;
      let skipped = 0;
      const pausedProcessIds = new Set<string>();
      for (const [index, item] of job.preview_envelopes.entries()) {
        if (item.decision.action === "skip") {
          skipped += 1;
          continue;
        }
        const memberId = String(item.id ?? "");
        const stableCode = item.shortId ?? `IMP-${input.importId.slice(0, 8)}-${String(item.sourceRow || index + 1).padStart(5, "0")}`;
        const displayEnvelope = item.displayEnvelope;
        const displayContentHash = item.displayContentHash;
        const contactEnvelope = item.contactEnvelope;
        const contactContentHash = item.contactContentHash;
        const eligible = item.eligible === true;
        // The existing encrypted import contract has no operational scope
        // columns. Updates therefore preserve scope; newly imported members are
        // explicitly unrestricted (null department and null validity limit).
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(memberId)
          || !stableCode || typeof displayEnvelope !== "object" || displayEnvelope === null
          || typeof displayContentHash !== "string") {
          throw new DataConflictError("IMPORT_ROW_INVALID", "Encrypted import row metadata is invalid");
        }
        if (item.decision.action === "update") {
          const previousResult = await this.client.query<{
            version: number; stable_code: string;
            eligibility_status: "eligible" | "ineligible" | "review"; available: boolean;
            eligibility_department_id: string | null; eligibility_valid_until: string | null;
          }>(
            `SELECT version,stable_code,eligibility_status,available,eligibility_department_id,
                    to_char(eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until
               FROM members WHERE id=$1 FOR UPDATE`,
            [memberId],
          );
          const previous = previousResult.rows[0];
          if (!previous || previous.version !== item.expectedVersion
              || previous.stable_code.toLocaleLowerCase("en-US") !== stableCode.toLocaleLowerCase("en-US")) {
            throw new DataConflictError("IMPORT_PLAN_STALE", "Member changed after import preview; preview the file again");
          }
          const nextEligibilityStatus = eligible ? "eligible" : "ineligible";
          const eligibilityMutation = previous.eligibility_status !== nextEligibilityStatus
            || previous.available !== eligible;
          const changed = await this.client.query<{ version: number; updated_at: Date }>(
            `UPDATE members SET display_envelope=$2,display_content_hash=$3,
                    contact_envelope=CASE WHEN $4::boolean THEN $5 ELSE contact_envelope END,
                    contact_content_hash=CASE WHEN $4::boolean THEN $6 ELSE contact_content_hash END,
                    eligibility_status=$7,available=$8,
                    version=version+1,updated_at=clock_timestamp()
               WHERE id=$1 AND version=$9 AND lower(stable_code)=lower($10)
               RETURNING version,updated_at`,
            [
              memberId, displayEnvelope, displayContentHash,
              contactEnvelope !== undefined, contactEnvelope ?? null, contactContentHash ?? null,
              nextEligibilityStatus, eligible, item.expectedVersion, stableCode,
            ],
          );
          const memberUpdate = changed.rows[0];
          if (!memberUpdate) {
            throw new DataConflictError("IMPORT_PLAN_STALE", "Member changed after import preview; preview the file again");
          }
          const pausedWorkflows = eligibilityMutation
            ? await this.pauseAffectedMemberWorkflows({
                identityId: input.identityId,
                memberId,
                memberVersion: memberUpdate.version,
                reasonCode: "MEMBER_ELIGIBILITY_CHANGED",
              })
            : [];
          for (const pause of pausedWorkflows) pausedProcessIds.add(String(pause["processId"]));
          await this.emit("member.changed", "member", memberId, {
            memberId, version: memberUpdate.version, operation: "import-updated",
          });
          await this.appendAudit("member.import.updated", "member", memberId, "success", {
            importId: input.importId,
            sourceRow: item.sourceRow,
            fields: [
              "displayEnvelope",
              ...(contactEnvelope !== undefined ? ["contactEnvelope"] : []),
              ...(previous.eligibility_status !== nextEligibilityStatus ? ["eligibilityStatus"] : []),
              ...(previous.available !== eligible ? ["available"] : []),
            ],
            version: memberUpdate.version,
            pausedProcessIds: pausedWorkflows.map((pause) => pause["processId"]),
          });
          updated += 1;
        } else {
          try {
            const inserted = await this.client.query<{ version: number; created_at: Date }>(
               `INSERT INTO members(
                  id,stable_code,profile_envelope,display_envelope,display_content_hash,
                  contact_envelope,contact_content_hash,profile_migration_required,eligibility_status,available,
                  eligibility_department_id,eligibility_valid_until
                ) VALUES ($1,$2,NULL,$3,$4,$5,$6,false,$7,$8,NULL,NULL)
                RETURNING version,created_at`,
              [
                memberId, stableCode, displayEnvelope, displayContentHash,
                contactEnvelope ?? null, contactContentHash ?? null,
                eligible ? "eligible" : "ineligible", eligible,
              ],
            );
            const createdMember = inserted.rows[0];
            if (!createdMember) throw new Error("Imported member insertion did not return a version");
            await this.emit("member.changed", "member", memberId, {
              memberId, version: createdMember.version, operation: "import-created",
            });
            await this.appendAudit("member.import.created", "member", memberId, "success", {
              importId: input.importId,
              sourceRow: item.sourceRow,
              eligibilityStatus: eligible ? "eligible" : "ineligible",
              available: eligible,
              departmentRestriction: null,
              validUntil: null,
              version: createdMember.version,
            });
          } catch (error) {
            if (isUniqueViolation(error)) {
              throw new DataConflictError("IMPORT_PLAN_STALE", "Member changed after import preview; preview the file again");
            }
            throw error;
          }
          created += 1;
        }
      }
      const summary = {
        created, updated, skipped, rejected: 0, total: job.preview_envelopes.length,
        pausedProcessIds: [...pausedProcessIds].sort(),
      };
      await this.client.query(
        `UPDATE member_import_jobs SET state='completed', summary=$2, completed_at=clock_timestamp()
          WHERE id=$1`,
        [input.importId, summary],
      );
      await this.emit("members.imported", "import", input.importId, { importId: input.importId, ...summary });
      await this.appendAudit("members.import.committed", "import", input.importId, "success", summary);
      return { importId: input.importId, state: "completed", ...summary };
    });
  }

  public async getOrganization(input: {
    readonly cycleId?: string;
    readonly stage: "proposal" | "elected";
  } = { stage: "elected" }): Promise<Record<string, unknown>> {
    const cycles = await this.client.query<{
      id: string; name: string; status: string; term_start: string; term_end: string;
    }>(
      `SELECT id,name,status,term_start::text,term_end::text
         FROM election_cycles
        ORDER BY term_start DESC,created_at DESC,id`,
    );
    const selectedCycle = input.cycleId
      ? cycles.rows.find(({ id }) => id === input.cycleId) ?? null
      : cycles.rows.find(({ status }) => status === "active") ?? cycles.rows[0] ?? null;
    const cycleOptions = cycles.rows.map((cycle) => ({
      id: cycle.id,
      name: cycle.name,
      status: cycle.status,
      termStart: cycle.term_start,
      termEnd: cycle.term_end,
    }));
    if (!selectedCycle) {
      return {
        cycles: cycleOptions,
        selectedCycle: null,
        cycleName: null,
        stage: input.stage,
        items: [],
      };
    }

    const result = await this.client.query<{
      item_id: string; vacancy_id: string; assignment_id: string | null;
      member_id: string | null; office_id: string; department_id: string;
      office_code: string; office_name: string; department_name: string;
      office_names: Record<string, string>; department_names: Record<string, string>;
      status: string; process_state: string | null; effective: boolean | null;
      independent: boolean | null; linked_to_assignment_id: string | null;
      member_snapshot: Record<string, unknown> | null;
      photo_snapshot: Record<string, unknown> | null;
    }>(
      `SELECT COALESCE(assignment.id,vacancy.id) AS item_id,
              vacancy.id AS vacancy_id,assignment.id AS assignment_id,
              assignment.member_id,
              office.id AS office_id,
              COALESCE(assignment.office_snapshot->>'departmentId',department.id::text) AS department_id,
              COALESCE(assignment.office_snapshot->>'canonicalCode',office.canonical_code) AS office_code,
              COALESCE(
                assignment.office_snapshot->'names'->>cycle.locale,
                assignment.office_snapshot->'names'->>'es',
                office.names->>cycle.locale,office.names->>'es',office.canonical_code
              ) AS office_name,
              COALESCE(
                assignment.office_snapshot->'departmentNames'->>cycle.locale,
                assignment.office_snapshot->'departmentNames'->>'es',
                department.names->>cycle.locale,department.names->>'es',department.canonical_code
              ) AS department_name,
              COALESCE(assignment.office_snapshot->'names',office.names) AS office_names,
              COALESCE(assignment.office_snapshot->'departmentNames',department.names) AS department_names,
              CASE
                WHEN assignment.id IS NULL THEN CASE WHEN $2='proposal' AND vacancy.status='pending' THEN 'pending' ELSE 'vacant' END
                WHEN $2='elected' THEN 'elected'
                WHEN assignment.state IN ('PROPUESTA_INTERNA','ACEPTACION_PENDIENTE') THEN 'recommended'
                ELSE 'accepted'
              END AS status,
              CASE
                WHEN $2='proposal' AND assignment.state IN ('ELEGIDA_POR_IGLESIA','VIGENTE','FINALIZADA')
                  THEN 'PRESENTADA_A_IGLESIA'
                ELSE assignment.state
              END AS process_state,
              assignment.effective,assignment.independent,assignment.linked_to_assignment_id,
              CASE
                WHEN assignment.id IS NULL THEN NULL
                WHEN COALESCE(
                  assignment.member_snapshot->'displayEnvelope',
                  member_snapshot.display_envelope
                ) IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object(
                  'memberId',assignment.member_id,
                  'displayEnvelope',COALESCE(
                    assignment.member_snapshot->'displayEnvelope',
                    member_snapshot.display_envelope
                  ),
                  'photo',assignment.member_snapshot->'photo'
                ))
                ELSE NULL
              END AS member_snapshot,
              assignment.member_snapshot->'photo' AS photo_snapshot
         FROM vacancies vacancy
         JOIN election_cycles cycle ON cycle.id=vacancy.cycle_id
         JOIN offices office ON office.id=vacancy.office_id
         JOIN departments department ON department.id=office.department_id
         LEFT JOIN LATERAL (
           SELECT candidate.*
             FROM assignments candidate
            WHERE candidate.vacancy_id=vacancy.id
              AND (
                ($2='elected'
                  AND candidate.state IN ('ELEGIDA_POR_IGLESIA','VIGENTE','FINALIZADA')
                  AND (candidate.effective OR candidate.state='FINALIZADA'))
                OR
                ($2='proposal'
                  AND candidate.state IN (
                    'PROPUESTA_INTERNA','ACEPTACION_PENDIENTE','ACEPTADA','PRESENTADA_A_IGLESIA',
                    'ELEGIDA_POR_IGLESIA','VIGENTE','FINALIZADA'
                  )
                  AND (candidate.effective OR candidate.state='FINALIZADA'))
              )
            ORDER BY candidate.effective DESC,candidate.updated_at DESC,candidate.created_at DESC,candidate.id
            LIMIT 1
         ) assignment ON true
         LEFT JOIN cycle_member_snapshots member_snapshot
           ON member_snapshot.cycle_id=vacancy.cycle_id
          AND member_snapshot.member_id=assignment.member_id
        WHERE vacancy.cycle_id=$1
          AND (
            vacancy.process_id IS NULL OR EXISTS (
              SELECT 1 FROM office_processes applicable
               WHERE applicable.cycle_id=vacancy.cycle_id AND applicable.enabled
                 AND (applicable.id=vacancy.process_id OR applicable.reused_vacancy_id=vacancy.id)
            )
          )
        ORDER BY department.sort_order,department.canonical_code,office.canonical_code,vacancy.ordinal,vacancy.id`,
      [selectedCycle.id, input.stage],
    );
    return {
      cycles: cycleOptions,
      selectedCycle: {
        id: selectedCycle.id,
        name: selectedCycle.name,
        status: selectedCycle.status,
        termStart: selectedCycle.term_start,
        termEnd: selectedCycle.term_end,
      },
      cycleName: selectedCycle.name,
      stage: input.stage,
      items: result.rows.map((row) => ({
        id: row.item_id,
        vacancyId: row.vacancy_id,
        ...(row.assignment_id ? { assignmentId: row.assignment_id } : {}),
        ...(row.member_id ? { memberId: row.member_id } : {}),
        officeId: row.office_id,
        departmentId: row.department_id,
        officeCode: row.office_code,
        officeName: row.office_name,
        departmentName: row.department_name,
        officeNames: row.office_names,
        departmentNames: row.department_names,
        status: row.status,
        processState: row.process_state,
        ...(row.effective !== null ? { effective: row.effective } : {}),
        ...(row.independent !== null ? { independent: row.independent } : {}),
        ...(row.linked_to_assignment_id ? { linkedToId: row.linked_to_assignment_id } : {}),
        ...(row.member_snapshot ? { memberSnapshot: row.member_snapshot } : {}),
        ...(row.photo_snapshot ? { photoSnapshot: row.photo_snapshot } : {}),
      })),
    };
  }

  public async getCommittee(): Promise<Record<string, unknown>> {
    const result = await this.client.query<{
      id: string; cycle_id: string; identity_id: string; member_id: string | null;
      display_envelope: EncryptedEnvelope; role_code: string; voting_right: boolean;
      status: string; joined_at: Date; left_at: Date | null;
    }>(
      `SELECT cm.id,cm.cycle_id,cm.identity_id,cm.member_id,cm.display_envelope,
              cm.role_code,cm.voting_right,cm.status,cm.joined_at,cm.left_at
         FROM committee_memberships cm
         JOIN election_cycles c ON c.id=cm.cycle_id
        WHERE c.status IN ('active','draft')
        ORDER BY CASE cm.role_code WHEN 'chair' THEN 0 WHEN 'pastor' THEN 1
                  WHEN 'secretary' THEN 2 WHEN 'custodian' THEN 3 ELSE 4 END,
                 cm.joined_at,cm.id`,
    );
    return {
      items: result.rows.map((row) => ({
        id: row.id,
        cycleId: row.cycle_id,
        identityId: row.identity_id,
        memberId: row.member_id,
        displayEnvelope: row.display_envelope,
        role: row.role_code,
        votingRight: row.voting_right,
        status: row.status,
        joinedAt: row.joined_at,
        leftAt: row.left_at,
      })),
    };
  }

  public async listReports(
    limit: number,
    permittedReportScopes: readonly string[],
  ): Promise<readonly Record<string, unknown>[]> {
    const result = await this.client.query<{
      id: string; report_type: string; audience: string; locale: string; format: string;
      filters: Record<string, unknown>; state: string; filename: string | null; media_type: string | null;
      artifact_sha256: string | null; ciphertext_sha256: string | null; plaintext_bytes: string | null;
      artifact_manifest: Record<string, unknown> | null; error_code: string | null;
      supersedes_report_id: string | null; corrected_by_report_id: string | null;
      correction_reason_code: ReportCorrectionReasonCode | null;
      lineage_root_id: string; lineage_revision: number;
      version: number; created_at: Date; ready_at: Date | null; failed_at: Date | null;
    }>(
      `SELECT report.id,report.report_type,report.audience,report.locale,report.format,report.filters,
              report.state,report.filename,report.media_type,report.artifact_sha256,report.ciphertext_sha256,
              report.plaintext_bytes::text,report.artifact_manifest,report.error_code,report.version,
              report.supersedes_report_id,successor.id AS corrected_by_report_id,
              report.correction_reason_code,report.lineage_root_id,report.lineage_revision,
              report.created_at,report.ready_at,report.failed_at
         FROM report_versions report
         LEFT JOIN report_versions successor ON successor.supersedes_report_id=report.id
        WHERE (report.report_type || ':' || report.audience)=ANY($2::text[])
        ORDER BY report.created_at DESC LIMIT $1`,
      [limit, permittedReportScopes],
    );
    return result.rows.map((row) => ({
      id: row.id,
      reportType: row.report_type,
      audience: row.audience,
      locale: row.locale,
      format: row.format,
      filters: row.filters,
      state: row.state,
      filename: row.filename ?? reportFilename(row.report_type, row.id, row.format),
      mediaType: row.media_type ?? mediaTypeFor(row.format as "pdf" | "xlsx" | "csv"),
      artifactSha256: row.artifact_sha256,
      ciphertextSha256: row.ciphertext_sha256,
      ciphertextBytes: row.plaintext_bytes === null ? null : Number(row.plaintext_bytes) + 16,
      plaintextBytes: row.plaintext_bytes === null ? null : Number(row.plaintext_bytes),
      manifest: row.artifact_manifest,
      errorCode: row.error_code,
      supersedesReportId: row.supersedes_report_id,
      correctedByReportId: row.corrected_by_report_id,
      correctionReasonCode: row.correction_reason_code,
      lineageRootId: row.lineage_root_id,
      lineageRevision: row.lineage_revision,
      version: row.version,
      createdAt: row.created_at,
      readyAt: row.ready_at,
      failedAt: row.failed_at,
    }));
  }

  public async getReportDescriptor(reportId: string): Promise<{
    readonly id: string; readonly reportType: string; readonly audience: string;
    readonly locale: string; readonly format: string; readonly state: string;
    readonly requestedByIdentityId: string; readonly version: number; readonly snapshotSha256: string;
    readonly filename: string; readonly mediaType: string;
    readonly supersedesReportId: string | null; readonly correctedByReportId: string | null;
    readonly correctionReasonCode: ReportCorrectionReasonCode | null;
    readonly lineageRootId: string; readonly lineageRevision: number;
  } | null> {
    const result = await this.client.query<{
      id: string; report_type: string; audience: string; locale: string; format: string;
      state: string; requested_by_identity_id: string; version: number; filters: Record<string, unknown>;
      filename: string; media_type: string;
      supersedes_report_id: string | null; corrected_by_report_id: string | null;
      correction_reason_code: ReportCorrectionReasonCode | null;
      lineage_root_id: string; lineage_revision: number;
    }>(
      `SELECT report.id,report.report_type,report.audience,report.locale,report.format,report.state,
              report.requested_by_identity_id,report.version,report.filters,report.filename,report.media_type,
              report.supersedes_report_id,successor.id AS corrected_by_report_id,
              report.correction_reason_code,report.lineage_root_id,report.lineage_revision
         FROM report_versions report
         LEFT JOIN report_versions successor ON successor.supersedes_report_id=report.id
        WHERE report.id=$1`,
      [reportId],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id, reportType: row.report_type, audience: row.audience, locale: row.locale,
      format: row.format, state: row.state, requestedByIdentityId: row.requested_by_identity_id,
      version: row.version, snapshotSha256: String(row.filters["snapshotSha256"] ?? ""),
      filename: row.filename, mediaType: row.media_type,
      supersedesReportId: row.supersedes_report_id, correctedByReportId: row.corrected_by_report_id,
      correctionReasonCode: row.correction_reason_code,
      lineageRootId: row.lineage_root_id, lineageRevision: row.lineage_revision,
    };
  }

  public async generateReport(input: {
    identityId: string; idempotencyKey: string; reportType: string;
    audience: "committee" | "auditor" | "church"; locale: "es" | "en" | "fr";
    format: "pdf" | "xlsx" | "csv"; filters: Readonly<Record<string, unknown>>;
  }): Promise<PendingReportIssuance> {
    return this.executeIdempotent(input.identityId, "report.generate", input.idempotencyKey, input, async () => {
      const reportId = randomUUID();
      const filename = reportFilename(input.reportType, reportId, input.format);
      const result = await this.client.query<{
        id: string; created_at: Date; version: number; lineage_root_id: string; lineage_revision: number;
      }>(
        `INSERT INTO report_versions(
           id,report_type,audience,locale,format,filters,state,requested_by_identity_id,
           filename,media_type,lineage_root_id,lineage_revision
         ) VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$1,1)
         RETURNING id,created_at,version,lineage_root_id,lineage_revision`,
        [reportId, input.reportType, input.audience, input.locale, input.format, input.filters, input.identityId, filename, mediaTypeFor(input.format)],
      );
      const row = result.rows[0];
      if (!row) throw new Error("Report request did not return a row");
      await this.emit("report.requested", "report", row.id, { reportId: row.id });
      await this.appendAudit("report.requested", "report", row.id, "success", { audience: input.audience, format: input.format });
      return {
        id: row.id,
        reportType: input.reportType,
        audience: input.audience,
        format: input.format,
        locale: input.locale,
        filters: input.filters,
        filename,
        mediaType: mediaTypeFor(input.format),
        state: "pending",
        version: row.version,
        artifactSha256: null,
        ciphertextSha256: null,
        ciphertextBytes: null,
        plaintextBytes: null,
        manifest: null,
        errorCode: null,
        supersedesReportId: null,
        correctedByReportId: null,
        correctionReasonCode: null,
        lineageRootId: row.lineage_root_id,
        lineageRevision: row.lineage_revision,
        createdAt: row.created_at,
        readyAt: null,
        failedAt: null,
      };
    });
  }

  public async correctReport(input: ReportCorrectionInput): Promise<PendingReportIssuance> {
    const reasonCode = normalizeAllowedReasonCode(input.reasonCode, REPORT_CORRECTION_REASON_CODES);
    if (!reasonCode) {
      throw new DataConflictError("REPORT_CORRECTION_REASON_INVALID", "Report corrections require an allowed non-sensitive reason code");
    }
    return this.executeIdempotent(input.identityId, "report.correct", input.idempotencyKey, {
      ...input,
      reasonCode,
    }, async () => {
      const previousResult = await this.client.query<{
        id: string; report_type: string; audience: "committee" | "auditor" | "church";
        locale: "es" | "en" | "fr"; format: "pdf" | "xlsx" | "csv" | "html";
        filters: Record<string, unknown>; state: string; version: number;
        supersedes_report_id: string | null;
        lineage_root_id: string; lineage_revision: number;
      }>(
        `SELECT report.id,report.report_type,report.audience,report.locale,report.format,report.filters,
                report.state,report.version,report.supersedes_report_id,
                report.lineage_root_id,report.lineage_revision
           FROM report_versions report
          WHERE report.id=$1
          FOR UPDATE`,
        [input.previousReportId],
      );
      const previous = previousResult.rows[0];
      if (!previous) throw new DataConflictError("REPORT_UNAVAILABLE", "The report selected for correction is unavailable");
      if (previous.version !== input.expectedPreviousVersion) {
        throw new DataConflictError("VERSION_CONFLICT", "The report selected for correction changed");
      }
      const retryableFailedCorrection = previous.state === "failed" && previous.supersedes_report_id !== null;
      if ((previous.state !== "ready" && !retryableFailedCorrection) || previous.format === "html") {
        throw new DataConflictError("REPORT_CORRECTION_NOT_ELIGIBLE", "Only a ready downloadable issuance or failed correction may be corrected");
      }
      const successor = await this.client.query<{ id: string }>(
        "SELECT id FROM report_versions WHERE supersedes_report_id=$1 LIMIT 1",
        [previous.id],
      );
      if (successor.rows[0]) {
        throw new DataConflictError("REPORT_ALREADY_CORRECTED", "Correct the latest report in the lineage instead of creating a branch");
      }
      if (hashCanonical(reportFilterScope(previous.filters)) !== hashCanonical(reportFilterScope(input.filters))) {
        throw new DataConflictError("REPORT_CORRECTION_SCOPE_MISMATCH", "A correction must preserve the original report filter scope");
      }
      if (!/^sha256:[0-9a-f]{64}$/u.test(String(input.filters["snapshotSha256"] ?? ""))
        || !Number.isFinite(Date.parse(String(input.filters["snapshotAt"] ?? "")))) {
        throw new DataConflictError("REPORT_SNAPSHOT_INVALID", "A correction requires a current report snapshot digest and timestamp");
      }

      const reportId = randomUUID();
      const filename = reportFilename(previous.report_type, reportId, previous.format);
      const lineageRevision = previous.lineage_revision + 1;
      const inserted = await this.client.query<{
        id: string; created_at: Date; version: number; lineage_root_id: string; lineage_revision: number;
      }>(
        `INSERT INTO report_versions(
           id,report_type,audience,locale,format,filters,state,requested_by_identity_id,
           filename,media_type,supersedes_report_id,correction_reason_code,lineage_root_id,lineage_revision
         ) VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$10,$11,$12,$13)
         RETURNING id,created_at,version,lineage_root_id,lineage_revision`,
        [
          reportId, previous.report_type, previous.audience, previous.locale, previous.format,
          input.filters, input.identityId, filename, mediaTypeFor(previous.format), previous.id,
          reasonCode, previous.lineage_root_id, lineageRevision,
        ],
      );
      const row = inserted.rows[0];
      if (!row) throw new Error("Report correction did not return a row");
      const lineageMetadata = {
        previousReportId: previous.id,
        lineageRootId: row.lineage_root_id,
        lineageRevision: row.lineage_revision,
        reasonCode,
      };
      await this.emit("report.correction_requested", "report", row.id, lineageMetadata);
      await this.appendAudit("report.correction_requested", "report", row.id, "success", lineageMetadata);
      return {
        id: row.id,
        reportType: previous.report_type,
        audience: previous.audience,
        format: previous.format,
        locale: previous.locale,
        filters: input.filters,
        filename,
        mediaType: mediaTypeFor(previous.format),
        state: "pending",
        version: row.version,
        artifactSha256: null,
        ciphertextSha256: null,
        ciphertextBytes: null,
        plaintextBytes: null,
        manifest: null,
        errorCode: null,
        supersedesReportId: previous.id,
        correctedByReportId: null,
        correctionReasonCode: reasonCode,
        lineageRootId: row.lineage_root_id,
        lineageRevision: row.lineage_revision,
        createdAt: row.created_at,
        readyAt: null,
        failedAt: null,
      };
    });
  }

  public async completeReport(input: {
    identityId: string; idempotencyKey: string; reportId: string; expectedVersion: number;
    envelope: EncryptedEnvelope; artifactSha256: string; ciphertextSha256: string;
    plaintextBytes: number; rowCount: number; generatedAt: string;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "report.complete", input.idempotencyKey, {
      ...input,
    }, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.envelope],
      });
      const ciphertext = Buffer.from(input.envelope.ciphertext, "base64url");
      if (ciphertext.toString("base64url") !== input.envelope.ciphertext
        || input.plaintextBytes < 1 || input.plaintextBytes > 20 * 1024 * 1024
        || ciphertext.byteLength !== input.plaintextBytes + 16) {
        throw new DataConflictError("REPORT_ARTIFACT_INVALID", "AES-GCM ciphertext must be canonical base64url and exactly plaintextBytes plus its 16-byte tag");
      }
      const canonicalEnvelope = JSON.stringify({
        algorithm: input.envelope.algorithm,
        keyId: input.envelope.keyId,
        nonce: input.envelope.nonce,
        ciphertext: input.envelope.ciphertext,
        aad: input.envelope.aad,
      });
      const actualArtifactSha256 = `sha256:${createHash("sha256").update(canonicalEnvelope, "utf8").digest("hex")}`;
      if (actualArtifactSha256 !== input.artifactSha256) {
        throw new DataConflictError("REPORT_DIGEST_MISMATCH", "Encrypted envelope does not match the declared digest");
      }
      const actualCiphertextSha256 = `sha256:${createHash("sha256").update(ciphertext).digest("hex")}`;
      if (actualCiphertextSha256 !== input.ciphertextSha256) {
        throw new DataConflictError("REPORT_CIPHERTEXT_DIGEST_MISMATCH", "Ciphertext does not match the declared digest");
      }
      const current = await this.client.query<{
        id: string; report_type: string; audience: string; locale: string; format: string;
        filters: Record<string, unknown>; filename: string; media_type: string;
        state: string; requested_by_identity_id: string; version: number; created_at: Date;
        supersedes_report_id: string | null; correction_reason_code: ReportCorrectionReasonCode | null;
        lineage_root_id: string; lineage_revision: number;
      }>(
        `SELECT id,report_type,audience,locale,format,filters,filename,media_type,
                state,requested_by_identity_id,version,created_at,supersedes_report_id,
                correction_reason_code,lineage_root_id,lineage_revision
           FROM report_versions WHERE id=$1 FOR UPDATE`,
        [input.reportId],
      );
      const report = current.rows[0];
      if (!report) throw new DataConflictError("REPORT_UNAVAILABLE", "Report request is unavailable");
      if (report.requested_by_identity_id !== input.identityId) {
        throw new DataConflictError("REPORT_ISSUER_MISMATCH", "Only the report issuer can complete this artifact");
      }
      if (report.version !== input.expectedVersion) throw new DataConflictError("VERSION_CONFLICT", "Report version is stale");
      if (report.state !== "pending") throw new DataConflictError("REPORT_STATE_CONFLICT", "Only a pending report can be completed");
      const snapshotSha256 = String(report.filters["snapshotSha256"] ?? "");
      if (!/^sha256:[0-9a-f]{64}$/.test(snapshotSha256)) {
        throw new DataConflictError("REPORT_SNAPSHOT_INVALID", "Report request has no valid snapshot digest");
      }
      const manifest = {
        schemaVersion: 1,
        reportId: report.id,
        reportType: report.report_type,
        audience: report.audience,
        locale: report.locale,
        format: report.format,
        requestVersion: input.expectedVersion,
        snapshotSha256,
        artifactSha256: actualArtifactSha256,
        ciphertextSha256: actualCiphertextSha256,
        ciphertextBytes: ciphertext.byteLength,
        plaintextBytes: input.plaintextBytes,
        rowCount: input.rowCount,
        generatedAt: input.generatedAt,
        lineageRootId: report.lineage_root_id,
        lineageRevision: report.lineage_revision,
        supersedesReportId: report.supersedes_report_id,
        correctionReasonCode: report.correction_reason_code,
      };
      const updated = await this.client.query<{ version: number; ready_at: Date }>(
        `UPDATE report_versions
            SET state='ready',artifact_envelope=$3,artifact_bytes=NULL,artifact_sha256=$4,ciphertext_sha256=$5,
                artifact_manifest=$6,plaintext_bytes=$7,ready_at=clock_timestamp(),version=version+1
          WHERE id=$1 AND version=$2 AND state='pending'
        RETURNING version,ready_at`,
        [report.id, input.expectedVersion, input.envelope, actualArtifactSha256, actualCiphertextSha256, manifest, input.plaintextBytes],
      );
      const row = updated.rows[0];
      if (!row) throw new DataConflictError("VERSION_CONFLICT", "Report changed while completing the artifact");
      await this.emit("report.ready", "report", report.id, {
        reportId: report.id, version: row.version, artifactSha256: actualArtifactSha256,
        ciphertextSha256: actualCiphertextSha256, plaintextBytes: input.plaintextBytes,
      });
      await this.appendAudit("report.ready", "report", report.id, "success", {
        version: row.version, artifactSha256: actualArtifactSha256, ciphertextSha256: actualCiphertextSha256,
        plaintextBytes: input.plaintextBytes, manifest,
      });
      return {
        id: report.id, reportType: report.report_type, audience: report.audience, locale: report.locale,
        format: report.format, filename: report.filename, mediaType: report.media_type,
        state: "ready", version: row.version, artifactSha256: actualArtifactSha256, ciphertextSha256: actualCiphertextSha256,
        ciphertextBytes: ciphertext.byteLength, plaintextBytes: input.plaintextBytes, manifest, filters: report.filters, errorCode: null,
        supersedesReportId: report.supersedes_report_id, correctedByReportId: null,
        correctionReasonCode: report.correction_reason_code,
        lineageRootId: report.lineage_root_id, lineageRevision: report.lineage_revision,
        createdAt: report.created_at, readyAt: row.ready_at, failedAt: null,
      };
    });
  }

  public async failReport(input: {
    identityId: string; idempotencyKey: string; reportId: string; expectedVersion: number; errorCode: string;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "report.fail", input.idempotencyKey, input, async () => {
      const updated = await this.client.query<{ version: number; failed_at: Date }>(
        `UPDATE report_versions
            SET state='failed',failed_at=clock_timestamp(),error_code=$4,version=version+1
          WHERE id=$1 AND version=$2 AND state='pending' AND requested_by_identity_id=$3
        RETURNING version,failed_at`,
        [input.reportId, input.expectedVersion, input.identityId, input.errorCode],
      );
      const row = updated.rows[0];
      if (!row) throw new DataConflictError("REPORT_STATE_CONFLICT", "Pending report is unavailable, stale, or belongs to another issuer");
      await this.emit("report.failed", "report", input.reportId, { reportId: input.reportId, version: row.version, errorCode: input.errorCode });
      await this.appendAudit("report.failed", "report", input.reportId, "failure", { version: row.version, errorCode: input.errorCode });
      return { id: input.reportId, state: "failed", version: row.version, errorCode: input.errorCode, failedAt: row.failed_at };
    });
  }

  public async getReportArtifact(
    reportId: string,
    permittedReportScopes: readonly string[],
  ): Promise<{
    readonly envelope: EncryptedEnvelope; readonly filename: string; readonly mediaType: string;
    readonly artifactSha256: string; readonly ciphertextSha256: string;
    readonly ciphertextBytes: number; readonly plaintextBytes: number; readonly requestVersion: number;
    readonly manifest: Readonly<Record<string, unknown>>; readonly reportType: string;
    readonly audience: string; readonly locale: string; readonly format: string; readonly version: number;
    readonly supersedesReportId: string | null; readonly correctionReasonCode: ReportCorrectionReasonCode | null;
    readonly lineageRootId: string; readonly lineageRevision: number;
  } | null> {
    const result = await this.client.query<{
      artifact_envelope: EncryptedEnvelope; filename: string; media_type: string;
      artifact_sha256: string; ciphertext_sha256: string;
      artifact_manifest: Record<string, unknown>; plaintext_bytes: string; report_type: string;
      audience: string; locale: string; format: string; version: number;
      supersedes_report_id: string | null; correction_reason_code: ReportCorrectionReasonCode | null;
      lineage_root_id: string; lineage_revision: number;
    }>(
      `SELECT artifact_envelope,filename,media_type,artifact_sha256,ciphertext_sha256,artifact_manifest,
              plaintext_bytes::text,report_type,audience,locale,format,version,supersedes_report_id,
              correction_reason_code,lineage_root_id,lineage_revision
         FROM report_versions
        WHERE id=$1 AND state='ready' AND artifact_bytes IS NULL
          AND (report_type || ':' || audience)=ANY($2::text[])`,
      [reportId, permittedReportScopes],
    );
    const row = result.rows[0];
    if (!row) return null;
    await appendSensitiveReadAuditEvent(this.client, {
      action: SENSITIVE_READ_AUDIT_ACTIONS.reportArtifact,
      entityType: "report",
      entityId: reportId,
      metadata: {
        reportType: row.report_type,
        audience: row.audience,
        format: row.format,
        version: row.version,
        lineageRevision: row.lineage_revision,
      },
    });
    return {
      envelope: row.artifact_envelope, filename: row.filename, mediaType: row.media_type,
      artifactSha256: row.artifact_sha256, plaintextBytes: Number(row.plaintext_bytes),
      ciphertextSha256: row.ciphertext_sha256,
      ciphertextBytes: Number(row.plaintext_bytes) + 16,
      requestVersion: Number(row.artifact_manifest["requestVersion"]),
      manifest: row.artifact_manifest, reportType: row.report_type, audience: row.audience,
      locale: row.locale, format: row.format, version: row.version,
      supersedesReportId: row.supersedes_report_id, correctionReasonCode: row.correction_reason_code,
      lineageRootId: row.lineage_root_id, lineageRevision: row.lineage_revision,
    };
  }

  public async recordReportPrint(input: {
    identityId: string; idempotencyKey: string; reportId: string; artifactSha256: string;
    permittedReportScopes: readonly string[];
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, "report.print", input.idempotencyKey, input, async () => {
      const report = await this.client.query<{ artifact_sha256: string; report_type: string; audience: string }>(
        `SELECT artifact_sha256,report_type,audience FROM report_versions
          WHERE id=$1 AND state='ready' AND artifact_sha256=$2
            AND (report_type || ':' || audience)=ANY($3::text[])`,
        [input.reportId, input.artifactSha256, input.permittedReportScopes],
      );
      const row = report.rows[0];
      if (!row) throw new DataConflictError("REPORT_ARTIFACT_UNAVAILABLE", "Ready report artifact or digest is unavailable");
      const printedAt = new Date().toISOString();
      await this.emit("report.printed", "report", input.reportId, { reportId: input.reportId, artifactSha256: row.artifact_sha256, printedAt });
      await this.appendAudit("report.printed", "report", input.reportId, "success", {
        artifactSha256: row.artifact_sha256, reportType: row.report_type, audience: row.audience, printedAt,
      });
      return { id: input.reportId, artifactSha256: row.artifact_sha256, printedAt };
    });
  }

  public async updateAssignment(input: {
    identityId: string; idempotencyKey: string; assignmentId: string;
    expectedVersion: number; operation: "consent" | "congregational-decision";
    consentStatus?: "PENDING" | "CONTACTED" | "ACCEPTED" | "DECLINED" | "WITHDRAWN";
    congregationalOutcome?: "ELECTED" | "RETURNED_TO_COMMITTEE" | "NOT_ELECTED" | "DEFERRED";
    envelope: EncryptedEnvelope;
  }): Promise<Record<string, unknown>> {
    return this.executeIdempotent(input.identityId, `assignment.${input.operation}`, input.idempotencyKey, input, async () => {
      await assertWritableTenantContentKey(this.client, {
        identityId: input.identityId,
        envelopes: [input.envelope],
      });
      const consent = input.operation === "consent";
      const currentResult = await this.client.query<{ state: string }>(
        "SELECT state FROM assignments WHERE id=$1 AND version=$2 FOR UPDATE",
        [input.assignmentId, input.expectedVersion],
      );
      const current = currentResult.rows[0];
      if (!current) throw new DataConflictError("VERSION_CONFLICT", "Assignment version is stale or unavailable");
      const nextState = consent
        ? stateAfterConsent(current.state, input.consentStatus)
        : stateAfterCongregationalDecision(current.state, input.congregationalOutcome);
      const result = await this.client.query<{ version: number; updated_at: Date }>(
        `UPDATE assignments SET
           state=$3,
           consent_status=CASE WHEN $4 THEN $6 ELSE consent_status END,
           congregational_outcome=CASE WHEN $4 THEN congregational_outcome ELSE $7 END,
           consent_envelope=CASE WHEN $4 THEN $5 ELSE consent_envelope END,
           congregational_decision=CASE WHEN $4 THEN congregational_decision ELSE $5 END,
           version=version+1, updated_at=clock_timestamp()
         WHERE id=$1 AND version=$2 RETURNING version,updated_at`,
        [input.assignmentId, input.expectedVersion, nextState, consent, input.envelope, input.consentStatus ?? null, input.congregationalOutcome ?? null],
      );
      const row = result.rows[0];
      if (!row) throw new DataConflictError("VERSION_CONFLICT", "Assignment version is stale or unavailable");
      await this.emit("assignment.changed", "assignment", input.assignmentId, { assignmentId: input.assignmentId, state: nextState, version: row.version });
      await this.appendAudit(`assignment.${input.operation}.recorded`, "assignment", input.assignmentId, "success", {
        previousState: current.state,
        nextState,
        version: row.version,
      });
      return { id: input.assignmentId, state: nextState, version: row.version, updatedAt: row.updated_at };
    });
  }

  public async recordSecurityDenial(
    action: string,
    entityType: string,
    entityId: string,
    metadata: Readonly<Record<string, unknown>> = {},
  ): Promise<void> {
    await this.appendAudit(action, entityType, entityId, "denied", metadata);
  }

  public async listAudit(limit: number, beforeSequence?: number): Promise<{
    readonly items: readonly Record<string, unknown>[];
    readonly verified: boolean;
  }> {
    const result = await this.client.query(
      `SELECT sequence,id,occurred_at,actor_identity_id,action,entity_type,entity_id,
              result,request_id,metadata,previous_hash,event_hash,hash_version
         FROM audit_events
        WHERE ($2::bigint IS NULL OR sequence < $2)
        ORDER BY sequence DESC LIMIT $1`,
      [limit, beforeSequence ?? null],
    );
    return {
      items: result.rows.map((row) => ({
        sequence: row["sequence"],
        id: row["id"],
        createdAt: row["occurred_at"],
        actorIdentityId: row["actor_identity_id"],
        action: row["action"],
        entityType: row["entity_type"],
        entityId: row["entity_id"],
        result: row["result"],
        requestId: row["request_id"],
        metadata: row["metadata"],
        previousHash: row["previous_hash"],
        eventHash: row["event_hash"],
        hashVersion: row["hash_version"],
      })),
      verified: await this.verifyAuditChain(),
    };
  }

  public async latestEventSequence(): Promise<number> {
    const result = await this.client.query<{ sequence: string }>(
      "SELECT COALESCE(MAX(sequence), 0)::text AS sequence FROM outbox_events WHERE audience = 'tenant.authorized'",
    );
    const sequence = Number(result.rows[0]?.sequence ?? "0");
    if (!Number.isSafeInteger(sequence) || sequence < 0) {
      throw new DataConflictError("EVENT_SEQUENCE_INVALID", "Outbox sequence exceeds the supported cursor range");
    }
    return sequence;
  }

  public async listEvents(afterSequence: number, limit = 100): Promise<readonly Record<string, unknown>[]> {
    const result = await this.client.query(
      `SELECT sequence,id,audience,event_type,aggregate_type,aggregate_id,payload,occurred_at
         FROM outbox_events
        WHERE sequence > $1 AND audience = 'tenant.authorized'
        ORDER BY sequence LIMIT $2`,
      [afterSequence, limit],
    );
    return result.rows;
  }

  private async verifyAuditChain(): Promise<boolean> {
    const chain = await this.client.query<{
      sequence: string;
      id: string;
      occurred_at: Date;
      actor_identity_id: string | null;
      action: string;
      entity_type: string | null;
      entity_id: string | null;
      result: string;
      request_id: string | null;
      metadata: Record<string, unknown>;
      previous_hash: string | null;
      event_hash: string;
      hash_version: 1 | 2;
    }>(
      `SELECT sequence::text,id::text,occurred_at,actor_identity_id,action,entity_type,entity_id,result,request_id,
              metadata,previous_hash,event_hash,hash_version
         FROM audit_events ORDER BY audit_events.sequence`,
    );
    if (chain.rows.length === 0) return true;
    const records: TenantAuditEventRecord[] = chain.rows.map((event) => ({
      sequence: event.sequence,
      id: event.id,
      occurredAt: event.occurred_at.toISOString(),
      hashVersion: event.hash_version,
      actorIdentityId: event.actor_identity_id,
      action: event.action,
      entityType: event.entity_type,
      entityId: event.entity_id,
      result: event.result as TenantAuditEventRecord["result"],
      requestId: event.request_id,
      metadata: event.metadata,
      previousHash: event.previous_hash,
      eventHash: event.event_hash,
    }));
    return verifyTenantAuditEventChain(records).valid;
  }

  private async executeIdempotent<T>(
    identityId: string,
    operation: string,
    idempotencyKey: string,
    request: unknown,
    work: () => Promise<T>,
  ): Promise<T> {
    const requestHash = hashCanonical(request);
    const inserted = await this.client.query(
      `INSERT INTO idempotency_records(identity_id,operation,idempotency_key,request_hash)
       VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
      [identityId, operation, idempotencyKey, requestHash],
    );
    if (inserted.rowCount === 0) {
      const existing = await this.client.query<{ request_hash: string; response_body: T | null }>(
        `SELECT request_hash,response_body FROM idempotency_records
          WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
        [identityId, operation, idempotencyKey],
      );
      const row = existing.rows[0];
      if (!row || row.request_hash !== requestHash) {
        throw new DataConflictError("IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different input");
      }
      if (row.response_body === null) {
        throw new DataConflictError("IDEMPOTENCY_IN_PROGRESS", "The original operation is still in progress");
      }
      return row.response_body;
    }
    const response = await work();
    await this.client.query(
      `UPDATE idempotency_records SET response_status=200,response_body=$4
        WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3`,
      [identityId, operation, idempotencyKey, response],
    );
    return response;
  }

  private async emit(
    eventType: string,
    aggregateType: string,
    aggregateId: string,
    payload: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.client.query(
      `INSERT INTO outbox_events(audience,event_type,aggregate_type,aggregate_id,payload)
       VALUES ('tenant.authorized',$1,$2,$3,$4)`,
      [eventType, aggregateType, aggregateId, payload],
    );
  }

  private async appendAudit(
    action: string,
    entityType: string,
    entityId: string,
    result: "success" | "denied" | "failure",
    metadata: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await appendTenantAuditEventV2(this.client, { action, entityType, entityId, result, metadata });
  }

  private async requireActiveDepartment(departmentId: string): Promise<void> {
    const result = await this.client.query<{ active: boolean }>(
      "SELECT active FROM departments WHERE id=$1 FOR SHARE",
      [departmentId],
    );
    const row = result.rows[0];
    if (!row || !row.active) {
      throw new DataConflictError("CATALOG_DEPARTMENT_UNAVAILABLE", "Parent department is unavailable or inactive");
    }
  }

  private async assertTenantTimezoneMutationSafe(): Promise<void> {
    const affected = await this.client.query(
      `SELECT 1
        WHERE EXISTS (
          SELECT 1
            FROM office_processes process
            JOIN election_cycles cycle ON cycle.id=process.cycle_id AND cycle.status='active'
           WHERE process.phase NOT IN ('CERRADO','ANULADO','SIN_CANDIDATOS')
             AND (
            EXISTS (
              SELECT 1 FROM rounds round_state
              JOIN candidate_snapshots snapshot ON snapshot.round_id=round_state.id
              JOIN members member ON member.id=snapshot.member_id
              WHERE round_state.process_id=process.id
                AND (snapshot.eligibility_valid_until_snapshot IS NOT NULL
                  OR member.eligibility_valid_until IS NOT NULL)
            )
            OR EXISTS (
              SELECT 1 FROM candidacies candidacy
              JOIN members member ON member.id=candidacy.member_id
              WHERE candidacy.process_id=process.id
                AND (candidacy.eligibility_valid_until_snapshot IS NOT NULL
                  OR member.eligibility_valid_until IS NOT NULL)
            )
             )
        ) OR EXISTS (
          SELECT 1
            FROM assignments assignment
            JOIN members member ON member.id=assignment.member_id
           WHERE (assignment.effective
               OR assignment.state NOT IN ('FINALIZADA','DECLINADA','DEVUELTA_A_COMISION','RETIRADA','SUSTITUIDA'))
             AND (member.eligibility_valid_until IS NOT NULL
               OR assignment.member_snapshot->'eligibility'->>'validUntil' IS NOT NULL)
        )
        LIMIT 1`,
    );
    if (affected.rowCount) {
      throw new DataConflictError(
        "TENANT_TIMEZONE_ELIGIBILITY_ACTIVE",
        "Timezone cannot change while a date-limited member participates in an active appointment workflow",
      );
    }
  }

  private async assertDepartmentDeactivationSafe(departmentId: string): Promise<void> {
    const [restrictedMembers, activeOffices] = await Promise.all([
      this.client.query(
        `SELECT 1 FROM members
          WHERE eligibility_department_id=$1 AND archived_at IS NULL
          LIMIT 1 FOR SHARE`,
        [departmentId],
      ),
      this.client.query(
        "SELECT 1 FROM offices WHERE department_id=$1 AND active LIMIT 1 FOR SHARE",
        [departmentId],
      ),
    ]);
    if (restrictedMembers.rowCount || activeOffices.rowCount) {
      throw new DataConflictError(
        "CATALOG_DEPARTMENT_ELIGIBILITY_IN_USE",
        "Department cannot be deactivated while it scopes an active member or contains an active office",
      );
    }
  }

  private async assertOfficeEligibilityMutationSafe(officeId: string): Promise<void> {
    const affected = await this.client.query(
      `SELECT 1
        WHERE EXISTS (
          SELECT 1
            FROM office_processes process
            JOIN election_cycles cycle ON cycle.id=process.cycle_id
           WHERE process.office_id=$1
             AND cycle.status='active'
             AND process.phase NOT IN ('CERRADO','ANULADO','SIN_CANDIDATOS')
        ) OR EXISTS (
          SELECT 1 FROM assignments assignment
           WHERE assignment.office_id=$1
             AND (assignment.effective
               OR assignment.state NOT IN ('FINALIZADA','DECLINADA','DEVUELTA_A_COMISION','RETIRADA','SUSTITUIDA'))
        )
        LIMIT 1`,
      [officeId],
    );
    if (affected.rowCount) {
      throw new DataConflictError(
        "CATALOG_OFFICE_ELIGIBILITY_IN_USE",
        "Office department or active state cannot change while its appointment workflow or assignment is active",
      );
    }
  }

  private async throwCatalogMutationConflict(
    table: "departments" | "offices",
    id: string,
    expectedVersion: number,
  ): Promise<never> {
    const result = await this.client.query<{ local_extension: boolean; version: number }>(
      `SELECT local_extension,version FROM ${table} WHERE id=$1`,
      [id],
    );
    const row = result.rows[0];
    if (!row) throw new DataConflictError("CATALOG_ITEM_UNAVAILABLE", "Catalog item is unavailable");
    if (!row.local_extension) {
      throw new DataConflictError("CANONICAL_CATALOG_IMMUTABLE", "Canonical catalog records cannot be changed by tenant administration");
    }
    if (row.version !== expectedVersion) throw new DataConflictError("VERSION_CONFLICT", "Catalog item version is stale");
    throw new DataConflictError("CATALOG_UPDATE_CONFLICT", "Catalog item could not be changed");
  }

  private async pauseAffectedMemberWorkflows(input: {
    readonly identityId: string;
    readonly memberId: string;
    readonly memberVersion: number;
    readonly reasonCode: "MEMBER_ELIGIBILITY_CHANGED" | "MEMBER_ARCHIVED";
  }): Promise<readonly Record<string, unknown>[]> {
    const activePhases = [
      "CONFIGURADO", "PROPUESTAS_ABIERTAS", "PROPUESTAS_CERRADAS", "DEPURACION", "LISTA_CONFIRMADA",
      "VOTACION_ABIERTA", "VOTACION_CERRADA", "ESCRUTINIO", "RESULTADO_INTERNO",
      "RECOMENDACION_CONFIRMADA", "DESEMPATE_PENDIENTE", "PAUSADO",
    ];
    const affected = await this.client.query<{ id: string; cycle_id: string; phase: string; version: number }>(
      `SELECT process.id,process.cycle_id,process.phase,process.version
         FROM office_processes process
        WHERE process.phase=ANY($2::text[])
          AND (
            EXISTS (SELECT 1 FROM candidacies candidacy
                     WHERE candidacy.process_id=process.id AND candidacy.member_id=$1)
            OR EXISTS (SELECT 1 FROM candidate_list_versions list
                       JOIN candidate_list_entries entry ON entry.list_id=list.id
                       WHERE list.process_id=process.id AND entry.member_id=$1)
             OR EXISTS (SELECT 1 FROM rounds round_state
                        JOIN candidate_snapshots snapshot ON snapshot.round_id=round_state.id
                        WHERE round_state.process_id=process.id AND snapshot.member_id=$1)
             OR EXISTS (SELECT 1 FROM assignments assignment
                        WHERE assignment.process_id=process.id
                          AND assignment.member_id=$1
                          AND assignment.effective)
           )
        ORDER BY process.id
        FOR UPDATE`,
      [input.memberId, activePhases],
    );
    const pauses: Record<string, unknown>[] = [];
    for (const process of affected.rows) {
      const roundResult = await this.client.query<{ id: string; phase: string; version: number }>(
        `SELECT id,phase,version FROM rounds
          WHERE process_id=$1 AND phase=ANY($2::text[])
          ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE`,
        [process.id, activePhases],
      );
      const round = roundResult.rows[0] ?? null;
      const existingResult = await this.client.query<{
        id: string; cycle_id: string; round_id: string | null; member_id: string;
        member_version: number; previous_process_phase: string; previous_round_phase: string | null;
        reason_code: string;
      }>(
        `SELECT id,cycle_id,round_id,member_id,member_version,
                previous_process_phase,previous_round_phase,reason_code
           FROM member_eligibility_workflow_pauses
          WHERE process_id=$1 AND resolved_at IS NULL
          ORDER BY id FOR UPDATE`,
        [process.id],
      );
      const sameMemberPause = existingResult.rows.find(({ member_id }) => member_id === input.memberId);
      if (sameMemberPause) {
        pauses.push({
          pauseId: sameMemberPause.id,
          processId: process.id,
          cycleId: sameMemberPause.cycle_id,
          roundId: sameMemberPause.round_id,
          previousProcessPhase: sameMemberPause.previous_process_phase,
          previousRoundPhase: sameMemberPause.previous_round_phase,
          processVersion: process.version,
          roundVersion: round?.version ?? null,
          reasonCode: sameMemberPause.reason_code,
          reused: true,
        });
        continue;
      }
      const existingPause = existingResult.rows[0];
      if (process.phase === "PAUSADO") {
        if (!existingPause || existingPause.cycle_id !== process.cycle_id
            || existingPause.round_id !== (round?.id ?? null)) {
          throw new DataConflictError(
            "ELIGIBILITY_PAUSE_INVALID",
            "Paused workflow has no consistent unresolved eligibility incident",
          );
        }
        const pauseId = randomUUID();
        await this.client.query(
          `INSERT INTO member_eligibility_workflow_pauses(
             id,cycle_id,process_id,round_id,member_id,member_version,
             previous_process_phase,previous_round_phase,reason_code,actor_identity_id
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            pauseId, process.cycle_id, process.id, existingPause.round_id, input.memberId,
            input.memberVersion, existingPause.previous_process_phase,
            existingPause.previous_round_phase, input.reasonCode, input.identityId,
          ],
        );
        const pause = {
          pauseId,
          processId: process.id,
          cycleId: process.cycle_id,
          roundId: existingPause.round_id,
          previousProcessPhase: existingPause.previous_process_phase,
          previousRoundPhase: existingPause.previous_round_phase,
          processVersion: process.version,
          roundVersion: round?.version ?? null,
          reasonCode: input.reasonCode,
          extended: true,
        };
        await this.emit("workflow.pause.extended", "office_process", process.id, {
          ...pause, memberId: input.memberId, memberVersion: input.memberVersion,
        });
        await this.appendAudit("workflow.pause.extended", "office_process", process.id, "success", {
          ...pause, memberId: input.memberId, memberVersion: input.memberVersion,
        });
        pauses.push(pause);
        continue;
      }
      if (existingPause) {
        throw new DataConflictError(
          "ELIGIBILITY_PAUSE_INVALID",
          "Unresolved eligibility incident exists while its workflow is not paused",
        );
      }
      const pauseId = randomUUID();
      await this.client.query(
        `INSERT INTO member_eligibility_workflow_pauses(
           id,cycle_id,process_id,round_id,member_id,member_version,
           previous_process_phase,previous_round_phase,reason_code,actor_identity_id
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          pauseId, process.cycle_id, process.id, round?.id ?? null, input.memberId,
          input.memberVersion, process.phase, round?.phase ?? null, input.reasonCode, input.identityId,
        ],
      );
      const processUpdate = await this.client.query<{ version: number }>(
        `UPDATE office_processes SET phase='PAUSADO',version=version+1,updated_at=clock_timestamp()
          WHERE id=$1 AND version=$2 RETURNING version`,
        [process.id, process.version],
      );
      const roundUpdate = round
        ? await this.client.query<{ version: number }>(
            "UPDATE rounds SET phase='PAUSADO',version=version+1 WHERE id=$1 AND version=$2 RETURNING version",
            [round.id, round.version],
          )
        : null;
      if (!processUpdate.rows[0] || (round && !roundUpdate?.rows[0])) {
        throw new DataConflictError("VERSION_CONFLICT", "Affected workflow changed while applying the eligibility pause");
      }
      const pause = {
        pauseId,
        processId: process.id,
        cycleId: process.cycle_id,
        roundId: round?.id ?? null,
        previousProcessPhase: process.phase,
        previousRoundPhase: round?.phase ?? null,
        processVersion: processUpdate.rows[0].version,
        roundVersion: roundUpdate?.rows[0]?.version ?? null,
        reasonCode: input.reasonCode,
      };
      await this.emit("workflow.paused", "office_process", process.id, {
        ...pause, memberId: input.memberId, memberVersion: input.memberVersion,
      });
      await this.appendAudit("workflow.paused", "office_process", process.id, "success", {
        ...pause, memberId: input.memberId, memberVersion: input.memberVersion,
      });
      pauses.push(pause);
    }
    return pauses;
  }

  private async tenantCivilDate(): Promise<string> {
    const result = await this.client.query<{ civil_date: string }>(
      `SELECT to_char((clock_timestamp() AT TIME ZONE timezone)::date,'YYYY-MM-DD') AS civil_date
         FROM tenant_settings WHERE singleton=true`,
    );
    const civilDate = result.rows[0]?.civil_date;
    if (!civilDate || !/^\d{4}-\d{2}-\d{2}$/u.test(civilDate)) {
      throw new DataConflictError("TENANT_TIMEZONE_INVALID", "Tenant civil date cannot be evaluated");
    }
    return civilDate;
  }

  private async assertRoundCandidatesCurrentlyEligible(roundId: string, officeId: string): Promise<void> {
    try {
      const result = await requireRoundCandidatesOperationallyEligible(this.client, roundId);
      if (result.officeId !== officeId) {
        throw new DataConflictError("ROUND_OFFICE_MISMATCH", "Round and office eligibility context differ");
      }
    } catch (error) {
      if (error instanceof MemberEligibilityGuardError) {
        throw new DataConflictError(error.code, error.message);
      }
      throw error;
    }
  }

  private async queryAccessMutation<T extends import("pg").QueryResultRow = import("pg").QueryResultRow>(
    text: string,
    values: readonly unknown[],
  ): Promise<import("pg").QueryResult<T>> {
    try {
      return await this.client.query<T>(text, [...values]);
    } catch (error) {
      if (typeof error === "object" && error !== null && "code" in error) {
        if (error.code === "42501") {
          throw new DataConflictError("PERMISSION_ESCALATION", "Requested access exceeds the actor's delegable authority");
        }
        if (error.code === "40001") {
          throw new DataConflictError("VERSION_CONFLICT", "Access-control state changed; reload before retrying");
        }
        if (error.code === "23505") {
          throw new DataConflictError("ACCESS_CONFLICT", "Role or binding already exists, or idempotency input conflicts");
        }
        if (error.code === "23503") {
          throw new DataConflictError("ROLE_NOT_FOUND", "The requested tenant role is unavailable");
        }
        if (error.code === "23514") {
          throw new DataConflictError("ACCESS_DEFINITION_INVALID", "The requested local role definition is invalid");
        }
      }
      throw error;
    }
  }
}

function hashCanonical(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function requireReasonCode(value: string, allowed: readonly string[]): string {
  const reasonCode = normalizeAllowedReasonCode(value, allowed);
  if (!reasonCode) {
    throw new DataConflictError("INVALID_REASON_CODE", "Operational reason code is not allowed for this operation");
  }
  return reasonCode;
}

function assertOrdinaryRoundMechanism(mechanism: string): void {
  if (isOrdinaryProposalBallotMechanism(mechanism)) return;
  if (mechanism === "council_recommendation_board_approval") {
    throw new DataConflictError(
      "COUNCIL_BOARD_PROCEDURE_REQUIRED",
      "This office requires council recommendation and board approval and cannot enter the ordinary proposal or ballot workflow",
    );
  }
  if (mechanism === "linked_designation") {
    throw new DataConflictError(
      "LINKED_DESIGNATION_DIRECT_ELECTION",
      "A linked responsibility must be derived from its configured base appointment and cannot enter an independent proposal or ballot",
    );
  }
  throw new DataConflictError("OFFICE_NOT_ELECTABLE", "This office cannot enter the ordinary proposal or ballot workflow");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

function reportFilename(reportType: string, reportId: string, format: string): string {
  const safeType = reportType.normalize("NFKD").replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase();
  return `${safeType || "report"}-${reportId.slice(0, 8)}.${format}`;
}

function reportFilterScope(filters: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>> {
  const { snapshotSha256: _snapshotSha256, snapshotAt: _snapshotAt, ...scope } = filters;
  return scope;
}

function mediaTypeFor(format: "pdf" | "xlsx" | "csv"): string {
  if (format === "pdf") return "application/pdf";
  if (format === "xlsx") return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
  return "text/csv; charset=utf-8";
}

function stateAfterConsent(
  current: string,
  status: "PENDING" | "CONTACTED" | "ACCEPTED" | "DECLINED" | "WITHDRAWN" | undefined,
): string {
  if (!status) throw new DataConflictError("CONSENT_STATUS_REQUIRED", "Consent status is required");
  if (!["PROPUESTA_INTERNA", "ACEPTACION_PENDIENTE"].includes(current)) {
    throw new DataConflictError("INVALID_STATE_TRANSITION", "Assignment is not awaiting consent");
  }
  if (status === "ACCEPTED") return "ACEPTADA";
  if (status === "DECLINED") return "DECLINADA";
  if (status === "WITHDRAWN") return "RETIRADA";
  return "ACEPTACION_PENDIENTE";
}

function stateAfterCongregationalDecision(
  current: string,
  outcome: "ELECTED" | "RETURNED_TO_COMMITTEE" | "NOT_ELECTED" | "DEFERRED" | undefined,
): string {
  if (!outcome) throw new DataConflictError("CONGREGATIONAL_OUTCOME_REQUIRED", "Congregational outcome is required");
  if (current !== "PRESENTADA_A_IGLESIA") {
    throw new DataConflictError("INVALID_STATE_TRANSITION", "Assignment is not presented to the congregation");
  }
  if (outcome === "ELECTED") return "ELEGIDA_POR_IGLESIA";
  if (outcome === "DEFERRED") return "PRESENTADA_A_IGLESIA";
  return "DEVUELTA_A_COMISION";
}

function validateSubmissionEnvelope(
  input: SubmissionInput,
  expected: { tenantId: string; cycleId: string; candidateSetHash: string; rulesHash: string },
): void {
  const canonicalEnvelope = JSON.stringify({
    algorithm: input.envelope.algorithm,
    keyId: input.envelope.keyId,
    nonce: input.envelope.nonce,
    ciphertext: input.envelope.ciphertext,
    aad: input.envelope.aad,
  });
  const computedHash = `sha256:${createHash("sha256").update(canonicalEnvelope, "utf8").digest("hex")}`;
  if (computedHash !== input.contentHash) {
    throw new DataConflictError("CONTENT_HASH_MISMATCH", "Submission ciphertext hash does not match");
  }
  let context: unknown;
  try {
    context = JSON.parse(Buffer.from(input.envelope.aad, "base64url").toString("utf8"));
  } catch {
    throw new DataConflictError("ENVELOPE_CONTEXT_INVALID", "Submission AAD is invalid");
  }
  if (!context || typeof context !== "object" || Array.isArray(context)) {
    throw new DataConflictError("ENVELOPE_CONTEXT_INVALID", "Submission AAD is invalid");
  }
  const record = context as Record<string, unknown>;
  const required: Record<string, unknown> = {
    tenantId: expected.tenantId,
    cycleId: expected.cycleId,
    roundId: input.roundId,
    purpose: input.kind,
    schemaVersion: 1,
    roundVersion: input.expectedVersion,
    candidateSetHash: expected.candidateSetHash,
    rulesHash: expected.rulesHash,
  };
  for (const [key, value] of Object.entries(required)) {
    if (record[key] !== value) {
      throw new DataConflictError("ENVELOPE_CONTEXT_MISMATCH", `Submission AAD mismatch: ${key}`);
    }
  }
}

function encryptedEnvelopeHash(envelope: EncryptedEnvelope): string {
  const canonical = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

function isValidIanaTimezone(value: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value }).format(new Date(0));
    return true;
  } catch {
    return false;
  }
}
