import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { canonicalJson, sha256 } from "./backup.js";

export const LEGACY_INVITATION_RECONCILIATION_MIGRATION =
  "036_transactional_invitation_grantor_lock.sql";
export const LEGACY_INVITATION_RECONCILIATION_AUDIT_ACTION =
  "tenant.legacy_invitation_bindings_reconciled";

export interface LegacyInvitationBindingManifestEntry {
  readonly tenantId: string;
  readonly invitationId: string;
  readonly acceptanceId: string;
  readonly identityId: string;
  readonly grantedByIdentityId: string;
  readonly acceptanceAttempt: number;
  readonly authorityKind: "tenant_delegate" | "initial_admin";
  readonly authorityEpoch: number;
  readonly roleCodes: readonly string[];
  readonly sourceInvitationVersion: number;
  readonly authorityFinalized: boolean;
}

export interface LegacyInvitationReconciliationEvidence {
  readonly required: boolean;
  readonly sourceSchema: "legacy_035" | "transactional_036";
  readonly invitationCount: number;
  readonly bindingCount: number;
  readonly manifestSha256: string;
  readonly controlSnapshotSha256: string;
}

export interface LegacyInvitationReconciliationInspection {
  readonly entries: readonly LegacyInvitationBindingManifestEntry[];
  readonly evidence: LegacyInvitationReconciliationEvidence;
}

interface TenantBindingRow {
  readonly invitation_id: string;
  readonly acceptance_id: string | null;
  readonly identity_id: string;
  readonly granted_by_identity_id: string | null;
  readonly role_code: string;
}

interface ControlInvitationRow {
  readonly invitation_id: string;
  readonly tenant_id: string;
  readonly acceptance_id: string | null;
  readonly acceptance_identity_id: string | null;
  readonly acceptance_attempt: number;
  readonly created_by_identity_id: string;
  readonly role_codes: string[];
  readonly authority_kind: string;
  readonly authority_epoch: string;
  readonly authority_finalized_at: Date | null;
  readonly status: string;
  readonly version: number;
}

interface TenantFenceRow {
  readonly invitation_id: string;
  readonly state: string;
  readonly acceptance_attempt: number;
  readonly acceptance_id: string;
  readonly invited_identity_id: string;
  readonly granted_by_identity_id: string;
  readonly role_codes: string[];
}

type QueryExecutor = Pick<Pool, "query">;

/**
 * Uses the same first control-plane lock as authentication, invitation
 * completion and identity-policy mutation. Maintenance callers acquire this
 * before the tenant route lock; the inspection repeats it harmlessly so a
 * direct caller cannot invert authority-row ordering.
 */
export async function lockLegacyInvitationReconciliationBoundary(
  control: QueryExecutor,
  tenantId: string,
): Promise<void> {
  await control.query(
    "SELECT pg_advisory_xact_lock(hashtextextended('tenant_identity_policy:' || $1::text,0))",
    [tenantId],
  );
}

/**
 * Builds an exact cross-database manifest. Invitation ids are existing tenant
 * provenance, never inferred from identity, email or current membership. Apply
 * callers set lockControlRows while holding the outer maintenance transaction.
 */
export async function inspectLegacyInvitationReconciliation(
  tenant: QueryExecutor,
  control: QueryExecutor,
  tenantId: string,
  options: { readonly lockControlRows?: boolean } = {},
): Promise<LegacyInvitationReconciliationInspection> {
  const schema = await tenant.query<{
    has_source_invitation_id: boolean;
    has_acceptance_id: boolean;
    has_fences: boolean;
  }>(
    `SELECT EXISTS (
       SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='role_bindings'
          AND column_name='source_invitation_id'
     ) AS has_source_invitation_id,
     EXISTS (
       SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='role_bindings'
          AND column_name='source_acceptance_id'
     ) AS has_acceptance_id,
     to_regclass('public.tenant_invitation_acceptance_fences') IS NOT NULL AS has_fences`,
  );
  const shape = schema.rows[0];
  if (
    !shape
    || (!shape.has_source_invitation_id && (shape.has_acceptance_id || shape.has_fences))
    || (shape.has_source_invitation_id && shape.has_acceptance_id !== shape.has_fences)
  ) {
    throw new Error("Tenant invitation acceptance schema is partial or unavailable");
  }
  const sourceSchema = shape.has_acceptance_id ? "transactional_036" : "legacy_035";
  // Pre-provenance tenants contain no invitation-bound rows by construction.
  // Later migrations add the nullable source column before 036; never infer a
  // historical binding from identity, email, membership or role similarity.
  if (!shape.has_source_invitation_id) {
    const entries: readonly LegacyInvitationBindingManifestEntry[] = [];
    return {
      entries,
      evidence: {
        required: false,
        sourceSchema,
        invitationCount: 0,
        bindingCount: 0,
        manifestSha256: stableManifestSha256(entries),
        controlSnapshotSha256: sha256(canonicalJson([])),
      },
    };
  }
  const acceptanceProjection = shape.has_acceptance_id
    ? "binding.source_acceptance_id::text"
    : "NULL::text";
  const bindings = await tenant.query<TenantBindingRow>(
    `SELECT binding.source_invitation_id::text AS invitation_id,
            ${acceptanceProjection} AS acceptance_id,
            binding.identity_id::text AS identity_id,
            binding.granted_by_identity_id::text AS granted_by_identity_id,
            role.code AS role_code
       FROM public.role_bindings binding
       JOIN public.roles role ON role.id=binding.role_id
      WHERE binding.source_invitation_id IS NOT NULL
      ORDER BY binding.source_invitation_id,role.code,binding.identity_id`,
  );
  const grouped = groupTenantBindings(bindings.rows);
  const invitationIds = [...grouped.keys()].sort();
  let controlRows = invitationIds.length === 0
    ? []
    : await readControlInvitations(control, tenantId, invitationIds, false);
  if (options.lockControlRows === true && controlRows.length > 0) {
    await lockLegacyInvitationReconciliationBoundary(control, tenantId);
    // Match the live authority order: identities/memberships precede invitation
    // row locks. A maintenance run therefore cannot invert the grantor locks
    // used by claim/offboarding even if a stale API connection still exists.
    const identities = [...new Set(controlRows.flatMap((row) => [
      row.acceptance_identity_id,
      row.created_by_identity_id,
    ]).filter((value): value is string => value !== null))].sort();
    await control.query(
      "SELECT id FROM public.platform_identities WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE",
      [identities],
    );
    await control.query(
      `SELECT identity_id FROM public.tenant_memberships
        WHERE tenant_id=$1 AND identity_id=ANY($2::uuid[])
        ORDER BY identity_id FOR UPDATE`,
      [tenantId, identities],
    );
    controlRows = await readControlInvitations(control, tenantId, invitationIds, true);
  }
  if (controlRows.length !== invitationIds.length) {
    throw new Error("Legacy tenant bindings do not have a one-to-one control-plane invitation source");
  }

  const controlByInvitation = new Map(controlRows.map((row) => [row.invitation_id, row]));
  const entries = invitationIds.map((invitationId): LegacyInvitationBindingManifestEntry => {
    const tenantBinding = grouped.get(invitationId)!;
    const controlInvitation = controlByInvitation.get(invitationId);
    if (!controlInvitation) {
      throw new Error("Legacy invitation binding is missing its exact control-plane source");
    }
    return exactManifestEntry(tenantId, tenantBinding, controlInvitation, sourceSchema);
  });

  if (sourceSchema === "transactional_036" && entries.length > 0) {
    const fences = await tenant.query<TenantFenceRow>(
      `SELECT invitation_id::text, state, acceptance_attempt, acceptance_id::text,
              invited_identity_id::text,granted_by_identity_id::text,role_codes
         FROM public.tenant_invitation_acceptance_fences
        WHERE invitation_id=ANY($1::uuid[])
        ORDER BY invitation_id`,
      [invitationIds],
    );
    assertExactFences(entries, fences.rows);
  }

  const manifestSha256 = stableManifestSha256(entries);
  const controlSnapshotSha256 = controlSnapshotSha256For(entries);
  const auditExists = entries.length === 0 ? false : (await control.query<{ exists: boolean }>(
    `SELECT EXISTS (
       SELECT 1 FROM public.platform_audit_events event
        WHERE event.tenant_id=$1::uuid
          AND event.action=$2
          AND event.entity_type='tenant_database'
          AND event.entity_id=$1::uuid::text
          AND event.result='success'
          AND event.metadata->>'manifestSha256'=$3
          AND event.metadata->>'controlSnapshotSha256'=$4
          AND event.metadata->>'migration'=$5
          AND event.metadata->>'invitationCount'=$6
          AND event.metadata->>'bindingCount'=$7
     ) AS exists`,
    [
      tenantId,
      LEGACY_INVITATION_RECONCILIATION_AUDIT_ACTION,
      manifestSha256,
      controlSnapshotSha256,
      LEGACY_INVITATION_RECONCILIATION_MIGRATION,
      String(entries.length),
      String(bindings.rows.length),
    ],
  )).rows[0]?.exists === true;
  const initialAdminFinalized = entries
    .filter(({ authorityKind }) => authorityKind === "initial_admin")
    .every(({ authorityFinalized }) => authorityFinalized);
  return {
    entries,
    evidence: {
      required: entries.length > 0
        && (sourceSchema === "legacy_035" || !auditExists || !initialAdminFinalized),
      sourceSchema,
      invitationCount: entries.length,
      bindingCount: bindings.rows.length,
      manifestSha256,
      controlSnapshotSha256,
    },
  };
}

export function assertLegacyInvitationReconciliationUnchanged(
  before: LegacyInvitationReconciliationInspection,
  locked: LegacyInvitationReconciliationInspection,
): void {
  if (canonicalJson(before.evidence) !== canonicalJson(locked.evidence)
      || before.evidence.manifestSha256 !== locked.evidence.manifestSha256) {
    throw new Error("Legacy invitation reconciliation changed after preflight; refusing to apply it");
  }
}

export function assertLegacyInvitationReconciliationApplied(
  before: LegacyInvitationReconciliationInspection,
  applied: LegacyInvitationReconciliationInspection,
): void {
  if (
    applied.evidence.sourceSchema !== "transactional_036"
    || before.evidence.invitationCount !== applied.evidence.invitationCount
    || before.evidence.bindingCount !== applied.evidence.bindingCount
    || before.evidence.manifestSha256 !== applied.evidence.manifestSha256
    || before.evidence.controlSnapshotSha256 !== applied.evidence.controlSnapshotSha256
  ) {
    throw new Error("Legacy invitation reconciliation did not apply the exact preflight manifest");
  }
}

export function assertLegacyInvitationReconciliationFinalized(
  applied: LegacyInvitationReconciliationInspection,
  finalized: LegacyInvitationReconciliationInspection,
): void {
  if (
    finalized.evidence.required
    || finalized.evidence.sourceSchema !== "transactional_036"
    || applied.evidence.invitationCount !== finalized.evidence.invitationCount
    || applied.evidence.bindingCount !== finalized.evidence.bindingCount
    || applied.evidence.manifestSha256 !== finalized.evidence.manifestSha256
  ) {
    throw new Error("Legacy invitation reconciliation control-plane evidence is incomplete");
  }
}

/** Installs only transaction-local, parameterized evidence for migration 036. */
export async function installLegacyInvitationReconciliationManifest(
  client: PoolClient,
  inspection: LegacyInvitationReconciliationInspection,
): Promise<void> {
  await client.query(`
    CREATE TEMP TABLE legacy_invitation_binding_reconciliation_manifest (
      tenant_id uuid NOT NULL,
      invitation_id uuid PRIMARY KEY,
      acceptance_id uuid NOT NULL UNIQUE,
      invited_identity_id uuid NOT NULL,
      granted_by_identity_id uuid NOT NULL,
      acceptance_attempt integer NOT NULL CHECK (acceptance_attempt > 0),
      authority_kind text NOT NULL CHECK (authority_kind IN ('tenant_delegate','initial_admin')),
      authority_epoch bigint NOT NULL CHECK (authority_epoch >= 0),
      role_codes text[] NOT NULL,
      source_invitation_version integer NOT NULL CHECK (source_invitation_version > 0),
      manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
      binding_count integer NOT NULL CHECK (binding_count > 0)
    ) ON COMMIT DROP
  `);
  for (const entry of inspection.entries) {
    await client.query(
      `INSERT INTO pg_temp.legacy_invitation_binding_reconciliation_manifest(
         tenant_id,invitation_id,acceptance_id,invited_identity_id,granted_by_identity_id,
         acceptance_attempt,authority_kind,authority_epoch,role_codes,
         source_invitation_version,manifest_sha256,binding_count
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        entry.tenantId,
        entry.invitationId,
        entry.acceptanceId,
        entry.identityId,
        entry.grantedByIdentityId,
        entry.acceptanceAttempt,
        entry.authorityKind,
        entry.authorityEpoch,
        [...entry.roleCodes],
        entry.sourceInvitationVersion,
        inspection.evidence.manifestSha256,
        inspection.evidence.bindingCount,
      ],
    );
  }
}

/**
 * Commits the control-plane half only after tenant 036 has committed and been
 * revalidated. A crash before this transaction commits is safely retryable:
 * the tenant fence remains exact and this routine is idempotent.
 */
export async function finalizeLegacyInvitationReconciliationEvidence(
  control: PoolClient,
  inspection: LegacyInvitationReconciliationInspection,
  requestId: string,
): Promise<void> {
  if (inspection.entries.length === 0 || !inspection.evidence.required) return;
  const tenantId = inspection.entries[0]!.tenantId;
  for (const entry of inspection.entries) {
    if (entry.tenantId !== tenantId) throw new Error("Legacy reconciliation crossed tenant boundaries");
    if (entry.authorityKind !== "initial_admin") continue;
    const finalized = await control.query<{ finalized: boolean }>(
      `SELECT public.mark_tenant_invitation_authority_finalized($1,$2,$3,$4) AS finalized`,
      [entry.invitationId, entry.acceptanceId, entry.identityId, entry.acceptanceAttempt],
    );
    if (finalized.rows[0]?.finalized !== true) {
      throw new Error("Legacy initial-administrator authority could not be finalized exactly");
    }
  }

  const finalizedRows = await control.query<{
    invitation_id: string;
    source_invitation_version: number;
    authority_finalized: boolean;
  }>(
    `SELECT invitation.id::text AS invitation_id,
            invitation.version AS source_invitation_version,
            invitation.authority_finalized_at IS NOT NULL AS authority_finalized
       FROM public.tenant_invitations invitation
      WHERE invitation.tenant_id=$1 AND invitation.id=ANY($2::uuid[])
      ORDER BY invitation.id
      FOR UPDATE OF invitation`,
    [tenantId, inspection.entries.map(({ invitationId }) => invitationId)],
  );
  const finalizedByInvitation = new Map(
    finalizedRows.rows.map((row) => [row.invitation_id, row]),
  );
  const finalizedSnapshot = inspection.entries.map((entry) => {
    const row = finalizedByInvitation.get(entry.invitationId);
    const markerWasAdded = entry.authorityKind === "initial_admin" && !entry.authorityFinalized;
    if (
      !row
      || row.source_invitation_version !== entry.sourceInvitationVersion + (markerWasAdded ? 1 : 0)
      || row.authority_finalized !== (entry.authorityKind === "initial_admin")
    ) {
      throw new Error("Legacy invitation authority finalization changed outside the exact maintenance tuple");
    }
    return {
      ...entry,
      sourceInvitationVersion: row.source_invitation_version,
      authorityFinalized: row.authority_finalized,
    };
  });
  if (finalizedByInvitation.size !== inspection.entries.length) {
    throw new Error("Legacy invitation authority finalization inventory changed");
  }
  const finalizedControlSnapshotSha256 = controlSnapshotSha256For(finalizedSnapshot);

  const metadata = {
    bindingCount: inspection.evidence.bindingCount,
    controlSnapshotSha256: finalizedControlSnapshotSha256,
    invitationCount: inspection.evidence.invitationCount,
    manifestSha256: inspection.evidence.manifestSha256,
    migration: LEGACY_INVITATION_RECONCILIATION_MIGRATION,
    preflightControlSnapshotSha256: inspection.evidence.controlSnapshotSha256,
  };
  await control.query("SELECT pg_advisory_xact_lock(hashtextextended('platform_audit_chain',0))");
  const duplicate = await control.query<{ exists: boolean }>(
    `SELECT EXISTS (
       SELECT 1 FROM public.platform_audit_events event
        WHERE event.tenant_id=$1::uuid AND event.action=$2
          AND event.entity_type='tenant_database' AND event.entity_id=$1::uuid::text
          AND event.result='success' AND event.metadata->>'manifestSha256'=$3
          AND event.metadata->>'controlSnapshotSha256'=$4
          AND event.metadata->>'migration'=$5
          AND event.metadata->>'invitationCount'=$6
          AND event.metadata->>'bindingCount'=$7
     ) AS exists`,
    [
      tenantId,
      LEGACY_INVITATION_RECONCILIATION_AUDIT_ACTION,
      inspection.evidence.manifestSha256,
      finalizedControlSnapshotSha256,
      LEGACY_INVITATION_RECONCILIATION_MIGRATION,
      String(inspection.evidence.invitationCount),
      String(inspection.evidence.bindingCount),
    ],
  );
  if (duplicate.rows[0]?.exists === true) return;
  const previous = await control.query<{ event_hash: string }>(
    "SELECT event_hash FROM public.platform_audit_events ORDER BY sequence DESC LIMIT 1",
  );
  const previousHash = previous.rows[0]?.event_hash ?? null;
  const canonical = JSON.stringify({
    previousHash,
    action: LEGACY_INVITATION_RECONCILIATION_AUDIT_ACTION,
    actorIdentityId: null,
    tenantId,
    entityType: "tenant_database",
    entityId: tenantId,
    result: "success",
    requestId,
    metadata,
  });
  const eventHash = createHash("sha256").update(canonical).digest("hex");
  await control.query(
    `INSERT INTO public.platform_audit_events(
       actor_identity_id,tenant_id,action,entity_type,entity_id,result,request_id,
       metadata,previous_hash,event_hash
     ) VALUES (NULL,$1::uuid,$2,'tenant_database',$1::uuid::text,'success',$3,$4,$5,$6)`,
    [tenantId, LEGACY_INVITATION_RECONCILIATION_AUDIT_ACTION, requestId, metadata, previousHash, eventHash],
  );
}

function groupTenantBindings(rows: readonly TenantBindingRow[]): Map<string, TenantBindingRow[]> {
  const grouped = new Map<string, TenantBindingRow[]>();
  for (const row of rows) {
    const existing = grouped.get(row.invitation_id) ?? [];
    existing.push(row);
    grouped.set(row.invitation_id, existing);
  }
  return grouped;
}

async function readControlInvitations(
  control: QueryExecutor,
  tenantId: string,
  invitationIds: readonly string[],
  lockRows: boolean,
): Promise<ControlInvitationRow[]> {
  return (await control.query<ControlInvitationRow>(
    `SELECT invitation.id::text AS invitation_id,invitation.tenant_id::text AS tenant_id,
            invitation.acceptance_id::text AS acceptance_id,
            invitation.acceptance_identity_id::text AS acceptance_identity_id,
            invitation.acceptance_attempt,invitation.created_by_identity_id::text,
            invitation.role_codes,invitation.authority_kind,
            invitation.authority_epoch::text,invitation.authority_finalized_at,
            invitation.status,invitation.version
       FROM public.tenant_invitations invitation
      WHERE invitation.tenant_id=$1 AND invitation.id=ANY($2::uuid[])
      ORDER BY invitation.id
      ${lockRows ? "FOR UPDATE OF invitation" : ""}`,
    [tenantId, [...invitationIds]],
  )).rows;
}

function exactManifestEntry(
  tenantId: string,
  tenantBindings: readonly TenantBindingRow[],
  control: ControlInvitationRow,
  sourceSchema: LegacyInvitationReconciliationEvidence["sourceSchema"],
): LegacyInvitationBindingManifestEntry {
  const identities = new Set(tenantBindings.map(({ identity_id }) => identity_id));
  const grantors = new Set(tenantBindings.map(({ granted_by_identity_id }) => granted_by_identity_id));
  const tenantRoles = tenantBindings.map(({ role_code }) => role_code).sort();
  const controlRoles = [...control.role_codes].sort();
  const authorityEpoch = Number(control.authority_epoch);
  if (
    control.tenant_id !== tenantId
    || control.status !== "accepted"
    || !control.acceptance_id
    || !control.acceptance_identity_id
    || control.acceptance_attempt <= 0
    || control.version <= 0
    || identities.size !== 1
    || !identities.has(control.acceptance_identity_id)
    || grantors.size !== 1
    || !grantors.has(control.created_by_identity_id)
    || controlRoles.length !== tenantRoles.length
    || controlRoles.some((role, index) => role !== tenantRoles[index])
    || !["tenant_delegate", "initial_admin"].includes(control.authority_kind)
    || !Number.isSafeInteger(authorityEpoch)
    || (control.authority_kind === "tenant_delegate" && authorityEpoch !== 0)
    || (control.authority_kind === "initial_admin"
      && (authorityEpoch <= 0 || controlRoles.length !== 1 || controlRoles[0] !== "CHURCH_ADMIN"))
  ) {
    throw new Error("Legacy invitation binding is ambiguous against its immutable control-plane acceptance");
  }
  const acceptanceIds = new Set(tenantBindings.map(({ acceptance_id }) => acceptance_id));
  if (
    (sourceSchema === "legacy_035" && (acceptanceIds.size !== 1 || !acceptanceIds.has(null)))
    || (sourceSchema === "transactional_036"
      && (acceptanceIds.size !== 1 || !acceptanceIds.has(control.acceptance_id)))
  ) {
    throw new Error("Tenant invitation binding acceptance epoch is incomplete or ambiguous");
  }
  return {
    tenantId,
    invitationId: control.invitation_id,
    acceptanceId: control.acceptance_id,
    identityId: control.acceptance_identity_id,
    grantedByIdentityId: control.created_by_identity_id,
    acceptanceAttempt: control.acceptance_attempt,
    authorityKind: control.authority_kind as "tenant_delegate" | "initial_admin",
    authorityEpoch,
    roleCodes: controlRoles,
    sourceInvitationVersion: control.version,
    authorityFinalized: control.authority_finalized_at !== null,
  };
}

function stableManifestSha256(entries: readonly LegacyInvitationBindingManifestEntry[]): string {
  return sha256(canonicalJson(entries.map((entry) => ({
    tenantId: entry.tenantId,
    invitationId: entry.invitationId,
    acceptanceId: entry.acceptanceId,
    identityId: entry.identityId,
    grantedByIdentityId: entry.grantedByIdentityId,
    acceptanceAttempt: entry.acceptanceAttempt,
    authorityKind: entry.authorityKind,
    authorityEpoch: entry.authorityEpoch,
    roleCodes: entry.roleCodes,
  }))));
}

function controlSnapshotSha256For(
  entries: readonly Pick<
    LegacyInvitationBindingManifestEntry,
    "invitationId" | "sourceInvitationVersion" | "authorityFinalized"
  >[],
): string {
  return sha256(canonicalJson(entries.map((entry) => ({
    invitationId: entry.invitationId,
    sourceInvitationVersion: entry.sourceInvitationVersion,
    authorityFinalized: entry.authorityFinalized,
  }))));
}

function assertExactFences(
  entries: readonly LegacyInvitationBindingManifestEntry[],
  fences: readonly TenantFenceRow[],
): void {
  const fenceByInvitation = new Map(fences.map((fence) => [fence.invitation_id, fence]));
  if (fenceByInvitation.size !== entries.length) {
    throw new Error("Transactional invitation fence inventory is incomplete");
  }
  for (const entry of entries) {
    const fence = fenceByInvitation.get(entry.invitationId);
    const roles = fence ? [...fence.role_codes].sort() : [];
    if (
      !fence
      || fence.state !== "applied"
      || fence.acceptance_attempt !== entry.acceptanceAttempt
      || fence.acceptance_id !== entry.acceptanceId
      || fence.invited_identity_id !== entry.identityId
      || fence.granted_by_identity_id !== entry.grantedByIdentityId
      || roles.length !== entry.roleCodes.length
      || roles.some((role, index) => role !== entry.roleCodes[index])
    ) {
      throw new Error("Transactional invitation fence does not match the exact control-plane acceptance");
    }
  }
}
