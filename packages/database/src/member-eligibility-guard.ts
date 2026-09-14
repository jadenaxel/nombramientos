import type { PoolClient } from "pg";
import {
  evaluateMemberEligibilityForOffice,
  isCanonicalCivilDate,
  type MemberEligibilityReason,
} from "@nombramientos/domain";

// All application paths which either consume or mutate operational member
// eligibility use this transaction-scoped lock before taking workflow/member
// row locks. Readers share it; policy mutations take it exclusively. This
// closes the READ COMMITTED gap between evaluating tenant civil time/catalog
// scope and persisting a ballot, manifest, aggregate, or workflow transition.
const ELIGIBILITY_POLICY_LOCK_NAMESPACE = 1_853_121_029;
const ELIGIBILITY_POLICY_LOCK_OBJECT = 30;

export async function acquireMemberEligibilityPolicySharedLock(client: PoolClient): Promise<void> {
  await client.query(
    "SELECT pg_advisory_xact_lock_shared($1::integer,$2::integer)",
    [ELIGIBILITY_POLICY_LOCK_NAMESPACE, ELIGIBILITY_POLICY_LOCK_OBJECT],
  );
}

export async function acquireMemberEligibilityPolicyExclusiveLock(client: PoolClient): Promise<void> {
  await client.query(
    "SELECT pg_advisory_xact_lock($1::integer,$2::integer)",
    [ELIGIBILITY_POLICY_LOCK_NAMESPACE, ELIGIBILITY_POLICY_LOCK_OBJECT],
  );
}

export class MemberEligibilityGuardError extends Error {
  public constructor(
    public readonly code: "ROUND_CANDIDATE_ELIGIBILITY_CHANGED" | "MEMBER_ELIGIBILITY_CHANGED" | "TENANT_TIMEZONE_INVALID",
    message: string,
  ) {
    super(message);
    this.name = "MemberEligibilityGuardError";
  }
}

export interface CurrentMemberEligibility {
  readonly memberId: string;
  readonly memberVersion: number;
  readonly evaluatedOn: string;
  readonly officeDepartmentId: string;
  readonly departmentRestriction: string | null;
  readonly validUntil: string | null;
  readonly effective: boolean;
  readonly reason: MemberEligibilityReason;
}

export interface RoundCandidateEligibility {
  readonly roundId: string;
  readonly officeId: string;
  readonly officeDepartmentId: string;
  readonly evaluatedOn: string;
  readonly candidateIds: readonly string[];
}

interface EligibilityContextRow {
  readonly office_id: string;
  readonly office_department_id: string;
  readonly office_active: boolean;
  readonly office_department_active: boolean;
  readonly evaluated_on: string;
}

interface MemberRow {
  readonly id: string;
  readonly version: number;
  readonly eligibility_status: string;
  readonly available: boolean;
  readonly archived: boolean;
  readonly eligibility_department_id: string | null;
  readonly eligibility_valid_until: string | null;
}

interface CandidateRow extends MemberRow {
  readonly candidate_id: string;
  readonly snapshot_eligible: boolean;
  readonly snapshot_effective: boolean;
  readonly snapshot_department_id: string | null;
  readonly snapshot_valid_until: string | null;
  readonly snapshot_evaluated_on: string | null;
}

/**
 * Revalidates both immutable candidate evidence and mutable member state on the
 * tenant civil date. No encrypted narrative is read or projected.
 */
export async function requireRoundCandidatesOperationallyEligible(
  client: PoolClient,
  roundId: string,
): Promise<RoundCandidateEligibility> {
  await acquireMemberEligibilityPolicySharedLock(client);
  const context = await loadEligibilityContext(client, roundId, null);
  const candidates = await client.query<CandidateRow>(
    `SELECT snapshot.candidate_id,
            snapshot.eligible AS snapshot_eligible,
            snapshot.eligibility_effective AS snapshot_effective,
            snapshot.eligibility_department_id_snapshot AS snapshot_department_id,
            to_char(snapshot.eligibility_valid_until_snapshot,'YYYY-MM-DD') AS snapshot_valid_until,
            to_char(snapshot.eligibility_evaluated_on,'YYYY-MM-DD') AS snapshot_evaluated_on,
            member.id,member.version,member.eligibility_status,member.available,
            member.archived_at IS NOT NULL AS archived,
            member.eligibility_department_id,
            to_char(member.eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until
       FROM candidate_snapshots snapshot
       JOIN members member ON member.id=snapshot.member_id
      WHERE snapshot.round_id=$1
      ORDER BY snapshot.candidate_id
      FOR SHARE OF member`,
    [roundId],
  );
  if (candidates.rows.length === 0) {
    throw new MemberEligibilityGuardError(
      "ROUND_CANDIDATE_ELIGIBILITY_CHANGED",
      "The frozen candidate set has no usable operational eligibility evidence",
    );
  }
  const departmentState = await loadDepartmentState(client, [
    context.office_department_id,
    ...candidates.rows.flatMap((row) => [row.snapshot_department_id, row.eligibility_department_id]),
  ]);
  const invalid = candidates.rows.some((row) => {
    if (!row.snapshot_eligible || !row.snapshot_effective
        || !row.snapshot_evaluated_on
        || !isCanonicalCivilDate(row.snapshot_evaluated_on)
        || row.snapshot_evaluated_on > context.evaluated_on) return true;
    const frozen = evaluateMemberEligibilityForOffice({
      eligibilityStatus: "eligible",
      available: true,
      archived: false,
      departmentRestriction: row.snapshot_department_id,
      validUntil: row.snapshot_valid_until,
      evaluatedOn: context.evaluated_on,
      officeDepartmentId: context.office_department_id,
      ...(row.snapshot_department_id === null ? {} : {
        restrictionDepartmentActive: departmentState.get(row.snapshot_department_id) === true,
      }),
    });
    const current = evaluateMemberRow(row, context, departmentState);
    return !frozen.eligible || !current.eligible;
  });
  if (!context.office_active || !context.office_department_active || invalid) {
    throw new MemberEligibilityGuardError(
      "ROUND_CANDIDATE_ELIGIBILITY_CHANGED",
      "The frozen candidate set contains a member outside current validity or department scope",
    );
  }
  return {
    roundId,
    officeId: context.office_id,
    officeDepartmentId: context.office_department_id,
    evaluatedOn: context.evaluated_on,
    candidateIds: candidates.rows.map(({ candidate_id }) => candidate_id),
  };
}

export async function inspectCurrentMemberEligibilityForOffice(
  client: PoolClient,
  memberId: string,
  officeId: string,
): Promise<CurrentMemberEligibility> {
  await acquireMemberEligibilityPolicySharedLock(client);
  const context = await loadEligibilityContext(client, null, officeId);
  const memberResult = await client.query<MemberRow>(
    `SELECT id,version,eligibility_status,available,archived_at IS NOT NULL AS archived,
            eligibility_department_id,
            to_char(eligibility_valid_until,'YYYY-MM-DD') AS eligibility_valid_until
       FROM members WHERE id=$1 FOR SHARE`,
    [memberId],
  );
  const member = memberResult.rows[0];
  if (!member) {
    throw new MemberEligibilityGuardError("MEMBER_ELIGIBILITY_CHANGED", "The assignment member is unavailable");
  }
  const departmentState = await loadDepartmentState(client, [
    context.office_department_id,
    member.eligibility_department_id,
  ]);
  const decision = evaluateMemberRow(member, context, departmentState);
  return {
    memberId: member.id,
    memberVersion: member.version,
    evaluatedOn: context.evaluated_on,
    officeDepartmentId: context.office_department_id,
    departmentRestriction: member.eligibility_department_id,
    validUntil: member.eligibility_valid_until,
    effective: context.office_active && context.office_department_active && decision.eligible,
    reason: context.office_active && context.office_department_active
      ? decision.reason
      : "DEPARTMENT_RESTRICTED",
  };
}

async function loadEligibilityContext(
  client: PoolClient,
  roundId: string | null,
  officeId: string | null,
): Promise<EligibilityContextRow> {
  try {
    const result = await client.query<EligibilityContextRow>(
      `SELECT office.id AS office_id,office.department_id AS office_department_id,
              office.active AS office_active,department.active AS office_department_active,
              to_char((clock_timestamp() AT TIME ZONE settings.timezone)::date,'YYYY-MM-DD') AS evaluated_on
         FROM offices office
         JOIN departments department ON department.id=office.department_id
         CROSS JOIN tenant_settings settings
         LEFT JOIN rounds round_state ON round_state.id=$1::uuid
        WHERE settings.singleton=true
          AND office.id=COALESCE(round_state.office_id,$2::uuid)
          AND (($1::uuid IS NULL AND $2::uuid IS NOT NULL)
            OR ($1::uuid IS NOT NULL AND round_state.id IS NOT NULL))
        FOR SHARE OF office,department,settings`,
      [roundId, officeId],
    );
    const context = result.rows[0];
    if (!context || !isCanonicalCivilDate(context.evaluated_on)) {
      throw new MemberEligibilityGuardError("TENANT_TIMEZONE_INVALID", "Tenant civil date cannot be evaluated");
    }
    return context;
  } catch (error) {
    if (error instanceof MemberEligibilityGuardError) throw error;
    if (postgresCode(error) === "22023") {
      throw new MemberEligibilityGuardError("TENANT_TIMEZONE_INVALID", "Tenant civil date cannot be evaluated");
    }
    throw error;
  }
}

async function loadDepartmentState(
  client: PoolClient,
  ids: readonly (string | null)[],
): Promise<ReadonlyMap<string, boolean>> {
  const unique = [...new Set(ids.filter((id): id is string => id !== null))];
  if (unique.length === 0) return new Map();
  const result = await client.query<{ id: string; active: boolean }>(
    "SELECT id,active FROM departments WHERE id=ANY($1::uuid[]) FOR SHARE",
    [unique],
  );
  return new Map(result.rows.map(({ id, active }) => [id, active]));
}

function evaluateMemberRow(
  member: MemberRow,
  context: EligibilityContextRow,
  departmentState: ReadonlyMap<string, boolean>,
) {
  return evaluateMemberEligibilityForOffice({
    eligibilityStatus: member.eligibility_status,
    available: member.available,
    archived: member.archived,
    departmentRestriction: member.eligibility_department_id,
    validUntil: member.eligibility_valid_until,
    evaluatedOn: context.evaluated_on,
    officeDepartmentId: context.office_department_id,
    ...(member.eligibility_department_id === null ? {} : {
      restrictionDepartmentActive: departmentState.get(member.eligibility_department_id) === true,
    }),
  });
}

function postgresCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}
