import path from "node:path";
import { Pool } from "pg";
import { runMigrations } from "../src/migrations.js";
import { loadLocalScriptEnvironment, resolveDatabasePackageRoot, withoutDatabase } from "./script-config.js";

const environment = loadLocalScriptEnvironment();
const controlDatabase = "nombramientos_control";
const adminUrl = withoutDatabase(environment.DATABASE_ADMIN_URL);
const admin = new Pool({ connectionString: adminUrl, max: 1 });
const controlRuntimeUrl = environment.DATABASE_CONTROL_URL;
const recoveryDeliveryWorkerRole = "nom_control_recovery_delivery_worker";
let controlRuntimeRole: string | undefined;
try {
  const deliveryRoleExists = await admin.query("SELECT 1 FROM pg_roles WHERE rolname=$1", [recoveryDeliveryWorkerRole]);
  if (deliveryRoleExists.rowCount === 0) {
    await executeFormatted(
      admin,
      "SELECT format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', $1::text) AS sql",
      [recoveryDeliveryWorkerRole],
    );
  }
  if (controlRuntimeUrl) {
    const runtime = new URL(controlRuntimeUrl);
    const administrator = new URL(environment.DATABASE_ADMIN_URL);
    if (runtime.hostname !== administrator.hostname || runtime.port !== administrator.port) {
      throw new Error("DATABASE_CONTROL_URL must target the same local PostgreSQL cluster as DATABASE_ADMIN_URL");
    }
    controlRuntimeRole = decodeURIComponent(runtime.username);
    const controlPassword = decodeURIComponent(runtime.password);
    if (!controlRuntimeRole || controlRuntimeRole === decodeURIComponent(administrator.username) || controlPassword.length < 16) {
      throw new Error("DATABASE_CONTROL_URL must use a distinct runtime role and a strong per-install password");
    }
    const roleExists = await admin.query("SELECT 1 FROM pg_roles WHERE rolname=$1", [controlRuntimeRole]);
    const roleStatement = roleExists.rowCount === 0
      ? "SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L', $1::text, $2::text) AS sql"
      : "SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text) AS sql";
    await executeFormatted(admin, roleStatement, [controlRuntimeRole, controlPassword]);
  }
  const exists = await admin.query("SELECT 1 FROM pg_database WHERE datname=$1", [controlDatabase]);
  if (exists.rowCount === 0) {
    const formatted = await admin.query<{ sql: string }>(
      "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
      [controlDatabase],
    );
    const sql = formatted.rows[0]?.sql;
    if (!sql) throw new Error("Could not format control database creation statement");
    await admin.query(sql);
  }
  await executeFormatted(admin, "SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', $1::text) AS sql", [controlDatabase]);
  if (controlRuntimeRole) {
    await executeFormatted(admin, "SELECT format('GRANT CONNECT ON DATABASE %I TO %I', $1::text, $2::text) AS sql", [controlDatabase, controlRuntimeRole]);
  }
} finally {
  await admin.end();
}

const controlAdminUrl = withoutDatabase(environment.DATABASE_ADMIN_URL, controlDatabase);
const control = new Pool({ connectionString: controlAdminUrl, application_name: "nombramientos-control-migrate", max: 1 });
try {
  const packageRoot = resolveDatabasePackageRoot(import.meta.url);
  const applied = await runMigrations(control, {
    scope: "control",
    directory: path.join(packageRoot, "migrations", "control"),
  });
  if (controlRuntimeRole) await applyControlRuntimeGrants(control, controlRuntimeRole);
  await applyRecoveryDeliveryWorkerGrants(control, recoveryDeliveryWorkerRole);
  process.stdout.write(`Control database ready. Applied ${applied.length} migration(s).\n`);
} finally {
  await control.end();
}

if (controlRuntimeUrl) {
  const runtime = new Pool({ connectionString: controlRuntimeUrl, application_name: "nombramientos-control-check", max: 1 });
  try {
    await runtime.query("SELECT count(*)::int FROM tenants");
  } finally {
    await runtime.end();
  }
}

async function executeFormatted(
  pool: Pool,
  query: string,
  values: readonly unknown[],
): Promise<void> {
  const result = await pool.query<{ sql: string }>(query, [...values]);
  const sql = result.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format an administrative statement");
  await pool.query(sql);
}

async function applyControlRuntimeGrants(pool: Pool, role: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("REVOKE ALL ON SCHEMA public FROM PUBLIC");
    await executeClientFormatted(client, "SELECT format('GRANT USAGE ON SCHEMA public TO %I', $1::text) AS sql", [role]);
    await executeClientFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I', $1::text) AS sql", [role]);
    await executeClientFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %I', $1::text) AS sql", [role]);
    await client.query("REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC");
    await executeClientFormatted(client, "SELECT format('REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM %I', $1::text) AS sql", [role]);
    await executeClientFormatted(client, "SELECT format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %I', $1::text) AS sql", [role]);
    await executeClientFormatted(client, "SELECT format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I', $1::text) AS sql", [role]);
    await client.query("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC");
    await executeClientFormatted(client, "SELECT format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM %I', $1::text) AS sql", [role]);

    for (const table of [
      "tenants", "platform_worker_status", "platform_role_bindings", "platform_identities", "tenant_memberships",
    ]) {
      await grantControlTablePrivileges(client, role, table, "SELECT");
    }
    await grantControlTablePrivileges(client, role, "platform_tenant_summaries", "SELECT");
    await grantControlTablePrivileges(client, role, "identity_policy_baseline", "SELECT");
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT SELECT(id,tenant_id,tenant_version,state,attempt_count,revision,public_manifest,encrypted_bytes,ciphertext_sha256,recovery_point_at,last_error_code,created_at,updated_at,ready_at,failed_at) ON TABLE tenant_export_jobs TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT SELECT(id,state,source_export_job_id,reason_code,retention_until,version,scheduled_at,cancelled_at) ON TABLE tenant_decommission_requests TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    // token_hash is a verifier, never a bearer and never runtime-readable.
    // Bearer-dependent operations cross raw-preimage SECURITY DEFINER gates
    // that hash internally; all ordinary reads stay column-scoped.
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT SELECT(id,tenant_id,email,normalized_email,role_codes,status,created_by_identity_id,authority_kind,authority_epoch,acceptance_attempt,created_at,updated_at,expires_at,acceptance_id,acceptance_identity_id,acceptance_started_at,accepted_at,consumed_at,authority_finalized_at,tenant_cleanup_completed_at,revoked_at,revoked_by_identity_id,revocation_reason,last_error_code,version) ON TABLE tenant_invitations TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT INSERT(tenant_id,email,normalized_email,role_codes,token_hash,expires_at,idempotency_key,request_hash,created_by_identity_id) ON TABLE tenant_invitations TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    for (const table of [
      "mfa_challenges",
      "mfa_recovery_codes",
      "tenant_identity_policies",
      "webauthn_credentials",
      "webauthn_ceremonies",
      "authentication_step_up_grants",
    ]) {
      await grantControlTablePrivileges(client, role, table, "SELECT,INSERT");
    }
    await grantControlTablePrivileges(client, role, "auth_sessions", "SELECT");
    // enrollment_source and invitation_id are intentionally absent: only the
    // guarded SECURITY DEFINER invitation completion may mint an invitation-
    // bound enrollment-only session.
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT INSERT(id,token_hash,csrf_hash,identity_id,active_tenant_id,user_agent_hash,ip_prefix_hash,created_at,last_seen_at,expires_at,revoked_at,revoke_reason,assurance_level,authenticated_at,mfa_verified_at,auth_method,aal,phishing_resistant,authenticated_credential_id,recovery_limited,idle_timeout_minutes,idle_expires_at,last_user_agent_hash,user_agent_change_count,user_agent_context_changed_at,last_ip_prefix_hash,ip_change_count,ip_context_changed_at,device_label,step_up_verified_at,step_up_method,step_up_credential_id,step_up_purpose,step_up_operation_hash,step_up_expires_at) ON TABLE auth_sessions TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await grantControlTablePrivileges(client, role, "platform_audit_events", "SELECT,INSERT");
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT UPDATE(failed_login_count,locked_until,updated_at,mfa_enabled,totp_secret_ciphertext,mfa_enrollment_id,mfa_enrollment_secret_ciphertext,mfa_enrollment_started_at,mfa_enrolled_at,mfa_recovery_generation,mfa_last_used_step,passkey_enabled,passkey_enrolled_at) ON TABLE platform_identities TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT EXECUTE ON FUNCTION queue_platform_tenant_provisioning(uuid,uuid,text,text,text,text,text,text,text,text,text,timestamptz,integer,text,uuid,uuid) TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT EXECUTE ON FUNCTION activate_platform_tenant_initial_admin(uuid,integer,text,text,text,timestamptz,uuid,text,uuid) TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT EXECUTE ON FUNCTION lock_active_authentication_context(uuid,uuid) TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    for (const signature of [
      "lock_active_invitation_grantor(uuid,uuid,uuid,text)",
      "find_tenant_invitation_idempotency(uuid,uuid,uuid)",
      "inspect_tenant_invitation_bearer(text,text,text)",
      "begin_tenant_invitation_acceptance(uuid,text,text,text,uuid,uuid,text,uuid,uuid)",
      "begin_tenant_invitation_compensation(uuid,uuid,uuid,integer)",
      "recover_tenant_invitation_enrollment_session(uuid,text,text,text,uuid,text,text,timestamptz,text,text)",
      "mark_tenant_invitation_authority_finalized(uuid,uuid,uuid,integer)",
      "mark_tenant_invitation_cleanup_completed(uuid,uuid,uuid,integer)",
      "claim_tenant_invitation_reconciliation(uuid)",
      "finish_tenant_invitation_reconciliation(uuid,uuid,uuid,integer,uuid,boolean,text)",
      "list_initial_admin_onboarding_recovery_candidates(uuid,uuid,uuid,integer)",
      "expire_stale_initial_admin_onboarding_recoveries(uuid,uuid,uuid,uuid)",
      "list_initial_admin_onboarding_recoveries(uuid,uuid,uuid,text,timestamptz,uuid,integer)",
      "get_initial_admin_onboarding_recovery_approval_context(uuid,uuid,uuid)",
      "get_initial_admin_onboarding_recovery_summary(uuid,uuid,uuid)",
      "request_initial_admin_onboarding_recovery(uuid,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,uuid,text,text,text,timestamptz,uuid)",
      "approve_initial_admin_onboarding_recovery(uuid,integer,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,text,timestamptz,text,text,uuid)",
      "redeem_initial_admin_onboarding_recovery(uuid,text,text[],uuid,text,text,timestamptz,text,text,uuid)",
      "revoke_initial_admin_onboarding_recovery(uuid,integer,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,text,uuid)",
      "authorize_initial_admin_recovery_factor_transaction(uuid,uuid)",
      "finalize_initial_admin_onboarding_recovery(uuid,uuid,uuid)",
    ]) {
      await executeClientFormatted(
        client,
        "SELECT format('GRANT EXECUTE ON FUNCTION %s TO %I', $1::text, $2::text) AS sql",
        [signature, role],
      );
    }
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT EXECUTE ON FUNCTION suspend_platform_tenant(uuid,integer,text,uuid) TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    for (const signature of [
      "queue_platform_tenant_export(uuid,integer,uuid,text,uuid,uuid)",
      "authorize_platform_tenant_export_download(uuid,uuid,uuid,timestamptz,uuid,text,uuid)",
      "consume_platform_tenant_export_download(uuid,uuid,uuid,uuid)",
      "revoke_platform_tenant_export_download(uuid,integer,uuid)",
      "schedule_platform_tenant_decommission(uuid,integer,uuid,integer,text,uuid,text,uuid)",
      "cancel_platform_tenant_decommission(uuid,uuid,integer,uuid,text,uuid)",
      "reactivate_platform_tenant(uuid,integer,text,uuid,text,uuid,uuid)",
    ]) {
      await executeClientFormatted(
        client,
        "SELECT format('GRANT EXECUTE ON FUNCTION %s TO %I', $1::text, $2::text) AS sql",
        [signature, role],
      );
    }
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT EXECUTE ON FUNCTION consume_platform_admin_bootstrap(text,text,text,text,text,uuid,uuid,text,text,timestamptz,text,text) TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT UPDATE(last_seen_at,idle_expires_at,last_user_agent_hash,user_agent_change_count,user_agent_context_changed_at,last_ip_prefix_hash,ip_change_count,ip_context_changed_at,revoked_at,revoke_reason,step_up_verified_at,step_up_method,step_up_credential_id,step_up_purpose,step_up_operation_hash,step_up_expires_at) ON TABLE auth_sessions TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      "SELECT format('GRANT UPDATE(attempt_count,consumed_at) ON TABLE mfa_challenges TO %I', $1::text) AS sql",
      [role],
    );
    await executeClientFormatted(
      client,
      "SELECT format('GRANT UPDATE(consumed_at,revoked_at) ON TABLE mfa_recovery_codes TO %I', $1::text) AS sql",
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT UPDATE(display_name,sign_count,backup_state,last_used_at,last_used_session_id,revoked_at,revoked_by_identity_id,revocation_reason,version) ON TABLE webauthn_credentials TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      "SELECT format('GRANT UPDATE(attempt_count,consumed_at,failed_at) ON TABLE webauthn_ceremonies TO %I', $1::text) AS sql",
      [role],
    );
    await executeClientFormatted(
      client,
      "SELECT format('GRANT UPDATE(consumed_at,revoked_at) ON TABLE authentication_step_up_grants TO %I', $1::text) AS sql",
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT UPDATE(enforcement_mode,minimum_aal,privileged_minimum_aal,require_user_verification,require_phishing_resistant_for_privileged,require_device_bound_for_privileged,require_attestation_for_privileged,allow_password,allow_totp_fallback,allow_recovery_codes,allow_synced_passkeys,minimum_passkey_count,privileged_minimum_passkey_count,maximum_passkeys,maximum_active_sessions,idle_timeout_minutes,absolute_session_minutes,step_up_ttl_seconds,action_requirements,changed_by_identity_id,version,updated_at) ON TABLE tenant_identity_policies TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    for (const signature of [
      "identity_action_requirements_are_valid(jsonb)",
      "identity_action_requirements_tighten(jsonb,jsonb)",
      "webauthn_rp_id_is_valid(text)",
    ]) {
      await executeClientFormatted(
        client,
        "SELECT format('GRANT EXECUTE ON FUNCTION %s TO %I', $1::text, $2::text) AS sql",
        [signature, role],
      );
    }
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT UPDATE(status,updated_at,acceptance_id,acceptance_identity_id,acceptance_started_at,acceptance_recovery_hash,revoked_at,revoked_by_identity_id,revocation_reason,last_error_code,version) ON TABLE tenant_invitations TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      "SELECT format('GRANT EXECUTE ON FUNCTION tenant_invitation_roles_are_valid(text[]) TO %I', $1::text) AS sql",
      [role],
    );
    await executeClientFormatted(
      client,
      `SELECT format(
         'GRANT EXECUTE ON FUNCTION complete_tenant_invitation_acceptance(uuid,uuid,uuid,integer,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text) TO %I',
         $1::text
       ) AS sql`,
      [role],
    );
    await executeClientFormatted(
      client,
      "SELECT format('GRANT USAGE,SELECT ON SEQUENCE platform_audit_events_sequence_seq TO %I', $1::text) AS sql",
      [role],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function applyRecoveryDeliveryWorkerGrants(pool: Pool, role: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await executeClientFormatted(
      client,
      "SELECT format('GRANT USAGE ON SCHEMA public TO %I', $1::text) AS sql",
      [role],
    );
    await executeClientFormatted(
      client,
      "SELECT format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I', $1::text) AS sql",
      [role],
    );
    await executeClientFormatted(
      client,
      "SELECT format('REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM %I', $1::text) AS sql",
      [role],
    );
    for (const signature of [
      "confirm_initial_admin_onboarding_recovery_delivery(uuid,integer,uuid,text,uuid)",
      "fail_initial_admin_onboarding_recovery_delivery(uuid,integer,uuid,text,uuid)",
    ]) {
      await executeClientFormatted(
        client,
        "SELECT format('GRANT EXECUTE ON FUNCTION %s TO %I', $1::text, $2::text) AS sql",
        [signature, role],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function grantControlTablePrivileges(
  client: import("pg").PoolClient,
  role: string,
  table: string,
  privileges: "SELECT" | "SELECT,INSERT",
): Promise<void> {
  await executeClientFormatted(
    client,
    `SELECT format('GRANT ${privileges} ON TABLE %I TO %I', $1::text, $2::text) AS sql`,
    [table, role],
  );
}

async function executeClientFormatted(
  client: import("pg").PoolClient,
  query: string,
  values: readonly unknown[],
): Promise<void> {
  const result = await client.query<{ sql: string }>(query, [...values]);
  const sql = result.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format a grant statement");
  await client.query(sql);
}
