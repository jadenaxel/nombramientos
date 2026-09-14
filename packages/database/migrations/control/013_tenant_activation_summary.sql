-- Reconcile the only legacy shape that could have been marked active before
-- secure initial-administrator activation existed. The guards intentionally
-- avoid changing any tenant with human activity or lifecycle work.
WITH legacy_real_without_activation AS MATERIALIZED (
  SELECT tenant.id
    FROM public.tenants tenant
    JOIN public.provisioning_jobs job ON job.tenant_id = tenant.id
   WHERE tenant.kind = 'real'
     AND tenant.status = 'active'
     AND tenant.version = 1
     AND tenant.decommission_request_id IS NULL
     AND job.state = 'active'
     AND COALESCE(job.request_payload->'initialAdmin'->>'mode', 'pending') = 'pending'
     AND NOT EXISTS (
       SELECT 1 FROM public.tenant_invitations invitation
        WHERE invitation.tenant_id = tenant.id
     )
     AND NOT EXISTS (
       SELECT 1 FROM public.tenant_memberships membership
        WHERE membership.tenant_id = tenant.id
     )
), reconciled_tenants AS (
  UPDATE public.tenants tenant
     SET status = 'provisioning',
         activated_at = NULL,
         suspended_at = NULL,
         suspension_reason = NULL,
         version = tenant.version + 1,
         updated_at = clock_timestamp()
    FROM legacy_real_without_activation candidate
   WHERE tenant.id = candidate.id
  RETURNING tenant.id
)
UPDATE public.provisioning_jobs job
   SET state = 'pending_activation',
       completed_at = NULL,
       next_attempt_at = NULL,
       last_error_code = NULL,
       updated_at = clock_timestamp()
  FROM reconciled_tenants tenant
 WHERE job.tenant_id = tenant.id;

-- The API runtime must list lifecycle state without receiving SELECT on
-- provisioning_jobs, whose request_payload can contain invitation material.
-- This owner-evaluated projection exposes only the bounded platform summary.
CREATE VIEW public.platform_tenant_summaries
WITH (security_barrier = true)
AS
SELECT COALESCE(tenant.id, job.tenant_id) AS id,
       COALESCE(tenant.slug, job.request_payload->>'slug', job.requested_slug) AS slug,
       COALESCE(tenant.display_name, job.request_payload->>'displayName') AS display_name,
       COALESCE(tenant.kind, job.request_payload->>'kind') AS kind,
       CASE
         WHEN job.state = 'pending_activation' THEN 'provisioning'
         WHEN job.request_payload->'initialAdmin'->>'mode' = 'invitation'
          AND COALESCE(initial_admin.status, 'missing') NOT IN ('pending','accepting','accepted')
           THEN 'provisioning'
         ELSE COALESCE(tenant.status, 'provisioning')
       END AS status,
       COALESCE(tenant.timezone, job.request_payload->>'timezone') AS timezone,
       COALESCE(tenant.locale, job.request_payload->>'locale') AS locale,
       COALESCE(tenant.version, 0) AS version,
       job.state AS provisioning_state,
       COALESCE(job.attempt_count, 0) AS attempt_count,
       job.last_error_code,
       CASE
         WHEN initial_admin.status = 'accepted' THEN 'admin_active'
         WHEN initial_admin.status IN ('pending','accepting') THEN 'invitation_pending'
         WHEN job.state = 'pending_activation'
           OR job.request_payload->'initialAdmin'->>'mode' = 'pending'
           OR job.request_payload->'initialAdmin'->>'mode' = 'invitation' THEN 'pending_activation'
         ELSE 'active'
       END AS activation_state,
       latest_export.id AS export_id,
       latest_export.tenant_version AS export_tenant_version,
       latest_export.state AS export_state,
       latest_export.attempt_count AS export_attempt_count,
       latest_export.revision AS export_revision,
       latest_export.public_manifest AS export_public_manifest,
       latest_export.encrypted_bytes,
       latest_export.ciphertext_sha256 AS export_ciphertext_sha256,
       latest_export.recovery_point_at AS export_recovery_point_at,
       latest_export.last_error_code AS export_last_error_code,
       latest_export.created_at AS export_created_at,
       latest_export.updated_at AS export_updated_at,
       latest_export.ready_at AS export_ready_at,
       latest_export.failed_at AS export_failed_at,
       decommission.id AS decommission_id,
       decommission.state AS decommission_state,
       decommission.source_export_job_id AS decommission_export_job_id,
       decommission.reason_code AS decommission_reason_code,
       decommission.retention_until AS decommission_retention_until,
       decommission.version AS decommission_version,
       decommission.scheduled_at AS decommission_scheduled_at,
       decommission.cancelled_at AS decommission_cancelled_at,
       COALESCE(tenant.created_at, job.created_at) AS created_at,
       COALESCE(tenant.updated_at, job.updated_at) AS updated_at
  FROM public.tenants tenant
  FULL JOIN public.provisioning_jobs job ON job.tenant_id = tenant.id
  LEFT JOIN LATERAL (
    SELECT invitation.status
      FROM public.tenant_invitations invitation
     WHERE invitation.tenant_id = COALESCE(tenant.id, job.tenant_id)
       AND invitation.role_codes @> ARRAY['CHURCH_ADMIN']::text[]
     ORDER BY invitation.created_at DESC, invitation.id DESC
     LIMIT 1
  ) initial_admin ON true
  LEFT JOIN LATERAL (
    SELECT export.id, export.tenant_version, export.state, export.attempt_count, export.revision,
           export.public_manifest, export.encrypted_bytes, export.ciphertext_sha256,
           export.recovery_point_at, export.last_error_code, export.created_at, export.updated_at,
           export.ready_at, export.failed_at
      FROM public.tenant_export_jobs export
     WHERE export.tenant_id = COALESCE(tenant.id, job.tenant_id)
     ORDER BY export.created_at DESC, export.id DESC
     LIMIT 1
  ) latest_export ON true
  LEFT JOIN public.tenant_decommission_requests decommission
    ON decommission.id = tenant.decommission_request_id
 WHERE tenant.id IS NOT NULL OR job.request_payload IS NOT NULL;

COMMENT ON VIEW public.platform_tenant_summaries IS
  'Sanitized lifecycle projection for the control runtime; excludes provisioning payloads, hashes, credentials and invitation recipients.';

REVOKE ALL ON TABLE public.platform_tenant_summaries FROM PUBLIC;
