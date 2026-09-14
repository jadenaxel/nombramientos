-- Runtime authentication must serialize session issuance with identity,
-- membership, tenant, and identity-policy transitions.  The runtime role is
-- intentionally not allowed to UPDATE tenant or membership rows, so it cannot
-- take the required row locks directly.  Expose only this boolean, fixed-scope
-- SECURITY DEFINER boundary instead of widening table privileges.
CREATE FUNCTION lock_active_authentication_context(
  p_identity_id uuid,
  p_tenant_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_identity_id IS NULL OR p_tenant_id IS NULL THEN
    RETURN false;
  END IF;

  -- Policy writes and invitation acceptance use the same transaction-scoped
  -- advisory lock.  Taking it before row locks gives every authentication path
  -- one ordering boundary and prevents a session from being minted against a
  -- policy snapshot that changes concurrently.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('tenant_identity_policy:' || p_tenant_id::text, 0)
  );

  PERFORM 1
    FROM public.platform_identities identity
    JOIN public.tenant_memberships membership
      ON membership.identity_id = identity.id
     AND membership.tenant_id = p_tenant_id
    JOIN public.tenants tenant
      ON tenant.id = membership.tenant_id
   WHERE identity.id = p_identity_id
     AND identity.status = 'active'
     AND membership.status = 'active'
     AND tenant.status = 'active'
   FOR SHARE OF identity, membership, tenant;

  RETURN FOUND;
END
$$;

REVOKE ALL ON FUNCTION lock_active_authentication_context(uuid,uuid) FROM PUBLIC;

COMMENT ON FUNCTION lock_active_authentication_context(uuid,uuid) IS
  'Fail-closed transaction lock for runtime session issuance; returns only whether the exact identity/tenant membership is active.';
