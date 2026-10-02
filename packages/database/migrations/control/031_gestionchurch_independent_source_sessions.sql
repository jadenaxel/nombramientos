-- Concurrent SSO for an unchanged subject must not revoke another source session.
-- Role/context changes still revoke existing sessions before issuing new access.
DO $$
DECLARE
  original_definition text;
  patched_definition text;
BEGIN
  SELECT pg_get_functiondef(
    'sync_gestionchurch_federated_identity(uuid,text,text,text,text,text,text[],text,text)'::regprocedure
  ) INTO original_definition;
  patched_definition := replace(original_definition,
    '  synthetic_normalized_email text;',
    E'  synthetic_normalized_email text;\n  previous_role_fingerprint text;\n  previous_identity_status text;\n  previous_membership_status text;'
  );
  patched_definition := replace(patched_definition,
    '  synthetic_normalized_email :=',
    E'  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_gestionchurch_subject, 0));\n  SELECT identity.gestionchurch_role_fingerprint,identity.status,membership.status\n    INTO previous_role_fingerprint,previous_identity_status,previous_membership_status\n    FROM public.platform_identities identity\n    LEFT JOIN public.tenant_memberships membership\n      ON membership.identity_id=identity.id AND membership.tenant_id=selected_tenant.id\n   WHERE identity.gestionchurch_subject=p_gestionchurch_subject\n   FOR UPDATE OF identity;\n\n  synthetic_normalized_email :='
  );
  patched_definition := replace(patched_definition,
    'WHERE session.identity_id=selected_identity_id AND session.revoked_at IS NULL;',
    E'WHERE session.identity_id=selected_identity_id AND session.revoked_at IS NULL\n     AND (previous_role_fingerprint IS DISTINCT FROM p_role_fingerprint\n       OR previous_identity_status IS DISTINCT FROM ''active''\n       OR previous_membership_status IS DISTINCT FROM ''active'');'
  );
  IF patched_definition = original_definition
     OR position('previous_role_fingerprint IS DISTINCT FROM p_role_fingerprint' IN patched_definition)=0
     OR position('pg_advisory_xact_lock' IN patched_definition)=0 THEN
    RAISE EXCEPTION 'GestionChurch independent-session patch did not match the expected function definition';
  END IF;
  EXECUTE patched_definition;
END
$$;

REVOKE ALL ON FUNCTION sync_gestionchurch_federated_identity(
  uuid,text,text,text,text,text,text[],text,text
) FROM PUBLIC;
