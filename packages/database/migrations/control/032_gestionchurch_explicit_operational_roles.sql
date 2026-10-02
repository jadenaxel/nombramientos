-- Add explicit central commission/custody assignments without changing accounts,
-- memberships, existing assignments, or the independent-source-session policy.
DO $$
DECLARE
  original_definition text;
  patched_definition text;
BEGIN
  SELECT pg_get_functiondef(
    'sync_gestionchurch_federated_identity(uuid,text,text,text,text,text,text[],text,text)'::regprocedure
  ) INTO original_definition;
  patched_definition := replace(original_definition,
    'cardinality(p_gestionchurch_roles) NOT BETWEEN 1 AND 12',
    'cardinality(p_gestionchurch_roles) NOT BETWEEN 1 AND 14'
  );
  patched_definition := replace(patched_definition,
    '''NOMINATIONS_USER'',''VIEWER'',''AUDITOR''',
    '''NOMINATIONS_USER'',''VIEWER'',''AUDITOR'',''NOMINATIONS_COMMISSION_MEMBER'',''NOMINATIONS_BALLOT_CUSTODIAN'''
  );
  IF patched_definition = original_definition
     OR position('NOMINATIONS_COMMISSION_MEMBER' IN patched_definition)=0
     OR position('NOMINATIONS_BALLOT_CUSTODIAN' IN patched_definition)=0
     OR position('cardinality(p_gestionchurch_roles) NOT BETWEEN 1 AND 14' IN patched_definition)=0
     OR position('previous_role_fingerprint IS DISTINCT FROM p_role_fingerprint' IN patched_definition)=0
     OR position('pg_advisory_xact_lock' IN patched_definition)=0 THEN
    RAISE EXCEPTION 'GestionChurch explicit-role patch did not match the expected function definition';
  END IF;
  EXECUTE patched_definition;
END
$$;

ALTER TABLE platform_identities
  DROP CONSTRAINT platform_identities_gestionchurch_federation_complete;
ALTER TABLE platform_identities
  ADD CONSTRAINT platform_identities_gestionchurch_federation_complete CHECK (
    (gestionchurch_subject IS NULL AND gestionchurch_roles IS NULL AND gestionchurch_role_fingerprint IS NULL)
    OR
    (gestionchurch_subject IS NOT NULL
      AND cardinality(gestionchurch_roles) BETWEEN 1 AND 14
      AND gestionchurch_role_fingerprint ~ '^[0-9a-f]{64}$')
  );

REVOKE ALL ON FUNCTION sync_gestionchurch_federated_identity(
  uuid,text,text,text,text,text,text[],text,text
) FROM PUBLIC;
