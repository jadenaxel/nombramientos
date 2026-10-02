DO $$
DECLARE
  original_definition text;
  patched_definition text;
BEGIN
  SELECT pg_get_functiondef(
    'sync_gestionchurch_federated_identity(uuid,text,text,text,text,text,text[],text,text)'::regprocedure
  ) INTO original_definition;

  patched_definition := replace(
    original_definition,
    'passkey_enabled,strong_auth_enabled,password_provisioned,gestionchurch_subject,',
    'passkey_enabled,password_provisioned,gestionchurch_subject,'
  );
  patched_definition := replace(
    patched_definition,
    '''active'',false,false,false,false,false,p_gestionchurch_subject,p_gestionchurch_roles,p_role_fingerprint',
    '''active'',false,false,false,false,p_gestionchurch_subject,p_gestionchurch_roles,p_role_fingerprint'
  );
  patched_definition := replace(
    patched_definition,
    E'        strong_auth_enabled=false,\n',
    ''
  );

  IF patched_definition = original_definition OR position('strong_auth_enabled' IN patched_definition) <> 0 THEN
    RAISE EXCEPTION 'GestionChurch federation generated-column patch did not match the expected function definition';
  END IF;
  EXECUTE patched_definition;
END
$$;

REVOKE ALL ON FUNCTION sync_gestionchurch_federated_identity(
  uuid,text,text,text,text,text,text[],text,text
) FROM PUBLIC;
