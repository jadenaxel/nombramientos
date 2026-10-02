-- The shared login must expire/revoke alongside its original GestionChurch session.
-- Existing unbound federated sessions fail closed and can be reopened through SSO.
ALTER TABLE public.auth_sessions ADD COLUMN gestionchurch_source_session_id uuid;
