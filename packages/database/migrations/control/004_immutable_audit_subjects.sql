-- Audit subject identifiers are immutable snapshots, not lifecycle-managed
-- relational pointers. ON DELETE SET NULL rewrites signed/hash-chained history
-- when an identity or tenant is removed, invalidating every affected event.
ALTER TABLE platform_audit_events
DROP CONSTRAINT IF EXISTS platform_audit_events_actor_identity_id_fkey;

ALTER TABLE platform_audit_events
DROP CONSTRAINT IF EXISTS platform_audit_events_tenant_id_fkey;
