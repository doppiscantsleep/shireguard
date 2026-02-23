-- Add network_id to audit_log for per-network scoping
ALTER TABLE audit_log ADD COLUMN network_id TEXT REFERENCES networks(id) ON DELETE SET NULL;
CREATE INDEX idx_audit_network ON audit_log(network_id, created_at);
