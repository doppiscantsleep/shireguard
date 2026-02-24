-- Add tls_enabled flag to relays table so the control plane knows whether to
-- use https:// when proxying requests to the relay HTTP API.
ALTER TABLE relays ADD COLUMN tls_enabled INTEGER NOT NULL DEFAULT 0;
