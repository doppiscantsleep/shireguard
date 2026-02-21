-- Add relay endpoint columns to devices table so peers can discover each other's relay slots
ALTER TABLE devices ADD COLUMN relay_host TEXT;
ALTER TABLE devices ADD COLUMN relay_port INTEGER;

-- Add auth_token to relays table so the control plane can return it to authenticated clients
ALTER TABLE relays ADD COLUMN auth_token TEXT;
