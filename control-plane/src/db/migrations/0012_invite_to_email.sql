-- Track who an invite was sent to (optional, set when to_email is provided at creation)
ALTER TABLE network_invites ADD COLUMN to_email TEXT;
