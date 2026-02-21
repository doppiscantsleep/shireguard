-- Remove password_hash column; Apple Sign-In is the only auth method now
ALTER TABLE users DROP COLUMN password_hash;
