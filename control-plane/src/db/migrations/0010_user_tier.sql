-- Add tier to users table (free | solo | team)
ALTER TABLE users ADD COLUMN tier TEXT NOT NULL DEFAULT 'free';
