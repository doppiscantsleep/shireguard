-- Add GitHub Sign-In support
ALTER TABLE users ADD COLUMN github_id TEXT;
CREATE UNIQUE INDEX idx_users_github_id ON users(github_id) WHERE github_id IS NOT NULL;
