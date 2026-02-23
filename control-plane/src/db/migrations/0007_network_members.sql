-- network_members: tracks who has access to a network beyond the owner
CREATE TABLE network_members (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('admin', 'member')),
  invited_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(network_id, user_id)
);
CREATE INDEX idx_network_members_network ON network_members(network_id);
CREATE INDEX idx_network_members_user ON network_members(user_id);

-- network_invites: shareable invite links for joining a network
CREATE TABLE network_invites (
  id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL CHECK(role IN ('admin', 'member')) DEFAULT 'member',
  token TEXT NOT NULL UNIQUE,
  max_uses INTEGER NOT NULL DEFAULT 1,
  use_count INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_network_invites_token ON network_invites(token);
CREATE INDEX idx_network_invites_network ON network_invites(network_id);
