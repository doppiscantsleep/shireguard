-- gatekeep_policies: per-network ACL policy stored as JSON
CREATE TABLE gatekeep_policies (
  network_id TEXT PRIMARY KEY REFERENCES networks(id) ON DELETE CASCADE,
  policy TEXT NOT NULL DEFAULT '{"default_action":"allow","rules":[]}',
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
