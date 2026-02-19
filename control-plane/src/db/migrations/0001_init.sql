-- Users
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- API keys
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  prefix TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  expires_at TEXT
);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(prefix);

-- Networks
CREATE TABLE networks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  cidr TEXT NOT NULL DEFAULT '10.100.0.0/24',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_networks_user ON networks(user_id);

-- Devices
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  public_key TEXT NOT NULL,
  assigned_ip TEXT NOT NULL,
  endpoint TEXT,
  last_seen_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_devices_network ON devices(network_id);
CREATE UNIQUE INDEX idx_devices_pubkey ON devices(public_key);

-- Metrics (time-bucketed aggregates)
CREATE TABLE metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  peer_device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
  bucket TEXT NOT NULL,
  bucket_size TEXT NOT NULL DEFAULT '1m',
  latency_ms REAL,
  jitter_ms REAL,
  packet_loss_ratio REAL,
  throughput_tx_bytes INTEGER,
  throughput_rx_bytes INTEGER,
  nat_type TEXT,
  connection_type TEXT DEFAULT 'direct',
  quality_score INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_metrics_device ON metrics(device_id, bucket);
CREATE INDEX idx_metrics_peer ON metrics(peer_device_id, bucket);

-- Relay servers
CREATE TABLE relays (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  region TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Audit log
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  detail TEXT,
  ip TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_user ON audit_log(user_id, created_at);
