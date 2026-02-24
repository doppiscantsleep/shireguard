-- advertised_routes: devices can advertise local subnets through the mesh.
-- Routes require owner/admin approval before peers receive them in AllowedIPs.
CREATE TABLE advertised_routes (
  id          TEXT PRIMARY KEY,
  network_id  TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  cidr        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
  description TEXT,
  approved_by TEXT REFERENCES users(id),
  approved_at TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(network_id, device_id, cidr)
);
CREATE INDEX idx_advertised_routes_network ON advertised_routes(network_id);
CREATE INDEX idx_advertised_routes_device  ON advertised_routes(device_id);
CREATE INDEX idx_advertised_routes_status  ON advertised_routes(network_id, status);
