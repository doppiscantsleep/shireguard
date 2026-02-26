-- Store device-to-relay latency reported by the client daemon
ALTER TABLE devices ADD COLUMN relay_latency_ms INTEGER;
