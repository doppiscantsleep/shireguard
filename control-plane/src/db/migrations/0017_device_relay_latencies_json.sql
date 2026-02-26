-- Replace single relay_latency_ms with JSON map of host → ms for all relays
ALTER TABLE devices ADD COLUMN relay_latencies TEXT;
