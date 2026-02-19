export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  SIGNALING: DurableObjectNamespace;
  METRICS_QUEUE: Queue;
  JWT_SECRET: string;
}

export interface User {
  id: string;
  email: string;
  password_hash: string;
  created_at: string;
  updated_at: string;
}

export interface ApiKey {
  id: string;
  user_id: string;
  name: string;
  key_hash: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
}

export interface Network {
  id: string;
  user_id: string;
  name: string;
  cidr: string;
  created_at: string;
}

export interface Device {
  id: string;
  user_id: string;
  network_id: string;
  name: string;
  platform: string;
  public_key: string;
  assigned_ip: string;
  endpoint: string | null;
  last_seen_at: string | null;
  created_at: string;
}

export interface MetricsBatch {
  device_id: string;
  metrics: MetricEntry[];
}

export interface MetricEntry {
  peer_device_id: string;
  latency_ms?: number;
  jitter_ms?: number;
  packet_loss_ratio?: number;
  throughput_tx_bytes?: number;
  throughput_rx_bytes?: number;
  nat_type?: string;
  connection_type?: 'direct' | 'relay';
  timestamp: string;
}

export interface JWTPayload {
  sub: string;
  email: string;
  iat: number;
  exp: number;
}
