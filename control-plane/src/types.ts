export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  SIGNALING: DurableObjectNamespace;
  JWT_SECRET: string;
  APPLE_TEAM_ID: string;
  APPLE_KEY_ID: string;
  APPLE_SERVICE_ID: string;
  APPLE_PRIVATE_KEY: string; // contents of the .p8 file
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  DISCORD_WEBHOOK_URL: string;
}

export interface User {
  id: string;
  email: string;
  apple_sub: string | null;
  google_sub: string | null;
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

export interface ACLRule {
  id: string;
  description: string;
  action: 'allow' | 'block';
  protocol: 'tcp' | 'udp' | 'icmp' | 'any';
  src: string;
  dst: string;
  ports: string;
}

export interface GatekeepPolicy {
  default_action: 'allow' | 'block';
  rules: ACLRule[];
}

export interface NetworkMember {
  id: string;
  network_id: string;
  user_id: string;
  email: string;
  role: 'owner' | 'admin' | 'member';
  invited_by: string | null;
  created_at: string;
}

export interface NetworkInvite {
  id: string;
  network_id: string;
  role: 'admin' | 'member';
  token: string;
  max_uses: number;
  use_count: number;
  expires_at: string;
  created_at: string;
}

export interface JWTPayload {
  sub: string;
  email: string;
  iat: number;
  exp: number;
}
