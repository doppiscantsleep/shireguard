import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';
import { checkRateLimit } from '../auth/ratelimit';
import { logAudit } from '../lib/audit';
import { getUserTier, TIER_LIMITS } from '../lib/tiers';

/** A valid WireGuard public key is exactly 32 bytes encoded as standard base64 (44 chars, trailing '='). */
function isValidWireGuardKey(key: string): boolean {
  if (key.length !== 44 || !key.endsWith('=')) return false;
  try {
    const decoded = atob(key);
    return decoded.length === 32;
  } catch {
    return false;
  }
}

const devices = new Hono<{ Bindings: Env }>();
devices.use('*', authMiddleware);

// POST /devices - Register a new device
devices.post('/', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, { action: 'device-register', limit: 5, windowSeconds: 60 });
  if (rl.limited) {
    return c.json({ error: 'Too many requests. Try again later.' }, 429, { 'Retry-After': String(rl.retryAfter) });
  }

  const userId = c.get('userId');
  const body = await c.req.json<{
    name: string;
    platform: string;
    public_key: string;
    network_id: string;
  }>();

  if (!body.name || !body.platform || !body.public_key || !body.network_id) {
    return c.json({ error: 'name, platform, public_key, and network_id are required' }, 400);
  }

  if (!['macos', 'linux', 'raspberrypi'].includes(body.platform)) {
    return c.json({ error: 'Platform must be macos, linux, or raspberrypi' }, 400);
  }

  if (!isValidWireGuardKey(body.public_key)) {
    return c.json({ error: 'Invalid public_key: must be a 44-character base64-encoded 32-byte WireGuard key' }, 400);
  }

  // Enforce tier device limit (counts all devices owned by this user across all networks)
  const [tier, deviceCount] = await Promise.all([
    getUserTier(c.env.DB, userId),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM devices WHERE user_id = ?')
      .bind(userId)
      .first<{ count: number }>(),
  ]);
  const limit = TIER_LIMITS[tier].devices;
  if ((deviceCount?.count ?? 0) >= limit) {
    return c.json({
      error: `${tier === 'free' ? 'Free plan' : 'Your plan'} is limited to ${limit} devices. Upgrade to add more.`,
      upgrade_required: true,
    }, 403);
  }

  // Verify the user owns or is a member of the network
  const network = await c.env.DB.prepare(`
    SELECT id, cidr FROM networks WHERE id = ? AND user_id = ?
    UNION
    SELECT n.id, n.cidr FROM networks n
    JOIN network_members nm ON nm.network_id = n.id AND nm.user_id = ?
    WHERE n.id = ?
    LIMIT 1
  `)
    .bind(body.network_id, userId, userId, body.network_id)
    .first<{ id: string; cidr: string }>();

  if (!network) {
    return c.json({ error: 'Network not found' }, 404);
  }

  // Assign next available IP in the network CIDR
  const assignedIp = await getNextIp(c.env.DB, body.network_id, network.cidr);
  if (!assignedIp) {
    return c.json({ error: 'No available IPs in network' }, 409);
  }

  const deviceId = crypto.randomUUID();

  try {
    await c.env.DB.prepare(
      'INSERT INTO devices (id, user_id, network_id, name, platform, public_key, assigned_ip) VALUES (?, ?, ?, ?, ?, ?, ?)'
    )
      .bind(deviceId, userId, body.network_id, body.name, body.platform, body.public_key, assignedIp)
      .run();
  } catch (e: unknown) {
    if (e instanceof Error && e.message.includes('UNIQUE')) {
      return c.json({ error: 'Device with this public key already exists' }, 409);
    }
    throw e;
  }

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'device.register',
    resourceType: 'device',
    resourceId: deviceId,
    detail: `Registered "${body.name}" (${body.platform})`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId: body.network_id,
  }));

  return c.json({
    id: deviceId,
    name: body.name,
    platform: body.platform,
    public_key: body.public_key,
    network_id: body.network_id,
    assigned_ip: assignedIp,
  }, 201);
});

// GET /devices - List devices
// With ?network_id and caller is owner/admin: returns ALL devices in that network with owner_email.
// Otherwise: returns the caller's own devices.
devices.get('/', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.query('network_id');
  const now = Date.now();

  if (networkId) {
    // Check if caller is owner or admin of this network
    const access = await c.env.DB.prepare(`
      SELECT 'owner' AS role FROM networks WHERE id = ? AND user_id = ?
      UNION
      SELECT role FROM network_members WHERE network_id = ? AND user_id = ? AND role = 'admin'
      LIMIT 1
    `)
      .bind(networkId, userId, networkId, userId)
      .first<{ role: string }>();

    if (access) {
      // Owner/admin: return all devices in the network with owner info
      const result = await c.env.DB.prepare(`
        SELECT d.id, d.name, d.platform, d.public_key, d.network_id, d.assigned_ip,
               d.endpoint, d.last_seen_at, d.created_at, d.user_id, d.client_version,
               u.email AS owner_email
        FROM devices d
        JOIN users u ON u.id = d.user_id
        WHERE d.network_id = ?
        ORDER BY d.assigned_ip
      `)
        .bind(networkId)
        .all();

      const devices = result.results.map((d: Record<string, unknown>) => ({
        ...d,
        online: d.last_seen_at ? now - new Date(d.last_seen_at as string).getTime() < 120_000 : false,
        is_own: d.user_id === userId,
      }));

      return c.json({ devices, caller_role: access.role });
    }
  }

  // Default: return caller's own devices, optionally filtered by network
  let query = 'SELECT id, name, platform, public_key, network_id, assigned_ip, endpoint, last_seen_at, created_at, client_version FROM devices WHERE user_id = ?';
  const params: string[] = [userId];
  if (networkId) {
    query += ' AND network_id = ?';
    params.push(networkId);
  }
  query += ' ORDER BY created_at DESC';

  const result = await c.env.DB.prepare(query).bind(...params).all();
  const devices = result.results.map((d: Record<string, unknown>) => ({
    ...d,
    online: d.last_seen_at ? now - new Date(d.last_seen_at as string).getTime() < 120_000 : false,
    is_own: true,
  }));

  return c.json({ devices, caller_role: 'member' });
});

// GET /devices/:id
devices.get('/:id', async (c) => {
  const userId = c.get('userId');
  const deviceId = c.req.param('id');

  const device = await c.env.DB.prepare(
    'SELECT * FROM devices WHERE id = ? AND user_id = ?'
  )
    .bind(deviceId, userId)
    .first();

  if (!device) {
    return c.json({ error: 'Device not found' }, 404);
  }

  return c.json({ device });
});

// PATCH /devices/:id - Update device
devices.patch('/:id', async (c) => {
  const userId = c.get('userId');
  const deviceId = c.req.param('id');
  const body = await c.req.json<{ name?: string; endpoint?: string }>();

  const sets: string[] = [];
  const params: (string | null)[] = [];

  if (body.name !== undefined) {
    sets.push('name = ?');
    params.push(body.name);
  }
  if (body.endpoint !== undefined) {
    sets.push('endpoint = ?');
    params.push(body.endpoint);
  }

  if (sets.length === 0) {
    return c.json({ error: 'No fields to update' }, 400);
  }

  params.push(deviceId, userId);

  const result = await c.env.DB.prepare(
    `UPDATE devices SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`
  )
    .bind(...params)
    .run();

  if (!result.meta.changes) {
    return c.json({ error: 'Device not found' }, 404);
  }

  return c.json({ updated: true });
});

// DELETE /devices/:id
devices.delete('/:id', async (c) => {
  const userId = c.get('userId');
  const deviceId = c.req.param('id');

  const result = await c.env.DB.prepare('DELETE FROM devices WHERE id = ? AND user_id = ?')
    .bind(deviceId, userId)
    .run();

  if (!result.meta.changes) {
    return c.json({ error: 'Device not found' }, 404);
  }

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'device.remove',
    resourceType: 'device',
    resourceId: deviceId,
    ip: c.req.header('CF-Connecting-IP') ?? null,
  }));

  return c.json({ deleted: true });
});

// POST /devices/:id/heartbeat - Device heartbeat
// No KV rate limit here — heartbeats are authenticated (JWT) and only update
// the caller's own device record. Adding a per-IP KV counter would burn
// through the free-tier KV write budget (1,000/day) with just a few devices.
devices.post('/:id/heartbeat', async (c) => {
  const userId = c.get('userId');
  const deviceId = c.req.param('id');
  const body = await c.req.json<{ endpoint?: string; client_version?: string }>().catch(() => ({} as { endpoint?: string; client_version?: string }));

  const sets = ["last_seen_at = datetime('now')"];
  const params: string[] = [];

  if (body.endpoint) {
    sets.push('endpoint = ?');
    params.push(body.endpoint);
  }

  if (body.client_version) {
    sets.push('client_version = ?');
    params.push(body.client_version);
  }

  params.push(deviceId, userId);

  await c.env.DB.prepare(
    `UPDATE devices SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`
  )
    .bind(...params)
    .run();

  return c.json({ ok: true });
});

// Helper: get next available IP in a CIDR
async function getNextIp(db: D1Database, networkId: string, cidr: string): Promise<string | null> {
  // Parse CIDR (e.g., 100.65.0.0/16)
  const [base, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr);
  const parts = base.split('.').map(Number);
  const baseNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const hostBits = 32 - prefix;
  const maxHosts = (2 ** hostBits) - 2; // Exclude network and broadcast

  // Get existing assigned IPs
  const existing = await db
    .prepare('SELECT assigned_ip FROM devices WHERE network_id = ?')
    .bind(networkId)
    .all();

  const usedIps = new Set(existing.results.map((r: Record<string, unknown>) => r.assigned_ip as string));

  // Start from .1 (skip .0 network address)
  for (let i = 1; i <= maxHosts; i++) {
    const ipNum = baseNum + i;
    const ip = `${(ipNum >> 24) & 0xff}.${(ipNum >> 16) & 0xff}.${(ipNum >> 8) & 0xff}.${ipNum & 0xff}`;
    if (!usedIps.has(ip)) {
      return ip;
    }
  }

  return null;
}

export { devices };
