import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';
import { checkRateLimit } from '../auth/ratelimit';
import { logAudit } from '../lib/audit';
import { sendEmail, inviteEmailHtml } from '../lib/email';
import { getUserTier, TIER_LIMITS } from '../lib/tiers';

const networks = new Hono<{ Bindings: Env }>();
networks.use('*', authMiddleware);

// ── Role helper ──
// Returns 'owner' | 'admin' | 'member' | null
async function getNetworkRole(
  db: D1Database,
  networkId: string,
  userId: string,
): Promise<'owner' | 'admin' | 'member' | null> {
  const owner = await db
    .prepare('SELECT id FROM networks WHERE id = ? AND user_id = ?')
    .bind(networkId, userId)
    .first<{ id: string }>();
  if (owner) return 'owner';

  const member = await db
    .prepare('SELECT role FROM network_members WHERE network_id = ? AND user_id = ?')
    .bind(networkId, userId)
    .first<{ role: 'admin' | 'member' }>();
  return member ? member.role : null;
}

// POST /networks - Create a new network
networks.post('/', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, { action: 'network-create', limit: 3, windowSeconds: 60 });
  if (rl.limited) {
    return c.json({ error: 'Too many requests. Try again later.' }, 429, { 'Retry-After': String(rl.retryAfter) });
  }

  const userId = c.get('userId');
  const body = await c.req.json<{ name: string; cidr?: string }>();

  if (!body.name) {
    return c.json({ error: 'Name is required' }, 400);
  }

  // Enforce tier network limit (owned networks only)
  const [tier, networkCount] = await Promise.all([
    getUserTier(c.env.DB, userId),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM networks WHERE user_id = ?')
      .bind(userId)
      .first<{ count: number }>(),
  ]);
  const netLimit = TIER_LIMITS[tier].networks;
  if ((networkCount?.count ?? 0) >= netLimit) {
    return c.json({
      error: `${tier === 'free' ? 'Free plan' : 'Your plan'} is limited to ${netLimit} network${netLimit !== 1 ? 's' : ''}. Upgrade to add more.`,
      upgrade_required: true,
    }, 403);
  }

  const cidr = body.cidr || '100.65.0.0/16';

  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) {
    return c.json({ error: 'Invalid CIDR format' }, 400);
  }

  const networkId = crypto.randomUUID();

  await c.env.DB.prepare('INSERT INTO networks (id, user_id, name, cidr) VALUES (?, ?, ?, ?)')
    .bind(networkId, userId, body.name, cidr)
    .run();

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'network.create',
    resourceType: 'network',
    resourceId: networkId,
    detail: `Created network "${body.name}" (${cidr})`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  return c.json({ id: networkId, name: body.name, cidr }, 201);
});

// GET /networks - List networks owned or joined by the user
networks.get('/', async (c) => {
  const userId = c.get('userId');

  // UNION: networks owned + networks where user is a member
  const result = await c.env.DB.prepare(`
    SELECT n.*, 'owner' AS role,
      (SELECT COUNT(*) FROM devices d WHERE d.network_id = n.id) AS device_count
    FROM networks n
    WHERE n.user_id = ?
    UNION
    SELECT n.*, nm.role AS role,
      (SELECT COUNT(*) FROM devices d WHERE d.network_id = n.id) AS device_count
    FROM networks n
    JOIN network_members nm ON nm.network_id = n.id AND nm.user_id = ?
    ORDER BY created_at
  `)
    .bind(userId, userId)
    .all();

  return c.json({ networks: result.results });
});

// GET /networks/:id
networks.get('/:id', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);

  const network = await c.env.DB.prepare('SELECT * FROM networks WHERE id = ?')
    .bind(networkId)
    .first();

  return c.json({ network, caller_role: role });
});

// GET /networks/:id/peers
networks.get('/:id/peers', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);

  const network = await c.env.DB.prepare('SELECT * FROM networks WHERE id = ?')
    .bind(networkId)
    .first();

  const deviceResult = await c.env.DB.prepare(
    'SELECT id, name, platform, public_key, assigned_ip, endpoint, last_seen_at, relay_host, relay_port FROM devices WHERE network_id = ? ORDER BY assigned_ip'
  )
    .bind(networkId)
    .all();

  // Fetch approved routes and group by device_id
  const routeResult = await c.env.DB.prepare(
    `SELECT device_id, cidr FROM advertised_routes
     WHERE network_id = ? AND status = 'approved' ORDER BY device_id`
  )
    .bind(networkId)
    .all<{ device_id: string; cidr: string }>();

  const routesByDevice = new Map<string, string[]>();
  for (const r of routeResult.results) {
    const existing = routesByDevice.get(r.device_id) ?? [];
    existing.push(r.cidr);
    routesByDevice.set(r.device_id, existing);
  }

  const now = Date.now();
  const peers = deviceResult.results.map((d: Record<string, unknown>) => ({
    ...d,
    online: d.last_seen_at ? now - new Date(d.last_seen_at as string).getTime() < 120_000 : false,
    advertised_routes: routesByDevice.get(d.id as string) ?? [],
  }));

  return c.json({ network, peers });
});

// DELETE /networks/:id — owner only
networks.delete('/:id', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);
  if (role !== 'owner') return c.json({ error: 'Only the network owner can delete the network' }, 403);

  const deviceCount = await c.env.DB.prepare(
    'SELECT COUNT(*) as count FROM devices WHERE network_id = ?'
  )
    .bind(networkId)
    .first<{ count: number }>();

  if (deviceCount && deviceCount.count > 0) {
    return c.json({ error: 'Cannot delete network with active devices. Remove devices first.' }, 409);
  }

  const result = await c.env.DB.prepare('DELETE FROM networks WHERE id = ?')
    .bind(networkId)
    .run();

  if (!result.meta.changes) return c.json({ error: 'Network not found' }, 404);

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'network.delete',
    resourceType: 'network',
    resourceId: networkId,
    ip: c.req.header('CF-Connecting-IP') ?? null,
  }));

  return c.json({ deleted: true });
});

// GET /networks/:id/members — any member (owner/admin/member)
networks.get('/:id/members', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const callerRole = await getNetworkRole(c.env.DB, networkId, userId);
  if (!callerRole) return c.json({ error: 'Network not found' }, 404);

  // Fetch the owner
  const network = await c.env.DB.prepare(
    'SELECT n.user_id, u.email FROM networks n JOIN users u ON u.id = n.user_id WHERE n.id = ?'
  )
    .bind(networkId)
    .first<{ user_id: string; email: string }>();

  if (!network) return c.json({ error: 'Network not found' }, 404);

  const members = await c.env.DB.prepare(`
    SELECT nm.id, nm.network_id, nm.user_id, u.email, nm.role, nm.invited_by, nm.created_at,
           inviter.email AS invited_by_email
    FROM network_members nm
    JOIN users u ON u.id = nm.user_id
    LEFT JOIN users inviter ON inviter.id = nm.invited_by
    WHERE nm.network_id = ?
    ORDER BY nm.created_at
  `)
    .bind(networkId)
    .all();

  // For each member, check if they have any device online in this network (seen < 2 min ago)
  const now = Date.now();
  const allUserIds = [network.user_id, ...members.results.map((m: Record<string, unknown>) => m.user_id as string)];

  const deviceRows = await c.env.DB.prepare(`
    SELECT user_id, MAX(last_seen_at) AS last_seen_at
    FROM devices
    WHERE network_id = ?
    GROUP BY user_id
  `)
    .bind(networkId)
    .all<{ user_id: string; last_seen_at: string | null }>();

  const onlineMap = new Map<string, boolean>();
  for (const row of deviceRows.results) {
    const online = row.last_seen_at
      ? now - new Date(row.last_seen_at + (row.last_seen_at.includes('T') ? 'Z' : 'Z')).getTime() < 120_000
      : false;
    onlineMap.set(row.user_id, online);
  }

  const ownerEntry = {
    id: network.user_id,
    network_id: networkId,
    user_id: network.user_id,
    email: network.email,
    role: 'owner' as const,
    invited_by: null,
    created_at: null,
    online: onlineMap.get(network.user_id) ?? false,
  };

  const enrichedMembers = members.results.map((m: Record<string, unknown>) => ({
    ...m,
    online: onlineMap.get(m.user_id as string) ?? false,
  }));

  return c.json({ members: [ownerEntry, ...enrichedMembers], caller_role: callerRole });
});

// POST /networks/:id/invites — owner or admin
networks.post('/:id/invites', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);
  if (role !== 'owner' && role !== 'admin') return c.json({ error: 'Forbidden' }, 403);

  const body = await c.req.json<{
    role?: 'admin' | 'member';
    max_uses?: number;
    expires_hours?: number;
    to_email?: string;
  }>();

  // Admins can only invite members, not admins
  const inviteRole = body.role ?? 'member';
  if (role === 'admin' && inviteRole === 'admin') {
    return c.json({ error: 'Admins can only invite members' }, 403);
  }
  if (!['admin', 'member'].includes(inviteRole)) {
    return c.json({ error: 'role must be admin or member' }, 400);
  }

  const toEmail = body.to_email?.trim() ?? null;
  if (toEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(toEmail)) {
    return c.json({ error: 'Invalid to_email address' }, 400);
  }

  const maxUses = body.max_uses ?? 1;
  const expiresHours = body.expires_hours ?? 168; // 7 days default

  const inviteId = crypto.randomUUID();
  // Generate a 256-bit cryptographically random token
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  const expiresAt = new Date(Date.now() + expiresHours * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);

  await c.env.DB.prepare(
    'INSERT INTO network_invites (id, network_id, created_by, role, token, max_uses, expires_at, to_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(inviteId, networkId, userId, inviteRole, token, maxUses, expiresAt, toEmail)
    .run();

  const inviteUrl = `https://shireguard.com/?invite=${token}`;

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'invite.create',
    resourceType: 'invite',
    resourceId: inviteId,
    detail: `Created ${inviteRole} invite (max ${maxUses} use${maxUses !== 1 ? 's' : ''}, expires in ${expiresHours}h)${toEmail ? ` → ${toEmail}` : ''}`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  if (toEmail) {
    c.executionCtx.waitUntil((async () => {
      const [network, inviter] = await Promise.all([
        c.env.DB.prepare('SELECT name FROM networks WHERE id = ?').bind(networkId).first<{ name: string }>(),
        c.env.DB.prepare('SELECT email FROM users WHERE id = ?').bind(userId).first<{ email: string }>(),
      ]);
      await sendEmail(c.env, {
        to: toEmail,
        subject: `You've been invited to join ${network?.name ?? 'a network'} on Shireguard`,
        html: inviteEmailHtml({
          inviterEmail: inviter?.email ?? 'Someone',
          networkName: network?.name ?? 'a network',
          inviteUrl,
          role: inviteRole,
          expiresHours,
        }),
      });
    })());
  }

  return c.json({
    token,
    invite_url: inviteUrl,
  }, 201);
});

// GET /networks/:id/invites — owner or admin
networks.get('/:id/invites', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);
  if (role !== 'owner' && role !== 'admin') return c.json({ error: 'Forbidden' }, 403);

  const invites = await c.env.DB.prepare(`
    SELECT ni.*, u.email AS created_by_email
    FROM network_invites ni
    JOIN users u ON u.id = ni.created_by
    WHERE ni.network_id = ?
      AND ni.expires_at > datetime('now')
      AND ni.use_count < ni.max_uses
    ORDER BY ni.created_at DESC
  `)
    .bind(networkId)
    .all();

  return c.json({ invites: invites.results });
});

// DELETE /networks/:id/invites/:inviteId — owner or admin
networks.delete('/:id/invites/:inviteId', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');
  const inviteId = c.req.param('inviteId');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);
  if (role !== 'owner' && role !== 'admin') return c.json({ error: 'Forbidden' }, 403);

  const result = await c.env.DB.prepare(
    'DELETE FROM network_invites WHERE id = ? AND network_id = ?'
  )
    .bind(inviteId, networkId)
    .run();

  if (!result.meta.changes) return c.json({ error: 'Invite not found' }, 404);

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'invite.revoke',
    resourceType: 'invite',
    resourceId: inviteId,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  return c.json({ deleted: true });
});

// DELETE /networks/:id/members/:userId — owner removes anyone; admin removes members only
networks.delete('/:id/members/:memberId', async (c) => {
  const callerId = c.get('userId');
  const networkId = c.req.param('id');
  const targetUserId = c.req.param('memberId');

  const callerRole = await getNetworkRole(c.env.DB, networkId, callerId);
  if (!callerRole) return c.json({ error: 'Network not found' }, 404);
  if (callerRole !== 'owner' && callerRole !== 'admin') return c.json({ error: 'Forbidden' }, 403);

  // Cannot remove the owner
  const network = await c.env.DB.prepare('SELECT user_id FROM networks WHERE id = ?')
    .bind(networkId)
    .first<{ user_id: string }>();
  if (network && network.user_id === targetUserId) {
    return c.json({ error: 'Cannot remove the network owner' }, 403);
  }

  // Admins cannot remove other admins
  if (callerRole === 'admin') {
    const targetMember = await c.env.DB.prepare(
      'SELECT role FROM network_members WHERE network_id = ? AND user_id = ?'
    )
      .bind(networkId, targetUserId)
      .first<{ role: string }>();
    if (targetMember && targetMember.role === 'admin') {
      return c.json({ error: 'Admins cannot remove other admins' }, 403);
    }
  }

  const result = await c.env.DB.prepare(
    'DELETE FROM network_members WHERE network_id = ? AND user_id = ?'
  )
    .bind(networkId, targetUserId)
    .run();

  if (!result.meta.changes) return c.json({ error: 'Member not found' }, 404);

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId: callerId,
    action: 'member.remove',
    resourceType: 'member',
    resourceId: targetUserId,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  return c.json({ deleted: true });
});

// PATCH /networks/:id/members/:memberId — owner only, change role
networks.patch('/:id/members/:memberId', async (c) => {
  const callerId = c.get('userId');
  const networkId = c.req.param('id');
  const targetUserId = c.req.param('memberId');

  const callerRole = await getNetworkRole(c.env.DB, networkId, callerId);
  if (!callerRole) return c.json({ error: 'Network not found' }, 404);
  if (callerRole !== 'owner') return c.json({ error: 'Only the network owner can change roles' }, 403);

  const body = await c.req.json<{ role: 'admin' | 'member' }>();
  if (!body.role || !['admin', 'member'].includes(body.role)) {
    return c.json({ error: 'role must be admin or member' }, 400);
  }

  const result = await c.env.DB.prepare(
    'UPDATE network_members SET role = ? WHERE network_id = ? AND user_id = ?'
  )
    .bind(body.role, networkId, targetUserId)
    .run();

  if (!result.meta.changes) return c.json({ error: 'Member not found' }, 404);

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId: callerId,
    action: 'member.role_change',
    resourceType: 'member',
    resourceId: targetUserId,
    detail: `Role changed to ${body.role}`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  return c.json({ updated: true });
});

// GET /networks/:id/gatekeep — any member can read the policy
networks.get('/:id/gatekeep', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);

  const row = await c.env.DB.prepare(
    'SELECT policy, updated_by, updated_at FROM gatekeep_policies WHERE network_id = ?'
  )
    .bind(networkId)
    .first<{ policy: string; updated_by: string | null; updated_at: string }>();

  const policy = row ? JSON.parse(row.policy) : { default_action: 'allow', rules: [] };

  return c.json({ policy, caller_role: role, updated_at: row?.updated_at ?? null });
});

// PUT /networks/:id/gatekeep — owner or admin only
networks.put('/:id/gatekeep', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);
  if (role !== 'owner' && role !== 'admin') return c.json({ error: 'Forbidden' }, 403);

  const body = await c.req.json<{ default_action: string; rules: unknown[] }>();

  if (!['allow', 'block'].includes(body.default_action)) {
    return c.json({ error: 'default_action must be "allow" or "block"' }, 400);
  }
  if (!Array.isArray(body.rules)) {
    return c.json({ error: 'rules must be an array' }, 400);
  }

  // Validate each rule minimally
  for (const r of body.rules as Record<string, unknown>[]) {
    if (!['allow', 'block'].includes(r.action as string)) {
      return c.json({ error: `Invalid rule action: ${r.action}` }, 400);
    }
    if (!['tcp', 'udp', 'icmp', 'any'].includes(r.protocol as string)) {
      return c.json({ error: `Invalid protocol: ${r.protocol}` }, 400);
    }
  }

  const policyJson = JSON.stringify({ default_action: body.default_action, rules: body.rules });

  await c.env.DB.prepare(`
    INSERT INTO gatekeep_policies (network_id, policy, updated_by, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(network_id) DO UPDATE SET
      policy = excluded.policy,
      updated_by = excluded.updated_by,
      updated_at = excluded.updated_at
  `)
    .bind(networkId, policyJson, userId)
    .run();

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'policy.update',
    resourceType: 'policy',
    resourceId: networkId,
    detail: `Updated gatekeep policy (default: ${body.default_action}, ${body.rules.length} rule${body.rules.length !== 1 ? 's' : ''})`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  return c.json({ saved: true });
});

export { networks };
