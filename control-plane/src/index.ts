import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';
import { auth } from './auth/handlers';
import { devices } from './api/devices';
import { networks } from './api/networks';
import { metrics } from './api/metrics';
import { relays } from './api/relays';
import { activity } from './api/activity';
import { billing } from './api/billing';
import { networkRoutes } from './api/routes';
import { authMiddleware } from './auth/middleware';
import { logAudit } from './lib/audit';
import { getUserTier, TIER_LIMITS, type Tier } from './lib/tiers';
import { timingSafeEqual } from './lib/stripe';

export { SignalingRoom } from './signaling/room';

const app = new Hono<{ Bindings: Env }>();

// Return JSON for unhandled exceptions instead of plain-text "Internal Server Error"
app.onError((err, c) => {
  console.error('[unhandled error]', err);
  return c.json({ error: err.message || 'Internal server error' }, 500);
});

// CORS — restrict to production origin only.
// The WireGuard CLI client is not a browser and does not send CORS preflight
// requests, so locking this down does not affect CLI functionality.
app.use('*', cors({
  origin: 'https://shireguard.com',
  allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Authorization', 'Content-Type'],
}));

// Health check
app.get('/health', (c) => c.json({ status: 'ok' }));

// HTML pages
import dashboardHtml from './dashboard.html';
import landingHtml from './landing.html';
import docsHtml from './docs.html';
import pricingHtml from './pricing.html';
import installScript from '../../install.sh';
import hobDoor from './hob_door.jpeg';

app.get('/', (c) => {
  return c.html(landingHtml);
});
app.get('/dashboard', (c) => {
  return c.html(dashboardHtml);
});
app.get('/docs', (c) => {
  return c.html(docsHtml);
});
// /pricing requires auth — unauthenticated users land on /dashboard which handles the auth flow
app.get('/pricing', (c) => c.redirect('/dashboard'));
app.get('/favicon.jpeg', (c) => {
  return c.body(hobDoor, 200, {
    'Content-Type': 'image/jpeg',
    'Cache-Control': 'public, max-age=86400',
  });
});

// Linux installer script — curl -sSL https://shireguard.com/install.sh | bash
app.get('/install.sh', (c) => {
  return c.text(installScript, 200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Disposition': 'inline; filename="install.sh"',
  });
});

// API routes
app.route('/v1/auth', auth);
app.route('/v1/devices', devices);
app.route('/v1/networks', networkRoutes); // /:networkId/routes — before networks for specificity
app.route('/v1/networks', networks);
app.route('/v1/metrics', metrics);
app.route('/v1/relays', relays);
app.route('/v1/activity', activity);
app.route('/v1/billing', billing);

// POST /v1/invites/:token/accept — accept a network invite
app.post('/v1/invites/:token/accept', authMiddleware, async (c) => {
  const token = c.req.param('token');
  const userId = c.get('userId');

  const invite = await c.env.DB.prepare(
    'SELECT * FROM network_invites WHERE token = ?'
  )
    .bind(token)
    .first<{
      id: string; network_id: string; created_by: string;
      role: 'admin' | 'member'; max_uses: number; use_count: number; expires_at: string;
    }>();

  if (!invite) return c.json({ error: 'Invite not found' }, 404);

  // Check validity
  const now = new Date();
  const expiresAt = new Date(invite.expires_at + (invite.expires_at.includes('T') ? 'Z' : 'Z'));
  if (now > expiresAt || invite.use_count >= invite.max_uses) {
    return c.json({ error: 'Invite has expired or reached its use limit' }, 410);
  }

  // Fetch network name
  const network = await c.env.DB.prepare('SELECT name FROM networks WHERE id = ?')
    .bind(invite.network_id)
    .first<{ name: string }>();

  if (!network) return c.json({ error: 'Network not found' }, 404);

  // Idempotent: already a member?
  const existing = await c.env.DB.prepare(
    'SELECT role FROM network_members WHERE network_id = ? AND user_id = ?'
  )
    .bind(invite.network_id, userId)
    .first<{ role: string }>();

  if (existing) {
    return c.json({ network_id: invite.network_id, network_name: network.name, role: existing.role });
  }

  // Check if caller is the owner
  const isOwner = await c.env.DB.prepare(
    'SELECT 1 FROM networks WHERE id = ? AND user_id = ?'
  )
    .bind(invite.network_id, userId)
    .first();

  if (isOwner) {
    return c.json({ network_id: invite.network_id, network_name: network.name, role: 'owner' });
  }

  // Enforce member limit based on the network owner's tier
  const networkOwner = await c.env.DB.prepare('SELECT user_id FROM networks WHERE id = ?')
    .bind(invite.network_id)
    .first<{ user_id: string }>();

  if (networkOwner) {
    const [ownerTier, memberCount] = await Promise.all([
      getUserTier(c.env.DB, networkOwner.user_id),
      c.env.DB.prepare('SELECT COUNT(*) as count FROM network_members WHERE network_id = ?')
        .bind(invite.network_id)
        .first<{ count: number }>(),
    ]);
    const memberLimit = TIER_LIMITS[ownerTier].members;
    // +1 for the owner themselves; memberCount is non-owner members
    if (memberLimit !== Infinity && (memberCount?.count ?? 0) + 1 >= memberLimit) {
      return c.json({
        error: `This network has reached its member limit (${memberLimit}). The owner must upgrade to add more members.`,
        upgrade_required: true,
      }, 403);
    }
  }

  const memberId = crypto.randomUUID();
  await c.env.DB.prepare(
    'INSERT INTO network_members (id, network_id, user_id, role, invited_by) VALUES (?, ?, ?, ?, ?)'
  )
    .bind(memberId, invite.network_id, userId, invite.role, invite.created_by)
    .run();

  await c.env.DB.prepare(
    'UPDATE network_invites SET use_count = use_count + 1 WHERE id = ?'
  )
    .bind(invite.id)
    .run();

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'member.join',
    resourceType: 'member',
    resourceId: userId,
    detail: `Joined network "${network.name}" as ${invite.role}`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId: invite.network_id,
  }));

  return c.json({ network_id: invite.network_id, network_name: network.name, role: invite.role });
});

// POST /v1/admin/tier — set a user's tier by email (requires ADMIN_SECRET bearer token)
app.post('/v1/admin/tier', async (c) => {
  const authHeader = c.req.header('Authorization') ?? '';
  const expected = `Bearer ${c.env.ADMIN_SECRET ?? ''}`;
  if (!c.env.ADMIN_SECRET || !timingSafeEqual(authHeader, expected)) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const body = await c.req.json<{ email: string; tier: string }>();
  if (!body.email || !body.tier) {
    return c.json({ error: 'email and tier are required' }, 400);
  }

  const validTiers: Tier[] = ['free', 'solo', 'team', 'comped'];
  if (!validTiers.includes(body.tier as Tier)) {
    return c.json({ error: `tier must be one of: ${validTiers.join(', ')}` }, 400);
  }

  const result = await c.env.DB.prepare('UPDATE users SET tier = ? WHERE email = ?')
    .bind(body.tier, body.email)
    .run();

  if (!result.meta.changes) {
    return c.json({ error: 'User not found' }, 404);
  }

  return c.json({ email: body.email, tier: body.tier, updated: true });
});

// WebSocket signaling upgrade
app.get('/v1/signal/:network_id', authMiddleware, async (c) => {
  const networkId = c.req.param('network_id');
  const deviceId = c.req.query('device_id');
  const userId = c.get('userId');

  if (!deviceId) {
    return c.json({ error: 'device_id query parameter is required' }, 400);
  }

  // Verify device ownership and network membership
  const device = await c.env.DB.prepare(
    'SELECT id FROM devices WHERE id = ? AND user_id = ? AND network_id = ?'
  )
    .bind(deviceId, userId, networkId)
    .first();

  if (!device) {
    return c.json({ error: 'Device not found in this network' }, 404);
  }

  // Route to Durable Object (one per network)
  const doId = c.env.SIGNALING.idFromName(networkId);
  const stub = c.env.SIGNALING.get(doId);

  const url = new URL(c.req.url);
  url.pathname = '/websocket';
  url.searchParams.set('device_id', deviceId);
  url.searchParams.set('network_id', networkId);

  return stub.fetch(new Request(url.toString(), c.req.raw));
});

async function pruneOldMetrics(env: Env): Promise<void> {
  const result = await env.DB.prepare(
    "DELETE FROM metrics WHERE created_at < datetime('now', '-7 days')"
  ).run();
  console.log(`[cron] pruned ${result.meta.changes} old metrics rows`);
}

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(pruneOldMetrics(env));
  },
};
