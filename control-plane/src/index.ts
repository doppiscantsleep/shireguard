import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';
import { auth } from './auth/handlers';
import { devices } from './api/devices';
import { networks } from './api/networks';
import { metrics } from './api/metrics';
import { relays } from './api/relays';
import { authMiddleware } from './auth/middleware';

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

// Dashboard (serve HTML)
import dashboardHtml from './dashboard.html';
import installScript from '../../install.sh';

app.get('/', (c) => {
  return c.html(dashboardHtml);
});
app.get('/dashboard', (c) => {
  return c.html(dashboardHtml);
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
app.route('/v1/networks', networks);
app.route('/v1/metrics', metrics);
app.route('/v1/relays', relays);

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
