import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';
import { auth } from './auth/handlers';
import { devices } from './api/devices';
import { networks } from './api/networks';
import { metrics } from './api/metrics';
import { authMiddleware } from './auth/middleware';

export { SignalingRoom } from './signaling/room';

const app = new Hono<{ Bindings: Env }>();

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

app.get('/', (c) => {
  return c.html(dashboardHtml);
});
app.get('/dashboard', (c) => {
  return c.html(dashboardHtml);
});

// API routes
app.route('/v1/auth', auth);
app.route('/v1/devices', devices);
app.route('/v1/networks', networks);
app.route('/v1/metrics', metrics);

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

export default {
  fetch: app.fetch,
};
