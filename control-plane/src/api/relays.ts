import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';

const relays = new Hono<{ Bindings: Env }>();
relays.use('*', authMiddleware);

// GET /relays — list active relay servers (auth_token excluded)
relays.get('/', async (c) => {
  const result = await c.env.DB.prepare(
    "SELECT host, port, region FROM relays WHERE status = 'active' ORDER BY created_at"
  ).all();

  return c.json({ relays: result.results });
});

// POST /relays/register — proxy relay registration through the control plane
// so that relay auth_tokens are never exposed to clients.
relays.post('/register', async (c) => {
  const userId = c.get('userId');
  const { device_id } = await c.req.json<{ device_id: string }>();

  // Verify device belongs to this user
  const device = await c.env.DB.prepare(
    'SELECT id FROM devices WHERE id = ? AND user_id = ?'
  ).bind(device_id, userId).first();
  if (!device) return c.json({ error: 'device not found' }, 404);

  // Fetch relay with auth_token (server-side only, never returned to clients)
  const relay = await c.env.DB.prepare(
    "SELECT host, port, auth_token FROM relays WHERE status = 'active' ORDER BY created_at LIMIT 1"
  ).first<{ host: string; port: number; auth_token: string }>();
  if (!relay) return c.json({ error: 'no relays available' }, 503);

  // Proxy registration to relay server
  const resp = await fetch(`http://${relay.host}:${relay.port}/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${relay.auth_token}`,
    },
    body: JSON.stringify({ device_id }),
  });
  if (!resp.ok) return c.json({ error: 'relay registration failed' }, 502);

  const data = await resp.json();
  return c.json(data);
});

export { relays };
