import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';

const relays = new Hono<{ Bindings: Env }>();

// GET /relays — list active relay servers (auth_token excluded)
relays.get('/', authMiddleware, async (c) => {
  const result = await c.env.DB.prepare(
    "SELECT host, port, region, tls_enabled FROM relays WHERE status = 'active' ORDER BY created_at"
  ).all();

  return c.json({ relays: result.results });
});

// POST /relays/register — proxy relay registration through the control plane
// so that relay auth_tokens are never exposed to clients.
relays.post('/register', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const { device_id } = await c.req.json<{ device_id: string }>();

  // Verify device belongs to this user
  const device = await c.env.DB.prepare(
    'SELECT id FROM devices WHERE id = ? AND user_id = ?'
  ).bind(device_id, userId).first();
  if (!device) return c.json({ error: 'device not found' }, 404);

  // Fetch relay with auth_token (server-side only, never returned to clients)
  const relay = await c.env.DB.prepare(
    "SELECT host, port, auth_token, tls_enabled FROM relays WHERE status = 'active' ORDER BY created_at LIMIT 1"
  ).first<{ host: string; port: number; auth_token: string; tls_enabled: number }>();
  if (!relay) return c.json({ error: 'no relays available' }, 503);

  const relayProto = relay.tls_enabled ? 'https' : 'http';

  // Proxy registration to relay server
  const resp = await fetch(`${relayProto}://${relay.host}:${relay.port}/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${relay.auth_token}`,
    },
    body: JSON.stringify({ device_id }),
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    console.error(`relay registration failed: relay returned ${resp.status}: ${body}`);
    return c.json({ error: `relay registration failed: relay returned ${resp.status}: ${body}` }, 502);
  }

  const data = await resp.json<{ relay_host: string; relay_port: number; relay_token: string }>();

  // Write relay_host and relay_port to the device record server-side, using the
  // authoritative relay.host from our DB — never the client-supplied value.
  // This removes the need for the client to call POST /devices/:id/relay-endpoint
  // and eliminates the client-controlled relay_host attack surface.
  await c.env.DB.prepare(
    'UPDATE devices SET relay_host = ?, relay_port = ? WHERE id = ?'
  ).bind(relay.host, data.relay_port, device_id).run();

  return c.json(data);
});

export { relays };
