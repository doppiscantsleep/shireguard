import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';

const networks = new Hono<{ Bindings: Env }>();
networks.use('*', authMiddleware);

// POST /networks - Create a new network
networks.post('/', async (c) => {
  const userId = c.get('userId');
  const body = await c.req.json<{ name: string; cidr?: string }>();

  if (!body.name) {
    return c.json({ error: 'Name is required' }, 400);
  }

  const cidr = body.cidr || '10.100.0.0/24';

  // Validate CIDR format
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) {
    return c.json({ error: 'Invalid CIDR format' }, 400);
  }

  const networkId = crypto.randomUUID();

  await c.env.DB.prepare('INSERT INTO networks (id, user_id, name, cidr) VALUES (?, ?, ?, ?)')
    .bind(networkId, userId, body.name, cidr)
    .run();

  return c.json({
    id: networkId,
    name: body.name,
    cidr,
  }, 201);
});

// GET /networks - List user's networks
networks.get('/', async (c) => {
  const userId = c.get('userId');

  const result = await c.env.DB.prepare(
    'SELECT n.*, (SELECT COUNT(*) FROM devices d WHERE d.network_id = n.id) AS device_count FROM networks n WHERE n.user_id = ? ORDER BY n.created_at'
  )
    .bind(userId)
    .all();

  return c.json({ networks: result.results });
});

// GET /networks/:id
networks.get('/:id', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  const network = await c.env.DB.prepare(
    'SELECT * FROM networks WHERE id = ? AND user_id = ?'
  )
    .bind(networkId, userId)
    .first();

  if (!network) {
    return c.json({ error: 'Network not found' }, 404);
  }

  return c.json({ network });
});

// GET /networks/:id/peers - List peers (devices) in a network with their config
networks.get('/:id/peers', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  // Verify network ownership
  const network = await c.env.DB.prepare(
    'SELECT * FROM networks WHERE id = ? AND user_id = ?'
  )
    .bind(networkId, userId)
    .first();

  if (!network) {
    return c.json({ error: 'Network not found' }, 404);
  }

  const deviceResult = await c.env.DB.prepare(
    'SELECT id, name, platform, public_key, assigned_ip, endpoint, last_seen_at FROM devices WHERE network_id = ? ORDER BY assigned_ip'
  )
    .bind(networkId)
    .all();

  const now = Date.now();
  const peers = deviceResult.results.map((d: Record<string, unknown>) => ({
    ...d,
    online: d.last_seen_at ? now - new Date(d.last_seen_at as string).getTime() < 120_000 : false,
  }));

  return c.json({ network, peers });
});

// DELETE /networks/:id
networks.delete('/:id', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('id');

  // Check for devices
  const deviceCount = await c.env.DB.prepare(
    'SELECT COUNT(*) as count FROM devices WHERE network_id = ? AND user_id = ?'
  )
    .bind(networkId, userId)
    .first<{ count: number }>();

  if (deviceCount && deviceCount.count > 0) {
    return c.json({ error: 'Cannot delete network with active devices. Remove devices first.' }, 409);
  }

  const result = await c.env.DB.prepare('DELETE FROM networks WHERE id = ? AND user_id = ?')
    .bind(networkId, userId)
    .run();

  if (!result.meta.changes) {
    return c.json({ error: 'Network not found' }, 404);
  }

  return c.json({ deleted: true });
});

export { networks };
