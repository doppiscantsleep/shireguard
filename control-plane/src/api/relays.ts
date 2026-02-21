import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';

const relays = new Hono<{ Bindings: Env }>();
relays.use('*', authMiddleware);

// GET /relays — list active relay servers (including auth_token for relay registration)
relays.get('/', async (c) => {
  const result = await c.env.DB.prepare(
    "SELECT host, port, auth_token, region FROM relays WHERE status = 'active' ORDER BY created_at"
  ).all();

  return c.json({ relays: result.results });
});

export { relays };
