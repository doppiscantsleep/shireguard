import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';

const activity = new Hono<{ Bindings: Env }>();
activity.use('*', authMiddleware);

// GET /activity — paginated audit log for the authenticated user
// ?network_id=<uuid>  filter to a specific network (caller must be owner/member)
// ?limit=<n>          default 50, max 100
// ?before=<iso>       cursor: return events older than this timestamp
activity.get('/', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.query('network_id') || null;
  const before = c.req.query('before') || null;
  const rawLimit = parseInt(c.req.query('limit') ?? '50', 10);
  const limit = Math.min(isNaN(rawLimit) ? 50 : rawLimit, 100);

  if (networkId) {
    // Verify the caller is a member or owner of the requested network
    const access = await c.env.DB.prepare(`
      SELECT 1 FROM networks WHERE id = ? AND user_id = ?
      UNION SELECT 1 FROM network_members WHERE network_id = ? AND user_id = ?
      LIMIT 1
    `)
      .bind(networkId, userId, networkId, userId)
      .first();
    if (!access) return c.json({ error: 'Network not found' }, 404);
  }

  const params: (string | number)[] = [];
  let where = networkId
    ? 'al.network_id = ?'
    : 'al.user_id = ?';
  params.push(networkId ?? userId);

  if (before) {
    where += ' AND al.created_at < ?';
    params.push(before);
  }

  // Fetch limit+1 to determine has_more
  params.push(limit + 1);

  const result = await c.env.DB.prepare(`
    SELECT al.id, al.user_id, u.email, al.action, al.resource_type,
           al.resource_id, al.detail, al.network_id, al.created_at
    FROM audit_log al
    LEFT JOIN users u ON u.id = al.user_id
    WHERE ${where}
    ORDER BY al.created_at DESC, al.id DESC
    LIMIT ?
  `)
    .bind(...params)
    .all<{
      id: number;
      user_id: string;
      email: string | null;
      action: string;
      resource_type: string;
      resource_id: string | null;
      detail: string | null;
      network_id: string | null;
      created_at: string;
    }>();

  const rows = result.results;
  const hasMore = rows.length > limit;
  const events = hasMore ? rows.slice(0, limit) : rows;

  return c.json({ events, has_more: hasMore });
});

export { activity };
