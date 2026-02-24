import { Hono } from 'hono';
import type { Env } from '../types';
import { authMiddleware } from '../auth/middleware';
import { logAudit } from '../lib/audit';

const routes = new Hono<{ Bindings: Env }>();
routes.use('*', authMiddleware);

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

function isValidCidr(cidr: string): boolean {
  const m = cidr.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) return false;
  const octets = [+m[1], +m[2], +m[3], +m[4]];
  if (octets.some(o => o > 255)) return false;
  const prefix = +m[5];
  return prefix >= 1 && prefix <= 32;
}

function cidrsOverlap(a: string, b: string): boolean {
  const parse = (cidr: string) => {
    const [base, pStr] = cidr.split('/');
    const parts = base.split('.').map(Number);
    const num = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    const prefix = parseInt(pStr);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return { network: (num & mask) >>> 0, mask };
  };
  const pa = parse(a);
  const pb = parse(b);
  return ((pa.network & pb.mask) >>> 0) === pb.network ||
         ((pb.network & pa.mask) >>> 0) === pa.network;
}

// POST /:networkId/routes — advertise a subnet route (any member, starts as pending)
routes.post('/:networkId/routes', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('networkId');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);

  const body = await c.req.json<{
    device_id: string;
    cidr: string;
    description?: string;
  }>();

  if (!body.device_id || !body.cidr) {
    return c.json({ error: 'device_id and cidr are required' }, 400);
  }

  if (body.cidr !== '0.0.0.0/0' && !isValidCidr(body.cidr)) {
    return c.json({ error: 'Invalid CIDR format' }, 400);
  }

  // Verify device belongs to this user and network
  const device = await c.env.DB.prepare(
    'SELECT id FROM devices WHERE id = ? AND user_id = ? AND network_id = ?'
  )
    .bind(body.device_id, userId, networkId)
    .first();
  if (!device) return c.json({ error: 'Device not found in this network' }, 404);

  // Reject advertised CIDRs that overlap with the network's own WireGuard CIDR
  if (body.cidr !== '0.0.0.0/0') {
    const network = await c.env.DB.prepare('SELECT cidr FROM networks WHERE id = ?')
      .bind(networkId)
      .first<{ cidr: string }>();
    if (network && cidrsOverlap(body.cidr, network.cidr)) {
      return c.json({
        error: `Route ${body.cidr} overlaps with the network CIDR ${network.cidr}`,
      }, 400);
    }
  }

  const routeId = crypto.randomUUID();
  const desc = body.cidr === '0.0.0.0/0'
    ? (body.description || 'Exit node (default route)')
    : (body.description || null);

  try {
    await c.env.DB.prepare(
      `INSERT INTO advertised_routes (id, network_id, device_id, cidr, description)
       VALUES (?, ?, ?, ?, ?)`
    )
      .bind(routeId, networkId, body.device_id, body.cidr, desc)
      .run();
  } catch (e: unknown) {
    if (e instanceof Error && e.message.includes('UNIQUE')) {
      return c.json({ error: 'This device is already advertising this route' }, 409);
    }
    throw e;
  }

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'route.advertise',
    resourceType: 'route',
    resourceId: routeId,
    detail: `Advertised ${body.cidr} from device ${body.device_id}`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  return c.json({
    id: routeId,
    network_id: networkId,
    device_id: body.device_id,
    cidr: body.cidr,
    status: 'pending',
    description: desc,
    created_at: new Date().toISOString(),
  }, 201);
});

// GET /:networkId/routes — list routes (members see approved only; owners/admins see all)
routes.get('/:networkId/routes', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('networkId');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);

  const statusFilter = role === 'member' ? "AND ar.status = 'approved'" : '';

  const result = await c.env.DB.prepare(`
    SELECT ar.*, d.name AS device_name, d.assigned_ip AS device_ip
    FROM advertised_routes ar
    JOIN devices d ON d.id = ar.device_id
    WHERE ar.network_id = ? ${statusFilter}
    ORDER BY ar.created_at DESC
  `)
    .bind(networkId)
    .all();

  return c.json({ routes: result.results, caller_role: role });
});

// PATCH /:networkId/routes/:routeId — approve or reject (owner/admin only)
routes.patch('/:networkId/routes/:routeId', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('networkId');
  const routeId = c.req.param('routeId');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);
  if (role !== 'owner' && role !== 'admin') {
    return c.json({ error: 'Only owners and admins can approve or reject routes' }, 403);
  }

  const body = await c.req.json<{ status: 'approved' | 'rejected' }>();
  if (!body.status || !['approved', 'rejected'].includes(body.status)) {
    return c.json({ error: 'status must be "approved" or "rejected"' }, 400);
  }

  let result;
  if (body.status === 'approved') {
    result = await c.env.DB.prepare(
      `UPDATE advertised_routes SET status = ?, approved_by = ?, approved_at = datetime('now')
       WHERE id = ? AND network_id = ?`
    )
      .bind(body.status, userId, routeId, networkId)
      .run();
  } else {
    result = await c.env.DB.prepare(
      'UPDATE advertised_routes SET status = ? WHERE id = ? AND network_id = ?'
    )
      .bind(body.status, routeId, networkId)
      .run();
  }

  if (!result.meta.changes) return c.json({ error: 'Route not found' }, 404);

  const route = await c.env.DB.prepare(
    'SELECT cidr, device_id FROM advertised_routes WHERE id = ?'
  )
    .bind(routeId)
    .first<{ cidr: string; device_id: string }>();

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: `route.${body.status}`,
    resourceType: 'route',
    resourceId: routeId,
    detail: `${body.status === 'approved' ? 'Approved' : 'Rejected'} route ${route?.cidr}`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  return c.json({ updated: true });
});

// DELETE /:networkId/routes/:routeId — owner/admin can delete any; member can delete their own
routes.delete('/:networkId/routes/:routeId', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('networkId');
  const routeId = c.req.param('routeId');

  const role = await getNetworkRole(c.env.DB, networkId, userId);
  if (!role) return c.json({ error: 'Network not found' }, 404);

  let result;
  if (role === 'owner' || role === 'admin') {
    result = await c.env.DB.prepare(
      'DELETE FROM advertised_routes WHERE id = ? AND network_id = ?'
    )
      .bind(routeId, networkId)
      .run();
  } else {
    result = await c.env.DB.prepare(
      `DELETE FROM advertised_routes WHERE id = ? AND network_id = ?
       AND device_id IN (SELECT id FROM devices WHERE user_id = ?)`
    )
      .bind(routeId, networkId, userId)
      .run();
  }

  if (!result.meta.changes) return c.json({ error: 'Route not found' }, 404);

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId,
    action: 'route.delete',
    resourceType: 'route',
    resourceId: routeId,
    ip: c.req.header('CF-Connecting-IP') ?? null,
    networkId,
  }));

  return c.json({ deleted: true });
});

export { routes as networkRoutes };
