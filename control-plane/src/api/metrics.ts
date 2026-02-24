import { Hono } from 'hono';
import type { Env, MetricsBatch } from '../types';
import { authMiddleware } from '../auth/middleware';
import { checkRateLimit } from '../auth/ratelimit';

const metrics = new Hono<{ Bindings: Env }>();
metrics.use('*', authMiddleware);

// POST /metrics - Batched metrics ingestion (write directly to D1)
metrics.post('/', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, { action: 'metrics-ingest', limit: 30, windowSeconds: 60 });
  if (rl.limited) {
    return c.json({ error: 'Too many requests. Try again later.' }, 429, { 'Retry-After': String(rl.retryAfter) });
  }

  const userId = c.get('userId');
  const body = await c.req.json<MetricsBatch>();

  if (!body.device_id || !body.metrics?.length) {
    return c.json({ error: 'device_id and metrics array are required' }, 400);
  }

  // Verify device ownership and capture the network the device belongs to.
  const device = await c.env.DB.prepare(
    'SELECT id, network_id FROM devices WHERE id = ? AND user_id = ?'
  )
    .bind(body.device_id, userId)
    .first<{ id: string; network_id: string }>();

  if (!device) {
    return c.json({ error: 'Device not found' }, 404);
  }

  // Validate that every peer_device_id in the batch belongs to the same
  // network.  This prevents a compromised device from poisoning metrics rows
  // that reference peers it has no legitimate relationship with.
  const peerIds = [
    ...new Set(
      body.metrics
        .map((e) => e.peer_device_id)
        .filter((id): id is string => typeof id === 'string' && id.length > 0),
    ),
  ];

  if (peerIds.length > 0) {
    // Build a parameterised IN clause — D1 does not support array binding
    // natively so we construct the placeholders manually.
    const placeholders = peerIds.map(() => '?').join(', ');
    const peerRows = await c.env.DB.prepare(
      `SELECT id FROM devices WHERE id IN (${placeholders}) AND network_id = ?`,
    )
      .bind(...peerIds, device.network_id)
      .all<{ id: string }>();

    if (peerRows.results.length !== peerIds.length) {
      return c.json(
        { error: 'One or more peer_device_id values do not belong to the same network' },
        400,
      );
    }
  }

  // Write directly to D1
  for (const entry of body.metrics) {
    const bucket = entry.timestamp.slice(0, 16); // Truncate to minute
    const qualityScore = computeQualityScore(entry);

    await c.env.DB.prepare(
      `INSERT INTO metrics (device_id, peer_device_id, bucket, bucket_size, latency_ms, jitter_ms,
       packet_loss_ratio, throughput_tx_bytes, throughput_rx_bytes, nat_type, connection_type, quality_score)
       VALUES (?, ?, ?, '1m', ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        body.device_id,
        entry.peer_device_id || null,
        bucket,
        entry.latency_ms ?? null,
        entry.jitter_ms ?? null,
        entry.packet_loss_ratio ?? null,
        entry.throughput_tx_bytes ?? null,
        entry.throughput_rx_bytes ?? null,
        entry.nat_type ?? null,
        entry.connection_type ?? 'direct',
        qualityScore
      )
      .run();
  }

  return c.json({ accepted: body.metrics.length });
});

// GET /metrics/peers/:id - Get metrics for a specific device
metrics.get('/peers/:id', async (c) => {
  const userId = c.get('userId');
  const deviceId = c.req.param('id');
  const bucketSize = c.req.query('bucket_size') || '5m';
  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 1000);

  // Verify device ownership
  const device = await c.env.DB.prepare(
    'SELECT id FROM devices WHERE id = ? AND user_id = ?'
  )
    .bind(deviceId, userId)
    .first();

  if (!device) {
    return c.json({ error: 'Device not found' }, 404);
  }

  const result = await c.env.DB.prepare(
    `SELECT * FROM metrics WHERE device_id = ? AND bucket_size = ? ORDER BY bucket DESC LIMIT ?`
  )
    .bind(deviceId, bucketSize, limit)
    .all();

  return c.json({ metrics: result.results });
});

// GET /metrics/summary/:network_id - Network health summary
metrics.get('/summary/:network_id', async (c) => {
  const userId = c.get('userId');
  const networkId = c.req.param('network_id');

  // Verify the user owns or is a member of the network
  const access = await c.env.DB.prepare(`
    SELECT 1 FROM networks WHERE id = ? AND user_id = ?
    UNION SELECT 1 FROM network_members WHERE network_id = ? AND user_id = ?
    LIMIT 1
  `)
    .bind(networkId, userId, networkId, userId)
    .first();

  if (!access) {
    return c.json({ error: 'Network not found' }, 404);
  }

  // Get latest metrics for each device in the network
  const result = await c.env.DB.prepare(`
    SELECT m.device_id, d.name as device_name, m.latency_ms, m.jitter_ms,
           m.packet_loss_ratio, m.connection_type, m.quality_score, m.bucket
    FROM metrics m
    JOIN devices d ON d.id = m.device_id
    WHERE d.network_id = ? AND m.bucket_size = '1m'
    AND m.bucket = (SELECT MAX(m2.bucket) FROM metrics m2 WHERE m2.device_id = m.device_id AND m2.bucket_size = '1m')
    ORDER BY d.name
  `)
    .bind(networkId)
    .all();

  return c.json({ summary: result.results });
});

export { metrics };

function computeQualityScore(entry: MetricsBatch['metrics'][0]): number {
  let score = 100;

  if (entry.latency_ms !== undefined) {
    if (entry.latency_ms > 300) score -= 30;
    else if (entry.latency_ms > 150) score -= 15;
    else if (entry.latency_ms > 50) score -= 5;
  }

  if (entry.jitter_ms !== undefined) {
    if (entry.jitter_ms > 100) score -= 20;
    else if (entry.jitter_ms > 50) score -= 10;
    else if (entry.jitter_ms > 20) score -= 5;
  }

  if (entry.packet_loss_ratio !== undefined) {
    if (entry.packet_loss_ratio > 0.1) score -= 30;
    else if (entry.packet_loss_ratio > 0.05) score -= 15;
    else if (entry.packet_loss_ratio > 0.01) score -= 5;
  }

  if (entry.connection_type === 'relay') score -= 10;

  return Math.max(0, score);
}
