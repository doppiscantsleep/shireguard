import { Hono } from 'hono';
import type { Env, MetricsBatch } from '../types';
import { authMiddleware } from '../auth/middleware';

const metrics = new Hono<{ Bindings: Env }>();
metrics.use('*', authMiddleware);

// POST /metrics - Batched metrics ingestion
metrics.post('/', async (c) => {
  const userId = c.get('userId');
  const body = await c.req.json<MetricsBatch>();

  if (!body.device_id || !body.metrics?.length) {
    return c.json({ error: 'device_id and metrics array are required' }, 400);
  }

  // Verify device ownership
  const device = await c.env.DB.prepare(
    'SELECT id FROM devices WHERE id = ? AND user_id = ?'
  )
    .bind(body.device_id, userId)
    .first();

  if (!device) {
    return c.json({ error: 'Device not found' }, 404);
  }

  // Enqueue metrics for async processing
  await c.env.METRICS_QUEUE.send({
    device_id: body.device_id,
    user_id: userId,
    metrics: body.metrics,
    received_at: new Date().toISOString(),
  });

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

  // Verify network ownership
  const network = await c.env.DB.prepare(
    'SELECT id FROM networks WHERE id = ? AND user_id = ?'
  )
    .bind(networkId, userId)
    .first();

  if (!network) {
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

// Queue consumer for processing batched metrics
export async function handleMetricsQueue(
  batch: MessageBatch<{
    device_id: string;
    user_id: string;
    metrics: MetricsBatch['metrics'];
    received_at: string;
  }>,
  env: Env
) {
  for (const msg of batch.messages) {
    const { device_id, metrics: entries } = msg.body;

    for (const entry of entries) {
      const bucket = entry.timestamp.slice(0, 16); // Truncate to minute: YYYY-MM-DDTHH:MM
      const qualityScore = computeQualityScore(entry);

      await env.DB.prepare(
        `INSERT INTO metrics (device_id, peer_device_id, bucket, bucket_size, latency_ms, jitter_ms,
         packet_loss_ratio, throughput_tx_bytes, throughput_rx_bytes, nat_type, connection_type, quality_score)
         VALUES (?, ?, ?, '1m', ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          device_id,
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

    msg.ack();
  }
}

function computeQualityScore(entry: MetricsBatch['metrics'][0]): number {
  let score = 100;

  // Latency penalties
  if (entry.latency_ms !== undefined) {
    if (entry.latency_ms > 300) score -= 30;
    else if (entry.latency_ms > 150) score -= 15;
    else if (entry.latency_ms > 50) score -= 5;
  }

  // Jitter penalties
  if (entry.jitter_ms !== undefined) {
    if (entry.jitter_ms > 100) score -= 20;
    else if (entry.jitter_ms > 50) score -= 10;
    else if (entry.jitter_ms > 20) score -= 5;
  }

  // Packet loss penalties
  if (entry.packet_loss_ratio !== undefined) {
    if (entry.packet_loss_ratio > 0.1) score -= 30;
    else if (entry.packet_loss_ratio > 0.05) score -= 15;
    else if (entry.packet_loss_ratio > 0.01) score -= 5;
  }

  // Relay penalty
  if (entry.connection_type === 'relay') score -= 10;

  return Math.max(0, score);
}
