import { Hono } from 'hono';
import type { Env } from '../types';
import { hashPassword, verifyPassword } from './crypto';
import { createAccessToken, createRefreshToken, refreshTokenTTL, verifyAccessToken } from './jwt';
import { authMiddleware } from './middleware';

const auth = new Hono<{ Bindings: Env }>();

// POST /auth/register
auth.post('/register', async (c) => {
  const body = await c.req.json<{ email: string; password: string }>();
  if (!body.email || !body.password) {
    return c.json({ error: 'Email and password are required' }, 400);
  }

  if (body.password.length < 8) {
    return c.json({ error: 'Password must be at least 8 characters' }, 400);
  }

  const email = body.email.toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return c.json({ error: 'Invalid email format' }, 400);
  }

  // Check if user exists
  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(email)
    .first();
  if (existing) {
    return c.json({ error: 'Email already registered' }, 409);
  }

  const userId = crypto.randomUUID();
  const passwordHash = await hashPassword(body.password);

  await c.env.DB.prepare('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)')
    .bind(userId, email, passwordHash)
    .run();

  // Create default network
  const networkId = crypto.randomUUID();
  await c.env.DB.prepare('INSERT INTO networks (id, user_id, name) VALUES (?, ?, ?)')
    .bind(networkId, userId, 'default')
    .run();

  const accessToken = await createAccessToken(userId, email, c.env.JWT_SECRET);
  const refreshToken = await createRefreshToken();

  // Store refresh token in KV
  await c.env.KV.put(`refresh:${refreshToken}`, userId, { expirationTtl: refreshTokenTTL() });

  return c.json({
    user: { id: userId, email },
    network: { id: networkId, name: 'default', cidr: '10.100.0.0/24' },
    access_token: accessToken,
    refresh_token: refreshToken,
  }, 201);
});

// POST /auth/login
auth.post('/login', async (c) => {
  const body = await c.req.json<{ email: string; password: string }>();
  if (!body.email || !body.password) {
    return c.json({ error: 'Email and password are required' }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const user = await c.env.DB.prepare('SELECT id, email, password_hash FROM users WHERE email = ?')
    .bind(email)
    .first<{ id: string; email: string; password_hash: string }>();

  if (!user || !(await verifyPassword(body.password, user.password_hash))) {
    return c.json({ error: 'Invalid email or password' }, 401);
  }

  const accessToken = await createAccessToken(user.id, user.email, c.env.JWT_SECRET);
  const refreshToken = await createRefreshToken();

  await c.env.KV.put(`refresh:${refreshToken}`, user.id, { expirationTtl: refreshTokenTTL() });

  return c.json({
    user: { id: user.id, email: user.email },
    access_token: accessToken,
    refresh_token: refreshToken,
  });
});

// POST /auth/refresh
auth.post('/refresh', async (c) => {
  const body = await c.req.json<{ refresh_token: string }>();
  if (!body.refresh_token) {
    return c.json({ error: 'Refresh token is required' }, 400);
  }

  const userId = await c.env.KV.get(`refresh:${body.refresh_token}`);
  if (!userId) {
    return c.json({ error: 'Invalid or expired refresh token' }, 401);
  }

  // Rotate refresh token
  await c.env.KV.delete(`refresh:${body.refresh_token}`);

  const user = await c.env.DB.prepare('SELECT id, email FROM users WHERE id = ?')
    .bind(userId)
    .first<{ id: string; email: string }>();

  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }

  const accessToken = await createAccessToken(user.id, user.email, c.env.JWT_SECRET);
  const newRefreshToken = await createRefreshToken();

  await c.env.KV.put(`refresh:${newRefreshToken}`, user.id, { expirationTtl: refreshTokenTTL() });

  return c.json({
    access_token: accessToken,
    refresh_token: newRefreshToken,
  });
});

// POST /auth/api-keys (authenticated)
auth.post('/api-keys', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const body = await c.req.json<{ name: string; expires_in_days?: number }>();
  if (!body.name) {
    return c.json({ error: 'Name is required' }, 400);
  }

  // Generate API key: sg_<prefix>_<random>
  const prefixBytes = crypto.getRandomValues(new Uint8Array(4));
  const randomBytes = crypto.getRandomValues(new Uint8Array(24));
  let prefix = '';
  for (const b of prefixBytes) prefix += b.toString(16).padStart(2, '0');
  let random = '';
  for (const b of randomBytes) random += b.toString(16).padStart(2, '0');

  const apiKey = `sg_${prefix}_${random}`;

  // Hash the full key for storage
  const keyBytes = new TextEncoder().encode(apiKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
  const hashArray = new Uint8Array(hashBuffer);
  let keyHash = '';
  for (const byte of hashArray) {
    keyHash += byte.toString(16).padStart(2, '0');
  }

  const id = crypto.randomUUID();
  const expiresAt = body.expires_in_days
    ? new Date(Date.now() + body.expires_in_days * 86400000).toISOString()
    : null;

  await c.env.DB.prepare(
    'INSERT INTO api_keys (id, user_id, name, key_hash, prefix, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind(id, userId, body.name, keyHash, `sg_${prefix}`, expiresAt)
    .run();

  return c.json({
    id,
    name: body.name,
    key: apiKey, // Only returned once at creation
    prefix: `sg_${prefix}`,
    expires_at: expiresAt,
  }, 201);
});

// GET /auth/api-keys (authenticated)
auth.get('/api-keys', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const keys = await c.env.DB.prepare(
    'SELECT id, name, prefix, created_at, last_used_at, expires_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC'
  )
    .bind(userId)
    .all();

  return c.json({ api_keys: keys.results });
});

// DELETE /auth/api-keys/:id (authenticated)
auth.delete('/api-keys/:id', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const keyId = c.req.param('id');

  const result = await c.env.DB.prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?')
    .bind(keyId, userId)
    .run();

  if (!result.meta.changes) {
    return c.json({ error: 'API key not found' }, 404);
  }
  return c.json({ deleted: true });
});

export { auth };
