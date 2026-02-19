import { Context, Next } from 'hono';
import type { Env, JWTPayload } from '../types';
import { verifyAccessToken } from './jwt';

// Extend Hono context with auth info
declare module 'hono' {
  interface ContextVariableMap {
    userId: string;
    userEmail: string;
  }
}

export async function authMiddleware(c: Context<{ Bindings: Env }>, next: Next) {
  const authHeader = c.req.header('Authorization');
  if (!authHeader) {
    return c.json({ error: 'Missing Authorization header' }, 401);
  }

  // Try Bearer token (JWT)
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const payload = await verifyAccessToken(token, c.env.JWT_SECRET);
    if (!payload) {
      return c.json({ error: 'Invalid or expired token' }, 401);
    }
    c.set('userId', payload.sub);
    c.set('userEmail', payload.email);
    return next();
  }

  // Try API key
  if (authHeader.startsWith('ApiKey ')) {
    const apiKey = authHeader.slice(7);
    const prefix = apiKey.slice(0, 8);

    // Hash the key to compare
    const keyBytes = new TextEncoder().encode(apiKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
    const hashArray = new Uint8Array(hashBuffer);
    let keyHash = '';
    for (const byte of hashArray) {
      keyHash += byte.toString(16).padStart(2, '0');
    }

    const result = await c.env.DB.prepare(
      'SELECT ak.user_id, u.email FROM api_keys ak JOIN users u ON u.id = ak.user_id WHERE ak.prefix = ? AND ak.key_hash = ? AND (ak.expires_at IS NULL OR ak.expires_at > datetime(\'now\'))'
    )
      .bind(prefix, keyHash)
      .first<{ user_id: string; email: string }>();

    if (!result) {
      return c.json({ error: 'Invalid API key' }, 401);
    }

    // Update last_used_at
    await c.env.DB.prepare('UPDATE api_keys SET last_used_at = datetime(\'now\') WHERE prefix = ? AND key_hash = ?')
      .bind(prefix, keyHash)
      .run();

    c.set('userId', result.user_id);
    c.set('userEmail', result.email);
    return next();
  }

  return c.json({ error: 'Invalid Authorization header format' }, 401);
}
