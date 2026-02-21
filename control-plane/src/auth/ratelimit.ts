import type { Env } from '../types';

export interface RateLimitConfig {
  /** Unique name for this limit bucket (e.g. 'login', 'register'). */
  action: string;
  /** Maximum number of attempts allowed within the window. */
  limit: number;
  /** Window duration in seconds. The counter resets after this many seconds. */
  windowSeconds: number;
}

export interface RateLimitResult {
  limited: boolean;
  /** Seconds until the window resets. Only meaningful when limited === true. */
  retryAfter: number;
}

/**
 * KV-based fixed-window rate limiter.
 *
 * Key structure: rl:<action>:<ip>
 *
 * On the first request in a window the key is written with the TTL equal to
 * windowSeconds, establishing the window boundary.  Subsequent requests
 * increment the counter.  Because KV TTLs are set at write time we use a
 * separate "window start" key to calculate the remaining TTL for Retry-After
 * responses, rather than trying to read the remaining TTL from KV (which is
 * not exposed by the Workers KV API).
 *
 * This is a fixed-window counter — not a sliding window — which is acceptable
 * for the low-volume auth endpoints it protects.
 */
export async function checkRateLimit(
  kv: Env['KV'],
  ip: string,
  config: RateLimitConfig,
): Promise<RateLimitResult> {
  const { action, limit, windowSeconds } = config;

  // Sanitise the IP to avoid any path-traversal style shenanigans in KV keys.
  const safeIp = ip.replace(/[^0-9a-fA-F.:]/g, '_').slice(0, 45);

  // Use epoch-based key names so every write carries the full TTL.
  // Each epoch maps to one fixed window, so the counter key naturally becomes
  // irrelevant once the epoch advances — no separate window-start key needed.
  const nowSeconds = Math.floor(Date.now() / 1000);
  const epoch = Math.floor(nowSeconds / windowSeconds);
  const counterKey = `rl:${action}:${safeIp}:${epoch}`;

  // Seconds remaining until the epoch boundary (used for Retry-After).
  const retryAfter = windowSeconds - (nowSeconds % windowSeconds);

  const raw = await kv.get(counterKey);
  const count = raw !== null ? parseInt(raw, 10) : 0;

  if (count >= limit) {
    return { limited: true, retryAfter };
  }

  // Write with a TTL of two windows so old epoch keys get cleaned up by KV
  // even if the counter never reaches the limit.
  await kv.put(counterKey, String(count + 1), { expirationTtl: windowSeconds * 2 });

  return { limited: false, retryAfter: 0 };
}
