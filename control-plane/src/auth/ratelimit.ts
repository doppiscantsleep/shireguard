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
  const counterKey = `rl:${action}:${safeIp}`;
  const windowStartKey = `rl:${action}:${safeIp}:ws`;

  // Read the current counter value (may be null on first request).
  const raw = await kv.get(counterKey);
  const count = raw !== null ? parseInt(raw, 10) : 0;

  if (count >= limit) {
    // Determine how long until the window resets.
    const windowStartRaw = await kv.get(windowStartKey);
    const windowStart = windowStartRaw !== null ? parseInt(windowStartRaw, 10) : Date.now();
    const elapsed = Math.floor((Date.now() - windowStart) / 1000);
    const retryAfter = Math.max(1, windowSeconds - elapsed);
    return { limited: true, retryAfter };
  }

  // Increment the counter.  On the first request also record the window-start
  // timestamp and set TTLs so both keys expire together.
  const newCount = count + 1;
  if (newCount === 1) {
    // First request in this window — set both keys with the full TTL.
    const nowMs = Date.now().toString();
    await Promise.all([
      kv.put(counterKey, String(newCount), { expirationTtl: windowSeconds }),
      kv.put(windowStartKey, nowMs, { expirationTtl: windowSeconds }),
    ]);
  } else {
    // Subsequent request — only update the counter; the TTL on the key is
    // already ticking down from when the window opened.  We cannot extend or
    // read the remaining TTL via the Workers KV API, so we write without a
    // TTL override and rely on the original expiration.
    await kv.put(counterKey, String(newCount));
  }

  return { limited: false, retryAfter: 0 };
}
