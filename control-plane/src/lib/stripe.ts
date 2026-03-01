const STRIPE_API = 'https://api.stripe.com/v1';

/**
 * Minimal fetch-based Stripe REST client (no npm dependency).
 * Params are sent as x-www-form-urlencoded.
 */
export async function stripeRequest(
  secretKey: string,
  method: string,
  path: string,
  params?: Record<string, string>,
): Promise<any> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${secretKey}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  const opts: RequestInit = { method, headers };
  if (params && (method === 'POST' || method === 'PATCH')) {
    opts.body = new URLSearchParams(params).toString();
  }

  const res = await fetch(`${STRIPE_API}${path}`, opts);
  const data = await res.json() as any;

  if (!res.ok) {
    const msg = data?.error?.message || `Stripe API error ${res.status}`;
    throw new Error(msg);
  }

  return data;
}

/**
 * Verify a Stripe webhook signature using Web Crypto API (HMAC-SHA256).
 * Checks the `t=...,v1=...` format from the Stripe-Signature header.
 * Returns the parsed event on success, throws on failure.
 */
export async function verifyWebhookSignature(
  payload: string,
  sigHeader: string,
  secret: string,
): Promise<any> {
  const parts = sigHeader.split(',').reduce((acc, part) => {
    const [key, val] = part.split('=');
    if (key === 't') acc.timestamp = val;
    if (key === 'v1') acc.signatures.push(val);
    return acc;
  }, { timestamp: '', signatures: [] as string[] });

  if (!parts.timestamp || parts.signatures.length === 0) {
    throw new Error('Invalid Stripe signature header');
  }

  // Reject timestamps older than 5 minutes
  const ts = parseInt(parts.timestamp, 10);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > 300) {
    throw new Error('Webhook timestamp too old');
  }

  const signedPayload = `${parts.timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
  const expected = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const match = parts.signatures.some((s) => timingSafeEqual(s, expected));
  if (!match) {
    throw new Error('Webhook signature verification failed');
  }

  return JSON.parse(payload);
}

/** Constant-time string comparison */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
