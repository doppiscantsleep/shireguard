import { Hono } from 'hono';
import type { Env } from '../types';
import { hashPassword, verifyPassword } from './crypto';
import { createAccessToken, createRefreshToken, refreshTokenTTL, verifyAccessToken } from './jwt';
import { authMiddleware } from './middleware';
import { checkRateLimit } from './ratelimit';

const auth = new Hono<{ Bindings: Env }>();

// POST /auth/register
auth.post('/register', async (c) => {
  // Rate limit: 5 registration attempts per IP per hour.
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, {
    action: 'register',
    limit: 5,
    windowSeconds: 3600,
  });
  if (rl.limited) {
    return c.json({ error: 'Too many registration attempts. Try again later.' }, 429, {
      'Retry-After': String(rl.retryAfter),
    });
  }

  const body = await c.req.json<{ email: string; password: string; invite_code?: string }>();
  if (!body.email || !body.password) {
    return c.json({ error: 'Email and password are required' }, 400);
  }

  if (body.invite_code !== c.env.INVITE_CODE) {
    return c.json({ error: 'Invalid invite code' }, 403);
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
  await c.env.DB.prepare('INSERT INTO networks (id, user_id, name, cidr) VALUES (?, ?, ?, ?)')
    .bind(networkId, userId, 'default', '100.65.0.0/16')
    .run();

  const accessToken = await createAccessToken(userId, email, c.env.JWT_SECRET);
  const refreshToken = await createRefreshToken();

  // Store refresh token in KV
  await c.env.KV.put(`refresh:${refreshToken}`, userId, { expirationTtl: refreshTokenTTL() });

  return c.json({
    user: { id: userId, email },
    network: { id: networkId, name: 'default', cidr: '100.65.0.0/16' },
    access_token: accessToken,
    refresh_token: refreshToken,
  }, 201);
});

// POST /auth/login
auth.post('/login', async (c) => {
  // Rate limit: 10 login attempts per IP per minute.
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, {
    action: 'login',
    limit: 10,
    windowSeconds: 60,
  });
  if (rl.limited) {
    return c.json({ error: 'Too many login attempts. Try again later.' }, 429, {
      'Retry-After': String(rl.retryAfter),
    });
  }

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

// ── Apple Sign-In helpers ──

function b64urlFromBytes(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlFromString(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str: string): Uint8Array {
  const binary = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function buildAppleClientSecret(env: Env): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  const header = { alg: 'ES256', kid: env.APPLE_KEY_ID };
  const payload = {
    iss: env.APPLE_TEAM_ID,
    iat,
    exp: iat + 300,
    aud: 'https://appleid.apple.com',
    sub: env.APPLE_SERVICE_ID,
  };

  const headerB64 = b64urlFromString(JSON.stringify(header));
  const payloadB64 = b64urlFromString(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  // Parse PEM private key from .p8 file (standard base64, not base64url)
  const pemContent = env.APPLE_PRIVATE_KEY
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  const pemBinary = atob(pemContent);
  const keyBytes = new Uint8Array(pemBinary.length);
  for (let i = 0; i < pemBinary.length; i++) keyBytes[i] = pemBinary.charCodeAt(i);

  const key = await crypto.subtle.importKey(
    'pkcs8',
    keyBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const signingData = new TextEncoder().encode(signingInput);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, signingData);

  return `${signingInput}.${b64urlFromBytes(new Uint8Array(signature))}`;
}

async function verifyAppleIdToken(idToken: string): Promise<{ sub: string; email?: string }> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Invalid id_token format');

  const headerJson = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
  const payloadJson = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

  // Fetch Apple JWKS (Apple uses RSA keys for id_token signing)
  const jwksRes = await fetch('https://appleid.apple.com/auth/keys');
  const jwks = await jwksRes.json<{ keys: Array<JsonWebKey & { kid: string }> }>();

  const jwk = jwks.keys.find((k) => k.kid === headerJson.kid);
  if (!jwk) throw new Error('No matching key found in Apple JWKS');

  const pubKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const sigBytes = b64urlDecode(parts[2]);
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);

  const valid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    pubKey,
    sigBytes,
    signingInput
  );
  if (!valid) throw new Error('Invalid Apple id_token signature');

  return { sub: payloadJson.sub, email: payloadJson.email };
}

// Only allow localhost CLI redirect URIs (prevents open redirect abuse)
function isLocalhostURL(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost');
  } catch {
    return false;
  }
}

// GET /apple — initiate Apple OAuth flow
// Accepts optional ?cli_session=<id> for CLI polling logins
// Accepts optional ?cli_redirect=http://127.0.0.1:PORT/callback for legacy CLI logins
auth.get('/apple', async (c) => {
  const cliSession = c.req.query('cli_session');
  const cliRedirect = c.req.query('cli_redirect');

  if (cliRedirect && !isLocalhostURL(cliRedirect)) {
    return c.json({ error: 'Invalid cli_redirect: must be a localhost URL' }, 400);
  }

  const state = crypto.randomUUID();
  // Determine state value: poll:<sessionId> | <redirectURL> | "web"
  let stateValue: string;
  if (cliSession) {
    stateValue = `poll:${cliSession}`;
  } else if (cliRedirect) {
    stateValue = cliRedirect;
  } else {
    stateValue = 'web';
  }
  await c.env.KV.put(`state:${state}`, stateValue, { expirationTtl: 600 });

  const params = new URLSearchParams({
    client_id: c.env.APPLE_SERVICE_ID,
    redirect_uri: 'https://shireguard.com/v1/auth/apple/callback',
    response_type: 'code',
    response_mode: 'form_post',
    scope: 'email',
    state,
  });

  return c.redirect(`https://appleid.apple.com/auth/authorize?${params}`);
});

// POST /apple/callback — Apple posts form_post here
auth.post('/apple/callback', async (c) => {
  const formData = await c.req.formData();
  const code = formData.get('code') as string;
  const state = formData.get('state') as string;
  const error = formData.get('error') as string | null;
  const userParam = formData.get('user') as string | null;

  // Validate state and retrieve stateData (poll:<id> | <redirectURL> | "web")
  const stateData = await c.env.KV.get(`state:${state}`);
  if (!stateData) {
    return c.html('<h1>Invalid or expired state</h1>', 400);
  }
  await c.env.KV.delete(`state:${state}`);
  const isPollSession = stateData.startsWith('poll:');
  const cliRedirect = !isPollSession && stateData !== 'web' ? stateData : null;

  if (error) {
    return c.html(`<!DOCTYPE html><html><body><h1>Sign in cancelled</h1><p>${error}</p><a href="/">Go back</a></body></html>`, 400);
  }

  // Exchange code for tokens
  const clientSecret = await buildAppleClientSecret(c.env);
  const tokenParams = new URLSearchParams({
    client_id: c.env.APPLE_SERVICE_ID,
    client_secret: clientSecret,
    code,
    redirect_uri: 'https://shireguard.com/v1/auth/apple/callback',
    grant_type: 'authorization_code',
  });

  const tokenRes = await fetch('https://appleid.apple.com/auth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenParams,
  });

  if (!tokenRes.ok) {
    const errBody = await tokenRes.text();
    console.error('Apple token exchange failed:', errBody);
    return c.html('<h1>Authentication failed</h1><a href="/">Go back</a>', 500);
  }

  const tokenData = await tokenRes.json<{ id_token: string }>();
  const { sub: appleSub, email: idTokenEmail } = await verifyAppleIdToken(tokenData.id_token);

  // Email: prefer id_token claim, fall back to user JSON param (first sign-in only)
  let email: string | undefined = idTokenEmail;
  if (!email && userParam) {
    try {
      const userJson = JSON.parse(userParam);
      email = userJson.email;
    } catch { /* ignore */ }
  }

  // Look up user: first by apple_sub, then by email
  let user = await c.env.DB.prepare(
    'SELECT id, email, apple_sub FROM users WHERE apple_sub = ?'
  ).bind(appleSub).first<{ id: string; email: string; apple_sub: string | null }>();

  if (!user && email) {
    const normalizedEmail = email.toLowerCase().trim();
    user = await c.env.DB.prepare(
      'SELECT id, email, apple_sub FROM users WHERE email = ?'
    ).bind(normalizedEmail).first<{ id: string; email: string; apple_sub: string | null }>();

    if (user && !user.apple_sub) {
      // Link apple_sub to existing email account
      await c.env.DB.prepare('UPDATE users SET apple_sub = ? WHERE id = ?')
        .bind(appleSub, user.id)
        .run();
    }
  }

  if (!user) {
    // Create new user
    const userId = crypto.randomUUID();
    const userEmail = email?.toLowerCase().trim() ?? `apple_${appleSub}@noemail.local`;
    await c.env.DB.prepare(
      'INSERT INTO users (id, email, password_hash, apple_sub) VALUES (?, ?, ?, ?)'
    ).bind(userId, userEmail, crypto.randomUUID(), appleSub).run();

    const networkId = crypto.randomUUID();
    await c.env.DB.prepare('INSERT INTO networks (id, user_id, name, cidr) VALUES (?, ?, ?, ?)')
      .bind(networkId, userId, 'default', '100.65.0.0/16')
      .run();

    user = { id: userId, email: userEmail, apple_sub: appleSub };
  }

  const accessToken = await createAccessToken(user.id, user.email, c.env.JWT_SECRET);
  const refreshToken = await createRefreshToken();
  await c.env.KV.put(`refresh:${refreshToken}`, user.id, { expirationTtl: refreshTokenTTL() });

  // Poll-based CLI login: store tokens in KV for the CLI to pick up
  if (isPollSession) {
    const sessionId = stateData.slice('poll:'.length);
    await c.env.KV.put(
      `cli_session:${sessionId}`,
      JSON.stringify({ access_token: accessToken, refresh_token: refreshToken, email: user.email }),
      { expirationTtl: 300 }
    );
    return c.html(`<!DOCTYPE html>
<html>
<head><title>Signed in</title></head>
<body style="font-family:sans-serif;text-align:center;padding:4rem">
<h2>&#x2713; Signed in</h2>
<p>You can close this tab and return to the terminal.</p>
</body>
</html>`);
  }

  // Legacy CLI login: redirect to local callback server with tokens in query params
  if (cliRedirect) {
    const params = new URLSearchParams({
      access_token: accessToken,
      refresh_token: refreshToken,
      email: user.email,
    });
    return c.redirect(`${cliRedirect}?${params}`);
  }

  // Web login: store tokens in localStorage and redirect to dashboard
  return c.html(`<!DOCTYPE html>
<html>
<head><title>Signing in...</title></head>
<body>
<script>
localStorage.setItem('sg_access_token', ${JSON.stringify(accessToken)});
localStorage.setItem('sg_refresh_token', ${JSON.stringify(refreshToken)});
localStorage.setItem('sg_user_email', ${JSON.stringify(user.email)});
window.location.replace('/');
</script>
</body>
</html>`);
});

// GET /poll — CLI polls this endpoint until tokens are ready
auth.get('/poll', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, {
    action: 'poll',
    limit: 60,
    windowSeconds: 60,
  });
  if (rl.limited) {
    return c.json({ error: 'Too many poll requests. Try again later.' }, 429, {
      'Retry-After': String(rl.retryAfter),
    });
  }

  const sessionId = c.req.query('session_id');
  if (!sessionId) {
    return c.json({ error: 'session_id is required' }, 400);
  }

  const data = await c.env.KV.get(`cli_session:${sessionId}`);
  if (!data) {
    return c.json({ status: 'pending' }, 202);
  }

  await c.env.KV.delete(`cli_session:${sessionId}`);
  const tokens = JSON.parse(data) as { access_token: string; refresh_token: string; email: string };
  return c.json({ status: 'complete', ...tokens });
});

export { auth };

