import { Hono } from 'hono';
import type { Env } from '../types';
import { createAccessToken, createRefreshToken, refreshTokenTTL, verifyAccessToken } from './jwt';
import { authMiddleware } from './middleware';
import { checkRateLimit } from './ratelimit';
import { logAudit } from '../lib/audit';

const auth = new Hono<{ Bindings: Env }>();

// Escape HTML special characters before embedding untrusted strings in HTML responses
function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// POST /auth/refresh
auth.post('/refresh', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, { action: 'refresh', limit: 10, windowSeconds: 60 });
  if (rl.limited) {
    return c.json({ error: 'Too many requests. Try again later.' }, 429, { 'Retry-After': String(rl.retryAfter) });
  }

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

async function verifyRSAIdToken(
  idToken: string,
  jwksUrl: string,
  label: string,
  expectedAud: string,
  expectedIss: string | string[],
): Promise<{ sub: string; email?: string }> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Invalid id_token format');

  const headerJson = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
  const payloadJson = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

  // Validate standard claims before touching JWKS
  const now = Math.floor(Date.now() / 1000);
  if (payloadJson.exp < now) throw new Error(`${label} id_token has expired`);
  const allowedIss = Array.isArray(expectedIss) ? expectedIss : [expectedIss];
  if (!allowedIss.includes(payloadJson.iss)) throw new Error(`${label} id_token has unexpected issuer`);
  // Apple may return aud as the service ID string; Google returns the client ID
  const aud = Array.isArray(payloadJson.aud) ? payloadJson.aud : [payloadJson.aud];
  if (!aud.includes(expectedAud)) throw new Error(`${label} id_token has unexpected audience`);

  const jwksRes = await fetch(jwksUrl);
  const jwks = await jwksRes.json<{ keys: Array<JsonWebKey & { kid: string }> }>();

  const jwk = jwks.keys.find((k) => k.kid === headerJson.kid);
  if (!jwk) throw new Error(`No matching key found in ${label} JWKS`);

  const pubKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const sigBytes = b64urlDecode(parts[2]);
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);

  const valid = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, pubKey, sigBytes, signingInput);
  if (!valid) throw new Error(`Invalid ${label} id_token signature`);

  return { sub: payloadJson.sub, email: payloadJson.email };
}

function verifyAppleIdToken(idToken: string, env: Env) {
  return verifyRSAIdToken(
    idToken,
    'https://appleid.apple.com/auth/keys',
    'Apple',
    env.APPLE_SERVICE_ID,
    'https://appleid.apple.com',
  );
}

function verifyGoogleIdToken(idToken: string, env: Env) {
  return verifyRSAIdToken(
    idToken,
    'https://www.googleapis.com/oauth2/v3/certs',
    'Google',
    env.GOOGLE_CLIENT_ID,
    ['accounts.google.com', 'https://accounts.google.com'],
  );
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
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, { action: 'oauth-init', limit: 10, windowSeconds: 60 });
  if (rl.limited) return c.json({ error: 'Too many requests. Try again later.' }, 429);

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
    return c.html(`<!DOCTYPE html><html><body><h1>Sign in cancelled</h1><p>${escHtml(String(error))}</p><a href="/">Go back</a></body></html>`, 400);
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
  const { sub: appleSub, email: idTokenEmail } = await verifyAppleIdToken(tokenData.id_token, c.env);

  // Email: prefer id_token claim, fall back to user JSON param (first sign-in only)
  let email: string | undefined = idTokenEmail;
  if (!email && userParam) {
    try {
      const userJson = JSON.parse(userParam);
      email = userJson.email;
    } catch { /* ignore */ }
  }

  // Look up user: first by apple_sub, then by email
  let isNewUser = false;
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
      'INSERT INTO users (id, email, apple_sub) VALUES (?, ?, ?)'
    ).bind(userId, userEmail, appleSub).run();

    const networkId = crypto.randomUUID();
    await c.env.DB.prepare('INSERT INTO networks (id, user_id, name, cidr) VALUES (?, ?, ?, ?)')
      .bind(networkId, userId, 'default', '100.65.0.0/16')
      .run();

    user = { id: userId, email: userEmail, apple_sub: appleSub };
    isNewUser = true;
    c.executionCtx.waitUntil(fetch(c.env.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: `🆕 New user signed up via Apple: ${userEmail}` }),
    }));
  }

  const accessToken = await createAccessToken(user.id, user.email, c.env.JWT_SECRET);
  const refreshToken = await createRefreshToken();
  await c.env.KV.put(`refresh:${refreshToken}`, user.id, { expirationTtl: refreshTokenTTL() });

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId: user.id,
    action: isNewUser ? 'user.signup' : 'login',
    resourceType: 'user',
    resourceId: user.id,
    detail: `Signed in via Apple`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
  }));

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
window.location.replace('/dashboard');
</script>
</body>
</html>`);
});

// GET /google — initiate Google OAuth flow
auth.get('/google', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, { action: 'oauth-init', limit: 10, windowSeconds: 60 });
  if (rl.limited) return c.json({ error: 'Too many requests. Try again later.' }, 429);

  const cliSession = c.req.query('cli_session');

  const state = crypto.randomUUID();
  const stateValue = cliSession ? `poll:${cliSession}` : 'web';
  await c.env.KV.put(`state:${state}`, stateValue, { expirationTtl: 600 });

  const params = new URLSearchParams({
    client_id: c.env.GOOGLE_CLIENT_ID,
    redirect_uri: 'https://shireguard.com/v1/auth/google/callback',
    response_type: 'code',
    scope: 'openid email',
    state,
  });

  return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// GET /google/callback — Google redirects here with ?code=&state=
auth.get('/google/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');

  const stateData = await c.env.KV.get(`state:${state}`);
  if (!stateData) {
    return c.html('<h1>Invalid or expired state</h1>', 400);
  }
  await c.env.KV.delete(`state:${state}`);
  const isPollSession = stateData.startsWith('poll:');

  if (error) {
    return c.html(`<!DOCTYPE html><html><body><h1>Sign in cancelled</h1><p>${escHtml(String(error))}</p><a href="/">Go back</a></body></html>`, 400);
  }

  // Exchange code for tokens
  const tokenParams = new URLSearchParams({
    client_id: c.env.GOOGLE_CLIENT_ID,
    client_secret: c.env.GOOGLE_CLIENT_SECRET,
    code: code!,
    redirect_uri: 'https://shireguard.com/v1/auth/google/callback',
    grant_type: 'authorization_code',
  });

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenParams,
  });

  if (!tokenRes.ok) {
    console.error('Google token exchange failed:', await tokenRes.text());
    return c.html('<h1>Authentication failed</h1><a href="/">Go back</a>', 500);
  }

  const tokenData = await tokenRes.json<{ id_token: string }>();
  const { sub: googleSub, email } = await verifyGoogleIdToken(tokenData.id_token, c.env);

  // Look up user: first by google_sub, then by email (links existing accounts)
  let isNewUser = false;
  let user = await c.env.DB.prepare(
    'SELECT id, email, google_sub FROM users WHERE google_sub = ?'
  ).bind(googleSub).first<{ id: string; email: string; google_sub: string | null }>();

  if (!user && email) {
    const normalizedEmail = email.toLowerCase().trim();
    user = await c.env.DB.prepare(
      'SELECT id, email, google_sub FROM users WHERE email = ?'
    ).bind(normalizedEmail).first<{ id: string; email: string; google_sub: string | null }>();

    if (user && !user.google_sub) {
      await c.env.DB.prepare('UPDATE users SET google_sub = ? WHERE id = ?')
        .bind(googleSub, user.id)
        .run();
    }
  }

  if (!user) {
    const userId = crypto.randomUUID();
    const userEmail = email?.toLowerCase().trim() ?? `google_${googleSub}@noemail.local`;
    await c.env.DB.prepare(
      'INSERT INTO users (id, email, google_sub) VALUES (?, ?, ?)'
    ).bind(userId, userEmail, googleSub).run();

    const networkId = crypto.randomUUID();
    await c.env.DB.prepare('INSERT INTO networks (id, user_id, name, cidr) VALUES (?, ?, ?, ?)')
      .bind(networkId, userId, 'default', '100.65.0.0/16')
      .run();

    user = { id: userId, email: userEmail, google_sub: googleSub };
    isNewUser = true;
    c.executionCtx.waitUntil(fetch(c.env.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: `🆕 New user signed up via Google: ${userEmail}` }),
    }));
  }

  const accessToken = await createAccessToken(user.id, user.email, c.env.JWT_SECRET);
  const refreshToken = await createRefreshToken();
  await c.env.KV.put(`refresh:${refreshToken}`, user.id, { expirationTtl: refreshTokenTTL() });

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId: user.id,
    action: isNewUser ? 'user.signup' : 'login',
    resourceType: 'user',
    resourceId: user.id,
    detail: `Signed in via Google`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
  }));

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

  return c.html(`<!DOCTYPE html>
<html>
<head><title>Signing in...</title></head>
<body>
<script>
localStorage.setItem('sg_access_token', ${JSON.stringify(accessToken)});
localStorage.setItem('sg_refresh_token', ${JSON.stringify(refreshToken)});
localStorage.setItem('sg_user_email', ${JSON.stringify(user.email)});
window.location.replace('/dashboard');
</script>
</body>
</html>`);
});

// GET /github — initiate GitHub OAuth flow
auth.get('/github', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rl = await checkRateLimit(c.env.KV, ip, { action: 'oauth-init', limit: 10, windowSeconds: 60 });
  if (rl.limited) return c.json({ error: 'Too many requests. Try again later.' }, 429);

  const cliSession = c.req.query('cli_session');

  const state = crypto.randomUUID();
  const stateValue = cliSession ? `poll:${cliSession}` : 'web';
  await c.env.KV.put(`state:${state}`, stateValue, { expirationTtl: 600 });

  const params = new URLSearchParams({
    client_id: c.env.GITHUB_CLIENT_ID,
    redirect_uri: 'https://shireguard.com/v1/auth/github/callback',
    scope: 'read:user user:email',
    state,
  });

  return c.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

// GET /github/callback — GitHub redirects here with ?code=&state=
auth.get('/github/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');

  const stateData = await c.env.KV.get(`state:${state}`);
  if (!stateData) {
    return c.html('<h1>Invalid or expired state</h1>', 400);
  }
  await c.env.KV.delete(`state:${state}`);
  const isPollSession = stateData.startsWith('poll:');

  if (error) {
    return c.html(`<!DOCTYPE html><html><body><h1>Sign in cancelled</h1><p>${escHtml(String(error))}</p><a href="/">Go back</a></body></html>`, 400);
  }

  // Exchange code for access token
  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({
      client_id: c.env.GITHUB_CLIENT_ID,
      client_secret: c.env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: 'https://shireguard.com/v1/auth/github/callback',
    }),
  });

  if (!tokenRes.ok) {
    console.error('GitHub token exchange failed:', await tokenRes.text());
    return c.html('<h1>Authentication failed</h1><a href="/">Go back</a>', 500);
  }

  const { access_token } = await tokenRes.json<{ access_token: string }>();

  // Fetch user profile
  const userRes = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${access_token}`, 'User-Agent': 'shireguard' },
  });
  if (!userRes.ok) {
    return c.html('<h1>Failed to fetch GitHub profile</h1><a href="/">Go back</a>', 500);
  }
  const ghUser = await userRes.json<{ id: number; email: string | null; login: string }>();

  // Email may be private — fall back to the emails endpoint
  let email = ghUser.email;
  if (!email) {
    const emailsRes = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${access_token}`, 'User-Agent': 'shireguard' },
    });
    if (emailsRes.ok) {
      const emails = await emailsRes.json<Array<{ email: string; primary: boolean; verified: boolean }>>();
      email = emails.find((e) => e.primary && e.verified)?.email ?? emails[0]?.email ?? null;
    }
  }

  const githubId = String(ghUser.id);

  // Look up user: first by github_id, then by email (links existing accounts)
  let isNewUser = false;
  let user = await c.env.DB.prepare(
    'SELECT id, email, github_id FROM users WHERE github_id = ?'
  ).bind(githubId).first<{ id: string; email: string; github_id: string | null }>();

  if (!user && email) {
    const normalizedEmail = email.toLowerCase().trim();
    user = await c.env.DB.prepare(
      'SELECT id, email, github_id FROM users WHERE email = ?'
    ).bind(normalizedEmail).first<{ id: string; email: string; github_id: string | null }>();

    if (user && !user.github_id) {
      await c.env.DB.prepare('UPDATE users SET github_id = ? WHERE id = ?')
        .bind(githubId, user.id)
        .run();
      c.executionCtx.waitUntil(fetch(c.env.DISCORD_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: `🔗 Existing user linked GitHub: ${user.email} (@${ghUser.login})` }),
      }));
    }
  }

  if (!user) {
    const userId = crypto.randomUUID();
    const userEmail = email?.toLowerCase().trim() ?? `github_${githubId}@noemail.local`;
    await c.env.DB.prepare(
      'INSERT INTO users (id, email, github_id) VALUES (?, ?, ?)'
    ).bind(userId, userEmail, githubId).run();

    const networkId = crypto.randomUUID();
    await c.env.DB.prepare('INSERT INTO networks (id, user_id, name, cidr) VALUES (?, ?, ?, ?)')
      .bind(networkId, userId, 'default', '100.65.0.0/16')
      .run();

    user = { id: userId, email: userEmail, github_id: githubId };
    isNewUser = true;
    c.executionCtx.waitUntil(fetch(c.env.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: `🆕 New user signed up via GitHub: ${userEmail} (@${ghUser.login})` }),
    }));
  }

  const accessToken = await createAccessToken(user.id, user.email, c.env.JWT_SECRET);
  const refreshToken = await createRefreshToken();
  await c.env.KV.put(`refresh:${refreshToken}`, user.id, { expirationTtl: refreshTokenTTL() });

  c.executionCtx.waitUntil(logAudit(c.env.DB, {
    userId: user.id,
    action: isNewUser ? 'user.signup' : 'login',
    resourceType: 'user',
    resourceId: user.id,
    detail: `Signed in via GitHub`,
    ip: c.req.header('CF-Connecting-IP') ?? null,
  }));

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

  return c.html(`<!DOCTYPE html>
<html>
<head><title>Signing in...</title></head>
<body>
<script>
localStorage.setItem('sg_access_token', ${JSON.stringify(accessToken)});
localStorage.setItem('sg_refresh_token', ${JSON.stringify(refreshToken)});
localStorage.setItem('sg_user_email', ${JSON.stringify(user.email)});
window.location.replace('/dashboard');
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

// GET /me — returns current user's profile and linked providers
auth.get('/me', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const user = await c.env.DB.prepare(
    'SELECT email, tier, apple_sub, google_sub, github_id, created_at FROM users WHERE id = ?'
  ).bind(userId).first<{
    email: string;
    tier: string | null;
    apple_sub: string | null;
    google_sub: string | null;
    github_id: string | null;
    created_at: string;
  }>();

  if (!user) return c.json({ error: 'User not found' }, 404);

  return c.json({
    email: user.email,
    tier: user.tier || 'free',
    providers: {
      apple: !!user.apple_sub,
      google: !!user.google_sub,
      github: !!user.github_id,
    },
    created_at: user.created_at,
  });
});

export { auth };

