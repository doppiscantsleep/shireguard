# Shireguard Control Plane - Network Security Architect Memory

## Project Overview
- Cloudflare Workers-based WireGuard P2P connectivity control plane
- Stack: Hono framework, Cloudflare D1 (SQLite), KV, Durable Objects
- Repo: /Users/alan/code/repos/shireguard/control-plane

## Key Architecture
- Main router: src/index.ts
- Auth handlers (register/login/refresh/API keys): src/auth/handlers.ts
- Auth middleware (JWT + API key): src/auth/middleware.ts
- Rate limiter (KV fixed-window): src/auth/ratelimit.ts  [added 2026-02-18]
- JWT (custom HMAC-SHA256): src/auth/jwt.ts
- Password hashing (PBKDF2): src/auth/crypto.ts
- Device API: src/api/devices.ts
- Network API: src/api/networks.ts
- Metrics ingestion: src/api/metrics.ts
- WebSocket signaling (Durable Object): src/signaling/room.ts
- Dashboard SPA: src/dashboard.html
- Config: wrangler.toml
- Schema: src/db/migrations/0001_init.sql

## Security Issues Status (Audit 2026-02-18)
See: security-audit-2026-02.md for full findings

### FIXED (2026-02-18)
- CORS restricted to https://shireguard.com (was '*') — src/index.ts
- KV rate limiting on login (10/min) and register (5/hour) by CF-Connecting-IP — src/auth/ratelimit.ts + handlers.ts
- WebSocket signaling now enforces network isolation: senderNetworkId vs peerNetworkId tag compared before forwarding — src/signaling/room.ts
- peer_device_id in metrics batch validated to same network_id as reporting device — src/api/metrics.ts

### OPEN — HIGH
- JWT has no issuer/audience claims; no revocation mechanism
- No input length limits on any field (name, public_key, endpoint, etc.)
- metrics/summary endpoint does not verify device belongs to requesting user's network (data join only on network ownership, not per-device auth)
- Heartbeat endpoint accepts arbitrary endpoint string with no validation
- database_id exposed in wrangler.toml (committed to repo)
- MEDIUM: API key hashed with plain SHA-256 (no salt, no PBKDF2)
- MEDIUM: Refresh token stored in KV with no rotation race condition protection
- MEDIUM: CIDR validation is regex-only (values like 999.999.999.999/99 pass)
- MEDIUM: No Content-Security-Policy header on dashboard
- MEDIUM: Tokens stored in JS variables (not HttpOnly cookies)
- MEDIUM: Audit log table exists in schema but is never written to
- MEDIUM: SELECT * used in devices/:id and networks/:id (over-exposure)
- LOW: PBKDF2 uses SHA-256 at 100k iterations (acceptable but bcrypt/Argon2 preferred)
- LOW: No account lockout after failed logins
- LOW: Error messages from DB exceptions can leak via thrown errors
