import crypto from 'node:crypto';
import config from './config.js';

// Constant-time string compare to avoid timing attacks on the token.
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) {
    // Still do a compare to keep timing roughly constant, then fail.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

// Resolve the client IP, honouring X-Forwarded-For only when explicitly trusted.
export function clientIp(req) {
  if (config.trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
  }
  // req.socket.remoteAddress may be IPv6-mapped IPv4 (::ffff:1.2.3.4)
  let ip = req.socket?.remoteAddress || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

function ipAllowed(ip) {
  if (config.allowedIps.length === 0) return true; // no allowlist configured
  return config.allowedIps.includes(ip);
}

// An address that keeps presenting wrong keys is locked out for a while, so the
// key cannot be guessed at network speed. Counted per IP, in memory.
const MAX_BAD = 10, WINDOW_MS = 5 * 60_000, LOCK_MS = 15 * 60_000;
const bad = new Map(); // ip -> { n, first, until }
export function lockedOut(ip, now = Date.now()) {
  const e = bad.get(ip);
  return !!e && e.until > now;
}
export function noteBadKey(ip, now = Date.now()) {
  let e = bad.get(ip);
  if (!e || now - e.first > WINDOW_MS) e = { n: 0, first: now, until: 0 };
  e.n++;
  if (e.n >= MAX_BAD) { e.until = now + LOCK_MS; e.n = 0; e.first = now; console.log(`[auth] ${ip} locked out for 15 min after ${MAX_BAD} wrong keys`); }
  bad.set(ip, e);
  if (bad.size > 5000) bad.clear(); // never grow without bound
}

// Express middleware: enforces IP allowlist first, then bearer token.
export function requireAuth(req, res, next) {
  const ip = clientIp(req);

  if (!ipAllowed(ip)) {
    // Don't reveal whether the token would have been valid.
    console.log(`[auth] refused ${ip}: not on the allowlist (${req.method} ${req.path})`);
    return res.status(403).json({ error: 'forbidden', reason: 'ip_not_allowed' });
  }
  if (lockedOut(ip)) {
    return res.status(429).json({ error: 'too_many_attempts', reason: 'locked_out' });
  }

  const hdr = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(hdr);
  if (!m) {
    console.log(`[auth] refused ${ip}: no key sent (${req.method} ${req.path})`);
    return res.status(401).json({ error: 'unauthorized', reason: 'missing_bearer' });
  }
  // nextToken: set by a key rotation, valid alongside the old key only until the
  // restart it schedules — so the portal can read the result and switch over.
  if (!safeEqual(m[1], config.authToken) && !(config.nextToken && safeEqual(m[1], config.nextToken))) {
    noteBadKey(ip);
    console.log(`[auth] refused ${ip}: wrong key (${req.method} ${req.path})`);
    return res.status(401).json({ error: 'unauthorized', reason: 'bad_token' });
  }

  req.clientIp = ip;
  next();
}