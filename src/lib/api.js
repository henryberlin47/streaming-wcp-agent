import {
  SEO_MONITOR_BASE, SEO_MONITOR_TOKEN, CDN_API_BASE, CDN_API_KEY,
} from './siteConfig.js';

// ============================================================
//  api.js — SEO monitor + CDN registry HTTP calls
// ============================================================
// All calls are best-effort: they return {ok, status} and never throw, so a
// failed registration warns but never aborts a deploy (matching the scripts).
// ============================================================

async function req(url, { method = 'GET', headers = {}, body, timeout = 15000 } = {}) {
  try {
    const res = await fetch(url, {
      method,
      headers,
      body: body != null ? JSON.stringify(body) : undefined,
      // node fetch: no global timeout; add an AbortController guard.
      signal: AbortSignal.timeout(timeout),
    });
    return { ok: res.ok, status: res.status };
  } catch (e) {
    // Surface the underlying network cause (ECONNREFUSED/ETIMEDOUT/ENOTFOUND/…)
    // rather than the generic "fetch failed".
    return { ok: false, status: 0, error: e?.cause?.code || e?.name || e?.message || 'request failed' };
  }
}

// --- SEO monitor "brands" ---------------------------------------------------

export function brandAdd(host) {
  return req(`${SEO_MONITOR_BASE}/api/machine/brands`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${SEO_MONITOR_TOKEN}`, 'Content-Type': 'application/json' },
    body: { host },
  });
}

export function brandDelete(host) {
  return req(`${SEO_MONITOR_BASE}/api/machine/brands`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${SEO_MONITOR_TOKEN}`, 'Content-Type': 'application/json' },
    body: { host },
  });
}

// --- CDN registry -----------------------------------------------------------

export function cdnAdd(domain, prefix) {
  return req(`${CDN_API_BASE}/domains`, {
    method: 'POST',
    headers: { 'x-api-key': CDN_API_KEY, 'Content-Type': 'application/json' },
    body: { domain, prefix },
    timeout: 120000, // endpoint issues an SSL cert synchronously (certbot) — can take well over 15s
  });
}

export function cdnDelete(domain) {
  return req(`${CDN_API_BASE}/domains/${encodeURIComponent(domain)}`, {
    method: 'DELETE',
    headers: { 'x-api-key': CDN_API_KEY },
  });
}