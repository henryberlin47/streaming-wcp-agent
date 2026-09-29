import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { pipeline } from 'node:stream/promises';

// ============================================================
//  s3.js — the four S3 calls backups need, for DigitalOcean Spaces
// ============================================================
// put (a file) · get (to a file) · list (a prefix) · del. Signed with AWS
// Signature V4 using node:crypto — no SDK: the agent's only dependency stays
// express, and these four calls are ~100 lines.
// Path-style URLs (https://<region>.digitaloceanspaces.com/<bucket>/<key>), which
// Spaces supports and which keep the TLS host independent of the bucket name.
// ponytail: single PUT, so one object is capped at 5 GB (a compressed dump of a
// WordPress DB is far below). Switch put() to multipart upload if that is hit.
// ============================================================

const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const encPath = (p) => p.split('/').map(enc).join('/');
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const sha256 = (d) => crypto.createHash('sha256').update(d).digest('hex');
export const EMPTY_SHA = sha256('');

/** Sign one request. Returns the headers to send (incl. Authorization) and the canonical query string. */
export function sign({ method, host, path, query = {}, headers = {}, payloadHash, region, key, secret, now = new Date() }) {
  const amzDate = now.toISOString().replace(/[-:]|\.\d{3}/g, ''); // 20130524T000000Z
  const date = amzDate.slice(0, 8);
  const h = { host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = v;
  const names = Object.keys(h).sort();
  const canonicalHeaders = names.map((n) => `${n}:${String(h[n]).trim().replace(/\s+/g, ' ')}\n`).join('');
  const signedHeaders = names.join(';');
  const canonicalQuery = Object.keys(query).sort().map((k) => `${enc(k)}=${enc(String(query[k]))}`).join('&');
  const canonicalRequest = [method, encPath(path), canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${date}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonicalRequest)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${secret}`, date), region), 's3'), 'aws4_request');
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  return {
    signature, canonicalQuery,
    headers: { ...h, authorization: `AWS4-HMAC-SHA256 Credential=${key}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` },
  };
}

const xml = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
const tag = (body, name) => xml(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`).exec(body)?.[1] || '');

/** cfg: { endpoint, region, bucket, key, secret } */
export function s3Client(cfg) {
  const u = new URL(cfg.endpoint);
  const lib = u.protocol === 'http:' ? http : https;

  // One signed request. `upload` = { file, size } streams a file up; `download` = path streams the body down.
  const request = ({ method, key = '', query = {}, upload, download }) => new Promise((resolve, reject) => {
    const path = `/${cfg.bucket}${key ? `/${key}` : ''}`;
    const s = sign({ method, host: u.host, path, query, payloadHash: upload ? 'UNSIGNED-PAYLOAD' : EMPTY_SHA, region: cfg.region, key: cfg.key, secret: cfg.secret });
    const headers = { ...s.headers, ...(upload && { 'content-length': upload.size, 'content-type': 'application/gzip' }) };
    const req = lib.request({ protocol: u.protocol, hostname: u.hostname, port: u.port || undefined, method, path: `${encPath(path)}${s.canonicalQuery ? `?${s.canonicalQuery}` : ''}`, headers, family: 4 }, (res) => {
      const okay = res.statusCode >= 200 && res.statusCode < 300;
      if (okay && download) {
        pipeline(res, fs.createWriteStream(download, { mode: 0o600 })).then(() => resolve({ status: res.statusCode }), reject);
        return;
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { if (body.length < 5_000_000) body += c; });
      res.on('end', () => {
        if (okay) return resolve({ status: res.statusCode, body });
        const why = [tag(body, 'Code'), tag(body, 'Message')].filter(Boolean).join(' — ') || body.slice(0, 200) || 'no detail';
        reject(Object.assign(new Error(`Spaces ${method} ${key || cfg.bucket}: HTTP ${res.statusCode} ${why}`), { status: res.statusCode, code: tag(body, 'Code') }));
      });
      res.on('error', reject);
    });
    req.setTimeout(120_000, () => req.destroy(new Error(`Spaces ${method} ${key || cfg.bucket}: no response for 120s`)));
    req.on('error', reject);
    if (upload) pipeline(fs.createReadStream(upload.file), req).catch(reject);
    else req.end();
  });

  return {
    async put(key, file) {
      const { size } = await fsp.stat(file);
      await request({ method: 'PUT', key, upload: { file, size } });
      return { key, size };
    },
    get: (key, file) => request({ method: 'GET', key, download: file }),
    del: (key) => request({ method: 'DELETE', key }),
    /** Every object under `prefix`: [{ key, size, modified }] (follows continuation tokens). */
    async list(prefix = '', { max = 20000 } = {}) {
      const out = [];
      let token;
      do {
        const r = await request({ method: 'GET', query: { 'list-type': '2', prefix, ...(token && { 'continuation-token': token }) } });
        for (const m of r.body.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
          out.push({ key: tag(m[1], 'Key'), size: Number(tag(m[1], 'Size')) || 0, modified: tag(m[1], 'LastModified') });
        }
        token = tag(r.body, 'IsTruncated') === 'true' ? tag(r.body, 'NextContinuationToken') : '';
      } while (token && out.length < max);
      return out;
    },
  };
}

// --- validating what the portal sends ------------------------------------------
// Flat param names on purpose: the job view redacts by KEY NAME (…Key, …Secret),
// which a nested { s3: { secret } } would slip past.
const BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const REGION_RE = /^[a-z0-9-]{1,40}$/;
const PREFIX_RE = /^[A-Za-z0-9._/-]{0,200}$/;
export function readS3Params(p, errors) {
  let endpoint = String(p.s3Endpoint || '').trim().replace(/\/+$/, '');
  const region = String(p.s3Region || '').trim();
  const bucket = String(p.s3Bucket || '').trim();
  const key = String(p.s3Key || '').trim();
  const secret = String(p.s3Secret || '').trim();
  let prefix = String(p.prefix || '').trim().replace(/^\/+/, '').replace(/\/+$/, '');
  try {
    const u = new URL(endpoint);
    const local = ['127.0.0.1', 'localhost'].includes(u.hostname);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) errors.push('s3Endpoint must be https');
    if (u.pathname !== '/' || u.search) errors.push('s3Endpoint must be just the host, e.g. https://sgp1.digitaloceanspaces.com');
    endpoint = u.origin;
  } catch { errors.push('s3Endpoint must be a URL, e.g. https://sgp1.digitaloceanspaces.com'); }
  if (!REGION_RE.test(region)) errors.push('s3Region is invalid (e.g. sgp1)');
  if (!BUCKET_RE.test(bucket)) errors.push('s3Bucket is invalid');
  if (!key || /\s/.test(key)) errors.push('s3Key is required');
  if (!secret || /\s/.test(secret)) errors.push('s3Secret is required');
  if (!PREFIX_RE.test(prefix) || prefix.split('/').includes('..')) errors.push('prefix may only contain letters, digits, . _ - /');
  return { s3Endpoint: endpoint, s3Region: region, s3Bucket: bucket, s3Key: key, s3Secret: secret, prefix: prefix ? `${prefix}/` : '' };
}
export const clientFrom = (p) => s3Client({ endpoint: p.s3Endpoint, region: p.s3Region, bucket: p.s3Bucket, key: p.s3Key, secret: p.s3Secret });
