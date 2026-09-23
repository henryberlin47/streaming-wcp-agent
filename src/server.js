import express from 'express';
import config, { validateConfig } from './config.js';
import { requireAuth } from './auth.js';
import { getOperation, operations } from './operations/index.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { enqueue, getJob, listJobs, publicView, subscribe, cancelJob } from './jobs.js';
import { woSiteList } from './lib/sys.js';
import { siteRoles } from './lib/site.js';
import { enforceAdminPanelCert } from './lib/panelcert.js';
import { cloneMap, readMapJson } from './lib/map.js';

// Version string the portal displays: package version + git short sha when
// this is a checkout (bootstrap installs by `git clone`), so a self-update
// visibly changes it even when package.json's version doesn't move.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PKG = createRequire(import.meta.url)('../package.json');
let GIT_SHA = '';
try {
  GIT_SHA = execFileSync('git', ['-C', ROOT, 'rev-parse', '--short', 'HEAD'], { stdio: ['ignore', 'pipe', 'ignore'] })
    .toString().trim();
} catch { /* not a git checkout */ }
export const VERSION = GIT_SHA ? `${PKG.version}+${GIT_SHA}` : PKG.version;

// --- startup validation -----------------------------------------------------
const problems = validateConfig();
if (problems.length) {
  console.error('Refusing to start due to configuration problems:');
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}

// Pin the :22222 admin panel to its self-signed cert and lock it immutable, so
// it can't be repointed at a deletable site cert. Idempotent; best-effort.
enforceAdminPanelCert().catch((e) => console.error('[agent] panel-cert enforce failed:', e));

const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', true);
app.use(express.json({ limit: '64kb' }));

// --- health (unauthenticated, minimal) --------------------------------------
// Useful for the panel to see the server is up before auth. Reveals nothing.
// The server's PUBLIC IPv4 (what DNS points at), as seen from outside — the
// portal only knows the tailnet address it talks to. Looked up once at start,
// refreshed every 6h; never blocks a request (healthz answers with what it has).
let PUBLIC_IP = null;
async function refreshPublicIp() {
  for (const url of ['https://api.ipify.org', 'https://ipv4.icanhazip.com']) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
      const ip = (await r.text()).trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) { PUBLIC_IP = ip; return; }
    } catch { /* try the next one */ }
  }
}
refreshPublicIp();
setInterval(refreshPublicIp, 6 * 3600 * 1000).unref();

app.get('/healthz', (req, res) => {
  res.json({ ok: true, server: config.serverName, version: VERSION, public_ip: PUBLIC_IP, time: Date.now() });
});

// Everything below requires auth + passes the IP allowlist.
app.use(requireAuth);

// --- server info ------------------------------------------------------------
app.get('/api/info', (req, res) => {
  res.json({
    server: config.serverName,
    version: VERSION,
    operations: Object.keys(operations), // derived, so new ops can't be forgotten here
    maxConcurrentJobs: config.maxConcurrentJobs,
  });
});

// --- list websites on this server ------------------------------------------
// GET /api/sites  ->  { server, sites: [domain, ...] }
// Read-only; runs `wo site list` directly (not a job).
app.get('/api/sites', async (req, res) => {
  // sys.run expects a helpers object; for a one-shot read we discard output.
  const helpers = { log: () => {}, err: () => {}, onCancel: () => {} };
  try {
    const sites = await woSiteList(helpers);
    const roles = await siteRoles(sites); // { domain: 'pc' | 'mob' } for main/mobile pairs
    res.json({ server: config.serverName, count: sites.length, sites, roles });
  } catch (e) {
    res.status(500).json({ error: 'wo_site_list_failed', message: e?.message || 'failed' });
  }
});

// --- domain map (for the panel's migrate pickers) ---------------------------
// GET /api/map  ->  { domains: [...], servers: [{name, host, port}] }
// Names only: the map holds DB passwords and they must never leave this box.
app.get('/api/map', async (req, res) => {
  const helpers = { log: () => {}, err: () => {}, onCancel: () => {} };
  let m;
  try {
    m = await cloneMap(helpers);
    const map = await readMapJson(m.mapPath, 'domain-map.json');
    const servers = await readMapJson(m.serversPath, 'servers.json');
    res.json({
      domains: Object.keys(map).sort(),
      servers: Object.entries(servers)
        .map(([name, v]) => ({ name, host: (v && v.host) || '', port: (v && v.port) || 3306 }))
        .sort((a, b) => a.name.localeCompare(b.name)),
    });
  } catch (e) {
    res.status(500).json({ error: 'map_unavailable', message: e?.message || 'failed' });
  } finally {
    if (m) await m.dispose();
  }
});

// --- start an operation -----------------------------------------------------
// POST /api/op/:type   body = operation params
// Returns { jobId } immediately; watch logs via SSE or poll the job.
app.post('/api/op/:type', (req, res) => {
  const type = req.params.type;
  const op = getOperation(type);
  if (!op) return res.status(404).json({ error: 'unknown_operation', type });

  const { ok, errors, clean } = op.validate(req.body || {});
  if (!ok) return res.status(400).json({ error: 'validation_failed', errors });

  const job = enqueue(type, clean, (j, helpers) => op.run(j, helpers, clean));
  res.status(202).json({ jobId: job.id, state: job.state, view: publicView(job) });
});

// --- list jobs --------------------------------------------------------------
app.get('/api/jobs', (req, res) => {
  res.json({ jobs: listJobs() });
});

// --- job status -------------------------------------------------------------
app.get('/api/jobs/:id', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'not_found' });
  res.json(publicView(job));
});

// --- job logs (full buffer, JSON) -------------------------------------------
app.get('/api/jobs/:id/logs', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'not_found' });
  res.json({ id: job.id, state: job.state, log: job.log });
});

// --- job logs (live stream, SSE) --------------------------------------------
// GET /api/jobs/:id/stream
// Emits event: line   data: {t,stream,line}
//       event: state  data: {state,reason}
// Replays existing log lines first, then streams new ones until terminal.
app.get('/api/jobs/:id/stream', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'not_found' });

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no', // disable nginx buffering if proxied
  });
  res.flushHeaders?.();

  const send = (event, data) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  send('hello', { id: job.id, state: job.state });

  const unsub = subscribe(
    job,
    (entry) => send('line', entry),
    (st) => {
      send('state', st);
      if (['succeeded', 'failed', 'timeout', 'cancelled'].includes(st.state)) {
        // Close the stream once the job is done.
        setTimeout(() => res.end(), 50);
      }
    }
  );

  // Heartbeat so proxies/load balancers don't drop the idle connection.
  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  hb.unref?.();

  req.on('close', () => {
    clearInterval(hb);
    unsub();
  });
});

// --- cancel a job -----------------------------------------------------------
app.post('/api/jobs/:id/cancel', (req, res) => {
  const result = cancelJob(req.params.id);
  if (!result.ok) return res.status(409).json({ error: 'cannot_cancel', reason: result.reason });
  res.json({ ok: true });
});

// --- 404 + error handlers ---------------------------------------------------
app.use((req, res) => res.status(404).json({ error: 'not_found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('unhandled error:', err);
  res.status(500).json({ error: 'internal_error' });
});

const server = app.listen(config.port, config.host, () => {
  console.log(
    `[agent] ${config.serverName} listening on http://${config.host}:${config.port} ` +
      `(allowlist: ${config.allowedIps.length ? config.allowedIps.join(',') : 'ANY'}, ` +
      `concurrency: ${config.maxConcurrentJobs})`
  );
});

// Graceful shutdown
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log(`\n[agent] ${sig} received, shutting down...`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}