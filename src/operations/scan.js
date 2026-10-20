import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import config from '../config.js';
import { run, pathExists } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// ============================================================
//  scan — ClamAV malware scan of a site's files, with a downloadable report
// ============================================================
// Scans /var/www/<domain>/htdocs (code, uploads, plugins, themes) with
// `clamscan`, skipping only .git and the page cache. ClamAV is installed on
// first use and the signature database is refreshed when older than a day.
// Every scan writes a full report to REPORT_DIR/<job id>_<domain>.txt; the
// agent serves it on GET /api/scan/report/:jobId and the portal offers it as
// a download. The job FAILS when something is found, so it stands out.
// ============================================================
export const REPORT_DIR = process.env.SCAN_REPORT_DIR || '/var/backups/clamav';
const DB_DIR = process.env.CLAMAV_DB_DIR || '/var/lib/clamav';
const DB_MAX_AGE_MS = 24 * 3600 * 1000;
const EXCLUDE_DIRS = ['/\\.git/', '/app/cache/', '/wp-content/cache/'];
const JOB_ID_RE = /^[A-Za-z0-9-]{8,64}$/;

const stamp = (d = new Date()) => d.toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '_');
const secs = (ms) => `${Math.round(ms / 1000)}s`;

/** Parse clamscan's stdout. Pure. -> { infected: [{ file, signature }], summary: { ... } } */
export function parseClamscan(out) {
  const infected = [];
  const summary = {};
  for (const raw of String(out).split('\n')) {
    const line = raw.trimEnd();
    const hit = /^(.+?): (.+) FOUND$/.exec(line);
    if (hit) { infected.push({ file: hit[1], signature: hit[2] }); continue; }
    const kv = /^(Known viruses|Engine version|Scanned directories|Scanned files|Infected files|Data scanned|Data read|Time):\s*(.+)$/.exec(line);
    if (kv) summary[kv[1]] = kv[2].trim();
  }
  return { infected, summary };
}

/** The report text. Pure. */
export function formatReport({ domain, server, dir, startedAt, finishedAt, version, infected, summary, exitCode, errors, rawTail }) {
  const result = infected.length ? `INFECTED — ${infected.length} file(s)` : exitCode === 0 ? 'CLEAN' : `INCOMPLETE — clamscan exited ${exitCode}`;
  const lines = [
    'ClamAV scan report',
    '==================',
    `Site      : ${domain}`,
    `Server    : ${server}`,
    `Path      : ${dir}`,
    `Started   : ${startedAt.toISOString()}`,
    `Finished  : ${finishedAt.toISOString()}  (${secs(finishedAt - startedAt)})`,
    `ClamAV    : ${version || 'unknown'}`,
    `Result    : ${result}`,
    '',
    `Infected files (${infected.length})`,
    '-'.repeat(40),
    ...(infected.length ? infected.map((i) => `${i.file}\n    ${i.signature}`) : ['none']),
    '',
    'Summary',
    '-'.repeat(40),
    ...Object.entries(summary).map(([k, v]) => `${k.padEnd(20)}: ${v}`),
  ];
  if (errors.length) lines.push('', `Errors / warnings (${errors.length})`, '-'.repeat(40), ...errors);
  if (exitCode !== 0 && !infected.length && rawTail) lines.push('', 'Last output', '-'.repeat(40), rawTail);
  return `${lines.join('\n')}\n`;
}

async function ensureClamav(helpers, { info, ok, warn }) {
  if ((await run(helpers, 'which', ['clamscan'], { quiet: true })).code !== 0) {
    info('ClamAV is not installed — installing (apt-get install clamav)');
    const r = await run(helpers, 'apt-get', ['install', '-y', '-qq', 'clamav'], { env: { DEBIAN_FRONTEND: 'noninteractive' } });
    if (r.code !== 0) throw new Error('could not install ClamAV (apt-get install clamav failed — see above)');
    ok('ClamAV installed');
  }
  // Signatures: refresh when missing or older than a day. freshclam refuses to
  // run while its daemon holds the lock, so that case is fine too.
  let age = Infinity;
  try { age = Date.now() - (await fs.stat(path.join(DB_DIR, 'main.cvd'))).mtimeMs; } catch { try { age = Date.now() - (await fs.stat(path.join(DB_DIR, 'main.cld'))).mtimeMs; } catch { /* missing */ } }
  if (age > DB_MAX_AGE_MS) {
    info(age === Infinity ? 'no signature database yet — downloading (freshclam)' : `signature database is ${Math.round(age / 3600000)}h old — refreshing (freshclam)`);
    const r = await run(helpers, 'freshclam', ['--quiet'], { quiet: true });
    if (r.code === 0) ok('signatures up to date');
    else if (/locked|already running|another instance/i.test(r.stderr + r.stdout)) info('freshclam daemon is updating signatures itself');
    else warn(`freshclam exited ${r.code}: ${(r.stderr || r.stdout).trim().split('\n').pop() || 'no detail'} — scanning with the signatures present`);
  }
  const v = await run(helpers, 'clamscan', ['--version'], { quiet: true });
  return v.stdout.trim();
}

// params: { domain }
export async function runScan(job, helpers, p) {
  const { log, step, info, ok, warn, err } = logger(helpers);
  const domain = p.domain;
  const dir = `${config.wwwDir}/${domain}/htdocs`;
  if (!(await pathExists(dir))) throw new Error(`${domain} is not on this server (no ${dir})`);

  step('ClamAV + signatures');
  const version = await ensureClamav(helpers, { info, ok, warn });
  info(version || 'clamscan present');

  step(`Scan ${dir}`);
  info(`excluding ${EXCLUDE_DIRS.map((e) => e.replace(/\\/g, '')).join(', ')} — this takes a few minutes for a site with many files`);
  const startedAt = new Date();
  const args = ['--recursive', '--infected', '--no-summary=no', '--stdout', ...EXCLUDE_DIRS.map((e) => `--exclude-dir=${e}`), dir];
  const child = spawn('clamscan', args, { shell: false });
  helpers.onCancel?.(() => { try { child.kill('SIGTERM'); } catch {} });
  let out = ''; const errors = [];
  let found = 0;
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (c) => {
    out += c;
    for (const m of c.matchAll(/^(.+?): (.+) FOUND$/gm)) { found++; err(`FOUND ${m[2]}  ${m[1].replace(dir, '')}`); }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (c) => { for (const l of c.split('\n')) if (l.trim()) errors.push(l.trim()); });
  const beat = setInterval(() => info(`… still scanning (${secs(Date.now() - startedAt)}, ${found} found so far)`), 30_000);
  const exitCode = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (c) => resolve(c ?? -1)); }).finally(() => clearInterval(beat));
  const finishedAt = new Date();
  // clamscan: 0 clean, 1 something found, 2 an error occurred
  const { infected, summary } = parseClamscan(out);
  for (const l of errors.slice(0, 20)) warn(l);
  if (errors.length > 20) warn(`… and ${errors.length - 20} more warnings (all in the report)`);

  step('Report');
  await fs.mkdir(REPORT_DIR, { recursive: true, mode: 0o700 });
  const file = path.join(REPORT_DIR, `${job.id}_${domain}.txt`);
  const rawTail = out.split('\n').filter(Boolean).slice(-20).join('\n');
  await fs.writeFile(file, formatReport({ domain, server: config.serverName, dir, startedAt, finishedAt, version, infected, summary, exitCode, errors, rawTail }), { mode: 0o600 });
  ok(`report written: ${file}`);
  info(`scanned ${summary['Scanned files'] || '?'} files in ${secs(finishedAt - startedAt)} — ${infected.length} infected`);

  if (exitCode === 2 && !infected.length) throw new Error(`clamscan reported an error (exit 2): ${errors.slice(-1)[0] || 'see the report'}`);
  if (infected.length) throw new Error(`${infected.length} infected file(s) found on ${domain} — download the report for the list`);
  log(`Scan clean: ${domain} (${summary['Scanned files'] || '?'} files)`);
}

/** The report for a job id, or null. (Only files this op wrote: the id is validated and the dir is fixed.) */
export async function reportFor(jobId) {
  if (!JOB_ID_RE.test(jobId)) return null;
  let names = [];
  try { names = await fs.readdir(REPORT_DIR); } catch { return null; }
  const name = names.find((n) => n.startsWith(`${jobId}_`) && n.endsWith('.txt'));
  return name ? { name, path: path.join(REPORT_DIR, name), stream: () => fsSync.createReadStream(path.join(REPORT_DIR, name)) } : null;
}
