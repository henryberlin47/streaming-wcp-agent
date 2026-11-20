import fs from 'node:fs/promises';
import { run } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// ============================================================
//  nginxupgrade — apply nginx package updates and put the new binary in use
// ============================================================
// Upgrades every installed nginx package from the configured repositories
// (WordOps' own repository for nginx-custom / nginx-wo), then RESTARTS nginx:
// a reload keeps the old program running, and a security fix only counts once
// the fixed program is the one answering. Config files are kept.
//
// nginx is what serves every site, so:
//   - the configuration must pass `nginx -t` BEFORE anything is installed
//     (a package restarts nginx itself; a broken config would leave it down);
//   - afterwards nginx must be running, or the job fails and says why.
// ============================================================
const APT = ['-o', 'Dpkg::Options::=--force-confold', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Acquire::ForceIPv4=true', '-o', 'DPkg::Lock::Timeout=300', '-y', '-qq'];
const ENV = { DEBIAN_FRONTEND: 'noninteractive', NEEDRESTART_MODE: 'l' };
const PID_FILE = process.env.AGENT_NGINX_PID || '/run/nginx.pid';
const Q = { log() {}, err() {}, onCancel() {} };
const last = (r) => (r.stderr || r.stdout).trim().split('\n').pop() || `exit ${r.code}`;

/** Installed nginx packages: { 'nginx-custom': '1.30.4-1ppa~…', … } */
export async function nginxPackages(helpers) {
  const r = await run(helpers, 'dpkg-query', ['-W', '-f', '${binary:Package} ${Version} ${db:Status-Status}\n', 'nginx*', 'libnginx*'], { quiet: true });
  const out = {};
  for (const line of r.stdout.split('\n')) {
    const [pkg, ver, status] = line.trim().split(' ');
    if (pkg && ver && status === 'installed') out[pkg] = ver;
  }
  return out;
}

/** "1.30.4" from `nginx -v` (it prints to stderr), or '' */
export async function nginxVersion(helpers = Q) {
  const r = await run(helpers, 'nginx', ['-v'], { quiet: true }).catch(() => ({ stdout: '', stderr: '' }));
  return /nginx\/(\d+\.\d+\.\d+)/.exec(`${r.stderr}${r.stdout}`)?.[1] || '';
}

/** Is the nginx that is running an older program than the one on disk? (its file was replaced since it started) */
async function runningIsStale() {
  try {
    const pid = (await fs.readFile(PID_FILE, 'utf8')).trim();
    return (await fs.readlink(`/proc/${pid}/exe`)).endsWith(' (deleted)');
  } catch { return false; }
}

export async function runNginxUpgrade(job, helpers) {
  const { log, step, info, ok } = logger(helpers);
  const active = async () => (await run(helpers, 'systemctl', ['is-active', 'nginx'], { quiet: true })).stdout.trim() === 'active';

  step('Installed nginx packages');
  const before = await nginxPackages(helpers);
  const names = Object.keys(before).sort();
  if (!names.length) throw new Error('no nginx packages are installed on this server');
  const was = await nginxVersion(helpers);
  info(`nginx -v: ${was || '?'} · ${names.join(', ')}`);
  const t0 = await run(helpers, 'nginx', ['-t'], { quiet: true });
  if (t0.code !== 0) throw new Error(`the nginx configuration is broken right now, so nothing was installed (an upgrade restarts nginx, and it would not come back): ${last(t0)}`);
  ok('configuration is valid');

  step('apt-get update');
  const upd = await run(helpers, 'apt-get', [...APT, 'update'], { env: ENV });
  if (upd.code !== 0) throw new Error('apt-get update failed — see the output above (a repository is unreachable or broken). Nothing was installed.');
  ok('package lists refreshed');

  step('Upgrade nginx packages');
  const up = await run(helpers, 'apt-get', [...APT, 'install', '--only-upgrade', ...names], { env: ENV });
  const after = await nginxPackages(helpers);
  const changed = names.filter((n) => before[n] !== after[n]);
  for (const n of changed) ok(`${n}: ${before[n]} → ${after[n]}`);
  if (!changed.length && up.code === 0) ok('every nginx package is already at the newest version the repository offers');

  step('Put the new nginx in use');
  const t1 = await run(helpers, 'nginx', ['-t'], { quiet: true });
  if (t1.code !== 0) {
    throw new Error(`the configuration no longer passes with the new nginx, so it was NOT restarted — nginx is ${(await active()) ? 'still running the OLD program' : 'DOWN'}: ${last(t1)}`);
  }
  if (changed.length || await runningIsStale() || !(await active())) {
    const r = await run(helpers, 'systemctl', ['restart', 'nginx'], { quiet: true });
    if (r.code !== 0 || !(await active())) throw new Error(`nginx did not start after the upgrade — on the server: systemctl status nginx (${last(r)})`);
    ok('nginx restarted: the upgraded program is the one answering');
  } else {
    ok('nginx is running the program that is installed; no restart needed');
  }
  if (up.code !== 0) throw new Error('apt-get install --only-upgrade failed — see the output above. nginx is running.');

  const now = await nginxVersion(helpers);
  log(`nginx upgrade done: nginx ${now || '?'}${now !== was && was ? ` (was ${was})` : ''} · ${changed.length} package(s) changed`);
  return { before, after, changed, nginx: now };
}
