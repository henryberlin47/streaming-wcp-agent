import { run } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { tunePhpNow } from '../lib/site.js';

// ============================================================
//  phpupgrade — apply PHP package updates (security patch releases)
// ============================================================
// Upgrades every installed php* package from the configured repositories
// (Ondřej Surý's PPA, where WordOps installs PHP from), then restarts each
// php*-fpm and re-applies the tuning. This moves 8.3.x -> 8.3.y; it never
// changes a site's major version. Nothing interactive: config files that a
// package wants to replace are KEPT (--force-confold), so php.ini survives.
// ============================================================
const APT = ['-o', 'Dpkg::Options::=--force-confold', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Acquire::ForceIPv4=true', '-y', '-qq'];
const ENV = { DEBIAN_FRONTEND: 'noninteractive' };

/** Installed PHP package versions: { 'php8.3-fpm': '8.3.26-1+ubuntu24.04…', … } */
export async function phpPackages(helpers) {
  const r = await run(helpers, 'dpkg-query', ['-W', '-f', '${binary:Package} ${Version} ${db:Status-Status}\n', 'php*'], { quiet: true });
  const out = {};
  for (const line of r.stdout.split('\n')) {
    const [pkg, ver, status] = line.trim().split(' ');
    if (pkg && ver && status === 'installed') out[pkg] = ver;
  }
  return out;
}

/** "8.3.26" from `php -v`, or '' */
export async function phpVersion(helpers = { log() {}, err() {}, onCancel() {} }) {
  const r = await run(helpers, 'php', ['-v'], { quiet: true });
  return /^PHP (\d+\.\d+\.\d+)/.exec(r.stdout)?.[1] || '';
}

/** Which installed php*-fpm versions: ['8.3', '8.4'] */
const fpmVersions = (pkgs) => Object.keys(pkgs).map((p) => /^php(\d+\.\d+)-fpm$/.exec(p)?.[1]).filter(Boolean);

export async function runPhpUpgrade(job, helpers) {
  const { log, step, info, ok, warn } = logger(helpers);

  step('Installed PHP packages');
  const before = await phpPackages(helpers);
  const names = Object.keys(before).sort();
  if (!names.length) throw new Error('no PHP packages are installed on this server');
  for (const v of fpmVersions(before)) info(`php${v}-fpm ${before[`php${v}-fpm`]}`);
  info(`${names.length} php* package(s) installed · php -v: ${await phpVersion(helpers) || '?'}`);

  step('apt-get update');
  const upd = await run(helpers, 'apt-get', [...APT, 'update'], { env: ENV });
  if (upd.code !== 0) throw new Error('apt-get update failed — see the output above (a repository is unreachable or broken)');
  ok('package lists refreshed');

  step('Upgrade PHP packages');
  // --only-upgrade: touch nothing that is not already installed; apt also pulls
  // any new dependency a patch release needs.
  const up = await run(helpers, 'apt-get', [...APT, 'install', '--only-upgrade', ...names], { env: ENV });
  if (up.code !== 0) throw new Error('apt-get install --only-upgrade failed — see the output above');
  const after = await phpPackages(helpers);
  const changed = names.filter((n) => before[n] !== after[n]);
  if (!changed.length) {
    ok('every PHP package is already at the newest version the repositories offer');
  } else {
    for (const n of changed) ok(`${n}: ${before[n]} → ${after[n]}`);
    info(`${changed.length} package(s) upgraded`);
  }

  step('Restart PHP-FPM + re-apply tuning');
  // A patch release restarts its own fpm via the postinst, but not always every
  // version; be explicit. The tuning script restarts only what it changes.
  for (const v of fpmVersions(after)) {
    const r = await run(helpers, 'systemctl', ['restart', `php${v}-fpm`], { quiet: true });
    if (r.code === 0) ok(`php${v}-fpm restarted`); else warn(`php${v}-fpm did not restart: ${r.stderr.trim().split('\n').pop() || `exit ${r.code}`}`);
  }
  try { await tunePhpNow(helpers, { info, ok }); } catch (e) { warn(`tuning check: ${e.message}`); }

  const now = await phpVersion(helpers);
  log(`PHP upgrade done: php -v ${now || '?'} · ${changed.length} package(s) changed`);
  return { before, after, changed, php: now };
}
