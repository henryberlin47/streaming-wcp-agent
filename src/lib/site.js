import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import config from '../config.js';
import { run, runOrThrow, pathExists, systemctl, GIT_SSH_ARGS, explainGitError } from './sys.js';
import { readEnv } from './envfile.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CACHE_CONF_TEMPLATE = path.join(__dirname, '..', 'templates', 'custom-cache.conf');

// ============================================================
//  site.js — WordOps site scaffolding (nginx, cron, wo, SSL)
// ============================================================

// Write the main nginx vhost + the shared custom-cache.conf include, and enable
// the site (symlink into sites-enabled).
export async function writeNginxVhost({ domain, siteDir, webroot }) {
  const available = `/etc/nginx/sites-available/${domain}`;
  const enabled = `/etc/nginx/sites-enabled/${domain}`;

  const vhost = `server {
    server_name ${domain} www.${domain};

    access_log /var/log/nginx/${domain}.access.log;
    error_log  /var/log/nginx/${domain}.error.log;

    root ${webroot};
    index index.php index.html index.htm;

    include common/php83.conf;
    include common/locations-wo.conf;
    include ${siteDir}/conf/nginx/*.conf;
}
`;
  await fs.writeFile(available, vhost);
  // enable (idempotent symlink)
  await fs.rm(enabled, { force: true });
  await fs.symlink(available, enabled);

  // custom-cache.conf include (verbatim template)
  const confDir = `${siteDir}/conf/nginx`;
  await fs.mkdir(confDir, { recursive: true });
  const cacheBody = await fs.readFile(CACHE_CONF_TEMPLATE, 'utf8');
  await fs.writeFile(`${confDir}/custom-cache.conf`, cacheBody);
}

// Write the MAIN site's 15-job cron file (football + basketball + feeds), each
// flock-guarded and domain-scoped. Mirrors deploy-streaming-site.sh.
export async function writeMainCron({ domain, cronFile, src }) {
  const L = `/tmp/${domain}`;
  const php = '/usr/bin/php';
  const wp = '/usr/local/bin/wp';
  const j = (sched, lock, task, timeout) => {
    const to = timeout ? `timeout ${timeout} ` : '';
    return `${sched} www-data /usr/bin/flock -n ${L}_cron-${lock}.lock bash -c 'cd ${src} && ${to}${php} ${wp} eval-file cron-tasks/${task}.php --path=web/wp' >/dev/null 2>&1`;
  };
  const lines = [
    'SHELL=/bin/bash',
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    '',
    '# ---- Football ----',
    j('*/5  * * * *', 'wp-cron-runner', 'cron-wp-cron-runner'),
    j('*/3  * * * *', 'create-match-list', 'cron-create-match-list'),
    j('*/15 * * * *', 'match-info', 'cron-match-info'),
    j('0    0 * * *', 'create-future-matches', 'cron-create-future-matches'),
    j('0    0 * * *', 'update-previous-day-00', 'cron-update-previous-day'),
    j('0    4 * * *', 'update-previous-day-04', 'cron-update-previous-day'),
    j('0   10 * * *', 'update-previous-day-10', 'cron-update-previous-day'),
    '',
    '# ---- Basketball ----',
    j('*/3  * * * *', 'bb-create-posts', 'cron-bb-create-posts', 180),
    j('0    2 * * *', 'bb-clean-old-posts', 'cron-bb-clean-old-posts', 180),
    j('0    1 * * *', 'bb-create-future-matches', 'cron-bb-create-future-matches', 180),
    j('0    0 * * *', 'bb-update-previous-day-00', 'cron-bb-update-previous-day', 180),
    j('0    4 * * *', 'bb-update-previous-day-04', 'cron-bb-update-previous-day', 180),
    '',
    '# ---- Static-feed writers ----',
    j('*    * * * *', 'livescores-feed', 'cron-livescores-feed', 65),
    j('*/5  * * * *', 'livescores-feed-heartbeat', 'cron-livescores-feed-heartbeat'),
    j('*/3  * * * *', 'match-modals', 'cron-match-modals', 120),
    '',
  ];
  await fs.writeFile(cronFile, lines.join('\n'));
}

// Write the ALIAS/clone 4-job cron file (feed writers only).
export async function writeAliasCron({ domain, cronFile, src }) {
  const L = `/tmp/${domain}`;
  const php = '/usr/bin/php';
  const wp = '/usr/local/bin/wp';
  const j = (sched, lock, task, timeout) => {
    const to = timeout ? `timeout ${timeout} ` : '';
    return `${sched} www-data /usr/bin/flock -n ${L}_cron-${lock}.lock bash -c 'cd ${src} && ${to}${php} ${wp} eval-file cron-tasks/${task}.php --path=web/wp' >/dev/null 2>&1`;
  };
  const lines = [
    'SHELL=/bin/bash',
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    '',
    '# ---- Clone / static-feed writers only ----',
    j('*    * * * *', 'livescores-feed', 'cron-livescores-feed', 65),
    j('*/5  * * * *', 'livescores-feed-heartbeat', 'cron-livescores-feed-heartbeat'),
    j('*/3  * * * *', 'match-modals', 'cron-match-modals', 120),
    j('*/5  * * * *', 'wp-cron-runner', 'cron-wp-cron-runner'),
    '',
  ];
  await fs.writeFile(cronFile, lines.join('\n'));
}

// Apply cron file ownership/perms (root:root 644).
export async function finalizeCronPerms(helpers, cronFile) {
  await run(helpers, 'chown', ['root:root', cronFile], { quiet: true });
  await run(helpers, 'chmod', ['644', cronFile], { quiet: true });
}

// Main/mobile pairing for a list of live sites, from what the alias deploy
// writes to disk:
//   alias .env -> SITE_ROLE=clone                 => 'mob'
//   main  .env -> SITE_MOBILE_HOST=<alias domain> => 'pc', but only while that
//                 alias is still a live site (deleting the alias leaves the key
//                 behind in the main .env — don't show a stale PC tag for it).
const TUNE_PHP = path.join(__dirname, '..', '..', 'scripts', 'tune-php.sh');

// Make sure the PHP that serves the sites is tuned, THEN restart it. Every
// operation that restarts PHP goes through here, so a server heals itself on
// its next deploy/alias/update — including ones that were never bootstrapped,
// and ones where PHP 8.3 was installed after any one-off tuning ran. (An
// untuned 8.3 — memory 128M, default regex limits — made WP Rocket die on a
// large homepage and serve HTTP 200 with an empty body.)
//   - idempotent: "already tuned" costs a few greps and logs nothing
//   - no extra restart: it rides the restart the operation was doing anyway
//   - never throws: a tuning problem is reported, and the restart still happens
export async function tuneAndRestartPhp(helpers, { info, warn }, service = 'php8.3-fpm') {
  const r = await run(helpers, 'bash', [TUNE_PHP, '--no-restart'], { quiet: true });
  const lines = `${r.stdout}\n${r.stderr}`.split('\n').map((s) => s.trim()).filter(Boolean);
  if (r.code === 0) {
    for (const l of lines.filter((l) => /tuned \(/.test(l))) info(l.replace(' — restart pending', ''));
  } else {
    warn(`PHP tuning check: ${lines.pop() || `exit ${r.code}`}`);
  }
  return systemctl(helpers, 'restart', service);
}

// Returns per-site metadata { [domain]: { root?, role?, pair? } }:
//   root = SITE_ROOT_DOMAIN (the domain-map key its DB creds came from)
//   role/pair = 'pc'|'mob' + the other half, so the portal can group them.
// Domains with none of these are omitted.
export async function siteRoles(sites) {
  const live = new Set(sites);
  const meta = {};
  const mobs = new Set();
  await Promise.all(sites.map(async (d) => {
    const env = `${config.wwwDir}/${d}/htdocs/src/.env`;
    const root = await readEnv(env, 'SITE_ROOT_DOMAIN');
    if (root) meta[d] = { root };
    if ((await readEnv(env, 'SITE_ROLE')) === 'clone') { mobs.add(d); return; }
    const mob = await readEnv(env, 'SITE_MOBILE_HOST');
    if (mob && live.has(mob)) meta[d] = { ...meta[d], role: 'pc', pair: mob };
  }));
  // Invert pc→alias so each alias knows its main (undefined if the main
  // doesn't point back at it — it then shows as a standalone MOB).
  const mainOf = new Map(
    Object.entries(meta).filter(([, v]) => v.role === 'pc').map(([main, v]) => [v.pair, main])
  );
  for (const d of mobs) meta[d] = { ...meta[d], role: 'mob', pair: mainOf.get(d) };
  return meta;
}

// Clone the app repo into a site's htdocs, without ever destroying a live site.
//   - A DEPLOYED site (one with src/.env) is refused unless `force`; with force
//     the clone goes to a temp dir, is layout-checked, then swapped in — the old
//     htdocs is kept as `.bak-<ts>`, so a bad branch or a network blip can never
//     take .env/uploads with it.
//   - A fresh `wo site create` leaves only a placeholder index.html; that (or an
//     empty dir) is the one case cloned in place.
// Returns { backup } — the .bak path, or null when nothing was replaced.
export async function cloneRepo(helpers, { htdocs, branch, repo, force = false }) {
  const layoutOk = async (dir) => (await pathExists(`${dir}/src`)) && (await pathExists(`${dir}/src/web`));
  const live = await pathExists(`${htdocs}/src/.env`);
  // Clone with a non-prompting ssh, and on failure say WHY (key not authorised,
  // unknown host, no access, network) rather than a bare exit code.
  const gitClone = async (cwd) => {
    const r = await run(helpers, 'git', [...GIT_SSH_ARGS, 'clone', '-b', branch, repo, '.'], { cwd, quiet: true });
    if (r.code !== 0) throw new Error(explainGitError(r.stderr, repo));
  };

  if (!live) {
    await fs.mkdir(htdocs, { recursive: true });
    for (const e of await fs.readdir(htdocs)) await fs.rm(`${htdocs}/${e}`, { recursive: true, force: true });
    await gitClone(htdocs);
    if (!(await layoutOk(htdocs))) throw new Error(`repo layout unexpected: missing ${htdocs}/src or ${htdocs}/src/web`);
    return { backup: null };
  }

  if (!force) {
    throw new Error(
      `${htdocs} already holds a deployed site (src/.env exists). Re-run with force:true to replace it — ` +
      'the current files are kept as a .bak.'
    );
  }
  const ts = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const fresh = `${htdocs}.new-${ts}`;
  const backup = `${htdocs}.bak-${ts}`;
  await fs.rm(fresh, { recursive: true, force: true });
  await fs.mkdir(fresh, { recursive: true });
  try {
    await gitClone(fresh);
  } catch (e) {
    await fs.rm(fresh, { recursive: true, force: true }); // don't leave an empty .new-* dir behind
    throw e;
  }
  if (!(await layoutOk(fresh))) {
    await fs.rm(fresh, { recursive: true, force: true });
    throw new Error('repo layout unexpected in the new clone (missing src or src/web) — live site left untouched');
  }
  // Two renames on the same filesystem: instant, and the live site is only
  // ever in a consistent state (old or new), never half-empty.
  await fs.rename(htdocs, backup);
  await fs.rename(fresh, htdocs);
  return { backup };
}

// wo site create <domain> --html --php83 (only if it doesn't already exist).
export async function woSiteCreate(helpers, domain) {
  await runOrThrow(helpers, 'wo', ['site', 'create', domain, '--html', '--php83']);
}

// wo site update <domain> --le --force ; returns true on success (SSL issued).
export async function woSiteSsl(helpers, domain) {
  const r = await run(helpers, 'wo', ['site', 'update', domain, '--le', '--force']);
  return r.code === 0;
}

// Drop the throwaway local DB/user WordOps auto-creates on `site create`.
export async function dropLocalWoDb(helpers, domain) {
  // WordOps names the DB by turning dots into underscores. In LIKE, `_` is a
  // one-character wildcard, so an unescaped `a_b_com%` also matches the
  // unrelated site `axb.com` and would drop ITS database and user. Escape it.
  const safe = domain.replace(/\./g, '_').replace(/[_%\\]/g, '\\$&');
  // Databases
  const dbs = await run(helpers, 'mariadb', ['-N', '-e', `SHOW DATABASES LIKE '${safe}%';`], { quiet: true });
  for (const db of dbs.stdout.split('\n').map((s) => s.trim()).filter(Boolean)) {
    await run(helpers, 'mariadb', ['-e', `DROP DATABASE \`${db}\`;`], { quiet: true });
  }
  // Users
  const users = await run(
    helpers, 'mariadb',
    ['-N', '-e', `SELECT User, Host FROM mysql.user WHERE User LIKE '${safe}%';`],
    { quiet: true }
  );
  for (const row of users.stdout.split('\n').map((s) => s.trim()).filter(Boolean)) {
    const [user, host] = row.split(/\s+/);
    if (user && host) {
      await run(helpers, 'mariadb', ['-e', `DROP USER IF EXISTS '${user}'@'${host}';`], { quiet: true });
    }
  }
  await run(helpers, 'mariadb', ['-e', 'FLUSH PRIVILEGES;'], { quiet: true });
}

// Recursively apply www-data ownership + 755/644 perms to a site dir.
export async function applySitePerms(helpers, siteDir) {
  await run(helpers, 'chown', ['-R', 'www-data:www-data', siteDir]);
  await run(helpers, 'find', [siteDir, '-type', 'd', '-exec', 'chmod', '755', '{}', '+'], { quiet: true });
  await run(helpers, 'find', [siteDir, '-type', 'f', '-exec', 'chmod', '644', '{}', '+'], { quiet: true });
}