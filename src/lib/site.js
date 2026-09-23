import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import config from '../config.js';
import { run, runOrThrow, pathExists, systemctl, GIT_SSH_ARGS, explainGitError } from './sys.js';
import { readEnv } from './envfile.js';
import { siteSsl, NGINX_DIR } from './cert.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CACHE_CONF_TEMPLATE = path.join(__dirname, '..', 'templates', 'custom-cache.conf');

// ============================================================
//  site.js — WordOps site scaffolding (nginx, cron, wo, SSL)
// ============================================================

// ---- WWW preference ---------------------------------------------------------
//   nonwww  www.<domain> is served and 301s to <domain>          (the default)
//   www     <domain> is served and 301s to www.<domain>
//   off     www.<domain> is not served at all (no vhost name, no www in the LE cert
//           — for domains whose www has no DNS record, which otherwise breaks LE)
export const WWW_MODES = ['nonwww', 'www', 'off'];
export const canonicalHost = (domain, www) => (www === 'www' ? `www.${domain}` : domain);

// A site's current mode, read from its vhost (the truth nginx serves), or null
// if it has none. A vhost from before this existed (one block, both names — the
// redirect happened inside WordPress) reads as 'nonwww', which is what it did.
export async function siteWww(domain) {
  let conf;
  try { conf = await fs.readFile(`${NGINX_DIR}/sites-available/${domain}`, 'utf8'); } catch { return null; }
  const names = [...conf.matchAll(/^\s*server_name\s+([^;]+);/gm)].flatMap((m) => m[1].trim().split(/\s+/));
  if (!names.includes(`www.${domain}`)) return 'off';
  return names[0] === `www.${domain}` ? 'www' : 'nonwww';
}

// Write the main nginx vhost + the shared custom-cache.conf include, and enable
// the site (symlink into sites-enabled).
export async function writeNginxVhost({ domain, siteDir, webroot, www = 'nonwww' }) {
  const available = `${NGINX_DIR}/sites-available/${domain}`;
  const enabled = `${NGINX_DIR}/sites-enabled/${domain}`;
  const main = canonicalHost(domain, www);
  const other = www === 'off' ? null : (www === 'www' ? domain : `www.${domain}`);

  // The non-canonical host gets its own block so the redirect happens in nginx
  // (no PHP, works for cached pages). `ssl*.conf` is a glob on purpose: it picks
  // up the site's listen-443 + certificate once SSL exists and matches nothing
  // before that — then the block is plain :80 and $scheme keeps it on http.
  // ACME challenges are answered here too, so Let's Encrypt can validate it.
  const redirect = other ? `
server {
    server_name ${other};
    include ${siteDir}/conf/nginx/ssl*.conf;
    location ^~ /.well-known/acme-challenge/ {
        alias /var/www/html/.well-known/acme-challenge/;
        allow all;
        auth_basic off;
    }
    location / {
        return 301 $scheme://${main}$request_uri;
    }
}
` : '';

  const vhost = `server {
    server_name ${main};

    access_log /var/log/nginx/${domain}.access.log;
    error_log  /var/log/nginx/${domain}.error.log;

    root ${webroot};
    index index.php index.html index.htm;

    include common/php83.conf;
    include common/locations-wo.conf;
    include ${siteDir}/conf/nginx/*.conf;
}
${redirect}`;
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

// ---- Cron on/off (backup sites) ---------------------------------------------
// A site's cron file is /etc/cron.d/<domain with _>. cron ignores any file in
// cron.d whose name has a dot, so "<name>.disabled" is the same file, inert.
// A BACKUP site (the same domain deployed again on another server, same shared
// DB) is written disabled and only switched on when the primary is down —
// two servers running the writers at once would double-post.
const CRON_DIR = process.env.AGENT_CRON_DIR || '/etc/cron.d'; // env: tests only
export const cronPath = (domain) => `${CRON_DIR}/${domain.replace(/\./g, '_')}`;
export async function siteCron(domain) {
  if (await pathExists(cronPath(domain))) return 'on';
  if (await pathExists(`${cronPath(domain)}.disabled`)) return 'off';
  return null; // no cron file at all
}
// Returns the state after the call; throws if the site has no cron file.
export async function setSiteCron(helpers, domain, active) {
  const on = cronPath(domain), off = `${on}.disabled`;
  const cur = await siteCron(domain);
  if (!cur) throw new Error(`${domain} has no cron file on this server (not deployed here?)`);
  const want = active ? 'on' : 'off';
  if (cur !== want) {
    await fs.rename(active ? off : on, active ? on : off);
    await systemctl(helpers, 'restart', 'cron');
  }
  return want;
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
// The portal's "Tune PHP" button: fix a server NOW instead of waiting for its
// next deploy. Here the script does its own restart — only of the PHP versions
// it actually changed, so an already-tuned server is not touched at all.
export async function tunePhpNow(helpers, { info, ok }) {
  const r = await run(helpers, 'bash', [TUNE_PHP], { quiet: true });
  const lines = `${r.stdout}\n${r.stderr}`.split('\n').map((s) => s.trim()).filter(Boolean);
  for (const l of lines) (r.code === 0 ? ok : info)(l);
  if (r.code !== 0) throw new Error(lines.pop() || `tune-php.sh exited ${r.code}`);
}

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

// The code a site runs: { repo: 'owner/name', branch } — read from htdocs/.git
// directly (two small files) rather than spawning git twice per site per listing.
// A detached HEAD reports the short commit as the branch; no checkout = {}.
export async function siteGit(domain) {
  const git = `${config.wwwDir}/${domain}/htdocs/.git`;
  const read = (f) => fs.readFile(`${git}/${f}`, 'utf8').catch(() => '');
  const head = (await read('HEAD')).trim();
  if (!head) return {};
  const branch = head.startsWith('ref: refs/heads/') ? head.slice(16) : head.slice(0, 7);
  const url = /\[remote "origin"\][^\[]*?^\s*url\s*=\s*(\S+)/m.exec(await read('config'))?.[1] || '';
  const repo = url.replace(/\.git$/, '').split(/[:/]/).slice(-2).join('/'); // git@host:owner/name(.git) or https://host/owner/name
  return { branch, ...(repo && { repo }) };
}

// Returns per-site metadata { [domain]: { root?, role?, pair?, ssl?, ssl_expires?, www?, repo?, branch?, cron?, backup? } }:
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
    const www = await siteWww(d); // 'nonwww' | 'www' | 'off' (absent = no vhost)
    const cron = await siteCron(d); // 'on' | 'off' | null
    const backup = (await readEnv(env, 'SITE_BACKUP')) === '1';
    meta[d] = { ...(root && { root }), ...(await siteSsl(d)), ...(www && { www }), ...(await siteGit(d)), ...(cron && { cron }), ...(backup && { backup }) };
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

const CLONE_BEAT_MS = parseInt(process.env.AGENT_CLONE_BEAT_MS || '15000', 10); // env: tests only

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
  // A clone is silent without a TTY, so a slow one and a hung one look the same
  // in the job log. Say every 15s how long it has run and how much has arrived:
  // growing = slow network / big repo, flat = stalled.
  const gitClone = async (cwd) => {
    const started = Date.now();
    const silent = { log() {}, err() {}, onCancel() {} };
    const beat = setInterval(async () => {
      const du = await run(silent, 'du', ['-sm', cwd], { quiet: true }).catch(() => null);
      helpers.log(`    … still cloning — ${Math.round((Date.now() - started) / 1000)}s, ${parseInt(du?.stdout, 10) || 0} MB received`);
    }, CLONE_BEAT_MS);
    let r;
    try {
      // Shallow + single-branch: a deploy needs the branch's files, not the
      // repo's whole history on every branch — that was most of the transfer,
      // and the long silent download is where deploys sat "stuck". The update op
      // fetches the one branch it needs, so switching branches still works.
      r = await run(helpers, 'git', [...GIT_SSH_ARGS, 'clone', '--depth', '1', '-b', branch, repo, '.'], { cwd, quiet: true });
    } finally {
      clearInterval(beat);
    }
    if (r.code !== 0) throw new Error(explainGitError(r.stderr, repo));
    helpers.log(`    cloned in ${Math.round((Date.now() - started) / 1000)}s`);
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
// WordOps adds www.<domain> to the certificate of every non-subdomain site, and
// the whole issuance fails when www has no DNS. With www off (read from the
// vhost unless given) it is asked for the bare domain only.
export async function woSiteSsl(helpers, domain, www) {
  const mode = www || (await siteWww(domain));
  const r = await run(helpers, 'wo', ['site', 'update', domain, mode === 'off' ? '--letsencrypt=subdomain' : '--le', '--force']);
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