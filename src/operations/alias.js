import config from '../config.js';
import fs from 'node:fs/promises';
import { runOrThrow, pathExists, woSiteExists, clearWpCaches, systemctl, nginxTest, nginxReload } from '../lib/sys.js';
import { injectEnv, readEnv, setEnv, setWpSiteUrl } from '../lib/envfile.js';
import {
  writeNginxVhost, writeAliasCron, finalizeCronPerms, woSiteCreate, woSiteSsl,
  dropLocalWoDb, applySitePerms, cloneRepo, tuneAndRestartPhp, siteWww, canonicalHost, cronPath,
} from '../lib/site.js';
import { brandAdd, cdnAdd } from '../lib/api.js';
import { APP_REPO_DEFAULT, BRANCH_DEFAULT } from '../lib/siteConfig.js';
import { logger } from '../lib/log.js';

// ============================================================
//  alias — native port of deploy-streaming-alias-site.sh
// ============================================================
// Clone/alias that shares a main site's DB. Injects SITE_MOBILE_HOST=<alias>
// into the MAIN .env, clones that .env, reads CDN_PREFIX from it, swaps the
// alias's own WP_HOME/CDN/SITE_ROLE, writes nginx + 4-job cron, SSL, clears
// BOTH caches, registers brand + CDN.
// ============================================================

// params: { aliasDomain, mainDomain, branch?, repo? }
export async function runAlias(job, helpers, p, opts = {}) {
  const { log, step, info, ok, warn } = logger(helpers, opts);
  const domain = p.aliasDomain;
  const mainDomain = p.mainDomain;
  const branch = p.branch || BRANCH_DEFAULT;
  const repo = p.repo || APP_REPO_DEFAULT;

  const SITE_DIR = `${config.wwwDir}/${domain}`;
  const HTDOCS = `${SITE_DIR}/htdocs`;
  const SRC = `${HTDOCS}/src`;
  const WEBROOT = `${SRC}/web`;
  const ENV_FILE = `${SRC}/.env`;
  const isBackup = !!p.backup; // see deploy.js — same site, cron inert until needed
  const CRON_FILE = isBackup ? `${cronPath(domain)}.disabled` : cronPath(domain);
  const CDN_DOMAIN = `cdn.${domain}`;

  const MAIN_SITE_DIR = `${config.wwwDir}/${mainDomain}`;
  const MAIN_SRC = `${MAIN_SITE_DIR}/htdocs/src`;
  const MAIN_ENV = `${MAIN_SRC}/.env`;

  // Validate main site exists.
  if (domain === mainDomain) throw new Error('alias and main domain must differ');
  if (!(await pathExists(MAIN_ENV))) {
    throw new Error(`main .env not found: ${MAIN_ENV} (deploy the main site first)`);
  }

  // 1) WordOps site (skip if exists).
  step('WordOps site');
  if (await woSiteExists(helpers, domain)) {
    warn(`Site already exists in WordOps: ${domain} — redeploying files/config`);
  } else {
    await woSiteCreate(helpers, domain);
    ok('WordOps site created');
  }

  // 2) Drop the throwaway local DB WordOps made.
  step('Drop throwaway local database');
  await dropLocalWoDb(helpers, domain);
  ok('Local database cleanup complete');

  // 3) Prepare webroot + clone repo.
  step(`Clone repository (branch ${branch})`);
  // Refuses to overwrite a deployed alias unless force; with force the old
  // htdocs is kept as a .bak, so a bad clone can never destroy its files.
  const { backup } = await cloneRepo(helpers, { htdocs: HTDOCS, branch, repo, force: p.force });
  ok(backup ? `Repository cloned (previous htdocs kept at ${backup})` : 'Repository cloned');

  // 4) Inject SITE_MOBILE_HOST=<alias> into the MAIN .env, then clone it.
  step(`Inherit .env from ${mainDomain}`);
  await injectEnv(MAIN_ENV, 'SITE_MOBILE_HOST', domain);
  ok(`Set SITE_MOBILE_HOST='${domain}' in ${mainDomain} .env`);
  await fs.copyFile(MAIN_ENV, ENV_FILE);
  ok(`Copied .env from ${mainDomain}`);

  // 5) CDN_PREFIX comes from the cloned .env (no map fetch).
  const CDN_PREFIX = await readEnv(ENV_FILE, 'CDN_PREFIX');
  info(`CDN_PREFIX inherited from main: ${CDN_PREFIX || '<empty>'}`);

  // 6) Swap alias-specific values.
  step('Swap alias-specific .env values');
  const www = p.www || (await siteWww(domain)) || 'nonwww'; // a redeploy keeps the site's WWW preference
  await setEnv(ENV_FILE, 'WP_HOME', `https://${canonicalHost(domain, www)}`);
  await setWpSiteUrl(ENV_FILE);
  await setEnv(ENV_FILE, 'ADVMO_DOS_DOMAIN', `https://${CDN_DOMAIN}/`);
  await setEnv(ENV_FILE, 'SITE_ROLE', 'clone');
  if (isBackup) await setEnv(ENV_FILE, 'SITE_BACKUP', '1');
  ok('WP_HOME, WP_SITEURL, ADVMO_DOS_DOMAIN, SITE_ROLE updated');
  info('SITE_CANONICAL_HOST, SITE_MOBILE_HOST, CDN_PREFIX, DB, Spaces, Telegram, salts inherited from main');

  // 7) Nginx + 4-job cron.
  step('Write nginx vhost + cron');
  await writeNginxVhost({ domain, siteDir: SITE_DIR, webroot: WEBROOT, www });
  ok('Nginx config written');
  await fs.rm(isBackup ? cronPath(domain) : `${cronPath(domain)}.disabled`, { force: true });
  await writeAliasCron({ domain, cronFile: CRON_FILE, src: SRC });
  await finalizeCronPerms(helpers, CRON_FILE);
  ok(`Cron file written: ${CRON_FILE} (4 jobs${isBackup ? ', INACTIVE — backup site' : ''})`);

  // 8) Permissions.
  step('Apply ownership and permissions');
  await applySitePerms(helpers, SITE_DIR);
  ok('Ownership and permissions applied');

  // 9) Test + reload services.
  step('Reload nginx, php-fpm, cron');
  if (await nginxTest(helpers)) {
    await nginxReload(helpers);
    ok('nginx reloaded');
  } else {
    throw new Error('nginx -t failed after writing alias config');
  }
  await tuneAndRestartPhp(helpers, { info, warn }); // tunes PHP if needed, then the usual restart
  await systemctl(helpers, 'restart', 'cron');

  // 10) Clear BOTH alias and main caches (shared DB).
  step('Clear alias + main caches');
  const aliasCache = await clearWpCaches(helpers, SRC, WEBROOT);
  ok(`alias cache: rocket ${aliasCache.rocketOk ? 'cleared' : 'skipped'}, object ${aliasCache.objectFlushed ? 'flushed' : 'skipped'}`);
  const mainCache = await clearWpCaches(helpers, MAIN_SRC, `${MAIN_SRC}/web`);
  ok(`main cache: rocket ${mainCache.rocketOk ? 'cleared' : 'skipped'}, object ${mainCache.objectFlushed ? 'flushed' : 'skipped'}`);

  // 11) SSL.
  step('Issue SSL certificate');
  let sslOk = false;
  if (isBackup) {
    info("backup site — DNS points at the primary, so Let's Encrypt would fail; use Re-issue SSL after switching DNS");
  } else if (await woSiteSsl(helpers, domain, www)) {
    sslOk = true;
    if (await nginxTest(helpers)) await nginxReload(helpers);
    ok('SSL installed');
  } else {
    warn('SSL installation failed (DNS/propagation?) — run `wo site update ' + domain + ' --le --force` later');
  }

  // 12) Register brand + CDN (best-effort). A backup: already done by the primary.
  step('Register brand + CDN');
  if (isBackup) { info('backup site — already registered by the primary'); log(`Backup alias deploy completed: ${domain} (cron inactive)`); return; }
  const b = await brandAdd(domain);
  logApi(helpers, `brand add ${domain}`, b);
  if (CDN_PREFIX) {
    const c = await cdnAdd(CDN_DOMAIN, CDN_PREFIX);
    logApi(helpers, `cdn add ${CDN_DOMAIN} (prefix=${CDN_PREFIX})`, c);
  } else {
    warn(`No CDN_PREFIX inherited — skipping CDN registration for ${CDN_DOMAIN}`);
  }

  log(`Alias deploy completed: ${domain} (clone of ${mainDomain}), ssl=${sslOk}`);
}

function logApi(helpers, label, r) {
  if (r.ok) helpers.log(`✓ ${label} — HTTP ${r.status}`);
  else helpers.log(`⚠ ${label} failed — HTTP ${r.status || 0}${r.error ? ` (${r.error})` : ''} (deploy unaffected)`);
}

