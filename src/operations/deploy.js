import config from '../config.js';
import fs from 'node:fs/promises';
import {
  runOrThrow, pathExists, woSiteExists, clearWpCaches, systemctl, nginxTest, nginxReload,
} from '../lib/sys.js';
import {
  setEnv, setEnvRaw, setWpSiteUrl, commentOutEnv, generateSalt,
} from '../lib/envfile.js';
import {
  writeNginxVhost, writeMainCron, finalizeCronPerms, woSiteCreate, woSiteSsl,
  dropLocalWoDb, applySitePerms, cloneRepo, tuneAndRestartPhp, siteWww, canonicalHost,
} from '../lib/site.js';
import { resolveFromMap } from '../lib/map.js';
import { brandAdd, brandDelete, cdnAdd, cdnDelete } from '../lib/api.js';
import { SITE_DEFAULTS, APP_REPO_DEFAULT, BRANCH_DEFAULT } from '../lib/siteConfig.js';
import { logger } from '../lib/log.js';
import { runCleanup } from './cleanup.js';
import { runDelete } from './delete.js';

// ============================================================
//  deploy — native port of deploy-streaming-site.sh
// ============================================================
// Full main-site deploy: resolve DB+CDN_PREFIX from the map (root required over
// the API), wo create, drop local DB, git clone, write .env (salts + all
// constants), nginx + 15-job cron, perms, cache clear, SSL, SEO+CDN register.
// If `delete` is set and SSL succeeded: cleanup cloned URLs -> delete old site
// -> unregister old brand + CDN.
// ============================================================

// params: { domain, root, delete?, branch?, repo? }
export async function runDeploy(job, helpers, p) {
  const { log, step, skip, info, ok, warn } = logger(helpers);
  const domain = p.domain;
  const root = p.root; // required (validated upstream)
  const branch = p.branch || BRANCH_DEFAULT;
  const repo = p.repo || APP_REPO_DEFAULT;
  const deleteDomain = p.delete || null;

  const SITE_DIR = `${config.wwwDir}/${domain}`;
  const HTDOCS = `${SITE_DIR}/htdocs`;
  const SRC = `${HTDOCS}/src`;
  const WEBROOT = `${SRC}/web`;
  const ENV_FILE = `${SRC}/.env`;
  const CRON_FILE = `/etc/cron.d/${domain.replace(/\./g, '_')}`;
  const CDN_DOMAIN = `cdn.${domain}`;

  if (deleteDomain && deleteDomain === domain) {
    throw new Error('delete target cannot equal the domain being deployed');
  }

  // 1) Resolve DB creds + CDN_PREFIX from the map (root required — no selector).
  step(`Resolve DB + CDN_PREFIX from the map (root '${root}')`);
  const creds = await resolveFromMap(helpers, root);
  if (!creds.DB_HOST || !creds.DB_NAME || !creds.DB_USER || !creds.DB_PASSWORD) {
    throw new Error(`map entry for '${root}' is missing one or more DB fields`);
  }
  ok(`Matched root '${root}' (DB ${creds.DB_USER}@${creds.DB_HOST})`);
  const CDN_PREFIX = creds.CDN_PREFIX;

  // 2) WordOps site.
  step('WordOps site');
  if (await woSiteExists(helpers, domain)) {
    warn(`Already exists in WordOps: ${domain} — redeploying`);
  } else {
    await woSiteCreate(helpers, domain);
    ok(`Created ${domain}`);
  }

  // 3) Drop throwaway local DB.
  step('Drop throwaway local database');
  await dropLocalWoDb(helpers, domain);
  ok('Local database cleanup complete');

  // 4) Webroot + clone.
  step(`Clone repository (branch ${branch})`);
  // Refuses to overwrite a deployed site unless force; with force the old
  // htdocs is kept as a .bak, so a bad clone can never destroy .env/uploads.
  const { backup } = await cloneRepo(helpers, { htdocs: HTDOCS, branch, repo, force: p.force });
  ok(backup ? `Repository cloned (previous htdocs kept at ${backup})` : 'Repository cloned');

  // 5+6) .env from example, then every value.
  step('Write .env (DB, CDN, Spaces, Telegram)');
  const example = `${SRC}/.env.example`;
  if (!(await pathExists(example))) throw new Error(`.env.example not found: ${example}`);
  await fs.copyFile(example, ENV_FILE);
  await setEnv(ENV_FILE, 'DB_HOST', creds.DB_HOST);
  await setEnv(ENV_FILE, 'DB_NAME', creds.DB_NAME);
  await setEnv(ENV_FILE, 'DB_USER', creds.DB_USER);
  await setEnv(ENV_FILE, 'DB_PASSWORD', creds.DB_PASSWORD);
  await setEnv(ENV_FILE, 'SITE_CANONICAL_HOST', domain);
  await setEnv(ENV_FILE, 'SITE_ROOT_DOMAIN', root); // the map key its DB creds came from (shown in the portal)
  await setEnv(ENV_FILE, 'CDN_PREFIX', CDN_PREFIX);
  await setEnvRaw(ENV_FILE, 'DB_SSL', SITE_DEFAULTS.DB_SSL); // raw: DB_SSL=false

  // Spaces + Telegram constants
  for (const k of [
    'ADVMO_DOS_KEY', 'ADVMO_DOS_SECRET', 'ADVMO_DOS_ENDPOINT', 'ADVMO_DOS_BUCKET',
    'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID',
    'TELEGRAM_THREAD_SAVE_MATCH_INFO', 'TELEGRAM_THREAD_CREATE_MATCH_LIST',
    'TELEGRAM_THREAD_SAVE_COMPETITIONS', 'TELEGRAM_THREAD_CLEAN_OLD_MATCHES',
    'TELEGRAM_THREAD_CREATE_FUTURE_MATCHES', 'TELEGRAM_THREAD_UPDATE_PREVIOUS_DAY',
    'TELEGRAM_THREAD_WP_CRON_RUNNER', 'TELEGRAM_THREAD_BB_CREATE_POSTS',
    'TELEGRAM_THREAD_BB_UPDATE_PREVIOUS_DAY', 'TELEGRAM_THREAD_BB_CREATE_FUTURE_MATCHES',
  ]) {
    await setEnv(ENV_FILE, k, SITE_DEFAULTS[k]);
  }
  // BB_CLEAN_OLD_POSTS stays commented out.
  await commentOutEnv(ENV_FILE, 'TELEGRAM_THREAD_BB_CLEAN_OLD_POSTS');

  // WWW preference: as asked, else what the site already has (a redeploy must not reset it).
  const www = p.www || (await siteWww(domain)) || 'nonwww';
  await setEnv(ENV_FILE, 'WP_HOME', `https://${canonicalHost(domain, www)}`);
  await setWpSiteUrl(ENV_FILE);
  await setEnv(ENV_FILE, 'ADVMO_DOS_DOMAIN', `https://${CDN_DOMAIN}/`);
  await setEnv(ENV_FILE, 'SITE_ROLE', 'main');
  ok(`.env written (DB ${creds.DB_USER}@${creds.DB_HOST}, CDN_PREFIX=${CDN_PREFIX || 'none'})`);

  // 7) WordPress salts.
  step('Generate security keys/salts');
  for (const k of [
    'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
    'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
  ]) {
    await setEnv(ENV_FILE, k, generateSalt());
  }
  ok('8 keys/salts generated');

  // 8) Nginx + 15-job cron.
  step('Write nginx vhost + cron');
  await writeNginxVhost({ domain, siteDir: SITE_DIR, webroot: WEBROOT, www });
  info(`www: ${www === 'off' ? 'not served' : `served, redirects to ${canonicalHost(domain, www)}`}`);
  await writeMainCron({ domain, cronFile: CRON_FILE, src: SRC });
  await finalizeCronPerms(helpers, CRON_FILE);
  ok(`nginx vhost + ${CRON_FILE} (15 jobs)`);

  // 9) Permissions.
  step('Apply ownership and permissions');
  await applySitePerms(helpers, SITE_DIR);
  ok(`www-data:www-data on ${SITE_DIR}`);

  // 10) Test + reload services.
  step('Reload nginx, php-fpm, cron');
  if (await nginxTest(helpers)) {
    await nginxReload(helpers);
    ok('nginx -t passed, reloaded');
  } else {
    throw new Error('nginx -t failed after writing config');
  }
  await tuneAndRestartPhp(helpers, { info, warn }); // tunes PHP if needed, then the usual restart
  await systemctl(helpers, 'restart', 'cron');
  ok('php8.3-fpm + cron restarted');

  // 11) Clear caches.
  step('Clear caches');
  const cache = await clearWpCaches(helpers, SRC, WEBROOT);
  ok(`rocket ${cache.rocketOk ? 'cleared' : 'skipped'}, object ${cache.objectFlushed ? 'flushed' : 'skipped'}`);

  // 12) SSL.
  step('Issue SSL certificate');
  let sslOk = false;
  if (await woSiteSsl(helpers, domain, www)) {
    sslOk = true;
    if (await nginxTest(helpers)) await nginxReload(helpers);
    ok(`SSL installed for ${domain}`);
  } else {
    warn(`SSL failed (DNS/propagation?) — run \`wo site update ${domain} --le --force\` later`);
  }

  // 13) Rotation: cleanup cloned URLs -> delete old -> unregister old APIs.
  //     Only when a delete target is set AND SSL succeeded (site is live).
  let deletedOld = false;
  if (deleteDomain) {
    if (!sslOk) {
      skip(`Rotate out '${deleteDomain}'`);
      warn("new site's SSL did not succeed — old site left in place");
    } else {
      // Rewrite cloned old-brand URLs in the new DB (non-interactive 'replace').
      // Optional: only when the deploy requested it (checkbox in the panel).
      if (p.cleanup) {
        step(`Rewrite cloned URLs (${deleteDomain} → ${domain})`);
        try {
          await runCleanup(job, helpers, { newDomain: domain, oldDomain: deleteDomain, mode: 'replace' }, { nested: true });
        } catch (e) {
          warn(`URL cleanup error (continuing): ${e.message}`);
        }
      } else {
        skip('Rewrite cloned URLs');
      }
      // Delete the old site natively.
      step(`Remove old site '${deleteDomain}'`);
      try {
        await runDelete(job, helpers, { domain: deleteDomain }, { nested: true });
        deletedOld = true;
        ok(`${deleteDomain} removed`);
      } catch (e) {
        warn(`Old-site delete error: ${e.message}`);
      }
    }
  }

  // 14) Register new brand + CDN; unregister old if rotated.
  step('Register brand + CDN');
  logApi(helpers, `brand add ${domain}`, await brandAdd(domain));
  if (deleteDomain && deletedOld) {
    logApi(helpers, `brand delete ${deleteDomain}`, await brandDelete(deleteDomain));
  }
  if (CDN_PREFIX) {
    logApi(helpers, `cdn add ${CDN_DOMAIN} (prefix=${CDN_PREFIX})`, await cdnAdd(CDN_DOMAIN, CDN_PREFIX));
  } else {
    warn(`No CDN_PREFIX resolved — skipping CDN registration for ${CDN_DOMAIN}`);
  }
  if (deleteDomain && deletedOld) {
    logApi(helpers, `cdn delete cdn.${deleteDomain}`, await cdnDelete(`cdn.${deleteDomain}`));
  }

  log(`Deploy completed: ${domain} (root=${root}, ssl=${sslOk}${deleteDomain ? `, rotated=${deletedOld}` : ''})`);
}

function logApi(helpers, label, r) {
  if (r.ok) helpers.log(`✓ ${label} — HTTP ${r.status}`);
  else helpers.log(`⚠ ${label} failed — HTTP ${r.status || 0}${r.error ? ` (${r.error})` : ''} (deploy unaffected)`);
}

