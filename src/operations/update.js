import config from '../config.js';
import fs from 'node:fs/promises';
import {
  run, runOrThrow, pathExists, git, gitShortHead, gitCurrentBranch,
  gitRemoteBranchExists, chownWww, wpCli, clearWpCaches, systemctl, nginxTest, nginxReload,
} from '../lib/sys.js';
import { logger } from '../lib/log.js';

// ============================================================
//  update — native port of deploy-update-streaming-site.sh
// ============================================================
// Pulls latest code for an existing site and redeploys cleanly:
//   verify branch on remote -> hard reset -> preserve .env (backup/restore) ->
//   reapply perms -> warm Acorn -> restart php-fpm + reload nginx -> clear caches.
// Git runs as root (holds the SSH deploy key); wp/acorn run as www-data.
// ============================================================

const DEFAULT_BRANCH = 'feature/nginx-wprocket';

// params: { domain, branch? }
export async function runUpdate(job, helpers, p, opts = {}) {
  const { log, step, info, ok, warn, err } = logger(helpers, opts);
  const domain = p.domain;

  const SITE_DIR = `${config.wwwDir}/${domain}`;
  const HTDOCS = `${SITE_DIR}/htdocs`;
  const SRC = `${HTDOCS}/src`;
  const WEBROOT = `${SRC}/web`;
  const ENV_FILE = `${SRC}/.env`;

  // 1) Validate deployment.
  step('Validate deployment');
  if (!(await pathExists(`${HTDOCS}/.git`))) {
    throw new Error(`no git repository at ${HTDOCS} (site not deployed here)`);
  }
  const hasEnv = await pathExists(ENV_FILE);
  if (hasEnv) ok('.env present (will be preserved)');
  else warn('.env not found — continuing, but the site may be misconfigured');

  // 2) Back up .env.
  let envBak = null;
  if (hasEnv) {
    envBak = `${ENV_FILE}.agentbak.${Date.now()}`;
    await fs.copyFile(ENV_FILE, envBak);
    info(`.env backed up`);
  }

  try {
    // 3) Fetch + verify branch before touching the tree.
    step('Fetch + verify branch');
    const before = await gitShortHead(helpers, HTDOCS);
    const curBranch = await gitCurrentBranch(helpers, HTDOCS);
    // No branch specified → stay on the repo's current branch. Only fall back to
    // the project default if HEAD is detached/unknown.
    const branch = p.branch || (['HEAD', 'unknown'].includes(curBranch) ? DEFAULT_BRANCH : curBranch);
    if (curBranch !== branch) info(`Repo on '${curBranch}'; switching to '${branch}'`);

    await runOrThrow(helpers, 'git', ['-C', HTDOCS, 'fetch', 'origin', '--quiet']);
    if (!(await gitRemoteBranchExists(helpers, HTDOCS, branch))) {
      throw new Error(`origin/${branch} not found on remote — nothing changed`);
    }

    // 4) Force the tree to exactly origin/<branch> (keeps untracked .env/uploads).
    step(`Reset working tree to origin/${branch}`);
    warn('Local uncommitted changes to tracked files will be discarded.');
    await runOrThrow(helpers, 'git', ['-C', HTDOCS, 'checkout', '-f', '-B', branch, `origin/${branch}`]);
    await runOrThrow(helpers, 'git', ['-C', HTDOCS, 'reset', '--hard', `origin/${branch}`]);

    const after = await gitShortHead(helpers, HTDOCS);
    if (before === after) info(`Already up to date at ${after} — re-running cache steps anyway.`);
    else ok(`Updated ${before} -> ${after}`);

    // 5) Restore .env unconditionally (guards against upstream tracking an .env).
    if (envBak) {
      const same = await filesEqual(envBak, ENV_FILE);
      if (!same) {
        await fs.copyFile(envBak, ENV_FILE);
        warn('.env differed after reset — restored from backup');
      } else {
        ok('.env unchanged');
      }
    }

    // 6) Reapply ownership + permissions.
    step('Apply ownership and permissions');
    await chownWww(helpers, SITE_DIR);
    await run(helpers, 'find', [SITE_DIR, '-type', 'd', '-exec', 'chmod', '755', '{}', '+'], { quiet: true });
    await run(helpers, 'find', [SITE_DIR, '-type', 'f', '-exec', 'chmod', '644', '{}', '+'], { quiet: true });
    ok('Ownership and permissions applied');

    // 7) Warm Acorn (Blade) caches.
    step('Warm Acorn (Blade) caches');
    const wp = wpCli(helpers, SRC);
    await wp(['acorn', 'package:discover']).catch(() => warn('acorn package:discover failed (non-fatal)'));
    await wp(['acorn', 'view:clear']).catch(() => warn('acorn view:clear failed (non-fatal)'));
    await wp(['acorn', 'view:cache']).catch(() => warn('acorn view:cache failed (non-fatal)'));
    ok('Acorn packages discovered, views cached');

    // 8) Restart php-fpm (clears OPcache), test + reload nginx.
    step('Restart php-fpm, reload nginx');
    await systemctl(helpers, 'restart', 'php8.3-fpm');
    if (await nginxTest(helpers)) {
      await nginxReload(helpers);
      ok('nginx reloaded');
    } else {
      err('nginx -t failed — not reloading');
    }

    // 9) Clear WP Rocket + object cache.
    step('Clear caches');
    const { rocketOk, objectFlushed } = await clearWpCaches(helpers, SRC, WEBROOT);
    ok(`WP Rocket ${rocketOk ? 'cleared' : 'skipped'}; object cache ${objectFlushed ? 'flushed' : 'skipped'}`);

    log(`Update completed for ${domain} (${before} -> ${after})`);
  } finally {
    if (envBak) await fs.rm(envBak, { force: true });
  }
}

async function filesEqual(a, b) {
  try {
    const [ba, bb] = await Promise.all([fs.readFile(a), fs.readFile(b)]);
    return ba.equals(bb);
  } catch {
    return false;
  }
}

