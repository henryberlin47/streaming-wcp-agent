import config from '../config.js';
import { pathExists, clearWpCaches } from '../lib/sys.js';
import { logger } from '../lib/log.js';

// Purge a site's caches on demand: WP Rocket page cache + object cache.
// Same routine deploy/update/alias run at the end — this is the standalone
// button for when content looks stale and you don't want a full update.
export async function runPurge(job, helpers, p, opts = {}) {
  const { step, ok, warn } = logger(helpers, opts);
  const domain = p.domain;
  const SRC = `${config.wwwDir}/${domain}/htdocs/src`;

  step(`Purge caches for ${domain}`);
  if (!(await pathExists(SRC))) {
    throw new Error(`${SRC} not found (site not deployed here?)`);
  }

  const r = await clearWpCaches(helpers, SRC, `${SRC}/web`);
  // Both failing means wp-cli itself is broken — worth failing the job over.
  // Rocket alone failing is normal (plugin inactive) and already disk-cleaned.
  if (!r.rocketOk && !r.objectFlushed) {
    throw new Error(`cache purge failed for ${domain} — wp-cli returned an error for both rocket and object cache`);
  }
  r.rocketOk ? ok('WP Rocket page cache cleared') : warn('WP Rocket not active (disk cache wiped)');
  r.objectFlushed ? ok('object cache flushed') : warn('object cache not flushed');
}
