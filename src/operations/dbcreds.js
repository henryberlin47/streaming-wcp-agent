import config from '../config.js';
import { pathExists, clearWpCaches } from '../lib/sys.js';
import { setEnv, readEnv } from '../lib/envfile.js';
import { resolveFromMap } from '../lib/map.js';
import { logger } from '../lib/log.js';

// ============================================================
//  dbcreds — re-pull a live site's DB credentials from the map
// ============================================================
// A deploy copies DB_HOST / DB_NAME / DB_USER / DB_PASSWORD out of
// seo-domain-map once. When the map changes afterwards (database moved to
// another server, password rotated) the site's .env is stale. This reads the
// map entry of the site's recorded root domain again and rewrites the four
// keys that differ — nothing else in the .env is touched. The password is
// never logged; only the names of the keys that changed are.
// ============================================================
const DB_KEYS = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'];

export async function runDbCreds(job, helpers, p) {
  const { step, ok, warn } = logger(helpers);
  const SRC = `${config.wwwDir}/${p.domain}/htdocs/src`;
  const env = `${SRC}/.env`;
  if (!(await pathExists(env))) throw new Error(`${p.domain} is not deployed on this server (no ${env})`);
  const root = await readEnv(env, 'SITE_ROOT_DOMAIN');
  if (!root) throw new Error(`${p.domain} has no root domain recorded — set it first (Sites → ⋯ → Set root domain), then retry`);

  step(`Resolve DB credentials from the map (root '${root}')`);
  const creds = await resolveFromMap(helpers, root);
  const missing = DB_KEYS.filter((k) => !creds[k]);
  if (missing.length) throw new Error(`map entry for '${root}' is missing: ${missing.join(', ')}`);
  ok(`Matched root '${root}' (DB ${creds.DB_USER}@${creds.DB_HOST})`);

  step(`Update ${env}`);
  const changed = [];
  for (const k of DB_KEYS) {
    if ((await readEnv(env, k)) === creds[k]) continue;
    await setEnv(env, k, creds[k]);
    changed.push(k);
  }
  if (!changed.length) { ok('already matches the map — nothing changed'); return; }
  ok(`updated: ${changed.join(', ')}`);

  // The page + object caches were filled through the old connection.
  step('Clear caches');
  const r = await clearWpCaches(helpers, SRC, `${SRC}/web`);
  if (!r.rocketOk && !r.objectFlushed) warn('caches not cleared — wp-cli failed. Open the site: if it shows a database error, the map entry does not work from this server.');
  else ok('caches cleared');
}
