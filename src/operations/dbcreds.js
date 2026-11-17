import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import config from '../config.js';
import { run, removePath, pathExists, clearWpCaches } from '../lib/sys.js';
import { writeDefaults, clientIsMariadb } from '../lib/mysql.js';
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
//
// A live site switches to whatever is written, so the map's credentials are
// TESTED from this server first (a real connection to that database). If they
// do not connect, nothing is written — a stale map entry must not take a
// working site down. The .env as it was is kept beside it as
// `.env.before-dbcreds` (0600, outside the webroot) for a manual way back.
// ============================================================
const DB_KEYS = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'];

/** Can this server open that database with these credentials? -> { ok, error } */
async function canConnect(helpers, creds, ssl) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dbc-'));
  try {
    const [host, port = '3306'] = String(creds.DB_HOST).split(':');
    // password in a 0600 option file, never on the process list
    const cnf = await writeDefaults(path.join(dir, 'db.cnf'), { host, port, user: creds.DB_USER, password: creds.DB_PASSWORD, ssl }, await clientIsMariadb(helpers, 'mysql'));
    const r = await run(helpers, 'mysql', [`--defaults-extra-file=${cnf}`, '--connect-timeout=10', '-N', '-e', 'SELECT 1', creds.DB_NAME], { quiet: true });
    return { ok: r.code === 0, error: `${r.stderr || r.stdout}`.trim().split('\n').pop() || `mysql exited ${r.code}` };
  } finally {
    await removePath(dir);
  }
}

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

  const differ = [];
  for (const k of DB_KEYS) if ((await readEnv(env, k)) !== creds[k]) differ.push(k);
  if (!differ.length) { ok('the .env already matches the map — nothing changed'); return; }

  step(`Test the map's credentials from this server (differs: ${differ.join(', ')})`);
  const test = await canConnect(helpers, creds, (await readEnv(env, 'DB_SSL')) === 'true' ? 'required' : 'disabled');
  if (!test.ok) {
    throw new Error(`the map's credentials for '${root}' do not connect from this server — the site's .env was NOT changed. `
      + `mysql said: ${test.error}. Fix the '${root}' entry in seo-domain-map (or allow this server on that database), then retry.`);
  }
  ok(`connected to ${creds.DB_NAME} on ${creds.DB_HOST} as ${creds.DB_USER}`);

  step(`Update ${env}`);
  const before = `${env}.before-dbcreds`;
  await fs.copyFile(env, before);
  await fs.chmod(before, 0o600);
  for (const k of differ) await setEnv(env, k, creds[k]);
  ok(`updated: ${differ.join(', ')} (previous .env kept at ${before})`);

  // The page + object caches were filled through the old connection.
  step('Clear caches');
  const r = await clearWpCaches(helpers, SRC, `${SRC}/web`);
  if (!r.rocketOk && !r.objectFlushed) warn('caches not cleared — wp-cli failed. Open the site: if it shows a database error, the map entry does not work from this server.');
  else ok('caches cleared');
}
