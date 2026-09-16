import config from '../config.js';
import { fileURLToPath } from 'node:url';
import { pathExists, run, clearWpCaches } from '../lib/sys.js';
import { readEnv } from '../lib/envfile.js';
import { logger } from '../lib/log.js';

// ============================================================
//  cleanup — DB-level URL rewrite (port of cleanup-urls-site.sh)
// ============================================================
// Rewrites https://<old> -> https://<new> straight in MySQL via an embedded
// PHP engine (PDO, serialize-safe, no WordPress bootstrap) — much faster than
// wp-cli search-replace. Modes: audit (count), replace (write + cache flush),
// verify (recount). Refuses to touch a clone/mobile site (shared DB) unless
// allowClone is set. The interactive 'all' mode is rejected by validate().
// ============================================================

const ENGINE = fileURLToPath(new URL('./url-cleanup.php', import.meta.url));
const PHP_BIN = process.env.PHP_BIN || '/usr/bin/php';

const normHost = (h) => String(h || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');

// params: { newDomain, oldDomain, mode, tables?, allowClone? }
export async function runCleanup(job, helpers, p, opts = {}) {
  const { log, info, ok, warn } = logger(helpers, opts);
  const mode = p.mode;
  const newHost = normHost(p.newDomain);
  const oldHost = normHost(p.oldDomain);
  const tables = Array.isArray(p.tables) ? p.tables.join(' ') : String(p.tables || '');

  if (!newHost || !oldHost) throw new Error('newDomain and oldDomain are required');
  if (newHost === oldHost) throw new Error(`new and old domain are identical (${newHost}) — nothing to do`);

  const NEW_URL = `https://${newHost}`;
  const OLD_URL = `https://${oldHost}`;
  const SRC = `${config.wwwDir}/${newHost}/htdocs/src`;
  const WEBROOT = `${SRC}/web`;
  const ENV_FILE = `${SRC}/.env`;

  if (!(await pathExists(SRC))) throw new Error(`site source dir not found: ${SRC} (is <newDomain> correct?)`);
  if (!(await pathExists(ENV_FILE))) throw new Error(`.env not found: ${ENV_FILE} (needed for DB credentials)`);

  // --- DB credentials from the site's Bedrock .env ---
  const DB_NAME = await readEnv(ENV_FILE, 'DB_NAME');
  const DB_USER = await readEnv(ENV_FILE, 'DB_USER');
  const DB_PASSWORD = await readEnv(ENV_FILE, 'DB_PASSWORD');
  const DB_PREFIX = (await readEnv(ENV_FILE, 'DB_PREFIX')) || 'wp_';
  const DB_SSL = await readEnv(ENV_FILE, 'DB_SSL');
  const rawHost = await readEnv(ENV_FILE, 'DB_HOST');
  if (!DB_NAME || !DB_USER || !rawHost) throw new Error(`missing DB_NAME/DB_USER/DB_HOST in ${ENV_FILE}`);
  const [DB_HOST, DB_PORT = '3306'] = rawHost.includes(':') ? rawHost.split(':') : [rawHost];

  // --- Clone/mobile guard: those share the main site's DB; rewriting would
  //     corrupt the main site's URLs too. Refuse unless explicitly overridden. ---
  const role = String((await readEnv(ENV_FILE, 'SITE_ROLE')) || '').toLowerCase();
  if (!p.allowClone && (role === 'clone' || role === 'mobile')) {
    throw new Error(`SITE_ROLE='${role}' shares the main site's database — refusing URL rewrite (pass allowClone to override)`);
  }

  const envFor = (m) => ({
    UC_MODE: m,
    UC_OLD_URL: OLD_URL, UC_NEW_URL: NEW_URL,
    UC_DB_HOST: DB_HOST, UC_DB_PORT: String(DB_PORT), UC_DB_NAME: DB_NAME,
    UC_DB_USER: DB_USER, UC_DB_PASSWORD: DB_PASSWORD || '',
    UC_DB_PREFIX: DB_PREFIX, UC_DB_SSL: DB_SSL || '', UC_TABLES: tables,
  });

  const runEngine = async (m, quiet = false) => {
    const r = await run(helpers, PHP_BIN, [ENGINE], { env: envFor(m), quiet });
    if (r.code !== 0) throw new Error(`cleanup engine failed (${m}): ${(r.stderr || r.stdout).trim()}`);
    return r.stdout;
  };
  const field = (out, name) => {
    const m = new RegExp(`^SUMMARY .*${name}=(\\d+)`, 'm').exec(out);
    return m ? parseInt(m[1], 10) : 0;
  };

  // Preflight: confirm the DB is reachable and show the current home URL.
  let home = '(unknown)';
  try {
    const r = await run(helpers, PHP_BIN, [ENGINE], { env: envFor('home'), quiet: true });
    if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim());
    home = r.stdout.trim() || '(unknown)';
  } catch (e) {
    throw new Error(`cannot reach ${DB_NAME} @ ${DB_HOST}:${DB_PORT} — ${e.message}`);
  }
  info(`DB ${DB_NAME} @ ${DB_HOST}:${DB_PORT}  ·  home=${home}`);
  info(`${OLD_URL} -> ${NEW_URL}  ·  mode=${mode}  ·  engine=direct SQL (serialize-safe)`);

  if (mode === 'audit') {
    const out = await runEngine('audit');
    ok(`${field(out, 'matched')} row(s) contain ${OLD_URL}`);
  } else if (mode === 'replace') {
    const out = await runEngine('replace');
    const skipped = field(out, 'skipped');
    ok(`${field(out, 'updated')} row(s) rewritten, ${field(out, 'serialized')} serialized`);
    if (skipped) {
      warn(`${skipped} row(s) held serialized objects/back-references and were SKIPPED — they still contain ${OLD_URL}; review by hand.`);
    }
    const cache = await clearWpCaches(helpers, SRC, WEBROOT);
    ok(`cache: rocket ${cache.rocketOk ? 'cleared' : 'skipped'}, object ${cache.objectFlushed ? 'flushed' : 'skipped'}`);
    ok('Replace + flush complete.');
  } else if (mode === 'verify') {
    const out = await runEngine('audit');
    const n = field(out, 'matched');
    if (n === 0) ok(`Verified: 0 remaining rows contain ${OLD_URL}.`);
    else warn(`${n} row(s) still contain ${OLD_URL} — re-run replace, or review skipped rows.`);
  } else {
    throw new Error(`unsupported mode over API: ${mode}`);
  }

  log(`Cleanup (${mode}) done for ${newHost}`);
}

