import fs from 'node:fs/promises';
import config from '../config.js';
import { pathExists } from '../lib/sys.js';
import { setEnv, readEnv } from '../lib/envfile.js';
import { logger } from '../lib/log.js';
import { INSTALL_DIR, requireEmptyQueue, scheduleRestart } from './selfupdate.js';

// ============================================================
//  secrets — rotate the deploy secrets on this server
// ============================================================
// The portal's .env is the source of truth for the five deploy secrets, but
// they only reach a server at bootstrap. This op takes new values from the
// portal and writes them (1) into the agent's own .env — read by systemd at
// start, so the agent is restarted like selfupdate — and (2) into every
// deployed site's src/.env, for the keys sites carry. Values are never logged;
// the job view redacts them by key name (KEY/SECRET/TOKEN).
// ============================================================
export const SECRET_KEYS = ['ADVMO_DOS_KEY', 'ADVMO_DOS_SECRET', 'TELEGRAM_BOT_TOKEN', 'SEO_MONITOR_TOKEN', 'CDN_API_KEY'];
const SITE_KEYS = ['ADVMO_DOS_KEY', 'ADVMO_DOS_SECRET', 'TELEGRAM_BOT_TOKEN']; // what a site's .env holds
const AGENT_ENV = process.env.AGENT_ENV_FILE || `${INSTALL_DIR}/.env`; // env: tests only

export async function runSecrets(job, helpers, p) {
  const { log, step, info, ok, warn } = logger(helpers);
  const keys = SECRET_KEYS.filter((k) => typeof p[k] === 'string' && p[k] !== '');
  if (!keys.length) throw new Error('no secrets given');
  requireEmptyQueue(job);

  step(`Agent .env (${AGENT_ENV})`);
  if (!(await pathExists(AGENT_ENV))) throw new Error(`${AGENT_ENV} not found`);
  let changed = 0;
  for (const k of keys) {
    if ((await readEnv(AGENT_ENV, k)) === p[k]) continue;
    await setEnv(AGENT_ENV, k, p[k]);
    changed++;
  }
  await fs.chmod(AGENT_ENV, 0o600);
  ok(`${keys.length} key(s) checked, ${changed} changed: ${keys.join(', ')}`);

  if (p.sites !== false) {
    step('Deployed sites');
    const siteKeys = keys.filter((k) => SITE_KEYS.includes(k));
    let dirs = [];
    try { dirs = await fs.readdir(config.wwwDir); } catch { /* no sites dir */ }
    let sites = 0, touched = 0;
    for (const d of dirs) {
      const env = `${config.wwwDir}/${d}/htdocs/src/.env`;
      if (!(await pathExists(env))) continue;
      sites++;
      let n = 0;
      for (const k of siteKeys) {
        if ((await readEnv(env, k)) === p[k]) continue;
        await setEnv(env, k, p[k]);
        n++;
      }
      if (n) { touched++; info(`${d}: ${n} key(s) updated`); }
    }
    ok(`${sites} site(s) found, ${touched} updated (${siteKeys.join(', ') || 'no site-level keys given'})`);
    if (touched) info('sites read their .env per request — no restart needed for them');
  }

  step('Restart the agent so it loads the new values');
  if (changed) ok(await scheduleRestart(helpers));
  else info('agent .env unchanged — no restart needed');
  log(`Secrets rotated: ${keys.join(', ')}`);
}
