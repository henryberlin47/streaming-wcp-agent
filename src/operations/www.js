import fs from 'node:fs/promises';
import config from '../config.js';
import { pathExists, nginxTest, nginxReload, clearWpCaches } from '../lib/sys.js';
import { readEnv, setEnv } from '../lib/envfile.js';
import { writeNginxVhost, woSiteSsl, siteWww, canonicalHost } from '../lib/site.js';
import { siteCert, NGINX_DIR } from '../lib/cert.js';
import { logger } from '../lib/log.js';

// ============================================================
//  www — change a live site's WWW preference
// ============================================================
//   nonwww  serve www.<domain>, redirect it to <domain>      (default)
//   www     serve <domain>, redirect it to www.<domain>
//   off     do not serve www.<domain> at all
// Order matters: the CERTIFICATE is dealt with first, because making www the
// canonical host while the cert does not cover it would put a browser warning
// in front of every visitor. Then the vhost (gated by `nginx -t`, restored on
// failure), then WP_HOME, then the caches (cached pages carry the old host).
// ============================================================
export async function runWww(job, helpers, p) {
  const { log, step, info, ok, warn } = logger(helpers);
  const { domain, mode } = p;
  const SITE_DIR = `${config.wwwDir}/${domain}`;
  const SRC = `${SITE_DIR}/htdocs/src`;
  const ENV_FILE = `${SRC}/.env`;
  const VHOST = `${NGINX_DIR}/sites-available/${domain}`;
  const wwwHost = `www.${domain}`;

  const current = await siteWww(domain);
  if (!current || !(await pathExists(ENV_FILE))) throw new Error(`${domain} is not a deployed site on this server`);
  step(`WWW preference: ${current} → ${mode}`);

  // 1) Certificate. (No SSL at all = plain http, nothing to cover.)
  const covers = async () => { const c = await siteCert(domain); return { type: c.type, www: !!c.x509?.checkHost(wwwHost) }; };
  let cert = await covers();
  if (mode !== 'off' && cert.type === 'letsencrypt' && !cert.www) {
    info(`the Let's Encrypt certificate does not cover ${wwwHost} — re-issuing it with www`);
    await woSiteSsl(helpers, domain, mode);
    cert = await covers();
  }
  if (mode !== 'off' && cert.type !== 'none' && !cert.www) {
    const why = cert.type === 'custom'
      ? `install a custom certificate that also covers ${wwwHost} first (Custom SSL)`
      : `Let's Encrypt did not issue for ${wwwHost}: point its DNS at this server and retry (WordOps never adds www for a subdomain site — use a custom certificate there)`;
    if (mode === 'www') throw new Error(`the certificate does not cover ${wwwHost} — ${why}. Nothing was changed.`);
    warn(`the certificate does not cover ${wwwHost}: https://${wwwHost} shows a browser warning before it redirects — ${why}`);
  } else if (cert.type !== 'none') {
    ok(mode === 'off' ? `certificate: ${cert.type}` : `certificate (${cert.type}) covers ${wwwHost}`);
  }

  // 2) vhost, gated by nginx -t.
  step('Write nginx vhost');
  const before = await fs.readFile(VHOST, 'utf8');
  await writeNginxVhost({ domain, siteDir: SITE_DIR, webroot: `${SRC}/web`, www: mode });
  if (!(await nginxTest(helpers))) {
    await fs.writeFile(VHOST, before);
    throw new Error('nginx -t rejected the new vhost — the old one was restored, the site is unchanged');
  }
  await nginxReload(helpers);
  ok(mode === 'off' ? `${wwwHost} is no longer served` : `${mode === 'www' ? domain : wwwHost} → 301 → ${canonicalHost(domain, mode)}`);

  // 3) WordPress must agree, or it redirects straight back (a loop).
  step('WordPress home URL');
  const home = `https://${canonicalHost(domain, mode)}`;
  if ((await readEnv(ENV_FILE, 'WP_HOME')) === home) {
    info(`WP_HOME already ${home}`);
  } else {
    await setEnv(ENV_FILE, 'WP_HOME', home);
    ok(`WP_HOME=${home}`);
    const cache = await clearWpCaches(helpers, SRC, `${SRC}/web`);
    ok(`caches: rocket ${cache.rocketOk ? 'cleared' : 'skipped'}, object ${cache.objectFlushed ? 'flushed' : 'skipped'}`);
    info('links stored inside post content keep the old host and simply redirect — run "Cleanup URLs" if you want them rewritten');
  }

  // 4) www off: a Let's Encrypt cert that still lists www fails to RENEW once
  //    www's DNS is gone. Re-issue it for the bare domain. Best-effort.
  if (mode === 'off' && cert.type === 'letsencrypt' && cert.www) {
    step(`Re-issue Let's Encrypt without ${wwwHost}`);
    if (await woSiteSsl(helpers, domain, 'off')) ok('certificate re-issued for the bare domain');
    else warn(`could not re-issue — the current certificate still lists ${wwwHost} and will stop renewing if that name has no DNS. Retry with "Re-issue SSL".`);
  }

  log(`WWW preference for ${domain} is now: ${mode}`);
}
