import { woSiteSsl, siteWww } from '../lib/site.js';
import { checkCertPair, installCustomCert } from '../lib/cert.js';
import { logger } from '../lib/log.js';

// SSL for a site, two ways:
//  - { domain }             re-issue Let's Encrypt (wo site update <domain> --le --force).
//                           Standalone retry for when SSL failed during deploy (it's
//                           best-effort there and doesn't block the deploy).
//  - { domain, cert, key }  install a certificate pasted into the portal (a bought
//                           cert, a Cloudflare origin cert, …). Validated before
//                           anything is written; rolled back if nginx rejects it.
// Fails the job on error so the result is visible.
export async function runSsl(job, helpers, p) {
  const domain = p.domain;
  if (p.cert || p.key) {
    // Jobs stay in memory for about an hour: don't let the private key stay with them.
    try { return await runCustomSsl(helpers, { ...p }); } finally { p.key = null; p.cert = null; }
  }
  helpers.log(`Issuing SSL for ${domain} (wo site update ${domain} --le --force)...`);
  const ok = await woSiteSsl(helpers, domain);
  if (!ok) {
    throw new Error(`SSL issuance failed for ${domain} — ensure its DNS points to this server and port 80 is reachable`);
  }
  helpers.log(`✓ SSL issued for ${domain}`);
}

async function runCustomSsl(helpers, p) {
  const { log, step, info, ok, warn } = logger(helpers);
  step('Validate the certificate + key');
  const v = checkCertPair(p); // validate() already ran this; re-check at the point of use
  if (v.errors.length) throw new Error(v.errors.join('; '));
  info(`subject: ${v.info.subject || '—'}`);
  info(`issuer:  ${v.info.issuer || '—'}`);
  info(`covers:  ${v.info.names || '—'}`);
  info(`expires: ${v.info.expires.slice(0, 10)} · ${v.info.chain} certificate(s) in the chain`);
  if (v.info.chain === 1) warn('no intermediate certificate pasted — fine for a Cloudflare origin cert, but a CA-issued cert needs its chain or some browsers will reject it');
  ok('key matches the certificate, and it covers this domain');
  const www = await siteWww(p.domain);
  if (www && www !== 'off' && !v.covers(`www.${p.domain}`)) {
    if (www === 'www') throw new Error(`this site's canonical host is www.${p.domain}, and the certificate does not cover it — nothing was changed`);
    warn(`the certificate does not cover www.${p.domain}: https://www.${p.domain} will show a browser warning before it redirects (set WWW to "off" if www is not used)`);
  }

  step('Install + reload nginx');
  await installCustomCert(helpers, { domain: p.domain, fullchain: v.fullchain, key: v.key }, { info, ok, warn });
  log(`Custom certificate installed for ${p.domain} (it does NOT auto-renew — replace it before ${v.info.expires.slice(0, 10)})`);
}
