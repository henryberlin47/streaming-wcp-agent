import { woSiteSsl } from '../lib/site.js';

// Re-issue Let's Encrypt SSL for a site (wo site update <domain> --le --force).
// Standalone retry for when SSL failed during deploy (it's best-effort there and
// doesn't block the deploy). Fails the job on error so the result is visible.
export async function runSsl(job, helpers, p) {
  const domain = p.domain;
  helpers.log(`Issuing SSL for ${domain} (wo site update ${domain} --le --force)...`);
  const ok = await woSiteSsl(helpers, domain);
  if (!ok) {
    throw new Error(`SSL issuance failed for ${domain} — ensure its DNS points to this server and port 80 is reachable`);
  }
  helpers.log(`✓ SSL issued for ${domain}`);
}
