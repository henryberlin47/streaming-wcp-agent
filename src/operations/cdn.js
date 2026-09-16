import config from '../config.js';
import { pathExists } from '../lib/sys.js';
import { readEnv } from '../lib/envfile.js';
import { cdnAdd } from '../lib/api.js';

// Re-register a site's CDN entry (cdn.<domain>) using CDN_PREFIX from its .env.
// Standalone retry for when the CDN step failed during deploy/alias (it's
// best-effort there and doesn't block the deploy). Unlike that path, this op
// DOES fail the job on error, so the retry's success/failure is visible.
export async function runCdn(job, helpers, p) {
  const domain = p.domain;
  const ENV_FILE = `${config.wwwDir}/${domain}/htdocs/src/.env`;
  if (!(await pathExists(ENV_FILE))) {
    throw new Error(`.env not found at ${ENV_FILE} (site not deployed here?)`);
  }
  const prefix = await readEnv(ENV_FILE, 'CDN_PREFIX');
  if (!prefix) throw new Error(`CDN_PREFIX is empty in ${domain} .env — nothing to register`);

  const cdnDomain = `cdn.${domain}`;
  helpers.log(`Registering ${cdnDomain} (prefix=${prefix})...`);
  const r = await cdnAdd(cdnDomain, prefix);
  if (r.ok) {
    helpers.log(`✓ cdn add ${cdnDomain} — HTTP ${r.status}`);
  } else {
    throw new Error(`cdn add ${cdnDomain} failed — HTTP ${r.status || 0}${r.error ? ` (${r.error})` : ''}`);
  }
}
