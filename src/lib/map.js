import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { run, removePath, GIT_SSH_ARGS, explainGitError } from './sys.js';
import { MAP_REPO } from './siteConfig.js';

// ============================================================
//  map.js — seo-domain-map fetch + credential resolution
// ============================================================
// Shallow-clones the private map repo, reads domain-map.json, and pulls DB
// credentials + CDN_PREFIX for a given root domain. The clone (which contains
// secrets) is always removed afterward.
//
// Unlike the interactive script, the API path REQUIRES a root domain — there's
// no selector. The operation validates that before calling here.
// ============================================================

/**
 * Clone the map into a private temp dir. Shallow by default; pass full:true when
 * you intend to WRITE (a registering edit must re-apply onto the latest main,
 * which a shallow clone cannot do). The clone holds credentials — the caller
 * MUST call dispose() when done.
 * @returns {Promise<{dir,mapPath,serversPath,dispose}>}
 */
export async function cloneMap(helpers, { full = false } = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'seomap-'));
  await fs.chmod(dir, 0o700).catch(() => {});
  const args = [...GIT_SSH_ARGS, 'clone', '--quiet'];
  if (!full) args.push('--depth', '1');
  args.push(MAP_REPO, dir);
  const clone = await run(helpers, 'git', args, { quiet: true });
  if (clone.code !== 0) {
    await removePath(dir);
    // git's stderr says WHICH of the possible causes this is — never discard it.
    throw new Error(explainGitError(clone.stderr, 'seo-domain-map'));
  }
  return {
    dir,
    mapPath: path.join(dir, 'domain-map.json'),
    serversPath: path.join(dir, 'servers.json'),
    dispose: () => removePath(dir),
  };
}

/** Read + parse a JSON file from the map clone, with a named error. */
export async function readMapJson(file, label) {
  let raw;
  try {
    raw = await fs.readFile(file, 'utf8');
  } catch {
    throw new Error(`${label} not found in seo-domain-map`);
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

/**
 * Resolve DB creds + CDN_PREFIX for a root domain from the map.
 * @returns {Promise<{DB_HOST,DB_NAME,DB_USER,DB_PASSWORD,CDN_PREFIX}>}
 * @throws if the map can't be cloned/parsed or the root isn't present.
 */
export async function resolveFromMap(helpers, rootDomain) {
  const m = await cloneMap(helpers);
  try {
    const map = await readMapJson(m.mapPath, 'domain-map.json');
    if (!Object.prototype.hasOwnProperty.call(map, rootDomain)) {
      const roots = Object.keys(map).join(', ') || '(none)';
      throw new Error(`root '${rootDomain}' not found in map. Available: ${roots}`);
    }
    const e = map[rootDomain] || {};
    return {
      DB_HOST: e.DB_HOST || '',
      DB_NAME: e.DB_NAME || '',
      DB_USER: e.DB_USER || '',
      DB_PASSWORD: e.DB_PASSWORD || '',
      CDN_PREFIX: e.CDN_PREFIX || '',
    };
  } finally {
    await m.dispose();
  }
}