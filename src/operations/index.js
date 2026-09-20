import { runDelete } from './delete.js';
import { runCleanup } from './cleanup.js';
import { runUpdate } from './update.js';
import { runAlias } from './alias.js';
import { runDeploy } from './deploy.js';
import { runCdn } from './cdn.js';
import { runSsl } from './ssl.js';
import { runPurge } from './purge.js';
import { runMigrate } from './migrate.js';
import { runSelfUpdate } from './selfupdate.js';
import { runSshCheck } from './sshcheck.js';
import { APP_REPO_DEFAULT } from '../lib/siteConfig.js';
import { tunePhpNow } from '../lib/site.js';
import { logger } from '../lib/log.js';

// ============================================================
//  Operation registry
// ============================================================
// Each operation defines:
//   - validate(params) -> { ok, errors[], clean }   (never trust the network)
//   - run(job, helpers, params)                       (the actual work)
//
// The `run` bodies below are STUBS. They currently shell out to the existing
// scripts as a placeholder so the pipeline is testable end-to-end, but they are
// the seam where you port each script's logic into JS incrementally. Replace the
// runProcess(...) call in each with native steps (WordOps calls, .env writing,
// nginx/cron, API calls) as you go. The param schemas are already the real
// contract the control panel will use.
//
// SECURITY: validation is the injection boundary. Domains/branches are checked
// against strict patterns so nothing dangerous reaches a shell even via the
// placeholder script calls. Keep these strict as you port.
// ============================================================

// --- validation primitives -------------------------------------------------

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
// git branch: no spaces, no shell metachars, no leading dash
const BRANCH_RE = /^(?!-)[A-Za-z0-9._\/-]{1,200}$/;
const ROOT_RE = DOMAIN_RE;
const MODE_RE = /^(audit|replace|verify|all)$/;

// `git clone` executes `ext::` transports and honours leading-dash options by
// design, and the agent runs as root — so an arbitrary repo URL is root code
// execution. Only known repos are ever cloned. shell:false does not help here.
const REPO_ALLOWLIST = new Set([
  APP_REPO_DEFAULT,
  ...(process.env.AGENT_REPO_ALLOWLIST || '').split(',').map((s) => s.trim()).filter(Boolean),
]);
function optRepo(errors, repo) {
  if (repo == null || repo === '') return;
  if (typeof repo !== 'string' || !REPO_ALLOWLIST.has(repo)) {
    errors.push('repo is not an allowed repository (set AGENT_REPO_ALLOWLIST to permit it)');
  }
}

// Hostnames are case-insensitive and are routinely pasted with a scheme and/or
// a trailing path ("https://Example.COM/"). Normalise instead of rejecting.
export function normDomain(v) {
  return String(v ?? '')
    .trim()
    .replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, '') // strip scheme
    .replace(/\/.*$/, '')                          // drop path / trailing slash
    .toLowerCase();
}

// Every domain-ish parameter, normalised the same way across all operations.
const DOMAIN_FIELDS = ['domain', 'root', 'delete', 'newDomain', 'oldDomain', 'aliasDomain', 'mainDomain'];
// Case-SENSITIVE values: git branches and MySQL identifiers must not be
// lower-cased, so these are only trimmed.
const TRIM_FIELDS = ['branch', 'repo', 'mode', 'destServer', 'destDb', 'file', 'cdnPrefix'];

function sanitize(p) {
  const out = { ...p };
  for (const k of DOMAIN_FIELDS) if (typeof out[k] === 'string') out[k] = normDomain(out[k]);
  for (const k of TRIM_FIELDS) if (typeof out[k] === 'string') out[k] = out[k].trim();
  return out;
}

function isDomain(v) {
  return typeof v === 'string' && DOMAIN_RE.test(v);
}
function reqDomain(errors, name, v) {
  if (!isDomain(v)) errors.push(`${name} must be a valid domain`);
}
function optBranch(errors, v) {
  if (v != null && !BRANCH_RE.test(v)) errors.push('branch has invalid characters');
}

// ============================================================
//  deploy
// ============================================================
const deploy = {
  name: 'deploy',
  // params: { domain, root, delete?, branch?, repo?, cleanup? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    // root is REQUIRED over the API: there's no interactive DB selector, so DB
    // creds + CDN_PREFIX must be resolvable from the map by root domain.
    if (!p.root) errors.push('root is required (API deploys resolve DB creds from the map)');
    else if (!ROOT_RE.test(p.root)) errors.push('root must be a valid domain');
    if (p.delete != null && !isDomain(p.delete)) errors.push('delete must be a valid domain');
    if (p.delete && p.delete === p.domain) errors.push('delete cannot equal domain');
    optBranch(errors, p.branch);
    optRepo(errors, p.repo);
    const clean = {
      domain: p.domain,
      root: p.root || null,
      delete: p.delete || null,
      branch: p.branch || null,
      repo: p.repo || null,
      cleanup: !!p.cleanup, // rewrite cloned old->new URLs during rotation
      force: !!p.force,     // replace an already-deployed site (its htdocs is kept as .bak)
    };
    return { ok: errors.length === 0, errors, clean };
  },
  async run(job, helpers, p) {
    // Native JS implementation — no longer shells out.
    await runDeploy(job, helpers, p);
  },
};

// ============================================================
//  update
// ============================================================
const update = {
  name: 'update',
  // params: { domain, branch? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    optBranch(errors, p.branch);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain, branch: p.branch || null } };
  },
  async run(job, helpers, p) {
    // Native JS implementation — no longer shells out.
    await runUpdate(job, helpers, p);
  },
};

// ============================================================
//  delete
// ============================================================
const del = {
  name: 'delete',
  // params: { domain, confirm: true }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    // Require an explicit confirm flag in the request body so a stray call can't
    // wipe a site. This replaces the script's interactive YES prompt.
    if (p.confirm !== true) errors.push('confirm:true is required to delete a site');
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
  },
  async run(job, helpers, p) {
    // Native JS implementation — no longer shells out to delete-streaming-site.sh.
    await runDelete(job, helpers, p);
  },
};

// ============================================================
//  alias
// ============================================================
const alias = {
  name: 'alias',
  // params: { aliasDomain, mainDomain, branch?, repo? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'aliasDomain', p.aliasDomain);
    reqDomain(errors, 'mainDomain', p.mainDomain);
    if (p.aliasDomain && p.mainDomain && p.aliasDomain === p.mainDomain) {
      errors.push('aliasDomain and mainDomain must differ');
    }
    optBranch(errors, p.branch);
    optRepo(errors, p.repo);
    const clean = {
      aliasDomain: p.aliasDomain,
      mainDomain: p.mainDomain,
      branch: p.branch || null,
      repo: p.repo || null,
      force: !!p.force, // replace an already-deployed alias (its htdocs is kept as .bak)
    };
    return { ok: errors.length === 0, errors, clean };
  },
  async run(job, helpers, p) {
    // Native JS implementation — no longer shells out.
    await runAlias(job, helpers, p);
  },
};

// ============================================================
//  cleanup
// ============================================================
const cleanup = {
  name: 'cleanup',
  // params: { newDomain, oldDomain, mode? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'newDomain', p.newDomain);
    reqDomain(errors, 'oldDomain', p.oldDomain);
    if (p.newDomain && p.oldDomain && p.newDomain === p.oldDomain) {
      errors.push('newDomain and oldDomain must differ');
    }
    let mode = p.mode || 'replace'; // API default: no interactive confirm
    if (!MODE_RE.test(mode)) errors.push('mode must be audit|replace|verify|all');
    // 'all' includes an interactive confirm — reject it over the API; use
    // 'replace' (does the work without prompting) or 'audit' (dry run).
    if (mode === 'all') errors.push("mode 'all' is interactive; use 'replace' or 'audit' over the API");
    return { ok: errors.length === 0, errors, clean: { newDomain: p.newDomain, oldDomain: p.oldDomain, mode } };
  },
  async run(job, helpers, p) {
    // Native JS implementation — no longer shells out.
    await runCleanup(job, helpers, p);
  },
};

// ============================================================
//  cdn — re-register cdn.<domain> (retry for a failed CDN step)
// ============================================================
const cdn = {
  name: 'cdn',
  // params: { domain }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
  },
  async run(job, helpers, p) {
    await runCdn(job, helpers, p);
  },
};

// ============================================================
//  ssl — re-issue Let's Encrypt cert (retry for a failed SSL step)
// ============================================================
const ssl = {
  name: 'ssl',
  // params: { domain }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
  },
  async run(job, helpers, p) {
    await runSsl(job, helpers, p);
  },
};

// ============================================================
//  purge — clear a site's WP Rocket + object caches
// ============================================================
const purge = {
  name: 'purge',
  // params: { domain }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    return { ok: errors.length === 0, errors, clean: { domain: p.domain } };
  },
  async run(job, helpers, p) {
    await runPurge(job, helpers, p);
  },
};

// ============================================================
//  sshcheck — can root read the private repos on GitHub? (read-only, no params)
// ============================================================
const sshcheck = {
  name: 'sshcheck',
  validate() {
    return { ok: true, errors: [], clean: {} };
  },
  async run(job, helpers) {
    await runSshCheck(job, helpers);
  },
};

// ============================================================
//  tunephp — apply scripts/tune-php.sh to every PHP version now (no params)
// ============================================================
const tunephp = {
  name: 'tunephp',
  validate() {
    return { ok: true, errors: [], clean: {} };
  },
  async run(job, helpers) {
    const { step, info, ok } = logger(helpers);
    step('Tune PHP-FPM (every installed version)');
    await tunePhpNow(helpers, { info, ok });
  },
};

// ============================================================
//  selfupdate — git pull this agent + restart it (no params)
// ============================================================
const selfupdate = {
  name: 'selfupdate',
  validate() {
    return { ok: true, errors: [], clean: {} };
  },
  async run(job, helpers) {
    await runSelfUpdate(job, helpers);
  },
};

// ============================================================
//  migrate — move/clone a domain's database to another DB server
// ============================================================
const MIGRATE_MODE_RE = /^(dump|import|pipe|all)$/;
// Interpolated into backticked SQL — keep it to identifier-safe characters.
const DB_NAME_RE = /^[A-Za-z0-9_]{1,64}$/;
const SERVER_LABEL_RE = /^[A-Za-z0-9._-]{1,64}$/;
const CDN_PREFIX_RE = /^[A-Za-z0-9-]{1,64}$/;

const migrate = {
  name: 'migrate',
  // params: { domain, destServer, mode?, destDb?, file?, newDomain?, cdnPrefix? }
  validate(p = {}) {
    p = sanitize(p);
    const errors = [];
    reqDomain(errors, 'domain', p.domain);
    if (!p.destServer) errors.push('destServer is required');
    else if (!SERVER_LABEL_RE.test(p.destServer)) errors.push('destServer has invalid characters');

    const mode = p.mode || 'all';
    if (!MIGRATE_MODE_RE.test(mode)) errors.push('mode must be dump|import|pipe|all');

    if (p.destDb && !DB_NAME_RE.test(p.destDb)) errors.push('destDb must match [A-Za-z0-9_]');
    if (mode === 'import' && !p.file) errors.push('import mode requires file (path to a dump)');
    if (p.file && !/^\/[\w./-]+$/.test(p.file)) errors.push('file must be an absolute path');
    if (p.newDomain && !isDomain(p.newDomain)) errors.push('newDomain must be a valid domain');
    if (p.cdnPrefix && !CDN_PREFIX_RE.test(p.cdnPrefix)) errors.push('cdnPrefix has invalid characters');
    // A move keeps the DB name; registering it would point the map at the new
    // server while the live .env still writes to the old one.
    if (p.newDomain && !p.destDb) errors.push('newDomain applies to a clone: destDb is required and must differ from the source');

    return {
      ok: errors.length === 0,
      errors,
      clean: {
        domain: p.domain,
        destServer: p.destServer,
        mode,
        destDb: p.destDb || null,
        file: p.file || null,
        newDomain: p.newDomain || null,
        cdnPrefix: p.cdnPrefix || null,
      },
    };
  },
  async run(job, helpers, p) {
    await runMigrate(job, helpers, p);
  },
};

// ---------------------------------------------------------------------------

export const operations = { deploy, update, delete: del, alias, cleanup, cdn, ssl, purge, migrate, selfupdate, sshcheck, tunephp };

export function getOperation(type) {
  return operations[type] || null;
}