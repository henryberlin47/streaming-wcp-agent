import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import fssync from 'node:fs';
import os from 'node:os';

// ============================================================
//  sys.js — shared system helpers for native operation logic
// ============================================================
// Everything an operation needs to touch the OS: run commands (streaming into
// the job log), remove files/dirs, kill processes, and thin wrappers around
// systemctl / nginx / wo. No shells are used (args are arrays), so interpolated
// domain values can never inject shell syntax.
// ============================================================

/**
 * Run a command to completion, streaming stdout/stderr into the job log.
 * Never uses a shell. Returns { code, stdout, stderr } and does NOT throw on
 * non-zero exit — callers decide what a failure means.
 *
 * @param {object} helpers  { log, err, onCancel }
 * @param {string} command
 * @param {string[]} args
 * @param {object} [opts]   { cwd, env, stdin, quiet, verbose, asUser }
 *   (default)   → silent while it succeeds; on failure the command line and the
 *                 tail of its output are logged, so a broken step stays
 *                 diagnosable without drowning the job log in normal output.
 *   verbose=true→ echo the command and stream every line live
 *   quiet=true  → never log, even on failure (probes/version checks)
 *   asUser      → run via `sudo -u <user> -H` (for wp-cli as www-data)
 */
export function run(helpers, command, args = [], opts = {}) {
  const { cwd, env = {}, stdin, quiet = false, verbose = false, asUser } = opts;
  const { log, err, onCancel } = helpers;

  let cmd = command;
  let cmdArgs = args;
  if (asUser) {
    cmd = 'sudo';
    cmdArgs = ['-u', asUser, '-H', command, ...args];
  }

  return new Promise((resolve, reject) => {
    if (verbose) log(`$ ${cmd} ${cmdArgs.join(' ')}`);
    // GIT_SSH_COMMAND for EVERY child: any git the agent spawns (clone, fetch,
    // pull, push — now or in ops written later) offers the agent's own key and
    // can never prompt. One choke point instead of an option at each call site.
    // Listed first so an operator can still override it via the service env.
    const child = spawn(cmd, cmdArgs, { cwd, env: { GIT_SSH_COMMAND: GIT_SSH_CMD, ...process.env, ...env }, shell: false });

    let stdout = '';
    let stderr = '';
    let killed = false;

    onCancel?.((reason) => {
      killed = true;
      err?.(`[cancel:${reason}] SIGTERM → pid ${child.pid}`);
      try { child.kill('SIGTERM'); } catch {}
      setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 5000).unref?.();
    });

    lineReader(child.stdout, (line) => { stdout += line + '\n'; if (verbose) log?.(line); });
    lineReader(child.stderr, (line) => { stderr += line + '\n'; if (verbose) err?.(line); });

    if (stdin != null) child.stdin.write(stdin);
    child.stdin.end();

    child.on('error', (e) => reject(new Error(`spawn failed for ${cmd}: ${e.message}`)));
    child.on('close', (code, signal) => {
      if (killed) return reject(new Error(`cancelled (signal ${signal || 'n/a'})`));
      const c = code ?? -1;
      // Failure is the only time the raw command + output are worth the noise.
      if (c !== 0 && !quiet && !verbose) {
        err?.(`$ ${cmd} ${cmdArgs.join(' ')}`);
        for (const line of tailLines(`${stdout}${stderr}`, 15)) err?.(`    ${line}`);
      }
      resolve({ code: c, stdout, stderr });
    });
  });
}

// Last n non-blank lines — enough context to diagnose, not a wall of text.
function tailLines(s, n) {
  const lines = String(s).split('\n').map((l) => l.trimEnd()).filter((l) => l.trim());
  return lines.slice(-n);
}

// Like run(), but throws if the command exits non-zero. Use for steps that must
// succeed (e.g. git clone, wo site create).
export async function runOrThrow(helpers, command, args = [], opts = {}) {
  const r = await run(helpers, command, args, opts);
  if (r.code !== 0) {
    throw new Error(`${command} exited ${r.code}${r.stderr ? `: ${r.stderr.trim().split('\n').slice(-1)[0]}` : ''}`);
  }
  return r;
}

function lineReader(stream, onLine) {
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      onLine(buf.slice(0, i).replace(/\r$/, ''));
      buf = buf.slice(i + 1);
    }
  });
  stream.on('end', () => { if (buf.length) onLine(buf.replace(/\r$/, '')); });
}

// --- filesystem -------------------------------------------------------------

export async function pathExists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

export async function removePath(p) {
  await fs.rm(p, { recursive: true, force: true });
}

export function existsSync(p) {
  return fssync.existsSync(p);
}

// --- process management -----------------------------------------------------

/**
 * Find PIDs whose full command line matches any of the given substrings.
 * Reads /proc directly (no pgrep dependency). Excludes our own PID.
 */
export async function findPidsMatching(patterns) {
  const self = String(process.pid);
  const pids = new Set();
  let entries;
  try { entries = await fs.readdir('/proc'); } catch { return []; }
  for (const name of entries) {
    if (!/^\d+$/.test(name) || name === self) continue;
    let cmdline;
    try {
      cmdline = await fs.readFile(`/proc/${name}/cmdline`, 'utf8');
    } catch { continue; }
    // cmdline args are NUL-separated
    const joined = cmdline.replace(/\0/g, ' ');
    if (patterns.some((p) => joined.includes(p))) pids.add(name);
  }
  return [...pids];
}

export function killPids(pids, signal = 'SIGTERM') {
  let n = 0;
  for (const pid of pids) {
    try { process.kill(Number(pid), signal); n += 1; } catch {}
  }
  return n;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- service wrappers -------------------------------------------------------

export async function systemctl(helpers, action, unit) {
  return run(helpers, 'systemctl', [action, unit]);
}

// nginx -t ; returns true if config is valid.
export async function nginxTest(helpers) {
  const r = await run(helpers, 'nginx', ['-t']);
  return r.code === 0;
}

export async function nginxReload(helpers) {
  return run(helpers, 'systemctl', ['reload', 'nginx']);
}

// wo site delete <domain> --no-prompt --force ; returns { ok, code }.
// --force removes the WordOps record even when files/DB are already gone (the
// agent deletes the site dir first, so paths won't exist by this point).
// --all is intentionally NOT used: these sites use a remote shared DB, so there
// is no local WordOps-owned DB to drop.
export async function woSiteDelete(helpers, domain) {
  const r = await run(helpers, 'wo', ['site', 'delete', domain, '--no-prompt', '--force'], { stdin: '' });
  return { ok: r.code === 0, code: r.code };
}

// True if the site is in WordOps' registry. Checks `wo site list` (the same
// source `wo site list` shows the user), NOT `wo site info` — info returns
// nonzero once a site's files/nginx config are gone, even while the registry
// row survives, which made delete skip the row and leave it un-deletable.
export async function woSiteExists(helpers, domain) {
  const sites = await woSiteList(helpers).catch(() => null);
  if (sites === null) return false; // couldn't read the registry — don't guess
  return sites.includes(domain);
}

// wo site list ; returns an array of domain strings (one per line).
// Filters out blank lines and any decorative/header lines wo might print.
export async function woSiteList(helpers) {
  const r = await run(helpers, 'wo', ['site', 'list'], { quiet: true });
  if (r.code !== 0) {
    throw new Error(`wo site list failed (code ${r.code})`);
  }
  return r.stdout
    .split('\n')
    // wo colorizes its output; strip ANSI so exact domain matching works.
    // eslint-disable-next-line no-control-regex
    .map((s) => s.replace(/\x1b\[[0-9;]*m/g, '').trim())
    // keep only plausible domain lines (contain a dot, no spaces)
    .filter((s) => s && !s.includes(' ') && s.includes('.'));
}

// --- git --------------------------------------------------------------------

// ssh for git, made safe for a daemon: BatchMode never prompts (a passphrase or
// unknown-host question would otherwise hang a job with no TTY), and a connect
// timeout bounds a dead network. Passed as `git -c core.sshCommand=…`.
// `-i ~/.ssh/id_ed25519` makes the agent ALWAYS offer the key bootstrap generated
// and the portal displays. Without it, a box whose ~/.ssh/config pins another
// key with `IdentitiesOnly yes` never presents this one, and GitHub answers
// "Permission denied" even though the right key was added. -i is additive (any
// configured identities are still tried) and a missing file is only a warning.
export const AGENT_SSH_KEY = `${os.homedir()}/.ssh/id_ed25519`;
export const GIT_SSH_CMD = `ssh -i ${AGENT_SSH_KEY} -o BatchMode=yes -o ConnectTimeout=15`;
export const GIT_SSH_ARGS = ['-c', `core.sshCommand=${GIT_SSH_CMD}`];

// A git-over-SSH failure as root has a handful of well-known causes, and git's
// own stderr is what tells them apart. It contains no secrets, so surface it
// with a concrete next step instead of a generic "check SSH access".
export function explainGitError(stderr, repo) {
  const s = String(stderr || '');
  const last = s.split('\n').map((l) => l.trim()).filter(Boolean).slice(-2).join(' | ') || 'no output from git';
  const tail = ` [git: ${last}]`;
  if (/Permission denied \(publickey\)/i.test(s)) {
    return `GitHub rejected this server's SSH key for ${repo}. Add root's public key (portal → server card → "SSH key", or /root/.ssh/id_ed25519.pub) to a GitHub ACCOUNT that can read the repo — Settings → SSH keys — then retry.${tail}`;
  }
  if (/Host key verification failed/i.test(s)) {
    return `github.com is not in root's known_hosts. On the server run: ssh-keyscan -t ed25519 github.com >> /root/.ssh/known_hosts${tail}`;
  }
  if (/Repository not found|does not appear to be a git repository/i.test(s)) {
    return `The SSH key authenticated, but that GitHub account cannot see ${repo} (no access to it, or the URL is wrong).${tail}`;
  }
  if (/Could not resolve hostname|Temporary failure in name resolution|Connection timed out|Network is unreachable|Connection refused/i.test(s)) {
    return `Network/DNS problem reaching github.com from this server.${tail}`;
  }
  return `git could not reach ${repo}.${tail}`;
}

// Run a git command in a repo (git -C <dir> ...). Returns { code, stdout }.
export function git(helpers, repoDir, args, opts = {}) {
  return run(helpers, 'git', ['-C', repoDir, ...args], opts);
}

// Short HEAD sha, or 'unknown'.
export async function gitShortHead(helpers, repoDir) {
  const r = await run(helpers, 'git', ['-C', repoDir, 'rev-parse', '--short', 'HEAD'], { quiet: true });
  return r.code === 0 ? r.stdout.trim() : 'unknown';
}

// Current branch name, or 'unknown'.
export async function gitCurrentBranch(helpers, repoDir) {
  const r = await run(helpers, 'git', ['-C', repoDir, 'rev-parse', '--abbrev-ref', 'HEAD'], { quiet: true });
  return r.code === 0 ? r.stdout.trim() : 'unknown';
}

// True if origin/<branch> resolves on the remote-tracking refs.
export async function gitRemoteBranchExists(helpers, repoDir, branch) {
  const r = await run(
    helpers, 'git',
    ['-C', repoDir, 'rev-parse', '--verify', '--quiet', `origin/${branch}`],
    { quiet: true }
  );
  return r.code === 0;
}

// --- ownership / wp-cli -----------------------------------------------------

// chown -R www-data:www-data <dir>
export async function chownWww(helpers, dir) {
  return run(helpers, 'chown', ['-R', 'www-data:www-data', dir]);
}

// Build a wp-cli runner bound to a site's app dir (SRC). All wp calls run as
// www-data with --path=web/wp, matching the scripts.
//   const wp = wpCli(helpers, SRC);
//   await wp(['option', 'get', 'home']);
export function wpCli(helpers, srcDir, opts = {}) {
  return (args, extra = {}) =>
    run(helpers, '/usr/bin/php', ['/usr/local/bin/wp', ...args, '--path=web/wp'], {
      cwd: srcDir,
      asUser: 'www-data',
      ...opts,
      ...extra,
    });
}

// Standard cache-clear routine used after code/DB changes:
//   - WP Rocket page cache (native fn via eval; disk fallback if provided)
//   - object cache flush
// webrootDir is optional; if given, the disk fallback wipes app/cache/wp-rocket.
export async function clearWpCaches(helpers, srcDir, webrootDir = null) {
  const wp = wpCli(helpers, srcDir);
  const rocket = await wp([
    'eval',
    'if (function_exists("rocket_clean_domain")) { rocket_clean_domain(); echo "WP Rocket cache cleared"; } else { echo "WP Rocket not active"; }',
  ]);
  if (rocket.code !== 0 && webrootDir) {
    const dir = `${webrootDir}/app/cache/wp-rocket`;
    if (await pathExists(dir)) {
      // wipe contents but keep the dir
      const fs = await import('node:fs/promises');
      try {
        for (const e of await fs.readdir(dir)) await removePath(`${dir}/${e}`);
      } catch {}
    }
  }
  const flush = await wp(['cache', 'flush'], { quiet: true });
  return { rocketOk: rocket.code === 0, objectFlushed: flush.code === 0 };
}