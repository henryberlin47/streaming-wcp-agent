import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { run, explainGitError, GIT_SSH_CMD, GIT_SSH_ARGS } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { APP_REPO_DEFAULT, MAP_REPO } from '../lib/siteConfig.js';

// ============================================================
//  sshcheck — can this server (as root) read the private repos?
// ============================================================
// Authorising root's SSH key on GitHub is the one manual step of provisioning,
// and until it's done every deploy fails at "clone seo-domain-map". This
// answers it in one click: which key, who GitHub thinks we are, and whether
// each repo a deploy needs is readable — with the fix for whatever is wrong.
// Read-only: `ssh -T` and `git ls-remote`, nothing is cloned or written.
// ============================================================
export async function runSshCheck(job, helpers) {
  const { log, step, info, ok, warn, err } = logger(helpers);

  step("Root's SSH public key");
  const pubFile = path.join(os.homedir(), '.ssh', 'id_ed25519.pub');
  try {
    info((await fs.readFile(pubFile, 'utf8')).trim());
  } catch {
    warn(`${pubFile} not found — generate one: ssh-keygen -t ed25519 -N '' -f ${pubFile.replace(/\.pub$/, '')}`);
  }

  step('Authenticate to GitHub');
  // GitHub greets and closes the session, so SUCCESS here is exit code 1 with
  // "Hi <account>!" — judge by the greeting, not the exit code.
  const t = await run(helpers, 'ssh', ['-T', ...GIT_SSH_CMD.split(' ').slice(1), 'git@github.com'], { quiet: true });
  const who = /Hi ([^!]+)!/.exec(`${t.stdout}${t.stderr}`);
  if (who) ok(`authenticated as ${who[1]}`);
  else err(explainGitError(t.stderr, 'github.com'));

  step('Read access to the repos a deploy needs');
  let unreadable = 0;
  for (const repo of [MAP_REPO, APP_REPO_DEFAULT]) {
    const r = await run(helpers, 'git', [...GIT_SSH_ARGS, 'ls-remote', '--heads', repo], { quiet: true });
    if (r.code === 0) ok(repo);
    else { unreadable++; err(`${repo} — ${explainGitError(r.stderr, repo)}`); }
  }

  if (!who || unreadable) {
    throw new Error(
      !who
        ? "GitHub does not recognise this server's SSH key — add it to a GitHub account that can read both repos (Settings → SSH keys)"
        : `${unreadable} repo(s) unreadable — see above`
    );
  }
  log('GitHub access OK — deploys can clone both repos');
}
