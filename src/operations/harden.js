import fs from 'node:fs/promises';
import path from 'node:path';
import config from '../config.js';
import { run } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { parseSshdT, parseUfw, parseListening, parseAccounts, listKeys, keyLoginSeen } from '../lib/security.js';

// ============================================================
//  harden — apply security fixes the audit recommends
// ============================================================
// { actions: [...] } — each one idempotent, run in a safe order:
//   fail2ban       ban addresses after repeated failed SSH logins
//   auto-updates   unattended-upgrades for Ubuntu security fixes
//   firewall       ufw on, with SSH, web and the agent (tailnet only) allowed
//   ssh-basics     MaxAuthTries 3, LoginGraceTime 30, no X11, no empty passwords
//   env-perms      site .env files + the agent .env not readable by other users
//   ssh-keys-only  turn SSH password login OFF
//
// ssh-keys-only is the one that can lock an operator out, so it REFUSES unless
// root has a key installed AND the SSH log shows a successful key login for
// root (proof that the key works from where the operator sits). Every sshd
// change is a drop-in that is syntax-checked (`sshd -t`), read back
// (`sshd -T`) and removed again if it did not take — and ssh is reloaded, not
// restarted, so sessions that are open stay open.
// ============================================================
export const ACTIONS = ['fail2ban', 'auto-updates', 'firewall', 'ssh-basics', 'env-perms', 'ssh-keys-only'];
const SSHD_DIR = process.env.AGENT_SSHD_DROPIN_DIR || '/etc/ssh/sshd_config.d';
const F2B_DIR = process.env.AGENT_F2B_JAIL_DIR || '/etc/fail2ban/jail.d';
const APT_DIR = process.env.AGENT_APT_CONF_DIR || '/etc/apt/apt.conf.d';
const PASSWD = process.env.AGENT_PASSWD_FILE || '/etc/passwd';
const ENV_FILE = process.env.AGENT_ENV_FILE || path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', '.env');
const APT = ['-o', 'Dpkg::Options::=--force-confold', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Acquire::ForceIPv4=true', '-o', 'DPkg::Lock::Timeout=300', '-y', '-qq'];
const ENV = { DEBIAN_FRONTEND: 'noninteractive' };

const sshd = async (helpers) => parseSshdT((await run(helpers, 'sshd', ['-T'], { quiet: true })).stdout);

async function aptInstall(helpers, pkg) {
  if ((await run(helpers, 'dpkg', ['-s', pkg], { quiet: true })).code === 0) return false;
  await run(helpers, 'apt-get', [...APT, 'update'], { env: ENV, quiet: true });
  const r = await run(helpers, 'apt-get', [...APT, 'install', pkg], { env: ENV });
  if (r.code !== 0) throw new Error(`apt-get install ${pkg} failed — see the output above`);
  return true;
}

/** Write an sshd drop-in, prove it parses and took effect, reload ssh. Rolls back on any failure. */
async function sshdDropin(helpers, name, body, expect) {
  const file = path.join(SSHD_DIR, name);
  const before = await fs.readFile(file, 'utf8').catch(() => null);
  const undo = async () => { if (before === null) await fs.rm(file, { force: true }); else await fs.writeFile(file, before); };
  await fs.mkdir(SSHD_DIR, { recursive: true });
  // 00- sorts first, and sshd keeps the FIRST value it reads — so this wins over
  // cloud-init's 50-cloud-init.conf (which sets PasswordAuthentication yes).
  await fs.writeFile(file, `# Managed by the WCP agent (harden). Remove this file to undo.\n${body}\n`, { mode: 0o644 });
  const t = await run(helpers, 'sshd', ['-t'], { quiet: true });
  if (t.code !== 0) { await undo(); throw new Error(`sshd rejected the new settings, nothing changed: ${(t.stderr || t.stdout).trim().split('\n').pop()}`); }
  const now = await sshd(helpers);
  const wrong = Object.entries(expect).filter(([k, v]) => String(now[k]) !== String(v));
  if (wrong.length) { await undo(); throw new Error(`the settings did not take effect (${wrong.map(([k]) => k).join(', ')} is overridden elsewhere in sshd_config) — nothing changed`); }
  let r = await run(helpers, 'systemctl', ['reload', 'ssh'], { quiet: true });
  if (r.code !== 0) r = await run(helpers, 'systemctl', ['reload-or-restart', 'sshd'], { quiet: true });
  if (r.code !== 0) throw new Error('settings written and valid, but ssh could not be reloaded — run: systemctl reload ssh');
  return file;
}

const steps = {
  async 'fail2ban'(helpers, { ok, info }) {
    if (await aptInstall(helpers, 'fail2ban')) info('fail2ban installed');
    await fs.mkdir(F2B_DIR, { recursive: true });
    // backend=systemd: Ubuntu 24.04 has no /var/log/auth.log by default. The tailnet range is never banned.
    await fs.writeFile(path.join(F2B_DIR, 'wcp-sshd.conf'), '# Managed by the WCP agent (harden).\n[sshd]\nenabled = true\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\nignoreip = 127.0.0.1/8 ::1 100.64.0.0/10\n');
    const r = await run(helpers, 'systemctl', ['enable', '--now', 'fail2ban'], { quiet: true });
    const r2 = await run(helpers, 'systemctl', ['restart', 'fail2ban'], { quiet: true });
    if (r.code !== 0 || r2.code !== 0) throw new Error('fail2ban is installed but would not start — check: systemctl status fail2ban');
    ok('fail2ban is running: 5 failed SSH logins in 10 minutes = banned for 1 hour');
  },

  async 'auto-updates'(helpers, { ok, info }) {
    if (await aptInstall(helpers, 'unattended-upgrades')) info('unattended-upgrades installed');
    await fs.mkdir(APT_DIR, { recursive: true });
    await fs.writeFile(path.join(APT_DIR, '20auto-upgrades'), 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n');
    await run(helpers, 'systemctl', ['enable', '--now', 'unattended-upgrades'], { quiet: true });
    ok('Ubuntu security updates now install automatically (daily)');
  },

  async 'firewall'(helpers, L) { await enableFirewall(helpers, L); },
};

/** ufw on, with SSH, web, Tailscale and the agent (tailnet only) allowed first. Shared with the firewall operation. */
export async function enableFirewall(helpers, { ok, info, warn }) {
  {
    if (await aptInstall(helpers, 'ufw')) info('ufw installed');
    const sshPort = (await sshd(helpers)).port || '22';
    const was = parseUfw((await run(helpers, 'ufw', ['status'], { quiet: true })).stdout);
    // SSH first, always — so turning the firewall on can never cut the session.
    const rules = [[`${sshPort}/tcp`], ['80/tcp'], ['443/tcp'], ['41641/udp'], ['in', 'on', 'tailscale0', 'to', 'any', 'port', String(config.port), 'proto', 'tcp']];
    for (const rule of rules) {
      const r = await run(helpers, 'ufw', ['allow', ...rule], { quiet: true });
      if (r.code !== 0) throw new Error(`ufw allow ${rule.join(' ')} failed — the firewall was not turned on`);
    }
    info(`allowed: SSH ${sshPort}, web 80/443, Tailscale 41641/udp, agent ${config.port} on the tailnet only`);
    if (!was.active) {
      const allowed = new Set([Number(sshPort), 80, 443]);
      const cut = parseListening((await run(helpers, 'ss', ['-tlnpH'], { quiet: true })).stdout).filter((l) => (l.scope === 'all' || l.scope === 'public') && !allowed.has(l.port));
      if (cut.length) warn(`these ports listen publicly and will now be BLOCKED from the internet: ${cut.map((l) => `${l.port} (${l.proc || '?'})`).join(', ')} — allow one with: ufw allow <port>/tcp`);
      const en = await run(helpers, 'ufw', ['--force', 'enable'], { quiet: true });
      if (en.code !== 0) throw new Error('ufw enable failed');
    }
    ok(was.active ? 'firewall was already on; rules checked' : 'firewall is ON');
  }
}

Object.assign(steps, {

  async 'ssh-basics'(helpers, { ok }) {
    const f = await sshdDropin(helpers, '00-wcp-basics.conf', 'MaxAuthTries 3\nLoginGraceTime 30\nX11Forwarding no\nPermitEmptyPasswords no',
      { maxauthtries: 3, logingracetime: 30, x11forwarding: 'no', permitemptypasswords: 'no' });
    ok(`SSH limits tightened (${f})`);
  },

  async 'env-perms'(helpers, { ok }) {
    let n = 0, dirs = [];
    try { dirs = await fs.readdir(config.wwwDir); } catch { /* no sites */ }
    for (const d of dirs) {
      const f = `${config.wwwDir}/${d}/htdocs/src/.env`;
      try { const m = (await fs.stat(f)).mode & 0o777; if (m & 0o007) { await fs.chmod(f, m & ~0o007); n++; } } catch { /* not a deployed site */ }
    }
    try { if (((await fs.stat(ENV_FILE)).mode & 0o777) !== 0o600) { await fs.chmod(ENV_FILE, 0o600); n++; } } catch { /* not installed the usual way */ }
    ok(`${n} .env file(s) closed to other users (the web user still reads its own)`);
  },

  async 'ssh-keys-only'(helpers, { ok, info }) {
    const root = parseAccounts(await fs.readFile(PASSWD, 'utf8')).find((u) => u.name === 'root');
    const keys = root ? await listKeys(root.home) : [];
    if (!keys.length) throw new Error('refused: root has no SSH key installed. Add your public key (Security → SSH access), log in with it once, then retry. Nothing changed.');
    if (!(await keyLoginSeen('root'))) throw new Error('refused: no successful KEY login for root is in the SSH log yet. Open a new SSH session using your key (not the password) to prove it works, then retry. Nothing changed.');
    info(`root has ${keys.length} key(s) and a key login has succeeded`);
    const f = await sshdDropin(helpers, '00-wcp-keys-only.conf', 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes',
      { passwordauthentication: 'no', kbdinteractiveauthentication: 'no', pubkeyauthentication: 'yes' });
    ok(`SSH password login is OFF — keys only (${f}). Sessions that are open stay open: test a NEW login before closing yours.`);
  },
});

export async function runHarden(job, helpers, p) {
  const L = logger(helpers);
  for (const a of ACTIONS.filter((x) => p.actions.includes(x))) {
    L.step(a);
    await steps[a](helpers, L);
  }
  console.log(`[security] hardened: ${p.actions.join(', ')}`);
}
