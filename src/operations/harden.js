import fs from 'node:fs/promises';
import path from 'node:path';
import config from '../config.js';
import { run, nginxTest, nginxReload, pathExists } from '../lib/sys.js';
import { allowlist, saveAllowlist, sshSources } from '../lib/proxies.js';
import { SSHD_DIR, F2B_DIR, sshRules } from './sshaccess.js';
import { cacheConf } from '../lib/site.js';
import { logger } from '../lib/log.js';
import { parseSshdT, parseUfw, parseListening, parseAccounts, listKeys, keyLoginSeen } from '../lib/security.js';

// ============================================================
//  harden — apply security fixes the audit recommends
// ============================================================
// { actions: [...] } — each one idempotent, run in a safe order:
//   trusted-proxies  the proxies in front of the sites: nginx trusts them for the
//                    visitor's real address, the firewall always lets them reach
//                    the web ports, and any ban on them is lifted
//   fail2ban       ban addresses after repeated failed SSH logins — the SSH jail ONLY
//   auto-updates   unattended-upgrades for Ubuntu security fixes
//   install-updates  install the waiting Ubuntu security updates now
//   all-updates    install EVERY waiting package update (nginx, database, PHP, … restart)
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
export const ACTIONS = ['trusted-proxies', 'fail2ban', 'auto-updates', 'install-updates', 'all-updates', 'firewall', 'ssh-basics', 'env-perms', 'ssh-keys-only'];
const APT_DIR = process.env.AGENT_APT_CONF_DIR || '/etc/apt/apt.conf.d';
const PASSWD = process.env.AGENT_PASSWD_FILE || '/etc/passwd';
const ENV_FILE = process.env.AGENT_ENV_FILE || path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', '.env');
const APT = ['-o', 'Dpkg::Options::=--force-confold', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Acquire::ForceIPv4=true', '-o', 'DPkg::Lock::Timeout=300', '-y', '-qq'];
const ENV = { DEBIAN_FRONTEND: 'noninteractive' };
const UPDATE_CHECK = process.env.AGENT_UPDATE_CHECK || '/usr/lib/update-notifier/apt-check'; // prints "<all>;<security>"
const REBOOT_FLAG = process.env.AGENT_REBOOT_FLAG || '/var/run/reboot-required';

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

// Jails that watch WEB traffic must never run here. These sites sit behind a
// proxy / Cloudflare, so every visitor and every bot reaches nginx from the
// proxy's address: a web jail counts all of the internet's bad requests against
// that one address and bans it — and `recidive` then bans it on every port for a
// week. That took a whole server offline (17 Nov 2026) when this fix simply
// started fail2ban and WordOps' preconfigured nginx jails came up with it.
// So: the SSH jail, and nothing else. `recidive` is switched off too — it turns
// repeated short bans into a week-long ban on ALL ports, which is not worth the risk.
// Never banned: this server, the tailnet, and the allowlist (the proxies all visitor
// traffic comes through). Its own file, so it holds whichever jails are running;
// wcp-allow.local is read with the other .local files, after every .conf.
async function writeIgnore() {
  await fs.mkdir(F2B_DIR, { recursive: true });
  await fs.writeFile(path.join(F2B_DIR, 'wcp-allow.local'), `# Managed by the WCP agent: addresses fail2ban must never ban (the panel's allowlist).\n[DEFAULT]\nignoreip = ${['127.0.0.1/8', '::1', '100.64.0.0/10', ...(await allowlist())].join(' ')}\n`);
}
const allowRule = (ip) => ['allow', 'from', ip];
const jailNames = (dump) => [...new Set([...String(dump).matchAll(/\['add',\s*'([^']+)'/g)].map((m) => m[1]))];
const jailList = (status) => (/Jail list:\s*(.*)$/m.exec(String(status))?.[1] || '').split(',').map((s) => s.trim()).filter(Boolean);

const steps = {
  async 'trusted-proxies'(helpers, { ok, info, warn }, removed = []) {
    const list = await allowlist();
    info(`always allowed: ${list.join(', ') || '(none)'}`);
    // 1) nginx: every site's custom-cache.conf is the shared template — rewrite it so the
    //    proxy list is current, test, reload; put every file back if nginx does not accept it.
    const body = await cacheConf();
    const changed = [];
    let dirs = [];
    try { dirs = await fs.readdir(config.wwwDir); } catch { /* no sites */ }
    for (const d of dirs) {
      const f = `${config.wwwDir}/${d}/conf/nginx/custom-cache.conf`;
      const cur = await fs.readFile(f, 'utf8').catch(() => null);
      if (cur === null || cur === body) continue;
      await fs.writeFile(f, body);
      changed.push([f, cur]);
    }
    if (changed.length) {
      if (!(await nginxTest(helpers))) {
        for (const [f, cur] of changed) await fs.writeFile(f, cur);
        throw new Error('nginx rejected the new proxy list — every file was put back, nothing changed');
      }
      await nginxReload(helpers);
    }
    ok(`nginx: ${changed.length} site(s) updated to trust these addresses for the visitor's real address`);
    // 2) firewall: name each one (rules are stored even while ufw is off), and drop the rules of addresses taken off the list
    if ((await run(helpers, 'ufw', ['status'], { quiet: true }).catch(() => ({ code: 127 }))).code !== 127) {
      for (const ip of list) await run(helpers, 'ufw', allowRule(ip), { quiet: true });
      for (const ip of removed) await run(helpers, 'ufw', ['delete', ...allowRule(ip)], { quiet: true });
      ok(`firewall: ${list.length} address(es) allowed by name${removed.length ? `, ${removed.length} removed` : ''}`);
    }
    // 3) fail2ban: never ban them, and lift any ban that exists right now
    await writeIgnore();
    if ((await run(helpers, 'systemctl', ['is-active', 'fail2ban'], { quiet: true })).stdout.trim() === 'active') {
      await run(helpers, 'fail2ban-client', ['reload'], { quiet: true });
      for (const ip of list) await run(helpers, 'fail2ban-client', ['unban', ip], { quiet: true });
      ok('fail2ban: these addresses can no longer be banned, and any ban on them was lifted');
      const jails = jailList((await run(helpers, 'fail2ban-client', ['status'], { quiet: true })).stdout).filter((j) => j !== 'sshd');
      if (jails.length) warn(`fail2ban is still watching web traffic (${jails.join(', ')}) — apply the fail2ban fix to leave only the SSH jail on`);
    }
  },

  async 'fail2ban'(helpers, { ok, info, warn }) {
    if (await aptInstall(helpers, 'fail2ban')) info('fail2ban installed');
    await fs.mkdir(F2B_DIR, { recursive: true });
    await fs.rm(path.join(F2B_DIR, 'wcp-sshd.conf'), { force: true }); // what an earlier version of this fix wrote
    const local = path.join(F2B_DIR, 'wcp.local'); // a .local in jail.d is read LAST, so it overrides every other file
    const port = (await sshd(helpers)).port || '22'; // bans apply to the port sshd is really on
    const write = (others) => fs.writeFile(local,
      '# Managed by the WCP agent (harden): SSH jail only. Delete this file to undo.\n'
      // backend=systemd: Ubuntu 24.04 has no /var/log/auth.log by default. The tailnet range is never banned.
      + `[sshd]\nenabled = true\nport = ${port}\n` + 'backend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n'
      + others.map((j) => `\n[${j}]\nenabled = false\n`).join(''));
    await writeIgnore();
    // Which jails would start? Read from the configuration WITHOUT starting anything (-d = dump).
    await write([]);
    const dump = await run(helpers, 'fail2ban-client', ['-d'], { quiet: true });
    if (dump.code !== 0) throw new Error(`fail2ban's configuration does not load, so it was not started: ${(dump.stderr || dump.stdout).trim().split('\n').pop()}`);
    const others = jailNames(dump.stdout).filter((j) => j !== 'sshd');
    await write(others);
    if (others.length) warn(`switched OFF: ${others.join(', ')} — jails that watch web traffic ban the proxy in front of the sites`);

    await run(helpers, 'systemctl', ['enable', 'fail2ban'], { quiet: true });
    const r = await run(helpers, 'systemctl', ['restart', 'fail2ban'], { quiet: true });
    if (r.code !== 0) throw new Error('fail2ban is installed but would not start — check: systemctl status fail2ban');
    // Prove it: anything but the SSH jail running means the override did not hold — stop rather than risk a ban.
    let running = [];
    for (let i = 0; i < 10 && !running.length; i++) {
      running = jailList((await run(helpers, 'fail2ban-client', ['status'], { quiet: true })).stdout);
      if (!running.length) await new Promise((res) => setTimeout(res, 500));
    }
    const extra = running.filter((j) => j !== 'sshd');
    if (extra.length || !running.includes('sshd')) {
      await run(helpers, 'systemctl', ['stop', 'fail2ban'], { quiet: true });
      await run(helpers, 'systemctl', ['disable', 'fail2ban'], { quiet: true });
      throw new Error(`fail2ban came up with ${running.join(', ') || 'no jails'} instead of the SSH jail alone, so it was stopped again. Nothing is banning anything.`);
    }
    await run(helpers, 'fail2ban-client', ['unban', '--all'], { quiet: true }); // bans left over from jails that are now off
    ok(`fail2ban is running with the SSH jail only: 5 failed SSH logins in 10 minutes = banned for 1 hour (port ${port})`);
  },

  async 'auto-updates'(helpers, { ok, info }) {
    if (await aptInstall(helpers, 'unattended-upgrades')) info('unattended-upgrades installed');
    await fs.mkdir(APT_DIR, { recursive: true });
    await fs.writeFile(path.join(APT_DIR, '20auto-upgrades'), 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n');
    await run(helpers, 'systemctl', ['enable', '--now', 'unattended-upgrades'], { quiet: true });
    ok('Ubuntu security updates now install automatically (daily)');
  },

  // The run unattended-upgrades does every night, done now: Ubuntu SECURITY updates only.
  async 'install-updates'(helpers, { ok, info, warn }) {
    if (await aptInstall(helpers, 'unattended-upgrades')) info('unattended-upgrades installed');
    await run(helpers, 'apt-get', [...APT, 'update'], { env: ENV, quiet: true });
    // ponytail: needrestart only LISTS here. Left to restart services on its own it can restart
    // this agent, and systemd then kills the upgrade halfway through. The services are named below instead.
    const r = await run(helpers, 'unattended-upgrade', ['-v'], { env: { ...ENV, NEEDRESTART_MODE: 'l' } });
    if (r.code !== 0) throw new Error('unattended-upgrade failed — see the output above');
    const left = /^\d+;(\d+)/.exec(await run(helpers, UPDATE_CHECK, [], { quiet: true }).then((c) => `${c.stderr}${c.stdout}`.trim(), () => ''))?.[1];
    if (Number(left) > 0) {
      // Ubuntu counts an update as "security" when ANY version newer than the installed one is in a
      // -security source, even if the version apt would install comes from somewhere else. Same rule here:
      // in `apt-cache policy`, the versions listed above the installed one (***) are the newer ones.
      const out = (cmd, args) => run(helpers, cmd, args, { quiet: true, env: ENV }).then((c) => c.stdout, () => '');
      const names = (await out('apt', ['list', '--upgradable'])).split('\n').map((l) => /^([^/\s]+)\//.exec(l)?.[1]).filter(Boolean);
      const waiting = names.length ? (await out('apt-cache', ['policy', ...names])).split(/^(?=\S+:$)/m).filter((blk) => /-security/.test(blk.split('***')[0])).map((blk) => blk.slice(0, blk.indexOf(':\n'))) : [];
      const held = (await out('apt-mark', ['showhold'])).split('\n').filter(Boolean);
      warn(`${left} security update(s) are still waiting${waiting.length ? `: ${waiting.join(', ')}` : ''}`);
      if (held.length) warn(`held back on purpose (apt-mark hold): ${held.join(', ')}`);
      info('The security-only run leaves these alone: the package is held, its config file was changed and it must ask, or the version apt would install comes from the regular updates or a third-party repository.');
      if (waiting.length) info(`to install by hand on the server: apt-get install --only-upgrade ${waiting.join(' ')}`);
    }
    else ok('no security updates are waiting');
    await afterUpgrade(helpers, { warn });
  },

  // Every waiting update, from every repository — the ones the security-only run never touches
  // (nginx, MariaDB, Redis, Node.js, Tailscale come from third-party repositories). New packages
  // may be installed (a new kernel), nothing is ever removed, and changed config files are kept.
  async 'all-updates'(helpers, { ok, info, warn }) {
    const before = await running(helpers);
    const upd = await run(helpers, 'apt-get', [...APT, 'update'], { env: ENV });
    if (upd.code !== 0) throw new Error('apt-get update failed (a repository is unreachable or broken) — nothing was installed');
    const r = await run(helpers, 'apt-get', [...APT, 'upgrade', '--with-new-pkgs'], { env: { ...ENV, NEEDRESTART_MODE: 'l' } });
    // Whatever apt said: nothing the sites need may be left down. Start what stopped, then look again.
    const stopped = async () => { const now = await running(helpers); return before.filter((u) => !now.includes(u)); };
    for (const u of await stopped()) { warn(`${u} was running before and is not now — starting it`); await run(helpers, 'systemctl', ['start', u], { quiet: true }); }
    const down = await stopped();
    if (down.length) throw new Error(`${down.join(', ')} did not come back after the update — on the server: systemctl status ${down[0]}`);
    if (r.code !== 0) throw new Error('apt-get upgrade failed — see the output above. The services that were running are still running.');
    const left = /^(\d+);/.exec(await run(helpers, UPDATE_CHECK, [], { quiet: true }).then((c) => `${c.stderr}${c.stdout}`.trim(), () => ''))?.[1];
    if (Number(left) > 0) info(`${left} update(s) are still waiting: apt keeps those back (a phased roll-out, or they would remove another package)`);
    ok(`updates installed; still running: ${before.join(', ') || 'none of the watched services were running'}`);
    await afterUpgrade(helpers, { warn });
  },

  async 'firewall'(helpers, L) { await enableFirewall(helpers, L); },
};

// Services the sites and the panel need: checked before and after a full update.
const WATCHED = /^(nginx|mysql|mariadb|php[\d.]*-fpm|redis-server|tailscaled)\.service$/;
const running = async (helpers) => (await run(helpers, 'systemctl', ['list-units', '--type=service', '--state=running', '--no-legend', '--plain'], { quiet: true })).stdout
  .split('\n').map((l) => l.trim().split(/\s+/)[0]).filter((u) => WATCHED.test(u));

/** After packages changed: which services still run the old code, and whether a reboot is needed. */
async function afterUpgrade(helpers, { warn }) {
  const stale = await run(helpers, 'needrestart', ['-b', '-r', 'l'], { quiet: true }).then((c) => [...c.stdout.matchAll(/^NEEDRESTART-SVC: (\S+)/gm)].map((m) => m[1]), () => []);
  if (stale.length) warn(`still running the old code until restarted: ${stale.join(', ')}`);
  if (await pathExists(REBOOT_FLAG)) warn('a reboot is needed to finish (kernel or core library) — restart the server when traffic is low');
}

/** ufw on, with SSH, web, Tailscale and the agent (tailnet only) allowed first. Shared with the firewall operation. */
export async function enableFirewall(helpers, { ok, info, warn }) {
  {
    if (await aptInstall(helpers, 'ufw')) info('ufw installed');
    const sshPort = (await sshd(helpers)).port || '22';
    const was = parseUfw((await run(helpers, 'ufw', ['status'], { quiet: true })).stdout);
    // SSH first, always — so turning the firewall on can never cut the session.
    const from = await sshSources(); // SSH stays limited to these if the operator limited it
    const rules = [...sshRules(sshPort, from), ['80/tcp'], ['443/tcp'], ['41641/udp'], ['in', 'on', 'tailscale0', 'to', 'any', 'port', String(config.port), 'proto', 'tcp'],
      ...(await allowlist()).map((ip) => allowRule(ip).slice(1))]; // the allowlist by name, so it stays allowed if the public rules are ever narrowed
    for (const rule of rules) {
      const r = await run(helpers, 'ufw', ['allow', ...rule], { quiet: true });
      if (r.code !== 0) throw new Error(`ufw allow ${rule.join(' ')} failed — the firewall was not turned on`);
    }
    info(`allowed: SSH ${sshPort}${from.length ? ` (from ${from.join(', ')} and the tailnet only)` : ''}, web 80/443, Tailscale 41641/udp, agent ${config.port} on the tailnet only`);
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
  // The panel sends its allowlist with every hardening action: store it first, so
  // whatever runs next (fail2ban, firewall, …) already uses the current list.
  let removed = [];
  if (p.allowlist) ({ removed } = await saveAllowlist(p.allowlist));
  for (const a of ACTIONS.filter((x) => p.actions.includes(x))) {
    L.step(a);
    await steps[a](helpers, L, removed);
  }
  console.log(`[security] hardened: ${p.actions.join(', ')}`);
}
