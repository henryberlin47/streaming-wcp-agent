import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import config from '../config.js';
import { run } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { parseUfw, parseListening, ruleAllows } from '../lib/security.js';
import { validAddress, allowlist, sshSources, saveSshSources } from '../lib/proxies.js';

// ============================================================
//  sshaccess — the SSH port, and who may reach it
// ============================================================
//   { port?, sources? }   port: the port sshd listens on
//                         sources: addresses/networks that may reach it; [] = anyone
//
// The order is what keeps the operator from being locked out:
//   1. the firewall is opened for the NEW settings first;
//   2. sshd is moved (a drop-in, syntax-checked and read back), and the agent
//      then connects to the new port itself and waits for sshd's greeting —
//      no greeting, and the drop-in is taken out again and sshd put back;
//   3. only then are the rules for the OLD settings removed.
// A failure anywhere before step 3 leaves the old way in untouched.
// Who may connect is enforced by the firewall, so it needs the firewall ON.
// The tailnet is always allowed, and the panel reaches this agent over the
// tailnet, not over SSH: a wrong setting can be put right from the panel.
// ============================================================
export const SSHD_DIR = process.env.AGENT_SSHD_DROPIN_DIR || '/etc/ssh/sshd_config.d';
export const F2B_DIR = process.env.AGENT_F2B_JAIL_DIR || '/etc/fail2ban/jail.d';
const DROPIN = '00-wcp-port.conf';
const NOT_SSH = new Set([80, 443, 3306]);

const q = (helpers, cmd, args) => run(helpers, cmd, args, { quiet: true });
const sshdPorts = async (helpers) => [...(await q(helpers, 'sshd', ['-T'])).stdout.matchAll(/^port\s+(\d+)\s*$/gim)].map((m) => Number(m[1]));

const fromRule = (ip, port) => ['from', ip, 'to', 'any', 'port', String(port), 'proto', 'tcp'];
/** The ufw rules (what follows `allow`) that let SSH in on `port`: anyone, or only `sources` and the tailnet. */
export const sshRules = (port, sources) => (sources.length
  ? [...sources.map((ip) => fromRule(ip, port)), ['in', 'on', 'tailscale0', 'to', 'any', 'port', String(port), 'proto', 'tcp']]
  : [[`${port}/tcp`]]);

export function validateSshAccess(p = {}) {
  const errors = [], clean = {};
  if (p.port !== undefined) {
    const port = Number(p.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push('port must be 1-65535');
    else if (NOT_SSH.has(port) || port === config.port) errors.push(`port ${port} is used by ${port === config.port ? 'this agent' : 'the web server or the database'}`);
    else clean.port = port;
  }
  if (p.sources !== undefined) {
    const raw = Array.isArray(p.sources) ? p.sources : [null];
    const wrong = raw.filter((x) => !validAddress(x));
    if (wrong.length || raw.length > 50) errors.push(`sources must be up to 50 IP addresses or networks${wrong.length ? ` (not valid: ${wrong.map(String).slice(0, 3).join(', ')})` : ''}`);
    else clean.sources = [...new Set(raw.map(validAddress))];
  }
  if (p.port === undefined && p.sources === undefined) errors.push('give a port, sources, or both');
  return { ok: errors.length === 0, errors, clean };
}

/** Does sshd greet a connection on this port? Asked from this machine, so it proves sshd — not the path from outside. */
const greets = (port) => new Promise((resolve) => {
  const s = net.connect({ port, host: '127.0.0.1' });
  const done = (v) => { s.destroy(); resolve(v); };
  s.setTimeout(3000, () => done(false));
  s.on('error', () => done(false));
  s.on('data', (d) => done(/^SSH-/.test(String(d))));
});
const waitGreeting = async (port) => {
  for (let i = 0; i < 6; i++) { if (await greets(port)) return true; await new Promise((r) => setTimeout(r, 1000)); }
  return false;
};

/** Make sshd pick up a changed port. Ubuntu 24.04 starts ssh from a socket unit that is generated from sshd's config. */
async function applyPort(helpers) {
  if ((await q(helpers, 'systemctl', ['is-active', 'ssh.socket'])).stdout.trim() === 'active') {
    await q(helpers, 'systemctl', ['daemon-reload']);
    return (await q(helpers, 'systemctl', ['restart', 'ssh.socket'])).code === 0;
  }
  if ((await q(helpers, 'systemctl', ['reload', 'ssh'])).code === 0) return true;
  return (await q(helpers, 'systemctl', ['reload-or-restart', 'sshd'])).code === 0;
}

export async function runSshAccess(job, helpers, p) {
  const { step, ok, info, warn } = logger(helpers);
  const ports = await sshdPorts(helpers);
  if (!ports.length) throw new Error('could not read sshd\'s settings (sshd -T) — nothing changed');
  const port = p.port ?? ports[0];
  const before = await sshSources();
  const sources = p.sources ?? before;
  const moving = ports.length !== 1 || ports[0] !== port;

  const st = await q(helpers, 'ufw', ['status']).catch(() => null); // null = ufw is not installed
  const fwOn = !!st && parseUfw(st.stdout).active;
  if (sources.length && !fwOn) throw new Error('limiting who can reach SSH is done by the firewall, and the firewall is off — turn it on first (Firewall tab), then apply this again. Nothing changed.');
  const ufw = async (verb, rule) => (st ? (await q(helpers, 'ufw', [...verb, ...rule])).code === 0 : true);

  if (moving) {
    const taken = parseListening((await q(helpers, 'ss', ['-tlnpH'])).stdout).find((l) => l.port === port && !ports.includes(port));
    if (taken) throw new Error(`port ${port} is already used by ${taken.proc || 'another program'} — nothing changed`);
  }

  step(`Firewall: let SSH in on port ${port} from ${sources.length ? `${sources.join(', ')} and the tailnet` : 'anywhere'}`);
  const wanted = sshRules(port, sources);
  for (const rule of wanted) if (!(await ufw(['allow'], rule))) throw new Error(`ufw allow ${rule.join(' ')} failed — nothing else was changed`);
  ok(st ? `${wanted.length} rule(s) in place${fwOn ? '' : ' (the firewall is off: they apply when it is turned on)'}` : 'no firewall installed — nothing to open');

  if (moving) {
    step(`Move sshd from port ${ports.join(', ')} to ${port}`);
    const file = path.join(SSHD_DIR, DROPIN);
    const was = await fs.readFile(file, 'utf8').catch(() => null);
    const undo = async () => {
      if (was === null) await fs.rm(file, { force: true }); else await fs.writeFile(file, was);
      await applyPort(helpers);
      if (!ports.includes(port)) for (const rule of wanted) await ufw(['delete', 'allow'], rule); // the opening made for a port sshd is not on
    };
    await fs.mkdir(SSHD_DIR, { recursive: true });
    await fs.writeFile(file, `# Managed by the WCP agent (sshaccess). Remove this file to go back to the default port.\nPort ${port}\n`, { mode: 0o644 });
    const t = await q(helpers, 'sshd', ['-t']);
    if (t.code !== 0) { await undo(); throw new Error(`sshd rejected the new port, nothing changed: ${(t.stderr || t.stdout).trim().split('\n').pop()}`); }
    const now = await sshdPorts(helpers);
    if (now.length !== 1 || now[0] !== port) {
      await undo();
      throw new Error(`sshd would listen on ${now.join(' and ') || 'nothing'} instead of ${port} alone — /etc/ssh/sshd_config (or another file in sshd_config.d) sets Port itself. Remove that line on the server, then apply again. Nothing changed.`);
    }
    if (!(await applyPort(helpers)) || !(await waitGreeting(port))) {
      await undo();
      throw new Error(`sshd did not answer on port ${port}, so it was put back: SSH is still on port ${ports.join(', ')}`);
    }
    ok(`sshd answers on port ${port}`);
  }

  // Only now: take away what the old settings allowed. By specification, never by guessing from the list.
  step('Firewall: close what is no longer wanted');
  const generic = (n) => [[`${n}/tcp`], [String(n)], ...(n === 22 ? [['OpenSSH']] : [])];
  const stale = [];
  for (const old of ports.filter((n) => n !== port)) stale.push(...generic(old), ...(before.length ? sshRules(old, before) : []));
  if (sources.length) stale.push(...generic(port), ...before.filter((ip) => !sources.includes(ip)).map((ip) => fromRule(ip, port))); // the "anyone" rule, and addresses taken off the list
  else if (before.length) stale.push(...sshRules(port, before)); // open to anyone again: the per-address rules are not needed
  for (const rule of stale) await ufw(['delete', 'allow'], rule);
  await saveSshSources(sources);
  let leak = false;
  if (fwOn && sources.length) {
    const open = parseUfw((await q(helpers, 'ufw', ['status'])).stdout).rules.filter((r) => /^Anywhere/.test(r.from) && !/ on \S+/.test(r.to) && ruleAllows(r, port));
    leak = open.length > 0;
    if (leak) warn(`SSH is STILL open to everyone through: ${open.map((r) => r.raw.replace(/\s+/g, ' ')).join(' | ')} — remove that rule in the Firewall tab`);
    const always = await allowlist();
    if (always.length) info(`the ${always.length} always-allowed address(es) reach every port, SSH included`);
  }
  ok('old openings removed');

  // fail2ban bans on the port its SSH jail names: keep it pointing at the real one.
  const jail = path.join(F2B_DIR, 'wcp.local');
  const conf = await fs.readFile(jail, 'utf8').catch(() => null);
  if (moving && conf) {
    await fs.writeFile(jail, conf.replace(/(\[sshd\]\nenabled = true\n)(port = \d+\n)?/, `$1port = ${port}\n`));
    if ((await q(helpers, 'systemctl', ['is-active', 'fail2ban'])).stdout.trim() === 'active') await q(helpers, 'fail2ban-client', ['reload']);
    info(`fail2ban now guards port ${port}`);
  }

  ok(`SSH: port ${port}, ${leak ? 'still open to everyone — see the warning above' : `reachable from ${sources.length ? `${sources.join(', ')} and the tailnet only` : 'anywhere'}`}`);
  warn(`keep the SSH session you have open, and test a NEW one now: ssh -p ${port} root@<this server>. If it does not get in, change the setting back from the panel.`);
  if (moving) info('sshd answering here does not prove the port is reachable from outside: a firewall at your hosting provider must allow it too');
  console.log(`[security] ssh access: port ${port}, sources ${sources.join(',') || 'any'}`);
}
