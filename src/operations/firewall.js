import net from 'node:net';
import config from '../config.js';
import { run } from '../lib/sys.js';
import { logger } from '../lib/log.js';
import { parseUfw, parseSshdT, ruleAllows } from '../lib/security.js';
import { enableFirewall } from './harden.js';

// ============================================================
//  firewall — manage ufw from the panel
// ============================================================
//   allow   { port, proto?, from?, tailnet? }  open a port: to everyone, to one
//                                              address/network, or on the tailnet only
//   delete  { number, raw }                    remove one rule (as numbered by ufw)
//   enable                                     switch ufw on (SSH, web, Tailscale and
//                                              the agent on the tailnet are allowed first)
//   disable                                    switch ufw off
//
// Two mistakes would cost the operator the server, so they are refused:
//   - removing the last rule that lets SSH in (while the firewall is on);
//   - removing the last rule that lets the portal reach this agent.
// And one would expose it: opening the agent's own port to the internet.
// `delete` takes the rule's text as well as its number: numbers shift when
// another rule is removed, so a stale number must never delete the wrong rule.
// ============================================================
const Q = { log() {}, err() {}, onCancel() {} };
const ufw = (helpers, args) => run(helpers, 'ufw', args, { quiet: true });
const numbered = async (helpers = Q) => parseUfw((await ufw(helpers, ['status', 'numbered'])).stdout);
const sshPort = async (helpers = Q) => Number(parseSshdT((await run(helpers, 'sshd', ['-T'], { quiet: true })).stdout).port || 22);

const PORT = /^(\d{1,5})(?::(\d{1,5}))?$/;
const portRange = (s) => {
  const m = PORT.exec(String(s ?? ''));
  if (!m) return null;
  const lo = Number(m[1]), hi = m[2] ? Number(m[2]) : lo;
  return lo >= 1 && hi <= 65535 && lo <= hi ? [lo, hi] : null;
};
/** "1.2.3.4", "10.0.0.0/8", "2001:db8::/32" -> normalized string, or null */
const source = (s) => {
  const [addr, bits, extra] = String(s).split('/');
  const v = net.isIP(addr);
  if (!v || extra !== undefined) return null;
  if (bits === undefined) return addr;
  return /^\d{1,3}$/.test(bits) && Number(bits) <= (v === 4 ? 32 : 128) ? `${addr}/${Number(bits)}` : null;
};

export function validateFirewall(p = {}) {
  const errors = [];
  const action = String(p.action || '');
  let clean = { action };
  if (action === 'allow') {
    const range = portRange(p.port);
    const proto = p.proto === 'udp' ? 'udp' : 'tcp';
    const from = p.from ? source(p.from) : '';
    if (!range) errors.push('port must be 1-65535, or a range like 8000:8100');
    if (p.proto && !['tcp', 'udp'].includes(p.proto)) errors.push('proto must be tcp or udp');
    if (p.from && !from) errors.push('from must be an IP address or a network like 203.0.113.0/24');
    if (from && p.tailnet) errors.push('choose either an address or the tailnet, not both');
    clean = { action, port: String(p.port ?? ''), proto, from: from || '', tailnet: !!p.tailnet };
  } else if (action === 'delete') {
    if (!Number.isInteger(p.number) || p.number < 1) errors.push('number must be the rule number from the list');
    if (typeof p.raw !== 'string' || !p.raw.trim() || p.raw.length > 300) errors.push('raw must be the rule text from the list');
    clean = { action, number: p.number, raw: String(p.raw || '').trim() };
  } else if (!['enable', 'disable'].includes(action)) {
    errors.push('action must be one of: allow, delete, enable, disable');
  }
  return { ok: errors.length === 0, errors, clean };
}

/** What the panel shows: status, numbered rules, and (while off) the rules waiting to apply. */
export async function firewallStatus() {
  let st;
  try { st = await ufw(Q, ['status', 'numbered']); } catch { return { installed: false, active: false, rules: [], staged: [] }; }
  const parsed = parseUfw(st.stdout);
  // an inactive ufw lists nothing; its stored rules are shown as the commands that made them
  const staged = parsed.active ? [] : (await ufw(Q, ['show', 'added'])).stdout.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('ufw '));
  return { installed: true, active: parsed.active, rules: parsed.rules, staged, ssh_port: await sshPort(), agent_port: config.port };
}

export async function runFirewall(job, helpers, p) {
  const L = logger(helpers);
  const { step, ok, info } = L;

  if (p.action === 'enable') { step('Turn the firewall on'); await enableFirewall(helpers, L); console.log('[security] firewall: enabled'); return; }

  if (p.action === 'disable') {
    step('Turn the firewall off');
    const r = await ufw(helpers, ['disable']);
    if (r.code !== 0) throw new Error(`ufw disable failed: ${(r.stderr || r.stdout).trim().split('\n').pop()}`);
    ok('firewall is OFF — every listening port is reachable from the internet');
    console.log('[security] firewall: disabled');
    return;
  }

  if (p.action === 'allow') {
    const [lo, hi] = portRange(p.port);
    const what = `${p.port}/${p.proto}${p.tailnet ? ' on the tailnet only' : p.from ? ` from ${p.from}` : ' from anywhere'}`;
    step(`Allow ${what}`);
    if (!p.from && !p.tailnet && p.proto === 'tcp' && config.port >= lo && config.port <= hi) {
      throw new Error(`refused: ${config.port} is this agent's own port. It runs as root and must never be open to the internet — allow it on the tailnet or from the portal's address only.`);
    }
    const args = p.tailnet ? ['allow', 'in', 'on', 'tailscale0', 'to', 'any', 'port', p.port, 'proto', p.proto]
      : p.from ? ['allow', 'from', p.from, 'to', 'any', 'port', p.port, 'proto', p.proto]
        : ['allow', `${p.port}/${p.proto}`];
    const r = await ufw(helpers, args);
    if (r.code !== 0) throw new Error(`ufw refused the rule: ${(r.stderr || r.stdout).trim().split('\n').pop()}`);
    ok((r.stdout.trim().split('\n').pop() || 'rule added').replace(/\s+/g, ' '));
    if (!(await numbered(helpers)).active) info('the firewall is OFF: the rule is stored and applies when you turn it on');
    console.log(`[security] firewall: allow ${what}`);
    return;
  }

  // delete
  step(`Remove rule ${p.number}`);
  const cur = await numbered(helpers);
  if (!cur.active) throw new Error('the firewall is off, so its rules are not numbered — turn it on first');
  const rule = cur.rules.find((r) => r.n === p.number);
  if (!rule || rule.raw.replace(/\s+/g, ' ') !== p.raw.replace(/\s+/g, ' ')) {
    throw new Error('the rule list changed since you loaded it (rule numbers shift when a rule is removed). Reload the list and try again — nothing was removed.');
  }
  const rest = cur.rules.filter((r) => r.n !== p.number);
  const ssh = await sshPort(helpers);
  if (ruleAllows(rule, ssh) && !rest.some((r) => ruleAllows(r, ssh))) {
    throw new Error(`refused: this is the last rule that lets SSH (port ${ssh}) in. Removing it would lock you out of the server. Add another SSH rule first.`);
  }
  if (ruleAllows(rule, config.port) && !rest.some((r) => ruleAllows(r, config.port))) {
    throw new Error(`refused: this is the last rule that lets the portal reach the agent (port ${config.port}). Removing it would cut this server off from the panel.`);
  }
  const r = await ufw(helpers, ['--force', 'delete', String(p.number)]);
  if (r.code !== 0) throw new Error(`ufw could not remove the rule: ${(r.stderr || r.stdout).trim().split('\n').pop()}`);
  ok(`removed: ${rule.raw.replace(/\s+/g, ' ')}`);
  console.log(`[security] firewall: removed rule "${rule.raw.replace(/\s+/g, ' ')}"`);
}
