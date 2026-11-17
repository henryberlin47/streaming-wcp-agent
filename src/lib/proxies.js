import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ============================================================
//  proxies.js — the always-allowed addresses (the panel's allowlist)
// ============================================================
// The proxies that sit in front of every site, plus anything else the operator
// adds in the panel. All visitor traffic reaches nginx from the proxies, so
// these addresses are:
//   - never banned            (fail2ban ignore list)
//   - never blocked           (a firewall rule naming each one)
//   - trusted for the visitor's real address (nginx set_real_ip_from)
// One list for all three. The panel sends it with every hardening action and it
// is kept in a file beside the agent, so deploys use it too. Until the panel has
// sent one, the built-in default below applies.
// ============================================================
const FILE = process.env.AGENT_ALLOWLIST_FILE || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'allowlist.txt');
export const DEFAULT_ALLOWLIST = (process.env.AGENT_TRUSTED_PROXIES || '45.135.237.4,45.135.237.5,45.135.237.15,103.28.89.157,179.43.144.186')
  .split(',').map((s) => s.trim()).filter(Boolean);

/** "1.2.3.4", "10.0.0.0/8", "2001:db8::/32" -> normalized string, or null */
export function validAddress(s) {
  const [addr, bits, extra] = String(s ?? '').trim().split('/');
  const v = net.isIP(addr);
  if (!v || extra !== undefined) return null;
  if (bits === undefined) return addr;
  return /^\d{1,3}$/.test(bits) && Number(bits) <= (v === 4 ? 32 : 128) ? `${addr}/${Number(bits)}` : null;
}

/** The current allowlist (the saved one, else the default). */
export async function allowlist() {
  try {
    const saved = (await fs.readFile(FILE, 'utf8')).split('\n').map((l) => validAddress(l)).filter(Boolean);
    return [...new Set(saved)];
  } catch {
    return DEFAULT_ALLOWLIST;
  }
}

/** Replace the allowlist. Returns { list, removed } — `removed` so their firewall rules can go too. */
export async function saveAllowlist(list) {
  const next = [...new Set(list.map(validAddress).filter(Boolean))];
  const before = await allowlist();
  await fs.writeFile(FILE, `${next.join('\n')}\n`, { mode: 0o644 });
  return { list: next, removed: before.filter((ip) => !next.includes(ip)) };
}
