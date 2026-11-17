import fs from 'node:fs/promises';
import path from 'node:path';
import config from '../config.js';
import { run, pathExists } from './sys.js';

// ============================================================
//  security.js — read-only security audit of this server
// ============================================================
// collectSecurity() gathers facts (how SSH lets people in, who holds a key,
// who logged in and who tried, firewall, updates, what listens publicly, the
// web user) and findingsFrom() turns them into a ranked list. Nothing here
// changes the server — the fixes are the `harden` operation. No secret is ever
// read into the result: public keys are reported as fingerprints, passwords
// only as set / locked / none.
//
// The parsers and findingsFrom() are pure, so they are tested on canned
// output; the paths below can be redirected for those tests only.
// ============================================================
const PASSWD = process.env.AGENT_PASSWD_FILE || '/etc/passwd';
const SHADOW = process.env.AGENT_SHADOW_FILE || '/etc/shadow';
const GROUP = process.env.AGENT_GROUP_FILE || '/etc/group';
// where an authorized_keys file could be hidden outside an account's own home
const KEY_SEARCH = (process.env.AGENT_KEY_SEARCH_DIRS || '/home,/root,/var,/opt,/srv,/etc,/usr/local,/tmp').split(',');
const TMP_DIRS = (process.env.AGENT_TMP_DIRS || '/tmp,/var/tmp,/dev/shm').split(',');
// where a database account can write files: its data and run folders, plus the temp folders
const DB_DIRS = (process.env.AGENT_DB_DIRS || '/var/lib/mysql,/run/mysqld').split(',');
const ENV_FILE = process.env.AGENT_ENV_FILE || path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', '.env');

const QUIET = { log() {}, err() {}, onCancel() {} };
/** Run a probe; a missing binary is just "no answer", never an exception. */
const probe = async (cmd, args = [], opts = {}) => {
  try { return await run(QUIET, cmd, args, { quiet: true, ...opts }); } catch { return { code: 127, stdout: '', stderr: '' }; }
};
const readText = async (f) => { try { return await fs.readFile(f, 'utf8'); } catch { return ''; } };

// ---------- pure parsers ----------------------------------------------------

/** `sshd -T` -> { passwordauthentication: 'yes', port: '22', … } (first value wins, as in sshd) */
export function parseSshdT(text) {
  const out = {};
  for (const line of String(text).split('\n')) {
    const m = /^(\S+)\s+(.*)$/.exec(line.trim());
    if (m && !(m[1].toLowerCase() in out)) out[m[1].toLowerCase()] = m[2].trim();
  }
  return out;
}

/** One line of `ssh-keygen -lf`: "256 SHA256:abc comment words (ED25519)" */
export function parseKeygenLine(line) {
  const m = /^(\d+)\s+(\S+)\s+(.*)\s+\(([^)]+)\)\s*$/.exec(String(line).trim());
  return m ? { bits: Number(m[1]), fingerprint: m[2], comment: m[3] === 'no comment' ? '' : m[3], type: m[4] } : null;
}

/**
 * sshd journal lines (journalctl -o short-iso) ->
 *   accepted: [{ at, user, method, ip, port, key }]  newest first
 *   failed:   { total, byIp: [{ ip, count, users, last }] }  most attempts first
 * "Failed" covers wrong passwords, unknown users and connections dropped during
 * authentication (which is what a refused key looks like).
 */
export function parseSshLog(text) {
  const accepted = [];
  const ips = new Map();
  let total = 0;
  const fail = (ip, user, at) => {
    total++;
    const e = ips.get(ip) || { ip, count: 0, users: [], last: at };
    e.count++; e.last = at;
    if (user && !e.users.includes(user) && e.users.length < 5) e.users.push(user);
    ips.set(ip, e);
  };
  for (const line of String(text).split('\n')) {
    const m = /^(\S+)\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+(.*)$/.exec(line);
    if (!m) continue;
    const [, at, msg] = m;
    let a;
    if ((a = /^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+))?/.exec(msg))) {
      accepted.push({ at, method: a[1], user: a[2], ip: a[3], port: Number(a[4]), key: a[6] ? `${a[5]} ${a[6]}` : null });
    } else if ((a = /^Failed \S+ for (?:invalid user )?(\S+) from (\S+)/.exec(msg))) fail(a[2], a[1], at);
    else if ((a = /^Invalid user (\S*) from (\S+)/.exec(msg))) fail(a[2], a[1], at);
    else if ((a = /^Connection (?:closed|reset) by (?:authenticating|invalid) user (\S+) (\S+) port \d+ \[preauth\]/.exec(msg))) fail(a[2], a[1], at);
  }
  accepted.reverse();
  return { accepted, failed: { total, byIp: [...ips.values()].sort((x, y) => y.count - x.count) } };
}

/** `ufw status` or `ufw status numbered` -> { active, rules: [{ n, to, action, from, raw }] } (n = rule number, or null) */
export function parseUfw(text) {
  const active = /^Status:\s*active/m.test(text);
  const rules = [];
  for (const line of String(text).split('\n')) {
    const m = /^\[\s*(\d+)\]\s+(.*)$/.exec(line.trim());
    const raw = (m ? m[2] : line).trim();
    const p = raw.split(/\s{2,}/);
    if (p.length >= 3 && /^(ALLOW|DENY|REJECT|LIMIT)/.test(p[1])) rules.push({ n: m ? Number(m[1]) : null, to: p[0], action: p[1], from: p.slice(2).join(' '), raw });
  }
  return { active, rules };
}

const UFW_APPS = { OpenSSH: [22], 'Nginx Full': [80, 443], 'Nginx HTTP': [80], 'Nginx HTTPS': [443] };
/** Is this an ALLOW rule for that TCP port — from anywhere, one address or one interface alike? */
export function ruleAllows(r, port) {
  if (!/^(ALLOW|LIMIT)/.test(r.action)) return false;
  const to = r.to.replace(/\s*\(v6\)$/, '').replace(/ on \S+$/, '');
  if (UFW_APPS[to]) return UFW_APPS[to].includes(port);
  const m = /^([\d,:]+)(?:\/(tcp|udp))?$/.exec(to);
  if (!m || m[2] === 'udp') return false;
  return m[1].split(',').some((part) => {
    const [lo, hi] = part.split(':').map(Number);
    return hi ? port >= lo && port <= hi : lo === port;
  });
}
/** Does the firewall let the whole internet reach this TCP port? (inactive = yes) */
export function ufwAllowsPublic(ufw, port) {
  if (!ufw.active) return true;
  return ufw.rules.some((r) => /^Anywhere/.test(r.from) && !/ on \S+/.test(r.to) && ruleAllows(r, port));
}

const scopeOf = (addr) => {
  const a = addr.replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (a === '0.0.0.0' || a === '::' || a === '*') return 'all';
  if (a.startsWith('127.') || a === '::1') return 'local';
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|f[cd]|fe80)/i.test(a)) return 'private';
  return 'public';
};
/** `ss -tlnpH` -> [{ addr, port, proc, scope: all|local|private|public }] (one per port+scope) */
export function parseListening(text) {
  const seen = new Map();
  for (const line of String(text).split('\n')) {
    const cols = line.trim().split(/\s+/);
    if (cols[0] !== 'LISTEN' || !cols[3]) continue;
    const i = cols[3].lastIndexOf(':');
    const addr = cols[3].slice(0, i), port = Number(cols[3].slice(i + 1));
    if (!port) continue;
    const proc = /users:\(\("([^"]+)"/.exec(line)?.[1] || '';
    const scope = scopeOf(addr);
    if (!seen.has(`${port}/${scope}`)) seen.set(`${port}/${scope}`, { addr, port, proc, scope });
  }
  return [...seen.values()].sort((a, b) => a.port - b.port);
}

/**
 * /etc/passwd (+ /etc/shadow, /etc/group) ->
 *   [{ name, uid, gid, home, shell, login, system, password: set|locked|none|unknown, changed, sudo }]
 * `changed` is the day the password field last changed (YYYY-MM-DD) — for an
 * account nobody has touched since, the day it was created. `sudo` = member of
 * sudo/admin/wheel. No hash ever leaves this function.
 */
export function parseAccounts(passwd, shadow = '', group = '') {
  const pw = new Map();
  for (const l of String(shadow).split('\n')) {
    const [name, hash, days] = l.split(':');
    if (name && hash !== undefined) {
      pw.set(name, {
        password: hash === '' ? 'none' : /^[!*]/.test(hash) ? 'locked' : 'set',
        changed: /^\d+$/.test(days || '') && Number(days) > 0 ? new Date(Number(days) * 86400000).toISOString().slice(0, 10) : null,
      });
    }
  }
  const sudoers = new Set(), sudoGids = new Set();
  for (const l of String(group).split('\n')) {
    const [g, , gid, members] = l.split(':');
    if (!['sudo', 'admin', 'wheel'].includes(g)) continue;
    sudoGids.add(Number(gid));
    for (const m of String(members || '').split(',')) if (m.trim()) sudoers.add(m.trim());
  }
  return String(passwd).split('\n').map((l) => l.split(':')).filter((p) => p.length >= 7).map(([name, , uid, gid, , home, shell]) => ({
    name, uid: Number(uid), gid: Number(gid), home, shell,
    login: !/(nologin|false|sync|shutdown|halt)$/.test(shell.trim()),
    system: Number(uid) > 0 && Number(uid) < 1000,
    password: pw.get(name)?.password || 'unknown',
    changed: pw.get(name)?.changed || null,
    sudo: sudoers.has(name) || sudoGids.has(Number(gid)),
  }));
}

const SENSITIVE = { 3306: 'MySQL/MariaDB', 6379: 'Redis', 11211: 'Memcached', 27017: 'MongoDB', 9200: 'Elasticsearch', 5432: 'PostgreSQL' };

/**
 * Facts -> findings, worst first: [{ id, severity: high|medium|low, title, detail, fix? }]
 * `fix` names a `harden` action that resolves it. Pure.
 */
export function findingsFrom(f) {
  const out = [];
  const add = (severity, id, title, detail, fix) => out.push({ id, severity, title, detail, ...(fix && { fix }) });
  const ssh = f.ssh || {};
  const root = (f.users || []).find((u) => u.name === 'root');
  const rootKeys = root?.keys?.length || 0;
  const passwordOn = ssh.passwordauthentication === 'yes' || ssh.kbdinteractiveauthentication === 'yes';

  if (passwordOn) {
    add('high', 'ssh-password', 'SSH accepts passwords',
      `Anyone on the internet can keep guessing passwords${ssh.permitrootlogin === 'yes' ? ', including root\'s' : ''}. `
      + (rootKeys ? 'A key is installed for root: confirm you can log in with it, then switch to keys only.' : 'Add your SSH public key first, log in with it once, then switch to keys only.'),
      rootKeys ? 'ssh-keys-only' : undefined);
  }
  if (!rootKeys && root) add(passwordOn ? 'medium' : 'high', 'ssh-no-key', 'No SSH key is installed for root', passwordOn ? 'Root can only log in with a password. Add a public key so password login can be turned off.' : 'Password login is off and root has no key — nobody can log in as root over SSH.');
  const byPassword = (f.logins?.accepted || []).filter((l) => l.method === 'password');
  if (byPassword.length) add('medium', 'ssh-password-logins', `${byPassword.length} SSH login(s) used a password`, `From ${[...new Set(byPassword.map((l) => l.ip))].slice(0, 6).join(', ')}. Check each address is yours.`);
  if (Number(ssh.maxauthtries) > 4 || ssh.x11forwarding === 'yes' || ssh.permitemptypasswords === 'yes') add('low', 'ssh-basics', 'SSH limits are loose', `MaxAuthTries ${ssh.maxauthtries || '?'}, X11Forwarding ${ssh.x11forwarding || '?'}. Tighten them.`, 'ssh-basics');

  const recent = (d) => d && (Date.parse(f.at || new Date().toISOString()) - Date.parse(d)) / 86400000 <= 14;
  for (const u of f.users || []) {
    const keys = u.keys?.length || 0;
    if (u.uid === 0 && u.name !== 'root') add('high', `uid0-${u.name}`, `Account "${u.name}" has root's user id`, 'A second uid-0 account is a classic backdoor. Remove it unless you created it.');
    if (u.password === 'none' && u.login) add('high', `nopass-${u.name}`, `Account "${u.name}" has an empty password`, 'It can log in without one. Lock it or set a password.');
    // service accounts (uid below 1000) never log in: a key or a password on one is how an intruder keeps a way back
    if (u.name !== 'root' && keys && (u.system || !u.login)) add('high', `acct-keys-${u.name}`, `Service account "${u.name}" has ${keys} SSH key(s)`, `Accounts like this never log in over SSH. A key here is a common backdoor — check whose it is (${u.keys.map((k) => k.comment || k.fingerprint).slice(0, 2).join(', ')}) and remove it if it is not yours.`);
    if (u.system && u.login && u.password === 'set') add('high', `acct-pass-${u.name}`, `Service account "${u.name}" has a shell and a password`, `uid ${u.uid}, shell ${u.shell}. Service accounts are normally locked; this one can be logged in to.`);
    if (u.name !== 'root' && u.sudo) add('low', `acct-sudo-${u.name}`, `Account "${u.name}" can become root (sudo)`, 'Fine if it is yours. An account you do not recognise in the sudo group is a takeover.');
    if (recent(u.changed) && (u.login || keys)) add('medium', `acct-new-${u.name}`, `Account "${u.name}" was created or had its password changed on ${u.changed}`, u.name === 'root' ? 'If you did not change root\'s password on that day, someone else did.' : 'If you did not create or change this account on that day, treat it as an intruder\'s.');
  }
  for (const p of f.strayKeyFiles || []) add('high', `stray-keys-${p}`, 'An authorized_keys file outside any account\'s home', `${p} — sshd does not normally read it, but it has no reason to exist. Check what it is.`);

  const failed = f.logins?.failed?.total || 0;
  const f2b = f.fail2ban || {};
  if (!f2b.active) add(passwordOn ? 'high' : 'medium', 'fail2ban', f2b.installed ? 'fail2ban is installed but not running' : 'Nothing bans repeated failed logins', `${failed} failed SSH attempt(s) in the log. fail2ban blocks an address after a few failures.`, 'fail2ban');
  else if (failed > 500) add('low', 'ssh-noise', `${failed} failed SSH attempts in the log`, `fail2ban is running (${f2b.banned ?? 0} address(es) banned now). Keys-only login makes these harmless.`);

  const fw = f.firewall || {};
  if (!fw.active) add('high', 'firewall', fw.installed ? 'The firewall is off' : 'No firewall is installed', 'Every listening port is reachable from the internet. Turn ufw on with SSH, web and the agent (tailnet only) allowed.', 'firewall');
  for (const p of f.exposed || []) {
    if (p.port === f.agent?.port) add('high', 'exposed-agent', `The agent port ${p.port} is open to the internet`, 'The agent runs as root. It should only be reachable over Tailscale.', fw.active ? undefined : 'firewall');
    else if (SENSITIVE[p.port]) add('high', `exposed-${p.port}`, `${SENSITIVE[p.port]} (port ${p.port}) is open to the internet`, `${p.proc || 'A service'} listens on every address and the firewall does not block it.`, fw.active ? undefined : 'firewall');
  }

  const up = f.updates || {};
  if (up.security > 0) add('medium', 'updates', `${up.security} security update(s) are waiting`, `${up.pending} package update(s) in total.`, up.autoUpdates ? undefined : 'auto-updates');
  if (up.autoUpdates === false) add('medium', 'auto-updates', 'Security updates are not installed automatically', 'unattended-upgrades applies Ubuntu security fixes on its own.', 'auto-updates');
  if (up.rebootRequired) add('low', 'reboot', 'A restart is pending', 'An installed update (usually the kernel) only takes effect after a reboot.');

  const w = f.wwwData || {};
  if (w.shell && !/(nologin|false)$/.test(w.shell)) add('high', 'www-shell', 'The web user can open a shell', `www-data's shell is ${w.shell}; it should be /usr/sbin/nologin.`);
  if (w.password === 'set' || w.password === 'none') add('high', 'www-password', 'The web user has a usable password', 'www-data should be locked.');
  if (w.crontab) add('high', 'www-crontab', 'The web user has its own crontab', 'Site jobs live in /etc/cron.d. A personal crontab for www-data is how malware comes back after cleanup — inspect it.');
  if (w.sshKeys) add('high', 'www-ssh', 'The web user has SSH keys', '/var/www/.ssh exists. www-data never needs to log in.');
  if (w.uploadsPhp?.length) add('high', 'uploads-php', `${w.uploadsPhp.length} PHP file(s) inside uploads folders`, `Uploads should hold media only; PHP there is usually a planted backdoor. First: ${w.uploadsPhp.slice(0, 3).join(', ')}`);
  if (w.tmpExecutables?.length) add('high', 'tmp-exec', `${w.tmpExecutables.length} program or script file(s) owned by the web user in temp folders`, `First: ${w.tmpExecutables.slice(0, 3).map((x) => `${x.path} (${x.kind})`).join(', ')}`);

  // A database attack: someone logged in to MySQL with a privileged account writes a
  // shared library where the database can write, then loads it to run OS commands.
  const db = f.database || {};
  if (db.udfs?.length) add('high', 'db-udf-loaded', `The database has ${db.udfs.length} foreign function(s) loaded`, `${db.udfs.slice(0, 4).map((u) => `${u.name} (${u.dl})`).join(', ')}. Functions like sys_exec run shell commands from SQL — treat this server as compromised and rebuild it.`);
  if (db.droppedLibs?.length) add('high', 'db-udf-files', `${db.droppedLibs.length} library file(s) where the database can write`, `${db.droppedLibs.slice(0, 4).join(', ')}. This is the mark of an attack through MySQL by a privileged database login: change every database password, close the database port to the internet, and check what was changed.`);
  for (const a of db.openAccounts || []) {
    add(a.user === 'root' ? 'high' : 'medium', `db-open-${a.user}`, `Database account "${a.user}" may connect from any address`, a.user === 'root' ? 'root@% with a guessable password is how databases get taken over. Restrict it to localhost.' : 'Restrict it to the web servers\' addresses.');
  }

  if (f.sites?.envWorldReadable?.length) add('medium', 'env-perms', `${f.sites.envWorldReadable.length} site .env file(s) are readable by every user`, 'They hold database and storage credentials. Only the web user needs to read them.', 'env-perms');
  const ag = f.agent || {};
  if (ag.allowlist === 0) add('high', 'agent-allowlist', 'The agent accepts connections from any address', 'Set AGENT_ALLOWED_IPS to the portal\'s Tailscale address.');
  if (ag.envMode && ag.envMode !== '600') add('medium', 'agent-env', `The agent's .env is mode ${ag.envMode}`, 'It holds the agent key and deploy secrets; it should be 600.', 'env-perms');

  const rank = { high: 0, medium: 1, low: 2 };
  return out.sort((a, b) => rank[a.severity] - rank[b.severity]);
}

// ---------- authorized keys --------------------------------------------------

const KEY_LINE = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+(?: [^\r\n]{0,200})?$/;
const fingerprintOf = async (line) => {
  const r = await probe('ssh-keygen', ['-lf', '-'], { stdin: `${line}\n` });
  return r.code === 0 ? parseKeygenLine(r.stdout.split('\n')[0]) : null;
};
const keysFile = (home) => path.join(home, '.ssh', 'authorized_keys');
// sshd reads BOTH by default (AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2);
// the second is long forgotten, which is exactly why intruders use it.
const keysFiles = (home) => [keysFile(home), `${keysFile(home)}2`];

/** Keys allowed to log in to an account: [{ fingerprint, type, bits, comment, restricted, file }] */
export async function listKeys(home) {
  const out = [];
  for (const file of keysFiles(home)) {
    for (const raw of (await readText(file)).split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      const k = await fingerprintOf(line);
      // a line that starts with options (command=…, from=…) is still a key, with strings attached
      if (k) out.push({ ...k, restricted: !KEY_LINE.test(line), file: path.basename(file) });
    }
  }
  return out;
}

const accounts = async () => parseAccounts(await readText(PASSWD), await readText(SHADOW), await readText(GROUP));
const sshdSettings = async () => parseSshdT((await probe('sshd', ['-T'])).stdout);
const fail = (message, status = 400) => Object.assign(new Error(message), { status });

/** Install a public key for root. Only a bare key line is accepted — no options. */
export async function addKey(keyLine) {
  const line = String(keyLine || '').trim().replace(/\s+/g, ' ');
  if (!KEY_LINE.test(line)) throw fail('paste one public key line: "ssh-ed25519 AAAA… comment" (the .pub file — never the private key)');
  const k = await fingerprintOf(line);
  if (!k) throw fail('that is not a valid public key');
  if (k.type === 'DSA' || (k.type === 'RSA' && k.bits < 2048)) throw fail(`a ${k.bits}-bit ${k.type} key is too weak — use ed25519`);
  const root = (await accounts()).find((u) => u.name === 'root');
  if (!root) throw fail('no root account found', 500);
  if ((await listKeys(root.home)).some((x) => x.fingerprint === k.fingerprint)) throw fail('that key is already installed');
  const file = keysFile(root.home);
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const cur = await readText(file);
  await fs.writeFile(file, `${cur}${cur && !cur.endsWith('\n') ? '\n' : ''}${line}\n`, { mode: 0o600 });
  await fs.chmod(file, 0o600);
  console.log(`[security] key added for root: ${k.type} ${k.fingerprint} ${k.comment}`);
  return k;
}

/** Remove one key (by fingerprint) from an account's authorized_keys. */
export async function removeKey(user, fingerprint) {
  const acct = (await accounts()).find((u) => u.name === user);
  if (!acct) throw fail(`no such account: ${user}`, 404);
  let removed = null, left = 0, hit = null;
  for (const file of keysFiles(acct.home)) {
    const keep = [];
    let here = false;
    for (const raw of (await readText(file)).split('\n')) {
      const line = raw.trim();
      const k = line && !line.startsWith('#') ? await fingerprintOf(line) : null;
      if (k && k.fingerprint === fingerprint && !removed) { removed = k; here = true; continue; }
      if (k) left++;
      keep.push(raw);
    }
    if (here) hit = { file, text: keep.join('\n').replace(/\n*$/, '\n') };
  }
  if (!removed) throw fail('that key is not installed for this account', 404);
  if (user === 'root' && left === 0 && (await sshdSettings()).passwordauthentication === 'no') {
    throw fail('this is root\'s last key and password login is off — removing it would lock you out. Add another key first.');
  }
  await fs.writeFile(hit.file, hit.text, { mode: 0o600 });
  console.log(`[security] key removed for ${user}: ${removed.type} ${removed.fingerprint} ${removed.comment}`);
  return removed;
}

// ---------- collection --------------------------------------------------------

/** Did a key login for this user succeed in the SSH log? (proof that key login works) */
export async function keyLoginSeen(user = 'root') {
  return (await sshLog()).accepted.some((l) => l.user === user && l.method === 'publickey');
}

async function sshLog() {
  // by identifier, so it works whatever the unit is called (ssh / sshd / socket-activated)
  const r = await probe('journalctl', ['-t', 'sshd', '-t', 'sshd-session', '--since=-60d', '-o', 'short-iso', '--no-pager']);
  return parseSshLog(r.stdout);
}

async function wwwFacts(www) {
  const uploads = await probe('find', [config.wwwDir, '-maxdepth', '9', '-path', '*/uploads/*', '-name', '*.php', '-size', '+0', '-type', 'f']);
  const tmp = await probe('find', [...TMP_DIRS, '-xdev', '-type', 'f', '-user', 'www-data', '-size', '+0']);
  const files = tmp.stdout.split('\n').filter(Boolean).slice(0, 300);
  const kinds = files.length ? (await probe('file', ['--', ...files])).stdout.split('\n') : [];
  const tmpExecutables = [];
  for (const l of kinds) {
    const i = l.indexOf(': ');
    if (i > 0 && /ELF|executable|script|PHP/i.test(l.slice(i + 2))) tmpExecutables.push({ path: l.slice(0, i), kind: l.slice(i + 2).trim().slice(0, 60) });
  }
  const cron = await probe('crontab', ['-u', 'www-data', '-l']);
  return {
    shell: www?.shell || null, password: www?.password || null,
    crontab: cron.code === 0 && cron.stdout.split('\n').some((l) => l.trim() && !l.trim().startsWith('#')),
    sshKeys: www ? await pathExists(path.join(www.home, '.ssh')) : false,
    uploadsPhp: uploads.stdout.split('\n').filter(Boolean).slice(0, 50),
    tmpExecutables,
    tmpFiles: files.length,
  };
}

/** Signs of an attack through the database. Reads account NAMES only, never a hash. */
async function dbFacts() {
  const libs = await probe('find', [...DB_DIRS, ...TMP_DIRS, '-maxdepth', '1', '-type', 'f', '-name', '*.so']);
  const q = async (sql) => {
    const r = await probe('mysql', ['-N', '-B', '-e', sql]); // root over the local socket; no password is ever passed
    return r.code === 0 ? r.stdout.split('\n').filter(Boolean).map((l) => l.split('\t')) : null;
  };
  const udfs = await q('SELECT name, dl FROM mysql.func');
  const open = await q("SELECT user, host FROM mysql.user WHERE host = '%' AND user <> ''");
  return {
    readable: udfs !== null, // false = no local database, or root cannot log in over the socket
    droppedLibs: libs.stdout.split('\n').filter(Boolean).slice(0, 50),
    udfs: (udfs || []).map(([name, dl]) => ({ name, dl })),
    openAccounts: (open || []).map(([user, host]) => ({ user, host })),
  };
}

async function envWorldReadable() {
  const out = [];
  let dirs = [];
  try { dirs = await fs.readdir(config.wwwDir); } catch { /* no sites */ }
  for (const d of dirs) {
    const f = `${config.wwwDir}/${d}/htdocs/src/.env`;
    try { if ((await fs.stat(f)).mode & 0o007) out.push(f); } catch { /* not a deployed site */ }
  }
  return out;
}

/** Every fact the audit reports, plus the findings drawn from them. */
export async function collectSecurity() {
  const [ssh, accts, log, ufwOut, ss, f2bActive, f2bStatus, aptCheck, autoConf, osRelease] = await Promise.all([
    sshdSettings(), accounts(), sshLog(),
    probe('ufw', ['status']), probe('ss', ['-tlnpH']),
    probe('systemctl', ['is-active', 'fail2ban']), probe('fail2ban-client', ['status', 'sshd']),
    probe('/usr/lib/update-notifier/apt-check'), readText('/etc/apt/apt.conf.d/20auto-upgrades'), readText('/etc/os-release'),
  ]);
  // Every account is checked for keys — a key on a service account is the thing to find.
  // Reported: accounts that can log in, hold a key, have root's id, or may sudo.
  const users = [], known = new Set();
  for (const a of accts) {
    for (const f of keysFiles(a.home)) known.add(path.resolve(f));
    const keys = a.home && a.home !== '/' && a.home !== '/nonexistent' ? await listKeys(a.home) : [];
    if (a.uid === 0 || a.login || keys.length || a.sudo) users.push({ ...a, keys });
  }
  const found = await probe('find', [...KEY_SEARCH, '-xdev', '-maxdepth', '6', '-type', 'f', '(', '-name', 'authorized_keys', '-o', '-name', 'authorized_keys2', ')']);
  const strayKeyFiles = found.stdout.split('\n').filter(Boolean).map((f) => path.resolve(f)).filter((f) => !known.has(f)).slice(0, 20);
  const ufw = { installed: ufwOut.code !== 127, ...parseUfw(ufwOut.stdout) };
  const listening = parseListening(ss.stdout);
  const exposed = listening.filter((l) => (l.scope === 'all' || l.scope === 'public') && ufwAllowsPublic(ufw, l.port));
  const apt = /^(\d+);(\d+)/.exec(`${aptCheck.stderr}${aptCheck.stdout}`.trim());
  let envMode = null;
  try { envMode = ((await fs.stat(ENV_FILE)).mode & 0o777).toString(8); } catch { /* not installed the usual way */ }

  const facts = {
    at: new Date().toISOString(),
    os: /^PRETTY_NAME="?([^"\n]+)"?/m.exec(osRelease)?.[1] || null,
    ssh: Object.fromEntries(['port', 'permitrootlogin', 'passwordauthentication', 'pubkeyauthentication', 'kbdinteractiveauthentication', 'maxauthtries', 'x11forwarding', 'permitemptypasswords', 'logingracetime'].map((k) => [k, ssh[k] ?? null])),
    users, accounts: accts.length, strayKeyFiles,
    logins: { accepted: log.accepted.slice(0, 200), failed: { total: log.failed.total, byIp: log.failed.byIp.slice(0, 25) } },
    firewall: { installed: ufw.installed, active: ufw.active, rules: ufw.rules.map((r) => r.raw) },
    fail2ban: {
      installed: f2bStatus.code !== 127, active: f2bActive.stdout.trim() === 'active',
      banned: Number(/Currently banned:\s*(\d+)/.exec(f2bStatus.stdout)?.[1] ?? 0), totalBanned: Number(/Total banned:\s*(\d+)/.exec(f2bStatus.stdout)?.[1] ?? 0),
    },
    listening, exposed,
    updates: {
      pending: apt ? Number(apt[1]) : null, security: apt ? Number(apt[2]) : null,
      autoUpdates: /Unattended-Upgrade\s+"1"/.test(autoConf),
      rebootRequired: await pathExists('/var/run/reboot-required'),
    },
    wwwData: await wwwFacts(accts.find((a) => a.name === 'www-data')),
    database: await dbFacts(),
    sites: { envWorldReadable: await envWorldReadable() },
    agent: { host: config.host, port: config.port, allowlist: config.allowedIps.length, envMode, tokenLength: config.authToken.length },
  };
  return { ...facts, findings: findingsFrom(facts) };
}
