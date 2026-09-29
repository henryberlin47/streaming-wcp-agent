import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import config from '../config.js';
import { wpCli, pathExists } from './sys.js';

// ============================================================
//  WordPress users of a site
// ============================================================
// list · create · reset (password) · set-role · deactivate · activate · delete
// All run scripts/wp-users.php through wp-cli as www-data, with the input as
// JSON on STDIN. They are answered directly (not queued as jobs): a job's log
// is stored by the portal, and a freshly generated password must never land in
// a log. Passwords are made HERE, handed to WordPress over stdin, and returned
// once in the response.
// ============================================================
const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'wp-users.php');
const silent = { log() {}, err() {}, onCancel() {} };

export const LOGIN_RE = /^[A-Za-z0-9 _.\-@]{1,60}$/; // what WordPress allows in a user_login
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const ROLE_RE = /^[a-z0-9_-]{1,40}$/;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const intId = (v, what) => { const n = Number(v); if (!Number.isInteger(n) || n < 1) throw bad(`${what} must be a user id`); return n; };

// 24 random bytes -> 32 url-safe characters (~190 bits). Returned ONCE.
export const newPassword = () => crypto.randomBytes(24).toString('base64url');

// Which actions take what, and which of them create a password to hand back.
const ACTIONS = {
  list: { input: () => ({}) },
  create: {
    password: true,
    input: (b) => {
      const login = String(b.login || '').trim(), email = String(b.email || '').trim(), role = String(b.role || '');
      if (!LOGIN_RE.test(login)) throw bad('invalid user login');
      if (!EMAIL_RE.test(email)) throw bad('invalid e-mail address');
      if (!ROLE_RE.test(role)) throw bad('invalid role');
      return { login, email, role };
    },
  },
  reset: { password: true, input: (b) => ({ id: intId(b.id, 'id') }) },
  activate: { password: true, input: (b) => ({ id: intId(b.id, 'id') }) },
  deactivate: { input: (b) => ({ id: intId(b.id, 'id') }) },
  'set-role': { input: (b) => { if (!ROLE_RE.test(String(b.role || ''))) throw bad('invalid role'); return { id: intId(b.id, 'id'), role: String(b.role) }; } },
  delete: { input: (b) => ({ id: intId(b.id, 'id'), reassign: intId(b.reassign, 'reassign') }) },
};
export const WP_USER_ACTIONS = Object.keys(ACTIONS);

export async function wpUsers(domain, action, body = {}) {
  const def = ACTIONS[action];
  if (!def) throw bad(`unknown action: ${action}`, 404);
  const input = def.input(body);
  const src = `${config.wwwDir}/${domain}/htdocs/src`;
  if (!(await pathExists(`${src}/.env`))) throw bad(`${domain} is not deployed on this server`, 404);

  const password = def.password ? newPassword() : undefined;
  const r = await wpCli(silent, src, { quiet: true })(['eval-file', SCRIPT, action], { stdin: JSON.stringify({ ...input, ...(password && { password }) }) });
  const line = r.stdout.split('\n').reverse().find((l) => l.startsWith('WCP_JSON:'));
  let data;
  try { data = JSON.parse(line.slice('WCP_JSON:'.length)); } catch { data = null; }
  if (!data) throw bad(`wp-cli failed: ${(r.stderr || r.stdout || `exit ${r.code}`).trim().split('\n').pop().slice(0, 300)}`, 502);
  if (data.error) throw bad(data.error, 400); // WordPress said no (last admin, duplicate login, …)
  return { ...data, ...(password && { password }) };
}
