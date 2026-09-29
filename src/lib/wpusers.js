import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import config from '../config.js';
import { wpCli, pathExists } from './sys.js';

// ============================================================
//  WordPress users of a site: list them, reset a password
// ============================================================
// Both run wp-cli as www-data in the site's app dir. They are answered
// directly (not queued as jobs): a job's log is stored by the portal, and a
// freshly generated password must never land in a log. The password is made
// HERE, handed to WordPress over stdin, and returned once in the response.
// ============================================================
const SET_PW = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'wp-set-password.php');
export const LOGIN_RE = /^[A-Za-z0-9 _.\-@]{1,60}$/; // what WordPress allows in a user_login
const silent = { log() {}, err() {}, onCancel() {} };

const siteSrc = async (domain) => {
  const src = `${config.wwwDir}/${domain}/htdocs/src`;
  if (!(await pathExists(`${src}/.env`))) throw Object.assign(new Error(`${domain} is not deployed on this server`), { status: 404 });
  return src;
};
const fail = (r, what) => Object.assign(new Error(`${what}: ${(r.stderr || r.stdout || `exit ${r.code}`).trim().split('\n').pop().slice(0, 300)}`), { status: 502 });

export async function listWpUsers(domain) {
  const wp = wpCli(silent, await siteSrc(domain), { quiet: true });
  const r = await wp(['user', 'list', '--fields=ID,user_login,user_email,display_name,roles,user_registered', '--format=json']);
  if (r.code !== 0) throw fail(r, 'wp user list failed');
  const rows = JSON.parse(r.stdout.slice(r.stdout.indexOf('['))); // tolerate PHP notices before the JSON
  return rows.map((u) => ({ id: Number(u.ID), login: u.user_login, email: u.user_email, name: u.display_name, roles: String(u.roles || '').split(',').filter(Boolean), registered: u.user_registered }));
}

// 24 random bytes -> 32 url-safe characters (~190 bits). Returned ONCE.
export const newPassword = () => crypto.randomBytes(24).toString('base64url');

export async function resetWpPassword(domain, login) {
  if (!LOGIN_RE.test(login)) throw Object.assign(new Error('invalid user login'), { status: 400 });
  const src = await siteSrc(domain);
  const wp = wpCli(silent, src, { quiet: true });
  const who = await wp(['user', 'get', login, '--field=ID']);
  const id = parseInt(who.stdout.trim().split('\n').pop(), 10);
  if (who.code !== 0 || !id) throw Object.assign(new Error(`no WordPress user "${login}" on ${domain}`), { status: 404 });
  const password = newPassword();
  const r = await wp(['eval-file', SET_PW, String(id)], { stdin: `${password}\n` });
  if (r.code !== 0 || !/ok\s*$/.test(r.stdout)) throw fail(r, 'could not set the password');
  return { id, login, password };
}
