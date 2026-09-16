import fs from 'node:fs/promises';
import crypto from 'node:crypto';

// ============================================================
//  envfile.js — native port of the scripts' .env helpers
// ============================================================
// setEnv / injectEnv:  in-place set KEY='value' (replacing a commented/blank
//   line if present, else appending). Values are single-quoted with embedded
//   quotes escaped — the same guarantee the awk-based set_env gave, but without
//   any shell/sed involvement so passwords with | & / \ ' are always safe.
// ============================================================

function escSingle(val) {
  // ' -> '\''  (POSIX single-quote escaping)
  return String(val).replace(/'/g, "'\\''");
}

const keyLineRe = (key) =>
  new RegExp(`^[\\t ]*#?[\\t ]*${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=`);

// Read the whole file (or '' if missing).
async function readFileSafe(file) {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return '';
  }
}

// Set KEY='value' in `file`, in place, preserving line position. Appends if the
// key is absent. Replaces the FIRST matching (possibly commented) line.
export async function setEnv(file, key, value) {
  const line = `${key}='${escSingle(value)}'`;
  const content = await readFileSafe(file);
  const lines = content.length ? content.split('\n') : [];
  const re = keyLineRe(key);
  let replaced = false;
  const out = lines.map((l) => {
    if (!replaced && re.test(l)) {
      replaced = true;
      return line;
    }
    return l;
  });
  if (!replaced) {
    // append (keep a single trailing newline)
    if (out.length && out[out.length - 1] === '') out[out.length - 1] = line;
    else out.push(line);
  }
  await fs.writeFile(file, out.join('\n').replace(/\n*$/, '\n'));
}

// injectEnv is an alias used by the alias operation for readability.
export const injectEnv = setEnv;

// Set a raw (non-quoted) assignment, e.g. DB_SSL=false. Replaces or appends.
export async function setEnvRaw(file, key, rawValue) {
  const line = `${key}=${rawValue}`;
  const content = await readFileSafe(file);
  const lines = content.length ? content.split('\n') : [];
  const re = keyLineRe(key);
  let replaced = false;
  const out = lines.map((l) => (!replaced && re.test(l) ? ((replaced = true), line) : l));
  if (!replaced) out.push(line);
  await fs.writeFile(file, out.join('\n').replace(/\n*$/, '\n'));
}

// Comment out a key (e.g. TELEGRAM_THREAD_BB_CLEAN_OLD_POSTS -> "# KEY=").
export async function commentOutEnv(file, key) {
  const content = await readFileSafe(file);
  const lines = content.length ? content.split('\n') : [];
  const re = keyLineRe(key);
  let done = false;
  const out = lines.map((l) => (!done && re.test(l) ? ((done = true), `# ${key}=`) : l));
  if (!done) out.push(`# ${key}=`);
  await fs.writeFile(file, out.join('\n').replace(/\n*$/, '\n'));
}

// Read a KEY='value' value from an .env file (strips surrounding quotes).
export async function readEnv(file, key) {
  const content = await readFileSafe(file);
  const re = new RegExp(`^[\\t ]*${key}=(.*)$`, 'm');
  const m = re.exec(content);
  if (!m) return '';
  let v = m[1].trim();
  // strip a single layer of surrounding quotes
  if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) {
    v = v.slice(1, -1);
  }
  return v;
}

// Set WP_SITEURL to the literal "${WP_HOME}/wp" (double-quoted, keeps the shell
// var reference Bedrock expands at runtime). Special-cased because it's not a
// single-quoted literal.
export async function setWpSiteUrl(file) {
  const content = await readFileSafe(file);
  const lines = content.length ? content.split('\n') : [];
  const re = keyLineRe('WP_SITEURL');
  const line = 'WP_SITEURL="${WP_HOME}/wp"';
  let replaced = false;
  const out = lines.map((l) => (!replaced && re.test(l) ? ((replaced = true), line) : l));
  if (!replaced) out.push(line);
  await fs.writeFile(file, out.join('\n').replace(/\n*$/, '\n'));
}

// Generate a WordPress salt (matches: openssl rand -base64 64 | tr -d '\n').
export function generateSalt() {
  return crypto.randomBytes(64).toString('base64').replace(/\n/g, '');
}