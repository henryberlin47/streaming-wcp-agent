import fs from 'node:fs/promises';
import { Transform } from 'node:stream';
import { run } from './sys.js';

// ============================================================
//  mysql.js — client plumbing for db migrations
// ============================================================

/**
 * Passwords go in a 0600 option file, never on the process list.
 * MariaDB clients don't understand `ssl-mode` (MySQL 5.7+ syntax), and MariaDB 11+
 * prefers SSL even unasked — so the mode has to be spelled per client flavour.
 */
export async function writeDefaults(file, { host, port, user, password, ssl }, mariadb) {
  const sslLines = mariadb
    ? (ssl === 'required' ? 'ssl=1\nssl-verify-server-cert=0' : 'ssl=0')
    : (ssl === 'required' ? 'ssl-mode=REQUIRED' : 'ssl-mode=DISABLED');
  const body =
    `[client]\nhost=${host}\nport=${port}\nuser=${user}\npassword="${password}"\n${sslLines}\n`;
  await fs.writeFile(file, body, { mode: 0o600 });
  await fs.chmod(file, 0o600).catch(() => {});
  return file;
}

/** True when the given client binary is MariaDB rather than MySQL. */
export async function clientIsMariadb(helpers, bin = 'mysql') {
  const r = await run(helpers, bin, ['--version'], { quiet: true });
  return /mariadb/i.test(`${r.stdout}${r.stderr}`);
}

// Collation/DEFINER normalization now runs as a `sed` process inside migrate.js
// (matching db-migrate-site.sh) rather than a Node Transform — a JS transform
// buffered whole lines and froze on a multi-MB --hex-blob row.

/**
 * Passthrough that counts bytes and reports throughput every `everyMs`, so a
 * long migration shows progress instead of going silent until the job timeout.
 * A frozen byte count = a real stall; a rising one = just slow. `onTick(mb, mbPerSec)`.
 */
export function progressStream(onTick, everyMs = 15000) {
  let bytes = 0;
  let lastBytes = 0;
  let lastAt = Date.now();
  const timer = setInterval(() => {
    const now = Date.now();
    const rate = (bytes - lastBytes) / 1048576 / ((now - lastAt) / 1000 || 1);
    onTick(bytes / 1048576, rate);
    lastBytes = bytes;
    lastAt = now;
  }, everyMs);
  timer.unref?.();
  const stop = () => clearInterval(timer);
  return new Transform({
    transform(chunk, _enc, cb) { bytes += chunk.length; cb(null, chunk); },
    flush(cb) { stop(); cb(); },
  }).once('close', stop);
}

