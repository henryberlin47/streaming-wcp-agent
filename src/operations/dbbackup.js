import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import { run, removePath } from '../lib/sys.js';
import { cloneMap, readMapJson } from '../lib/map.js';
import { writeDefaults, clientIsMariadb, progressStream } from '../lib/mysql.js';
import { clientFrom } from '../lib/s3.js';
import { logger } from '../lib/log.js';
import { SED_ARGS } from './migrate.js';

// ============================================================
//  dbbackup / dbrestore — database backups in DigitalOcean Spaces
// ============================================================
// WHAT is backed up comes from the seo-domain-map (the same source deploys and
// migrations use): every root domain names a database. Several roots can point
// at one database, so targets are de-duplicated by server + database name.
//
//   backup   mysqldump | gzip -> a temp file -> Spaces, then retention
//   restore  Spaces -> temp file -> (safety backup of the target) -> mysql
//
// Object layout:  <prefix><db-server>/<database>/<database>_<UTC stamp>.sql.gz
// A failed database never stops the others; the job fails at the end if any did.
// ============================================================
const WORK_DIR = process.env.BACKUP_DIR || '/var/backups/db-backups';
const silent = { log() {}, err() {}, onCancel() {} };
const stampOf = (d = new Date()) => d.toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '_');
const mb = (n) => `${(n / 1048576).toFixed(1)} MB`;
// A fast child can be gone before we get here (we await its output first), and
// a 'close' that already fired would never resolve — so check before listening.
const exitOf = (child) => new Promise((resolve, reject) => {
  if (child.exitCode !== null || child.signalCode !== null) return resolve(child.exitCode ?? -1);
  child.once('error', reject);
  child.once('close', (c) => resolve(c ?? -1));
});

/**
 * The databases named by the map, one entry per server+database.
 * roots (optional) limits it to the databases of those root domains.
 * Pure. -> [{ label, host, port, ssl, db, user, password, roots: [...] }]
 */
export function targetsFromMap(map, servers, roots = null) {
  const want = roots && roots.length ? new Set(roots) : null;
  const out = new Map();
  for (const [root, e] of Object.entries(map || {})) {
    if (want && !want.has(root)) continue;
    if (!e || !e.DB_HOST || !e.DB_NAME || !e.DB_USER || !e.DB_PASSWORD) continue;
    const [host, portInHost] = String(e.DB_HOST).split(':');
    const name = Object.keys(servers || {}).find((k) => servers[k] && servers[k].host === host);
    const port = String(portInHost || (name ? servers[name].port ?? 3306 : 3306));
    const id = `${host}:${port}/${e.DB_NAME}`;
    const t = out.get(id) || {
      label: (name || host).replace(/[^A-Za-z0-9._-]/g, '_'), host, port,
      ssl: name ? servers[name].ssl ?? 'required' : 'required',
      db: e.DB_NAME, user: e.DB_USER, password: e.DB_PASSWORD, roots: [],
    };
    t.roots.push(root);
    out.set(id, t);
  }
  return [...out.values()].sort((a, b) => `${a.label}/${a.db}`.localeCompare(`${b.label}/${b.db}`));
}

/**
 * Which backups of ONE database to delete. Pure.
 *  keepLast    keep at most this many, newest first (0 = no limit)
 *  maxAgeDays  delete anything older than this (0 = no limit)
 * The newest backup is never deleted, whatever the rules say.
 */
export function pickExpired(objects, { keepLast = 0, maxAgeDays = 0, now = Date.now() } = {}) {
  const sorted = [...objects].sort((a, b) => new Date(b.modified) - new Date(a.modified));
  return sorted.filter((o, i) => i > 0 && (
    (keepLast > 0 && i >= keepLast) ||
    (maxAgeDays > 0 && now - new Date(o.modified).getTime() > maxAgeDays * 86_400_000)
  ));
}

/** "<prefix><server>/<db>/<file>.sql.gz" -> { server, db, file } (null if it isn't one of ours). */
export function parseKey(key, prefix = '') {
  if (!key.startsWith(prefix) || !key.endsWith('.sql.gz')) return null;
  const parts = key.slice(prefix.length).split('/');
  if (parts.length !== 3 || parts.some((x) => !x)) return null;
  return { server: parts[0], db: parts[1], file: parts[2] };
}

// Every child is reachable from the Kill button / job timeout.
function cancellable(helpers) {
  const kids = new Set();
  const killAll = (sig) => { for (const c of kids) { try { c.kill(sig); } catch {} } };
  helpers.onCancel?.(() => { killAll('SIGTERM'); setTimeout(() => killAll('SIGKILL'), 5000).unref?.(); });
  return {
    killAll,
    spawnK(cmd, args, opts = {}) {
      const c = spawn(cmd, args, { shell: false, ...opts });
      kids.add(c);
      c.once('close', () => kids.delete(c));
      return c;
    },
  };
}
const collectStderr = (child, sink) => { let b = ''; child.stderr.setEncoding('utf8'); child.stderr.on('data', (c) => { b += c; }); child.stderr.on('end', () => b.split('\n').map((l) => l.trim()).filter(Boolean).forEach(sink)); };

async function loadTargets(helpers, roots) {
  const m = await cloneMap(helpers);
  try {
    return targetsFromMap(await readMapJson(m.mapPath, 'domain-map.json'), await readMapJson(m.serversPath, 'servers.json'), roots);
  } finally { await m.dispose(); }
}

// Dump ONE database to Spaces. Returns { key, size }.
async function backupOne(helpers, { info, warn }, s3, t, prefix, flags, suffix = '') {
  const secrets = await fs.mkdtemp(path.join(os.tmpdir(), 'bak-'));
  await fs.mkdir(WORK_DIR, { recursive: true, mode: 0o700 });
  const file = path.join(WORK_DIR, `${t.db}_${stampOf()}${suffix}.sql.gz`);
  try {
    const defaults = await writeDefaults(path.join(secrets, 'db.cnf'), { host: t.host, port: t.port, user: t.user, password: t.password, ssl: t.ssl }, flags.mariadbClient);
    const probe = await run(helpers, 'mysql', [`--defaults-file=${defaults}`, '-sNe', 'SELECT 1', t.db], { quiet: true });
    if (probe.code !== 0) throw new Error(`cannot connect to ${t.db} @ ${t.host}:${t.port} — ${probe.stderr.trim().split('\n').pop() || 'no detail'}`);

    const { spawnK, killAll } = cancellable(helpers);
    const dump = spawnK('mysqldump', [
      `--defaults-file=${defaults}`,
      ...(flags.dumpIsMariadb ? [] : ['--set-gtid-purged=OFF', '--column-statistics=0']),
      '--single-transaction', '--skip-lock-tables', '--no-tablespaces', '--hex-blob', t.db,
    ]);
    const errs = [];
    collectStderr(dump, (l) => errs.push(l));
    try {
      await pipeline(dump.stdout, progressStream((m, r) => info(`… ${m.toFixed(1)} MB dumped (${r.toFixed(1)} MB/s)`)), zlib.createGzip(), fsSync.createWriteStream(file, { mode: 0o600 }));
    } catch (e) { killAll('SIGKILL'); throw e; }
    const code = await exitOf(dump);
    if (code !== 0) throw new Error(`mysqldump failed (${code}): ${errs.slice(-2).join(' | ') || 'no detail'}`);
    for (const l of errs) warn(l);

    // An "empty" gzip is ~20 bytes; a real dump of even an empty DB has a header.
    const { size } = await fs.stat(file);
    if (size < 200) throw new Error(`the dump is only ${size} bytes — refusing to store an empty backup`);
    const key = `${prefix}${t.label}/${t.db}/${path.basename(file)}`;
    await s3.put(key, file);
    return { key, size };
  } finally {
    await removePath(file);
    await removePath(secrets);
  }
}

// params: { s3Endpoint, s3Region, s3Bucket, s3Key, s3Secret, prefix, roots?, keepLast, maxAgeDays }
export async function runDbBackup(job, helpers, p) {
  const { log, step, info, ok, warn, err } = logger(helpers);
  const s3 = clientFrom(p);

  step('Databases to back up (from seo-domain-map)');
  const targets = await loadTargets(helpers, p.roots);
  if (!targets.length) throw new Error(p.roots?.length ? `none of the chosen roots is in the map: ${p.roots.join(', ')}` : 'the map names no database');
  info(`${targets.length} database(s)${p.roots?.length ? ` for ${p.roots.length} chosen root(s)` : ' — all of them'}`);
  const flags = { mariadbClient: await clientIsMariadb(helpers, 'mysql'), dumpIsMariadb: await clientIsMariadb(helpers, 'mysqldump') };

  const failed = [];
  let total = 0;
  for (const [i, t] of targets.entries()) {
    step(`${i + 1}/${targets.length}  ${t.db} @ ${t.label}  (${t.roots.join(', ')})`);
    try {
      const started = Date.now();
      const r = await backupOne(helpers, { info, warn }, s3, t, p.prefix, flags);
      total += r.size;
      ok(`${mb(r.size)} -> ${r.key}  (${Math.round((Date.now() - started) / 1000)}s)`);

      if (p.keepLast || p.maxAgeDays) {
        const mine = (await s3.list(`${p.prefix}${t.label}/${t.db}/`)).filter((o) => parseKey(o.key, p.prefix));
        const gone = pickExpired(mine, { keepLast: p.keepLast, maxAgeDays: p.maxAgeDays });
        for (const o of gone) await s3.del(o.key);
        info(`retention: ${mine.length - gone.length} kept, ${gone.length} deleted`);
      }
    } catch (e) {
      failed.push(t.db);
      err(`${t.db}: ${e.message}`);
    }
  }

  log(`Backup finished: ${targets.length - failed.length}/${targets.length} database(s), ${mb(total)} uploaded`);
  if (failed.length) throw new Error(`${failed.length} database(s) failed: ${failed.join(', ')}`);
}

// params: { s3…, prefix, key, root, confirm, safety }
export async function runDbRestore(job, helpers, p) {
  const { log, step, info, ok, warn } = logger(helpers);
  const s3 = clientFrom(p);
  const from = parseKey(p.key, p.prefix);
  if (!from) throw new Error(`not a backup under "${p.prefix}": ${p.key}`);

  step(`Target database (root ${p.root})`);
  const [t] = await loadTargets(helpers, [p.root]);
  if (!t) throw new Error(`root '${p.root}' is not in the map`);
  if (p.confirm !== t.db) throw new Error(`confirmation does not match: ${p.root} uses database '${t.db}'`);
  info(`${t.db} @ ${t.label} (${t.host}:${t.port}) — used by: ${t.roots.join(', ')}`);
  if (from.db !== t.db) warn(`this backup is of '${from.db}', restoring it INTO '${t.db}'`);
  const flags = { mariadbClient: await clientIsMariadb(helpers, 'mysql'), dumpIsMariadb: await clientIsMariadb(helpers, 'mysqldump') };

  const secrets = await fs.mkdtemp(path.join(os.tmpdir(), 'rst-'));
  await fs.mkdir(WORK_DIR, { recursive: true, mode: 0o700 });
  const file = path.join(WORK_DIR, `restore_${stampOf()}_${from.file}`);
  try {
    step('Download the backup');
    await s3.get(p.key, file);
    const { size } = await fs.stat(file);
    ok(`${mb(size)} downloaded`);

    // The way back: what the database holds NOW, stored next to the others.
    if (p.safety !== false) {
      step(`Safety backup of ${t.db} as it is now`);
      const s = await backupOne(helpers, { info, warn }, s3, t, p.prefix, flags, '_pre-restore');
      ok(`${mb(s.size)} -> ${s.key}`);
    } else {
      warn('safety backup skipped — there is no way back from this restore');
    }

    step(`Import into ${t.db}`);
    const defaults = await writeDefaults(path.join(secrets, 'db.cnf'), { host: t.host, port: t.port, user: t.user, password: t.password, ssl: t.ssl }, flags.mariadbClient);
    const { spawnK, killAll } = cancellable(helpers);
    const sed = spawnK('sed', SED_ARGS, { env: { ...process.env, LC_ALL: 'C' } });
    const imp = spawnK('mysql', [`--defaults-file=${defaults}`, '--force',
      "--init-command=SET SESSION sql_mode='NO_ENGINE_SUBSTITUTION', unique_checks=0, foreign_key_checks=0", t.db]);
    const iErr = [];
    collectStderr(sed, (l) => warn(l));
    collectStderr(imp, (l) => iErr.push(l));
    try {
      await Promise.all([
        pipeline(fsSync.createReadStream(file), zlib.createGunzip(), sed.stdin),
        pipeline(sed.stdout, progressStream((m, r) => info(`… ${m.toFixed(1)} MB imported (${r.toFixed(1)} MB/s)`)), imp.stdin),
      ]);
    } catch (e) { killAll('SIGKILL'); throw e; }
    const [ic] = await Promise.all([exitOf(imp), exitOf(sed)]);
    for (const l of iErr) warn(l);
    if (ic !== 0) throw new Error(`mysql import failed (${ic}): ${iErr.slice(-2).join(' | ') || 'no detail'}`);
    ok('import complete');
    info('tables in the backup were replaced; tables that exist only in the database were left alone');
    info('purge the caches of the sites on this database (Sites → Purge) so they stop serving old pages');
    log(`Restored ${p.key} into ${t.db} @ ${t.label}`);
  } finally {
    await removePath(file);
    await removePath(secrets);
  }
}

// --- answered directly (no job): what is in the bucket, and does it work at all ---

/** { backups: [{ key, server, db, file, size, modified, safety }], databases: [{ server, db, roots }] } */
export async function listBackups(p) {
  const s3 = clientFrom(p);
  const objects = await s3.list(p.prefix);
  const backups = objects.map((o) => ({ ...o, ...parseKey(o.key, p.prefix) })).filter((o) => o.db)
    .map((o) => ({ key: o.key, server: o.server, db: o.db, file: o.file, size: o.size, modified: o.modified, safety: o.file.includes('_pre-restore') }))
    .sort((a, b) => new Date(b.modified) - new Date(a.modified));
  let databases = [];
  try { databases = (await loadTargets(silent)).map((t) => ({ server: t.label, db: t.db, roots: t.roots })); } catch { /* map unreachable: the list still helps */ }
  return { backups, databases };
}

/** Prove the credentials can list, write and delete under the prefix. */
export async function testStorage(p) {
  const s3 = clientFrom(p);
  const probe = path.join(os.tmpdir(), `wcp-probe-${process.pid}-${Date.now()}`);
  const key = `${p.prefix}.wcp-write-test`;
  await fs.writeFile(probe, 'ok');
  try {
    const found = await s3.list(p.prefix, { max: 1000 });
    await s3.put(key, probe);
    await s3.del(key);
    return { ok: true, objects: found.length };
  } finally { await removePath(probe); }
}
