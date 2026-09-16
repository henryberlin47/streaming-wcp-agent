import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import { run, pathExists, removePath } from '../lib/sys.js';
import { cloneMap, readMapJson } from '../lib/map.js';
import { writeDefaults, clientIsMariadb, progressStream } from '../lib/mysql.js';
import { logger } from '../lib/log.js';

// ============================================================
//  migrate — native port of db-migrate-site.sh
// ============================================================
// Moves one domain's WordPress database to another database server, using the
// seo-domain-map as the single source of truth:
//   source = domain-map.json[<domain>] -> DB_NAME/DB_USER/DB_PASSWORD + DB_HOST,
//            reverse-looked-up in servers.json for port + ssl
//   dest   = servers.json[<destServer>] -> host + port + ssl
//   creds  = the SAME map entry both sides (the map user holds ALL PRIVILEGES
//            ON *.* everywhere, so it creates the destination DB itself).
// Modes: all (dump+import) | dump | import (needs file) | pipe (stream).
// newDomain registers the CLONE in domain-map.json and pushes it.
// The interactive pickers/confirm are gone — the panel supplies everything.
// ============================================================

const DUMP_DIR = process.env.DUMP_DIR || '/var/backups/db-migrations';

const normHost = (h) => String(h || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
const exitOf = (child) =>
  new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code) => resolve(code ?? -1));
  });

// Stream a child's stderr into the job log, line by line.
function pipeStderr(child, sink) {
  let b = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (c) => {
    b += c;
    let i;
    while ((i = b.indexOf('\n')) >= 0) {
      const l = b.slice(0, i).trim();
      b = b.slice(i + 1);
      if (l) sink(l);
    }
  });
  child.stderr.on('end', () => {
    if (b.trim()) sink(b.trim());
  });
}

// params: { domain, destServer, mode, destDb?, file?, newDomain?, cdnPrefix? }
export async function runMigrate(job, helpers, p, opts = {}) {
  const { log, info, ok, warn } = logger(helpers, opts);
  const domain = p.domain;
  const destServer = p.destServer;
  const mode = p.mode || 'all';
  const wantRegister = !!p.newDomain;

  for (const bin of ['mysql', 'mysqldump', 'sed', 'git']) {
    const r = await run(helpers, 'which', [bin], { quiet: true });
    if (r.code !== 0) throw new Error(`missing required binary: ${bin}`);
  }

  // Registering re-applies its edit onto the latest main — needs a full clone.
  const m = await cloneMap(helpers, { full: wantRegister });
  const secretsDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mig-'));
  await fs.chmod(secretsDir, 0o700).catch(() => {});

  try {
    const map = await readMapJson(m.mapPath, 'domain-map.json');
    const servers = await readMapJson(m.serversPath, 'servers.json');

    if (!Object.prototype.hasOwnProperty.call(map, domain)) {
      throw new Error(`domain not found in domain-map.json: ${domain}`);
    }
    if (!Object.prototype.hasOwnProperty.call(servers, destServer)) {
      throw new Error(`server not found in servers.json: ${destServer}`);
    }

    // --- source (map entry) ---
    const e = map[domain] || {};
    const SRC_DB_NAME = e.DB_NAME || '';
    const SRC_DB_USER = e.DB_USER || '';
    const SRC_DB_PASS = e.DB_PASSWORD || '';
    const SRC_RAW = e.DB_HOST || '';
    for (const [k, v] of [['DB_NAME', SRC_DB_NAME], ['DB_USER', SRC_DB_USER], ['DB_PASSWORD', SRC_DB_PASS], ['DB_HOST', SRC_RAW]]) {
      if (!v) throw new Error(`domain-map.json[${domain}].${k} is empty`);
    }
    const SRC_HOST = SRC_RAW.split(':')[0];
    let SRC_PORT = SRC_RAW.includes(':') ? SRC_RAW.split(':')[1] : '';

    // servers.json reverse lookup for the source's port + ssl
    let SRC_SERVER = Object.keys(servers).find((k) => servers[k] && servers[k].host === SRC_HOST) || '';
    let SRC_SSL;
    if (SRC_SERVER) {
      SRC_PORT = SRC_PORT || String(servers[SRC_SERVER].port ?? 3306);
      SRC_SSL = servers[SRC_SERVER].ssl ?? 'required';
    } else {
      SRC_SERVER = '(unlisted)';
      SRC_PORT = SRC_PORT || '3306';
      SRC_SSL = 'required';
    }

    // --- destination (servers.json); credentials come from the map ---
    const d = servers[destServer] || {};
    const DEST_HOST = d.host || '';
    const DEST_PORT = String(d.port ?? 3306);
    const DEST_SSL = d.ssl ?? 'disabled';
    if (!DEST_HOST) throw new Error(`servers.json[${destServer}].host is missing`);
    const DEST_DB = p.destDb || SRC_DB_NAME;

    if (SRC_HOST === DEST_HOST && String(SRC_PORT) === DEST_PORT && SRC_DB_NAME === DEST_DB) {
      throw new Error(`source and destination are the same database (${SRC_HOST}:${SRC_PORT}/${SRC_DB_NAME}) — nothing to do`);
    }

    // --- clone-registration guards ---
    let NEW_DOMAIN = '';
    let CDN_PREFIX = '';
    if (wantRegister) {
      if (mode === 'dump') throw new Error('newDomain has nothing to register in dump mode — no destination was written');
      // A move keeps the database name. Registering it would point the map at the
      // new server while the live site's .env still writes to the old one.
      if (DEST_DB === SRC_DB_NAME) {
        throw new Error(`newDomain applies to a clone: destDb must differ from the source database (${SRC_DB_NAME})`);
      }
      NEW_DOMAIN = normHost(p.newDomain);
      CDN_PREFIX = p.cdnPrefix || NEW_DOMAIN.split('.')[0];
      if (Object.prototype.hasOwnProperty.call(map, NEW_DOMAIN)) {
        throw new Error(`${NEW_DOMAIN} is already in domain-map.json — refusing to overwrite it`);
      }
    }

    // --- client plumbing ---
    const mariadbClient = await clientIsMariadb(helpers, 'mysql');
    const dumpIsMariadb = await clientIsMariadb(helpers, 'mysqldump');
    const srcDefaults = await writeDefaults(path.join(secretsDir, 'src.cnf'),
      { host: SRC_HOST, port: SRC_PORT, user: SRC_DB_USER, password: SRC_DB_PASS, ssl: SRC_SSL }, mariadbClient);
    const dstDefaults = await writeDefaults(path.join(secretsDir, 'dst.cnf'),
      { host: DEST_HOST, port: DEST_PORT, user: SRC_DB_USER, password: SRC_DB_PASS, ssl: DEST_SSL }, mariadbClient);

    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '_');
    const DUMP_FILE = `${DUMP_DIR}/${SRC_DB_NAME}_${stamp}.sql.gz`;

    info(`Source : ${SRC_DB_NAME} @ ${SRC_SERVER} (${SRC_HOST}:${SRC_PORT}, ssl=${SRC_SSL})`);
    info(`Dest   : ${DEST_DB} @ ${destServer} (${DEST_HOST}:${DEST_PORT}, ssl=${DEST_SSL})`);
    info(`User   : ${SRC_DB_USER} (from domain-map.json, both sides)   Mode: ${mode}`);
    if (SRC_SERVER === '(unlisted)') {
      warn('Source host is not in servers.json — assuming ssl=required. Add it for an accurate port/SSL.');
    }

    const q = (defaults, sql, db) =>
      run(helpers, 'mysql', [`--defaults-file=${defaults}`, '-sNe', sql, ...(db ? [db] : [])], { quiet: true });

    let SRC_VER = '';
    let DST_VER = '';

    const testSource = async () => {
      const r = await q(srcDefaults, 'SELECT 1', SRC_DB_NAME);
      if (r.code !== 0) {
        throw new Error(`cannot connect to source ${SRC_DB_NAME} @ ${SRC_SERVER} (${SRC_HOST}:${SRC_PORT}) — IP whitelisted? ${r.stderr.trim()}`);
      }
      SRC_VER = (await q(srcDefaults, 'SELECT VERSION();', SRC_DB_NAME)).stdout.trim();
      ok(`Source ready: ${SRC_DB_NAME} @ ${SRC_SERVER} (MySQL ${SRC_VER})`);
    };

    // The map's user holds ALL PRIVILEGES ON *.* on every database server, so it
    // creates the destination itself. No admin credential is involved.
    const ensureDestination = async () => {
      if ((await q(dstDefaults, 'SELECT 1', DEST_DB)).code === 0) {
        DST_VER = (await q(dstDefaults, 'SELECT VERSION();', DEST_DB)).stdout.trim();
        ok(`Destination ready: ${DEST_DB} @ ${destServer} (MySQL ${DST_VER})`);
        return;
      }
      if ((await q(dstDefaults, 'SELECT 1')).code !== 0) {
        throw new Error(`'${SRC_DB_USER}' cannot authenticate on ${destServer} (${DEST_HOST}:${DEST_PORT})`);
      }
      info(`Creating '${DEST_DB}' on ${destServer} as '${SRC_DB_USER}'`);
      let r = await run(helpers, 'mysql',
        [`--defaults-file=${dstDefaults}`, '-e', `CREATE DATABASE IF NOT EXISTS \`${DEST_DB}\` DEFAULT CHARACTER SET utf8mb4`], { quiet: true });
      if (r.code !== 0) {
        throw new Error(`'${SRC_DB_USER}' cannot CREATE DATABASE '${DEST_DB}' on ${destServer} — check SHOW GRANTS FOR CURRENT_USER()`);
      }
      // CREATE alone does not imply write access — prove it before streaming into it.
      r = await run(helpers, 'mysql',
        [`--defaults-file=${dstDefaults}`, '-e', 'CREATE TABLE `_ba_migrate_probe` (i int); DROP TABLE `_ba_migrate_probe`;', DEST_DB], { quiet: true });
      if (r.code !== 0) {
        throw new Error(`'${SRC_DB_USER}' created '${DEST_DB}' but cannot write to it on ${destServer}`);
      }
      DST_VER = (await q(dstDefaults, 'SELECT VERSION();', DEST_DB)).stdout.trim();
      ok(`Destination ready: created ${DEST_DB} @ ${destServer} (MySQL ${DST_VER})`);
    };

    const versionDriftWarn = () => {
      if (/^8\.0\./.test(SRC_VER) && /^8\.4\./.test(DST_VER)) {
        warn('Version drift 8.0 -> 8.4: wp_match_list generated-column syntax may fail on import.');
      }
    };

    // GTID/column-statistics are MySQL-only concepts; mariadb-dump rejects the flags.
    const dumpArgs = () => [
      `--defaults-file=${srcDefaults}`,
      ...(dumpIsMariadb ? [] : ['--set-gtid-purged=OFF', '--column-statistics=0']),
      '--single-transaction', '--skip-lock-tables', '--no-tablespaces', '--hex-blob',
      SRC_DB_NAME,
    ];
    // unique_checks/foreign_key_checks off = the import stops re-validating every
    // secondary index and FK per row, which is what drags a big WP table's import
    // down to a few MB/s. Session-scoped, safe on a fresh import (the dump is
    // internally consistent). Both are MySQL & MariaDB session vars.
    const importArgs = () => [
      `--defaults-file=${dstDefaults}`, '--force',
      "--init-command=SET SESSION sql_mode='NO_ENGINE_SUBSTITUTION', unique_checks=0, foreign_key_checks=0",
      DEST_DB,
    ];

    // Liveness/throughput heartbeat so a long transfer isn't a silent black box.
    const tick = (mb, rate) => info(`… ${mb.toFixed(1)} MB transferred (${rate.toFixed(1)} MB/s)`);

    // normalize_stream from db-migrate-site.sh, verbatim: rewrite MySQL-8
    // collations MariaDB doesn't know and strip DEFINER=. Run as `sed` (a
    // separate, constant-memory process) exactly like the shell script — NOT a
    // Node Transform, which buffered whole lines and froze the event loop on a
    // multi-MB --hex-blob row. LC_ALL=C makes sed byte-oriented (safe on UTF-8).
    const SED_ARGS = [
      '-e', 's/utf8mb4_0900_ai_ci/utf8mb4_unicode_ci/g',
      '-e', 's/utf8mb4_0900_as_ci/utf8mb4_unicode_ci/g',
      '-e', 's/utf8mb4_0900_as_cs/utf8mb4_unicode_ci/g',
      '-e', 's/utf8mb4_0900_bin/utf8mb4_bin/g',
      '-e', 's/[[:space:]]DEFINER=`[^`]*`@`[^`]*`//g',
    ];
    const spawnSed = (spawnK) => spawnK('sed', SED_ARGS, { env: { ...process.env, LC_ALL: 'C' } });

    // A stuck migration must be killable: the Kill button + job timeout fire
    // helpers.onCancel, so every child we spawn has to be reachable from it.
    // Registered per do-step (after the run()-based preflight, whose own cancel
    // hooks would otherwise clobber ours).
    const startCancellable = () => {
      const kids = new Set();
      const killAll = (sig) => { for (const c of kids) { try { c.kill(sig); } catch {} } };
      helpers.onCancel?.(() => { killAll('SIGTERM'); setTimeout(() => killAll('SIGKILL'), 5000).unref?.(); });
      const spawnK = (cmd, args, opts = {}) => {
        const c = spawn(cmd, args, { shell: false, ...opts });
        kids.add(c);
        c.once('close', () => kids.delete(c));
        return c;
      };
      return { spawnK, killAll };
    };

    const doDump = async () => {
      await fs.mkdir(DUMP_DIR, { recursive: true, mode: 0o700 });
      await fs.chmod(DUMP_DIR, 0o700).catch(() => {});
      info(`DUMP ${SRC_DB_NAME} @ ${SRC_SERVER}  ->  ${DUMP_FILE}`);
      const { spawnK, killAll } = startCancellable();
      const dump = spawnK('mysqldump', dumpArgs());
      const errs = [];
      pipeStderr(dump, (l) => { errs.push(l); warn(l); });
      try {
        await pipeline(dump.stdout, progressStream(tick), zlib.createGzip(), fsSync.createWriteStream(DUMP_FILE, { mode: 0o600 }));
      } catch (e) { killAll('SIGKILL'); throw e; }
      const code = await exitOf(dump);
      if (code !== 0) throw new Error(`mysqldump failed (${code}): ${errs.slice(-3).join(' | ')}`);
      const { size } = await fs.stat(DUMP_FILE);
      ok(`Dump complete (${(size / 1048576).toFixed(1)} MB)`);
    };

    const doImport = async (file) => {
      if (!(await pathExists(file))) throw new Error(`dump file not found: ${file}`);
      info(`IMPORT -> ${DEST_DB} @ ${destServer}  (normalizing MySQL 8 collations for MariaDB compatibility)`);
      const { spawnK, killAll } = startCancellable();
      const sed = spawnSed(spawnK);
      const imp = spawnK('mysql', importArgs());
      const sErr = []; const iErr = [];
      pipeStderr(sed, (l) => { sErr.push(l); warn(l); });
      pipeStderr(imp, (l) => { iErr.push(l); warn(l); });
      // file -> (gunzip) -> sed -> progress -> mysql, mirroring the shell pipe.
      const src = fsSync.createReadStream(file);
      const inLeg = file.endsWith('.gz')
        ? pipeline(src, zlib.createGunzip(), sed.stdin)
        : pipeline(src, sed.stdin);
      try {
        await Promise.all([inLeg, pipeline(sed.stdout, progressStream(tick), imp.stdin)]);
      } catch (e) { killAll('SIGKILL'); throw e; }
      const [ic] = await Promise.all([exitOf(imp), exitOf(sed)]);
      if (ic !== 0) throw new Error(`mysql import failed (${ic}): ${iErr.slice(-3).join(' | ')}`);
      ok('Import complete (review any --force-skipped errors above)');
    };

    const doPipe = async () => {
      info(`PIPE ${SRC_DB_NAME} @ ${SRC_SERVER}  ->  ${DEST_DB} @ ${destServer}  (streaming, no intermediate file)`);
      const { spawnK, killAll } = startCancellable();
      const dump = spawnK('mysqldump', dumpArgs());
      const sed = spawnSed(spawnK);
      const imp = spawnK('mysql', importArgs());
      const dErr = []; const sErr = []; const iErr = [];
      pipeStderr(dump, (l) => { dErr.push(l); warn(l); });
      pipeStderr(sed, (l) => { sErr.push(l); warn(l); });
      pipeStderr(imp, (l) => { iErr.push(l); warn(l); });
      // mysqldump -> sed -> progress -> mysql, matching dump_cmd | normalize_stream | import_cmd.
      try {
        await Promise.all([
          pipeline(dump.stdout, sed.stdin),
          pipeline(sed.stdout, progressStream(tick), imp.stdin),
        ]);
      } catch (e) { killAll('SIGKILL'); throw e; }
      const [dc, ic] = await Promise.all([exitOf(dump), exitOf(imp), exitOf(sed)]);
      if (dc !== 0) throw new Error(`mysqldump failed (${dc}): ${dErr.slice(-3).join(' | ')}`);
      if (ic !== 0) throw new Error(`mysql import failed (${ic}): ${iErr.slice(-3).join(' | ')}`);
      ok('Stream import complete (review any --force-skipped errors above)');
    };

    // Add the cloned database to domain-map.json and push it. Read-modify-write
    // with retry: each attempt re-applies the edit onto the freshly fetched main,
    // so two servers registering at once can never clobber one another.
    const registerNewDomain = async () => {
      const entry = {
        DB_HOST: `${DEST_HOST}:${DEST_PORT}`,
        DB_NAME: DEST_DB,
        DB_USER: SRC_DB_USER,
        DB_PASSWORD: SRC_DB_PASS,
        CDN_PREFIX,
      };
      const gitEmail = `db-migrate-site@${os.hostname() || 'localhost'}`;
      const git = (...args) => run(helpers, 'git', ['-C', m.dir, ...args], { quiet: true });

      for (let attempt = 1; attempt <= 3; attempt++) {
        if ((await git('fetch', '--quiet', 'origin', 'main')).code !== 0 ||
            (await git('reset', '--quiet', '--hard', 'origin/main')).code !== 0) {
          warn('Could not refresh the map clone.');
          return false;
        }

        const raw = await fs.readFile(m.mapPath, 'utf8');
        let cur;
        try { cur = JSON.parse(raw); } catch { warn('domain-map.json is not valid JSON — aborting.'); return false; }

        if (Object.prototype.hasOwnProperty.call(cur, NEW_DOMAIN)) {
          warn(`${NEW_DOMAIN} was added to domain-map.json upstream — leaving it alone.`);
          return false;
        }

        // domain-map.json is tab-indented. Rewrite it only if our formatter
        // reproduces it byte-for-byte; otherwise a one-entry add reformats every
        // record. Fails closed.
        if (JSON.stringify(cur, null, '\t') + '\n' !== raw) {
          warn('tab-JSON does not reproduce domain-map.json byte-for-byte — refusing to rewrite it.');
          return false;
        }

        const next = { ...cur, [NEW_DOMAIN]: entry };
        // Exactly one new key, every other entry untouched (order included).
        const { [NEW_DOMAIN]: _added, ...rest } = next;
        if (JSON.stringify(rest) !== JSON.stringify(cur) ||
            Object.keys(next).length !== Object.keys(cur).length + 1) {
          warn(`Generated map alters entries other than ${NEW_DOMAIN} — aborting.`);
          return false;
        }

        await fs.writeFile(m.mapPath, JSON.stringify(next, null, '\t') + '\n');
        if ((await git('add', 'domain-map.json')).code !== 0) return false;

        // A clean append deletes no lines (git aligns the trailing brace, so the
        // new entry is a pure insertion). Anything else means it got reformatted.
        const ns = await git('diff', '--cached', '--numstat', '--', 'domain-map.json');
        const dels = ns.stdout.trim().split('\t')[1] ?? '1';
        if (dels !== '0') {
          warn(`Refusing to push: the edit removed ${dels} line(s) — domain-map.json would be reformatted.`);
          await git('reset', '--quiet', '--hard', 'origin/main');
          return false;
        }

        const commit = await git(
          '-c', 'user.name=db-migrate-site', '-c', `user.email=${gitEmail}`,
          'commit', '--quiet', '-m', `chore: add ${NEW_DOMAIN} -> ${DEST_DB} @ ${destServer}`
        );
        if (commit.code !== 0) { warn('Could not commit the map edit.'); return false; }

        if ((await git('push', '--quiet', 'origin', 'main')).code === 0) {
          ok(`Registered ${NEW_DOMAIN} in domain-map.json (CDN_PREFIX=${CDN_PREFIX}) and pushed`);
          return true;
        }
        warn(`Push rejected (attempt ${attempt}/3) — refetching and retrying`);
      }
      return false;
    };

    // --- run the mode ---
    if (mode === 'dump') {
      await testSource();
      await doDump();
      info(`Stopped after dump. Import later with mode=import and file=${DUMP_FILE}`);
    } else if (mode === 'import') {
      if (!p.file) throw new Error('import mode needs a dump file path');
      await ensureDestination();
      await doImport(p.file);
    } else if (mode === 'pipe') {
      await testSource();
      await ensureDestination();
      versionDriftWarn();
      await doPipe();
    } else if (mode === 'all') {
      await testSource();
      await ensureDestination();
      versionDriftWarn();
      await doDump();
      await doImport(DUMP_FILE);
    } else {
      throw new Error(`unknown mode: ${mode}`);
    }

    let registered = false;
    if (wantRegister && mode !== 'dump') {
      registered = await registerNewDomain();
      if (!registered) warn(`Could not register ${NEW_DOMAIN} — add the entry by hand.`);
    }

    // `dump` writes nothing to the destination, so there is nothing to follow up on.
    if (mode !== 'dump') {
      if (DEST_DB === SRC_DB_NAME) {
        // Same database name: the domain was MOVED to another server.
        info(`NEXT STEPS — moved ${SRC_DB_NAME} to ${destServer}. Repoint ${domain}:`);
        info(`  1. In domain-map.json set DB_HOST=${DEST_HOST}:${DEST_PORT} for ${domain}, commit + push.`);
        info('  2. Update DB_HOST in /var/www/<domain>/htdocs/src/.env on every site using it.');
        info('  3. systemctl restart php8.3-fpm (clears OPcache), then verify the site loads.');
        info(`  4. Once verified, drop the old ${SRC_DB_NAME} on ${SRC_SERVER}.`);
      } else {
        // New database name: the source was CLONED as a base for another site.
        info(`NEXT STEPS — cloned ${SRC_DB_NAME} -> ${DEST_DB}. ${domain} is untouched; nothing to restart.`);
        if (registered) {
          info(`  1. domain-map.json already has ${NEW_DOMAIN} -> ${DEST_DB} (committed + pushed).`);
          info(`  2. Deploy the site with root=${NEW_DOMAIN}.`);
          info(`  3. Rewrite the cloned URLs: cleanup ${NEW_DOMAIN} <- ${domain}.`);
        } else {
          info(`  1. Add a domain-map.json entry for the new root: DB_HOST=${DEST_HOST}:${DEST_PORT} DB_NAME=${DEST_DB} DB_USER=${SRC_DB_USER} (same password + CDN_PREFIX).`);
          info('  2. Deploy the site with that root.');
          info(`  3. Rewrite the cloned URLs from ${domain}.`);
        }
      }
    }

    log(`Migrate (${mode}) done: ${domain} -> ${DEST_DB} @ ${destServer}`);
  } finally {
    // Both hold credentials — never leave them behind.
    await m.dispose();
    await removePath(secretsDir);
  }
}

