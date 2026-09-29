import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import http from "node:http"; import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// ---- a fake Spaces (path-style S3): PUT / GET / DELETE / list-type=2 ----------
const store = new Map(); // key -> { body: Buffer, modified: ISO }
const seen = [];         // every request's Authorization header
const spaces = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  seen.push(req.headers.authorization || "");
  const [, bucket, ...rest] = decodeURIComponent(u.pathname).split("/");
  const key = rest.join("/");
  if (bucket !== "backups") { res.writeHead(404, { "content-type": "application/xml" }); return res.end("<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"); }
  if (!/^AWS4-HMAC-SHA256 Credential=GOODKEY\//.test(req.headers.authorization || "")) { res.writeHead(403); return res.end("<Error><Code>InvalidAccessKeyId</Code><Message>bad key</Message></Error>"); }
  if (req.method === "PUT") { const c = []; req.on("data", (d) => c.push(d)); return req.on("end", () => { store.set(key, { body: Buffer.concat(c), modified: new Date().toISOString() }); res.writeHead(200); res.end(); }); }
  if (req.method === "DELETE") { store.delete(key); res.writeHead(204); return res.end(); }
  if (req.method === "GET" && key) { const o = store.get(key); if (!o) { res.writeHead(404); return res.end("<Error><Code>NoSuchKey</Code></Error>"); } res.writeHead(200); return res.end(o.body); }
  const prefix = u.searchParams.get("prefix") || "";
  const items = [...store].filter(([k]) => k.startsWith(prefix)).map(([k, o]) => `<Contents><Key>${k}</Key><LastModified>${o.modified}</LastModified><Size>${o.body.length}</Size></Contents>`).join("");
  res.writeHead(200, { "content-type": "application/xml" }); res.end(`<ListBucketResult><IsTruncated>false</IsTruncated>${items}</ListBucketResult>`);
});
await new Promise((r) => spaces.listen(0, "127.0.0.1", r));
const endpoint = `http://127.0.0.1:${spaces.address().port}`;

// ---- a fake box: git (the map), mysqldump, mysql ------------------------------
const base = fs.mkdtempSync(path.join(os.tmpdir(), "dbbackup-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const imported = path.join(base, "imported.sql"), mysqlArgs = path.join(base, "mysql.args");
const stub = (n, body) => { fs.writeFileSync(path.join(bin, n), `#!/bin/bash\n${body}\n`); fs.chmodSync(path.join(bin, n), 0o755); };
const MAP = {
  "brand.tv": { DB_HOST: "10.0.0.1:3306", DB_NAME: "brand_db", DB_USER: "app", DB_PASSWORD: "DBPASSWORD-1" },
  "alias-of-brand.tv": { DB_HOST: "10.0.0.1:3306", DB_NAME: "brand_db", DB_USER: "app", DB_PASSWORD: "DBPASSWORD-1" }, // same database
  "other.tv": { DB_HOST: "10.0.0.2", DB_NAME: "other_db", DB_USER: "app", DB_PASSWORD: "DBPASSWORD-2" },
  "broken.tv": { DB_HOST: "10.0.0.2", DB_NAME: "broken_db", DB_USER: "app", DB_PASSWORD: "DBPASSWORD-3" },
  "half.tv": { DB_HOST: "10.0.0.2", DB_NAME: "" },
};
const SERVERS = { "db-sg1": { host: "10.0.0.1", port: 3306, ssl: "disabled" }, "db-sg2": { host: "10.0.0.2", port: 3307, ssl: "required" } };
stub("git", `dir="\${@: -1}"; mkdir -p "$dir"; cat > "$dir/domain-map.json" <<'J'\n${JSON.stringify(MAP)}\nJ\ncat > "$dir/servers.json" <<'J'\n${JSON.stringify(SERVERS)}\nJ`);
stub("mysqldump", `[ "$1" = "--version" ] && { echo "mysqldump Ver 8.0"; exit 0; }
db="\${@: -1}"; [ "$db" = broken_db ] && { echo "mysqldump: Got error: 1045: Access denied" >&2; exit 2; }
echo "-- dump of $db"; for i in $(seq 1 400); do echo "INSERT INTO t VALUES ($i,'$db-$RANDOM-$RANDOM');"; done`);
stub("mysql", `[ "$1" = "--version" ] && { echo "mysql Ver 8.0"; exit 0; }
echo "$*" >> "${mysqlArgs}"
case "$*" in *--force*) cat > "${imported}";; esac; exit 0`);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, BACKUP_DIR: path.join(base, "work") });

const { sign, EMPTY_SHA } = await import(path.join(A, "src/lib/s3.js"));
const { targetsFromMap, pickExpired, parseKey, listBackups, testStorage } = await import(path.join(A, "src/operations/dbbackup.js"));
const { operations } = await import(path.join(A, "src/operations/index.js"));
const S3 = { s3Endpoint: endpoint, s3Region: "sgp1", s3Bucket: "backups", s3Key: "GOODKEY", s3Secret: "SECRET-VALUE-NEVER-LOGGED", prefix: "wcp" };
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const keys = (p = "") => [...store.keys()].filter((k) => k.startsWith(p)).sort();

// 1) the signer reproduces AWS's two published SigV4 examples
const AWS = { host: "examplebucket.s3.amazonaws.com", payloadHash: EMPTY_SHA, region: "us-east-1", key: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", now: new Date("2013-05-24T00:00:00Z"), method: "GET" };
assert.equal(sign({ ...AWS, path: "/test.txt", headers: { Range: "bytes=0-9" } }).signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
assert.equal(sign({ ...AWS, path: "/", query: { "max-keys": "2", prefix: "J" } }).signature, "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7");
console.log("1. SigV4 signatures match AWS's published examples");

// 2) what gets backed up: one entry per server+database, incomplete map entries skipped
const t = targetsFromMap(MAP, SERVERS);
assert.deepEqual(t.map((x) => [x.label, x.db, x.port, x.roots.join("+")]), [["db-sg1", "brand_db", "3306", "brand.tv+alias-of-brand.tv"], ["db-sg2", "broken_db", "3307", "broken.tv"], ["db-sg2", "other_db", "3307", "other.tv"]]);
assert.deepEqual(targetsFromMap(MAP, SERVERS, ["other.tv"]).map((x) => x.db), ["other_db"]);
console.log("2. targets: two roots on one database = one backup; port/ssl from servers.json");

// 3) retention rules
const day = 86_400_000, now = Date.parse("2026-09-29T00:00:00Z");
const objs = [0, 1, 2, 5, 40].map((d) => ({ key: `k${d}`, modified: new Date(now - d * day).toISOString() }));
assert.deepEqual(pickExpired(objs, { keepLast: 3, now }).map((o) => o.key), ["k5", "k40"]);
assert.deepEqual(pickExpired(objs, { maxAgeDays: 30, now }).map((o) => o.key), ["k40"]);
assert.deepEqual(pickExpired(objs, { keepLast: 4, maxAgeDays: 1, now }).map((o) => o.key), ["k2", "k5", "k40"]);
assert.deepEqual(pickExpired(objs, {}).length, 0, "no rules = keep everything");
assert.deepEqual(pickExpired([{ key: "only", modified: new Date(now - 900 * day).toISOString() }], { maxAgeDays: 1, keepLast: 1, now }), [], "the newest backup is never deleted");
assert.deepEqual(parseKey("wcp/db-sg1/brand_db/brand_db_20260929_000000.sql.gz", "wcp/"), { server: "db-sg1", db: "brand_db", file: "brand_db_20260929_000000.sql.gz" });
assert.equal(parseKey("wcp/stray.txt", "wcp/"), null); assert.equal(parseKey("elsewhere/a/b/c.sql.gz", "wcp/"), null);
console.log("3. retention: keep-last and max-age combine; the newest backup always survives");

// 4) validation
const bad = (p) => operations.dbbackup.validate({ ...S3, ...p }).errors.join(" | ");
assert.match(bad({ s3Endpoint: "http://evil.example.com" }), /must be https/);
assert.match(bad({ s3Secret: "" }), /s3Secret is required/);
assert.match(bad({ prefix: "../etc" }), /prefix may only contain/);
assert.match(bad({ keepLast: -1 }), /keepLast must be/);
assert.match(bad({ roots: ["ok.com", "not a domain"] }), /roots must all be valid domains/);
const v = operations.dbbackup.validate({ ...S3, prefix: "/wcp/", roots: ["brand.tv", "other.tv"], keepLast: 2 });
assert.ok(v.ok, v.errors.join()); assert.equal(v.clean.prefix, "wcp/");
assert.match(operations.dbrestore.validate({ ...S3, key: "wcp/../x.sql.gz", root: "brand.tv", confirm: "brand_db" }).errors.join(), /key must be a backup object/);
console.log("4. bad endpoint / secret / prefix / retention / roots / key are refused");

// 5) storage test: list + write + delete a probe
assert.deepEqual(await testStorage(v.clean), { ok: true, objects: 0 });
assert.deepEqual(keys(), [], "the probe object is removed");
await assert.rejects(() => testStorage({ ...v.clean, s3Key: "WRONG" }), /HTTP 403 InvalidAccessKeyId/);
await assert.rejects(() => testStorage({ ...v.clean, s3Bucket: "nope" }), /HTTP 404 NoSuchBucket/);
console.log("5. storage test proves list+write+delete, and names the reason when it fails");

// 6) a backup run: objects land under <prefix><server>/<db>/, old ones are pruned
for (const d of [3, 9]) store.set(`wcp/db-sg1/brand_db/brand_db_old${d}.sql.gz`, { body: Buffer.from("x"), modified: new Date(Date.now() - d * day).toISOString() });
await operations.dbbackup.run({ id: "j1" }, helpers, v.clean);
const brand = keys("wcp/db-sg1/brand_db/");
assert.equal(brand.length, 2, "keepLast 2: the new one + the newest old one");
assert.ok(brand.some((k) => /brand_db_\d{8}_\d{6}\.sql\.gz$/.test(k)) && brand.some((k) => k.endsWith("old3.sql.gz")));
assert.equal(keys("wcp/db-sg2/other_db/").length, 1);
const dump = zlib.gunzipSync(store.get(brand.find((k) => !k.includes("old"))).body).toString();
assert.match(dump, /^-- dump of brand_db/);
const out = lines.join("\n");
assert.ok(!out.includes(S3.s3Secret) && !out.includes("DBPASSWORD"), "no secret reaches the job log");
assert.ok(!fs.existsSync(process.env.BACKUP_DIR) || fs.readdirSync(process.env.BACKUP_DIR).length === 0, "no dump file left on disk");
assert.ok(seen.every((a) => a.startsWith("AWS4-HMAC-SHA256 Credential=")), "every request is signed");
console.log("6. backup: gzip dumps uploaded, retention applied, nothing secret logged, temp files removed");

// 7) one database failing does not stop the others — and fails the job
await new Promise((r) => setTimeout(r, 1100)); // object names carry a 1-second stamp
lines.length = 0;
const all = operations.dbbackup.validate({ ...S3 }).clean;
await assert.rejects(() => operations.dbbackup.run({ id: "j2" }, helpers, all), /1 database\(s\) failed: broken_db/);
assert.match(lines.join("\n"), /mysqldump failed \(2\).*Access denied/);
assert.equal(keys("wcp/db-sg2/other_db/").length, 2, "other_db was still backed up");
assert.equal(keys("wcp/db-sg2/broken_db/").length, 0);
console.log("7. a failing database is reported, the rest still run, the job is marked failed");

// 8) listing: backups newest first + which roots use each database
const l = await listBackups(all);
assert.ok(l.backups.length >= 4 && l.backups.every((b) => b.db && b.server && b.size > 0));
assert.deepEqual(l.databases.find((d) => d.db === "brand_db").roots, ["brand.tv", "alias-of-brand.tv"]);
console.log("8. list: backups with server/db/size/date, and the roots on each database");

// 9) restore
await new Promise((r) => setTimeout(r, 1100));
const key = brand.find((k) => !k.includes("old"));
const rs = (p) => operations.dbrestore.validate({ ...S3, key, root: "brand.tv", confirm: "brand_db", ...p });
await assert.rejects(() => operations.dbrestore.run({ id: "j3" }, helpers, rs({ confirm: "other_db" }).clean), /confirmation does not match: brand\.tv uses database 'brand_db'/);
assert.ok(!fs.existsSync(imported), "nothing was imported after a wrong confirmation");
await operations.dbrestore.run({ id: "j4" }, helpers, rs({}).clean);
assert.match(fs.readFileSync(imported, "utf8"), /^-- dump of brand_db/, "the backup's SQL reached mysql, gunzipped");
assert.match(fs.readFileSync(mysqlArgs, "utf8"), /--force .*unique_checks=0.* brand_db/);
assert.equal(keys("wcp/db-sg1/brand_db/").filter((k) => k.endsWith("_pre-restore.sql.gz")).length, 1, "a safety backup was taken first");
assert.ok((await listBackups(all)).backups.find((b) => b.safety), "safety backups are flagged in the list");
console.log("9. restore: wrong confirmation refused; safety backup first, then the import");

console.log("\nPASS: databases are backed up to Spaces with retention, listed, and restored safely");
spaces.close(); fs.rmSync(base, { recursive: true, force: true });
