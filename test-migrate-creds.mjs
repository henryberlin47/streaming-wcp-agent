import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake estate: a real (local, bare) git repo standing in for seo-domain-map, and mysql / mysqldump stand-ins
// that know each database server's OWN password — the source's password is refused on the destination,
// which is exactly what broke migrations after the per-server rotation.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "migcreds-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const stub = (name, body) => { fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`); fs.chmodSync(path.join(bin, name), 0o755); };
const PW = { "10.0.0.1": "PW-of-DB01", "10.0.0.11": "PW-of-DB11", "10.0.0.12": "PW-of-DB12", "10.0.0.13": "PW-of-DB13" };
const MAP = {
  "brand.tv": { DB_HOST: "10.0.0.1:3306", DB_NAME: "brand_db", DB_USER: "app", DB_PASSWORD: PW["10.0.0.1"], CDN_PREFIX: "brand" },
  "other.tv": { DB_HOST: "10.0.0.11:3306", DB_NAME: "other_db", DB_USER: "app", DB_PASSWORD: PW["10.0.0.11"], CDN_PREFIX: "other" },
  "third.tv": { DB_HOST: "10.0.0.11", DB_NAME: "third_db", DB_USER: "app", DB_PASSWORD: PW["10.0.0.11"], CDN_PREFIX: "third" },
  "legacy.tv": { DB_HOST: "10.0.0.11:3306", DB_NAME: "legacy_db", DB_USER: "legacy", DB_PASSWORD: "someone-elses", CDN_PREFIX: "legacy" },
  "wrong.tv": { DB_HOST: "10.0.0.13:3306", DB_NAME: "wrong_db", DB_USER: "app", DB_PASSWORD: "stale-in-the-map", CDN_PREFIX: "wrong" },
};
const SERVERS = { "DB-01": { host: "10.0.0.1", port: 3306, ssl: "disabled" }, "DB-11": { host: "10.0.0.11", port: 3306, ssl: "disabled" }, "DB-12": { host: "10.0.0.12", port: 3306, ssl: "disabled" }, "DB-13": { host: "10.0.0.13", port: 3306, ssl: "disabled" } };
const realGit = execFileSync("which", ["git"]).toString().trim();
const git = (cwd, ...a) => execFileSync(realGit, ["-C", cwd, "-c", "user.name=t", "-c", "user.email=t@t", ...a], { stdio: "pipe" }).toString();
const bare = path.join(base, "map.git"); execFileSync(realGit, ["init", "-q", "--bare", "-b", "main", bare]);
const seed = path.join(base, "seed"); execFileSync(realGit, ["clone", "-q", bare, seed], { stdio: "pipe" });
fs.writeFileSync(path.join(seed, "domain-map.json"), JSON.stringify(MAP, null, "\t") + "\n"); fs.writeFileSync(path.join(seed, "servers.json"), JSON.stringify(SERVERS, null, "\t") + "\n");
git(seed, "checkout", "-q", "-B", "main"); git(seed, "add", "."); git(seed, "commit", "-q", "-m", "seed"); git(seed, "push", "-q", "origin", "main");
// git: the private map URL is answered from the local repo; everything else is real git
stub("git", `args=(); for a in "$@"; do case "$a" in git@github.com:*seo-domain-map.git) a="${bare}";; esac; args+=("$a"); done; exec ${realGit} "\${args[@]}"`);
// mysql: logs who logged in where (test-only), refuses a password that is not that server's own
fs.mkdirSync(path.join(base, "db/10.0.0.1"), { recursive: true }); fs.writeFileSync(path.join(base, "db/10.0.0.1/brand_db"), "");
fs.writeFileSync(path.join(base, "passwords"), Object.entries(PW).map(([h, p]) => `${h} ${p}`).join("\n") + "\n");
stub("mysql", `[ "$1" = "--version" ] && { echo "mysql  Ver 8.0.36"; exit 0; }
f="\${1#--defaults-file=}"; host=$(sed -n 's/^host=//p' "$f"); pw=$(sed -n 's/^password="\\(.*\\)"$/\\1/p' "$f")
echo "$host $pw" >> "${base}/logins"
want=$(sed -n "s/^$host //p" "${base}/passwords")
[ "$pw" = "$want" ] || { echo "mysql: [Warning] Deprecated program name." >&2; echo "ERROR 1045 (28000): Access denied for user 'app'@'10.9.9.9' (using password: YES)" >&2; exit 1; }
mkdir -p "${base}/db/$host"; last="\${@: -1}"
case "$*" in
  *"CREATE DATABASE"*) touch "${base}/db/$host/$(echo "$*" | sed 's/.*\`\\(.*\\)\`.*/\\1/')"; exit 0;;
  *--force*) cat > "${base}/db/$host/$last"; exit 0;;
  *"SELECT VERSION"*) echo "8.0.36"; exit 0;;
  *"SELECT 1") echo 1; exit 0;;
  *"SELECT 1 "*|*"_ba_migrate_probe"*) [ -e "${base}/db/$host/$last" ] || { echo "ERROR 1049 (42000): Unknown database '$last'" >&2; exit 1; }; echo 1; exit 0;;
esac`);
stub("mysqldump", `[ "$1" = "--version" ] && { echo "mysqldump  Ver 8.0.36"; exit 0; }
echo "CREATE TABLE t (a int) COLLATE=utf8mb4_0900_ai_ci;"; echo "INSERT INTO t VALUES (1);"`);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, DUMP_DIR: path.join(base, "dumps") });
delete process.env.DEST_DB_PASSWORD;

const { operations } = await import(path.join(A, "src/operations/index.js"));
const { destPassword } = await import(path.join(A, "src/operations/migrate.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const go = (p) => { const v = operations.migrate.validate(p); assert.ok(v.ok, v.errors.join()); lines.length = 0; fs.rmSync(path.join(base, "logins"), { force: true }); return operations.migrate.run({ id: "j" }, helpers, v.clean); };
const logins = () => fs.readFileSync(path.join(base, "logins"), "utf8").trim().split("\n");
const noSecrets = () => { const out = lines.join("\n"); for (const p of [...Object.values(PW), "stale-in-the-map", "someone-elses", "from-the-agent-env"]) assert.ok(!out.includes(p), "a password reached the job log"); };

// ---- 1) which password the destination gets ----------------------------------------------
assert.deepEqual(destPassword(MAP, "10.0.0.11", "app"), { password: PW["10.0.0.11"], from: "domain-map.json" }, "from the entries hosted there (with or without :port), one distinct value");
assert.deepEqual(destPassword(MAP, "10.0.0.1", "app"), { password: PW["10.0.0.1"], from: "domain-map.json" });
assert.throws(() => destPassword(MAP, "10.0.0.12", "app", "", "DB-12"), /no domain-map\.json entry on DB-12 \(10\.0\.0\.12\) uses 'app'.*DEST_DB_PASSWORD/s, "another user's entry or another server's does not count");
assert.deepEqual(destPassword(MAP, "10.0.0.12", "app", "x"), { password: "x", from: "DEST_DB_PASSWORD" });
assert.deepEqual(destPassword(MAP, "10.0.0.11", "app", "x").from, "domain-map.json", "the map wins over the fallback");
assert.throws(() => destPassword({ ...MAP, "split.tv": { DB_HOST: "10.0.0.11", DB_USER: "app", DB_PASSWORD: "different" } }, "10.0.0.11", "app", "x", "DB-11"), /2 different 'app' passwords for DB-11 .* Fix the map first/, "two answers is no answer — not even with a fallback");
console.log("1. destination password: the one its own map entries agree on; none -> DEST_DB_PASSWORD or a clear error; two -> refused");

// ---- 2) the reported case: move DB-01 -> DB-11 ------------------------------------------------
await go({ domain: "brand.tv", destServer: "DB-11", mode: "pipe" });
assert.ok(logins().includes(`10.0.0.1 ${PW["10.0.0.1"]}`), "the source is read with the source's password");
assert.ok(logins().some((l) => l.startsWith("10.0.0.11 ")) && logins().filter((l) => l.startsWith("10.0.0.11 ")).every((l) => l === `10.0.0.11 ${PW["10.0.0.11"]}`), "EVERY login on DB-11 uses DB-11's own password");
assert.equal(fs.readFileSync(path.join(base, "db/10.0.0.11/brand_db"), "utf8"), "CREATE TABLE t (a int) COLLATE=utf8mb4_unicode_ci;\nINSERT INTO t VALUES (1);\n", "the data arrived, collation normalised");
assert.match(lines.join("\n"), /each server's own password; DB-11's from domain-map\.json/); assert.match(lines.join("\n"), /DB_PASSWORD to DB-11's password/); assert.match(lines.join("\n"), /Re-pull DB credentials/);
noSecrets();
console.log("2. DB-01 -> DB-11: source read with DB-01's password, destination written with DB-11's; next steps name DB_PASSWORD; no password logged");

// ---- 3) dump + import (mode all) takes the same path ---------------------------------------------
fs.rmSync(path.join(base, "db/10.0.0.11/brand_db"));
await go({ domain: "brand.tv", destServer: "DB-11", mode: "all" });
assert.match(fs.readFileSync(path.join(base, "db/10.0.0.11/brand_db"), "utf8"), /utf8mb4_unicode_ci/); assert.ok(logins().filter((l) => l.startsWith("10.0.0.11 ")).every((l) => l.endsWith(PW["10.0.0.11"])));
console.log("3. mode all (dump file, then import): same credentials");

// ---- 4) what goes wrong says why, and says which password was tried — never the password --------
await assert.rejects(go({ domain: "brand.tv", destServer: "DB-13", mode: "pipe" }), /'app' cannot log in on DB-13 \(10\.0\.0\.13:3306\) with the password from domain-map\.json: ERROR 1045 \(28000\): Access denied/); noSecrets();
await assert.rejects(go({ domain: "brand.tv", destServer: "DB-12", mode: "pipe" }), /no domain-map\.json entry on DB-12 \(10\.0\.0\.12\) uses 'app'/);
assert.ok(!fs.existsSync(path.join(base, "logins")), "refused before anything connected");
process.env.DEST_DB_PASSWORD = "from-the-agent-env";
await assert.rejects(go({ domain: "brand.tv", destServer: "DB-12", mode: "pipe" }), /with the password from DEST_DB_PASSWORD: ERROR 1045/); noSecrets();
process.env.DEST_DB_PASSWORD = PW["10.0.0.12"];
await go({ domain: "brand.tv", destServer: "DB-12", mode: "pipe" });
assert.ok(fs.existsSync(path.join(base, "db/10.0.0.12/brand_db"))); assert.match(lines.join("\n"), /DB-12's from DEST_DB_PASSWORD/);
await go({ domain: "brand.tv", destServer: "DB-11", mode: "pipe" });
assert.ok(logins().filter((l) => l.startsWith("10.0.0.11 ")).every((l) => l.endsWith(PW["10.0.0.11"])), "DEST_DB_PASSWORD does not override a server the map knows");
delete process.env.DEST_DB_PASSWORD;
console.log("4. stale map password / server with no entries: mysql's own error and where the password came from; DEST_DB_PASSWORD only fills the gap");

// ---- 5) a clone registered in the map gets the DESTINATION's password ------------------------------
await go({ domain: "brand.tv", destServer: "DB-11", mode: "pipe", destDb: "brand_clone", newDomain: "newbrand.tv", cdnPrefix: "nb" });
const after = path.join(base, "after"); execFileSync(realGit, ["clone", "-q", bare, after], { stdio: "pipe" });
const pushed = JSON.parse(fs.readFileSync(path.join(after, "domain-map.json"), "utf8"));
assert.deepEqual(pushed["newbrand.tv"], { DB_HOST: "10.0.0.11:3306", DB_NAME: "brand_clone", DB_USER: "app", DB_PASSWORD: PW["10.0.0.11"], CDN_PREFIX: "nb" }, "not the source server's password");
const { ["newbrand.tv"]: _n, ...rest } = pushed; assert.deepEqual(rest, MAP, "every other entry untouched");
assert.match(git(after, "log", "-1", "--format=%s"), /chore: add newbrand\.tv -> brand_clone @ DB-11/); noSecrets();
// a clone on the SAME server as its source keeps that server's password
fs.writeFileSync(path.join(base, "db/10.0.0.11/other_db"), "");
await go({ domain: "other.tv", destServer: "DB-11", mode: "pipe", destDb: "other_copy" });
assert.ok(logins().every((l) => l === `10.0.0.11 ${PW["10.0.0.11"]}`));
console.log("5. clone + register: the pushed map entry carries the destination server's password; a same-server clone works");

fs.rmSync(base, { recursive: true, force: true });
console.log("\nPASS: migrate uses each database server's own password — source from the domain's entry, destination from that server's entries");
