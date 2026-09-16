import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
const A = dirname(fileURLToPath(import.meta.url));

// Stub binaries on PATH: a fake `git clone` that lays out src/web, and a fake
// `mariadb` that records the SQL it was handed. Set up BEFORE any import.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "secfix-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const capture = path.join(base, "mariadb.sql");
const stub = (name, body) => { const p = path.join(bin, name); fs.writeFileSync(p, `#!/usr/bin/env bash\n${body}\n`); fs.chmodSync(p, 0o755); };
stub("git", 'mkdir -p src/web && echo cloned > src/web/index.php; exit 0');
stub("mariadb", `printf '%s\\n' "$*" >> "${capture}"; exit 0`);
process.env.PATH = `${bin}:${process.env.PATH}`;
process.env.AGENT_REPO_ALLOWLIST = "git@github.com:me/extra.git";

const { getOperation } = await import(`${A}/src/operations/index.js`);
const { APP_REPO_DEFAULT } = await import(`${A}/src/lib/siteConfig.js`);
const { cloneRepo, dropLocalWoDb } = await import(`${A}/src/lib/site.js`);
const helpers = { log() {}, err() {}, onCancel() {} };

// ---- Fix 2: `repo` is allowlisted (git clone as root = RCE via ext::) -------
const deploy = getOperation("deploy");
const ok = (repo) => deploy.validate({ domain: "x.com", root: "r.com", repo });
assert.ok(ok(undefined).ok, "no repo -> default, allowed");
assert.ok(ok(APP_REPO_DEFAULT).ok, "the default repo is allowed");
assert.ok(ok("git@github.com:me/extra.git").ok, "AGENT_REPO_ALLOWLIST entries are allowed");
let r = ok("ext::sh -c id>/tmp/pwn");
assert.ok(!r.ok && /allowed repository/.test(r.errors.join()), "ext:: transport is rejected: " + r.errors);
r = ok("https://attacker.example/evil.git");
assert.ok(!r.ok, "an arbitrary https repo is rejected");
r = getOperation("alias").validate({ aliasDomain: "m.x.com", mainDomain: "x.com", repo: "ext::id" });
assert.ok(!r.ok, "alias validates repo too (it had no check at all before)");
console.log("1. repo allowlist: default + allowlist pass, ext:: / arbitrary URLs rejected (deploy + alias)");

// ---- Fix 2b: a leading-dash branch can't reach git's option parser ----------
r = deploy.validate({ domain: "x.com", root: "r.com", branch: "--upload-pack=id" });
assert.ok(!r.ok, "leading-dash branch rejected");
assert.ok(deploy.validate({ domain: "x.com", root: "r.com", branch: "feature/nginx-wprocket" }).ok);
console.log("2. leading-dash branch rejected, normal branch accepted");

// ---- Fix 5: LIKE `_` wildcard escaped in dropLocalWoDb ----------------------
await dropLocalWoDb(helpers, "a.b.com");
const sql = fs.readFileSync(capture, "utf8");
assert.ok(sql.includes("LIKE 'a\\_b\\_com%'"), "underscores escaped so a_b_com% can't match axb_com: " + sql.split("\n")[0]);
console.log("3. dropLocalWoDb escapes `_` — can no longer drop a neighbouring site's DB");

// ---- Fix 6: cloneRepo never destroys a deployed site ------------------------
const site = path.join(base, "www", "site.com");
const htdocs = path.join(site, "htdocs");
// (a) fresh `wo site create` placeholder -> cloned in place, placeholder gone
fs.mkdirSync(htdocs, { recursive: true }); fs.writeFileSync(path.join(htdocs, "index.html"), "wo placeholder");
let res = await cloneRepo(helpers, { htdocs, branch: "main", repo: "x" });
assert.equal(res.backup, null);
assert.ok(!fs.existsSync(path.join(htdocs, "index.html")) && fs.existsSync(path.join(htdocs, "src/web/index.php")), "placeholder replaced by clone");
console.log("4a. wo placeholder cloned in place");

// (b) now it's a DEPLOYED site (src/.env). Without force: REFUSED, untouched.
fs.writeFileSync(path.join(htdocs, "src/.env"), "DB_PASSWORD=live-secret\n");
fs.mkdirSync(path.join(htdocs, "src/web/app/uploads"), { recursive: true });
fs.writeFileSync(path.join(htdocs, "src/web/app/uploads/photo.jpg"), "bytes");
await assert.rejects(() => cloneRepo(helpers, { htdocs, branch: "main", repo: "x" }), /already holds a deployed site/);
assert.equal(fs.readFileSync(path.join(htdocs, "src/.env"), "utf8"), "DB_PASSWORD=live-secret\n", ".env untouched after refusal");
console.log("4b. redeploy without force is refused; live .env + uploads untouched");

// (c) with force: swapped in, previous htdocs kept as .bak with .env + uploads intact
res = await cloneRepo(helpers, { htdocs, branch: "main", repo: "x", force: true });
assert.ok(res.backup && fs.existsSync(res.backup), "a .bak was kept: " + res.backup);
assert.equal(fs.readFileSync(path.join(res.backup, "src/.env"), "utf8"), "DB_PASSWORD=live-secret\n", "old .env preserved in .bak");
assert.ok(fs.existsSync(path.join(res.backup, "src/web/app/uploads/photo.jpg")), "old uploads preserved in .bak");
assert.ok(fs.existsSync(path.join(htdocs, "src/web/index.php")) && !fs.existsSync(path.join(htdocs, "src/.env")), "htdocs is the fresh clone");
console.log("4c. force redeploy swaps in the new clone; old .env + uploads kept in", path.basename(res.backup));

// (d) a BAD clone (wrong layout) with force must leave the live site untouched
stub("git", 'echo "nothing useful"; exit 0'); // clones nothing
fs.writeFileSync(path.join(htdocs, "src/.env"), "DB_PASSWORD=live-2\n");
await assert.rejects(() => cloneRepo(helpers, { htdocs, branch: "main", repo: "x", force: true }), /live site left untouched/);
assert.equal(fs.readFileSync(path.join(htdocs, "src/.env"), "utf8"), "DB_PASSWORD=live-2\n", "live site survives a bad clone even with force");
console.log("4d. a bad clone under force leaves the live site untouched");

console.log("\nPASS: repo allowlist, branch guard, LIKE escape, and safe clone all hold");
fs.rmSync(base, { recursive: true, force: true });
