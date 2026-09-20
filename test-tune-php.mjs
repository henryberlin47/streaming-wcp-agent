import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.join(A, "scripts/tune-php.sh");

// A fake /etc/php that mirrors the server where sites went blank: PHP 8.3 (the
// one sites actually run on) untouched at 128M with pcre.* only as commented
// docs, next to an 8.4 that someone had already tuned.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "tunephp-"));
const etc = path.join(base, "php");
const mk = (v, ini, pools) => {
  const d = path.join(etc, v, "fpm", "pool.d"); fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(etc, v, "fpm", "php.ini"), ini);
  for (const [n, body] of Object.entries(pools)) fs.writeFileSync(path.join(d, n), body);
};
const pool = (name) => `[${name}]\npm = dynamic\npm.max_children = 5\npm.start_servers = 2\npm.min_spare_servers = 1\npm.max_spare_servers = 3\n;pm.max_requests = 500\n`;
mk("8.3",
  "[PHP]\nmemory_limit = 128M\nmax_execution_time = 30\n; pcre docs below\n;pcre.backtrack_limit=100000\n;pcre.recursion_limit=100000\n;pcre.jit=1\npost_max_size = 8M\nupload_max_filesize = 2M\n",
  { "www.conf": pool("www"), "www-two.conf": pool("www-two"), "debug.conf": "[debug]\npm.max_children = 1\n" });
mk("8.4", "[PHP]\nmemory_limit = 512M\n", { "www.conf": pool("www") });

const run = (args = [], env = {}) => spawnSync("bash", [SCRIPT, ...args], { env: { ...process.env, PHP_ETC: etc, ...env }, encoding: "utf8" });
const ini = (v) => fs.readFileSync(path.join(etc, v, "fpm/php.ini"), "utf8");
const active = (text, key) => (text.split("\n").filter((l) => new RegExp(`^\\s*${key.replace(/\./g, "\\.")}\\s*=`).test(l)).pop() || "").split("=")[1]?.trim();

// 1) first run fixes BOTH versions — the whole point: 8.3 must not be skipped
let r = run(["--no-restart"]);
assert.equal(r.status, 0, r.stderr);
assert.match(r.stdout, /php 8\.3: tuned \(\d+ setting\(s\) changed\) — restart pending/);
assert.match(r.stdout, /php 8\.4: tuned/);
for (const v of ["8.3", "8.4"]) {
  const t = ini(v);
  assert.equal(active(t, "memory_limit"), "512M", `${v} memory_limit`);
  assert.equal(active(t, "pcre.backtrack_limit"), "10000000", `${v} backtrack`);
  assert.equal(active(t, "pcre.recursion_limit"), "10000000", `${v} recursion`);
  assert.equal(active(t, "pcre.jit"), "0", `${v} jit`);
}
console.log("1. the untuned 8.3 (128M) AND 8.4 both end up with memory 512M + pcre limits");

// 2) commented documentation lines are left alone; the active value is appended once
const t83 = ini("8.3");
assert.ok(t83.includes(";pcre.backtrack_limit=100000"), "commented doc line untouched");
assert.equal((t83.match(/^pcre\.jit\s*=/gm) || []).length, 1, "exactly one active pcre.jit line");
assert.equal((t83.match(/^memory_limit\s*=/gm) || []).length, 1, "memory_limit replaced in place, not duplicated");
console.log("2. doc comments untouched, no duplicate active lines");

// 3) both WordOps pools tuned; an unrelated pool file is not
const p = (n) => fs.readFileSync(path.join(etc, "8.3/fpm/pool.d", n), "utf8");
for (const n of ["www.conf", "www-two.conf"]) { assert.equal(active(p(n), "pm.max_children"), "30", n); assert.equal(active(p(n), "pm.max_requests"), "500", n); }
assert.equal(active(p("debug.conf"), "pm.max_children"), "1", "only www*.conf pools are touched");
console.log("3. www + www-two pools tuned, other pools left alone");

// 4) idempotent: a second run changes nothing (so calling it on every deploy is free)
const before = ini("8.3");
r = run(["--no-restart"]);
assert.equal(r.status, 0);
assert.match(r.stdout, /php 8\.3: already tuned/); assert.match(r.stdout, /php 8\.4: already tuned/);
assert.equal(ini("8.3"), before, "file byte-identical on re-run");
console.log("4. idempotent — second run reports 'already tuned' and rewrites nothing");

// 5) a config that fails `php-fpm -t` is ROLLED BACK — tuning can never take PHP down
fs.writeFileSync(path.join(etc, "8.3/fpm/php.ini"), "[PHP]\nmemory_limit = 128M\n");
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
fs.writeFileSync(path.join(bin, "php-fpm8.3"), "#!/bin/bash\nexit 1\n"); fs.chmodSync(path.join(bin, "php-fpm8.3"), 0o755);
r = run(["--no-restart"], { PATH: `${bin}:${process.env.PATH}` });
assert.equal(r.status, 1, "non-zero when validation fails");
assert.match(r.stderr, /config test FAILED after tuning — changes rolled back/);
assert.equal(ini("8.3"), "[PHP]\nmemory_limit = 128M\n", "php.ini restored byte-for-byte");
console.log("5. failed `php-fpm -t` -> changes rolled back, exit 1");

// 6) nothing to tune -> clear error, distinct exit code
r = spawnSync("bash", [SCRIPT, "--no-restart"], { env: { ...process.env, PHP_ETC: path.join(base, "nope") }, encoding: "utf8" });
assert.equal(r.status, 2); assert.match(r.stderr, /no PHP-FPM found/);
console.log("6. no PHP installed -> exit 2 with a clear message");

console.log("\nPASS: every PHP-FPM version converges on the tuned values, safely and idempotently");
fs.rmSync(base, { recursive: true, force: true });
