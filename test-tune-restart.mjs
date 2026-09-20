import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Stub systemctl so the restart is observable; point the script at a fake /etc/php.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "tunerestart-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const calls = path.join(base, "systemctl.calls");
fs.writeFileSync(path.join(bin, "systemctl"), `#!/bin/bash\necho "$@" >> "${calls}"\n`); fs.chmodSync(path.join(bin, "systemctl"), 0o755);
const etc = path.join(base, "php");
fs.mkdirSync(path.join(etc, "8.3/fpm/pool.d"), { recursive: true });
const INI = path.join(etc, "8.3/fpm/php.ini");
fs.writeFileSync(INI, "[PHP]\nmemory_limit = 128M\n");
process.env.PATH = `${bin}:${process.env.PATH}`;
process.env.PHP_ETC = etc;

const { tuneAndRestartPhp } = await import(path.join(A, "src/lib/site.js"));
const helpers = { log() {} };
const seen = () => { const m = { info: [], warn: [] }; return { m, info: (s) => m.info.push(s), warn: (s) => m.warn.push(s) }; };
const restarts = () => (fs.existsSync(calls) ? fs.readFileSync(calls, "utf8").trim().split("\n") : []);

// 1) untuned PHP 8.3 -> fixed, reported once, and the restart still happens
let l = seen();
await tuneAndRestartPhp(helpers, l);
assert.match(fs.readFileSync(INI, "utf8"), /^memory_limit = 512M$/m);
assert.match(fs.readFileSync(INI, "utf8"), /^pcre\.backtrack_limit = 10000000$/m);
assert.equal(l.m.info.length, 1); assert.match(l.m.info[0], /^php 8\.3: tuned \(\d+ setting\(s\) changed\)$/);
assert.deepEqual(restarts(), ["restart php8.3-fpm"]);
console.log("1. untuned 8.3 is tuned, logged once, then restarted");

// 2) already tuned -> silent, exactly one more restart (no extra restart from the script)
l = seen();
await tuneAndRestartPhp(helpers, l);
assert.deepEqual(l.m, { info: [], warn: [] });
assert.deepEqual(restarts(), ["restart php8.3-fpm", "restart php8.3-fpm"]);
console.log("2. already tuned -> no log noise, one restart per call");

// 3) tuning fails (no PHP found) -> warning, but the operation's restart is NOT skipped
process.env.PHP_ETC = path.join(base, "nope");
l = seen();
await tuneAndRestartPhp(helpers, l);
assert.equal(l.m.warn.length, 1); assert.match(l.m.warn[0], /PHP tuning check: no PHP-FPM found/);
assert.equal(restarts().length, 3);
console.log("3. tuning problem -> warned, restart still runs");

console.log("\nPASS: deploy/alias/update tune PHP before their existing restart, safely");
fs.rmSync(base, { recursive: true, force: true });
