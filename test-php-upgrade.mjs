import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: dpkg-query / apt-get / php / systemctl stubs; the tuning script sees no PHP (warns only).
const base = fs.mkdtempSync(path.join(os.tmpdir(), "phpup-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const calls = path.join(base, "calls"), state = path.join(base, "state");
fs.writeFileSync(state, "old");
const stub = (n, body) => { fs.writeFileSync(path.join(bin, n), `#!/bin/bash\necho "${n} $*" >> "${calls}"\n${body}\n`); fs.chmodSync(path.join(bin, n), 0o755); };
stub("dpkg-query", `if [ "$(cat "${state}")" = old ]; then v83=8.3.26-1+ubuntu24.04.1+deb.sury.org+1; else v83=8.3.36-1+ubuntu24.04.1+deb.sury.org+1; fi
printf 'php8.3-fpm %s installed\\nphp8.3-cli %s installed\\nphp8.4-fpm 8.4.27-1+ubuntu24.04.1+deb.sury.org+1 installed\\nphp8.1-fpm 8.1.0 deinstall\\n' "$v83" "$v83"`);
stub("apt-get", `case "$*" in *"--only-upgrade"*) echo new > "${state}";; esac; exit 0`);
stub("php", `if [ "$(cat "${state}")" = old ]; then echo "PHP 8.3.26 (cli) (built: Sep 1 2026)"; else echo "PHP 8.3.36 (cli) (built: Oct 21 2026)"; fi`);
stub("systemctl", "exit 0");
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, PHP_ETC: path.join(base, "no-php") });

const { phpPackages, phpVersion, runPhpUpgrade } = await import(path.join(A, "src/operations/phpupgrade.js"));
const { operations } = await import(path.join(A, "src/operations/index.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };

// 1) only INSTALLED packages count (a removed one is ignored); php -v parsed
assert.deepEqual(Object.keys(await phpPackages(helpers)).sort(), ["php8.3-cli", "php8.3-fpm", "php8.4-fpm"]);
assert.equal(await phpVersion(helpers), "8.3.26");
console.log("1. installed php* packages listed, removed ones ignored; php -v parsed");

// 2) the upgrade: apt update + only-upgrade of exactly those packages, non-interactive, config kept; both fpm restarted; result reported
const r = await runPhpUpgrade({ id: "j1" }, helpers);
const c = fs.readFileSync(calls, "utf8");
assert.match(c, /apt-get .*--force-confold.*--force-confdef.*ForceIPv4=true.* update/);
assert.match(c, /apt-get .* install --only-upgrade php8\.3-cli php8\.3-fpm php8\.4-fpm/);
assert.match(c, /systemctl restart php8\.3-fpm/); assert.match(c, /systemctl restart php8\.4-fpm/);
assert.deepEqual(r.changed.sort(), ["php8.3-cli", "php8.3-fpm"]); assert.equal(r.php, "8.3.36");
assert.match(lines.join("\n"), /php8\.3-fpm: 8\.3\.26.* → 8\.3\.36/);
assert.match(lines.join("\n"), /PHP upgrade done: php -v 8\.3\.36 · 2 package\(s\) changed/);
console.log("2. apt update + only-upgrade of the installed set, fpm restarted, before/after reported");

// 3) nothing to do -> still succeeds, says so
lines.length = 0;
const r2 = await runPhpUpgrade({ id: "j2" }, helpers);
assert.equal(r2.changed.length, 0); assert.match(lines.join("\n"), /already at the newest version/);
assert.equal(operations.phpupgrade.validate({}).ok, true);
console.log("3. up to date -> no-op, reported as such");

console.log("\nPASS: PHP patch releases are applied fleet-wide through apt, fpm restarted, versions reported");
fs.rmSync(base, { recursive: true, force: true });
