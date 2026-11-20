import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: dpkg-query / apt-get / nginx / systemctl stand-ins that record what they were asked.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "nginxup-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const calls = path.join(base, "calls"), state = path.join(base, "state");
const f = (n) => path.join(base, n), flag = (n, on = true) => (on ? fs.writeFileSync(f(n), "") : fs.rmSync(f(n), { force: true }));
const reset = () => { fs.writeFileSync(state, "old"); fs.writeFileSync(calls, ""); fs.writeFileSync(f("active"), "active"); };
const stub = (n, body) => { fs.writeFileSync(path.join(bin, n), `#!/bin/bash\necho "${n} $*" >> "${calls}"\n${body}\n`); fs.chmodSync(path.join(bin, n), 0o755); };
stub("dpkg-query", `if [ "$(cat "${state}")" = old ]; then v=1.30.4-1ppa~stable; else v=1.30.7-1ppa~stable; fi
printf 'nginx-common %s installed\\nnginx-custom %s installed\\nnginx-wo %s installed\\nnginx-light 1.24.0 deinstall\\n' "$v" "$v" "$v"`);
// the package's own scripts restart nginx: if that fails (flag), nginx is left stopped
stub("apt-get", `case "$*" in *"--only-upgrade"*) [ -f "${base}/no-newer" ] || echo new > "${state}"; [ -f "${base}/pkg-leaves-it-down" ] && echo inactive > "${base}/active";; esac; exit 0`);
stub("nginx", `if [ "$1" = "-v" ]; then if [ "$(cat "${state}")" = old ]; then echo "nginx version: nginx/1.30.4" >&2; else echo "nginx version: nginx/1.30.7" >&2; fi; exit 0; fi
if [ -f "${base}/config-broken" ] || { [ -f "${base}/breaks-on-new" ] && [ "$(cat "${state}")" = new ]; }; then echo 'nginx: [emerg] unknown directive "foo" in /etc/nginx/nginx.conf:3' >&2; exit 1; fi; exit 0`);
stub("systemctl", `case "$1" in is-active) cat "${base}/active";; restart) [ -f "${base}/wont-start" ] && { echo inactive > "${base}/active"; echo "Job for nginx.service failed" >&2; exit 1; }; echo active > "${base}/active";; esac; exit 0`);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_NGINX_PID: f("no-pid-file") });

const { nginxPackages, nginxVersion, runNginxUpgrade } = await import(path.join(A, "src/operations/nginxupgrade.js"));
const { operations } = await import(path.join(A, "src/operations/index.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const said = () => fs.readFileSync(calls, "utf8");

// 1) only INSTALLED packages count; nginx -v is read from stderr
reset();
assert.deepEqual(Object.keys(await nginxPackages(helpers)).sort(), ["nginx-common", "nginx-custom", "nginx-wo"]);
assert.equal(await nginxVersion(helpers), "1.30.4"); assert.equal(operations.nginxupgrade.validate({}).ok, true);
console.log("1. installed nginx packages listed, removed ones ignored; nginx -v parsed");

// 2) the upgrade: config checked first, only-upgrade of exactly those packages, config kept, then a RESTART (not a reload)
const r = await runNginxUpgrade({ id: "j1" }, helpers);
assert.ok(said().indexOf("nginx -t") < said().indexOf("apt-get"), "the configuration is tested before anything is installed");
assert.match(said(), /apt-get .*--force-confold.*--force-confdef.* install --only-upgrade nginx-common nginx-custom nginx-wo/);
assert.match(said(), /systemctl restart nginx/); assert.ok(!/systemctl reload nginx/.test(said()));
assert.deepEqual(r.changed, ["nginx-common", "nginx-custom", "nginx-wo"]); assert.equal(r.nginx, "1.30.7");
assert.match(lines.join("\n"), /nginx-custom: 1\.30\.4.* → 1\.30\.7/); assert.match(lines.join("\n"), /nginx upgrade done: nginx 1\.30\.7 \(was 1\.30\.4\) · 3 package\(s\) changed/);
console.log("2. config tested, packages upgraded, nginx RESTARTED so the new program answers; before/after reported");

// 3) nothing newer in the repository: says so, and does not restart a healthy nginx for nothing
fs.writeFileSync(calls, ""); lines.length = 0;
const r2 = await runNginxUpgrade({ id: "j2" }, helpers);
assert.equal(r2.changed.length, 0); assert.match(lines.join("\n"), /already at the newest version the repository offers/); assert.ok(!/systemctl restart/.test(said()));
assert.match(lines.join("\n"), /nginx upgrade done: nginx 1\.30\.7 · 0 package\(s\) changed/);
console.log("3. up to date -> said so, no needless restart");

// 4) a broken configuration: nothing is installed at all
reset(); flag("config-broken");
await assert.rejects(runNginxUpgrade({ id: "j3" }, helpers), /configuration is broken right now, so nothing was installed.*unknown directive "foo"/);
assert.ok(!/apt-get/.test(said())); flag("config-broken", false);
console.log("4. config already broken -> refused before installing anything");

// 5) the package left nginx stopped: it is started again; if it will not start, the job fails and says so
reset(); flag("pkg-leaves-it-down");
await runNginxUpgrade({ id: "j4" }, helpers); assert.equal(fs.readFileSync(f("active"), "utf8").trim(), "active");
reset(); flag("wont-start");
await assert.rejects(runNginxUpgrade({ id: "j5" }, helpers), /nginx did not start after the upgrade — on the server: systemctl status nginx/);
flag("pkg-leaves-it-down", false); flag("wont-start", false);
// the new nginx rejects the old configuration: not restarted into a failure, and the state is spelled out
reset(); flag("breaks-on-new");
await assert.rejects(runNginxUpgrade({ id: "j6" }, helpers), /no longer passes with the new nginx, so it was NOT restarted — nginx is still running the OLD program/);
assert.ok(!/systemctl restart/.test(said()));
console.log("5. left stopped -> started; will not start -> job fails; new nginx rejects the config -> not restarted, said plainly");

console.log("\nPASS: nginx is upgraded through apt, restarted onto the new program, and never left down silently");
fs.rmSync(base, { recursive: true, force: true });
