import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box. wp-cli runs as `sudo -u www-data -H /usr/bin/php /usr/local/bin/wp …`,
// so `sudo` is the binary resolved off PATH: the stub plays wp-cli and records
// what it was given in argv and on stdin.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "wpusers-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const argvLog = path.join(base, "argv"), stdinLog = path.join(base, "stdin");
fs.writeFileSync(path.join(bin, "sudo"), `#!/bin/bash
echo "$*" >> "${argvLog}"
case "$*" in
  *"user list"*) echo 'PHP Notice: something noisy'; echo '[{"ID":1,"user_login":"admin","user_email":"a@x.com","display_name":"Admin","roles":"administrator","user_registered":"2026-01-02 03:04:05"},{"ID":7,"user_login":"editor.one","user_email":"e@x.com","display_name":"Ed","roles":"editor,author","user_registered":"2026-02-02 00:00:00"}]';;
  *"user get admin"*) echo 1;;
  *"user get "*) echo "Error: Invalid user" >&2; exit 1;;
  *"eval-file"*) cat > "${stdinLog}"; echo ok;;
esac
`); fs.chmodSync(path.join(bin, "sudo"), 0o755);
const www = path.join(base, "www");
fs.mkdirSync(path.join(www, "site.com/htdocs/src"), { recursive: true });
fs.writeFileSync(path.join(www, "site.com/htdocs/src/.env"), "WP_HOME='https://site.com'\n");
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_WWW_DIR: www });

const { listWpUsers, resetWpPassword, newPassword } = await import(path.join(A, "src/lib/wpusers.js"));

// 1) list: parsed even with PHP notices in front of the JSON
const users = await listWpUsers("site.com");
assert.deepEqual(users.map((u) => [u.id, u.login, u.roles.join("+")]), [[1, "admin", "administrator"], [7, "editor.one", "editor+author"]]);
console.log("1. users listed (notices before the JSON tolerated)");

// 2) reset: strong password, delivered on STDIN, never in argv
const r = await resetWpPassword("site.com", "admin");
assert.equal(r.id, 1); assert.equal(r.login, "admin");
assert.match(r.password, /^[A-Za-z0-9_-]{32}$/);
assert.equal(fs.readFileSync(stdinLog, "utf8"), `${r.password}\n`, "password went over stdin");
assert.ok(!fs.readFileSync(argvLog, "utf8").includes(r.password), "password never appears in a command line");
assert.match(fs.readFileSync(argvLog, "utf8"), /eval-file .*wp-set-password\.php 1 /);
assert.notEqual(newPassword(), newPassword());
console.log("2. password generated on the server, passed over stdin, absent from argv");

// 3) refusals
await assert.rejects(() => resetWpPassword("site.com", "ghost"), /no WordPress user "ghost"/);
await assert.rejects(() => resetWpPassword("site.com", "x; rm -rf /"), /invalid user login/);
await assert.rejects(() => listWpUsers("nothere.com"), /not deployed on this server/);
console.log("3. unknown user, hostile login and undeployed site are refused");

console.log("\nPASS: WordPress users can be listed and a password reset without the secret touching logs or argv");
fs.rmSync(base, { recursive: true, force: true });
