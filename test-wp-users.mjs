import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box. wp-cli runs as `sudo -u www-data -H /usr/bin/php /usr/local/bin/wp …`,
// so `sudo` is the binary resolved off PATH: the stub plays WordPress, recording
// what it was given in argv and on stdin. (scripts/wp-users.php itself needs a
// real WordPress to run; what is tested here is everything around it.)
const base = fs.mkdtempSync(path.join(os.tmpdir(), "wpusers-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const argvLog = path.join(base, "argv"), stdinLog = path.join(base, "stdin");
fs.writeFileSync(path.join(bin, "sudo"), `#!/bin/bash
echo "$*" >> "${argvLog}"
in="$(cat)"; echo "$in" >> "${stdinLog}"
action=""; prev=""
for a in "$@"; do case "$prev" in *wp-users.php) action="$a";; esac; prev="$a"; done
echo 'PHP Notice: something noisy in front'
case "$action" in
  list) echo 'WCP_JSON:{"users":[{"id":1,"login":"admin","email":"a@x.com","name":"Admin","roles":["administrator"],"registered":"2026-01-02 03:04:05","deactivated":false},{"id":7,"login":"editor.one","email":"e@x.com","name":"Ed","roles":[],"registered":"2026-02-02 00:00:00","deactivated":true}],"roles":[{"role":"administrator","name":"Administrator"},{"role":"editor","name":"Editor"}]}';;
  create) echo 'WCP_JSON:{"user":{"id":9,"login":"new.user","email":"n@x.com","name":"new.user","roles":["editor"],"registered":"2026-09-29 00:00:00","deactivated":false}}';;
  reset|activate) echo 'WCP_JSON:{"user":{"id":1,"login":"admin","roles":["administrator"],"deactivated":false}}';;
  set-role) echo 'WCP_JSON:{"error":"this is the only administrator — make another user an administrator first"}'; exit 1;;
  deactivate) echo 'WCP_JSON:{"user":{"id":7,"login":"editor.one","roles":[],"deactivated":true}}';;
  delete) echo 'WCP_JSON:{"deleted":7,"reassigned_to":1}';;
  *) echo "Fatal error: boom" >&2; exit 255;;
esac
`); fs.chmodSync(path.join(bin, "sudo"), 0o755);
const www = path.join(base, "www");
fs.mkdirSync(path.join(www, "site.com/htdocs/src"), { recursive: true });
fs.writeFileSync(path.join(www, "site.com/htdocs/src/.env"), "WP_HOME='https://site.com'\n");
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_WWW_DIR: www });

const { wpUsers, newPassword, WP_USER_ACTIONS } = await import(path.join(A, "src/lib/wpusers.js"));
const argv = () => fs.readFileSync(argvLog, "utf8");
const lastStdin = () => JSON.parse(fs.readFileSync(stdinLog, "utf8").trim().split("\n").pop());

// 1) list: users + the site's roles, parsed even with PHP notices in front
const l = await wpUsers("site.com", "list");
assert.deepEqual(l.users.map((u) => [u.id, u.login, u.deactivated]), [[1, "admin", false], [7, "editor.one", true]]);
assert.deepEqual(l.roles.map((r) => r.role), ["administrator", "editor"]);
assert.ok(!("password" in l));
console.log("1. list: users, deactivated flag and the site's roles");

// 2) actions that set a password: generated here, sent over STDIN, returned once, never in argv
for (const [action, body] of [["create", { login: "new.user", email: "n@x.com", role: "editor" }], ["reset", { id: 1 }], ["activate", { id: 7 }]]) {
  const r = await wpUsers("site.com", action, body);
  assert.match(r.password, /^[A-Za-z0-9_-]{32}$/, action);
  assert.equal(lastStdin().password, r.password, `${action}: password went over stdin`);
  assert.ok(!argv().includes(r.password), `${action}: password never in a command line`);
}
assert.deepEqual((({ password, ...rest }) => rest)(lastStdin()), { id: 7 });
assert.notEqual(newPassword(), newPassword());
console.log("2. create / reset / activate: password generated on the server, over stdin, returned once");

// 3) actions without a password carry none
assert.deepEqual(await wpUsers("site.com", "deactivate", { id: 7 }), { user: { id: 7, login: "editor.one", roles: [], deactivated: true } });
assert.deepEqual(lastStdin(), { id: 7 });
assert.deepEqual(await wpUsers("site.com", "delete", { id: 7, reassign: 1 }), { deleted: 7, reassigned_to: 1 });
assert.deepEqual(lastStdin(), { id: 7, reassign: 1 });
console.log("3. deactivate / delete: exactly the validated input is sent, no password involved");

// 4) WordPress' own refusals come back as a clear 400
await assert.rejects(() => wpUsers("site.com", "set-role", { id: 1, role: "editor" }), (e) => e.status === 400 && /only administrator/.test(e.message));
console.log("4. WordPress refusing (last administrator) is reported as such");

// 5) input is validated BEFORE anything runs
const calls = argv().split("\n").length;
for (const [action, body, re] of [
  ["create", { login: "x; rm -rf /", email: "n@x.com", role: "editor" }, /invalid user login/],
  ["create", { login: "ok", email: "nope", role: "editor" }, /invalid e-mail/],
  ["create", { login: "ok", email: "n@x.com", role: "Editor; DROP" }, /invalid role/],
  ["set-role", { id: "1 OR 1=1", role: "editor" }, /must be a user id/],
  ["delete", { id: 7 }, /reassign must be a user id/],
  ["nuke", {}, /unknown action/],
]) await assert.rejects(() => wpUsers("site.com", action, body), re);
await assert.rejects(() => wpUsers("nothere.com", "list"), /not deployed on this server/);
assert.equal(argv().split("\n").length, calls, "nothing was executed for invalid input");
assert.deepEqual(WP_USER_ACTIONS, ["list", "create", "reset", "activate", "deactivate", "set-role", "delete"]);
console.log("5. hostile or incomplete input is refused before wp-cli is called");

console.log("\nPASS: WordPress users can be listed, created, re-roled, deactivated, activated and deleted");
fs.rmSync(base, { recursive: true, force: true });
