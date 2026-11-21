import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: its own passwd/shadow/group, homes with real public keys, and stand-ins for the commands that change accounts.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "rmacct-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const f = (n) => path.join(base, n), flag = (n, on = true) => (on ? fs.writeFileSync(f(n), "") : fs.rmSync(f(n), { force: true }));
const stub = (name, body = "exit 0") => { fs.writeFileSync(path.join(bin, name), `#!/bin/bash\necho "${name} $*" >> "${base}/calls"\n${body}\n`); fs.chmodSync(path.join(bin, name), 0o755); };
stub("sshd", `cat "${base}/sshd"`);
stub("userdel", `[ -f "${base}/userdel-fails" ] && { echo "userdel: user intruder is currently used by process 4242" >&2; exit 8; }; exit 0`);
stub("usermod"); stub("loginctl"); stub("pkill"); stub("journalctl");
const pub = (name) => { const k = f(`key-${name}`); execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", name, "-f", k]); return fs.readFileSync(`${k}.pub`, "utf8").trim(); };
const home = (name, keys = [], second = []) => { const d = f(name); fs.mkdirSync(path.join(d, ".ssh"), { recursive: true }); if (keys.length) fs.writeFileSync(path.join(d, ".ssh/authorized_keys"), keys.join("\n") + "\n"); if (second.length) fs.writeFileSync(path.join(d, ".ssh/authorized_keys2"), second.join("\n") + "\n"); return d; };
const H = { root: home("root", [pub("owner")]), intruder: home("intruder", [pub("a"), pub("b")], [pub("hidden")]), mysql: home("mysql", [pub("planted")]), www: home("www") };
fs.writeFileSync(f("passwd"), [
  `root:x:0:0:root:${H.root}:/bin/bash`, `toor:x:0:0:second root:${H.root}:/bin/bash`, `www-data:x:33:33::${H.www}:/usr/sbin/nologin`,
  `mysql:x:110:110::${H.mysql}:/bin/bash`, `intruder:x:1001:1001::${H.intruder}:/bin/bash`, `twin:x:1001:1001::${f("twin")}:/bin/bash`, ""].join("\n"));
fs.writeFileSync(f("shadow"), "root:*:1::::::\ntoor:$6$x:1::::::\nmysql:$6$x:1::::::\nintruder:$6$x:1::::::\n");
fs.writeFileSync(f("group"), "root:x:0:\n");
const sshd = (o) => fs.writeFileSync(f("sshd"), Object.entries({ port: 22, permitrootlogin: "prohibit-password", passwordauthentication: "no", ...o }).map(([k, v]) => `${k} ${v}`).join("\n") + "\n");
sshd({});
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_PASSWD_FILE: f("passwd"), AGENT_SHADOW_FILE: f("shadow"), AGENT_GROUP_FILE: f("group"), AGENT_TOKEN: "t".repeat(64) });
const S = await import(path.join(A, "src/lib/security.js"));
const calls = () => { try { return fs.readFileSync(f("calls"), "utf8").split("\n").filter((l) => l && !l.startsWith("sshd") && !l.startsWith("journalctl")); } catch { return []; } };
const reset = () => fs.writeFileSync(f("calls"), "");
const keyFiles = (h) => ["authorized_keys", "authorized_keys2"].filter((n) => fs.existsSync(path.join(h, ".ssh", n)));

// 1) root is never removed, an unknown name is an error, and nothing is touched
await assert.rejects(S.removeAccount("root"), /root is never removed/);
await assert.rejects(S.removeAccount("nobody-here"), /no such account/);
assert.deepEqual(calls(), []); assert.deepEqual(keyFiles(H.root), ["authorized_keys"]);
console.log("1. root is never removed; an unknown account is refused");

// 2) refused while root itself cannot log in: the account may be the only way in
sshd({ permitrootlogin: "no" });
await assert.rejects(S.removeAccount("intruder"), /root cannot log in over SSH.*intruder may be the only way in/);
sshd({}); fs.renameSync(path.join(H.root, ".ssh/authorized_keys"), f("root-keys"));
await assert.rejects(S.removeAccount("intruder"), /root cannot log in over SSH/, "keys only, and root has no key");
fs.renameSync(f("root-keys"), path.join(H.root, ".ssh/authorized_keys"));
assert.deepEqual(calls(), []); assert.equal(keyFiles(H.intruder).length, 2, "nothing was deleted");
console.log("2. refused while root cannot log in (root login off, or no key for root)");

// 3) an ordinary account: sessions ended, BOTH key files deleted, account deleted, home kept
fs.writeFileSync(f("passwd"), fs.readFileSync(f("passwd"), "utf8").replace(/^twin:.*\n/m, "")); // its id is its own now
const r = await S.removeAccount("intruder");
assert.deepEqual(r, { user: "intruder", action: "deleted", keys: 3, home: H.intruder });
assert.deepEqual(calls(), ["loginctl terminate-user intruder", "pkill -KILL -U 1001", "userdel intruder"], "no -r and no -f: the home folder is never deleted");
assert.deepEqual(keyFiles(H.intruder), [], "the hidden second key file is gone too"); assert.ok(fs.existsSync(H.intruder), "home kept");
console.log("3. ordinary account: sessions ended, every key file deleted, account deleted, home kept");

// 4) userdel refuses: said plainly, keys already gone
home("intruder", [pub("c")]); flag("userdel-fails"); reset();
await assert.rejects(S.removeAccount("intruder"), /1 key\(s\) were removed, but the account could not be deleted: userdel: user intruder is currently used by process 4242/);
flag("userdel-fails", false);
console.log("4. the account will not delete -> reported with the reason, its keys are already gone");

// 5) a service account: keys removed and password locked, NOT deleted, and its processes are not killed
reset();
assert.deepEqual(await S.removeAccount("mysql"), { user: "mysql", action: "locked", keys: 1, home: H.mysql });
assert.deepEqual(calls(), ["loginctl terminate-user mysql", "usermod -L mysql"]); assert.deepEqual(keyFiles(H.mysql), []);
console.log("5. service account: keys removed, password locked, account and its service left alone");

// 6) a second account with root's id, living in root's home: locked — and root's own keys and sessions are untouched
reset();
const t = await S.removeAccount("toor");
assert.equal(t.action, "locked"); assert.equal(t.keys, 0); assert.match(t.note, /is also root's, so no key file was deleted there/);
assert.deepEqual(calls(), ["usermod -L toor"], "no session or process is ended by root's id");
assert.deepEqual(keyFiles(H.root), ["authorized_keys"], "root can still log in");
console.log("6. root-id clone: locked; root's keys, sessions and processes untouched");

// 7) two accounts sharing one id are never killed-by-id or deleted
fs.appendFileSync(f("passwd"), `one:x:1500:1500::${home("one", [pub("d")])}:/bin/bash\ntwo:x:1500:1500::${f("two")}:/bin/bash\n`); reset();
assert.equal((await S.removeAccount("one")).action, "locked"); assert.ok(!calls().some((c) => /pkill|userdel/.test(c)));
console.log("7. an id shared by two accounts: locked, never killed by id");

console.log("\nPASS: accounts are removed or locked with their keys, never root, never root's keys, never a service's processes");
fs.rmSync(base, { recursive: true, force: true });
