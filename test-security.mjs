import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box, built BEFORE importing: passwd/shadow, root's home, sshd/journalctl/systemctl/dpkg/ufw/ss stubs.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "security-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const stub = (name, body) => { fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`); fs.chmodSync(path.join(bin, name), 0o755); };
const rootHome = path.join(base, "root"); fs.mkdirSync(rootHome);
const dropins = path.join(base, "sshd_config.d"); fs.mkdirSync(dropins);
fs.writeFileSync(path.join(dropins, "50-cloud-init.conf"), "PasswordAuthentication yes\n"); // what Ubuntu cloud images ship
const passwd = path.join(base, "passwd");
fs.writeFileSync(passwd, `root:x:0:0:root:${rootHome}:/bin/bash\nwww-data:x:33:33:www-data:${base}/www:/usr/sbin/nologin\ndeploy:x:1000:1000::${base}/deploy:/bin/bash\n`);
const shadow = path.join(base, "shadow"); fs.writeFileSync(shadow, "root:$6$hash:1::::::\nwww-data:*:1::::::\ndeploy::1::::::\n");
const group = path.join(base, "group"); fs.writeFileSync(group, "root:x:0:\nsudo:x:27:deploy\nwww-data:x:33:\n");
const sshlog = path.join(base, "sshlog");
// sshd: -t = syntax check; -T = effective settings. Like the real one, the FIRST value wins and drop-ins are read in name order, before the defaults.
stub("sshd", `if [ "$1" = "-t" ]; then [ -f "${base}/sshd-t-fails" ] && { echo "bad configuration option" >&2; exit 1; }; exit 0; fi
[ -f "${base}/ignore-dropins" ] || cat "${dropins}"/*.conf 2>/dev/null | grep -v '^#' | tr 'A-Z' 'a-z'
printf 'port 22\\npasswordauthentication yes\\nkbdinteractiveauthentication yes\\npermitrootlogin yes\\npubkeyauthentication yes\\nmaxauthtries 6\\nlogingracetime 120\\nx11forwarding yes\\npermitemptypasswords no\\n'`);
stub("journalctl", `cat "${sshlog}" 2>/dev/null`);
stub("systemctl", `echo "$*" >> "${base}/systemctl"`);
stub("mysql", `case "$*" in *mysql.func*) printf 'sys_exec\\tlib_mysqludf_sys.so\\n';; *mysql.user*) printf 'root\\t%%\\napp\\t%%\\n';; esac`);
stub("dpkg", "exit 0"); // everything "already installed": no apt in a test
stub("ufw", `echo "$*" >> "${base}/ufw"; [ "$1" = status ] && echo "Status: inactive"; exit 0`);
stub("ss", `echo 'LISTEN 0 511 0.0.0.0:22222 0.0.0.0:* users:(("nginx",pid=1,fd=6))'`);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_PASSWD_FILE: passwd, AGENT_SHADOW_FILE: shadow, AGENT_GROUP_FILE: group, AGENT_KEY_SEARCH_DIRS: base, AGENT_SSHD_DROPIN_DIR: dropins,
  AGENT_F2B_JAIL_DIR: path.join(base, "jail.d"), AGENT_APT_CONF_DIR: path.join(base, "apt.conf.d"), AGENT_WWW_DIR: path.join(base, "www"), AGENT_ENV_FILE: path.join(base, "agent.env"),
  AGENT_TMP_DIRS: path.join(base, "tmp"), AGENT_DB_DIRS: path.join(base, "mysql"), AGENT_TOKEN: "t".repeat(64) });

const S = await import(path.join(A, "src/lib/security.js"));
const { operations } = await import(path.join(A, "src/operations/index.js"));
const { lockedOut, noteBadKey } = await import(path.join(A, "src/auth.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const harden = (...actions) => operations.harden.run({ id: "j" }, helpers, operations.harden.validate({ actions }).clean);

// ---- 1) parsers, on real-looking output -------------------------------------------------
const LOG = `2026-10-24T06:32:07+0000 seo-1 sshd[26753]: Accepted password for root from 94.207.20.128 port 64671 ssh2
2026-10-24T07:41:12+0000 seo-1 sshd[41582]: userauth_pubkey: key type ssh-rsa not in PubkeyAcceptedAlgorithms [preauth]
2026-10-24T07:41:12+0000 seo-1 sshd[41582]: Connection closed by authenticating user root 203.0.113.9 port 40022 [preauth]
2026-10-25T01:00:00+0000 seo-1 sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 1 ssh2
2026-10-25T01:00:01+0000 seo-1 sshd[1]: Failed password for root from 198.51.100.7 port 2 ssh2
2026-10-25T01:00:02+0000 seo-1 sshd[2]: Invalid user oracle from 198.51.100.7 port 3
2026-11-17T09:26:57+0000 seo-1 sshd-session[8327]: Accepted publickey for root from 94.207.20.128 port 56130 ssh2: ED25519 SHA256:abcDEF123
2026-11-17T09:27:00+0000 seo-1 sudo[9]: pam_unix(sudo:session): session opened for user www-data(uid=33) by (uid=0)`;
const log = S.parseSshLog(LOG);
assert.deepEqual(log.accepted.map((l) => [l.method, l.user, l.ip, l.key]), [["publickey", "root", "94.207.20.128", "ED25519 SHA256:abcDEF123"], ["password", "root", "94.207.20.128", null]], "newest first; sudo's 'session opened' is not a login");
assert.equal(log.failed.total, 4);
assert.deepEqual(log.failed.byIp.map((e) => [e.ip, e.count, e.users]), [["198.51.100.7", 3, ["admin", "root", "oracle"]], ["203.0.113.9", 1, ["root"]]], "a refused key shows up with its address");
assert.equal(S.parseSshdT("port 22\npasswordauthentication no\npasswordauthentication yes\n").passwordauthentication, "no", "first value wins, as in sshd");
assert.deepEqual(S.parseKeygenLine("256 SHA256:Xy+z/1 me@laptop work (ED25519)"), { bits: 256, fingerprint: "SHA256:Xy+z/1", comment: "me@laptop work", type: "ED25519" });
const ufw = S.parseUfw("Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n80,443/tcp                 ALLOW       Anywhere\n8787/tcp on tailscale0     ALLOW       Anywhere\n3306                       ALLOW       10.0.0.5\nOpenSSH (v6)               ALLOW       Anywhere (v6)\n");
assert.equal(ufw.active, true); assert.equal(ufw.rules.length, 5);
assert.deepEqual([22, 443, 8787, 3306, 6379].map((p) => S.ufwAllowsPublic(ufw, p)), [true, true, false, false, false], "tailnet-only and single-source rules are not public");
assert.equal(S.ufwAllowsPublic({ active: false, rules: [] }, 6379), true, "no firewall = everything is reachable");
const ss = S.parseListening('LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1,fd=6))\nLISTEN 0 511 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=2,fd=6))\nLISTEN 0 511 *:8787 *:* users:(("node",pid=3,fd=20))\nLISTEN 0 80 100.90.1.2:3306 0.0.0.0:* users:(("mariadbd",pid=4,fd=20))\nLISTEN 0 511 [::]:80 [::]:* users:(("nginx",pid=1,fd=7))');
assert.deepEqual(ss.map((l) => `${l.port}/${l.scope}/${l.proc}`), ["80/all/nginx", "3306/private/mariadbd", "6379/local/redis-server", "8787/all/node"]);
const accts = S.parseAccounts(fs.readFileSync(passwd, "utf8"), fs.readFileSync(shadow, "utf8"));
assert.deepEqual(accts.map((u) => [u.name, u.login, u.password]), [["root", true, "set"], ["www-data", false, "locked"], ["deploy", true, "none"]]);
const full = S.parseAccounts("root:x:0:0::/root:/bin/bash\nbackup:x:34:34::/var/backups:/bin/sh\nops:x:1001:27::/home/ops:/bin/bash\n", "root:$6$h:20000::::::\nbackup:$6$h:20772::::::\nops:!:20001::::::\n", "sudo:x:27:\n");
assert.deepEqual(full.map((u) => [u.name, u.system, u.sudo, u.changed]), [["root", false, false, "2024-10-04"], ["backup", true, false, "2026-11-15"], ["ops", false, true, "2024-10-05"]], "service accounts, sudo by primary group, and the day the password field changed");
console.log("1. parsers: SSH log (logins, refusals with addresses), sshd settings, keys, firewall, listening ports, accounts");

// ---- 2) findings ---------------------------------------------------------------------------
const risky = { // the kind of server this was written for: root + password, no key, nothing guarding it
  ssh: { port: "22", passwordauthentication: "yes", kbdinteractiveauthentication: "no", permitrootlogin: "yes", maxauthtries: "6", x11forwarding: "yes" },
  users: [{ name: "root", uid: 0, login: true, password: "set", keys: [] }, { name: "toor", uid: 0, login: true, password: "set", keys: [] }],
  logins: log, firewall: { installed: true, active: false }, fail2ban: { installed: false, active: false },
  exposed: [{ port: 8787, proc: "node" }, { port: 6379, proc: "redis-server" }, { port: 80, proc: "nginx" }],
  updates: { pending: 30, security: 12, autoUpdates: false, rebootRequired: true },
  wwwData: { shell: "/bin/bash", password: "locked", crontab: true, uploadsPhp: ["/var/www/a.com/htdocs/src/web/app/uploads/x.php"], tmpExecutables: [{ path: "/tmp/.x", kind: "ELF 64-bit" }] },
  sites: { envWorldReadable: ["/var/www/a.com/htdocs/src/.env"] }, agent: { port: 8787, allowlist: 0, envMode: "644" },
};
const found = S.findingsFrom(risky);
const ids = found.map((f) => f.id);
for (const id of ["ssh-password", "ssh-no-key", "uid0-toor", "fail2ban", "firewall", "exposed-agent", "exposed-6379", "updates", "auto-updates", "www-shell", "www-crontab", "uploads-php", "tmp-exec", "env-perms", "agent-allowlist", "agent-env", "ssh-basics", "reboot"]) assert.ok(ids.includes(id), `finds ${id}`);
assert.ok(!ids.includes("exposed-80"), "a web port open to the web is not a finding");
assert.equal(found.find((f) => f.id === "ssh-password").fix, undefined, "no one-click 'keys only' while root has no key");
assert.equal(found[0].severity, "high"); assert.equal(found.at(-1).severity, "low");
const clean = S.findingsFrom({
  ssh: { passwordauthentication: "no", kbdinteractiveauthentication: "no", maxauthtries: "3", x11forwarding: "no", permitemptypasswords: "no" },
  users: [{ name: "root", uid: 0, login: true, password: "locked", keys: [{ fingerprint: "SHA256:a" }] }],
  logins: { accepted: [{ method: "publickey", user: "root", ip: "1.1.1.1" }], failed: { total: 40, byIp: [] } },
  firewall: { installed: true, active: true }, fail2ban: { installed: true, active: true, banned: 2 }, exposed: [{ port: 443, proc: "nginx" }],
  updates: { pending: 0, security: 0, autoUpdates: true, rebootRequired: false }, wwwData: { shell: "/usr/sbin/nologin", password: "locked", crontab: false, uploadsPhp: [], tmpExecutables: [] },
  sites: { envWorldReadable: [] }, agent: { port: 8787, allowlist: 1, envMode: "600" },
});
assert.deepEqual(clean, [], "a hardened server has nothing to report");
assert.equal(S.findingsFrom({ ...risky, users: [{ name: "root", uid: 0, login: true, password: "set", keys: [{ fingerprint: "SHA256:a" }] }] }).find((f) => f.id === "ssh-password").fix, "ssh-keys-only");
// intruder patterns on accounts: a key or password on a service account, a brand-new account, a stray key file
const acct = S.findingsFrom({ at: "2026-11-17T12:00:00Z", strayKeyFiles: ["/var/tmp/.x/authorized_keys"], users: [
  { name: "root", uid: 0, login: true, password: "set", changed: "2026-07-14", keys: [{ fingerprint: "SHA256:a" }] },
  { name: "www-data", uid: 33, system: true, login: false, password: "locked", changed: "2024-03-19", keys: [{ fingerprint: "SHA256:evil", comment: "x@kali" }] },
  { name: "backup", uid: 34, system: true, login: true, password: "set", changed: "2026-11-15", keys: [] },
  { name: "support", uid: 1001, login: true, password: "set", changed: "2026-11-16", sudo: true, keys: [] },
  { name: "ubuntu", uid: 1000, login: true, password: "locked", changed: "2026-07-14", sudo: true, keys: [{ fingerprint: "SHA256:b" }] },
] }).map((f) => `${f.severity}:${f.id}`);
for (const id of ["high:acct-keys-www-data", "high:acct-pass-backup", "medium:acct-new-backup", "medium:acct-new-support", "low:acct-sudo-support", "low:acct-sudo-ubuntu", "high:stray-keys-/var/tmp/.x/authorized_keys"]) assert.ok(acct.includes(id), `finds ${id}: ${acct}`);
assert.ok(!acct.some((x) => /acct-(new|keys|pass)-(root|ubuntu)/.test(x)), "an old root and a normal user with a key are not flagged");
console.log("2. findings: a risky server is flagged across SSH, accounts, firewall, ports, updates, web user; a hardened one is clean; planted accounts and keys are caught");

// ---- 3) authorized keys --------------------------------------------------------------------
const kp = path.join(base, "k1"), kp2 = path.join(base, "k2");
for (const k of [kp, kp2]) execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", `test@${path.basename(k)}`, "-f", k]);
const pub = fs.readFileSync(`${kp}.pub`, "utf8").trim(), pub2 = fs.readFileSync(`${kp2}.pub`, "utf8").trim();
await assert.rejects(S.addKey(fs.readFileSync(kp, "utf8")), /public key line/, "a private key is refused");
await assert.rejects(S.addKey(`command="/bin/sh" ${pub}`), /public key line/, "key options are refused");
await assert.rejects(S.addKey("ssh-ed25519 AAAAnotakey x"), /not a valid public key/);
const added = await S.addKey(pub);
assert.match(added.fingerprint, /^SHA256:/); assert.equal(added.comment, "test@k1");
const kf = path.join(rootHome, ".ssh/authorized_keys");
assert.equal(fs.statSync(kf).mode & 0o777, 0o600); assert.equal(fs.statSync(path.dirname(kf)).mode & 0o777, 0o700);
await assert.rejects(S.addKey(pub), /already installed/);
await S.addKey(pub2);
assert.deepEqual((await S.listKeys(rootHome)).map((k) => k.comment), ["test@k1", "test@k2"]);
await S.removeKey("root", added.fingerprint);
assert.deepEqual((await S.listKeys(rootHome)).map((k) => k.comment), ["test@k2"]);
await assert.rejects(S.removeKey("root", added.fingerprint), /not installed/);
console.log("3. keys: only a bare public key is accepted; add, list and remove by fingerprint; file stays 0600");

// ---- 4) hardening, and the guards that prevent a lockout --------------------------------------
assert.equal(operations.harden.validate({ actions: ["rm -rf /"] }).ok, false);
assert.equal(operations.harden.validate({ actions: [] }).ok, false);
const keysOnly = path.join(dropins, "00-wcp-keys-only.conf");
const k2fp = (await S.listKeys(rootHome))[0].fingerprint;
fs.rmSync(kf);
await assert.rejects(harden("ssh-keys-only"), /root has no SSH key installed/); assert.ok(!fs.existsSync(keysOnly));
await S.addKey(pub2);
fs.writeFileSync(sshlog, "2026-11-17T09:26:57+0000 seo-1 sshd[1]: Accepted password for root from 94.207.20.128 port 1 ssh2\n");
await assert.rejects(harden("ssh-keys-only"), /no successful KEY login for root/, "a key that was never used to log in proves nothing"); assert.ok(!fs.existsSync(keysOnly));
fs.writeFileSync(sshlog, `2026-11-17T09:30:00+0000 seo-1 sshd[1]: Accepted publickey for root from 94.207.20.128 port 1 ssh2: ED25519 ${k2fp}\n`);
fs.writeFileSync(path.join(base, "sshd-t-fails"), "");
await assert.rejects(harden("ssh-keys-only"), /sshd rejected the new settings, nothing changed/); assert.ok(!fs.existsSync(keysOnly), "rolled back");
fs.rmSync(path.join(base, "sshd-t-fails")); fs.writeFileSync(path.join(base, "ignore-dropins"), "");
await assert.rejects(harden("ssh-keys-only"), /did not take effect/); assert.ok(!fs.existsSync(keysOnly), "rolled back when overridden elsewhere");
fs.rmSync(path.join(base, "ignore-dropins"));
await harden("ssh-keys-only");
assert.match(fs.readFileSync(keysOnly, "utf8"), /PasswordAuthentication no/);
assert.match(fs.readFileSync(path.join(base, "systemctl"), "utf8"), /reload ssh/, "reloaded, not restarted: open sessions survive");
await assert.rejects(S.removeKey("root", k2fp), /last key and password login is off/, "cannot remove the last key once passwords are off");
console.log("4. keys-only: refused without a key, without a proven key login, on a bad config or an override; then applied; last key protected");

fs.mkdirSync(path.join(base, "www/a.com/htdocs/src"), { recursive: true });
const siteEnv = path.join(base, "www/a.com/htdocs/src/.env"); fs.writeFileSync(siteEnv, "X=1\n", { mode: 0o644 }); fs.chmodSync(siteEnv, 0o644);
fs.writeFileSync(path.join(base, "agent.env"), "AGENT_TOKEN=x\n"); fs.chmodSync(path.join(base, "agent.env"), 0o644);
await harden("fail2ban", "auto-updates", "firewall", "ssh-basics", "env-perms");
assert.match(fs.readFileSync(path.join(base, "jail.d/wcp-sshd.conf"), "utf8"), /enabled = true[\s\S]*ignoreip = .*100\.64\.0\.0\/10/);
assert.match(fs.readFileSync(path.join(base, "apt.conf.d/20auto-upgrades"), "utf8"), /Unattended-Upgrade "1"/);
const ufwCalls = fs.readFileSync(path.join(base, "ufw"), "utf8").split("\n");
assert.ok(ufwCalls.indexOf("allow 22/tcp") >= 0 && ufwCalls.indexOf("allow 22/tcp") < ufwCalls.indexOf("--force enable"), "SSH is allowed BEFORE the firewall is turned on");
assert.ok(ufwCalls.includes("allow in on tailscale0 to any port 8787 proto tcp"));
assert.match(lines.join("\n"), /will now be BLOCKED from the internet: 22222 \(nginx\)/, "says which public ports the firewall will cut");
assert.match(fs.readFileSync(path.join(dropins, "00-wcp-basics.conf"), "utf8"), /MaxAuthTries 3/);
assert.equal(fs.statSync(siteEnv).mode & 0o777, 0o640); assert.equal(fs.statSync(path.join(base, "agent.env")).mode & 0o777, 0o600);
console.log("5. fail2ban, auto-updates, firewall (SSH allowed first), SSH limits, .env permissions");

fs.mkdirSync(path.join(base, "mysql")); fs.mkdirSync(path.join(base, "tmp"));
fs.writeFileSync(path.join(base, "mysql/lib_mysqludf_sys.so"), "x"); fs.writeFileSync(path.join(base, "tmp/pt7408.so"), "x"); fs.writeFileSync(path.join(base, "mysql/ibdata1"), "x");
// a key hidden in the forgotten second file of a service account, and a key file that belongs to nobody
fs.mkdirSync(path.join(base, "www/.ssh"), { recursive: true }); fs.writeFileSync(path.join(base, "www/.ssh/authorized_keys2"), `${pub}\n`);
fs.mkdirSync(path.join(base, "tmp/.x"), { recursive: true }); fs.writeFileSync(path.join(base, "tmp/.x/authorized_keys"), `${pub}\n`);
// ---- 5) the audit end to end on the fake box --------------------------------------------------
const audit = await S.collectSecurity();
assert.equal(audit.ssh.passwordauthentication, "no"); assert.equal(audit.users.find((u) => u.name === "root").keys.length, 1);
assert.ok(audit.findings.some((f) => f.id === "nopass-deploy"), "an account with an empty password is flagged");
assert.deepEqual(audit.users.map((u) => u.name), ["root", "www-data", "deploy"], "every account that can log in, holds a key or may sudo");
assert.deepEqual(audit.users.find((u) => u.name === "www-data").keys.map((k) => [k.comment, k.file]), [["test@k1", "authorized_keys2"]]);
for (const id of ["acct-keys-www-data", "acct-sudo-deploy"]) assert.ok(audit.findings.some((f) => f.id === id), `finds ${id}`);
assert.deepEqual(audit.strayKeyFiles.map((f) => f.replace(fs.realpathSync(base), "").replace(base, "")), ["/tmp/.x/authorized_keys"]);
await S.removeKey("www-data", audit.users.find((u) => u.name === "www-data").keys[0].fingerprint);
assert.equal((await S.listKeys(path.join(base, "www"))).length, 0, "and it can be removed from the panel");
assert.ok(!JSON.stringify(audit).includes("$6$hash"), "no password hash in the report");
// an attack through the database: dropped libraries, a loaded command function, root open to any address
assert.deepEqual(audit.database.droppedLibs.map((p) => path.basename(p)).sort(), ["lib_mysqludf_sys.so", "pt7408.so"]);
for (const id of ["db-udf-loaded", "db-udf-files", "db-open-root", "db-open-app"]) assert.ok(audit.findings.some((f) => f.id === id), `finds ${id}`);
assert.equal(audit.findings.find((f) => f.id === "db-open-root").severity, "high"); assert.equal(audit.findings.find((f) => f.id === "db-open-app").severity, "medium");
console.log("6. audit: collects and reports without a hash or a key body; flags a database attack (dropped .so, loaded function, root@%)");

// ---- 6) wrong keys lock an address out ----------------------------------------------------------
const t0 = 1_000_000;
for (let i = 0; i < 9; i++) noteBadKey("9.9.9.9", t0 + i);
assert.equal(lockedOut("9.9.9.9", t0 + 10), false);
const _log = console.log; console.log = () => {}; noteBadKey("9.9.9.9", t0 + 10); console.log = _log;
assert.equal(lockedOut("9.9.9.9", t0 + 11), true); assert.equal(lockedOut("8.8.8.8", t0 + 11), false);
assert.equal(lockedOut("9.9.9.9", t0 + 16 * 60_000), false, "and is let back in after 15 minutes");
console.log("7. agent: 10 wrong keys from one address = locked out for 15 minutes");

console.log("\nPASS: security audit, authorized keys, hardening with lockout guards, agent lockout");
fs.rmSync(base, { recursive: true, force: true });
