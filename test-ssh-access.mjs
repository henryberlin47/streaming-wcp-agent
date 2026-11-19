import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path"; import net from "node:net";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: sshd / systemctl / ufw / ss stand-ins that record what they were asked, and two real
// listeners that greet like sshd (the operation connects to the new port to prove sshd is there).
const base = fs.mkdtempSync(path.join(os.tmpdir(), "sshaccess-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const dropins = path.join(base, "sshd_config.d"); fs.mkdirSync(dropins);
const jaild = path.join(base, "jail.d"); fs.mkdirSync(jaild);
const stub = (name, body) => { fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`); fs.chmodSync(path.join(bin, name), 0o755); };
const f = (name) => path.join(base, name);
const flag = (name, on = true) => (on ? fs.writeFileSync(f(name), "") : fs.rmSync(f(name), { force: true }));
const said = (name) => { try { return fs.readFileSync(f(name), "utf8"); } catch { return ""; } };
// sshd -T: a Port in a drop-in replaces the default 22 — unless the main config names a port itself, then both apply
stub("sshd", `if [ "$1" = "-t" ]; then [ -f "${base}/sshd-t-fails" ] && { echo "Bad port" >&2; exit 1; }; exit 0; fi
cat "${dropins}"/*.conf 2>/dev/null | grep -v '^#' | tr 'A-Z' 'a-z'
if [ -f "${base}/main-sets-port" ] || ! grep -qi '^port' "${dropins}"/*.conf 2>/dev/null; then echo "port 22"; fi
echo "passwordauthentication no"`);
stub("systemctl", `echo "$*" >> "${base}/systemctl"; [ "$*" = "is-active ssh.socket" ] && [ -f "${base}/socket" ] && echo active; exit 0`);
stub("ufw", `echo "$*" >> "${base}/ufw"; if [ "$1" = status ]; then cat "${base}/ufw-status" 2>/dev/null || echo "Status: inactive"; fi; exit 0`);
stub("ss", `echo 'LISTEN 0 511 0.0.0.0:22222 0.0.0.0:* users:(("nginx",pid=1,fd=6))'`);
stub("dpkg", "exit 0"); // ufw counts as installed: no apt in a test
stub("fail2ban-client", `echo "$*" >> "${base}/f2b"`);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_SSHD_DROPIN_DIR: dropins, AGENT_F2B_JAIL_DIR: jaild, AGENT_SSH_SOURCES_FILE: f("ssh-sources.txt"),
  AGENT_ALLOWLIST_FILE: f("allowlist.txt"), AGENT_TOKEN: "t".repeat(64) });

const greeter = () => new Promise((res) => { const s = net.createServer((c) => { c.on("error", () => {}); c.write("SSH-2.0-OpenSSH_9.6\r\n"); }).listen(0, "127.0.0.1", () => res(s)); });
const s1 = await greeter(), s2 = await greeter();
const P1 = s1.address().port, P2 = s2.address().port;
const dead = await new Promise((res) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); }); // a free port nothing answers on

const { operations } = await import(path.join(A, "src/operations/index.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const go = (p) => { const v = operations.sshaccess.validate(p); assert.ok(v.ok, v.errors.join()); lines.length = 0; fs.writeFileSync(f("ufw"), ""); fs.writeFileSync(f("systemctl"), ""); return operations.sshaccess.run({ id: "j" }, helpers, v.clean); };
const dropin = () => { try { return fs.readFileSync(path.join(dropins, "00-wcp-port.conf"), "utf8"); } catch { return null; } };
const ufwCalls = () => said("ufw").split("\n").filter((l) => l && !l.startsWith("status"));

// ---- 1) what is refused before anything runs ---------------------------------------------
for (const bad of [{}, { port: 0 }, { port: 70000 }, { port: "22; reboot" }, { port: 80 }, { port: 443 }, { sources: ["1.2.3.4; reboot"] }, { sources: "1.2.3.4" }, { sources: Array(51).fill("1.2.3.4") }]) {
  assert.equal(operations.sshaccess.validate(bad).ok, false, JSON.stringify(bad));
}
assert.deepEqual(operations.sshaccess.validate({ port: "2222", sources: ["1.2.3.4", "1.2.3.4", "10.0.0.0/8"] }).clean, { port: 2222, sources: ["1.2.3.4", "10.0.0.0/8"] });
console.log("1. validation: only a real port (not web, database or the agent's) and real addresses get through");

// ---- 2) moving the port: firewall opened first, sshd proven on the new port, old opening removed last ----
await go({ port: P1 });
assert.match(dropin(), new RegExp(`\\nPort ${P1}\\n$`));
assert.deepEqual(ufwCalls(), [`allow ${P1}/tcp`, "delete allow 22/tcp", "delete allow 22", "delete allow OpenSSH"], "the new port is opened BEFORE the old one is closed");
assert.match(said("systemctl"), /reload ssh\n/); assert.ok(!/ssh\.socket\n.*restart/s.test(said("systemctl")));
assert.match(lines.join("\n"), new RegExp(`sshd answers on port ${P1}`)); assert.match(lines.join("\n"), new RegExp(`test a NEW one now: ssh -p ${P1} `));
console.log("2. port moved: opened in the firewall first, sshd greeted on the new port, the old port's rules removed last");

// ---- 3) every way it can go wrong leaves the old way in untouched --------------------------
const before = dropin();
await assert.rejects(go({ port: dead }), new RegExp(`sshd did not answer on port ${dead}, so it was put back: SSH is still on port ${P1}`));
assert.equal(dropin(), before, "the drop-in is back as it was"); assert.deepEqual(ufwCalls(), [`allow ${dead}/tcp`, `delete allow ${dead}/tcp`], "its opening is taken away again, and the working port's rules were never touched");
flag("main-sets-port");
await assert.rejects(go({ port: P2 }), /sets Port itself\. Remove that line on the server/); assert.equal(dropin(), before); flag("main-sets-port", false);
flag("sshd-t-fails");
await assert.rejects(go({ port: P2 }), /sshd rejected the new port, nothing changed: Bad port/); assert.equal(dropin(), before); flag("sshd-t-fails", false);
await assert.rejects(go({ port: 22222 }), /port 22222 is already used by nginx — nothing changed/); assert.deepEqual(ufwCalls(), []);
console.log("3. no answer on the new port / Port set elsewhere / sshd rejects it / port taken: all put back, old port still open");

// ---- 4) who may connect: needs the firewall on; the tailnet is always let in ------------------
await assert.rejects(go({ sources: ["1.2.3.4"] }), /the firewall is off — turn it on first/); assert.deepEqual(ufwCalls(), []); assert.equal(said("ssh-sources.txt"), "");
fs.writeFileSync(f("ufw-status"), `Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] ${P1}/tcp                  ALLOW IN    Anywhere\n`);
await go({ sources: ["1.2.3.4", "10.0.0.0/8"] });
const tail = `in on tailscale0 to any port ${P1} proto tcp`;
assert.deepEqual(ufwCalls(), [`allow from 1.2.3.4 to any port ${P1} proto tcp`, `allow from 10.0.0.0/8 to any port ${P1} proto tcp`, `allow ${tail}`,
  `delete allow ${P1}/tcp`, `delete allow ${P1}`], "the listed addresses and the tailnet are let in BEFORE the open-to-everyone rule is removed");
assert.equal(said("ssh-sources.txt"), "1.2.3.4\n10.0.0.0/8\n"); assert.equal(dropin(), before, "the port was not touched");
assert.match(lines.join("\n"), new RegExp(`SSH is STILL open to everyone through: ${P1}/tcp ALLOW IN Anywhere`), "a rule that still lets everyone in is named (the stand-in firewall never forgets its rule)");
assert.match(lines.join("\n"), /still open to everyone — see the warning above/, "and the summary does not claim otherwise");
console.log("4. limited to two addresses: needs the firewall on, tailnet always allowed, the open rule removed last, leftovers named");

// one address taken off: only its rule goes
await go({ sources: ["10.0.0.0/8"] });
assert.ok(ufwCalls().includes(`delete allow from 1.2.3.4 to any port ${P1} proto tcp`)); assert.ok(!ufwCalls().includes(`delete allow ${tail}`)); assert.ok(!ufwCalls().some((c) => c.startsWith("delete allow from 10.")));
// turning the firewall on again later rebuilds the SAME limit instead of opening SSH to everyone
fs.writeFileSync(f("ufw"), "");
await operations.harden.run({ id: "j" }, helpers, operations.harden.validate({ actions: ["firewall"] }).clean);
assert.ok(ufwCalls().includes(`allow from 10.0.0.0/8 to any port ${P1} proto tcp`) && ufwCalls().includes(`allow ${tail}`)); assert.ok(!ufwCalls().includes(`allow ${P1}/tcp`), "the firewall fix keeps SSH limited");
console.log("5. an address removed loses only its own rule; the firewall fix keeps the limit");

// ---- 5) port and list together, on a server that starts ssh from a socket (Ubuntu 24.04); fail2ban follows ----
fs.writeFileSync(path.join(jaild, "wcp.local"), "[sshd]\nenabled = true\nport = 22\nbackend = systemd\n\n[recidive]\nenabled = false\n");
flag("socket");
await go({ port: P2, sources: ["10.0.0.0/8", "203.0.113.7"] });
assert.match(said("systemctl"), /daemon-reload\nrestart ssh\.socket\n/, "the socket unit is regenerated and restarted");
const calls = ufwCalls();
assert.ok(calls.indexOf(`allow from 203.0.113.7 to any port ${P2} proto tcp`) < calls.indexOf(`delete allow from 10.0.0.0/8 to any port ${P1} proto tcp`), "new port opened to the list before the old port's rules go");
assert.ok(calls.includes(`delete allow in on tailscale0 to any port ${P1} proto tcp`) && calls.includes(`delete allow ${P1}/tcp`));
assert.match(fs.readFileSync(path.join(jaild, "wcp.local"), "utf8"), new RegExp(`^\\[sshd\\]\\nenabled = true\\nport = ${P2}\\nbackend = systemd\\n\\n\\[recidive\\]`));
assert.equal(said("ssh-sources.txt"), "10.0.0.0/8\n203.0.113.7\n");
console.log("6. port + list in one go on a socket-started ssh: socket restarted, old port fully closed, fail2ban guards the new port");

// ---- 6) open to anyone again: the open rule first, then the per-address rules go ---------------
await go({ sources: [] });
assert.equal(ufwCalls()[0], `allow ${P2}/tcp`); assert.ok(ufwCalls().includes(`delete allow from 203.0.113.7 to any port ${P2} proto tcp`) && ufwCalls().includes(`delete allow in on tailscale0 to any port ${P2} proto tcp`));
assert.equal(said("ssh-sources.txt"), "");
console.log("7. open to anyone again: opened first, per-address rules removed after");

s1.close(); s2.close();
console.log("\nPASS: SSH port and who may reach it — opened before closed, proven before committed, put back on any failure");
