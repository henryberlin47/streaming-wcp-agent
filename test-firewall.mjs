import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// A small ufw that keeps real state, so rule numbers shift the way they really do. Built BEFORE importing.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "firewall-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const state = path.join(base, "ufw.json");
fs.writeFileSync(state, JSON.stringify({ active: true, rules: [["22/tcp", "Anywhere"], ["80/tcp", "Anywhere"], ["8787/tcp on tailscale0", "Anywhere"]] }));
fs.writeFileSync(path.join(bin, "ufw"), `#!/usr/bin/env node
const fs = require("fs"); const s = JSON.parse(fs.readFileSync(${JSON.stringify(state)}, "utf8")); const a = process.argv.slice(2);
const save = () => fs.writeFileSync(${JSON.stringify(state)}, JSON.stringify(s));
const pad = (x, n) => String(x).padEnd(n);
if (a[0] === "status") {
  if (!s.active) { console.log("Status: inactive"); process.exit(0); }
  console.log("Status: active\\n\\n     To                         Action      From\\n     --                         ------      ----");
  s.rules.forEach(([to, from], i) => console.log("[" + String(i + 1).padStart(2) + "] " + pad(to, 27) + pad("ALLOW IN", 12) + from));
} else if (a[0] === "show") { s.rules.forEach(([to, from]) => console.log("ufw allow " + to + (from === "Anywhere" ? "" : " from " + from))); }
else if (a[0] === "allow") {
  let rule;
  if (a[1] === "in") rule = [a[7] + "/" + a[9] + " on " + a[3], "Anywhere"];
  else if (a[1] === "from") rule = [a[6] + "/" + a[8], a[2]];
  else rule = [a[1], "Anywhere"];
  if (s.rules.some((r) => r[0] === rule[0] && r[1] === rule[1])) console.log("Skipping adding existing rule"); else { s.rules.push(rule); console.log("Rule added"); }
  save();
} else if (a[0] === "--force" && a[1] === "delete") { s.rules.splice(Number(a[2]) - 1, 1); save(); console.log("Rule deleted"); }
else if (a[0] === "--force" && a[1] === "enable") { s.active = true; save(); console.log("Firewall is active"); }
else if (a[0] === "disable") { s.active = false; save(); console.log("Firewall stopped"); }
`); fs.chmodSync(path.join(bin, "ufw"), 0o755);
const stub = (name, body) => { fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`); fs.chmodSync(path.join(bin, name), 0o755); };
stub("sshd", "echo 'port 22'"); stub("dpkg", "exit 0");
stub("ss", `echo 'LISTEN 0 80 0.0.0.0:3306 0.0.0.0:* users:(("mariadbd",pid=4,fd=20))'`);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_PORT: "8787", AGENT_TOKEN: "t".repeat(64) });

const { operations } = await import(path.join(A, "src/operations/index.js"));
const { firewallStatus } = await import(path.join(A, "src/operations/firewall.js"));
const { parseUfw, ruleAllows } = await import(path.join(A, "src/lib/security.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const _log = console.log; const quiet = async (fn) => { console.log = () => {}; try { return await fn(); } finally { console.log = _log; } };
const fw = (p) => { const v = operations.firewall.validate(p); assert.ok(v.ok, v.errors.join("; ")); return quiet(() => operations.firewall.run({ id: "j" }, helpers, v.clean)); };
const rules = async () => (await firewallStatus()).rules.map((r) => `${r.to} <- ${r.from}`);
const bad = (p) => operations.firewall.validate(p).ok === false;

// 1) validation: nothing but a port, a protocol and an address ever reaches the command line
assert.ok(bad({ action: "allow", port: "0" }) && bad({ action: "allow", port: "70000" }) && bad({ action: "allow", port: "80; rm -rf /" }) && bad({ action: "allow", port: "90:80" }));
assert.ok(bad({ action: "allow", port: "3306", from: "not-an-ip" }) && bad({ action: "allow", port: "3306", from: "1.2.3.4/40" }) && bad({ action: "allow", port: "3306", from: "1.2.3.4; reboot" }));
assert.ok(bad({ action: "allow", port: "3306", from: "1.2.3.4", tailnet: true }) && bad({ action: "allow", port: "53", proto: "icmp" }) && bad({ action: "reset" }) && bad({ action: "delete", number: 0, raw: "x" }));
assert.deepEqual(operations.firewall.validate({ action: "allow", port: "3306", from: "157.245.59.219" }).clean, { action: "allow", port: "3306", proto: "tcp", from: "157.245.59.219", tailnet: false });
console.log("1. validate: ports, ranges, tcp/udp, addresses and networks only; anything else is refused");

// 2) the parser reads ufw's numbered list (real format)
const real = parseUfw("Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n[ 2] 3306/tcp                   ALLOW IN    157.245.59.219\n[ 3] 8787/tcp on tailscale0     ALLOW IN    Anywhere\n[10] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n");
assert.deepEqual(real.rules.map((r) => [r.n, r.to, r.from]), [[1, "22/tcp", "Anywhere"], [2, "3306/tcp", "157.245.59.219"], [3, "8787/tcp on tailscale0", "Anywhere"], [10, "22/tcp (v6)", "Anywhere (v6)"]]);
assert.deepEqual([22, 3306, 8787, 80].map((p) => real.rules.some((r) => ruleAllows(r, p))), [true, true, true, false]);

// 3) allow: to everyone, to one address, on the tailnet
await fw({ action: "allow", port: "443" });
await fw({ action: "allow", port: "3306", from: "157.245.59.219" });
await fw({ action: "allow", port: "3306", tailnet: true });
assert.deepEqual(await rules(), ["22/tcp <- Anywhere", "80/tcp <- Anywhere", "8787/tcp on tailscale0 <- Anywhere", "443/tcp <- Anywhere", "3306/tcp <- 157.245.59.219", "3306/tcp on tailscale0 <- Anywhere"]);
await assert.rejects(fw({ action: "allow", port: "8787" }), /this agent's own port/, "the agent port is never opened to the internet");
await assert.rejects(fw({ action: "allow", port: "8000:9000" }), /this agent's own port/, "…not inside a range either");
await fw({ action: "allow", port: "8787", from: "100.120.27.124" }); // from one address is fine
console.log("2. allow: for everyone, for one address, on the tailnet; the agent's own port is never opened to the internet");

// 4) delete: by number + text; a stale number never removes the wrong rule
let st = await firewallStatus();
const r443 = st.rules.find((r) => r.to === "443/tcp");
await fw({ action: "delete", number: r443.n, raw: r443.raw });
assert.ok(!(await rules()).includes("443/tcp <- Anywhere"));
await assert.rejects(fw({ action: "delete", number: r443.n, raw: r443.raw }), /rule list changed/, "same number now points at another rule: refused");
assert.equal((await rules()).length, 6, "nothing else was removed");

// 5) the two deletions that would cost you the server
st = await firewallStatus();
const ssh = st.rules.find((r) => r.to === "22/tcp");
await assert.rejects(fw({ action: "delete", number: ssh.n, raw: ssh.raw }), /last rule that lets SSH \(port 22\) in/);
const ag = st.rules.filter((r) => r.to.startsWith("8787/tcp"));
await fw({ action: "delete", number: ag[1].n, raw: ag[1].raw }); // one of two agent rules: fine
st = await firewallStatus();
const lastAgent = st.rules.find((r) => r.to.startsWith("8787/tcp"));
await assert.rejects(fw({ action: "delete", number: lastAgent.n, raw: lastAgent.raw }), /last rule that lets the portal reach the agent/);
await fw({ action: "allow", port: "22", from: "94.207.20.128" }); // SSH restricted to one address…
st = await firewallStatus();
await fw({ action: "delete", number: st.rules.find((r) => r.to === "22/tcp" && r.from === "Anywhere").n, raw: st.rules.find((r) => r.to === "22/tcp" && r.from === "Anywhere").raw }); // …then the open rule may go
assert.ok((await rules()).includes("22/tcp <- 94.207.20.128") && !(await rules()).includes("22/tcp <- Anywhere"));
console.log("3. delete: by number and text; refused for the last SSH rule and the last agent rule; SSH can be narrowed to one address");

// 6) off and on
await fw({ action: "disable" });
st = await firewallStatus();
assert.equal(st.active, false); assert.ok(st.staged.length > 0, "stored rules are still shown while it is off");
await assert.rejects(fw({ action: "delete", number: 1, raw: "x" }), /firewall is off/);
lines.length = 0;
await fw({ action: "enable" });
assert.equal((await firewallStatus()).active, true);
assert.match(lines.join("\n"), /will now be BLOCKED from the internet: 3306 \(mariadbd\)/);
assert.ok((await rules()).includes("22/tcp <- Anywhere"), "turning it on makes sure SSH is allowed first");
console.log("4. disable and enable: rules survive; enabling allows SSH first and names the ports it will block");

console.log("\nPASS: firewall rules can be listed, added, removed and switched from the panel, without a lockout");
fs.rmSync(base, { recursive: true, force: true });
