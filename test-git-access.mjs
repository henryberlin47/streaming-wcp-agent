import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
const A = dirname(fileURLToPath(import.meta.url));

// Stub ssh + git on PATH; fake HOME with a public key. Set up BEFORE imports.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "gitacc-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
fs.mkdirSync(path.join(base, ".ssh"));
fs.writeFileSync(path.join(base, ".ssh/id_ed25519.pub"), "ssh-ed25519 AAAAC3Nza…FAKE streaming-agent@test\n");
const stub = (name, body) => { const p = path.join(bin, name); fs.writeFileSync(p, `#!/usr/bin/env bash\n${body}\n`); fs.chmodSync(p, 0o755); };
process.env.PATH = `${bin}:${process.env.PATH}`;
process.env.HOME = base;

const { explainGitError, GIT_SSH_ARGS, run } = await import(`${A}/src/lib/sys.js`);
const { cloneMap } = await import(`${A}/src/lib/map.js`);
const { runSshCheck } = await import(`${A}/src/operations/sshcheck.js`);
const mk = () => { const lines = []; return { lines, helpers: { log: (m) => lines.push(String(m)), err: (m) => lines.push(String(m)), onCancel() {} } }; };

// ---- 1. each well-known cause gets its own, actionable explanation ----------
const cases = [
  ["git@github.com: Permission denied (publickey).\nfatal: Could not read from remote repository.", /rejected this server's SSH key.*GitHub ACCOUNT/],
  ["Host key verification failed.\nfatal: Could not read from remote repository.", /known_hosts.*ssh-keyscan/],
  ["ERROR: Repository not found.\nfatal: Could not read from remote repository.", /authenticated, but that GitHub account cannot see/],
  ["ssh: Could not resolve hostname github.com: Temporary failure in name resolution", /Network\/DNS problem/],
  ["something nobody anticipated", /git could not reach/],
];
for (const [stderr, want] of cases) {
  const msg = explainGitError(stderr, "seo-domain-map");
  assert.ok(want.test(msg), `${want} !~ ${msg}`);
  assert.ok(msg.includes("[git: "), "git's own words always travel with the explanation");
}
console.log("1. five distinct causes → five distinct, actionable messages (git's stderr always included)");

// ---- 2. cloneMap no longer hides the cause (this is the bug in the screenshot)
stub("git", 'echo "git@github.com: Permission denied (publickey)." >&2; echo "fatal: Could not read from remote repository." >&2; exit 128');
await assert.rejects(() => cloneMap(mk().helpers), (e) => {
  assert.ok(/rejected this server's SSH key for seo-domain-map/.test(e.message), e.message);
  assert.ok(/Permission denied \(publickey\)/.test(e.message), "real git error is in the message");
  return true;
});
// ssh can never prompt/hang a job, and ALWAYS offers the agent's own key — even
// when ~/.ssh/config pins a different one with IdentitiesOnly (the real-world
// failure: right key on GitHub, never presented, "Permission denied").
assert.equal(GIT_SSH_ARGS[0], "-c");
assert.equal(GIT_SSH_ARGS[1], `core.sshCommand=ssh -i ${base}/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4`);
console.log("2. cloneMap reports the real cause instead of 'check root SSH access'");

// ---- 3. sshcheck: authenticated, map readable, app repo NOT → precise verdict
// GitHub's `ssh -T` greets then exits 1 — success must be judged by the greeting.
stub("ssh", `echo "Hi yosua! You've successfully authenticated, but GitHub does not provide shell access." >&2; exit 1`);
stub("git", 'if [[ "$*" == *seo-domain-map* ]]; then echo "abc123\trefs/heads/main"; exit 0; fi; echo "ERROR: Repository not found." >&2; exit 128');
let t = mk();
await assert.rejects(() => runSshCheck({}, t.helpers), /1 repo\(s\) unreadable/);
let out = t.lines.join("\n");
assert.ok(out.includes("ssh-ed25519 AAAAC3Nza…FAKE"), "shows which key to authorise");
assert.ok(out.includes("authenticated as yosua"), "exit 1 + greeting is treated as success");
assert.ok(/✓ .*seo-domain-map/.test(out) && /✗ .*xoilac-ols.*cannot see/.test(out), "per-repo verdicts");
console.log("3. sshcheck: key shown, 'Hi yosua' = authenticated despite exit 1, per-repo ✓/✗ with the reason");

// ---- 4. sshcheck: everything fine → succeeds
stub("git", 'echo "abc123\trefs/heads/main"; exit 0');
t = mk();
await runSshCheck({}, t.helpers);
assert.ok(t.lines.join("\n").includes("GitHub access OK"));
console.log("4. sshcheck passes when both repos are readable");

// ---- 5. EVERY git the agent spawns gets the pinned ssh, not just the clones.
// Site updates (`git fetch`) and the map push go through plain run(); before
// this they used default ssh and would hit "Permission denied" on a box whose
// ~/.ssh/config pins another key — even after the clone paths were fixed.
stub("git", 'echo "GIT_SSH_COMMAND=$GIT_SSH_COMMAND"; exit 0');
const fetched = await run(mk().helpers, "git", ["-C", "/var/www/x/htdocs", "fetch", "origin"], { quiet: true });
assert.ok(fetched.stdout.includes(`GIT_SSH_COMMAND=ssh -i ${base}/.ssh/id_ed25519 -o BatchMode=yes`), fetched.stdout);
console.log("5. a plain `git fetch` via run() inherits the pinned key — all call sites covered");

console.log("\nPASS: git/SSH failures now explain themselves, and access is checkable in one click");
fs.rmSync(base, { recursive: true, force: true });
