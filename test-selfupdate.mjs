import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
const A = dirname(fileURLToPath(import.meta.url));

// Stub git / npm / systemd-run on PATH and record what they were asked to do.
// The op resolves its install dir from its own location (this repo, which IS a
// git checkout), but the stubs mean nothing real is pulled or restarted.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "selfupd-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const log = path.join(base, "calls.log");
const stub = (name, body) => { const p = path.join(bin, name); fs.writeFileSync(p, `#!/usr/bin/env bash\necho "${name} $*" >> "${log}"\n${body}\n`); fs.chmodSync(p, 0o755); };
// git: rev-parse returns a sha that changes after the pull
stub("git", 'if [[ "$*" == *rev-parse* ]]; then [ -f "'+base+'/pulled" ] && echo bbbbbbb || echo aaaaaaa; fi; if [[ "$*" == *pull* ]]; then touch "'+base+'/pulled"; fi; exit 0');
stub("npm", "exit 0");
stub("systemd-run", "exit 0");
process.env.PATH = `${bin}:${process.env.PATH}`;
process.env.AGENT_JOB_TIMEOUT_MS = "5000";

const { enqueue, getJob, STATE } = await import(`${A}/src/jobs.js`);
const { runSelfUpdate } = await import(`${A}/src/operations/selfupdate.js`);
const { getOperation } = await import(`${A}/src/operations/index.js`);
const lines = [];
const helpers = { log: (m) => lines.push(String(m)), err: (m) => lines.push(String(m)), onCancel() {} };
const until = async (id, state, ms = 4000) => { const t0 = Date.now(); while (getJob(id).state !== state) { if (Date.now() - t0 > ms) throw new Error(`stuck in ${getJob(id).state}`); await new Promise((r) => setTimeout(r, 20)); } };

// 1) registered as an op with no params
assert.ok(getOperation("selfupdate"), "selfupdate registered");
assert.ok(getOperation("selfupdate").validate({ anything: 1 }).ok);
console.log("1. selfupdate is a registered, param-less op");

// 2) happy path: pull -> install -> restart is DEFERRED via systemd-run, never run inline
const res = await runSelfUpdate({ id: "self" }, helpers);
const calls = fs.readFileSync(log, "utf8");
assert.deepEqual(res, { before: "aaaaaaa", after: "bbbbbbb" });
assert.ok(/git .*pull --ff-only/.test(calls), "git pull ran");
assert.ok(/npm install --omit=dev/.test(calls), "npm install ran");
assert.ok(/systemd-run --quiet --on-active=5 systemctl restart streaming-agent/.test(calls), "restart handed to systemd on a delay");
assert.ok(!/^systemctl /m.test(calls), "systemctl was NOT invoked directly (would kill this process mid-job)");
assert.ok(lines.some((l) => l.includes("aaaaaaa → bbbbbbb")), "logs show the sha change");
console.log("2. pull → install → deferred restart (never inline):", res);

// 3) refuses while another job is queued: the restart would drop it
const stuck = enqueue("deploy", {}, () => new Promise(() => {})); // holds the slot forever
await until(stuck.id, STATE.RUNNING);
await assert.rejects(() => runSelfUpdate({ id: "self2" }, helpers), /other job\(s\) queued or running/);
console.log("3. refuses to restart while another job is live");

console.log("\nPASS: selfupdate pulls, installs, defers the restart to systemd, and guards the queue");
fs.rmSync(base, { recursive: true, force: true });
process.exit(0);
