import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: agent .env + stubbed systemd-run. Built BEFORE importing.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "rotatekey-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const calls = path.join(base, "calls");
fs.writeFileSync(path.join(bin, "systemd-run"), `#!/bin/bash\necho "$@" >> "${calls}"\n`); fs.chmodSync(path.join(bin, "systemd-run"), 0o755);
const OLD = "o".repeat(64), NEW = "n".repeat(64);
const agentEnv = path.join(base, "agent.env");
fs.writeFileSync(agentEnv, `AGENT_TOKEN=${OLD}\nADVMO_DOS_KEY=keep\n`);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_ENV_FILE: agentEnv, AGENT_TOKEN: OLD, AGENT_ALLOWED_IPS: "" });

const { operations } = await import(path.join(A, "src/operations/index.js"));
const { readEnv } = await import(path.join(A, "src/lib/envfile.js"));
const { requireAuth } = await import(path.join(A, "src/auth.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
// status the auth middleware answers for a bearer token (200 = let through)
const auth = (token) => {
  let status = 200;
  requireAuth({ headers: { authorization: `Bearer ${token}` }, socket: { remoteAddress: "127.0.0.1" } }, { status: (s) => { status = s; return { json() {} }; } }, () => {});
  return status;
};

// 1) validation: a long, env-file-safe token only
for (const bad of [undefined, "", "short", "x".repeat(31), `${"x".repeat(40)}\nEVIL=1`, `${"x".repeat(40)}'`, "x".repeat(201)]) {
  assert.equal(operations.rotatekey.validate({ token: bad }).ok, false, `rejects ${JSON.stringify(bad)}`);
}
assert.equal(operations.rotatekey.validate({ token: NEW }).ok, true);
console.log("1. validate: 32-200 safe characters, nothing an env file could trip on");

// 2) before: only the old key
assert.equal(auth(OLD), 200); assert.equal(auth(NEW), 401);

// 3) run: .env holds the new key (0600), other keys stay, restart scheduled, key never logged
await operations.rotatekey.run({ id: "j1" }, helpers, { token: NEW });
assert.equal(await readEnv(agentEnv, "AGENT_TOKEN"), NEW);
assert.equal(await readEnv(agentEnv, "ADVMO_DOS_KEY"), "keep");
assert.equal(fs.statSync(agentEnv).mode & 0o777, 0o600);
assert.equal(fs.readFileSync(calls, "utf8").trim().split("\n").length, 1, "one restart scheduled");
assert.ok(!lines.join("\n").includes(NEW), "the key is never logged");
console.log("2. new key in the agent .env, restart scheduled, key never logged");

// 4) until the restart BOTH keys work (the portal reads the result with the old one), nothing else does
assert.equal(auth(OLD), 200); assert.equal(auth(NEW), 200); assert.equal(auth("z".repeat(64)), 401);
console.log("3. old and new key both accepted until the restart; any other key is refused");

console.log("\nPASS: the agent key rotates into .env, overlaps until the restart, and is never logged");
fs.rmSync(base, { recursive: true, force: true });
