import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: agent .env, two deployed sites, stubbed systemd-run. Built BEFORE importing.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "secrets-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const calls = path.join(base, "calls");
fs.writeFileSync(path.join(bin, "systemd-run"), `#!/bin/bash\necho "$@" >> "${calls}"\n`); fs.chmodSync(path.join(bin, "systemd-run"), 0o755);
const agentEnv = path.join(base, "agent.env");
fs.writeFileSync(agentEnv, "AGENT_TOKEN=abc\nADVMO_DOS_KEY=oldkey\nADVMO_DOS_SECRET=oldsecret\nTELEGRAM_BOT_TOKEN=oldbot\nSEO_MONITOR_TOKEN=oldseo\nCDN_API_KEY=oldcdn\n");
const www = path.join(base, "www");
const site = (d, body) => { fs.mkdirSync(path.join(www, d, "htdocs/src"), { recursive: true }); fs.writeFileSync(path.join(www, d, "htdocs/src/.env"), body); };
site("a.com", "WP_HOME='https://a.com'\nADVMO_DOS_KEY='oldkey'\nADVMO_DOS_SECRET='oldsecret'\nTELEGRAM_BOT_TOKEN='oldbot'\n");
site("b.com", "WP_HOME='https://b.com'\nADVMO_DOS_KEY='newkey'\nADVMO_DOS_SECRET='newsecret'\nTELEGRAM_BOT_TOKEN='oldbot'\n");
fs.mkdirSync(path.join(www, "notasite"));
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_WWW_DIR: www, AGENT_ENV_FILE: agentEnv });

const { operations } = await import(path.join(A, "src/operations/index.js"));
const { readEnv } = await import(path.join(A, "src/lib/envfile.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };

// 1) validation: at least one key, single-line strings only, unknown keys dropped
assert.equal(operations.secrets.validate({}).ok, false);
assert.equal(operations.secrets.validate({ ADVMO_DOS_KEY: "a\nb" }).ok, false);
const v = operations.secrets.validate({ ADVMO_DOS_KEY: "newkey", ADVMO_DOS_SECRET: "newsecret", AGENT_TOKEN: "hack" });
assert.deepEqual(v.clean, { sites: true, ADVMO_DOS_KEY: "newkey", ADVMO_DOS_SECRET: "newsecret" });
console.log("1. validate: needs a key, single line, only the five deploy secrets pass through");

// 2) run: agent .env updated (0600), both sites converge, restart scheduled once
await operations.secrets.run({ id: "j1" }, helpers, v.clean);
assert.equal(await readEnv(agentEnv, "ADVMO_DOS_KEY"), "newkey");
assert.equal(await readEnv(agentEnv, "SEO_MONITOR_TOKEN"), "oldseo", "untouched keys stay");
assert.equal(fs.statSync(agentEnv).mode & 0o777, 0o600);
assert.equal(await readEnv(path.join(www, "a.com/htdocs/src/.env"), "ADVMO_DOS_SECRET"), "newsecret");
assert.equal(await readEnv(path.join(www, "a.com/htdocs/src/.env"), "TELEGRAM_BOT_TOKEN"), "oldbot", "keys not given stay");
assert.equal(fs.readFileSync(calls, "utf8").trim().split("\n").length, 1, "one restart scheduled");
const out = lines.join("\n");
assert.ok(!out.includes("newkey") && !out.includes("newsecret"), "values never logged");
assert.match(out, /2 site\(s\) found, 1 updated/);
console.log("2. agent .env + sites updated, values never logged, one restart");

// 3) nothing changed -> no restart
lines.length = 0;
await operations.secrets.run({ id: "j2" }, helpers, v.clean);
assert.equal(fs.readFileSync(calls, "utf8").trim().split("\n").length, 1, "no second restart");
assert.match(lines.join("\n"), /agent \.env unchanged/);
console.log("3. re-run with the same values is a no-op (no restart)");

console.log("\nPASS: secrets rotate into the agent .env and every site, then the agent restarts");
fs.rmSync(base, { recursive: true, force: true });
