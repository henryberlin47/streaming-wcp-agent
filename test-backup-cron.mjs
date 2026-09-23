import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: /var/www + a cron.d dir (AGENT_CRON_DIR), stubbed systemctl. Built BEFORE importing.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "backupcron-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const calls = path.join(base, "calls");
fs.writeFileSync(path.join(bin, "systemctl"), `#!/bin/bash\necho "$@" >> "${calls}"\n`); fs.chmodSync(path.join(bin, "systemctl"), 0o755);
const cronDir = path.join(base, "cron.d"); fs.mkdirSync(cronDir);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_WWW_DIR: path.join(base, "www"), AGENT_CRON_DIR: cronDir });

const site = await import(path.join(A, "src/lib/site.js"));
const { operations } = await import(path.join(A, "src/operations/index.js"));
const helpers = { log() {}, err() {}, onCancel() {} };
const D = "example.com";
const cronOn = site.cronPath(D), cronOff = `${cronOn}.disabled`;
fs.writeFileSync(cronOff, "# test\n");
const fsOk = true;

// 1) validation of the cron op + backup flag on deploy/alias
assert.equal(operations.cron.validate({ domain: D, active: true }).ok, true);
assert.equal(operations.cron.validate({ domain: D, active: "yes" }).ok, false, "active must be a boolean");
assert.equal(operations.deploy.validate({ domain: D, root: D, backup: true }).clean.backup, true);
assert.equal(operations.deploy.validate({ domain: D, root: D }).clean.backup, false);
assert.equal(operations.alias.validate({ aliasDomain: `m.${D}`, mainDomain: D, backup: 1 }).clean.backup, true);
console.log("1. cron op validates; deploy/alias carry backup:true");

if (fsOk) {
  // 2) off -> on -> on (idempotent) -> off, cron restarted only on a real change
  assert.equal(await site.siteCron(D), "off");
  assert.equal(await site.setSiteCron(helpers, D, true), "on");
  assert.ok(fs.existsSync(cronOn) && !fs.existsSync(cronOff));
  await site.setSiteCron(helpers, D, true);
  assert.equal(fs.readFileSync(calls, "utf8").trim().split("\n").length, 1, "no restart when already on");
  assert.equal(await site.setSiteCron(helpers, D, false), "off");
  assert.ok(!fs.existsSync(cronOn) && fs.existsSync(cronOff));
  await assert.rejects(() => site.setSiteCron(helpers, "ghost.com", true), /no cron file/);
  fs.rmSync(cronOff, { force: true });
  console.log("2. cron on/off renames the file, restarts cron only on change, refuses unknown sites");
} else {
  console.log("2. (skipped: /etc/cron.d not writable here — rename logic exercised on a server)");
}
console.log("\nPASS: backup sites' cron can be switched on/off");
fs.rmSync(base, { recursive: true, force: true });
