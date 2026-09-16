import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
const R = dirname(fileURLToPath(import.meta.url));

// build the fake world BEFORE importing anything (config.js reads env at import)
const base = fs.mkdtempSync(path.join(os.tmpdir(), "purge-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const SRC = path.join(base, "www", "site.com", "htdocs", "src");
const ROCKET = path.join(SRC, "web", "app", "cache", "wp-rocket");
fs.mkdirSync(ROCKET, { recursive: true });
fs.writeFileSync(path.join(ROCKET, "stale.html"), "old");

// wp-cli runs as `sudo -u www-data -H /usr/bin/php /usr/local/bin/wp ...`,
// so `sudo` is the binary that actually gets resolved off PATH.
const sudo = path.join(bin, "sudo");
const stubSudo = (body) => { fs.writeFileSync(sudo, `#!/usr/bin/env bash\n${body}\n`); fs.chmodSync(sudo, 0o755); };
stubSudo('echo "WP Rocket cache cleared"; exit 0');

process.env.AGENT_WWW_DIR = path.join(base, "www");
process.env.PATH = `${bin}:${process.env.PATH}`;

const { getOperation } = await import(`${R}/src/operations/index.js`);
const { runPurge } = await import(`${R}/src/operations/purge.js`);

const op = getOperation("purge");
assert.ok(op, "purge must be registered");
const r = op.validate({ domain: " HTTPS://Site.COM/ " });
assert.ok(r.ok && r.clean.domain === "site.com", JSON.stringify(r));
assert.ok(!op.validate({}).ok, "missing domain must be rejected");
console.log("purge: registered, domain sanitized, empty rejected\n");

const lines = [];
const helpers = { log: (m) => lines.push(String(m)), err: (m) => lines.push(String(m)), onCancel: () => {} };
await runPurge({}, helpers, { domain: "site.com" });
const out = lines.join("\n");
console.log(out);
assert.ok(/➜ 1\. Purge caches for site\.com/.test(out), "numbered step");
assert.ok(out.includes("WP Rocket page cache cleared"), "rocket reported");
assert.ok(out.includes("object cache flushed"), "object cache reported");

// a site that isn't deployed here must fail loudly, not silently "succeed"
await assert.rejects(() => runPurge({}, helpers, { domain: "nope.com" }), /not found/);

// both wp calls failing (broken wp-cli) must fail the job, after the disk fallback
stubSudo('echo "PHP Fatal error" >&2; exit 255');
await assert.rejects(() => runPurge({}, helpers, { domain: "site.com" }), /cache purge failed/);
assert.ok(!fs.existsSync(path.join(ROCKET, "stale.html")), "disk fallback wiped the stale rocket cache");
assert.ok(fs.existsSync(ROCKET), "disk fallback keeps the cache dir itself");

console.log("\nPASS: purges a real tree, disk fallback works, fails on missing site + broken wp-cli");
fs.rmSync(base, { recursive: true, force: true });
