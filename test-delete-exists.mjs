import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
const R = dirname(fileURLToPath(import.meta.url));

// stub `wo` so we can simulate the orphaned-registry bug:
// - `wo site list`  → domain IS listed (registry row survives)
// - `wo site info`  → FAILS (files gone) — the old, broken signal
// - `wo site delete`→ removes it from the fake registry
const base = fs.mkdtempSync(path.join(os.tmpdir(), "del-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const reg = path.join(base, "registry"); fs.writeFileSync(reg, "frontfive.io\nother.com\n");
const wo = path.join(bin, "wo");
fs.writeFileSync(wo, `#!/usr/bin/env bash
sub="$2"
if [ "$sub" = "list" ]; then cat "${reg}"; exit 0; fi
dom="$3"
if [ "$sub" = "info" ]; then exit 1; fi          # info always fails (files gone) — the old trap
if [ "$sub" = "delete" ]; then grep -vx "$dom" "${reg}" > "${reg}.tmp"; mv "${reg}.tmp" "${reg}"; exit 0; fi
exit 0
`);
fs.chmodSync(wo, 0o755);
process.env.PATH = `${bin}:${process.env.PATH}`;

const { woSiteExists, woSiteList } = await import(`${R}/src/lib/sys.js`);
const helpers = { log() {}, err() {}, onCancel() {} };

// the crux: site is in the registry but `wo site info` fails.
// old code returned false here → skipped delete. new code must return true.
assert.equal(await woSiteExists(helpers, "frontfive.io"), true,
  "orphaned registry row (info fails) must still count as existing");
assert.equal(await woSiteExists(helpers, "ghost.com"), false, "a domain never in the list is absent");

// simulate what delete's step 4 does now: exists → delete → verify gone
const { run } = await import(`${R}/src/lib/sys.js`);
await run(helpers, "wo", ["site", "delete", "frontfive.io", "--no-prompt", "--force"], { stdin: "" });
assert.equal(await woSiteExists(helpers, "frontfive.io"), false, "after delete it's gone from the registry");
assert.deepEqual(await woSiteList(helpers), ["other.com"], "only the sibling remains");

console.log("PASS: orphaned registry rows are now detected and deleted (root cause fixed)");
fs.rmSync(base, { recursive: true, force: true });
