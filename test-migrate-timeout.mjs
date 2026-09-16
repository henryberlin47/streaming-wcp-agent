import assert from "node:assert";
import { pipeline } from "node:stream/promises";
import { Readable, PassThrough } from "node:stream";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
const A = dirname(fileURLToPath(import.meta.url));

// 1) per-op timeout: migrate gets its own leash, everyone else the default
const { default: config } = await import(`${A}/src/config.js`);
const pick = (type) => config.opTimeouts?.[type] || config.jobTimeoutMs;
assert.equal(pick("deploy"), config.jobTimeoutMs, "deploy uses default");
assert.ok(pick("migrate") > config.jobTimeoutMs, "migrate gets a longer timeout");
assert.equal(pick("migrate"), 2 * 60 * 60 * 1000, "migrate default is 2h");
console.log(`timeouts: default=${config.jobTimeoutMs/60000}min, migrate=${pick("migrate")/3600000}h`);

// 2) progressStream must be byte-exact (it sits in the SQL pipe — one dropped
//    byte corrupts the import) and must report ticks
const { progressStream } = await import(`${A}/src/lib/mysql.js`);
const payload = crypto.randomBytes(5 * 1024 * 1024); // 5 MB incl. binary/hex-blob bytes
let ticks = 0, lastMb = 0;
const chunks = [];
const sink = new PassThrough();
sink.on("data", (c) => chunks.push(c));
await pipeline(Readable.from(payload), progressStream((mb, rate) => { ticks++; lastMb = mb; }, 20), sink);
const out = Buffer.concat(chunks);
assert.ok(out.equals(payload), "progressStream must pass bytes through byte-exact");
console.log(`byte-exact through ${(out.length/1048576).toFixed(1)} MB; ${ticks} tick(s), last=${lastMb.toFixed(1)} MB`);

console.log("\nPASS: migrate gets a 2h leash, progress is byte-exact + reported");

// 3) ticks actually fire during a slow transfer + timer is cleaned up
{
  async function* trickle() {
    for (let i = 0; i < 6; i++) { await new Promise((r) => setTimeout(r, 30)); yield Buffer.alloc(1048576, 1); }
  }
  let ticks = 0;
  const s = new PassThrough(); s.resume();
  await pipeline(Readable.from(trickle()), progressStream(() => { ticks++; }, 25), s);
  assert.ok(ticks >= 2, `expected ongoing ticks during a slow transfer, got ${ticks}`);
  console.log(`slow transfer produced ${ticks} heartbeat tick(s)`);
}
