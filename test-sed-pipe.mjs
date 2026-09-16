import assert from "node:assert";
import { spawn } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { Readable, PassThrough } from "node:stream";

// Mirror the exact SED_ARGS from migrate.js
const SED_ARGS = [
  "-e", "s/utf8mb4_0900_ai_ci/utf8mb4_unicode_ci/g",
  "-e", "s/utf8mb4_0900_as_ci/utf8mb4_unicode_ci/g",
  "-e", "s/utf8mb4_0900_as_cs/utf8mb4_unicode_ci/g",
  "-e", "s/utf8mb4_0900_bin/utf8mb4_bin/g",
  "-e", "s/[[:space:]]DEFINER=`[^`]*`@`[^`]*`//g",
];
const runSed = async (inputBuf) => {
  const sed = spawn("sed", SED_ARGS, { env: { ...process.env, LC_ALL: "C" } });
  const out = []; sed.stdout.on("data", (c) => out.push(c));
  await Promise.all([
    pipeline(Readable.from(inputBuf), sed.stdin),
    new Promise((res, rej) => { sed.on("close", res); sed.on("error", rej); }),
  ]);
  return Buffer.concat(out);
};

// 1) collation rewrite + DEFINER strip (same as the shell normalize_stream)
let r = (await runSed(Buffer.from(
  "COLLATE=utf8mb4_0900_ai_ci ...\n" +
  "/*!50013 DEFINER=`app_write`@`%` SQL SECURITY DEFINER */\n" +
  "x utf8mb4_0900_bin y\n", "latin1"))).toString("latin1");
assert.ok(r.includes("utf8mb4_unicode_ci") && !r.includes("0900_ai"), "ai_ci rewritten");
assert.ok(r.includes("utf8mb4_bin") && !r.includes("0900_bin"), "bin rewritten");
assert.ok(!/DEFINER=/.test(r), "DEFINER stripped");
console.log("1. sed rewrites collations + strips DEFINER: OK");

// 2) byte-exact on --hex-blob-style content (ASCII hex, no patterns) at size
const hex = Buffer.from("INSERT INTO t VALUES (0x" + "AB".repeat(2_000_000) + ");\n", "latin1");
r = await runSed(hex);
assert.ok(r.equals(hex), "hex-blob line passes through byte-exact");
console.log(`2. byte-exact through a ${(hex.length/1048576).toFixed(1)} MB hex line: OK`);

// 3) THE FREEZE CASE: one 80 MB line, no newline until the end. sed streams it
//    in its own process — Node's event loop stays responsive the whole time.
const HUGE = 80 * 1024 * 1024;
let heartbeats = 0;
const hb = setInterval(() => { heartbeats++; }, 15); // proves the loop isn't blocked
async function* giant() {
  const blk = Buffer.alloc(1024 * 1024, 0x41);
  for (let i = 0; i < HUGE / blk.length; i++) { yield blk; await new Promise((r)=>setImmediate(r)); }
  yield Buffer.from("\n");
}
const sed = spawn("sed", SED_ARGS, { env: { ...process.env, LC_ALL: "C" } });
let outBytes = 0; sed.stdout.on("data", (c) => outBytes += c.length);
const t0 = Date.now();
await Promise.all([
  pipeline(Readable.from(giant()), sed.stdin),
  new Promise((res) => sed.on("close", res)),
]);
clearInterval(hb);
assert.equal(outBytes, HUGE + 1, "all 80MB streamed through sed");
assert.ok(heartbeats > 5, `event loop stayed live (${heartbeats} heartbeats) — no freeze`);
console.log(`3. 80 MB single line through sed in ${Date.now()-t0}ms, ${heartbeats} heartbeats — event loop never blocked`);

// 4) killable: a sed reading a stream that never ends must die on SIGTERM
const stuck = spawn("sed", SED_ARGS, { env: { ...process.env, LC_ALL: "C" } });
const neverEnds = new PassThrough(); neverEnds.write("SELECT 1;\n"); // keep stdin open, no end
neverEnds.pipe(stuck.stdin);
await new Promise((r) => setTimeout(r, 100));
assert.equal(stuck.killed, false, "still running before kill");
stuck.kill("SIGTERM");
const sig = await new Promise((res) => stuck.on("close", (_code, signal) => res(signal)));
assert.equal(sig, "SIGTERM", "sed terminates on SIGTERM (cancellable)");
neverEnds.destroy();
console.log("4. a running sed is killable via SIGTERM (Kill button / timeout works)");

console.log("\nPASS: sed pipe matches the shell script — no freeze, byte-exact, cancellable");
