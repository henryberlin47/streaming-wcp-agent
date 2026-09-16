import assert from "node:assert";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
const A = dirname(fileURLToPath(import.meta.url));

// Short timeout BEFORE import (config.js reads env at import time).
process.env.AGENT_JOB_TIMEOUT_MS = "200";
const { enqueue, getJob, cancelJob, STATE } = await import(`${A}/src/jobs.js`);

const until = async (id, state, ms = 3000) => {
  const t0 = Date.now();
  while (getJob(id).state !== state) {
    if (Date.now() - t0 > ms) throw new Error(`job ${id} stuck in '${getJob(id).state}', wanted '${state}'`);
    await new Promise((r) => setTimeout(r, 20));
  }
};

// 1) THE WEDGE: a runner stuck forever in a non-child await registers NO cancel
//    hook. Before the fix the timeout only flipped a flag, the runner never
//    settled, and the single concurrency slot was held forever. Now the runner
//    is raced against the timeout, so it MUST time out AND free the slot.
const stuck = enqueue("deploy", {}, () => new Promise(() => {}));
await until(stuck.id, STATE.TIMEOUT);
console.log("1. stuck runner timed out:", getJob(stuck.id).state);

//    ...and the slot is free: a job queued behind it actually runs.
const next = enqueue("deploy", {}, async () => "ok");
await until(next.id, STATE.SUCCEEDED);
console.log("2. queued job ran after the stuck one — slot was released");

// 3) Cancel a running job: its child cancel hooks fire AND state is CANCELLED,
//    not FAILED, so the panel can tell "I stopped it" from "it broke".
let killed = 0;
const j = enqueue("deploy", {}, (job, helpers) => new Promise(() => {
  helpers.onCancel(() => { killed++; });
  helpers.onCancel(() => { killed++; }); // a second child: ALL hooks must fire, not just the latest
}));
await until(j.id, STATE.RUNNING);
assert.deepEqual(cancelJob(j.id), { ok: true }, "a running job is always cancellable");
await until(j.id, STATE.CANCELLED);
assert.equal(killed, 2, "every registered child cancel hook fired");
console.log("3. cancel -> state 'cancelled' (not 'failed'), all", killed, "child hooks fired");

// 4) A normal failure is still FAILED (cancel plumbing doesn't mask real errors).
const bad = enqueue("deploy", {}, async () => { throw new Error("boom"); });
await until(bad.id, STATE.FAILED);
console.log("4. a thrown error is still 'failed'");

console.log("\nPASS: stuck jobs time out and free the slot; cancel is distinct and kills all children");
process.exit(0);
