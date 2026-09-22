import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// A REAL git repo (file:// so --depth is honoured) with history on two branches.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "shallow-"));
const origin = path.join(base, "origin.git"), work = path.join(base, "work");
const g = (cwd, ...a) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...a], { cwd, stdio: "pipe" }).toString().trim();
fs.mkdirSync(work); g(work, "init", "-q", "-b", "main");
fs.mkdirSync(path.join(work, "src/web"), { recursive: true });
for (let i = 1; i <= 5; i++) { fs.writeFileSync(path.join(work, "src/web/v.txt"), `main ${i}`); g(work, "add", "-A"); g(work, "commit", "-qm", `main ${i}`); }
g(work, "checkout", "-qb", "JA-Theme"); fs.writeFileSync(path.join(work, "src/web/v.txt"), "theme 1"); g(work, "commit", "-qam", "theme 1");
g(base, "clone", "-q", "--bare", work, origin);
const url = `file://${origin}`;

process.env.AGENT_WWW_DIR = path.join(base, "www");
const { cloneRepo } = await import(path.join(A, "src/lib/site.js"));
const { run, gitRemoteBranchExists } = await import(path.join(A, "src/lib/sys.js"));
const helpers = { log() {}, err() {}, onCancel() {} };
const htdocs = path.join(base, "www/site.com/htdocs");

// 1) deploy clones ONE commit of ONE branch
await cloneRepo(helpers, { htdocs, branch: "main", repo: url });
assert.equal(g(htdocs, "rev-list", "--count", "HEAD"), "1", "history is not downloaded");
assert.equal(g(htdocs, "branch", "-r").includes("JA-Theme"), false, "other branches are not downloaded");
assert.equal(fs.readFileSync(path.join(htdocs, "src/web/v.txt"), "utf8"), "main 5");
console.log("1. deploy clone: 1 commit, 1 branch, right files");

// 2) the update op's fetch (same args) can still move to a new commit AND to another branch
const fetchBranch = async (b) => {
  const shallow = fs.existsSync(path.join(htdocs, ".git/shallow"));
  return run(helpers, "git", ["-C", htdocs, "fetch", "--quiet", ...(shallow ? ["--depth", "1"] : []), "origin", `+refs/heads/${b}:refs/remotes/origin/${b}`], { quiet: true });
};
g(work, "checkout", "-q", "main"); fs.writeFileSync(path.join(work, "src/web/v.txt"), "main 6"); g(work, "commit", "-qam", "main 6"); g(work, "push", "-q", origin, "main");
assert.equal((await fetchBranch("main")).code, 0);
g(htdocs, "reset", "-q", "--hard", "origin/main");
assert.equal(fs.readFileSync(path.join(htdocs, "src/web/v.txt"), "utf8"), "main 6");
assert.equal((await fetchBranch("JA-Theme")).code, 0);
assert.ok(await gitRemoteBranchExists(helpers, htdocs, "JA-Theme"));
g(htdocs, "checkout", "-q", "-f", "-B", "JA-Theme", "origin/JA-Theme");
assert.equal(fs.readFileSync(path.join(htdocs, "src/web/v.txt"), "utf8"), "theme 1");
assert.ok(Number(g(htdocs, "rev-list", "--count", "--all")) <= 3, "still shallow after updates");
console.log("2. update: new commits and a branch switch both work on the shallow clone, and it stays shallow");

// 3) a branch that doesn't exist is reported as such (not as a network error)
const miss = await fetchBranch("nope");
assert.notEqual(miss.code, 0); assert.match(miss.stderr, /couldn't find remote ref/i);
console.log("3. missing branch -> recognisable error");

// 4) the same fetch leaves an OLD full clone full
const full = path.join(base, "full"); g(base, "clone", "-q", url, full);
await run(helpers, "git", ["-C", full, "fetch", "--quiet", "origin", "+refs/heads/JA-Theme:refs/remotes/origin/JA-Theme"], { quiet: true });
assert.ok(!fs.existsSync(path.join(full, ".git/shallow")));
console.log("4. existing full clones are not truncated");

// 5) update validate: "owner/name" expands to the allowed SSH URL; anything else is refused
const { operations } = await import(path.join(A, "src/operations/index.js"));
const v = operations.update.validate({ domain: "site.com", repo: "yosuahernandez468-png/xoilac-ols", branch: "JA-Theme" });
assert.ok(v.ok, v.errors.join()); assert.equal(v.clean.repo, "git@github.com:yosuahernandez468-png/xoilac-ols.git"); assert.equal(v.clean.branch, "JA-Theme");
assert.equal(operations.update.validate({ domain: "site.com", repo: "evil/other" }).ok, false, "not on the allowlist");
assert.equal(operations.update.validate({ domain: "site.com", repo: "ext::sh -c id" }).ok, false);
assert.equal(operations.update.validate({ domain: "site.com" }).clean.repo, null);
console.log("5. update: repo shorthand expands, allowlist enforced");

// 6) cancelling a job never signals commands that already finished
const cancels = []; const errs = [];
const h2 = { log() {}, err: (l) => errs.push(l), onCancel: (fn) => cancels.push(fn) };
await run(h2, "true", [], { quiet: true }); await run(h2, "true", [], { quiet: true });
for (const fn of cancels) fn("cancelled");
assert.deepEqual(errs, [], "no SIGTERM lines for finished pids");
console.log("6. cancel only signals what is still running");

console.log("\nPASS: deploys clone shallow + single-branch, and update still works on them");
fs.rmSync(base, { recursive: true, force: true });
