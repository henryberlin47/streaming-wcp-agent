import assert from "node:assert";
import http from "node:http";
import { execFile } from "node:child_process"; import { promisify } from "node:util";
import path from "node:path"; import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// A stand-in CDN manager: JSON under /api (key checked), its web page with HTTP 200 everywhere else.
const seen = [];
const srv = http.createServer((req, res) => {
  let body = ""; req.on("data", (c) => { body += c; }); req.on("end", () => {
    seen.push(`${req.method} ${req.url} ${body}`);
    if (!req.url.startsWith("/api/")) { res.writeHead(200, { "content-type": "text/html" }); return res.end("<!DOCTYPE html><title>CDN Manager</title>"); }
    const json = (code, o) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
    if (req.headers["x-api-key"] !== "good-key") return json(401, { success: false, error: "unauthorized" });
    if (body.includes("taken.example")) return json(200, { success: false, error: "domain already exists" });
    json(200, { success: true, data: {} });
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const at = `http://127.0.0.1:${srv.address().port}`;
// the address and key are read when the agent starts, so each case runs in its own process
const ask = async (env, code) => { const e = { ...process.env, ...env }; for (const k of Object.keys(env)) if (env[k] === null) delete e[k];
  return JSON.parse((await promisify(execFile)("node", ["--input-type=module", "-e", `const a = await import(${JSON.stringify(path.join(A, "src/lib/api.js"))}); const c = await import(${JSON.stringify(path.join(A, "src/lib/siteConfig.js"))}); console.log(JSON.stringify(${code}));`], { env: e })).stdout); };

assert.equal(await ask({ CDN_API_BASE: null }, "c.CDN_API_BASE"), "https://cdnimgproxy.com/api");
console.log("1. default address: https://cdnimgproxy.com/api (https, and the /api path)");

const good = { CDN_API_BASE: `${at}/api/`, CDN_API_KEY: "good-key" };
assert.deepEqual(await ask(good, `await a.cdnAdd("cdn.a.example", "pfx")`), { ok: true, status: 200 });
assert.deepEqual(await ask(good, `await a.cdnDelete("cdn.a.example")`), { ok: true, status: 200 });
assert.ok(seen.includes(`POST /api/domains {"domain":"cdn.a.example","prefix":"pfx"}`) && seen.includes("DELETE /api/domains/cdn.a.example "), seen.join(" | "));
console.log("2. add and remove reach /api/domains and succeed");

assert.deepEqual(await ask(good, `await a.cdnAdd("cdn.taken.example", "pfx")`), { ok: false, status: 200, error: "domain already exists" });
assert.deepEqual(await ask({ ...good, CDN_API_KEY: "old-key" }, `await a.cdnAdd("cdn.a.example", "pfx")`), { ok: false, status: 401, error: "unauthorized" });
console.log("3. the service saying no is a failure, with its reason: a refused domain, a wrong key");

// the mistake this guards against: the bare host answers ANY path with its web page and HTTP 200
const r = await ask({ ...good, CDN_API_BASE: at }, `await a.cdnAdd("cdn.a.example", "pfx")`);
assert.equal(r.ok, false); assert.match(r.error, /did not answer \(got a web page/);
console.log("4. a web page with HTTP 200 is NOT counted as registered");

srv.close();
console.log("\nPASS: CDN registration talks to the API under /api and only believes its JSON answer");
