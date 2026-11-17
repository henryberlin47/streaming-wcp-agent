import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake box: deployed sites and a stubbed `git clone` of the map. Built BEFORE importing.
// (wp-cli is /usr/bin/php + an absolute path — not stubbable; without it the op warns and carries on.)
const base = fs.mkdtempSync(path.join(os.tmpdir(), "dbcreds-"));
const bin = path.join(base, "bin"); fs.mkdirSync(bin);
const stub = (name, body) => { fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`); fs.chmodSync(path.join(bin, name), 0o755); };
const MAP = {
  "brand.tv": { DB_HOST: "10.0.0.9:3306", DB_NAME: "brand_db", DB_USER: "app", DB_PASSWORD: "NEW-pa'ss|word", CDN_PREFIX: "from-map" },
  "half.tv": { DB_HOST: "10.0.0.9:3306", DB_NAME: "half_db", DB_USER: "", DB_PASSWORD: "" },
};
stub("git", `dir="\${@: -1}"; mkdir -p "$dir"; cat > "$dir/domain-map.json" <<'J'\n${JSON.stringify(MAP)}\nJ`);
const www = path.join(base, "www");
const site = (d, body) => { fs.mkdirSync(path.join(www, d, "htdocs/src/web"), { recursive: true }); fs.writeFileSync(path.join(www, d, "htdocs/src/.env"), body); return path.join(www, d, "htdocs/src/.env"); };
const env = site("a.com", "WP_HOME='https://a.com'\nDB_HOST='10.0.0.1:3306'\nDB_NAME='brand_db'\nDB_USER='app'\nDB_PASSWORD='OLD-password'\nCDN_PREFIX='keep-me'\nSITE_ROOT_DOMAIN='brand.tv'\n");
site("noroot.com", "DB_HOST='10.0.0.1'\n");
site("half.com", "DB_HOST='10.0.0.1'\nSITE_ROOT_DOMAIN='half.tv'\n");
site("gone.com", "DB_HOST='10.0.0.1'\nSITE_ROOT_DOMAIN='gone.tv'\n");
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_WWW_DIR: www });

const { operations } = await import(path.join(A, "src/operations/index.js"));
const { readEnv } = await import(path.join(A, "src/lib/envfile.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const run = (domain) => operations.dbcreds.run({ id: "j" }, helpers, operations.dbcreds.validate({ domain }).clean);

// 1) validation
assert.equal(operations.dbcreds.validate({}).ok, false);
assert.equal(operations.dbcreds.validate({ domain: "a.com; rm -rf /" }).ok, false);
console.log("1. validate: a real domain is required");

// 2) stale .env converges on the map: only the keys that differ, nothing else touched, password never logged
await run("a.com");
const raw = fs.readFileSync(env, "utf8");
assert.match(raw, /DB_HOST='10\.0\.0\.9:3306'/);
assert.ok(raw.includes(`DB_PASSWORD='NEW-pa'\\''ss|word'`), "password written, shell-safe");
assert.equal(await readEnv(env, "CDN_PREFIX"), "keep-me", "CDN_PREFIX is not a DB credential — left alone");
assert.equal(await readEnv(env, "WP_HOME"), "https://a.com");
const out = lines.join("\n");
assert.match(out, /updated: DB_HOST, DB_PASSWORD/);
assert.ok(!out.includes("NEW-pa") && !out.includes("OLD-password"), "passwords never logged");
assert.match(out, /caches cleared|caches not cleared/, "cache clear attempted after a change; a wp-cli failure is a warning, not a failed job");
console.log("2. .env updated from the map (DB_HOST, DB_PASSWORD), rest untouched, cache clear attempted, password never logged");

// 3) refusals leave the .env alone
await assert.rejects(run("noroot.com"), /no root domain recorded/);
await assert.rejects(run("half.com"), /missing: DB_USER, DB_PASSWORD/);
await assert.rejects(run("gone.com"), /root 'gone.tv' not found in map/);
await assert.rejects(run("nothere.com"), /not deployed on this server/);
assert.equal(fs.readFileSync(path.join(www, "half.com/htdocs/src/.env"), "utf8"), "DB_HOST='10.0.0.1'\nSITE_ROOT_DOMAIN='half.tv'\n");
console.log("3. no root, incomplete map entry, unknown root, unknown site: refused, .env untouched");

console.log("\nPASS: DB credentials are re-pulled from the map into the site's .env");
fs.rmSync(base, { recursive: true, force: true });
