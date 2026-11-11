import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
const A = dirname(fileURLToPath(import.meta.url));

// fake wwwDir BEFORE import (config.js reads env at import time)
const www = fs.mkdtempSync(path.join(os.tmpdir(), "roles-"));
const env = (d, body) => { const p = path.join(www, d, "htdocs/src"); fs.mkdirSync(p, { recursive: true }); fs.writeFileSync(path.join(p, ".env"), body); };
env("main.com",   "SITE_ROLE=main\nSITE_MOBILE_HOST=m.main.com\nSITE_ROOT_DOMAIN=main.com\n");  // main with LIVE alias -> pc
env("m.main.com", "SITE_ROLE=clone\nSITE_MOBILE_HOST=m.main.com\nSITE_ROOT_DOMAIN=main.com\n"); // the alias -> mob; root inherited
env("orphan.com", "SITE_MOBILE_HOST=gone.com\n");                     // alias was deleted -> NO stale pc tag, no root
env("plain.com",  "SITE_ROLE=main\nSITE_ROOT_DOMAIN=brand.com\n");    // no alias, but has a root -> root only
fs.mkdirSync(path.join(www, "nofile.com"), { recursive: true });      // no .env at all -> nothing
// --- aliases that the main's single SITE_MOBILE_HOST does not point at ---
env("m2.main.com", "SITE_ROLE=clone\nSITE_CANONICAL_HOST=main.com\nSITE_MOBILE_HOST=m2.main.com\n"); // a SECOND alias of main.com (older deploy: only the inherited canonical host)
env("redeployed.com", "SITE_ROLE=main\nSITE_CANONICAL_HOST=redeployed.com\n");                        // main was redeployed: its SITE_MOBILE_HOST is gone
env("m.redeployed.com", "SITE_ROLE=clone\nSITE_MAIN_DOMAIN=redeployed.com\nSITE_CANONICAL_HOST=redeployed.com\n");
env("lost.alias.com", "SITE_ROLE=clone\nSITE_MAIN_DOMAIN=not-here.com\n");                            // its main is not on this server
process.env.AGENT_WWW_DIR = www;

// main.com has a real checkout on a feature branch; plain.com is on a detached HEAD
const gitDir = (d, head, url) => {
  const g = path.join(www, d, "htdocs/.git"); fs.mkdirSync(g, { recursive: true });
  fs.writeFileSync(path.join(g, "HEAD"), head);
  fs.writeFileSync(path.join(g, "config"), `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "x"]\n\tremote = origin\n`);
};
gitDir("main.com", "ref: refs/heads/feature/nginx-wprocket\n", "git@github.com:acme/xoilac-ols.git");
gitDir("plain.com", "0123456789abcdef0123456789abcdef01234567\n", "https://github.com/acme/other-app");
const { siteRoles } = await import(`${A}/src/lib/site.js`);
const { aliasesOf } = await import(`${A}/src/lib/site.js`);
const meta = await siteRoles(["main.com", "m.main.com", "orphan.com", "plain.com", "nofile.com", "m2.main.com", "redeployed.com", "m.redeployed.com", "lost.alias.com"]);
console.log(meta);
assert.deepEqual(meta, {
  "main.com":   { root: "main.com", role: "pc",  pair: "m.main.com", aliases: ["m.main.com", "m2.main.com"], ssl: "none", repo: "acme/xoilac-ols", branch: "feature/nginx-wprocket" },
  "m2.main.com": { role: "mob", pair: "main.com", ssl: "none" },                    // second alias: recognised through its own .env
  "redeployed.com": { role: "pc", pair: "m.redeployed.com", aliases: ["m.redeployed.com"], ssl: "none" }, // main lost SITE_MOBILE_HOST, still paired
  "m.redeployed.com": { role: "mob", pair: "redeployed.com", ssl: "none" },
  "lost.alias.com": { role: "mob", ssl: "none" },                                   // an alias with no main here: MOB, unpaired // main knows its alias + its root
  "m.main.com": { root: "main.com", role: "mob", pair: "main.com", ssl: "none" },   // alias knows its main; root inherited
  "plain.com":  { root: "brand.com", ssl: "none", repo: "acme/other-app", branch: "0123456" },                                  // root shown even with no pair
  "orphan.com": { ssl: "none" },                                                     // deleted alias: no stale PC tag
  "nofile.com": { ssl: "none" },                                                     // no .env: nothing but the SSL state
});
assert.deepEqual(await aliasesOf("main.com"), ["m2.main.com"], "aliasesOf reads each alias .env (m.main.com predates both fields)");
assert.deepEqual(await aliasesOf("redeployed.com"), ["m.redeployed.com"]);
console.log("PASS: root + pc/mob derived from disk, no stale tag after alias deletion, untagged otherwise");
fs.rmSync(www, { recursive: true, force: true });
