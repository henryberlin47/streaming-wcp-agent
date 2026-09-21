import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// Fake server (built BEFORE importing: config reads env at import).
const base = fs.mkdtempSync(path.join(os.tmpdir(), "www-"));
const www = path.join(base, "www"), ngx = path.join(base, "nginx"), bin = path.join(base, "bin");
for (const d of [bin, path.join(ngx, "sites-available"), path.join(ngx, "sites-enabled")]) fs.mkdirSync(d, { recursive: true });
const nginxRc = path.join(base, "nginx.rc"), woCalls = path.join(base, "wo.calls");
const stub = (name, body) => { fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`); fs.chmodSync(path.join(bin, name), 0o755); };
stub("nginx", `exit "$(cat "${nginxRc}")"`);
stub("systemctl", "exit 0");
stub("sudo", "exit 0");                                   // wp-cli (cache clearing)
stub("wo", `echo "$@" >> "${woCalls}"; exit 0`);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_WWW_DIR: www, AGENT_NGINX_DIR: ngx });
fs.writeFileSync(nginxRc, "0");

const D = "example.com";
const SITE = path.join(www, D), ENV = path.join(SITE, "htdocs/src/.env"), VHOST = path.join(ngx, "sites-available", D);
fs.mkdirSync(path.join(SITE, "htdocs/src/web"), { recursive: true });
fs.mkdirSync(path.join(SITE, "conf/nginx"), { recursive: true });
fs.writeFileSync(ENV, `WP_HOME='https://${D}'\n`);

const { writeNginxVhost, siteWww, canonicalHost } = await import(path.join(A, "src/lib/site.js"));
const { operations } = await import(path.join(A, "src/operations/index.js"));
const { runWww } = await import(path.join(A, "src/operations/www.js"));
const { readEnv } = await import(path.join(A, "src/lib/envfile.js"));
const lines = []; const helpers = { log: (l) => lines.push(String(l)), err: (l) => lines.push(String(l)), onCancel() {} };
const vhost = () => fs.readFileSync(VHOST, "utf8");
const names = () => [...vhost().matchAll(/server_name ([^;]+);/g)].map((m) => m[1]);
const write = (mode) => writeNginxVhost({ domain: D, siteDir: SITE, webroot: `${SITE}/htdocs/src/web`, ...(mode && { www: mode }) });

// 1) the vhost for each mode, and reading the mode back from it
await write(); // default
assert.deepEqual(names(), [D, `www.${D}`]); assert.match(vhost(), /return 301 \$scheme:\/\/example\.com\$request_uri;/);
assert.match(vhost(), /include .*\/conf\/nginx\/ssl\*\.conf;/); assert.match(vhost(), /acme-challenge/);
assert.equal(await siteWww(D), "nonwww");
await write("www");
assert.deepEqual(names(), [`www.${D}`, D]); assert.match(vhost(), /return 301 \$scheme:\/\/www\.example\.com\$request_uri;/);
assert.equal(await siteWww(D), "www"); assert.equal(canonicalHost(D, "www"), `www.${D}`);
await write("off");
assert.deepEqual(names(), [D]); assert.ok(!vhost().includes("return 301")); assert.equal(await siteWww(D), "off");
fs.writeFileSync(VHOST, `server {\n    server_name ${D} www.${D};\n}\n`); // a vhost from before this feature
assert.equal(await siteWww(D), "nonwww", "legacy single-block vhost = what it did: www -> non-www");
assert.equal(await siteWww("ghost.com"), null);
console.log("1. default = www served and redirected to non-www; www / off written and read back; legacy vhost reads as nonwww");

// 2) validation
assert.equal(operations.www.validate({ domain: "https://Example.com/", mode: "www" }).clean.domain, D);
assert.equal(operations.www.validate({ domain: D, mode: "sideways" }).ok, false);
assert.equal(operations.www.validate({ domain: D }).ok, false);
assert.equal(operations.deploy.validate({ domain: D, root: D, www: "nope" }).ok, false);
assert.equal(operations.deploy.validate({ domain: D, root: D, www: "off" }).clean.www, "off");
assert.equal(operations.deploy.validate({ domain: D, root: D }).clean.www, null, "not given = keep the site's / default");
console.log("2. www op + deploy/alias validate the mode");

// 3) no SSL: switch the legacy site to www-canonical
await runWww({}, helpers, { domain: D, mode: "www" });
assert.equal(await siteWww(D), "www");
assert.equal(await readEnv(ENV, "WP_HOME"), `https://www.${D}`, "WordPress agrees with nginx (no redirect loop)");
console.log("3. nonwww -> www: vhost + WP_HOME both move to www");

// 4) nginx rejects the vhost -> restored, WP_HOME untouched
fs.writeFileSync(nginxRc, "1");
const keep = vhost();
await assert.rejects(() => runWww({}, helpers, { domain: D, mode: "off" }), /old one was restored/);
assert.equal(vhost(), keep); assert.equal(await readEnv(ENV, "WP_HOME"), `https://www.${D}`);
fs.writeFileSync(nginxRc, "0");
console.log("4. nginx -t fails -> vhost restored byte-for-byte, WP_HOME untouched");

// 5) certificate rules
const mkCert = (name, sans) => {
  const k = path.join(base, `${name}.key`), c = path.join(base, `${name}.crt`);
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", c, "-days", "30", "-subj", `/CN=${sans[0]}`, "-addext", `subjectAltName=${sans.map((s) => `DNS:${s}`).join(",")}`], { stdio: "ignore" });
  return c;
};
const useCert = (file) => fs.writeFileSync(path.join(SITE, "conf/nginx/ssl.conf"), `listen 443 ssl;\nssl_certificate ${file};\nssl_certificate_key ${file}.key;\n`);
await runWww({}, helpers, { domain: D, mode: "nonwww" });                    // back to the default first
useCert(mkCert("apex", [D]));                                                 // custom cert WITHOUT www
const pre = vhost();
await assert.rejects(() => runWww({}, helpers, { domain: D, mode: "www" }), /does not cover www\.example\.com.*Nothing was changed/);
assert.equal(vhost(), pre); assert.equal(await readEnv(ENV, "WP_HOME"), `https://${D}`);
lines.length = 0;
await runWww({}, helpers, { domain: D, mode: "nonwww" });                    // allowed, but said out loud
assert.match(lines.join("\n"), /does not cover www\.example\.com/);
useCert(mkCert("both", [D, `www.${D}`]));
await runWww({}, helpers, { domain: D, mode: "www" });
assert.equal(await siteWww(D), "www");
console.log("5. www-canonical is refused when the cert lacks www (nothing changed); nonwww only warns; a covering cert passes");

// 6) www off on a Let's Encrypt cert that lists www -> re-issued for the bare domain only
// (siteCert only calls a cert "letsencrypt" under /etc/letsencrypt, so the wo call is checked via the helper)
const { woSiteSsl } = await import(path.join(A, "src/lib/site.js"));
fs.rmSync(woCalls, { force: true });
await runWww({}, helpers, { domain: D, mode: "off" });
assert.equal(await siteWww(D), "off"); assert.equal(await readEnv(ENV, "WP_HOME"), `https://${D}`);
await woSiteSsl(helpers, D);            // mode read from the vhost: off
await woSiteSsl(helpers, D, "nonwww");
assert.deepEqual(fs.readFileSync(woCalls, "utf8").trim().split("\n"),
  [`site update ${D} --letsencrypt=subdomain --force`, `site update ${D} --le --force`]);
console.log("6. www off: WP_HOME back on the bare domain, and Let's Encrypt is asked for the bare domain only");

console.log("\nPASS: WWW preference (nonwww default / www / off) is applied in nginx + WordPress, safely");
fs.rmSync(base, { recursive: true, force: true });
