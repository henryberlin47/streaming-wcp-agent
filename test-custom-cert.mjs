import assert from "node:assert";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const A = path.dirname(fileURLToPath(import.meta.url));

// A fake server: /var/www, /etc/nginx, the cert dir, and stubbed nginx/systemctl.
const base = fs.mkdtempSync(path.join(os.tmpdir(), "customcert-"));
const www = path.join(base, "www"), ngx = path.join(base, "nginx"), certs = path.join(base, "certs"), bin = path.join(base, "bin");
for (const d of [bin, path.join(ngx, "conf.d"), path.join(ngx, "sites-available")]) fs.mkdirSync(d, { recursive: true });
const nginxMode = path.join(base, "nginx.mode"); // "ok" | "fail" | "old" (old nginx: rejects `http2 on;`)
fs.writeFileSync(path.join(bin, "nginx"), `#!/bin/bash
mode="$(cat "${nginxMode}")"
[ "$mode" = fail ] && { echo "nginx: [emerg] boom" >&2; exit 1; }
[ "$mode" = old ] && grep -rqs "http2 on;" "${www}" && { echo 'nginx: [emerg] unknown directive "http2"' >&2; exit 1; }
exit 0\n`);
fs.writeFileSync(path.join(bin, "systemctl"), "#!/bin/bash\nexit 0\n");
for (const f of ["nginx", "systemctl"]) fs.chmodSync(path.join(bin, f), 0o755);
Object.assign(process.env, { PATH: `${bin}:${process.env.PATH}`, AGENT_WWW_DIR: www, AGENT_NGINX_DIR: ngx, AGENT_CERT_DIR: certs });

const mkSite = (d) => {
  fs.mkdirSync(path.join(www, d, "conf/nginx"), { recursive: true });
  fs.writeFileSync(path.join(ngx, "sites-available", d), `server {\n  server_name ${d} www.${d};\n  include ${www}/${d}/conf/nginx/*.conf;\n}\n`);
};
const mkCert = (name, sans, days = "30") => {
  const k = path.join(base, `${name}.key`), c = path.join(base, `${name}.crt`);
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", c, "-days", days,
    "-subj", `/CN=${sans[0]}`, "-addext", `subjectAltName=${sans.map((s) => `DNS:${s}`).join(",")}`], { stdio: "ignore" });
  return { cert: fs.readFileSync(c, "utf8"), key: fs.readFileSync(k, "utf8") };
};

const { checkCertPair, installCustomCert, siteSsl } = await import(path.join(A, "src/lib/cert.js"));
const { operations } = await import(path.join(A, "src/operations/index.js"));
const good = mkCert("good", ["example.com", "*.example.com"]);
const other = mkCert("other", ["other.net"]);

// 1) validation — the trust boundary. Every bad paste is refused with the reason.
const errs = (o) => checkCertPair({ domain: "example.com", ...o }).errors.join(" | ");
assert.equal(errs(good), "");
assert.equal(checkCertPair({ domain: "m.example.com", ...good }).errors.length, 0, "wildcard SAN covers a subdomain");
assert.match(errs({ cert: good.cert, key: other.key }), /private key does not belong/);
assert.match(errs(other), /does not cover example\.com \(it is for: other\.net\)/);
assert.match(errs({ cert: "hello", key: good.key }), /no "-----BEGIN CERTIFICATE-----" block/);
assert.match(errs({ cert: good.cert, key: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END ENCRYPTED PRIVATE KEY-----" }), /passphrase-protected/);
assert.match(errs({ cert: good.cert, key: "nope" }), /not a readable PEM private key/);
assert.match(errs({ cert: good.cert }), /key is required/);
assert.match(checkCertPair({ domain: "example.com", ...good, now: Date.now() + 40 * 864e5 }).errors.join(), /expired on/);
const crlf = checkCertPair({ domain: "example.com", cert: good.cert.replace(/\n/g, "\r\n"), key: `\n  ${good.key.replace(/\n/g, "\r\n")}` });
assert.equal(crlf.errors.length, 0); assert.ok(!/\r/.test(crlf.fullchain + crlf.key), "CRLF paste normalised");
console.log("1. wrong key / wrong domain / garbage / encrypted key / expired are refused; CRLF paste accepted");

// 2) the op's validate() refuses a bad pair up front (a 400, not a failed job) and keeps the LE form working
assert.equal(operations.ssl.validate({ domain: "example.com" }).ok, true);
assert.deepEqual(operations.ssl.validate({ domain: "example.com" }).clean, { domain: "example.com" });
assert.equal(operations.ssl.validate({ domain: "https://Example.com/", ...good }).ok, true);
const bad = operations.ssl.validate({ domain: "example.com", cert: good.cert, key: other.key });
assert.equal(bad.ok, false); assert.match(bad.errors.join(), /does not belong/);
assert.equal(operations.ssl.validate({ domain: "example.com", cert: good.cert }).ok, false, "cert without key is refused");
console.log("2. ssl op: {domain} still means Let's Encrypt; {domain,cert,key} is validated before it is queued");

// 3) install on a site that never had SSL
const lines = []; const helpers = { log: (l) => lines.push(l), err: (l) => lines.push(l), onCancel() {} };
const lg = { info() {}, ok() {}, warn: (w) => lines.push(`WARN ${w}`) };
const v = checkCertPair({ domain: "example.com", ...good });
mkSite("example.com"); fs.writeFileSync(nginxMode, "ok");
assert.deepEqual(await siteSsl("example.com"), { ssl: "none" }, "no ssl.conf -> reported as none");
await installCustomCert(helpers, { domain: "example.com", fullchain: v.fullchain, key: v.key }, lg);
const sslConf = path.join(www, "example.com/conf/nginx/ssl.conf");
const conf = fs.readFileSync(sslConf, "utf8");
assert.match(conf, /listen 443 ssl;\nlisten \[::\]:443 ssl;\nhttp2 on;/);
assert.ok(conf.includes(`ssl_certificate     ${certs}/example.com/fullchain.pem;`) && conf.includes(`ssl_certificate_key ${certs}/example.com/key.pem;`));
assert.equal(fs.statSync(path.join(certs, "example.com/key.pem")).mode & 0o777, 0o600, "private key is 0600");
const force = fs.readFileSync(path.join(ngx, "conf.d/force-ssl-example.com.conf"), "utf8");
assert.match(force, /server_name example\.com www\.example\.com;/); assert.match(force, /return 301 https:\/\/\$host\$request_uri;/);
const seen = await siteSsl("example.com");
assert.equal(seen.ssl, "custom"); assert.equal(seen.ssl_expires, v.info.expires);
assert.ok(!lines.join("\n").includes("PRIVATE KEY"), "the key never reaches the job log");
console.log("3. fresh site: certs written (key 0600), ssl.conf + HTTP→HTTPS redirect created, reported as custom with its expiry");

// 4) a Let's Encrypt site: its own listen lines are kept, only the cert lines are swapped
mkSite("le.example.com");
const leConf = path.join(www, "le.example.com/conf/nginx/ssl.conf");
const LE = "listen 443 ssl;\nlisten [::]:443 ssl;\nlisten 443 quic;\nhttp2 on;\nssl_certificate     /etc/letsencrypt/live/le.example.com/fullchain.pem;\nssl_certificate_key     /etc/letsencrypt/live/le.example.com/key.pem;\nssl_trusted_certificate /etc/letsencrypt/live/le.example.com/ca.pem;\nssl_stapling_verify on;\n";
fs.writeFileSync(leConf, LE);
assert.equal((await siteSsl("le.example.com")).ssl, "letsencrypt");
await installCustomCert(helpers, { domain: "le.example.com", fullchain: v.fullchain, key: v.key }, lg);
const after = fs.readFileSync(leConf, "utf8");
assert.match(after, /listen 443 quic;/); assert.ok(!after.includes("letsencrypt") && !after.includes("ssl_stapling"));
assert.equal((after.match(/^ssl_certificate /gm) || []).length, 1);
assert.equal((await siteSsl("le.example.com")).ssl, "custom");
console.log("4. Let's Encrypt site -> custom: listen/quic lines kept, LE cert + stapling lines replaced");

// 5) nginx rejects it -> EVERYTHING is put back (the LE config, no stray files)
fs.writeFileSync(leConf, LE); fs.rmSync(path.join(certs, "le.example.com"), { recursive: true });
fs.rmSync(path.join(ngx, "conf.d/force-ssl-le.example.com.conf"));
fs.writeFileSync(nginxMode, "fail");
await assert.rejects(() => installCustomCert(helpers, { domain: "le.example.com", fullchain: v.fullchain, key: v.key }, lg), /everything was restored/);
assert.equal(fs.readFileSync(leConf, "utf8"), LE, "ssl.conf restored byte-for-byte");
assert.ok(!fs.existsSync(path.join(certs, "le.example.com/key.pem")) && !fs.existsSync(path.join(ngx, "conf.d/force-ssl-le.example.com.conf")));
console.log("5. nginx -t fails -> ssl.conf, cert files and redirect all rolled back");

// 6) older nginx without `http2 on;` -> falls back to `listen 443 ssl http2`
mkSite("old.example.com"); fs.writeFileSync(nginxMode, "old");
fs.rmSync(sslConf); // the stub greps every site: keep only the one under test
fs.rmSync(leConf);
await installCustomCert(helpers, { domain: "old.example.com", fullchain: v.fullchain, key: v.key }, lg);
assert.match(fs.readFileSync(path.join(www, "old.example.com/conf/nginx/ssl.conf"), "utf8"), /^listen 443 ssl http2;/);
console.log("6. old nginx -> `listen 443 ssl http2` form chosen by nginx -t");

// 7) not a site on this server -> refused before anything is written
await assert.rejects(() => installCustomCert(helpers, { domain: "ghost.com", fullchain: v.fullchain, key: v.key }, lg), /not a WordOps site/);
assert.ok(!fs.existsSync(path.join(certs, "ghost.com")));
console.log("7. unknown site refused, nothing written");

console.log("\nPASS: custom certificates are validated, installed safely, and reported in the site list");
fs.rmSync(base, { recursive: true, force: true });
