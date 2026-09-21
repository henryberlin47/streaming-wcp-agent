import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import config from '../config.js';
import { nginxTest, nginxReload, pathExists, removePath } from './sys.js';

// ============================================================
//  Custom SSL certificates (pasted into the portal)
// ============================================================
// WordOps keeps a site's TLS in /var/www/<domain>/conf/nginx/ssl.conf, which the
// vhost includes. A custom cert is that same file pointed at OUR copy of the
// cert, kept outside /etc/letsencrypt so acme.sh renewals never touch it.
// "Re-issue SSL" (wo site update --le) rewrites ssl.conf and switches back.
// Paths are env-overridable for the tests only.
// ============================================================
export const CERT_DIR = process.env.AGENT_CERT_DIR || '/etc/ssl/wcp';
export const NGINX_DIR = process.env.AGENT_NGINX_DIR || '/etc/nginx';

const CERT_BLOCK_RE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
const KEY_BLOCK_RE = /-----BEGIN ((?:RSA |EC )?PRIVATE KEY)-----[\s\S]+?-----END \1-----/;
const MAX_PEM = 32 * 1024;

const sslConfPath = (domain) => `${config.wwwDir}/${domain}/conf/nginx/ssl.conf`;

/**
 * Validate a pasted certificate + private key for a domain. Pure (no I/O).
 * Returns { errors: [...] } or { errors: [], fullchain, key, info } where
 * fullchain/key are normalised PEM ready to write. The key is never echoed.
 */
export function checkCertPair({ cert, key, domain, now = Date.now() }) {
  const errors = [];
  if (typeof cert !== 'string' || !cert.trim()) errors.push('cert is required (PEM, leaf certificate first, then any intermediates)');
  if (typeof key !== 'string' || !key.trim()) errors.push('key is required (PEM private key)');
  if (errors.length) return { errors };
  if (cert.length > MAX_PEM || key.length > MAX_PEM) return { errors: ['cert/key too large (32 KB max each)'] };

  const blocks = cert.replace(/\r/g, '').match(CERT_BLOCK_RE);
  if (!blocks) return { errors: ['cert has no "-----BEGIN CERTIFICATE-----" block — paste the PEM text of the certificate'] };

  let chain;
  try { chain = blocks.map((b) => new crypto.X509Certificate(b)); }
  catch { return { errors: ['cert is not a readable X.509 certificate (corrupted PEM?)'] }; }
  const leaf = chain[0];

  const keyText = key.replace(/\r/g, '');
  if (/BEGIN ENCRYPTED PRIVATE KEY|Proc-Type: 4,ENCRYPTED/.test(keyText)) {
    return { errors: ['key is passphrase-protected — nginx cannot load it; remove the passphrase first (openssl pkey -in enc.key -out plain.key)'] };
  }
  const keyBlock = KEY_BLOCK_RE.exec(keyText)?.[0];
  let priv;
  try { priv = crypto.createPrivateKey(keyBlock); }
  catch { return { errors: ['key is not a readable PEM private key ("-----BEGIN PRIVATE KEY-----")'] }; }

  if (!leaf.checkPrivateKey(priv)) errors.push('the private key does not belong to this certificate');
  // (No CA:TRUE check: self-signed origin certs carry it. A chain pasted in the
  // wrong order already fails the two checks around this line.)
  if (!leaf.checkHost(domain)) {
    errors.push(`the certificate does not cover ${domain} (it is for: ${(leaf.subjectAltName || leaf.subject || '?').replace(/DNS:/g, '').slice(0, 300)})`);
  }
  const expires = new Date(leaf.validTo);
  if (expires.getTime() <= now) errors.push(`the certificate expired on ${expires.toISOString().slice(0, 10)}`);
  if (new Date(leaf.validFrom).getTime() > now) errors.push(`the certificate is not valid until ${new Date(leaf.validFrom).toISOString().slice(0, 10)}`);
  if (errors.length) return { errors };

  const line = (s) => String(s || '').split('\n').filter((l) => /^(CN|O)=/.test(l)).join(', ');
  return {
    errors: [],
    fullchain: `${blocks.join('\n')}\n`,
    key: `${keyBlock}\n`,
    covers: (host) => !!leaf.checkHost(host), // e.g. does it also cover www.<domain>?
    info: {
      subject: line(leaf.subject), issuer: line(leaf.issuer),
      names: (leaf.subjectAltName || '').replace(/DNS:/g, ''),
      expires: expires.toISOString(), chain: chain.length,
    },
  };
}

// Which certificate does a site serve? -> { ssl: 'letsencrypt'|'custom'|'none', ssl_expires? }
// ('none' is said out loud so the portal can tell "no SSL" from "old agent, unknown".)
// Read from what nginx is actually configured with, so it is right no matter
// who set it up (deploy, the SSL button, or someone by hand).
export async function siteSsl(domain) {
  const { type, x509 } = await siteCert(domain);
  return { ssl: type, ...(x509 && { ssl_expires: new Date(x509.validTo).toISOString() }) };
}

// The certificate nginx serves for a site: { type, x509? } (x509 missing = unreadable).
export async function siteCert(domain) {
  let conf;
  try { conf = await fs.readFile(sslConfPath(domain), 'utf8'); } catch { return { type: 'none' }; }
  const file = /^\s*ssl_certificate\s+([^;\s]+)\s*;/m.exec(conf)?.[1];
  if (!file) return { type: 'none' };
  const type = file.startsWith('/etc/letsencrypt/') ? 'letsencrypt' : 'custom';
  try {
    const pem = (await fs.readFile(file, 'utf8')).match(CERT_BLOCK_RE)?.[0];
    return { type, x509: new crypto.X509Certificate(pem) };
  } catch { return { type }; /* unreadable cert — still report the type */ }
}

// Listen lines for a site that never had ssl.conf. nginx >= 1.25.1 wants
// `http2 on;`, older ones only know `listen … http2` — `nginx -t` picks.
const LISTEN_CANDIDATES = [
  'listen 443 ssl;\nlisten [::]:443 ssl;\nhttp2 on;\n',
  'listen 443 ssl http2;\nlisten [::]:443 ssl http2;\n',
];

/**
 * Install a validated pair for a site and reload nginx. Everything it changes
 * is restored if `nginx -t` rejects the result, so a bad paste can never take
 * the web server down.
 */
export async function installCustomCert(helpers, { domain, fullchain, key }, { info, ok, warn }) {
  const dir = `${CERT_DIR}/${domain}`;
  const certFile = `${dir}/fullchain.pem`;
  const keyFile = `${dir}/key.pem`;
  const sslConf = sslConfPath(domain);
  const forceConf = `${NGINX_DIR}/conf.d/force-ssl-${domain}.conf`;
  const vhost = `${NGINX_DIR}/sites-available/${domain}`;

  if (!(await pathExists(`${config.wwwDir}/${domain}/conf/nginx`))) {
    throw new Error(`${domain} is not a WordOps site on this server (no ${config.wwwDir}/${domain}/conf/nginx)`);
  }
  const read = (f) => fs.readFile(f, 'utf8').catch(() => null);
  const before = { [certFile]: await read(certFile), [keyFile]: await read(keyFile), [sslConf]: await read(sslConf), [forceConf]: await read(forceConf) };
  const restore = async () => {
    for (const [f, old] of Object.entries(before)) {
      if (old == null) await removePath(f); else await fs.writeFile(f, old);
    }
  };

  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(certFile, fullchain, { mode: 0o644 });
  await fs.writeFile(keyFile, key, { mode: 0o600 });
  await fs.chmod(keyFile, 0o600); // writeFile's mode is ignored when the file already existed
  ok(`certificate + key written to ${dir} (key 0600)`);

  // Keep the site's own listen/http2/quic lines; replace only the cert lines.
  // (OCSP stapling lines go too: they point at Let's Encrypt's CA file.)
  const kept = (before[sslConf] || '').split('\n')
    .filter((l) => l.trim() && !/^\s*(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate|ssl_stapling|ssl_stapling_verify)\s/.test(l));
  const certLines = `ssl_certificate     ${certFile};\nssl_certificate_key ${keyFile};\n`;
  const candidates = kept.some((l) => /^\s*listen\s/.test(l)) ? [`${kept.join('\n')}\n`] : LISTEN_CANDIDATES;

  // HTTP -> HTTPS, as WordOps does for Let's Encrypt sites. Once ssl.conf adds
  // `listen 443`, the vhost stops answering on :80, so this block takes it over.
  if (before[forceConf] == null) {
    // every name the vhost serves — the www-redirect block's too, or that host has no :80
    const names = [...new Set([...((await read(vhost)) || '').matchAll(/^\s*server_name\s+([^;]+);/gm)]
      .flatMap((m) => m[1].trim().split(/\s+/)))].join(' ') || domain;
    await fs.writeFile(forceConf, `server {\n\tlisten 80;\n\tlisten [::]:80;\n\tserver_name ${names};\n\treturn 301 https://$host$request_uri;\n}\n`);
    info(`HTTP→HTTPS redirect added (${forceConf})`);
  }
  if (!/conf\/nginx\/\*\.conf/.test((await read(vhost)) || '')) {
    warn(`${vhost} does not include conf/nginx/*.conf — nginx may not pick ssl.conf up`);
  }

  let valid = false;
  for (const head of candidates) {
    await fs.writeFile(sslConf, head + certLines);
    if ((valid = await nginxTest(helpers))) break;
  }
  if (!valid) {
    await restore();
    throw new Error('nginx -t rejected the new SSL config — everything was restored, the site is unchanged (see the nginx output above)');
  }
  ok('nginx -t passed');
  await nginxReload(helpers);
  ok('nginx reloaded');
}
