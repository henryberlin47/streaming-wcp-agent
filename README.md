# Streaming Server Agent

A per-server HTTP agent that runs your deploy/update/delete/alias/cleanup
operations, so your control panel can trigger them over an authenticated API
instead of SSH. Returns a **job ID** immediately and streams **live logs** over
SSE.

> **Security posture.** The agent runs as **root** (it invokes root-level deploy
> scripts). Its bearer token is therefore equivalent to root. Protect it: bind to
> a private/VPN interface, set an IP allowlist, and keep the token secret.

## Status: fully native

The server, auth, job runner, and SSE are complete, and **all five operations
are native JS** — the agent reimplements the deploy/update/delete/alias/cleanup
logic itself and no longer shells out to the `.sh` scripts. The scripts remain
only for manual SSH work; the agent is the source of truth for API-driven ops.

Operation logic lives in `src/operations/*.js`, built on shared helpers in
`src/lib/*` (system/process/git in `sys.js`, `.env` read/write in `envfile.js`,
nginx/cron/wo scaffolding in `site.js`, the SEO/CDN HTTP calls in `api.js`, the
domain-map resolver in `map.js`, and the global constants in `siteConfig.js`).

Because the API has no TTY, the interactive gates from the scripts become
parameters: `delete` requires `confirm:true`, `deploy` requires `root` (no DB
selector — creds resolve from the map), and `cleanup` uses `mode:replace`
(the interactive `all` mode is rejected).

### SSL: Let's Encrypt or a custom certificate

`POST /api/op/ssl` with `{ domain }` re-issues Let's Encrypt. With
`{ domain, cert, key }` (PEM) it installs a pasted certificate instead:

- the pair is validated **before** the job is queued — key matches the cert, the
  cert covers the domain (SAN/wildcard), not expired, key not passphrase-protected
  — so a bad paste is a `400` with the reason;
- files go to `/etc/ssl/wcp/<domain>/` (key `0600`), outside `/etc/letsencrypt`
  so acme.sh never touches them; the site's `conf/nginx/ssl.conf` keeps its own
  `listen` lines and only the certificate lines change; an HTTP→HTTPS block is
  added if the site had none;
- `nginx -t` gates the reload, and everything is restored if it fails;
- the key is redacted from job views and dropped from memory after the run.

A custom certificate does **not** auto-renew. Re-issuing Let's Encrypt switches
back. `GET /api/sites` reports each site's `ssl` (`letsencrypt` | `custom` |
`none`) and `ssl_expires`, read from what nginx is actually configured with.

### WWW preference

Per site, one of `nonwww` (default: `www.<domain>` is served and 301s to
`<domain>`), `www` (the reverse) or `off` (`www` is not served, and Let's Encrypt
is issued with `--letsencrypt=subdomain` so a missing `www` DNS record can't fail
it). Set at deploy time (`www` param of `deploy`/`alias`; absent = keep the
site's, else WordOps' own choice) or on a live site with
`POST /api/op/www { domain, mode }`.

The redirect is an nginx server block (not WordPress), `WP_HOME` is kept in step
so the two never fight, and caches are purged when the host changes. Switching to
`www` is refused — before anything changes — if the certificate doesn't cover
`www.<domain>` (a Let's Encrypt cert is re-issued with it first). The mode is read
back from the vhost, so `GET /api/sites` reports `www` for every site; a vhost
written before this feature reads as `nonwww`, which is what it did.

### Backup sites + cron on/off

A **backup** is the same site deployed again on another server (`deploy`/`alias`
with `backup: true`): same shared DB, same code, `.env` gets `SITE_BACKUP=1`, and
its cron file is written as `/etc/cron.d/<name>.disabled` — cron ignores names
with a dot, so the jobs exist but never run. SSL and brand/CDN registration are
skipped (DNS points at the primary). `POST /api/op/cron { domain, active }`
renames the file on/off and restarts cron; the portal's monitor does this by
itself while the primary is down. `GET /api/sites` reports `backup` and `cron`
(`on`|`off`) per site.

## Install

**Full fresh-VPS walkthrough — including WordOps, Redis, Node, and Tailscale — is
in [`INSTALL.md`](INSTALL.md).** The short version, once the host already
has WordOps + Node 18+ installed:

```bash
sudo mkdir -p /opt/streaming-agent
sudo cp -r src package.json streaming-agent.service /opt/streaming-agent/
cd /opt/streaming-agent
sudo npm install --omit=dev
sudo cp .env.example .env
# edit .env — at minimum set AGENT_TOKEN (openssl rand -hex 32)
sudo nano .env
```

Run under systemd (the unit targets `/opt/streaming-agent`):

```bash
sudo cp /opt/streaming-agent/streaming-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now streaming-agent
sudo journalctl -u streaming-agent -f
```

## Prerequisites

The host must have **WordOps** (which brings nginx, PHP, MariaDB with
`mysqldump`, wp-cli, certbot), **Redis** (`wo stack install --redis`),
**Node.js 18+**, plus `git` and `sed`. See [`INSTALL.md`](INSTALL.md).

## Configuration

See [`.env.example`](.env.example). Key vars: `AGENT_TOKEN` (required),
`AGENT_HOST` / `AGENT_PORT`, `AGENT_ALLOWED_IPS` (the portal's tailnet IP(s)),
`AGENT_MIGRATE_TIMEOUT_MS`.

The agent **refuses to start** if the token is missing, or if bound to `0.0.0.0`
with no IP allowlist.

## API

All endpoints except `/healthz` require `Authorization: Bearer <AGENT_TOKEN>` and
must come from an allowed IP.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness (no auth) |
| GET | `/api/info` | Server name + supported operations |
| GET | `/api/sites` | List websites on this server (`wo site list`) |
| POST | `/api/op/:type` | Start an operation → `{ jobId }` |
| GET | `/api/jobs` | List recent jobs |
| GET | `/api/jobs/:id` | Job status |
| GET | `/api/jobs/:id/logs` | Full log buffer (JSON) |
| GET | `/api/jobs/:id/stream` | Live logs (SSE) |
| POST | `/api/jobs/:id/cancel` | Cancel queued/running job |

### Operations & params

- **deploy** — `{ domain, root, delete?, branch?, repo? }` (`root` required over
  the API — no interactive selector)
- **update** — `{ domain, branch? }`
- **delete** — `{ domain, confirm: true }` (the `confirm` flag replaces the typed
  `YES`)
- **alias** — `{ aliasDomain, mainDomain, branch?, repo? }`
- **cleanup** — `{ newDomain, oldDomain, mode? }` (`mode`: `audit`|`replace`|`verify`;
  `all` is rejected — it's interactive)

### Examples

```bash
TOKEN=... ; BASE=http://10.0.0.5:8787

# list sites on this server
curl -s $BASE/api/sites -H "Authorization: Bearer $TOKEN"
# => {"server":"AGENT_SEO_1","count":8,"sites":["a.com","b.com",...]}

# start a deploy
curl -s -X POST $BASE/api/op/deploy \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domain":"newsite.com","root":"rootdomain.com"}'
# => {"jobId":"...","state":"queued"}

# stream its logs
curl -sN $BASE/api/jobs/<jobId>/stream -H "Authorization: Bearer $TOKEN"

# delete (requires confirm)
curl -s -X POST $BASE/api/op/delete \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domain":"oldsite.com","confirm":true}'
```

SSE events: `hello` (on connect), `line` (`{t,stream,line}`), `state`
(`{state,reason}`). The stream closes when the job reaches a terminal state
(`succeeded`/`failed`/`timeout`/`cancelled`).

## Operation internals

Each operation in `src/operations/index.js` has `validate()` (strict — the
injection boundary) and delegates `run()` to its native module:

- `deploy.js` — resolve DB + CDN_PREFIX from the map, wo create, drop local DB,
  git clone, write `.env` (salts + constants), nginx + 15-job cron, perms, cache
  clear, SSL, SEO+CDN register; rotation (cleanup → delete → unregister) when
  `delete` is set and SSL succeeded.
- `alias.js` — inject `SITE_MOBILE_HOST` into the main `.env`, clone it, read
  `CDN_PREFIX`, swap alias values, nginx + 4-job cron, SSL, clear both caches,
  register.
- `update.js` — verify branch, hard reset, preserve `.env`, perms, Acorn warm,
  restart + reload, cache clear.
- `delete.js` — cron rm, kill domain procs (via `/proc`), locks, wo delete, rm
  site/nginx/certs, nginx test+reload, cron restart.
- `cleanup.js` — wp-cli search-replace with audit/replace/verify modes.

Values only ever reach array-arg `spawn` calls (never a shell) and a quote-safe
`.env` writer, so domains/passwords with shell metacharacters can't inject.

## Notes

- Jobs and logs are **in-memory** (retention `AGENT_JOB_RETENTION_MS`, default
  1h). The control panel is the durable record; a restart forgets history.
- `AGENT_MAX_CONCURRENT` defaults to **1** to serialize deploys (avoids
  nginx/php-fpm/DB races). Raise only if operations are known-independent.
- Secrets in job params (matching `pass|secret|token|key`) are redacted in job
  views and logs of params.