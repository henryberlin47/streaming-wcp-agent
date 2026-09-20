# Install & Deployment — streaming-wcp-agent

The **agent** runs on every WordOps VPS you manage. The **portal** (separate
repo: `streaming-wcp-portal`) sends it commands over an authenticated HTTP API
and streams the logs back. Adding a server = install the agent here, then
register its tailnet URL + token in the portal.

```
Portal ──HTTP + token──> Agent on VPS-A → wo / nginx / mysql / redis …
       └──HTTP + token──> Agent on VPS-B → …
```

Portal ⇄ agent traffic rides your **Tailscale** tailnet, so no agent port is
ever exposed to the public internet.

---

# Zero-touch (recommended)

You don't have to do Part 1 by hand. In the portal go to **Servers → Provision
new server**, give it a name, and run the printed one-liner as root on a fresh
Ubuntu 22.04/24.04 VPS:

```bash
curl -fsSL https://<portal>/api/bootstrap/<id>/<key> | sudo bash
```

That URL serves a small wrapper holding this server's config (agent token,
allowlist, deploy secrets, optional Tailscale auth key) and pipes
[`bootstrap.sh`](bootstrap.sh) from this repo into bash. It performs every step
of Part 1 below — WordOps + stack + Redis, a hardened default vhost, tuned
PHP-FPM, Node LTS, Tailscale, the agent under systemd, the firewall rule, and a
root deploy key — then **reports its tailnet IP back to the portal**, which fills
in the server's address and pings it. The only manual step left is adding the
printed deploy key to GitHub for the private app + map repos.

The key in the URL is one-time and expires in 2 hours; the script is idempotent,
so a half-finished run can simply be re-run. Part 1 remains the reference for
what it does and for doing it manually.

**PHP tuning is self-healing.** The values live in one place,
[`scripts/tune-php.sh`](scripts/tune-php.sh) (memory 512M, raised `pcre.*`
limits, FPM pool sizes — for *every* installed PHP version). The bootstrap
installs PHP 8.3 up front and runs it, and the agent re-runs it before each PHP
restart in deploy / alias / update, so an older server fixes itself on its next
operation. Untuned PHP 8.3 is what makes WP Rocket serve a blank page (HTTP 200,
empty body) on large homepages. To fix a server by hand right now:

```bash
sudo bash /opt/streaming-agent/scripts/tune-php.sh
```

---

# Part 1 — Fresh VPS (manual)

**Assumptions:** Ubuntu 22.04 or 24.04, run as **root** (`sudo -i`). WordOps only
supports these. **Order matters** — WordOps must be first; everything after
step 2 assumes its stack (nginx/PHP/MariaDB/wp-cli) is present.

### 1. WordOps (the whole LEMP + wp-cli + certbot stack)

```bash
wget -qO wo wops.cc && sudo bash wo
```
```bash
wo --version && nginx -v && php -v && mysql --version
```
This single install provides every binary the agent calls except Node, git and
sed: **nginx, PHP, MariaDB (`mysql`/`mariadb`/`mysqldump`), wp-cli, certbot**.

### 2. Redis (object-cache backend)

```bash
wo stack install --redis
```
```bash
systemctl is-active redis-server && redis-cli ping   # → active  /  PONG
```
**Purge** and the end-of-deploy cache clear run `wp cache flush`, which only does
anything with a persistent object cache. Make sure sites are created with the
Redis flag (`wo site create … --wp --wpredis`) or the server sits idle.

### 3. Node.js LTS (system-wide → `/usr/bin/node`)

```bash
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs
```
```bash
node --version && which node      # must print /usr/bin/node — what the systemd unit runs
```
(NodeSource, not nvm, precisely so `/usr/bin/node` exists for systemd.)

### 4. git + sed

```bash
sudo apt-get update && sudo apt-get install -y git sed
```

### 5. Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```
```bash
sudo tailscale up
```
```bash
tailscale ip -4        # this VPS's 100.x.y.z — register the agent under it
```
> The **portal host must be on the same tailnet** too.

### 6. Install the agent by cloning this repo

Clone straight into `/opt/streaming-agent` so later updates are a `git pull`:
```bash
sudo git clone https://github.com/henryberlin47/streaming-wcp-agent.git /opt/streaming-agent
```
```bash
cd /opt/streaming-agent && sudo npm install --omit=dev
```
For a **private** repo, give the box a read-only deploy key and clone the SSH
URL instead (`git@github.com:henryberlin47/streaming-wcp-agent.git`).
The agent's only npm dependency is `express`.

### 7. Configure `/opt/streaming-agent/.env`

`.env` is gitignored, so a `git pull` never touches it. `AGENT_TOKEN` and the
five deploy secrets are **required** — the agent refuses to start without them.
```bash
sudo cp /opt/streaming-agent/.env.example /opt/streaming-agent/.env
sudo chmod 600 /opt/streaming-agent/.env
sudo nano /opt/streaming-agent/.env
```
Fill in at least: `AGENT_TOKEN` (`openssl rand -hex 32`),
`AGENT_ALLOWED_IPS=<PORTAL_TAILSCALE_IP>`, and the five secrets. See
[Environment reference](#environment-reference).

### 8. Run under systemd

The unit already targets `/opt/streaming-agent`:
```bash
sudo cp /opt/streaming-agent/streaming-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now streaming-agent
```
```bash
sudo systemctl status streaming-agent --no-pager
sudo journalctl -u streaming-agent -n 20 --no-pager
```
Want: `active (running)` and `[agent] <name> listening on http://0.0.0.0:8787`.

### 9. Firewall — tailnet only

```bash
sudo ufw allow in on tailscale0 to any port 8787 proto tcp
```
Do **not** open 8787 to the public internet.

### 10. Verify + register in the portal

From the portal host:
```bash
curl -s http://<VPS_TAILSCALE_IP>:8787/healthz
```
Then **Portal → Servers → Add**: base URL `http://<VPS_TAILSCALE_IP>:8787`, paste
the **AGENT_TOKEN**, ping until green.

---

# Part 2 — Updating an agent

**From the portal (recommended):** on the server's card, **Update**. The agent
git-pulls its own checkout, reinstalls dependencies, then hands its restart to
systemd on a 5-second delay so the job can report first. It refuses while any
other job is queued on that server, since the restart would drop it. The card
shows the new version (`<pkg>+<git sha>`) after the re-ping.

**By hand:** because `/opt/streaming-agent` is a clone, updating is:
```bash
cd /opt/streaming-agent && sudo git pull && sudo npm install --omit=dev && sudo systemctl restart streaming-agent
```
`.env` survives the pull (it's gitignored). If a release adds a **new required
env var**, the agent refuses to start and the journal names the missing key.

---

# Environment reference

`/opt/streaming-agent/.env` — see `.env.example`.

| Variable | Default | Purpose |
|---|---|---|
| `AGENT_TOKEN` | — (**required**) | Shared bearer token the portal must send. ≥32 chars. |
| `AGENT_HOST` | `127.0.0.1` | Bind address. `0.0.0.0` needs `AGENT_ALLOWED_IPS`. |
| `AGENT_PORT` | `8787` | Listen port. |
| `AGENT_ALLOWED_IPS` | (any) | Comma-separated allowlist — the portal's tailnet IP(s). |
| `AGENT_SERVER_NAME` | hostname | Label shown in the portal. |
| `ADVMO_DOS_KEY` / `ADVMO_DOS_SECRET` | — (**required**) | DigitalOcean Spaces creds written into each site's `.env`. |
| `TELEGRAM_BOT_TOKEN` | — (**required**) | Telegram bot token written into each site's `.env`. |
| `SEO_MONITOR_TOKEN` | — (**required**) | Auth for the SEO-monitor brand API. |
| `CDN_API_KEY` | — (**required**) | Auth for the CDN registry API. |
| `AGENT_REPO_ALLOWLIST` | (default repo only) | Extra **full clone URLs** `deploy`/`alias` may clone, comma-separated. `git clone` runs as root, so only listed repos are ever cloned. The default app repo is always allowed. |
| `AGENT_MAX_CONCURRENT` | `1` | Concurrent jobs. Keep 1 — deploys race on nginx/php-fpm. |
| `AGENT_JOB_TIMEOUT_MS` | `1200000` (20m) | Hard timeout for a job. |
| `AGENT_MIGRATE_TIMEOUT_MS` | `7200000` (2h) | Longer timeout just for DB migrations. |
| `AGENT_TRUST_PROXY` | off | Trust `X-Forwarded-For` (only behind a known proxy). |
| `DUMP_DIR` | `/var/backups/db-migrations` | Where DB-migrate dumps are written. |

> The five secrets were once hardcoded in the source and have been rotated.
> They live only in `.env` on each server — never commit them.

---

# Troubleshooting

**Service won't start** — `sudo journalctl -u streaming-agent -n 50 --no-pager`.
Common causes: a required env var missing (the log names it); `AGENT_HOST=0.0.0.0`
with an empty `AGENT_ALLOWED_IPS`; `/usr/bin/node` missing (re-check step 3).

**Server shows offline in the portal** — the portal host isn't on the tailnet,
`AGENT_ALLOWED_IPS` doesn't list its `100.x` IP, or ufw isn't allowing
`tailscale0`. Test with `curl http://<vps-tailnet-ip>:8787/healthz` from the portal.

**An operation is stuck** — one stuck job holds the single concurrency slot. On
the portal's **Operations** page hit **Kill** on that row: it terminates the job
on the agent (freeing the slot) and marks it failed. Since the queue fix, a job
stuck outside any child process also times out on its own and frees the slot.

**DB migration seems stuck** — watch the throughput heartbeat in the logs
(`… N MB transferred`). Rising = just slow (raise `AGENT_MIGRATE_TIMEOUT_MS`);
frozen = a real stall (network/lock).

**Redeploy refused: "already holds a deployed site"** — intentional. A site with
`src/.env` is never overwritten silently. Tick **Force redeploy** in the portal;
the previous `htdocs` is kept as `htdocs.bak-<timestamp>` beside it.
