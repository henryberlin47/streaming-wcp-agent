#!/bin/bash
# ============================================================
#  streaming-wcp-agent — zero-touch server bootstrap
# ============================================================
#  Turns a fresh Ubuntu 22.04/24.04 VPS into a managed WordOps server:
#  WordOps + stack + Redis, hardened default vhost, tuned PHP-FPM, Node LTS,
#  Tailscale, this agent under systemd, a root deploy key — then reports the
#  tailnet IP back to the portal so it can register the server by itself.
#
#  Not meant to be run by hand. The portal's "Provision new server" prints a
#  one-liner that exports this server's config and pipes this file into bash:
#
#      curl -fsSL https://<portal>/api/bootstrap/<id>/<key> | sudo bash
#
#  Config arrives as environment variables (never as arguments, never in this
#  file). Required: AGENT_TOKEN AGENT_SERVER_NAME AGENT_ALLOWED_IPS
#  AGENT_REPO_URL BOOTSTRAP_REPORT_URL + the five deploy secrets
#  (ADVMO_DOS_KEY ADVMO_DOS_SECRET TELEGRAM_BOT_TOKEN SEO_MONITOR_TOKEN
#  CDN_API_KEY). Optional: TS_AUTHKEY (zero-touch Tailscale; without it,
#  `tailscale up` prints a login URL and waits for you), AGENT_PORT (8787).
#
#  Idempotent: safe to re-run on a half-finished box — every step skips what
#  is already in place.
# ============================================================
set -uo pipefail
# NOT `set -e`: some steps legitimately return non-zero on an already-set-up
# box; those become warnings. Steps the agent cannot live without die().

# ============================================================
#  UI helpers (same look as the sibling scripts)
# ============================================================
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "1" ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
  C_BLUE=$'\e[34m'; C_CYAN=$'\e[36m'; C_GREY=$'\e[90m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''
  C_RED=''; C_GREEN=''; C_YELLOW=''
  C_BLUE=''; C_CYAN=''; C_GREY=''
fi
if [[ "${LANG:-}${LC_ALL:-}" == *UTF-8* || "${LANG:-}${LC_ALL:-}" == *utf8* ]]; then
  G_OK="✓"; G_ERR="✗"; G_WARN="⚠"; G_ARROW="➜"; G_DOT="•"
  BOX_TL="╭"; BOX_TR="╮"; BOX_BL="╰"; BOX_BR="╯"; BOX_H="─"; BOX_V="│"
else
  G_OK="+"; G_ERR="x"; G_WARN="!"; G_ARROW=">"; G_DOT="*"
  BOX_TL="+"; BOX_TR="+"; BOX_BL="+"; BOX_BR="+"; BOX_H="-"; BOX_V="|"
fi

BOX_WIDTH=60
STEP_NO=0
STEP_TOTAL=12

_repeat() { local n=$1 ch=$2 out=''; while ((n-- > 0)); do out+="$ch"; done; printf '%s' "$out"; }
banner() {
  local accent="$1"; shift; local title="$1"; shift; local line
  printf '%s%s%s%s%s\n' "$accent" "$BOX_TL" "$(_repeat "$BOX_WIDTH" "$BOX_H")" "$BOX_TR" "$C_RESET"
  printf '%s%s%s %s%-*s%s %s%s\n' "$accent" "$BOX_V" "$C_RESET" "$C_BOLD" $((BOX_WIDTH - 2)) "$title" "$C_RESET" "$accent$BOX_V" "$C_RESET"
  for line in "$@"; do
    printf '%s%s%s %-*s %s%s\n' "$accent" "$BOX_V" "$C_RESET" $((BOX_WIDTH - 2)) "$line" "$accent$BOX_V" "$C_RESET"
  done
  printf '%s%s%s%s%s\n' "$accent" "$BOX_BL" "$(_repeat "$BOX_WIDTH" "$BOX_H")" "$BOX_BR" "$C_RESET"
}
step()  { STEP_NO=$((STEP_NO + 1)); printf '\n%s%s[%d/%d]%s %s%s%s\n' "$C_BOLD" "$C_BLUE" "$STEP_NO" "$STEP_TOTAL" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; }
info()  { printf '   %s%s%s %s\n' "$C_GREY" "$G_DOT" "$C_RESET" "$1"; }
ok()    { printf '   %s%s%s %s\n' "$C_GREEN" "$G_OK" "$C_RESET" "$1"; }
warn()  { printf '   %s%s%s %s\n' "$C_YELLOW" "$G_WARN" "$C_RESET" "$1"; }
err()   { printf '   %s%s%s %s\n' "$C_RED" "$G_ERR" "$C_RESET" "$1" >&2; }
die()   { err "$1"; report_failure "$1"; exit "${2:-1}"; }

WARNINGS=()
note_warn() { warn "$1"; WARNINGS+=("$1"); }

# JSON string escape for the report payload (values are single-line).
json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'; }

# ============================================================
#  Report back to the portal
# ============================================================
AGENT_PORT="${AGENT_PORT:-8787}"
INSTALL_DIR="/opt/streaming-agent"
TS_IP=""; PUBKEY=""; AGENT_VERSION=""

post_report() {  # $1 = status
  local w='' first=1 line
  for line in ${WARNINGS[@]+"${WARNINGS[@]}"}; do
    [ $first = 1 ] || w+=','; first=0; w+="\"$(json_str "$line")\""
  done
  local payload
  payload="{\"status\":\"$(json_str "$1")\",\"tailscale_ip\":\"$(json_str "$TS_IP")\",\"agent_port\":${AGENT_PORT},\"hostname\":\"$(json_str "$(hostname)")\",\"agent_version\":\"$(json_str "$AGENT_VERSION")\",\"ssh_pubkey\":\"$(json_str "$PUBKEY")\",\"warnings\":[${w}]}"
  if [ -z "${BOOTSTRAP_REPORT_URL:-}" ]; then return 1; fi
  curl -fsS -m 20 -X POST -H 'Content-Type: application/json' -d "$payload" "$BOOTSTRAP_REPORT_URL" >/dev/null 2>&1
}
report_failure() { post_report "failed: $1" || true; }

# ============================================================
#  Preflight
# ============================================================
clear 2>/dev/null || true
banner "$C_CYAN" "Streaming WCP — server bootstrap" \
  "Server  : ${AGENT_SERVER_NAME:-?}" \
  "Agent   : $INSTALL_DIR  (port $AGENT_PORT)" \
  "Stacks  : WordOps + Redis + Node + Tailscale"

step "Preflight checks"
[[ $EUID -eq 0 ]] || { err "Run as root (the one-liner uses sudo bash)."; exit 1; }
ok "running as root"
if [ -r /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}-${VERSION_ID:-}" in
    ubuntu-22.04|ubuntu-24.04) ok "Ubuntu $VERSION_ID" ;;
    *) note_warn "Untested OS: ${PRETTY_NAME:-unknown} (WordOps supports Ubuntu 22.04/24.04)" ;;
  esac
fi
missing=()
for v in AGENT_TOKEN AGENT_SERVER_NAME AGENT_ALLOWED_IPS AGENT_REPO_URL BOOTSTRAP_REPORT_URL \
         ADVMO_DOS_KEY ADVMO_DOS_SECRET TELEGRAM_BOT_TOKEN SEO_MONITOR_TOKEN CDN_API_KEY; do
  [ -n "${!v:-}" ] || missing+=("$v")
done
if [ "${#missing[@]}" -gt 0 ]; then
  err "Missing config: ${missing[*]}"
  info "This script expects the portal's one-liner to export them. Don't run it by hand."
  exit 1
fi
ok "all required config present"
for c in curl wget; do
  command -v "$c" >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq "$c" >/dev/null; }
  command -v "$c" >/dev/null 2>&1 && ok "$c present" || die "cannot install $c"
done
export DEBIAN_FRONTEND=noninteractive

# ============================================================
step "Installing WordOps"
if command -v wo >/dev/null 2>&1; then
  ok "WordOps already installed ($(wo --version 2>/dev/null | head -n1 || echo present)) — skipping"
else
  info "Downloading installer (wops.cc)…"
  if wget -qO /tmp/wo-install wops.cc && bash /tmp/wo-install; then ok "WordOps installed"; else rm -f /tmp/wo-install; die "WordOps install failed"; fi
  rm -f /tmp/wo-install
fi
command -v wo >/dev/null 2>&1 || export PATH="$PATH:/usr/local/bin"

# ============================================================
step "Installing WordOps stack + Redis"
if wo stack install >/dev/null 2>&1; then ok "base stack installed"; else note_warn "wo stack install returned non-zero (may already be installed)"; fi
if wo stack install --redis >/dev/null 2>&1; then ok "Redis stack installed"; else note_warn "wo stack install --redis returned non-zero (may already be installed)"; fi
systemctl is-active --quiet redis-server && ok "redis-server active" || note_warn "redis-server is not active"

# ============================================================
step "Securing default Nginx vhost (unknown domains → 403)"
# 443 catch-all needs the :22222 panel's self-signed cert; skip it if absent so
# nginx -t can't fail on a box without the admin stack.
CRT=/var/www/22222/cert/22222.crt; KEY=/var/www/22222/cert/22222.key
{
cat <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
    location ^~ /.well-known/acme-challenge/ { allow all; default_type "text/plain"; try_files $uri =404; }
    location / { return 403; }
}
EOF
if [ -f "$CRT" ] && [ -f "$KEY" ]; then
cat <<EOF
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    root /var/www/html;
    ssl_certificate     $CRT;
    ssl_certificate_key $KEY;
    location ^~ /.well-known/acme-challenge/ { allow all; default_type "text/plain"; try_files \$uri =404; }
    location / { return 403; }
}
EOF
fi
} > /etc/nginx/sites-available/default
mkdir -p /var/www/html/.well-known/acme-challenge
chown -R www-data:www-data /var/www/html/.well-known 2>/dev/null || true
if nginx -t >/dev/null 2>&1 && systemctl reload nginx; then ok "default vhost secured, ACME challenges allowed"; else note_warn "nginx -t failed after writing the default vhost — review /etc/nginx/sites-available/default"; fi

# ============================================================
step "Tuning PHP-FPM"
PHPV=""; for v in 8.4 8.3 8.2; do [ -f "/etc/php/$v/fpm/php.ini" ] && { PHPV=$v; break; }; done
set_ini() { local f="$1" k="$2" val="$3"
  if grep -qE "^[;[:space:]]*$k[[:space:]]*=" "$f"; then sed -i -E "s|^[;[:space:]]*$k[[:space:]]*=.*|$k = $val|" "$f"; else echo "$k = $val" >> "$f"; fi; }
if [ -n "$PHPV" ]; then
  INI="/etc/php/$PHPV/fpm/php.ini"; POOL="/etc/php/$PHPV/fpm/pool.d/www.conf"
  set_ini "$INI" max_execution_time 600;  set_ini "$INI" max_input_time 600
  set_ini "$INI" max_input_vars 3000;     set_ini "$INI" memory_limit 512M
  set_ini "$INI" post_max_size 512M;      set_ini "$INI" upload_max_filesize 512M
  set_ini "$INI" session.gc_maxlifetime 1440
  if [ -f "$POOL" ]; then
    set_ini "$POOL" pm.start_servers 12;  set_ini "$POOL" pm.min_spare_servers 8
    set_ini "$POOL" pm.max_spare_servers 16; set_ini "$POOL" pm.max_children 30
    set_ini "$POOL" pm.max_requests 500
  fi
  systemctl restart "php$PHPV-fpm" && ok "PHP $PHPV FPM tuned + restarted" || note_warn "php$PHPV-fpm failed to restart after tuning"
else
  note_warn "no PHP-FPM found under /etc/php — tuning skipped"
fi

# ============================================================
step "Installing Node.js LTS"
need_node=1
if command -v node >/dev/null 2>&1; then
  major="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
  [ "${major:-0}" -ge 18 ] && { ok "node $(node -v) already present"; need_node=0; }
fi
if [ $need_node = 1 ]; then
  if curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1 && apt-get install -y -qq nodejs >/dev/null; then
    ok "node $(node -v) installed"
  else die "Node.js install failed"; fi
fi
[ "$(command -v node)" = "/usr/bin/node" ] || note_warn "node is at $(command -v node), but the systemd unit runs /usr/bin/node"

# ============================================================
step "Installing git, sed, ufw"
apt-get install -y -qq git sed ufw >/dev/null 2>&1 && ok "git, sed, ufw present" || note_warn "apt-get install git sed ufw returned non-zero"

# ============================================================
step "Joining the Tailscale tailnet"
if ! command -v tailscale >/dev/null 2>&1; then
  curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1 && ok "tailscale installed" || die "Tailscale install failed"
else ok "tailscale already installed"; fi
if [ -n "${TS_AUTHKEY:-}" ]; then
  tailscale up --auth-key="$TS_AUTHKEY" --hostname="$(echo "$AGENT_SERVER_NAME" | tr '[:upper:]' '[:lower:]' | tr '_' '-' | tr -cd 'a-z0-9-')" >/dev/null 2>&1 \
    && ok "joined tailnet with auth key" || note_warn "tailscale up with the auth key returned non-zero"
else
  warn "No TS_AUTHKEY — tailscale will print a login URL and WAIT until you approve it."
  tailscale up || note_warn "tailscale up returned non-zero"
fi
TS_IP="$(tailscale ip -4 2>/dev/null | head -n1)"
[ -n "$TS_IP" ] && ok "tailnet IP: $TS_IP" || die "no Tailscale IPv4 — the portal cannot reach this server"

# ============================================================
step "Installing the agent ($INSTALL_DIR)"
if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" pull -q && ok "agent repo updated (git pull)" || note_warn "git pull failed in $INSTALL_DIR"
else
  if [ -e "$INSTALL_DIR" ]; then
    # An agent installed by copying files (pre-bootstrap). git clone refuses a
    # non-empty dir, so move it aside — its .env is regenerated below and nothing
    # else in it is needed — and clone fresh so future updates are a git pull.
    OLD="$INSTALL_DIR.old-$(date +%Y%m%d%H%M%S)"
    mv "$INSTALL_DIR" "$OLD" && note_warn "existing non-git agent moved to $OLD (old .env kept there; delete once the new agent works)"
  fi
  git clone -q "$AGENT_REPO_URL" "$INSTALL_DIR" && ok "agent cloned" || die "git clone $AGENT_REPO_URL failed"
fi
( cd "$INSTALL_DIR" && npm install --omit=dev --silent >/dev/null 2>&1 ) && ok "npm dependencies installed" || die "npm install failed in $INSTALL_DIR"
AGENT_VERSION="$(node -p "require('$INSTALL_DIR/package.json').version" 2>/dev/null || echo unknown)"

# ============================================================
step "Writing $INSTALL_DIR/.env"
( umask 077; cat > "$INSTALL_DIR/.env" <<EOF
# Written by bootstrap.sh $(date -u +%FT%TZ) — managed by the portal
AGENT_TOKEN=$AGENT_TOKEN
AGENT_HOST=0.0.0.0
AGENT_PORT=$AGENT_PORT
AGENT_ALLOWED_IPS=$AGENT_ALLOWED_IPS
AGENT_SERVER_NAME=$AGENT_SERVER_NAME
ADVMO_DOS_KEY=$ADVMO_DOS_KEY
ADVMO_DOS_SECRET=$ADVMO_DOS_SECRET
TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN
SEO_MONITOR_TOKEN=$SEO_MONITOR_TOKEN
CDN_API_KEY=$CDN_API_KEY
EOF
)
chmod 600 "$INSTALL_DIR/.env"
ok ".env written (0600) — allowlist: $AGENT_ALLOWED_IPS"

# ============================================================
step "Starting the agent under systemd"
cp "$INSTALL_DIR/streaming-agent.service" /etc/systemd/system/streaming-agent.service
systemctl daemon-reload
systemctl enable --now streaming-agent >/dev/null 2>&1
systemctl restart streaming-agent
sleep 2
if systemctl is-active --quiet streaming-agent; then
  ok "streaming-agent active"
  if curl -fsS -m 5 "http://127.0.0.1:$AGENT_PORT/healthz" >/dev/null 2>&1; then ok "healthz responds on :$AGENT_PORT"; else note_warn "agent is active but /healthz did not answer on 127.0.0.1:$AGENT_PORT"; fi
else
  journalctl -u streaming-agent -n 15 --no-pager 2>/dev/null | sed 's/^/     /' >&2
  die "streaming-agent failed to start (see journal above)"
fi
if command -v ufw >/dev/null 2>&1; then
  ufw allow in on tailscale0 to any port "$AGENT_PORT" proto tcp >/dev/null 2>&1 && ok "ufw: :$AGENT_PORT allowed on tailscale0 only" || note_warn "could not add the ufw rule for tailscale0"
  ufw status 2>/dev/null | grep -q "Status: active" || info "ufw is installed but inactive — enable it yourself (ufw enable) after allowing SSH"
fi

# ============================================================
step "Root SSH deploy key (for the private app + map repos)"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
if [ ! -f /root/.ssh/id_ed25519 ]; then
  ssh-keygen -t ed25519 -N '' -q -f /root/.ssh/id_ed25519 -C "streaming-agent@$(hostname)" && ok "generated /root/.ssh/id_ed25519" || note_warn "ssh-keygen failed"
else ok "deploy key already exists"; fi
if ! grep -q "^github.com" /root/.ssh/known_hosts 2>/dev/null; then
  ssh-keyscan -t ed25519 github.com >> /root/.ssh/known_hosts 2>/dev/null && ok "github.com added to known_hosts" || note_warn "ssh-keyscan github.com failed"
fi
PUBKEY="$(cat /root/.ssh/id_ed25519.pub 2>/dev/null || true)"

# ============================================================
step "Reporting to the portal"
if post_report "ready"; then
  ok "reported: $TS_IP:$AGENT_PORT — the portal will register and ping this server"
else
  note_warn "could not reach $BOOTSTRAP_REPORT_URL — register manually: base URL http://$TS_IP:$AGENT_PORT"
fi

# ============================================================
echo
if [ "${#WARNINGS[@]}" -eq 0 ]; then
  banner "$C_GREEN" "${G_OK} Server ready: $AGENT_SERVER_NAME" \
    "Agent   : http://$TS_IP:$AGENT_PORT  (tailnet only)" \
    "Stacks  : WordOps + Redis + Node $(node -v 2>/dev/null) + Tailscale"
else
  banner "$C_YELLOW" "${G_WARN} Ready with ${#WARNINGS[@]} warning(s)" "Agent   : http://$TS_IP:$AGENT_PORT"
  echo; for w in "${WARNINGS[@]}"; do printf '     %s%s%s %s\n' "$C_YELLOW" "$G_ARROW" "$C_RESET" "$w"; done
fi
echo
printf '   %sACTION REQUIRED — add this deploy key to GitHub (app repo + seo-domain-map):%s\n' "$C_BOLD" "$C_RESET"
printf '     %s%s%s\n' "$C_DIM" "${PUBKEY:-<no key>}" "$C_RESET"
printf '     %s%s Settings: https://github.com/settings/keys — the portal also shows this key.%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
printf '     %s%s Verify: ssh -T git@github.com%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
echo
