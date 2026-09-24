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
#      curl -4 -fsSL https://<portal>/api/bootstrap/<id>/<key> | sudo bash
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
# Count the step() calls in this very file, so adding a step can never again
# leave the total behind ("[13/12]", and a progress bar past 100% in the portal).
STEP_TOTAL=13
if [ -f "$0" ]; then _n="$(grep -cE '^step "' "$0" 2>/dev/null || true)"; [ "${_n:-0}" -gt 0 ] 2>/dev/null && STEP_TOTAL="$_n"; fi

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
step()  { STEP_NO=$((STEP_NO + 1)); printf '\n%s%s[%d/%d]%s %s%s%s\n' "$C_BOLD" "$C_BLUE" "$STEP_NO" "$STEP_TOTAL" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; post_progress "$STEP_NO" "$1"; }
info()  { printf '   %s%s%s %s\n' "$C_GREY" "$G_DOT" "$C_RESET" "$1"; }
ok()    { printf '   %s%s%s %s\n' "$C_GREEN" "$G_OK" "$C_RESET" "$1"; }
warn()  { printf '   %s%s%s %s\n' "$C_YELLOW" "$G_WARN" "$C_RESET" "$1"; }
err()   { printf '   %s%s%s %s\n' "$C_RED" "$G_ERR" "$C_RESET" "$1" >&2; }
die()   { err "$1"; report_failure "$1${LAST_FAIL:+ — $LAST_FAIL}"; exit "${2:-1}"; }

WARNINGS=()
note_warn() { warn "$1"; WARNINGS+=("$1"); }

# JSON string escape for the report payload (values are single-line).
json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'; }

# Quiet on success, loud on failure. Runs a command with its output captured;
# if it fails, prints the command and the last lines so the CAUSE is visible
# instead of a bare "X failed" (and the portal gets the tail too, via die()).
# stdin is closed so nothing can sit waiting on a prompt. Never pass a secret
# as an argument to try(): the command line is echoed on failure.
LAST_LOG="$(mktemp)"; LAST_FAIL=""
trap 'rm -f "$LAST_LOG"' EXIT
try() {
  "$@" >"$LAST_LOG" 2>&1 </dev/null; local rc=$?
  if [ $rc -ne 0 ]; then
    LAST_FAIL="$(tail -n 3 "$LAST_LOG" | tr '\n' ' ' | cut -c1-280)"
    printf '     %s$ %s   (exit %d)%s\n' "$C_DIM" "$*" "$rc" "$C_RESET" >&2
    tail -n 15 "$LAST_LOG" | sed 's/^/       /' >&2
  else
    LAST_FAIL=""
  fi
  return $rc
}
# Network steps get a few attempts: DNS can be dead for seconds right after
# `tailscale up` swaps resolv.conf to MagicDNS, and package mirrors hiccup.
retry() {  # retry <attempts> cmd…
  local n=$1 i; shift
  for ((i = 1; i <= n; i++)); do
    try "$@" && return 0
    [ "$i" -lt "$n" ] && { info "attempt $i/$n failed — retrying in 5s"; sleep 5; }
  done
  return 1
}

# ============================================================
#  Report back to the portal
# ============================================================
# WordOps refuses to START without a git identity. On first run it asks for a
# name + email on stdin; this script runs with stdin closed (so nothing can hang),
# so that prompt gets EOF and EVERY `wo` command dies with EOFError — nothing is
# installed at all. WordOps reads ~/.gitconfig [user], so seed it before wo ever
# runs. An existing identity is left alone. It is only used for WordOps' local
# commits of /etc config ("stored locally only", per its own prompt).
ensure_git_identity() {
  local n e
  n="$(git config --global user.name 2>/dev/null || true)"
  e="$(git config --global user.email 2>/dev/null || true)"
  [ -n "$n" ] || git config --global user.name "${WO_GIT_NAME:-${AGENT_SERVER_NAME:-wordops}}"
  [ -n "$e" ] || git config --global user.email "${WO_GIT_EMAIL:-root@$(hostname -f 2>/dev/null || hostname)}"
}

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
  curl -4 -fsS -m 20 -X POST -H 'Content-Type: application/json' -d "$payload" "$BOOTSTRAP_REPORT_URL" >/dev/null 2>&1
}
report_failure() { post_report "failed: $1" || true; }

# Step progress for the portal's dialog. Fire-and-forget in a detached
# subshell with a short timeout, so a slow or unreachable portal never stalls
# the install. The portal only ever moves the step forward, so ordering is moot.
post_progress() {  # $1 = step no, $2 = label
  [ -n "${BOOTSTRAP_REPORT_URL:-}" ] || return 0
  local payload="{\"status\":\"progress\",\"step\":$1,\"total\":$STEP_TOTAL,\"label\":\"$(json_str "$2")\"}"
  ( curl -4 -fsS -m 8 -X POST -H 'Content-Type: application/json' -d "$payload" "$BOOTSTRAP_REPORT_URL" >/dev/null 2>&1 & )
}

# ============================================================
#  Preflight
# ============================================================
clear 2>/dev/null || true
# Fingerprint of the exact script content that is running. GitHub's raw CDN
# caches for minutes per edge, so after a push a VPS can still be handed the
# previous version — this makes "which version actually ran?" visible at a
# glance. Compare with: sha256sum bootstrap.sh | cut -c1-12
SCRIPT_ID="unknown (piped)"
if [ -f "$0" ]; then SCRIPT_ID="$( (sha256sum "$0" 2>/dev/null || shasum -a 256 "$0" 2>/dev/null) | cut -c1-12)"; fi
banner "$C_CYAN" "Streaming WCP — server bootstrap" \
  "Script  : $SCRIPT_ID" \
  "Server  : ${AGENT_SERVER_NAME:-?}" \
  "Agent   : $INSTALL_DIR  (port $AGENT_PORT)" \
  "Stacks  : WordOps + Redis + Node + Tailscale"

step "Preflight checks"
[[ $EUID -eq 0 ]] || { err "Run as root (the one-liner uses sudo bash)."; exit 1; }
ok "running as root"
# Everything below (git identity, SSH key, npm cache) must land in ROOT's home:
# the agent runs under systemd with HOME=/root, and some sudo setups keep the
# invoking user's HOME, which would put root's config in the wrong place.
export HOME=/root
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
for c in curl wget git; do
  command -v "$c" >/dev/null 2>&1 || { apt-get -o Acquire::ForceIPv4=true update -qq && apt-get -o Acquire::ForceIPv4=true install -y -qq "$c" >/dev/null; }
  command -v "$c" >/dev/null 2>&1 && ok "$c present" || die "cannot install $c"
done
export DEBIAN_FRONTEND=noninteractive

# IPv4 ONLY, for everything, unconditionally. Cloud VMs routinely get an IPv6
# address with no working route; then anything that tries IPv6 first (apt,
# Launchpad via Python, npm, git, curl inside the NodeSource/Tailscale
# installers) hangs or fails. Cover every resolver in one go:
#   gai.conf   getaddrinfo() sorts IPv4 first — Python, git, ssh, node, wget…
#   apt        ForceIPv4
#   curl/wget  rc files in root's HOME (also caught by the piped installers)
#   node/npm   --dns-result-order=ipv4first for this session
#   ssh        AddressFamily inet (git over ssh)
force_ipv4() {
  grep -qE '^precedence ::ffff:0:0/96[[:space:]]+100' /etc/gai.conf 2>/dev/null || echo 'precedence ::ffff:0:0/96  100' >> /etc/gai.conf
  echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4
  grep -qs '^--ipv4' "$HOME/.curlrc" 2>/dev/null || echo '--ipv4' >> "$HOME/.curlrc"
  grep -qs '^inet4_only' "$HOME/.wgetrc" 2>/dev/null || echo 'inet4_only = on' >> "$HOME/.wgetrc"
  export NODE_OPTIONS="--dns-result-order=ipv4first${NODE_OPTIONS:+ $NODE_OPTIONS}"
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  grep -qs '^AddressFamily inet' /root/.ssh/config 2>/dev/null || printf 'AddressFamily inet\n' >> /root/.ssh/config
  chmod 600 /root/.ssh/config
  ok "IPv4 only: gai.conf, apt, curl, wget, node, ssh"
}
force_ipv4

# ============================================================
step "Installing WordOps"
# BEFORE the installer, and also on a box where wo already exists: this is what
# repairs a server whose WordOps was installed but could never start.
ensure_git_identity
ok "git identity: $(git config --global user.name) <$(git config --global user.email)>"
if command -v wo >/dev/null 2>&1; then
  ok "WordOps already installed — skipping the installer"
else
  info "Downloading installer (wops.cc)…"
  if wget -4 -qO /tmp/wo-install wops.cc && bash /tmp/wo-install; then ok "WordOps installed"; else rm -f /tmp/wo-install; die "WordOps install failed"; fi
  rm -f /tmp/wo-install
fi
command -v wo >/dev/null 2>&1 || export PATH="$PATH:/usr/local/bin"
# "Installed" is not enough — it has to actually run. This is the check that
# would have caught the EOFError crash instead of sailing on to "Ready".
try wo --version && ok "wo runs ($(wo --version 2>/dev/null | head -n1))" || die "WordOps is installed but cannot start"

# ============================================================
step "Installing WordOps stack + Redis"
# A fresh Ubuntu runs unattended-upgrades / apt-daily right after first boot and
# holds the dpkg lock for minutes; any apt underneath `wo` then fails with a bare
# "Oops Something went wrong". Wait for the lock to clear first (up to 10 min).
wait_for_apt() {
  command -v fuser >/dev/null 2>&1 || return 0
  local i
  for ((i = 0; i < 120; i++)); do
    fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1 || return 0
    [ "$i" -eq 0 ] && info "apt/dpkg is busy (unattended-upgrades on a fresh VM) — waiting for it"
    sleep 5
  done
  warn "apt/dpkg still locked after 10 min — continuing anyway"
}
# `wo` swallows apt's error; the reason is only in its log. Show it on failure.
wo_stack() {
  wait_for_apt
  if try wo stack install "$@"; then return 0; fi
  [ -f /var/log/wo/wordops.log ] && { echo "       --- /var/log/wo/wordops.log ---" >&2; grep -vE '^\s*$' /var/log/wo/wordops.log | tail -n 25 | sed 's/^/       /' >&2; }
  return 1
}
# WordOps adds its PHP and nginx repositories as Launchpad PPAs; the whole
# stack install fails ("Unable to locate package php8.x-…") if Launchpad can't
# be reached. Everything is IPv4-only already (force_ipv4 in preflight); this
# just says so early if the network blocks it.
curl -4 -sS -m 8 -o /dev/null https://api.launchpad.net/ 2>/dev/null \
  || note_warn "api.launchpad.net is unreachable over IPv4 — the PHP/nginx PPAs cannot be added from this network"
wait_for_apt
try apt-get update -qq || note_warn "apt-get update returned non-zero"
if retry 3 wo_stack; then ok "base stack installed"; else note_warn "wo stack install returned non-zero"; fi
if retry 2 wo_stack --redis; then ok "Redis stack installed"; else note_warn "wo stack install --redis returned non-zero"; fi
# Judge by what is actually ON the box, not by exit codes. Without nginx, PHP-FPM
# and MariaDB no site can ever be deployed here, so that is fatal — never "Ready
# with warnings". (Redis stays a warning: sites work without an object cache.)
missing_stack=()
command -v nginx >/dev/null 2>&1 || missing_stack+=("nginx")
ls /etc/php/*/fpm/php.ini >/dev/null 2>&1 || missing_stack+=("php-fpm")
{ command -v mariadb >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1; } || missing_stack+=("mariadb")
if [ "${#missing_stack[@]}" -gt 0 ]; then
  die "WordOps stack is incomplete — missing: ${missing_stack[*]}. No site can be deployed on this server. See the wordops.log lines above (tail /var/log/wo/wordops.log), fix the cause, and re-run this same command."
fi
ok "stack verified: nginx, php-fpm, mariadb"
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
# Sites are created with --php83, so PHP 8.3 must exist NOW. If it only arrived
# with the first deploy it would be installed AFTER this tuning ran and stay at
# the defaults (memory 128M, default regex limits) — which is exactly how sites
# ended up serving blank pages: WP Rocket dies on a large homepage.
if [ ! -f /etc/php/8.3/fpm/php.ini ]; then
  if try wo stack install --php83; then ok "PHP 8.3 installed (the version sites run on)"; else note_warn "could not install PHP 8.3 (wo stack install --php83)"; fi
fi
# The settings live in ONE place — scripts/tune-php.sh — shared with the agent,
# which re-applies them before every PHP restart. It tunes every installed
# version, validates with php-fpm -t, and rolls back rather than break PHP.
TUNE=""
for c in "$(dirname "$0")/scripts/tune-php.sh" "$INSTALL_DIR/scripts/tune-php.sh"; do [ -f "$c" ] && { TUNE="$c"; break; }; done
if [ -n "$TUNE" ]; then
  if out="$(bash "$TUNE" 2>&1)"; then
    while IFS= read -r l; do [ -n "$l" ] && ok "$l"; done <<< "$out"
  else
    while IFS= read -r l; do [ -n "$l" ] && warn "$l"; done <<< "$out"
    note_warn "PHP-FPM tuning reported a problem (the agent re-applies it on the next deploy)"
  fi
else
  note_warn "scripts/tune-php.sh not found — PHP left untuned for now (the agent applies it on the first deploy)"
fi

# ============================================================
step "Installing Node.js LTS"
need_node=1
if command -v node >/dev/null 2>&1; then
  major="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
  [ "${major:-0}" -ge 18 ] && { ok "node $(node -v) already present"; need_node=0; }
fi
# node being present does NOT mean npm is on PATH. The classic case: /usr/bin/node
# is a symlink into an nvm install, whose npm sits beside the REAL binary and is
# only on PATH in interactive shells (where nvm.sh is sourced) — never under
# `sudo bash` or systemd. Look beside the real binary before giving up.
if [ $need_node = 0 ] && ! command -v npm >/dev/null 2>&1; then
  real_bin="$(dirname "$(readlink -f "$(command -v node)")")"
  if [ -x "$real_bin/npm" ]; then
    export PATH="$real_bin:$PATH"
    note_warn "npm was not on PATH; using $real_bin/npm. node here is a symlink (nvm?) — an nvm upgrade can break /usr/bin/node. A NodeSource install is sturdier."
  else
    info "node is present but npm is nowhere to be found — installing Node.js LTS from NodeSource"
    need_node=1
  fi
fi
if [ $need_node = 1 ]; then
  if retry 2 bash -c 'curl -4 -fsSL https://deb.nodesource.com/setup_lts.x | bash -' && retry 2 apt-get install -y -qq nodejs; then
    ok "node $(node -v) installed"
  else die "Node.js install failed"; fi
fi
command -v npm >/dev/null 2>&1 && ok "npm $(npm -v 2>/dev/null)" || die "npm is not on PATH even after installing Node.js"
# What the systemd unit needs is that /usr/bin/node EXISTS (a symlink is fine) —
# not that it is first on PATH, which it isn't once the real bin dir is prepended.
[ -x /usr/bin/node ] || note_warn "/usr/bin/node does not exist, but the systemd unit runs it — symlink your node there or install Node.js from NodeSource"

# ============================================================
step "Installing git, sed, ufw"
retry 2 apt-get install -y -qq git sed ufw && ok "git, sed, ufw present" || note_warn "apt-get install git sed ufw returned non-zero"

# ============================================================
step "Joining the Tailscale tailnet"
if ! command -v tailscale >/dev/null 2>&1; then
  retry 2 bash -c 'curl -4 -fsSL https://tailscale.com/install.sh | sh' && ok "tailscale installed" || die "Tailscale install failed"
else ok "tailscale already installed"; fi
if [ -n "${TS_AUTHKEY:-}" ]; then
  tailscale up --auth-key="$TS_AUTHKEY" --hostname="$(echo "$AGENT_SERVER_NAME" | tr '[:upper:]' '[:lower:]' | tr '_' '-' | tr -cd 'a-z0-9-')" >/dev/null 2>&1 \
    && ok "joined tailnet with auth key" || note_warn "tailscale up with the auth key returned non-zero"
  # (deliberately NOT via try(): it would echo the auth key on failure)
else
  warn "No TS_AUTHKEY — tailscale will print a login URL and WAIT until you approve it."
  tailscale up || note_warn "tailscale up returned non-zero"
fi
TS_IP="$(tailscale ip -4 2>/dev/null | head -n1)"
[ -n "$TS_IP" ] && ok "tailnet IP: $TS_IP" || die "no Tailscale IPv4 — the portal cannot reach this server"
# Joining swaps /etc/resolv.conf to MagicDNS, and resolution can be dead for a
# few seconds. Wait for it to settle so the git/npm fetches that follow don't
# hit a resolver that isn't answering yet.
for _ in 1 2 3 4 5 6 7 8 9 10; do getent hosts registry.npmjs.org >/dev/null 2>&1 && break; sleep 2; done
getent hosts registry.npmjs.org >/dev/null 2>&1 && ok "DNS settled" || note_warn "registry.npmjs.org is not resolving after joining the tailnet"

# ============================================================
step "Installing the agent ($INSTALL_DIR)"
if [ -d "$INSTALL_DIR/.git" ]; then
  retry 3 git -C "$INSTALL_DIR" pull -q && ok "agent repo updated (git pull)" || note_warn "git pull failed in $INSTALL_DIR"
else
  if [ -e "$INSTALL_DIR" ]; then
    # An agent installed by copying files (pre-bootstrap). git clone refuses a
    # non-empty dir, so move it aside — its .env is regenerated below and nothing
    # else in it is needed — and clone fresh so future updates are a git pull.
    OLD="$INSTALL_DIR.old-$(date +%Y%m%d%H%M%S)"
    mv "$INSTALL_DIR" "$OLD" && note_warn "existing non-git agent moved to $OLD (old .env kept there; delete once the new agent works)"
  fi
  retry 3 git clone -q "$AGENT_REPO_URL" "$INSTALL_DIR" && ok "agent cloned" || die "git clone $AGENT_REPO_URL failed"
fi
# No --silent and no /dev/null: try() captures the output and shows it if npm
# fails, which is the only way to learn WHY. Retried because this is the first
# registry fetch after the tailnet join.
export HOME="${HOME:-/root}"
retry 3 npm --prefix "$INSTALL_DIR" install --omit=dev --no-audit --no-fund && ok "npm dependencies installed" || die "npm install failed in $INSTALL_DIR"
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
  if curl -4 -fsS -m 5 "http://127.0.0.1:$AGENT_PORT/healthz" >/dev/null 2>&1; then ok "healthz responds on :$AGENT_PORT"; else note_warn "agent is active but /healthz did not answer on 127.0.0.1:$AGENT_PORT"; fi
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
  ssh-keyscan -4 -t ed25519 github.com >> /root/.ssh/known_hosts 2>/dev/null && ok "github.com added to known_hosts" || note_warn "ssh-keyscan github.com failed"
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
printf '   %sACTION REQUIRED — add this SSH key to a GitHub ACCOUNT that can read the app repo + seo-domain-map:%s\n' "$C_BOLD" "$C_RESET"
printf '     %s%s%s\n' "$C_DIM" "${PUBKEY:-<no key>}" "$C_RESET"
printf '     %s%s https://github.com/settings/keys  (an account SSH key — NOT a per-repo deploy key:%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
printf '     %s  GitHub allows a deploy key on only ONE repo, and deploys need two.)%s\n' "$C_DIM" "$C_RESET"
printf '     %s%s The portal shows this key too, and its "Check GitHub" button verifies access.%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
printf '     %s%s Verify: ssh -T git@github.com%s\n' "$C_DIM" "$G_ARROW" "$C_RESET"
echo
