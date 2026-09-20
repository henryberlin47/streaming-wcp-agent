#!/bin/bash
# ============================================================
#  tune-php.sh — idempotent PHP-FPM tuning (single source of truth)
# ============================================================
#  Used by bootstrap.sh on a new server AND by the agent before it restarts
#  PHP in deploy / alias / update, so every server converges on these values
#  no matter when or how its PHP got installed.
#
#  Why this exists: sites run on PHP 8.3 (created with --php83), but a server
#  can also carry 8.4 — and PHP 8.3 is often installed LATER, by the first
#  deploy, after any one-off tuning already ran. An untuned 8.3 (memory 128M,
#  default regex limits) made WP Rocket's page post-processing die on a large
#  homepage: fatal inside the output buffer -> HTTP 200 with an EMPTY body.
#  memory_limit and the three pcre.* lines were applied together on the
#  affected server and fixed it, so they are kept together here.
#
#  Usage: tune-php.sh [--no-restart]
#    --no-restart   fix the config only; the caller restarts PHP itself
#  Env:   PHP_ETC   config root (default /etc/php) — for tests
#
#  Safe by construction: every file it changes is backed up first, the result
#  is validated with `php-fpm -t`, and on failure the backups are restored — a
#  bad value can never leave PHP unable to start. Exit 0 = tuned/already tuned.
# ============================================================
set -uo pipefail

PHP_ETC="${PHP_ETC:-/etc/php}"
RESTART=1
[ "${1:-}" = "--no-restart" ] && RESTART=0

INI_SETTINGS="max_execution_time=600 max_input_time=600 max_input_vars=3000
memory_limit=512M post_max_size=512M upload_max_filesize=512M
session.gc_maxlifetime=1440
pcre.backtrack_limit=10000000 pcre.recursion_limit=10000000 pcre.jit=0"
POOL_SETTINGS="pm.start_servers=12 pm.min_spare_servers=8 pm.max_spare_servers=16
pm.max_children=30 pm.max_requests=500"

TOUCHED=""   # space-separated list of files changed for the PHP version in hand

# set_kv <file> <key> <value> -> 0 if the file was changed, 1 if already right.
# Only ACTIVE lines are edited; commented documentation lines are left alone and
# a missing key is appended. The file is backed up once before its first change.
# No `sed -i` (GNU/BSD differ), and it is rewritten with cat so owner, mode and
# inode are preserved.
set_kv() {
  local file="$1" key="$2" val="$3" kre current tmp
  kre="$(printf '%s' "$key" | sed 's/\./\\./g')"
  current="$(grep -E "^[[:space:]]*${kre}[[:space:]]*=" "$file" | tail -n 1 | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//')"
  [ "$current" = "$val" ] && return 1
  case " $TOUCHED " in *" $file "*) ;; *) cp -p "$file" "$file.bak-tune"; TOUCHED="$TOUCHED $file" ;; esac
  tmp="$(mktemp)"
  if grep -qE "^[[:space:]]*${kre}[[:space:]]*=" "$file"; then
    sed -E "s|^[[:space:]]*${kre}[[:space:]]*=.*|${key} = ${val}|" "$file" > "$tmp"
  else
    { cat "$file"; printf '%s = %s\n' "$key" "$val"; } > "$tmp"
  fi
  cat "$tmp" > "$file"; rm -f "$tmp"
  return 0
}

found=0
failed=0

for INI in "$PHP_ETC"/*/fpm/php.ini; do
  [ -f "$INI" ] || continue
  found=$((found + 1))
  V="$(basename "$(dirname "$(dirname "$INI")")")"   # …/8.3/fpm/php.ini -> 8.3
  changed=0
  TOUCHED=""

  for kv in $INI_SETTINGS; do
    set_kv "$INI" "${kv%%=*}" "${kv#*=}" && changed=$((changed + 1))
  done
  # WordOps runs two pools per version (www + www-two): tune both.
  for POOL in "$PHP_ETC/$V"/fpm/pool.d/www*.conf; do
    [ -f "$POOL" ] || continue
    for kv in $POOL_SETTINGS; do
      set_kv "$POOL" "${kv%%=*}" "${kv#*=}" && changed=$((changed + 1))
    done
  done

  if [ "$changed" -eq 0 ]; then
    echo "php $V: already tuned"
    continue
  fi

  # Validate BEFORE anything restarts. On failure, put the old files back.
  if command -v "php-fpm$V" >/dev/null 2>&1 && ! "php-fpm$V" -t >/dev/null 2>&1; then
    for f in $TOUCHED; do [ -f "$f.bak-tune" ] && cat "$f.bak-tune" > "$f"; done
    echo "php $V: config test FAILED after tuning — changes rolled back" >&2
    failed=$((failed + 1))
    continue
  fi

  if [ "$RESTART" = 1 ]; then
    if systemctl restart "php$V-fpm" 2>/dev/null; then
      echo "php $V: tuned ($changed setting(s) changed), restarted"
    else
      echo "php $V: tuned ($changed setting(s) changed) but php$V-fpm did not restart" >&2
      failed=$((failed + 1))
    fi
  else
    echo "php $V: tuned ($changed setting(s) changed) — restart pending"
  fi
done

[ "$found" -gt 0 ] || { echo "no PHP-FPM found under $PHP_ETC" >&2; exit 2; }
[ "$failed" -eq 0 ] || exit 1
exit 0
