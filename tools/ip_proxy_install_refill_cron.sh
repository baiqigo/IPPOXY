#!/usr/bin/env bash
set -euo pipefail

ROOT="${IPPOXY_ROOT:-/home/daytona/IPPOXY}"
LOG_DIR="$ROOT/captures"
mkdir -p "$LOG_DIR"

if ! command -v crontab >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y cron
  else
    echo "crontab is missing and apt-get is unavailable" >&2
    exit 1
  fi
fi

if command -v service >/dev/null 2>&1; then
  sudo service cron start || true
fi

FETCH_PROXY="${IP_PROXY_FETCH_PROXY:-socks5h://127.0.0.1:19081}"
GROK_KEY="${GROK_API_KEY:-}"
REFILL_CMD="cd $ROOT && IP_PROXY_FETCH_PROXY=$FETCH_PROXY IP_PROXY_APPLY_RUNTIME=0 IP_PROXY_POOL_MODE=relaxed IP_PROXY_ALLOW_STALE_FALLBACK_CANDIDATES=1 INCLUDE_COOLDOWN_SOURCES=1 MAX_CHECK=240 MAX_SOCKS_PER_SOURCE=200 WORKERS=10 TIMEOUT=12 bash tools/ip_proxy_refill_once.sh >> $LOG_DIR/ip-refill.log 2>&1"
GROK_CMD="cd $ROOT && IP_PROXY_FETCH_PROXY=$FETCH_PROXY IP_PROXY_APPLY_RUNTIME=0 IP_PROXY_POOL_MODE=relaxed IP_PROXY_ALLOW_STALE_FALLBACK_CANDIDATES=1 INCLUDE_COOLDOWN_SOURCES=1 WITH_GROK=1 GROK_API_KEY=$GROK_KEY MAX_CHECK=240 MAX_SOCKS_PER_SOURCE=200 WORKERS=10 TIMEOUT=12 bash tools/ip_proxy_refill_once.sh >> $LOG_DIR/ip-refill-grok.log 2>&1"
VERIFY_CMD="cd $ROOT && python3 tools/ip_proxy_runtime_verify.py >> $LOG_DIR/ip-runtime-verify.log 2>&1"

tmp="$(mktemp)"
crontab -l 2>/dev/null | grep -v 'tools/ip_proxy_refill_once.sh' | grep -v 'tools/ip_proxy_runtime_verify.py' > "$tmp" || true
{
  cat "$tmp"
  echo "*/30 * * * * $REFILL_CMD"
  echo "7 */6 * * * $GROK_CMD"
  echo "*/15 * * * * $VERIFY_CMD"
} | crontab -
rm -f "$tmp"

echo "[cron] installed"
crontab -l | grep -E 'ip_proxy_refill_once|ip_proxy_runtime_verify'
