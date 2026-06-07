#!/usr/bin/env bash
set -euo pipefail

ROOT="${IPPOXY_ROOT:-/home/daytona/IPPOXY}"
LOG_DIR="$ROOT/captures"
mkdir -p "$LOG_DIR"

REFILL_CMD="cd $ROOT && MAX_CHECK=240 MAX_SOCKS_PER_SOURCE=200 WORKERS=10 TIMEOUT=12 bash tools/ip_proxy_refill_once.sh >> $LOG_DIR/ip-refill.log 2>&1"
GROK_CMD="cd $ROOT && WITH_GROK=1 MAX_CHECK=240 MAX_SOCKS_PER_SOURCE=200 WORKERS=10 TIMEOUT=12 bash tools/ip_proxy_refill_once.sh >> $LOG_DIR/ip-refill-grok.log 2>&1"
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
