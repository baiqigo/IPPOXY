#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_ID="${RUN_ID:-$(date -u +%Y%m%d_%H%M%S)}"
WORKERS="${WORKERS:-10}"
TIMEOUT="${TIMEOUT:-12}"
MAX_CHECK="${MAX_CHECK:-240}"
MAX_SOCKS_PER_SOURCE="${MAX_SOCKS_PER_SOURCE:-200}"
WITH_GROK="${WITH_GROK:-0}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

mkdir -p docs/ip-proxy/research/runtime docs/ip-proxy/resin

if [[ "$WITH_GROK" == "1" ]]; then
  if [[ -n "${GROK_API_KEY:-${BAIQI_API_KEY:-}}" ]]; then
    "$PYTHON_BIN" tools/ip_grok_source_discovery.py || true
  else
    echo '{"grok":"skipped","reason":"missing GROK_API_KEY or BAIQI_API_KEY"}'
  fi
fi

"$PYTHON_BIN" tools/ip_proxy_candidate_harvest.py \
  --run-id "$RUN_ID" \
  --workers "$WORKERS" \
  --timeout "$TIMEOUT" \
  --max-check "$MAX_CHECK" \
  --max-socks-per-source "$MAX_SOCKS_PER_SOURCE"

"$PYTHON_BIN" tools/ip_proxy_classify_clean.py \
  --run-id "$RUN_ID" \
  --input "docs/ip-proxy/research/runtime/proxy_candidate_check_${RUN_ID}.json"

echo "{\"run_id\":\"$RUN_ID\",\"status\":\"ok\"}"
