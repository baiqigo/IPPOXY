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

mkdir -p .runtime/ip-proxy/research .runtime/ip-proxy/resin

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
  --input ".runtime/ip-proxy/research/proxy_candidate_check_${RUN_ID}.json"

"$PYTHON_BIN" tools/ip_proxy_source_quality_report.py \
  --input ".runtime/ip-proxy/research/proxy_candidate_check_${RUN_ID}.json" || true

"$PYTHON_BIN" tools/ip_proxy_registrar_feedback.py || true

POOL_REFRESH_ARGS=(--input ".runtime/ip-proxy/resin/clean_candidates_classified.latest.json")
if [[ "${IP_PROXY_APPLY_RUNTIME:-1}" != "1" ]]; then
  POOL_REFRESH_ARGS+=(--dry-run)
fi
POOL_REFRESH_JSON="$("$PYTHON_BIN" tools/ip_proxy_pool_refresh.py "${POOL_REFRESH_ARGS[@]}")"
echo "$POOL_REFRESH_JSON"

POOL_CHANGED="$("$PYTHON_BIN" -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("changed") else "0")' "$POOL_REFRESH_JSON")"
if [[ "${IP_PROXY_APPLY_RUNTIME:-1}" == "1" && "$POOL_CHANGED" == "1" ]]; then
  docker compose -f docker-compose.ipproxy.yml run --rm --no-deps xray-turn-pool run -test -config /usr/local/etc/xray/config.json
  docker compose -f docker-compose.ipproxy.yml up -d --force-recreate xray-turn-pool
  "$PYTHON_BIN" tools/ip_proxy_resin_configure.py
fi

echo "{\"run_id\":\"$RUN_ID\",\"status\":\"ok\"}"
