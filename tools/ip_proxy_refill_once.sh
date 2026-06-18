#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_ID="${RUN_ID:-$(date -u +%Y%m%d_%H%M%S)}"
WORKERS="${WORKERS:-10}"
TIMEOUT="${TIMEOUT:-12}"
MAX_CHECK="${MAX_CHECK:-240}"
MAX_CHECK_PER_SOURCE="${MAX_CHECK_PER_SOURCE:-80}"
MAX_CHECK_PER_KIND="${MAX_CHECK_PER_KIND:-0}"
MAX_SOCKS_PER_SOURCE="${MAX_SOCKS_PER_SOURCE:-200}"
ONLY_KIND="${ONLY_KIND:-}"
INCLUDE_COOLDOWN_SOURCES="${INCLUDE_COOLDOWN_SOURCES:-0}"
RELAX_SOURCE_CAP="${RELAX_SOURCE_CAP:-0}"
IP_PROXY_POOL_SIZE_WAS_SET="${IP_PROXY_POOL_SIZE+x}"
IP_PROXY_MIN_CLEAN_WAS_SET="${IP_PROXY_MIN_CLEAN+x}"
IP_PROXY_MIN_NEW_CANDIDATES_WAS_SET="${IP_PROXY_MIN_NEW_CANDIDATES+x}"
IP_PROXY_MAX_RISKY_CANDIDATES_WAS_SET="${IP_PROXY_MAX_RISKY_CANDIDATES+x}"
IP_PROXY_MAX_RISKY_RATIO_WAS_SET="${IP_PROXY_MAX_RISKY_RATIO+x}"
IP_PROXY_MIN_STRICT_CLEAN_SELECTED_WAS_SET="${IP_PROXY_MIN_STRICT_CLEAN_SELECTED+x}"
IP_PROXY_MIN_COUNTRIES_WAS_SET="${IP_PROXY_MIN_COUNTRIES+x}"
IP_PROXY_MAX_COUNTRY_RATIO_WAS_SET="${IP_PROXY_MAX_COUNTRY_RATIO+x}"
IP_PROXY_MAX_COMPANY_RATIO_WAS_SET="${IP_PROXY_MAX_COMPANY_RATIO+x}"
IP_PROXY_MAX_ASN_RATIO_WAS_SET="${IP_PROXY_MAX_ASN_RATIO+x}"
IP_PROXY_POOL_MODE="${IP_PROXY_POOL_MODE:-relaxed}"
IP_PROXY_POOL_SIZE="${IP_PROXY_POOL_SIZE:-25}"
IP_PROXY_MIN_CLEAN="${IP_PROXY_MIN_CLEAN:-12}"
IP_PROXY_MIN_NEW_CANDIDATES="${IP_PROXY_MIN_NEW_CANDIDATES:-8}"
IP_PROXY_EXCLUDE_COUNTRY="${IP_PROXY_EXCLUDE_COUNTRY:-}"
IP_PROXY_MAX_RESPONSE_TIME="${IP_PROXY_MAX_RESPONSE_TIME:-0}"
IP_PROXY_MAX_RISKY_CANDIDATES="${IP_PROXY_MAX_RISKY_CANDIDATES:-10}"
IP_PROXY_MAX_RISKY_RATIO="${IP_PROXY_MAX_RISKY_RATIO:-0.40}"
IP_PROXY_MIN_STRICT_CLEAN_SELECTED="${IP_PROXY_MIN_STRICT_CLEAN_SELECTED:-12}"
IP_PROXY_MIN_COUNTRIES="${IP_PROXY_MIN_COUNTRIES:-8}"
IP_PROXY_MAX_COUNTRY_RATIO="${IP_PROXY_MAX_COUNTRY_RATIO:-0.40}"
IP_PROXY_MAX_COMPANY_RATIO="${IP_PROXY_MAX_COMPANY_RATIO:-0.24}"
IP_PROXY_MAX_ASN_RATIO="${IP_PROXY_MAX_ASN_RATIO:-0.24}"
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

# Layer 0 intake: fetch source registry and emit stable lane artifacts.
WITH_LAYER0_INTAKE="${WITH_LAYER0_INTAKE:-1}"
WITH_LAYER0_CONSUMER="${WITH_LAYER0_CONSUMER:-0}"
WITH_LAYER0_HTTP_SOCKS_CHECK="${WITH_LAYER0_HTTP_SOCKS_CHECK:-1}"
WITH_LAYER0_STAGE0_HEALTHCHECK="${WITH_LAYER0_STAGE0_HEALTHCHECK:-0}"
LAYER0_SOURCE_REGISTRY="${LAYER0_SOURCE_REGISTRY:-tools/layer0_sources.json}"
LAYER0_INTAKE_TIMEOUT="${LAYER0_INTAKE_TIMEOUT:-8}"
LAYER0_INTAKE_WORKERS="${LAYER0_INTAKE_WORKERS:-8}"
LAYER0_HTTP_SOCKS_POOL=".runtime/ip-proxy/research/layer0_http_socks_pool_${RUN_ID}.json"
LAYER0_SUBSCRIPTION_RAW=".runtime/ip-proxy/research/layer0_subscription_stage0_raw_${RUN_ID}.json"
if [[ "$WITH_LAYER0_INTAKE" == "1" ]]; then
  LAYER0_INTAKE_ARGS=(
    --config "$LAYER0_SOURCE_REGISTRY"
    --output-dir ".runtime/ip-proxy/research"
    --run-id "$RUN_ID"
    --timeout "$LAYER0_INTAKE_TIMEOUT"
    --workers "$LAYER0_INTAKE_WORKERS"
  )
  if [[ "${IP_PROXY_APPLY_RUNTIME:-1}" != "1" ]]; then
    LAYER0_INTAKE_ARGS+=(--dry-run)
  fi
  "$PYTHON_BIN" tools/ip_proxy_layer0_intake.py "${LAYER0_INTAKE_ARGS[@]}" || true
elif [[ "$WITH_LAYER0_CONSUMER" == "1" ]]; then
  "$PYTHON_BIN" tools/ip_proxy_layer0_consumer.py --run-id "$RUN_ID" || true
fi

HARVEST_ARGS=(
  --run-id "$RUN_ID" \
  --workers "$WORKERS" \
  --timeout "$TIMEOUT" \
  --max-check "$MAX_CHECK" \
  --max-check-per-source "$MAX_CHECK_PER_SOURCE" \
  --max-check-per-kind "$MAX_CHECK_PER_KIND" \
  --max-socks-per-source "$MAX_SOCKS_PER_SOURCE"
)
if [[ "$WITH_LAYER0_HTTP_SOCKS_CHECK" == "1" && -s "$LAYER0_HTTP_SOCKS_POOL" ]]; then
  HARVEST_ARGS+=(--extra-candidate-pool "$LAYER0_HTTP_SOCKS_POOL")
fi
if [[ "$INCLUDE_COOLDOWN_SOURCES" == "1" ]]; then
  HARVEST_ARGS+=(--include-cooldown-sources)
fi
if [[ "$RELAX_SOURCE_CAP" == "1" ]]; then
  HARVEST_ARGS+=(--relax-source-cap)
fi
if [[ -n "$ONLY_KIND" ]]; then
  IFS=',' read -ra ONLY_KIND_ITEMS <<< "$ONLY_KIND"
  for KIND in "${ONLY_KIND_ITEMS[@]}"; do
    if [[ -n "$KIND" ]]; then
      HARVEST_ARGS+=(--only-kind "$KIND")
    fi
  done
fi

"$PYTHON_BIN" tools/ip_proxy_candidate_harvest.py "${HARVEST_ARGS[@]}"

if [[ "$WITH_LAYER0_STAGE0_HEALTHCHECK" == "1" && -s "$LAYER0_SUBSCRIPTION_RAW" ]]; then
  "$PYTHON_BIN" tools/ip_proxy_stage0_healthcheck.py \
    --run-id "${RUN_ID}_layer0_stage0" \
    --input "$LAYER0_SUBSCRIPTION_RAW" || true
fi

CLASSIFY_JSON="$("$PYTHON_BIN" tools/ip_proxy_classify_clean.py \
  --run-id "$RUN_ID" \
  --input ".runtime/ip-proxy/research/proxy_candidate_check_${RUN_ID}.json")"
echo "$CLASSIFY_JSON"
CLASSIFY_LATEST_UPDATED="$("$PYTHON_BIN" -c 'import json,sys; print("1" if json.loads(sys.argv[1]).get("latest_updated") else "0")' "$CLASSIFY_JSON")"
if [[ "$CLASSIFY_LATEST_UPDATED" != "1" && "${IP_PROXY_APPLY_ON_STALE_CLASSIFY:-0}" != "1" ]]; then
  IP_PROXY_APPLY_RUNTIME="0"
  echo '{"status":"guarded","reason":"classify_latest_not_updated","apply_runtime":false}'
fi

"$PYTHON_BIN" tools/ip_proxy_source_quality_report.py \
  --input ".runtime/ip-proxy/research/proxy_candidate_check_${RUN_ID}.json" || true

"$PYTHON_BIN" tools/ip_proxy_registrar_feedback.py || true

if [[ "$IP_PROXY_POOL_MODE" == "auto" ]]; then
  POOL_MODE="$(IP_PROXY_MIN_CLEAN="$IP_PROXY_MIN_CLEAN" "$PYTHON_BIN" -c 'import json, os; from pathlib import Path
root=Path(".runtime/ip-proxy/resin")
strict=root/"clean_candidates_classified.latest.json"
relaxed=root/"relaxed_candidates_classified.latest.json"
raw=root/"all_candidates_classified.latest.json"
min_clean=int(os.environ.get("IP_PROXY_MIN_CLEAN", "12"))
runtime_kinds={"turn", "http", "https", "socks4", "socks5", "vless", "vmess", "trojan", "ss"}
def runtime_count(path, tiers):
    if not path.exists():
        return 0
    rows=json.loads(path.read_text(encoding="utf-8-sig"))
    return sum(1 for r in rows if isinstance(r, dict) and r.get("kind") in runtime_kinds and r.get("success") and r.get("raw") and r.get("exit_ip") and str(r.get("registration_tier") or "").lower() in tiers)
strict_count=runtime_count(strict, {"clean"})
relaxed_count=runtime_count(relaxed, {"clean","risky"})
raw_count=runtime_count(raw, {"clean","risky","dirty_alive_noncn"})
if strict_count >= min_clean:
    print("strict")
elif relaxed_count >= min_clean:
    print("relaxed")
elif raw_count >= min_clean:
    print("raw")
else:
    print("strict")')"
else
  POOL_MODE="$IP_PROXY_POOL_MODE"
fi
if [[ "$POOL_MODE" != "strict" && "$POOL_MODE" != "relaxed" && "$POOL_MODE" != "raw" ]]; then
  echo "{\"status\":\"error\",\"reason\":\"invalid_IP_PROXY_POOL_MODE\",\"value\":\"$IP_PROXY_POOL_MODE\"}"
  exit 2
fi
if [[ "$POOL_MODE" == "relaxed" || "$POOL_MODE" == "raw" ]]; then
  [[ -z "$IP_PROXY_POOL_SIZE_WAS_SET" ]] && IP_PROXY_POOL_SIZE="80"
  [[ -z "$IP_PROXY_MIN_CLEAN_WAS_SET" ]] && IP_PROXY_MIN_CLEAN="1"
  [[ -z "$IP_PROXY_MIN_NEW_CANDIDATES_WAS_SET" ]] && IP_PROXY_MIN_NEW_CANDIDATES="55"
  [[ -z "$IP_PROXY_MAX_RISKY_CANDIDATES_WAS_SET" ]] && IP_PROXY_MAX_RISKY_CANDIDATES="-1"
  [[ -z "$IP_PROXY_MAX_RISKY_RATIO_WAS_SET" ]] && IP_PROXY_MAX_RISKY_RATIO="0"
  [[ -z "$IP_PROXY_MIN_STRICT_CLEAN_SELECTED_WAS_SET" ]] && IP_PROXY_MIN_STRICT_CLEAN_SELECTED="0"
  [[ -z "$IP_PROXY_MIN_COUNTRIES_WAS_SET" ]] && IP_PROXY_MIN_COUNTRIES="0"
  [[ -z "$IP_PROXY_MAX_COUNTRY_RATIO_WAS_SET" ]] && IP_PROXY_MAX_COUNTRY_RATIO="0"
  [[ -z "$IP_PROXY_MAX_COMPANY_RATIO_WAS_SET" ]] && IP_PROXY_MAX_COMPANY_RATIO="0"
  [[ -z "$IP_PROXY_MAX_ASN_RATIO_WAS_SET" ]] && IP_PROXY_MAX_ASN_RATIO="0"
fi

POOL_REFRESH_INPUT=".runtime/ip-proxy/resin/clean_candidates_classified.latest.json"
if [[ "$POOL_MODE" == "relaxed" ]]; then
  POOL_REFRESH_INPUT=".runtime/ip-proxy/resin/relaxed_candidates_classified.latest.json"
elif [[ "$POOL_MODE" == "raw" ]]; then
  POOL_REFRESH_INPUT=".runtime/ip-proxy/resin/all_candidates_classified.latest.json"
fi
POOL_REFRESH_ARGS=(
  --input "$POOL_REFRESH_INPUT"
  --pool-mode "$POOL_MODE"
  --limit "$IP_PROXY_POOL_SIZE"
  --min-clean "$IP_PROXY_MIN_CLEAN"
  --min-new-candidates "$IP_PROXY_MIN_NEW_CANDIDATES"
  --exclude-country "$IP_PROXY_EXCLUDE_COUNTRY"
  --max-response-time "$IP_PROXY_MAX_RESPONSE_TIME"
  --max-risky-candidates "$IP_PROXY_MAX_RISKY_CANDIDATES"
  --max-risky-ratio "$IP_PROXY_MAX_RISKY_RATIO"
  --min-strict-clean-selected "$IP_PROXY_MIN_STRICT_CLEAN_SELECTED"
  --min-countries "$IP_PROXY_MIN_COUNTRIES"
  --max-country-ratio "$IP_PROXY_MAX_COUNTRY_RATIO"
  --max-company-ratio "$IP_PROXY_MAX_COMPANY_RATIO"
  --max-asn-ratio "$IP_PROXY_MAX_ASN_RATIO"
)
if [[ "${IP_PROXY_ALLOW_SELECTION_QUALITY_FAILURES:-0}" == "1" ]]; then
  POOL_REFRESH_ARGS+=(--allow-selection-quality-failures)
fi
if [[ "${IP_PROXY_ALLOW_STALE_FALLBACK_CANDIDATES:-0}" == "1" ]]; then
  POOL_REFRESH_ARGS+=(--allow-stale-fallback-candidates)
fi
if [[ -n "${IP_PROXY_TURN_WORKER_HOST:-}" ]]; then
  POOL_REFRESH_ARGS+=(--worker-host "$IP_PROXY_TURN_WORKER_HOST")
fi
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

echo "{\"run_id\":\"$RUN_ID\",\"status\":\"ok\",\"pool_mode\":\"$POOL_MODE\"}"
