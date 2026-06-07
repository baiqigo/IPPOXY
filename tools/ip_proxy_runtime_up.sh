#!/usr/bin/env bash
set -euo pipefail

ROOT="${IPPOXY_ROOT:-/home/daytona/IPPOXY}"
XRAY_BIN="${XRAY_BIN:-/home/daytona/ip-proxy-poc/bin/xray}"
RUNTIME="${IP_PROXY_RUNTIME_DIR:-$ROOT/.runtime/ip-proxy}"
LOG_DIR="${RUNTIME}/logs"
CONF_DIR="${RUNTIME}/conf"
XRAY_CONF="${CONF_DIR}/xray_turn_pool_25.generated.json"
XRAY_LOG="${LOG_DIR}/xray-turn-pool-25.log"
XRAY_PID="${RUNTIME}/xray-turn-pool-25.pid"

mkdir -p "$LOG_DIR" "$CONF_DIR" "$ROOT/.runtime/resin/cache" "$ROOT/.runtime/resin/state" "$ROOT/.runtime/resin/log"
cp "$ROOT/docs/ip-proxy/resin/xray_turn_pool_25.generated.json" "$XRAY_CONF"

if [ ! -x "$XRAY_BIN" ]; then
  echo "missing executable xray: $XRAY_BIN" >&2
  exit 1
fi

stop_pid_file() {
  if [ -f "$XRAY_PID" ]; then
    pid="$(cat "$XRAY_PID" 2>/dev/null || true)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" || true
      sleep 1
    fi
    rm -f "$XRAY_PID"
  fi
}

stop_port_owner() {
  local port="$1"
  local pids
  pids="$(ss -ltnp 2>/dev/null | awk -v port=":${port}" '$0 ~ port { if (match($0, /pid=[0-9]+/)) { print substr($0, RSTART + 4, RLENGTH - 4) } }' | sort -u)"
  if [ -n "$pids" ]; then
    for pid in $pids; do
      kill "$pid" 2>/dev/null || true
    done
  fi
}

wait_port_free() {
  local port="$1"
  for _ in $(seq 1 20); do
    if ! ss -ltnp 2>/dev/null | grep -q ":${port} "; then
      return 0
    fi
    sleep 0.25
  done
  echo "port still busy: $port" >&2
  ss -ltnp | grep ":${port} " >&2 || true
  return 1
}

stop_pid_file
if [ -x /home/daytona/ip-proxy-poc/rotate/stop_turn_pool.sh ]; then
  bash /home/daytona/ip-proxy-poc/rotate/stop_turn_pool.sh || true
fi
for port in $(seq 19080 19104); do
  stop_port_owner "$port"
done
sleep 1
for port in $(seq 19080 19104); do
  wait_port_free "$port"
done

"$XRAY_BIN" run -test -config "$XRAY_CONF"
nohup "$XRAY_BIN" run -config "$XRAY_CONF" > "$XRAY_LOG" 2>&1 &
echo "$!" > "$XRAY_PID"

for port in 19080 19104; do
  for _ in $(seq 1 40); do
    if ss -ltnp | grep -q ":${port} "; then
      break
    fi
    sleep 0.25
  done
  ss -ltnp | grep ":${port} " >/dev/null
done

cd "$ROOT"
docker compose -f docker-compose.ipproxy.yml pull resin
docker compose -f docker-compose.ipproxy.yml up -d resin

for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:2260/healthz >/dev/null; then
    echo "runtime=ok xray_pid=$(cat "$XRAY_PID") resin=healthy"
    exit 0
  fi
  sleep 1
done

docker logs ippoxy-resin --tail 80 >&2 || true
exit 1
