#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import argparse
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", "/home/daytona/IPPOXY"))
BASE = os.environ.get("RESIN_BASE_URL", "http://127.0.0.1:2260/api/v1").rstrip("/")
ADMIN_TOKEN = os.environ.get("RESIN_ADMIN_TOKEN", "daytona-admin")
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
DEFAULT_EPHEMERAL_NODE_EVICT_DELAY = "30m"
ZERO_DURATION_VALUES = {"0", "0s", "0m", "0h", "0ms", "0us", "0ns"}


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_ephemeral_node_evict_delay() -> str:
    value = os.environ.get("RESIN_EPHEMERAL_NODE_EVICT_DELAY", DEFAULT_EPHEMERAL_NODE_EVICT_DELAY).strip()
    if not value:
        value = DEFAULT_EPHEMERAL_NODE_EVICT_DELAY
    if value.lower() in ZERO_DURATION_VALUES and not env_bool("RESIN_ALLOW_ZERO_EVICT_DELAY", False):
        raise RuntimeError(
            "RESIN_EPHEMERAL_NODE_EVICT_DELAY=0 is unsafe for the local Xray runtime pool; "
            "use a positive delay such as 30m, or set RESIN_ALLOW_ZERO_EVICT_DELAY=1 to override."
        )
    return value


def request(method: str, path: str, body: dict | None = None, retry_without: tuple[str, ...] = ()) -> object:
    data = None if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}", "Content-Type": "application/json"}
    req = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            return json.loads(raw.decode() or "{}") if raw else {}
    except urllib.error.HTTPError as exc:
        if retry_without and body is not None and exc.code == 400:
            reduced = {k: v for k, v in body.items() if k not in retry_without}
            return request(method, path, reduced)
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"{method} {path} failed: {exc.code} {detail}") from exc


def items(value: object) -> list[dict]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        for key in ("items", "data", "results"):
            if isinstance(value.get(key), list):
                return [x for x in value[key] if isinstance(x, dict)]
    return []


def find_by_name(path: str, name: str) -> dict | None:
    for item in items(request("GET", path)):
        if item.get("name") == name:
            return item
    return None


def upsert_subscription(*, force_replace: bool = False) -> str:
    content_file = Path(
        os.environ.get(
            "RESIN_SUBSCRIPTION_FILE",
            RUNTIME / "resin/turn_xray_pool_25.local.txt",
        )
    )
    if not content_file.exists():
        content_file = ROOT / "docs/ip-proxy/resin/turn_xray_pool_25.local.txt"
    content = content_file.read_text(encoding="utf-8")
    incremental_alive_nodes = not force_replace and env_bool("RESIN_INCREMENTAL_ALIVE_NODES", True)
    evict_delay = resolve_ephemeral_node_evict_delay()
    body = {
        "name": "ippoxy-turn-xray-local",
        "source_type": "local",
        "content": content,
        "update_interval": "5m",
        "enabled": True,
        "ephemeral": True,
        "incremental_alive_nodes": incremental_alive_nodes,
        "ephemeral_node_evict_delay": evict_delay,
    }
    existing = find_by_name("/subscriptions?limit=200", body["name"])
    retry_without = ("incremental_alive_nodes",)
    if existing:
        sub_id = existing["id"]
        if force_replace:
            request("DELETE", f"/subscriptions/{sub_id}")
            created = request("POST", "/subscriptions", body, retry_without=retry_without)
            sub_id = created["id"] if isinstance(created, dict) else find_by_name("/subscriptions?limit=200", body["name"])["id"]
        else:
            patch_body = {k: v for k, v in body.items() if k != "source_type"}
            request("PATCH", f"/subscriptions/{sub_id}", patch_body, retry_without=retry_without)
    else:
        created = request("POST", "/subscriptions", body, retry_without=retry_without)
        sub_id = created["id"] if isinstance(created, dict) else find_by_name("/subscriptions?limit=200", body["name"])["id"]
    request("POST", f"/subscriptions/{sub_id}/actions/refresh")
    return str(sub_id)


def upsert_platform(payload: dict, *, force_replace: bool = False) -> str:
    sticky_ttl = os.environ.get(f"RESIN_{payload['name']}_STICKY_TTL", "")
    if not sticky_ttl and force_replace:
        sticky_ttl = os.environ.get("RESIN_FORCE_REPLACE_STICKY_TTL", "5m")
    body = {
        "name": payload["name"],
        "sticky_ttl": sticky_ttl or payload["sticky_ttl"],
        "regex_filters": payload["regex_filters"],
        "region_filters": payload.get("region_filters", []),
        "reverse_proxy_miss_action": payload["reverse_proxy_miss_action"],
        "allocation_policy": payload["allocation_policy"],
        "passive_circuit_breaker_disabled": payload["passive_circuit_breaker_disabled"],
    }
    existing = find_by_name("/platforms?limit=200", body["name"])
    if existing:
        platform_id = existing["id"]
        request("PATCH", f"/platforms/{platform_id}", body)
    else:
        created = request("POST", "/platforms", body)
        platform_id = created["id"] if isinstance(created, dict) else find_by_name("/platforms?limit=200", body["name"])["id"]
    try:
        request("POST", f"/platforms/{platform_id}/actions/rebuild-routable-view")
    except RuntimeError:
        pass
    return str(platform_id)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force-replace",
        action="store_true",
        default=env_bool("RESIN_FORCE_REPLACE", False),
        help="Disable incremental alive-node preservation and shorten sticky state for repair refreshes.",
    )
    args = parser.parse_args()

    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:2260/healthz", timeout=3).read()
            break
        except OSError:
            time.sleep(1)
    else:
        raise SystemExit("Resin healthz not ready")

    sub_id = upsert_subscription(force_replace=args.force_replace)
    payloads = json.loads((ROOT / "docs/ip-proxy/resin/platform_payloads.json").read_text(encoding="utf-8"))
    platforms = {p["name"]: upsert_platform(p, force_replace=args.force_replace) for p in payloads["platforms"]}
    print(
        json.dumps(
            {
                "subscription": sub_id,
                "platforms": platforms,
                "force_replace": args.force_replace,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
