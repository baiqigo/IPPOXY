#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", "/home/daytona/IPPOXY"))
BASE = os.environ.get("RESIN_BASE_URL", "http://127.0.0.1:2260/api/v1").rstrip("/")
ADMIN_TOKEN = os.environ.get("RESIN_ADMIN_TOKEN", "daytona-admin")
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))


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


def upsert_subscription() -> str:
    content_file = Path(
        os.environ.get(
            "RESIN_SUBSCRIPTION_FILE",
            RUNTIME / "resin/turn_xray_pool_25.local.txt",
        )
    )
    if not content_file.exists():
        content_file = ROOT / "docs/ip-proxy/resin/turn_xray_pool_25.local.txt"
    content = content_file.read_text(encoding="utf-8")
    body = {
        "name": "ippoxy-turn-xray-local",
        "source_type": "local",
        "content": content,
        "update_interval": "5m",
        "enabled": True,
        "ephemeral": True,
        "incremental_alive_nodes": True,
        "ephemeral_node_evict_delay": "30m",
    }
    existing = find_by_name("/subscriptions?limit=200", body["name"])
    retry_without = ("incremental_alive_nodes",)
    if existing:
        sub_id = existing["id"]
        patch_body = {k: v for k, v in body.items() if k != "source_type"}
        request("PATCH", f"/subscriptions/{sub_id}", patch_body, retry_without=retry_without)
    else:
        created = request("POST", "/subscriptions", body, retry_without=retry_without)
        sub_id = created["id"] if isinstance(created, dict) else find_by_name("/subscriptions?limit=200", body["name"])["id"]
    request("POST", f"/subscriptions/{sub_id}/actions/refresh")
    return str(sub_id)


def upsert_platform(payload: dict) -> str:
    body = {
        "name": payload["name"],
        "sticky_ttl": payload["sticky_ttl"],
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
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:2260/healthz", timeout=3).read()
            break
        except OSError:
            time.sleep(1)
    else:
        raise SystemExit("Resin healthz not ready")

    sub_id = upsert_subscription()
    payloads = json.loads((ROOT / "docs/ip-proxy/resin/platform_payloads.json").read_text(encoding="utf-8"))
    platforms = {p["name"]: upsert_platform(p) for p in payloads["platforms"]}
    print(json.dumps({"subscription": sub_id, "platforms": platforms}, ensure_ascii=False))


if __name__ == "__main__":
    main()
