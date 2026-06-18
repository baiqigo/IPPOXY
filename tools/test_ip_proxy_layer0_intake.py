#!/usr/bin/env python3
"""Behavior tests for the Layer 0 intake deep module."""

from __future__ import annotations

import json
import threading
import time
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_intake_routes_registry_sources_to_stable_artifacts(tmp_path):
    from ip_proxy_layer0_intake import run_intake

    http_file = tmp_path / "http.txt"
    http_file.write_text("203.0.113.10:8080\n", encoding="utf-8")
    socks_file = tmp_path / "socks5.txt"
    socks_file.write_text("198.51.100.20:1080\n", encoding="utf-8")
    subscription_file = tmp_path / "sub.txt"
    subscription_file.write_text(
        "vless://fixture@example.com:443?type=ws\n"
        "trojan://secret@example.net:443?security=tls\n",
        encoding="utf-8",
    )

    registry = tmp_path / "layer0_sources.json"
    registry.write_text(
        json.dumps(
            {
                "http_sources": [
                    {
                        "name": "fixture_http",
                        "url": http_file.as_uri(),
                        "kind": "http",
                        "type": "ip_port",
                    }
                ],
                "socks_sources": [
                    {
                        "name": "fixture_socks",
                        "url": socks_file.as_uri(),
                        "kind": "socks5",
                        "type": "ip_port",
                    }
                ],
                "subscription_sources": [
                    {
                        "name": "fixture_subscription",
                        "url": subscription_file.as_uri(),
                        "type": "share_url",
                    }
                ],
                "api_sources": [],
            }
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"
    manifest = run_intake(
        source_registry=registry,
        output_dir=output_dir,
        run_id="tdd",
        dry_run=True,
        timeout=1,
    )

    assert manifest["run_id"] == "tdd"
    assert manifest["dry_run"] is True
    assert manifest["source_registry"] == str(registry)

    http_socks_lane = manifest["lanes"]["http_socks"]
    subscription_lane = manifest["lanes"]["subscription"]
    assert http_socks_lane["raw_count"] == 2
    assert subscription_lane["raw_count"] == 2

    http_socks = json.loads(Path(http_socks_lane["raw_path"]).read_text(encoding="utf-8"))
    subscriptions = json.loads(Path(subscription_lane["raw_path"]).read_text(encoding="utf-8"))
    assert {item["kind"] for item in http_socks} == {"http", "socks5"}
    assert {item["kind"] for item in subscriptions} == {"vless", "trojan"}

    traces = {trace["source_id"]: trace for trace in manifest["sources"]}
    assert traces["fixture_http"]["lane"] == "http_socks"
    assert traces["fixture_socks"]["lane"] == "http_socks"
    assert traces["fixture_subscription"]["lane"] == "subscription"
    assert traces["fixture_http"]["raw_count"] == 1
    assert traces["fixture_subscription"]["raw_count"] == 2

    for item in http_socks + subscriptions:
        assert item["source_id"]
        assert item["source_type"]
        assert item["trace"]["source_id"] == item["source_id"]
        assert item["trace"]["lane"] in {"http_socks", "subscription"}

    manifest_path = Path(manifest["manifest_path"])
    assert manifest_path.name == "layer0_intake_manifest_tdd.json"
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest


def test_intake_records_bad_source_error_evidence(tmp_path):
    from ip_proxy_layer0_intake import run_intake

    good_file = tmp_path / "http.txt"
    good_file.write_text("203.0.113.30:8080\n", encoding="utf-8")
    missing_file = tmp_path / "missing.txt"

    registry = tmp_path / "layer0_sources.json"
    registry.write_text(
        json.dumps(
            {
                "http_sources": [
                    {
                        "name": "fixture_http",
                        "url": good_file.as_uri(),
                        "kind": "http",
                        "type": "ip_port",
                    },
                    {
                        "name": "missing_http",
                        "url": missing_file.as_uri(),
                        "kind": "http",
                        "type": "ip_port",
                    },
                ],
                "socks_sources": [],
                "subscription_sources": [],
                "api_sources": [],
            }
        ),
        encoding="utf-8",
    )

    manifest = run_intake(
        source_registry=registry,
        output_dir=tmp_path / "out",
        run_id="bad-source",
        dry_run=True,
        timeout=1,
    )

    assert manifest["lanes"]["http_socks"]["raw_count"] == 1
    traces = {trace["source_id"]: trace for trace in manifest["sources"]}
    assert traces["fixture_http"]["status"] == "ok"
    assert traces["missing_http"]["status"] == "error"
    assert traces["missing_http"]["raw_count"] == 0
    assert "error" in traces["missing_http"]
    assert manifest["errors"] == [
        {
            "source_id": "missing_http",
            "source_type": "http",
            "lane": "http_socks",
            "url": missing_file.as_uri(),
            "error": traces["missing_http"]["error"],
        }
    ]


def test_intake_dry_run_does_not_update_latest_aliases(tmp_path):
    from ip_proxy_layer0_intake import run_intake

    source_file = tmp_path / "http.txt"
    source_file.write_text("203.0.113.40:8080\n", encoding="utf-8")
    registry = tmp_path / "layer0_sources.json"
    registry.write_text(
        json.dumps(
            {
                "http_sources": [
                    {
                        "name": "fixture_http",
                        "url": source_file.as_uri(),
                        "kind": "http",
                        "type": "ip_port",
                    }
                ],
                "socks_sources": [],
                "subscription_sources": [],
                "api_sources": [],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"

    run_intake(
        source_registry=registry,
        output_dir=output_dir,
        run_id="dry-run",
        dry_run=True,
        timeout=1,
    )

    assert not (output_dir / "layer0_http_socks_pool.latest.json").exists()
    assert not (output_dir / "layer0_subscription_stage0_raw.latest.json").exists()
    assert not (output_dir / "layer0_intake_manifest.latest.json").exists()

    apply_manifest = run_intake(
        source_registry=registry,
        output_dir=output_dir,
        run_id="apply",
        dry_run=False,
        timeout=1,
    )

    assert json.loads((output_dir / "layer0_http_socks_pool.latest.json").read_text(encoding="utf-8"))
    assert json.loads((output_dir / "layer0_subscription_stage0_raw.latest.json").read_text(encoding="utf-8")) == []
    assert json.loads((output_dir / "layer0_intake_manifest.latest.json").read_text(encoding="utf-8")) == apply_manifest


def test_intake_fetches_sources_concurrently(tmp_path):
    from ip_proxy_layer0_intake import run_intake

    registry = tmp_path / "layer0_sources.json"
    registry.write_text(
        json.dumps(
            {
                "http_sources": [
                    {"name": f"http_{idx}", "url": f"memory://http/{idx}", "kind": "http", "type": "ip_port"}
                    for idx in range(4)
                ],
                "socks_sources": [],
                "subscription_sources": [],
                "api_sources": [],
            }
        ),
        encoding="utf-8",
    )

    lock = threading.Lock()
    active = 0
    max_active = 0

    def fetcher(url: str, timeout: int) -> str:
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        port = 8000 + int(url.rsplit("/", 1)[1])
        return f"203.0.113.1:{port}\n"

    manifest = run_intake(
        source_registry=registry,
        output_dir=tmp_path / "out",
        run_id="parallel",
        dry_run=True,
        timeout=1,
        workers=4,
        fetch_text_func=fetcher,
    )

    assert manifest["lanes"]["http_socks"]["raw_count"] == 4
    assert max_active > 1
