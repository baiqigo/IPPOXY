#!/usr/bin/env python3
"""Behavior tests for Layer 0 raw proxy promotion into runtime refresh."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, rows: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def test_raw_pool_mode_promotes_checked_http_socks_and_l3_candidates(tmp_path):
    input_path = tmp_path / "runtime/resin/all_candidates_classified.latest.json"
    baseline_path = tmp_path / "baseline.json"
    source_quality_path = tmp_path / "source_quality.json"
    rows = [
        {
            "kind": "http",
            "raw": "http://203.0.113.10:8080",
            "success": True,
            "registration_tier": "dirty_alive_noncn",
            "dirty": ["is_suspicious"],
            "exit_ip": "198.51.100.10",
            "country": "US",
            "company": "Raw HTTP",
            "responseTime": 120,
        },
        {
            "kind": "socks5",
            "raw": "socks5://203.0.113.11:1080",
            "success": True,
            "registration_tier": "risky",
            "dirty": ["is_proxy"],
            "exit_ip": "198.51.100.11",
            "country": "DE",
            "company": "Raw SOCKS",
            "responseTime": 80,
        },
        {
            "kind": "turn",
            "raw": "turn://turn.example.test:3478",
            "success": True,
            "registration_tier": "clean",
            "dirty": [],
            "exit_ip": "198.51.100.12",
            "country": "JP",
            "company": "Raw TURN",
            "responseTime": 50,
        },
        {
            "kind": "http",
            "raw": "http://203.0.113.99:8080",
            "success": True,
            "registration_tier": "dirty",
            "dirty": ["is_abuser"],
            "exit_ip": "198.51.100.99",
            "country": "GB",
            "company": "Hard Dirty",
            "responseTime": 10,
        },
    ]
    write_json(input_path, rows)
    write_json(baseline_path, [])
    write_json(source_quality_path, {"by_source": {}})

    env = {
        **os.environ,
        "IPPOXY_ROOT": str(tmp_path / "root"),
        "IP_PROXY_RUNTIME_DIR": str(tmp_path / "runtime"),
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/ip_proxy_pool_refresh.py"),
            "--input",
            str(input_path),
            "--baseline",
            str(baseline_path),
            "--source-quality",
            str(source_quality_path),
            "--verify",
            str(tmp_path / "missing_verify.json"),
            "--registrar-feedback",
            str(tmp_path / "missing_feedback.json"),
            "--pool-mode",
            "raw",
            "--limit",
            "3",
            "--min-clean",
            "3",
            "--min-new-candidates",
            "3",
            "--max-fallback-candidate-age-hours",
            "0",
            "--allow-selection-quality-failures",
            "--dry-run",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert proc.returncode == 0, proc.stdout
    result = json.loads(proc.stdout)
    assert result["status"] == "ok", result
    assert result["pool_mode"] == "raw", result
    assert result["added_from_candidates"] == 3, result
    assert result["selection_quality"]["tier_counts"] == {
        "clean": 1,
        "dirty_alive_noncn": 1,
        "risky": 1,
    }


def test_raw_non_dry_run_requires_sandbox_live_candidates_by_default(tmp_path):
    input_path = tmp_path / "runtime/resin/all_candidates_classified.latest.json"
    baseline_path = tmp_path / "baseline.json"
    source_quality_path = tmp_path / "source_quality.json"
    rows = [
        {
            "kind": "http",
            "raw": "http://203.0.113.10:8080",
            "success": True,
            "registration_tier": "clean",
            "dirty": [],
            "exit_ip": "198.51.100.10",
            "country": "US",
            "company": "External Checker Only",
            "responseTime": 120,
        }
    ]
    write_json(input_path, rows)
    write_json(baseline_path, [])
    write_json(source_quality_path, {"by_source": {}})

    env = {
        **os.environ,
        "IPPOXY_ROOT": str(tmp_path / "root"),
        "IP_PROXY_RUNTIME_DIR": str(tmp_path / "runtime"),
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/ip_proxy_pool_refresh.py"),
            "--input",
            str(input_path),
            "--baseline",
            str(baseline_path),
            "--source-quality",
            str(source_quality_path),
            "--verify",
            str(tmp_path / "missing_verify.json"),
            "--registrar-feedback",
            str(tmp_path / "missing_feedback.json"),
            "--pool-mode",
            "raw",
            "--limit",
            "1",
            "--min-clean",
            "1",
            "--min-new-candidates",
            "1",
            "--max-fallback-candidate-age-hours",
            "0",
            "--allow-selection-quality-failures",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert proc.returncode == 2, proc.stdout
    result = json.loads(proc.stdout)
    assert result["status"] == "skipped"
    assert result["reason"] == "not_enough_clean_candidates"
    assert result["sandbox_live_filter"] == {
        "require_sandbox_live": True,
        "before_filter": 1,
        "after_filter": 0,
        "excluded_not_sandbox_live": 1,
    }


def test_raw_non_dry_run_accepts_sandbox_live_candidates(tmp_path):
    input_path = tmp_path / "runtime/resin/all_candidates_classified.latest.json"
    baseline_path = tmp_path / "baseline.json"
    source_quality_path = tmp_path / "source_quality.json"
    rows = [
        {
            "kind": "http",
            "raw": "http://203.0.113.10:8080",
            "success": True,
            "registration_tier": "clean",
            "dirty": [],
            "exit_ip": "198.51.100.10",
            "trace_ip": "198.51.100.10",
            "checked_from": "sandbox",
            "country": "US",
            "company": "Sandbox Live",
            "responseTime": 120,
        }
    ]
    write_json(input_path, rows)
    write_json(baseline_path, [])
    write_json(source_quality_path, {"by_source": {}})

    env = {
        **os.environ,
        "IPPOXY_ROOT": str(tmp_path / "root"),
        "IP_PROXY_RUNTIME_DIR": str(tmp_path / "runtime"),
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/ip_proxy_pool_refresh.py"),
            "--input",
            str(input_path),
            "--baseline",
            str(baseline_path),
            "--source-quality",
            str(source_quality_path),
            "--verify",
            str(tmp_path / "missing_verify.json"),
            "--registrar-feedback",
            str(tmp_path / "missing_feedback.json"),
            "--pool-mode",
            "raw",
            "--limit",
            "1",
            "--min-clean",
            "1",
            "--min-new-candidates",
            "1",
            "--max-fallback-candidate-age-hours",
            "0",
            "--allow-selection-quality-failures",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert proc.returncode == 0, proc.stdout
    result = json.loads(proc.stdout)
    assert result["status"] == "ok"
    assert result["sandbox_live_filter"]["after_filter"] == 1


def test_runtime_config_routes_direct_proxy_candidates_without_turn_wrapper():
    from ip_proxy_pool_refresh import normalize_row, xray_config

    rows = [
        normalize_row(
            {
                "kind": "http",
                "raw": "http://user:pass@203.0.113.10:8080",
                "success": True,
                "registration_tier": "dirty_alive_noncn",
                "dirty": ["is_suspicious"],
                "exit_ip": "198.51.100.10",
                "country": "US",
                "raw_pool": True,
            },
            19080,
            "worker.example.test",
            "2523c510-9ff0-415b-9582-93949bfae7e3",
            "raw_latest",
        ),
        normalize_row(
            {
                "kind": "socks5",
                "raw": "socks5://203.0.113.11:1080",
                "success": True,
                "registration_tier": "risky",
                "dirty": ["is_proxy"],
                "exit_ip": "198.51.100.11",
                "country": "DE",
                "raw_pool": True,
            },
            19081,
            "worker.example.test",
            "2523c510-9ff0-415b-9582-93949bfae7e3",
            "raw_latest",
        ),
    ]

    assert [row["kind"] for row in rows] == ["http", "socks5"]
    assert all(row["tag"].startswith("ippoxy-raw-") for row in rows)
    assert all(row["registration_eligible"] is True for row in rows)

    config = xray_config(rows, "2523c510-9ff0-415b-9582-93949bfae7e3", "worker.example.test")
    outbounds = {item["tag"]: item for item in config["outbounds"]}
    http_out = outbounds["out-19080"]
    socks_out = outbounds["out-19081"]

    assert http_out["protocol"] == "http"
    assert http_out["settings"]["servers"] == [
        {
            "address": "203.0.113.10",
            "port": 8080,
            "users": [{"user": "user", "pass": "pass"}],
        }
    ]
    assert "streamSettings" not in http_out

    assert socks_out["protocol"] == "socks"
    assert socks_out["settings"]["servers"] == [
        {"address": "203.0.113.11", "port": 1080}
    ]
    assert "streamSettings" not in socks_out


def test_runtime_config_routes_checked_subscription_candidates():
    from ip_proxy_pool_refresh import normalize_row, xray_config

    rows = [
        normalize_row(
            {
                "kind": "vless",
                "raw": "vless://2523c510-9ff0-415b-9582-93949bfae7e3@vless.example.test:443?type=ws&security=tls&path=/ws&host=vless.example.test&sni=vless.example.test&encryption=none",
                "success": True,
                "registration_tier": "dirty_alive_noncn",
                "dirty": ["is_suspicious"],
                "exit_ip": "198.51.100.21",
                "country": "SG",
                "raw_pool": True,
            },
            19082,
            "worker.example.test",
            "2523c510-9ff0-415b-9582-93949bfae7e3",
            "raw_latest",
        ),
        normalize_row(
            {
                "kind": "trojan",
                "raw": "trojan://secret@trojan.example.test:443?type=tcp&sni=trojan.example.test",
                "success": True,
                "registration_tier": "dirty_alive_noncn",
                "dirty": ["is_suspicious"],
                "exit_ip": "198.51.100.22",
                "country": "NL",
                "raw_pool": True,
            },
            19083,
            "worker.example.test",
            "2523c510-9ff0-415b-9582-93949bfae7e3",
            "raw_latest",
        ),
        normalize_row(
            {
                "kind": "ss",
                "raw": "ss://YWVzLTEyOC1nY206cGFzcw@ss.example.test:8388",
                "success": True,
                "registration_tier": "dirty_alive_noncn",
                "dirty": ["is_suspicious"],
                "exit_ip": "198.51.100.23",
                "country": "US",
                "raw_pool": True,
            },
            19084,
            "worker.example.test",
            "2523c510-9ff0-415b-9582-93949bfae7e3",
            "raw_latest",
        ),
    ]

    config = xray_config(rows, "2523c510-9ff0-415b-9582-93949bfae7e3", "worker.example.test")
    outbounds = {item["tag"]: item for item in config["outbounds"]}

    assert outbounds["out-19082"]["protocol"] == "vless"
    assert outbounds["out-19082"]["settings"]["vnext"][0]["address"] == "vless.example.test"
    assert outbounds["out-19083"]["protocol"] == "trojan"
    assert outbounds["out-19083"]["settings"]["servers"][0]["address"] == "trojan.example.test"
    assert outbounds["out-19084"]["protocol"] == "shadowsocks"
    assert outbounds["out-19084"]["settings"]["servers"][0]["method"] == "aes-128-gcm"


def test_classify_latest_accepts_checked_direct_proxy_runtime_candidates(tmp_path):
    input_path = tmp_path / "runtime/research/proxy_candidate_check_raw.json"
    rows = [
        {
            "kind": "http",
            "raw": "http://203.0.113.10:8080",
            "success": True,
            "clean": True,
            "dirty": [],
            "exit_ip": "198.51.100.10",
            "country": "US",
        },
        {
            "kind": "socks5",
            "raw": "socks5://203.0.113.11:1080",
            "success": True,
            "clean": False,
            "dirty": ["is_proxy"],
            "exit_ip": "198.51.100.11",
            "country": "DE",
        },
        {
            "kind": "http",
            "raw": "http://203.0.113.12:8080",
            "success": True,
            "clean": False,
            "dirty": ["is_suspicious"],
            "exit_ip": "198.51.100.12",
            "country": "JP",
        },
        {
            "kind": "vless",
            "raw": "vless://2523c510-9ff0-415b-9582-93949bfae7e3@vless.example.test:443?type=ws&security=tls&path=/ws&host=vless.example.test&sni=vless.example.test&encryption=none",
            "success": True,
            "clean": False,
            "dirty": ["is_suspicious"],
            "exit_ip": "198.51.100.13",
            "country": "SG",
        },
    ]
    write_json(input_path, rows)

    env = {
        **os.environ,
        "IP_PROXY_RUNTIME_DIR": str(tmp_path / "runtime"),
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/ip_proxy_classify_clean.py"),
            "--run-id",
            "raw_latest",
            "--input",
            str(input_path),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert proc.returncode == 0, proc.stdout
    result = json.loads(proc.stdout)
    assert result["latest_updated"] is True, result
    resin_dir = tmp_path / "runtime/resin"
    assert json.loads((resin_dir / "clean_candidates_classified.latest.json").read_text(encoding="utf-8"))[0]["kind"] == "http"
    assert len(json.loads((resin_dir / "relaxed_candidates_classified.latest.json").read_text(encoding="utf-8"))) == 2
    assert len(json.loads((resin_dir / "all_candidates_classified.latest.json").read_text(encoding="utf-8"))) == 4


def test_refill_once_exposes_raw_pool_mode():
    text = (ROOT / "tools/ip_proxy_refill_once.sh").read_text(encoding="utf-8")
    required = [
        'dirty_alive_noncn',
        'all_candidates_classified.latest.json',
        '"raw"',
        '"$POOL_MODE" != "raw"',
        'runtime_kinds',
    ]
    missing = [item for item in required if item not in text]
    assert not missing, missing


def test_subscription_renderers_keep_direct_proxies_in_resin_only():
    from ip_proxy_pool_refresh import normalize_row
    from ip_proxy_subscription_export import render_clash, render_resin, render_vless

    rows = [
        normalize_row(
            {
                "kind": "http",
                "raw": "http://203.0.113.10:8080",
                "success": True,
                "registration_tier": "dirty_alive_noncn",
                "dirty": ["is_suspicious"],
                "exit_ip": "198.51.100.10",
                "country": "US",
                "raw_pool": True,
            },
            19080,
            "worker.example.test",
            "2523c510-9ff0-415b-9582-93949bfae7e3",
            "raw_latest",
        ),
        normalize_row(
            {
                "kind": "turn",
                "raw": "turn://turn.example.test:3478",
                "success": True,
                "registration_tier": "clean",
                "dirty": [],
                "exit_ip": "198.51.100.12",
                "country": "JP",
                "raw_pool": True,
            },
            19081,
            "worker.example.test",
            "2523c510-9ff0-415b-9582-93949bfae7e3",
            "raw_latest",
        ),
    ]

    resin = render_resin(rows)
    assert "127.0.0.1:19080" in resin
    assert "127.0.0.1:19081" in resin

    vless = render_vless(rows)
    assert "turn.example.test" in vless
    assert "203.0.113.10" not in vless

    clash = render_clash(rows, "worker.example.test", "2523c510-9ff0-415b-9582-93949bfae7e3")
    assert "turn.example.test" in clash
    assert "203.0.113.10" not in clash


def test_resin_platform_payloads_expose_l3_raw_without_polluting_relaxed():
    payloads = json.loads((ROOT / "docs/ip-proxy/resin/platform_payloads.json").read_text(encoding="utf-8"))
    platforms = {item["name"]: item for item in payloads["platforms"]}

    assert "IPPOXY_RAW" in platforms
    assert platforms["IPPOXY_RAW"]["regex_filters"] == ["ippoxy-raw-"]
    assert "ippoxy-raw-" not in "".join(platforms["IPPOXY_RELAXED"]["regex_filters"])
    assert payloads["registrar_proxy_examples"]["raw_bulk"].startswith("socks5h://IPPOXY_RAW.")
