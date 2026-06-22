#!/usr/bin/env python3
"""Tests for the registrar-oriented thin live proxy filter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_thin_filter_keeps_only_live_fresh_non_feedback_rows():
    from ip_proxy_thin_live_filter import thin_filter_rows

    now = 1_700_000_000.0
    rows = [
        {
            "kind": "http",
            "raw": "http://203.0.113.1:8080",
            "success": True,
            "sandbox_live": True,
            "exit_ip": "198.51.100.1",
            "checked_at": now - 10,
            "sandbox_response_ms": 30,
        },
        {
            "kind": "socks5",
            "raw": "socks5://203.0.113.2:1080",
            "success": True,
            "sandbox_live": True,
            "exit_ip": "198.51.100.2",
            "checked_at": now - 10,
        },
        {
            "kind": "http",
            "raw": "http://203.0.113.3:8080",
            "success": True,
            "sandbox_live": True,
            "exit_ip": "198.51.100.3",
            "checked_at": now - 999,
        },
        {
            "kind": "http",
            "raw": "http://203.0.113.4:8080",
            "success": False,
            "sandbox_live": False,
            "exit_ip": "198.51.100.4",
            "checked_at": now - 10,
        },
        {
            "kind": "http",
            "raw": "http://203.0.113.5:8080",
            "success": True,
            "sandbox_live": True,
            "exit_ip": "198.51.100.1",
            "checked_at": now - 10,
        },
    ]

    kept, summary = thin_filter_rows(
        rows,
        bad_exit_ips={"198.51.100.2"},
        ttl_seconds=120,
        now=now,
    )

    assert [row["raw"] for row in kept] == ["http://203.0.113.1:8080"]
    assert kept[0]["registration_tier"] == "dirty_alive_noncn"
    assert kept[0]["raw_pool"] is True
    assert summary["kept"] == 1
    assert summary["bad_feedback"] == 1
    assert summary["expired"] == 1
    assert summary["not_live"] == 1
    assert summary["duplicate"] == 1


def test_thin_filter_cli_writes_output_and_latest(tmp_path):
    input_path = tmp_path / "live.json"
    output_path = tmp_path / "out.json"
    runtime_dir = tmp_path / "runtime"
    feedback_path = tmp_path / "feedback.json"
    input_path.write_text(
        json.dumps(
            [
                {
                    "kind": "http",
                    "raw": "http://203.0.113.1:8080",
                    "success": True,
                    "sandbox_live": True,
                    "exit_ip": "198.51.100.1",
                    "checked_at": 1_700_000_000,
                },
                {
                    "kind": "http",
                    "raw": "http://203.0.113.2:8080",
                    "success": True,
                    "sandbox_live": True,
                    "exit_ip": "198.51.100.2",
                    "checked_at": 1_700_000_000,
                },
            ]
        ),
        encoding="utf-8",
    )
    feedback_path.write_text(json.dumps({"bad_exit_ips": ["198.51.100.2"]}), encoding="utf-8")
    env = {**os.environ, "IP_PROXY_RUNTIME_DIR": str(runtime_dir)}

    proc = subprocess.run(
        [
            sys.executable,
            "tools/ip_proxy_thin_live_filter.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--feedback",
            str(feedback_path),
            "--ttl-seconds",
            "0",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["status"] == "thin_live_filter"
    assert result["kept"] == 1
    assert json.loads(output_path.read_text(encoding="utf-8"))[0]["exit_ip"] == "198.51.100.1"
    latest = runtime_dir / "research/proxy_candidate_thin_live.latest.json"
    assert json.loads(latest.read_text(encoding="utf-8"))[0]["raw"] == "http://203.0.113.1:8080"
