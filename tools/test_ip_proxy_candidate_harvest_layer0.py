#!/usr/bin/env python3
"""Behavior tests for candidate_harvest consuming Layer 0 intake artifacts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_candidate_harvest_can_use_layer0_extra_candidate_pool(tmp_path):
    layer0_pool = tmp_path / "layer0_http_socks_pool.json"
    layer0_pool.write_text(
        json.dumps(
            [
                {"kind": "http", "raw": "http://203.0.113.10:8080", "source": "fixture_http"},
                {"kind": "socks5", "raw": "socks5://198.51.100.20:1080", "source": "fixture_socks"},
            ]
        ),
        encoding="utf-8",
    )
    runtime_dir = tmp_path / "runtime"
    env = {
        **os.environ,
        "IP_PROXY_RUNTIME_DIR": str(runtime_dir),
    }

    result = subprocess.run(
        [
            sys.executable,
            "tools/ip_proxy_candidate_harvest.py",
            "--run-id",
            "layer0-extra",
            "--skip-default-sources",
            "--extra-candidate-pool",
            str(layer0_pool),
            "--harvest-only",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["candidates"] == 2
    assert summary["by_kind"] == {"http": 1, "socks5": 1}

    written_pool = json.loads(
        (runtime_dir / "research" / "proxy_candidate_pool_layer0-extra.json").read_text(encoding="utf-8")
    )
    assert written_pool == [
        {"kind": "http", "raw": "http://203.0.113.10:8080", "source": "fixture_http", "port": 8080},
        {"kind": "socks5", "raw": "socks5://198.51.100.20:1080", "source": "fixture_socks", "port": 1080},
    ]


def test_candidate_harvest_reads_default_candidates_from_source_registry(tmp_path):
    source_file = tmp_path / "socks.txt"
    source_file.write_text("198.51.100.30:1080\nsocks5://198.51.100.31:1081\n", encoding="utf-8")
    registry = tmp_path / "layer0_sources.json"
    registry.write_text(
        json.dumps(
            {
                "http_sources": [],
                "socks_sources": [],
                "subscription_sources": [],
                "api_sources": [],
                "candidate_sources": [
                    {
                        "name": "fixture_candidate_socks",
                        "url": source_file.as_uri(),
                        "kind": "socks5",
                        "type": "socks5_lines",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    runtime_dir = tmp_path / "runtime"
    env = {
        **os.environ,
        "IP_PROXY_RUNTIME_DIR": str(runtime_dir),
    }

    result = subprocess.run(
        [
            sys.executable,
            "tools/ip_proxy_candidate_harvest.py",
            "--run-id",
            "registry-default",
            "--source-registry",
            str(registry),
            "--no-dynamic-sources",
            "--harvest-only",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["candidates"] == 2
    assert summary["by_kind"] == {"socks5": 2}
    written_pool = json.loads(
        (runtime_dir / "research" / "proxy_candidate_pool_registry-default.json").read_text(encoding="utf-8")
    )
    assert written_pool == [
        {
            "kind": "socks5",
            "raw": "socks5://198.51.100.30:1080",
            "source": "fixture_candidate_socks",
            "port": 1080,
        },
        {
            "kind": "socks5",
            "raw": "socks5://198.51.100.31:1081",
            "source": "fixture_candidate_socks",
            "port": 1081,
        },
    ]
