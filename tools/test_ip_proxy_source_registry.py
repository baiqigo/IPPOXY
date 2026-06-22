#!/usr/bin/env python3
"""Tests for the IPPOXY Source Registry Module."""

from __future__ import annotations

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_source_registry_merges_fetchable_dynamic_sources_without_duplicates(tmp_path):
    from ip_proxy_source_registry import load_merged_source_registry

    static_url = "https://example.test/static-socks.txt"
    registry = tmp_path / "layer0_sources.json"
    registry.write_text(
        json.dumps(
            {
                "socks_sources": [
                    {
                        "name": "static_socks",
                        "url": static_url,
                        "kind": "socks5",
                        "type": "ip_port",
                    }
                ],
                "candidate_sources": [
                    {
                        "name": "static_turn",
                        "url": "https://example.test/turn.txt",
                        "kind": "turn",
                        "type": "turn_results",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    dynamic = tmp_path / "dynamic_sources.json"
    dynamic.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "url": "https://example.test/new-socks.txt",
                        "source_type": "socks_subscription",
                        "expected_kind": "socks5",
                        "fetchable": True,
                    },
                    {
                        "url": "https://example.test/new-turn.txt",
                        "source_type": "turn_list",
                        "expected_kind": "turn",
                        "fetchable": True,
                    },
                    {
                        "url": static_url,
                        "source_type": "socks_subscription",
                        "expected_kind": "socks5",
                        "fetchable": True,
                    },
                    {
                        "url": "https://example.test/repo",
                        "source_type": "github_repo",
                        "expected_kind": "unknown",
                        "fetchable": False,
                    },
                    {
                        "url": "https://raw.githubusercontent.com/example/proxies/main/mixed.txt",
                        "source_type": "github_raw",
                        "expected_kind": "unknown",
                        "fetchable": True,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    merged = load_merged_source_registry(registry, dynamic_path=dynamic)

    socks_urls = {entry["url"] for entry in merged["socks_sources"]}
    candidate_urls = {entry["url"] for entry in merged["candidate_sources"]}
    http_urls = {entry["url"] for entry in merged["http_sources"]}
    http_raw_entry = next(
        entry for entry in merged["http_sources"] if entry["url"] == "https://raw.githubusercontent.com/example/proxies/main/mixed.txt"
    )
    assert socks_urls == {static_url, "https://example.test/new-socks.txt"}
    assert "https://raw.githubusercontent.com/example/proxies/main/mixed.txt" in http_urls
    assert http_raw_entry["kind"] == "http"
    assert http_raw_entry["type"] == "regex_ip_port"
    assert candidate_urls == {"https://example.test/turn.txt", "https://example.test/new-turn.txt"}


def test_source_registry_preserves_dynamic_source_name_and_format(tmp_path):
    from ip_proxy_source_registry import load_merged_source_registry

    registry = tmp_path / "layer0_sources.json"
    registry.write_text("{}", encoding="utf-8")
    dynamic = tmp_path / "dynamic_sources.json"
    dynamic.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "name": "gfp_space_socks",
                        "url": "https://example.test/socks-space.txt",
                        "source_type": "gfp_socks5",
                        "expected_kind": "socks5",
                        "source_format": "regex_ip_port",
                        "fetchable": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    merged = load_merged_source_registry(registry, dynamic_path=dynamic)

    assert merged["socks_sources"] == [
        {
            "name": "gfp_space_socks",
            "url": "https://example.test/socks-space.txt",
            "origin": "dynamic_sources",
            "dynamic_source_type": "gfp_socks5",
            "kind": "socks5",
            "type": "regex_ip_port",
            "max_bytes": 2000000,
            "max_lines": 50000,
            "max_candidates": 10000,
        }
    ]
