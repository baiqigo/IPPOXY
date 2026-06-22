#!/usr/bin/env python3
"""Tests for importing gfpcom/free-proxy-list source files."""

from __future__ import annotations

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_free_proxy_list_import_splits_direct_and_subscription_sources(tmp_path):
    from ip_proxy_free_proxy_list_import import build_direct_sources, build_subscription_sources

    source_dir = tmp_path / "sources"
    source_dir.mkdir()
    (source_dir / "http.txt").write_text(
        "\n".join(
            [
                "https://example.test/http.txt",
                "https://example.test/already-static.txt",
                "https://example.test/data/{YYYY}/{MM}/proxy.txt",
                "# comment",
            ]
        ),
        encoding="utf-8",
    )
    (source_dir / "socks5.txt").write_text(
        "https://example.test/socks-space.txt,,SpaceURL\n",
        encoding="utf-8",
    )
    (source_dir / "vmess.txt").write_text(
        "https://example.test/vmess.txt,base64,\n",
        encoding="utf-8",
    )

    skip = {"https://example.test/already-static.txt"}
    direct = build_direct_sources(source_dir=source_dir, skip_urls=skip, include_existing=False)
    subscriptions = build_subscription_sources(source_dir=source_dir, skip_urls=skip, include_existing=False)

    assert [row["url"] for row in direct] == [
        "https://example.test/http.txt",
        "https://example.test/socks-space.txt",
    ]
    assert direct[0]["expected_kind"] == "http"
    assert direct[0]["source_format"] == "ip_port"
    assert direct[1]["expected_kind"] == "socks5"
    assert direct[1]["source_format"] == "regex_ip_port"
    assert subscriptions == [
        {
            "name": subscriptions[0]["name"],
            "project": "gfpcom/free-proxy-list",
            "url": "https://example.test/vmess.txt",
            "protocol_hint": "vmess",
        }
    ]


def test_free_proxy_list_import_cli_writes_runtime_inputs(tmp_path, monkeypatch):
    import ip_proxy_free_proxy_list_import as importer

    source_dir = tmp_path / "sources"
    source_dir.mkdir()
    (source_dir / "http.txt").write_text("https://example.test/http.txt\n", encoding="utf-8")
    (source_dir / "ss.txt").write_text("https://example.test/ss.txt\n", encoding="utf-8")
    registry = tmp_path / "layer0_sources.json"
    registry.write_text("{}", encoding="utf-8")
    output_dir = tmp_path / "out"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ip_proxy_free_proxy_list_import.py",
            "--source-dir",
            str(source_dir),
            "--registry",
            str(registry),
            "--output-dir",
            str(output_dir),
            "--source-base-url",
            "",
            "--run-id",
            "test",
        ],
    )

    assert importer.main() == 0
    dynamic = json.loads((output_dir / "free_proxy_list_dynamic_sources_test.json").read_text(encoding="utf-8"))
    subscription = json.loads((output_dir / "free_proxy_list_subscription_sources_test.json").read_text(encoding="utf-8"))
    assert len(dynamic["sources"]) == 1
    assert dynamic["sources"][0]["url"] == "https://example.test/http.txt"
    assert len(subscription) == 1
    assert subscription[0]["url"] == "https://example.test/ss.txt"


def test_free_proxy_list_import_fetches_missing_source_file_from_upstream(tmp_path):
    from ip_proxy_free_proxy_list_import import build_direct_sources

    calls = []

    def fake_fetch(url, timeout):
        calls.append((url, timeout))
        if url.endswith("/http.txt"):
            return "https://example.test/http.txt\n"
        return ""

    direct = build_direct_sources(
        source_dir=tmp_path / "missing",
        skip_urls=set(),
        include_existing=False,
        source_base_url="https://upstream.example/sources",
        fetch_timeout=3,
        fetch_text_func=fake_fetch,
    )

    assert direct[0]["url"] == "https://example.test/http.txt"
    assert direct[0]["expected_kind"] == "http"
    assert ("https://upstream.example/sources/http.txt", 3) in calls
