#!/usr/bin/env python3
"""Tests for IPPOXY Grok IP pool source discovery wrapper."""

from __future__ import annotations

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_grok_ip_pool_search_dedupes_full_urls_not_root_domain(tmp_path):
    from ip_proxy_grok_ip_pool_search import run_search

    def search(query: str, model: str, timeout: int) -> list[str]:
        assert model == "fast"
        return [
            "https://raw.githubusercontent.com/owner/a/main/http.txt",
            "https://raw.githubusercontent.com/owner/b/main/socks5.txt",
            "https://raw.githubusercontent.com/owner/a/main/http.txt",
        ]

    result = run_search(
        queries=["free proxy raw"],
        model_sequence=["fast"],
        search_func=search,
        timeout=1,
        target_urls=10,
        concurrency=1,
    )

    assert result["dedupe"] == "full_url"
    assert result["url_count"] == 2
    assert [item["url"] for item in result["urls"]] == [
        "https://raw.githubusercontent.com/owner/a/main/http.txt",
        "https://raw.githubusercontent.com/owner/b/main/socks5.txt",
    ]
    dynamic_urls = {item["url"] for item in result["dynamic_sources"]}
    assert "https://raw.githubusercontent.com/owner/a/main/http.txt" in dynamic_urls
    assert "https://raw.githubusercontent.com/owner/b/main/socks5.txt" in dynamic_urls


def test_grok_ip_pool_search_writes_dynamic_sources_only_when_not_dry_run(tmp_path):
    from ip_proxy_grok_ip_pool_search import run_search, write_outputs

    result = run_search(
        queries=["turn proxy"],
        model_sequence=["fast"],
        search_func=lambda _query, _model, _timeout: ["https://raw.githubusercontent.com/neworg/CF-Workers-TURN/main/turn_results.txt"],
        timeout=1,
        target_urls=10,
        concurrency=1,
    )
    dynamic_path = tmp_path / "dynamic_sources.json"

    dry_summary = write_outputs(
        result=result,
        output_dir=tmp_path / "out",
        run_id="dry",
        dry_run=True,
        dynamic_sources_path=dynamic_path,
    )
    assert dry_summary["url_count"] == 1
    assert not dynamic_path.exists()

    write_outputs(
        result=result,
        output_dir=tmp_path / "out",
        run_id="apply",
        dry_run=False,
        dynamic_sources_path=dynamic_path,
    )
    payload = json.loads(dynamic_path.read_text(encoding="utf-8"))
    assert payload["source"] == "ip_proxy_grok_ip_pool_search"
    assert len(payload["sources"]) == 1


def test_grok_ip_pool_search_can_run_queries_concurrently():
    from ip_proxy_grok_ip_pool_search import run_search

    seen_queries: list[str] = []

    def search(query: str, model: str, timeout: int) -> list[str]:
        seen_queries.append(query)
        return [f"https://raw.githubusercontent.com/org/{query}/main/http.txt"]

    result = run_search(
        queries=["one", "two", "three"],
        model_sequence=["fast"],
        search_func=search,
        timeout=1,
        target_urls=10,
        concurrency=3,
    )

    assert result["concurrency"] == 3
    assert result["url_count"] == 3
    assert {item["query"] for item in result["urls"]} == {"one", "two", "three"}
    assert set(seen_queries) == {"one", "two", "three"}


def test_grok_ip_pool_search_normalizes_prefixed_newapi_key():
    from ip_proxy_grok_ip_pool_search import normalize_api_key

    assert normalize_api_key("UNsk-abc123") == "sk-abc123"
    assert normalize_api_key("sk-abc123") == "sk-abc123"


def test_grok_ip_pool_search_records_system_exit_and_falls_back():
    from ip_proxy_grok_ip_pool_search import run_search

    def search(query: str, model: str, timeout: int) -> list[str]:
        if model == "first":
            raise SystemExit("temporary upstream disconnect")
        return ["https://raw.githubusercontent.com/org/fallback/main/http.txt"]

    result = run_search(
        queries=["free proxy raw"],
        model_sequence=["first", "fallback"],
        search_func=search,
        timeout=1,
        target_urls=10,
        concurrency=1,
    )

    assert result["url_count"] == 1
    assert result["runs"][0]["status"] == "ok"
    assert result["runs"][0]["attempts"][0]["status"] == "error"
    assert result["runs"][0]["attempts"][1]["status"] == "ok"


def test_grok_ip_pool_classifies_raw_protocol_sources_without_repo_expansion():
    from ip_grok_source_discovery import classify_urls

    sources = classify_urls(
        [
            "https://raw.githubusercontent.com/org/proxies/main/http.txt",
            "https://raw.githubusercontent.com/org/proxies/main/socks5.txt",
            "https://github.com/org/proxies",
            "https://github.com/org/socks5_list",
        ]
    )

    by_url = {item["url"]: item for item in sources}
    assert by_url["https://raw.githubusercontent.com/org/proxies/main/http.txt"]["expected_kind"] == "http"
    assert by_url["https://raw.githubusercontent.com/org/proxies/main/http.txt"]["fetchable"] is True
    assert by_url["https://raw.githubusercontent.com/org/proxies/main/socks5.txt"]["expected_kind"] == "socks5"
    assert by_url["https://github.com/org/proxies"]["source_type"] == "github_repo"
    assert by_url["https://github.com/org/proxies"]["fetchable"] is False
    assert by_url["https://github.com/org/socks5_list"]["source_type"] == "github_repo"
    assert by_url["https://github.com/org/socks5_list"]["fetchable"] is False
    assert not any(item.get("expanded_from") == "https://github.com/org/proxies" for item in sources)
