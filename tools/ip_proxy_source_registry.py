#!/usr/bin/env python3
"""Source Registry Module for IPPOXY Layer0 and candidate harvest.

The registry is the single interface for curated source URLs plus discovered
dynamic URLs. Callers should not keep their own URL tables.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
DEFAULT_SOURCE_REGISTRY = ROOT / "tools" / "layer0_sources.json"
DEFAULT_DYNAMIC_SOURCES = IP_RUNTIME_DIR / "research" / "dynamic_sources.json"

SOURCE_GROUP_DEFAULTS = {
    "http_sources": {"default_kind": "http", "source_type": "http"},
    "socks_sources": {"default_kind": "socks5", "source_type": "socks"},
    "subscription_sources": {"default_kind": None, "source_type": "subscription"},
    "api_sources": {"default_kind": "http", "source_type": "api"},
    "candidate_sources": {"default_kind": None, "source_type": "candidate"},
}


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_source_registry(path: Path | None = None) -> dict:
    registry_path = path or DEFAULT_SOURCE_REGISTRY
    data = read_json(registry_path, {})
    if not isinstance(data, dict):
        return {}
    return {group: list(data.get(group) or []) for group in SOURCE_GROUP_DEFAULTS}


def source_urls(registry: dict) -> set[str]:
    urls: set[str] = set()
    for group in SOURCE_GROUP_DEFAULTS:
        for entry in registry.get(group, []) or []:
            url = str(entry.get("url") or "").strip()
            if url:
                urls.add(url)
            urls.update(str(item).strip() for item in entry.get("urls", []) or [] if str(item).strip())
    return urls


def _dynamic_name(entry: dict) -> str:
    explicit_name = str(entry.get("name") or "").strip()
    if explicit_name:
        return explicit_name
    source_type = str(entry.get("source_type") or "unknown").replace(" ", "_")
    expected_kind = str(entry.get("expected_kind") or "unknown").replace(" ", "_")
    url_hash = hashlib.sha1(str(entry.get("url") or "").encode("utf-8")).hexdigest()[:10]
    return f"grok_dynamic_{source_type}_{expected_kind}_{url_hash}"


def _with_dynamic_limits(group: str, entry: dict) -> dict:
    limits_by_group = {
        "http_sources": {"max_bytes": 2_000_000, "max_lines": 50_000, "max_candidates": 10_000},
        "socks_sources": {"max_bytes": 2_000_000, "max_lines": 50_000, "max_candidates": 10_000},
        "subscription_sources": {"max_bytes": 3_000_000, "max_lines": 50_000, "max_candidates": 10_000},
        "candidate_sources": {"max_bytes": 1_000_000, "max_lines": 20_000, "max_candidates": 5_000},
    }
    out = dict(entry)
    for key, value in limits_by_group.get(group, {}).items():
        out.setdefault(key, value)
    return out


def _dynamic_to_registry_entry(entry: dict) -> tuple[str, dict] | None:
    if not entry.get("fetchable"):
        return None
    url = str(entry.get("url") or "").strip()
    if not url:
        return None

    expected_kind = str(entry.get("expected_kind") or "unknown").lower()
    source_type = str(entry.get("source_type") or "dynamic")
    base = {
        "name": _dynamic_name(entry),
        "url": url,
        "origin": "dynamic_sources",
        "dynamic_source_type": source_type,
    }

    if expected_kind in {"http", "https"}:
        group = "http_sources"
        source_format = str(entry.get("source_format") or "ip_port")
        return group, _with_dynamic_limits(group, {**base, "kind": expected_kind, "type": source_format})
    if expected_kind in {"socks4", "socks5"}:
        group = "socks_sources"
        source_format = str(entry.get("source_format") or "ip_port")
        return group, _with_dynamic_limits(group, {**base, "kind": expected_kind, "type": source_format})
    if expected_kind == "subscription":
        group = "subscription_sources"
        return group, _with_dynamic_limits(group, {**base, "type": "share_url"})
    if expected_kind in {"turn", "sstp"}:
        group = "candidate_sources"
        return group, _with_dynamic_limits(group, {**base, "kind": expected_kind, "type": f"{expected_kind}_generic"})
    if source_type == "socks_subscription":
        group = "socks_sources"
        return group, _with_dynamic_limits(group, {**base, "kind": "socks5", "type": "ip_port"})
    if source_type in {"github_raw", "gist_raw"}:
        group = "http_sources"
        return group, _with_dynamic_limits(group, {**base, "kind": "http", "type": "regex_ip_port"})
    return None


def load_dynamic_registry_entries(dynamic_path: Path | None = None, *, skip_urls: set[str] | None = None) -> dict:
    path = dynamic_path or DEFAULT_DYNAMIC_SOURCES
    data = read_json(path, {})
    if not isinstance(data, dict):
        return {group: [] for group in SOURCE_GROUP_DEFAULTS}

    skip = skip_urls or set()
    merged = {group: [] for group in SOURCE_GROUP_DEFAULTS}
    seen: set[str] = set(skip)
    for entry in data.get("sources") or []:
        if not isinstance(entry, dict):
            continue
        converted = _dynamic_to_registry_entry(entry)
        if not converted:
            continue
        group, source_entry = converted
        url = str(source_entry.get("url") or "")
        if url in seen:
            continue
        seen.add(url)
        merged[group].append(source_entry)
    return merged


def load_merged_source_registry(
    path: Path | None = None,
    *,
    dynamic_path: Path | None = None,
    include_dynamic: bool = True,
) -> dict:
    registry = load_source_registry(path)
    if not include_dynamic:
        return registry
    dynamic = load_dynamic_registry_entries(dynamic_path, skip_urls=source_urls(registry))
    for group, entries in dynamic.items():
        registry.setdefault(group, []).extend(entries)
    return registry


def candidate_source_entries(
    path: Path | None = None,
    *,
    dynamic_path: Path | None = None,
    include_dynamic: bool = True,
) -> list[dict]:
    registry = load_merged_source_registry(path, dynamic_path=dynamic_path, include_dynamic=include_dynamic)
    return [dict(entry) for entry in registry.get("candidate_sources", [])]
