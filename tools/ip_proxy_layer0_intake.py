#!/usr/bin/env python3
"""Layer 0 intake deep module.

This module gives callers one stable entrypoint for source-registry intake:
read configured Layer 0 sources, route raw candidates to the correct check lane,
and emit a manifest with source trace for later healthcheck/classify stages.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import time
from pathlib import Path
from typing import Callable

from ip_proxy_layer0_consumer import (
    DEFAULT_SOURCES_CONFIG,
    decode_base64_content,
    fetch_text,
    parse_line,
)
from ip_proxy_source_registry import load_dynamic_registry_entries, load_merged_source_registry


HTTP_SOCKS_KINDS = {"http", "https", "socks4", "socks5"}
IP_PORT_SCAN_RE = re.compile(
    r"(?:(http|https|socks4|socks5)://)?"
    r"(?<!\d)((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)",
    re.IGNORECASE,
)
SOURCE_GROUPS = (
    ("http_sources", "http", "http"),
    ("socks_sources", "socks5", "socks"),
    ("subscription_sources", None, "subscription"),
    ("api_sources", "http", "api"),
)
FetchTextFunc = Callable[[str, int], str]


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _source_lane(source_type: str) -> str:
    if source_type == "subscription":
        return "subscription"
    return "http_socks"


def _positive_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _valid_port(port: str) -> bool:
    try:
        value = int(port)
    except (TypeError, ValueError):
        return False
    return 1 <= value <= 65535


def _normalise_kind(proto: str | None, default_kind: str | None) -> str | None:
    candidate = (proto or "").lower()
    if candidate in HTTP_SOCKS_KINDS:
        return candidate
    fallback = (default_kind or "").lower()
    if fallback in HTTP_SOCKS_KINDS:
        return fallback
    return None


def _make_proxy_candidate(*, ip: str, port: str, kind: str | None, source_id: str) -> dict | None:
    if kind not in HTTP_SOCKS_KINDS:
        return None
    if not _valid_ip(ip) or not _valid_port(port):
        return None
    return {"kind": kind, "raw": f"{kind}://{ip}:{int(port)}", "source": source_id}


def _strip_html(value: str) -> str:
    value = re.sub(r"<script\b.*?</script>", "", value, flags=re.IGNORECASE | re.DOTALL)
    value = re.sub(r"<style\b.*?</style>", "", value, flags=re.IGNORECASE | re.DOTALL)
    value = re.sub(r"<[^>]+>", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _entry_urls(entry: dict) -> list[str]:
    urls = entry.get("urls")
    if isinstance(urls, list):
        return [str(url) for url in urls if str(url).strip()]
    url = str(entry.get("url") or "")
    pages = _positive_int(entry.get("pages"))
    if pages and "{page}" in url:
        page_start = _positive_int(entry.get("page_start")) or 1
        return [url.format(page=page) for page in range(page_start, page_start + pages)]
    return [url] if url else []


def _fetch_entry_text(
    *,
    url: str,
    timeout: int,
    max_bytes: int | None,
    fetch_text_func: FetchTextFunc,
) -> tuple[str, dict]:
    if fetch_text_func is fetch_text:
        raw_text = fetch_text(url, timeout, max_bytes=max_bytes)
    else:
        raw_text = fetch_text_func(url, timeout)
        if max_bytes:
            raw_text = raw_text.encode("utf-8", errors="ignore")[:max_bytes].decode("utf-8", errors="ignore")

    bytes_read = len(raw_text.encode("utf-8", errors="ignore"))
    return raw_text, {
        "bytes_read": bytes_read,
        "truncated_by_bytes": bool(max_bytes and bytes_read >= max_bytes),
    }


def _parse_text_candidates(
    *,
    raw_text: str,
    source_id: str,
    source_kind: str | None,
    source_format: str,
    max_lines: int | None,
    max_candidates: int | None,
) -> tuple[list[dict], dict]:
    candidates: list[dict] = []
    meta = {
        "parser": source_format,
        "lines_seen": 0,
        "truncated_by_lines": False,
        "truncated_by_candidates": False,
    }

    def append_candidate(item: dict | None) -> bool:
        if item is None:
            return False
        candidates.append(item)
        if max_candidates and len(candidates) >= max_candidates:
            meta["truncated_by_candidates"] = True
            return True
        return False

    if source_format in {"ip_port", "share_url", "base64_subscription"}:
        lines = raw_text.splitlines()
        meta["lines_seen"] = len(lines)
        if max_lines and len(lines) > max_lines:
            lines = lines[:max_lines]
            meta["truncated_by_lines"] = True
        for line in lines:
            if append_candidate(parse_line(line, source=source_id, kind=source_kind)):
                break
        return candidates, meta

    if source_format in {"regex_ip_port", "openproxy_space"}:
        for index, match in enumerate(IP_PORT_SCAN_RE.finditer(raw_text), start=1):
            meta["lines_seen"] = index
            proto, ip, port = match.groups()
            if append_candidate(
                _make_proxy_candidate(
                    ip=ip,
                    port=port,
                    kind=_normalise_kind(proto, source_kind),
                    source_id=source_id,
                )
            ):
                break
        return candidates, meta

    if source_format == "json_geonode":
        data = json.loads(raw_text)
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise ValueError("json_geonode response missing data list")
        meta["lines_seen"] = len(rows)
        for row in rows:
            if not isinstance(row, dict):
                continue
            protocols = row.get("protocols")
            proto = protocols[0] if isinstance(protocols, list) and protocols else source_kind
            if append_candidate(
                _make_proxy_candidate(
                    ip=str(row.get("ip") or "").strip(),
                    port=str(row.get("port") or "").strip(),
                    kind=_normalise_kind(str(proto or ""), source_kind),
                    source_id=source_id,
                )
            ):
                break
        return candidates, meta

    if source_format == "proxifly_json":
        rows = json.loads(raw_text)
        if not isinstance(rows, list):
            raise ValueError("proxifly_json response is not a list")
        meta["lines_seen"] = len(rows)
        for row in rows:
            if not isinstance(row, dict):
                continue
            raw_proxy = str(row.get("proxy") or "")
            match = IP_PORT_SCAN_RE.search(raw_proxy)
            if match:
                proto, ip, port = match.groups()
                kind = _normalise_kind(str(row.get("protocol") or proto or ""), source_kind)
            else:
                ip = str(row.get("ip") or "").strip()
                port = str(row.get("port") or "").strip()
                kind = _normalise_kind(str(row.get("protocol") or ""), source_kind)
            if append_candidate(_make_proxy_candidate(ip=ip, port=port, kind=kind, source_id=source_id)):
                break
        return candidates, meta

    if source_format == "html_proxy_table":
        rows = re.findall(r"<tr\b[^>]*>(.*?)</tr>", raw_text, flags=re.IGNORECASE | re.DOTALL)
        meta["lines_seen"] = len(rows)
        if max_lines and len(rows) > max_lines:
            rows = rows[:max_lines]
            meta["truncated_by_lines"] = True
        for row in rows:
            cells = [_strip_html(cell) for cell in re.findall(r"<td\b[^>]*>(.*?)</td>", row, flags=re.IGNORECASE | re.DOTALL)]
            if len(cells) < 2:
                continue
            ip, port = cells[0], cells[1]
            lower_cells = [cell.lower() for cell in cells]
            proto = None
            if any("socks4" in cell for cell in lower_cells):
                proto = "socks4"
            elif any("socks5" in cell for cell in lower_cells):
                proto = "socks5"
            elif len(cells) >= 7 and cells[6].lower() == "yes":
                proto = "https"
            if append_candidate(
                _make_proxy_candidate(
                    ip=ip,
                    port=port,
                    kind=_normalise_kind(proto, source_kind),
                    source_id=source_id,
                )
            ):
                break
        return candidates, meta

    raise ValueError(f"unsupported source parser: {source_format}")


def _candidate_trace(
    *,
    run_id: str,
    source_id: str,
    source_type: str,
    source_format: str,
    lane: str,
    url: str,
) -> dict:
    return {
        "run_id": run_id,
        "source_id": source_id,
        "source_type": source_type,
        "source_format": source_format,
        "lane": lane,
        "url": url,
    }


def _parse_source_entry(
    *,
    entry: dict,
    run_id: str,
    source_type: str,
    default_kind: str | None,
    timeout: int,
    fetch_text_func: FetchTextFunc = fetch_text,
) -> tuple[str, list[dict], dict]:
    source_id = entry.get("name") or entry.get("id") or "unknown"
    urls = _entry_urls(entry)
    source_format = entry.get("type") or "ip_port"
    source_kind = entry.get("kind", default_kind)
    source_timeout = _positive_int(entry.get("timeout")) or timeout
    max_bytes = _positive_int(entry.get("max_bytes"))
    max_lines = _positive_int(entry.get("max_lines"))
    max_candidates = _positive_int(entry.get("max_candidates"))
    lane = _source_lane(source_type)

    candidates: list[dict] = []
    parse_meta = {
        "parser": source_format,
        "bytes_read": 0,
        "lines_seen": 0,
        "truncated": False,
        "truncated_by_bytes": False,
        "truncated_by_lines": False,
        "truncated_by_candidates": False,
        "urls_fetched": [],
    }

    for url in urls:
        remaining_candidates = None
        if max_candidates:
            remaining_candidates = max_candidates - len(candidates)
            if remaining_candidates <= 0:
                parse_meta["truncated_by_candidates"] = True
                break

        raw_text, fetch_meta = _fetch_entry_text(
            url=url,
            timeout=source_timeout,
            max_bytes=max_bytes,
            fetch_text_func=fetch_text_func,
        )
        parse_meta["urls_fetched"].append(url)
        parse_meta["bytes_read"] += fetch_meta["bytes_read"]
        parse_meta["truncated_by_bytes"] = parse_meta["truncated_by_bytes"] or fetch_meta["truncated_by_bytes"]

        if source_format == "base64_subscription":
            raw_text = decode_base64_content(raw_text)

        parsed_candidates, item_meta = _parse_text_candidates(
            raw_text=raw_text,
            source_id=source_id,
            source_kind=source_kind,
            source_format=source_format,
            max_lines=max_lines,
            max_candidates=remaining_candidates,
        )
        candidates.extend(parsed_candidates)
        parse_meta["lines_seen"] += int(item_meta.get("lines_seen") or 0)
        parse_meta["truncated_by_lines"] = parse_meta["truncated_by_lines"] or bool(item_meta.get("truncated_by_lines"))
        parse_meta["truncated_by_candidates"] = parse_meta["truncated_by_candidates"] or bool(
            item_meta.get("truncated_by_candidates")
        )
        if max_candidates and len(candidates) >= max_candidates:
            break

    trace_url = entry.get("url") or (urls[0] if urls else "")
    parse_meta["truncated"] = bool(
        parse_meta["truncated_by_bytes"]
        or parse_meta["truncated_by_lines"]
        or parse_meta["truncated_by_candidates"]
    )

    for item in candidates:
        item["source_id"] = source_id
        item["source_type"] = source_type
        item["trace"] = _candidate_trace(
            run_id=run_id,
            source_id=source_id,
            source_type=source_type,
            source_format=source_format,
            lane=lane,
            url=trace_url,
        )

    return lane, candidates, parse_meta


def run_intake(
    *,
    source_registry: Path,
    output_dir: Path,
    run_id: str,
    dry_run: bool,
    timeout: int = 30,
    workers: int = 8,
    dynamic_sources: Path | None = None,
    include_dynamic_sources: bool = False,
    only_dynamic_sources: bool = False,
    fetch_text_func: FetchTextFunc = fetch_text,
) -> dict:
    """Run Layer 0 source intake and write stable artifacts.

    Args:
        source_registry: path to layer0_sources.json.
        output_dir: directory for timestamped intake artifacts.
        run_id: stable run id used in output filenames.
        dry_run: records mode in manifest; does not change runtime behavior.
        timeout: fetch timeout per source.
        workers: concurrent source fetch workers.
        dynamic_sources: optional dynamic_sources.json produced by discovery.
        include_dynamic_sources: merge dynamic fetchable sources into the registry.
        only_dynamic_sources: ignore curated registry entries and run only dynamic fetchable sources.
        fetch_text_func: injectable fetcher for tests or alternate transports.

    Returns:
        Manifest dict matching the on-disk manifest artifact.
    """
    if only_dynamic_sources:
        config = load_dynamic_registry_entries(dynamic_sources)
    else:
        config = load_merged_source_registry(
            source_registry,
            dynamic_path=dynamic_sources,
            include_dynamic=include_dynamic_sources,
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    http_socks: list[dict] = []
    subscriptions: list[dict] = []
    source_traces: list[dict] = []
    errors: list[dict] = []
    source_specs: list[tuple[int, dict, str, str | None]] = []

    for group_key, default_kind, source_type in SOURCE_GROUPS:
        for entry in config.get(group_key, []):
            if not entry.get("url"):
                continue
            source_specs.append((len(source_specs), entry, source_type, default_kind))

    def process_source(spec: tuple[int, dict, str, str | None]) -> tuple[int, str, list[dict], dict, dict | None]:
        index, entry, source_type, default_kind = spec
        source_id = entry.get("name") or entry.get("id") or "unknown"
        lane = _source_lane(source_type)
        try:
            lane, candidates, parse_meta = _parse_source_entry(
                entry=entry,
                run_id=run_id,
                source_type=source_type,
                default_kind=default_kind,
                timeout=timeout,
                fetch_text_func=fetch_text_func,
            )
            status = "ok"
            error = None
        except Exception as exc:
            candidates = []
            parse_meta = {}
            status = "error"
            error = repr(exc)
        error_entry = None
        if error is not None:
            error_entry = {
                "source_id": source_id,
                "source_type": source_type,
                "lane": lane,
                "url": entry.get("url"),
                "error": error,
            }

        source_trace = {
            "source_id": source_id,
            "source_type": source_type,
            "source_format": entry.get("type") or "ip_port",
            "kind": entry.get("kind", default_kind),
            "url": entry.get("url"),
            "lane": lane,
            "raw_count": len(candidates),
            "status": status,
        }
        if parse_meta:
            source_trace.update(
                {
                    "parser": parse_meta.get("parser"),
                    "bytes_read": parse_meta.get("bytes_read", 0),
                    "lines_seen": parse_meta.get("lines_seen", 0),
                    "truncated": parse_meta.get("truncated", False),
                    "truncated_by_bytes": parse_meta.get("truncated_by_bytes", False),
                    "truncated_by_lines": parse_meta.get("truncated_by_lines", False),
                    "truncated_by_candidates": parse_meta.get("truncated_by_candidates", False),
                    "urls_fetched": parse_meta.get("urls_fetched", []),
                    "max_bytes": _positive_int(entry.get("max_bytes")),
                    "max_lines": _positive_int(entry.get("max_lines")),
                    "max_candidates": _positive_int(entry.get("max_candidates")),
                }
            )
        if error is not None:
            source_trace["error"] = error
        return index, lane, candidates, source_trace, error_entry

    worker_count = max(1, int(workers or 1))
    if worker_count == 1 or len(source_specs) <= 1:
        processed = [process_source(spec) for spec in source_specs]
    else:
        processed = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(process_source, spec) for spec in source_specs]
            for future in concurrent.futures.as_completed(futures):
                processed.append(future.result())

    for _index, lane, candidates, source_trace, error_entry in sorted(processed, key=lambda row: row[0]):
        if lane == "subscription":
            subscriptions.extend(candidates)
        else:
            http_socks.extend(candidates)
        source_traces.append(source_trace)
        if error_entry is not None:
            errors.append(error_entry)

    http_path = output_dir / f"layer0_http_socks_pool_{run_id}.json"
    subscription_path = output_dir / f"layer0_subscription_stage0_raw_{run_id}.json"
    manifest_path = output_dir / f"layer0_intake_manifest_{run_id}.json"

    _write_json(http_path, http_socks)
    _write_json(subscription_path, subscriptions)

    manifest = {
        "run_id": run_id,
        "dry_run": bool(dry_run),
        "source_registry": str(source_registry),
        "dynamic_sources": str(dynamic_sources) if dynamic_sources else "",
        "include_dynamic_sources": bool(include_dynamic_sources),
        "only_dynamic_sources": bool(only_dynamic_sources),
        "manifest_path": str(manifest_path),
        "lanes": {
            "http_socks": {
                "raw_path": str(http_path),
                "raw_count": len(http_socks),
                "sources": [trace["source_id"] for trace in source_traces if trace["lane"] == "http_socks"],
            },
            "subscription": {
                "raw_path": str(subscription_path),
                "raw_count": len(subscriptions),
                "sources": [trace["source_id"] for trace in source_traces if trace["lane"] == "subscription"],
            },
        },
        "sources": source_traces,
        "errors": errors,
    }
    _write_json(manifest_path, manifest)
    if not dry_run:
        _write_json(output_dir / "layer0_http_socks_pool.latest.json", http_socks)
        _write_json(output_dir / "layer0_subscription_stage0_raw.latest.json", subscriptions)
        _write_json(output_dir / "layer0_intake_manifest.latest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a stable Layer 0 intake artifact")
    parser.add_argument("--config", type=Path, default=DEFAULT_SOURCES_CONFIG, help="path to layer0_sources.json")
    parser.add_argument("--output-dir", type=Path, required=True, help="directory for intake artifacts")
    parser.add_argument("--run-id", default="", help="stable run id for artifact filenames")
    parser.add_argument("--dry-run", action="store_true", help="record dry-run mode and avoid runtime side effects")
    parser.add_argument("--timeout", type=int, default=30, help="fetch timeout per source")
    parser.add_argument("--workers", type=int, default=8, help="concurrent source fetch workers")
    parser.add_argument("--dynamic-sources", type=Path, default=None, help="dynamic_sources.json from source discovery")
    parser.add_argument("--no-dynamic-sources", action="store_true", help="do not merge discovered dynamic sources")
    parser.add_argument("--only-dynamic-sources", action="store_true", help="ignore curated registry and fetch only dynamic sources")
    args = parser.parse_args()

    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    manifest = run_intake(
        source_registry=args.config,
        output_dir=args.output_dir,
        run_id=run_id,
        dry_run=args.dry_run,
        timeout=args.timeout,
        workers=args.workers,
        dynamic_sources=args.dynamic_sources,
        include_dynamic_sources=not args.no_dynamic_sources,
        only_dynamic_sources=args.only_dynamic_sources,
    )
    print(json.dumps(manifest, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
