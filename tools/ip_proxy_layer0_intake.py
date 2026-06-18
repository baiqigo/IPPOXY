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
import time
from pathlib import Path
from typing import Callable

from ip_proxy_layer0_consumer import (
    DEFAULT_SOURCES_CONFIG,
    decode_base64_content,
    fetch_text,
    parse_line,
)


HTTP_SOCKS_KINDS = {"http", "https", "socks4", "socks5"}
SOURCE_GROUPS = (
    ("http_sources", "http", "http"),
    ("socks_sources", "socks5", "socks"),
    ("subscription_sources", None, "subscription"),
    ("api_sources", "http", "api"),
)
FetchTextFunc = Callable[[str, int], str]


def _read_registry(source_registry: Path) -> dict:
    return json.loads(source_registry.read_text(encoding="utf-8-sig"))


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _source_lane(source_type: str) -> str:
    if source_type == "subscription":
        return "subscription"
    return "http_socks"


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
) -> tuple[str, list[dict]]:
    source_id = entry.get("name") or entry.get("id") or "unknown"
    url = entry.get("url") or ""
    source_format = entry.get("type") or "ip_port"
    source_kind = entry.get("kind", default_kind)
    lane = _source_lane(source_type)

    raw_text = fetch_text_func(url, timeout)
    if source_format == "base64_subscription":
        raw_text = decode_base64_content(raw_text)

    candidates: list[dict] = []
    for line in raw_text.splitlines():
        parsed = parse_line(line, source=source_id, kind=source_kind)
        if parsed is None:
            continue
        item = dict(parsed)
        item["source_id"] = source_id
        item["source_type"] = source_type
        item["trace"] = _candidate_trace(
            run_id=run_id,
            source_id=source_id,
            source_type=source_type,
            source_format=source_format,
            lane=lane,
            url=url,
        )
        candidates.append(item)

    return lane, candidates


def run_intake(
    *,
    source_registry: Path,
    output_dir: Path,
    run_id: str,
    dry_run: bool,
    timeout: int = 30,
    workers: int = 8,
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
        fetch_text_func: injectable fetcher for tests or alternate transports.

    Returns:
        Manifest dict matching the on-disk manifest artifact.
    """
    config = _read_registry(source_registry)
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
            lane, candidates = _parse_source_entry(
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
    args = parser.parse_args()

    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    manifest = run_intake(
        source_registry=args.config,
        output_dir=args.output_dir,
        run_id=run_id,
        dry_run=args.dry_run,
        timeout=args.timeout,
        workers=args.workers,
    )
    print(json.dumps(manifest, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
