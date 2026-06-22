#!/usr/bin/env python3
"""Thin live-node filter for registrar-oriented IPPOXY pools."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
DEFAULT_INPUT = RUNTIME / "research/proxy_candidate_sandbox_live.latest.json"
DEFAULT_OUTPUT = RUNTIME / "research/proxy_candidate_thin_live.latest.json"
DEFAULT_FEEDBACK = ROOT / "captures/ip_registrar_feedback_latest.json"
SUPPORTED_KINDS = {"http", "https", "socks4", "socks5"}


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def parse_time(value: object) -> float | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return float(text)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def feedback_bad_exit_ips(feedback: object) -> set[str]:
    if not isinstance(feedback, dict):
        return set()
    out: set[str] = set()
    for field in ("bad_exit_ips", "avoid_exit_ips"):
        values = feedback.get(field, [])
        if isinstance(values, list):
            out.update(str(item).strip() for item in values if str(item).strip())
    return out


def is_live_row(row: dict) -> bool:
    kind = str(row.get("kind") or "").lower()
    return (
        kind in SUPPORTED_KINDS
        and bool(row.get("success"))
        and bool(row.get("sandbox_live"))
        and bool(str(row.get("raw") or "").strip())
        and bool(str(row.get("exit_ip") or row.get("trace_ip") or "").strip())
    )


def row_checked_at(row: dict) -> float | None:
    return parse_time(row.get("checked_at") or row.get("ts") or row.get("timestamp"))


def thin_filter_rows(
    rows: list[dict],
    *,
    bad_exit_ips: set[str],
    ttl_seconds: int,
    limit: int = 0,
    now: float | None = None,
) -> tuple[list[dict], dict]:
    now = time.time() if now is None else now
    kept: list[dict] = []
    seen_raw: set[str] = set()
    seen_exit: set[str] = set()
    counters = {
        "input": len(rows),
        "not_live": 0,
        "bad_feedback": 0,
        "expired": 0,
        "duplicate": 0,
    }

    for row in rows:
        if not isinstance(row, dict) or not is_live_row(row):
            counters["not_live"] += 1
            continue
        raw = str(row.get("raw") or "").strip()
        exit_ip = str(row.get("exit_ip") or row.get("trace_ip") or "").strip()
        if exit_ip in bad_exit_ips:
            counters["bad_feedback"] += 1
            continue
        checked_at = row_checked_at(row)
        if ttl_seconds > 0 and checked_at is not None and now - checked_at > ttl_seconds:
            counters["expired"] += 1
            continue
        if raw in seen_raw or exit_ip in seen_exit:
            counters["duplicate"] += 1
            continue
        seen_raw.add(raw)
        seen_exit.add(exit_ip)
        item = dict(row)
        item["exit_ip"] = exit_ip
        item["success"] = True
        item["sandbox_live"] = True
        item["checked_from"] = item.get("checked_from") or "sandbox"
        item["registration_tier"] = "dirty_alive_noncn"
        item["raw_pool"] = True
        if "dirty" not in item:
            item["dirty"] = ["thin_live_unclassified"]
        kept.append(item)

    kept.sort(key=lambda item: (int(item.get("responseTime") or item.get("sandbox_response_ms") or 999999), str(item.get("raw") or "")))
    if limit > 0:
        kept = kept[:limit]
    summary = {
        **counters,
        "bad_feedback_exit_ips": sorted(bad_exit_ips),
        "kept": len(kept),
        "ttl_seconds": ttl_seconds,
        "limit": limit,
    }
    return kept, summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--feedback", type=Path, default=DEFAULT_FEEDBACK)
    parser.add_argument("--ttl-seconds", type=int, default=int(os.environ.get("IP_PROXY_THIN_TTL_SECONDS", "1200")))
    parser.add_argument("--limit", type=int, default=int(os.environ.get("IP_PROXY_THIN_FILTER_LIMIT", "0")))
    args = parser.parse_args()

    data = read_json(args.input, [])
    rows = data if isinstance(data, list) else []
    feedback = read_json(args.feedback, {})
    kept, summary = thin_filter_rows(
        rows,
        bad_exit_ips=feedback_bad_exit_ips(feedback),
        ttl_seconds=max(0, args.ttl_seconds),
        limit=max(0, args.limit),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(kept, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    latest = RUNTIME / "research/proxy_candidate_thin_live.latest.json"
    if args.output != latest:
        latest.parent.mkdir(parents=True, exist_ok=True)
        latest.write_text(json.dumps(kept, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "thin_live_filter", "input": str(args.input), "output": str(args.output), **summary}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
