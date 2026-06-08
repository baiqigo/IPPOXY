#!/usr/bin/env python3
"""Summarize IP proxy candidate quality by upstream source."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
DEFAULT_INPUT = IP_RUNTIME_DIR / "research/proxy_candidate_check.latest.json"
DEFAULT_JSON_OUT = IP_RUNTIME_DIR / "research/proxy_source_quality_latest.json"
DEFAULT_MD_OUT = IP_RUNTIME_DIR / "research/proxy_source_quality_latest.md"
DEFAULT_COOLDOWN_MIN_TOTAL = int(os.environ.get("IP_PROXY_SOURCE_COOLDOWN_MIN_TOTAL", "20"))
DEFAULT_COOLDOWN_MAX_CLEAN_RATE = float(os.environ.get("IP_PROXY_SOURCE_COOLDOWN_MAX_CLEAN_RATE", "1.0"))
DEFAULT_COOLDOWN_MAX_SUCCESS_RATE = float(os.environ.get("IP_PROXY_SOURCE_COOLDOWN_MAX_SUCCESS_RATE", "25.0"))


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator * 100.0 / denominator, 2)


def normalize_error(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > 180:
        text = text[:177] + "..."
    return text.replace("\r", " ").replace("\n", " ")


def cooldown_reason(item: dict, min_total: int, max_clean_rate: float, max_success_rate: float) -> str:
    total = int(item.get("total") or 0)
    clean_rate = float(item.get("clean_rate_pct") or 0.0)
    success_rate = float(item.get("success_rate_pct") or 0.0)
    if total < min_total:
        return ""
    if int(item.get("clean") or 0) <= 0:
        return "no_clean_candidates"
    if clean_rate <= max_clean_rate and success_rate <= max_success_rate:
        return "low_clean_and_success_rate"
    return ""


def summarize_source_quality(
    rows: list[dict],
    *,
    cooldown_min_total: int = DEFAULT_COOLDOWN_MIN_TOTAL,
    cooldown_max_clean_rate: float = DEFAULT_COOLDOWN_MAX_CLEAN_RATE,
    cooldown_max_success_rate: float = DEFAULT_COOLDOWN_MAX_SUCCESS_RATE,
) -> dict:
    by_source: dict[str, dict] = {}
    global_kinds = Counter()

    buckets: dict[str, list[dict]] = defaultdict(list)
    for item in rows:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or "unknown")
        buckets[source].append(item)
        global_kinds[str(item.get("kind") or "unknown")] += 1

    for source, items in sorted(buckets.items()):
        total = len(items)
        success = sum(1 for item in items if item.get("success"))
        clean = sum(1 for item in items if item.get("clean"))
        kinds = Counter(str(item.get("kind") or "unknown") for item in items)
        clean_kinds = Counter(str(item.get("kind") or "unknown") for item in items if item.get("clean"))
        dirty_reasons = Counter()
        errors = Counter()
        exit_ips = set()
        clean_exit_ips = set()

        for item in items:
            exit_ip = str(item.get("exit_ip") or "").strip()
            if exit_ip:
                exit_ips.add(exit_ip)
                if item.get("clean"):
                    clean_exit_ips.add(exit_ip)
            dirty = item.get("dirty") if isinstance(item.get("dirty"), list) else []
            for reason in dirty:
                dirty_reasons[str(reason)] += 1
            if item.get("error"):
                errors[normalize_error(item.get("error"))] += 1

        source_summary = {
            "total": total,
            "success": success,
            "clean": clean,
            "success_rate_pct": pct(success, total),
            "clean_rate_pct": pct(clean, total),
            "unique_exit_ips": len(exit_ips),
            "unique_clean_exit_ips": len(clean_exit_ips),
            "by_kind": dict(sorted(kinds.items())),
            "clean_by_kind": dict(sorted(clean_kinds.items())),
            "dirty_reasons": dict(dirty_reasons.most_common(10)),
            "errors": dict(errors.most_common(10)),
        }
        reason = cooldown_reason(source_summary, cooldown_min_total, cooldown_max_clean_rate, cooldown_max_success_rate)
        source_summary["cooldown_recommended"] = bool(reason)
        source_summary["cooldown_reason"] = reason
        by_source[source] = source_summary

    ranked = sorted(
        by_source.items(),
        key=lambda item: (item[1]["clean"], item[1]["success"], -item[1]["total"], item[0]),
        reverse=True,
    )

    cooldown_sources = {
        source: {
            "reason": item.get("cooldown_reason"),
            "total": item.get("total"),
            "success_rate_pct": item.get("success_rate_pct"),
            "clean_rate_pct": item.get("clean_rate_pct"),
        }
        for source, item in sorted(by_source.items())
        if item.get("cooldown_recommended")
    }

    return {
        "ts": int(time.time()),
        "total": sum(item["total"] for item in by_source.values()),
        "success": sum(item["success"] for item in by_source.values()),
        "clean": sum(item["clean"] for item in by_source.values()),
        "source_count": len(by_source),
        "by_kind": dict(sorted(global_kinds.items())),
        "top_sources_by_clean": [source for source, _ in ranked[:8]],
        "cooldown_policy": {
            "min_total": cooldown_min_total,
            "max_clean_rate_pct": cooldown_max_clean_rate,
            "max_success_rate_pct": cooldown_max_success_rate,
        },
        "cooldown_sources": cooldown_sources,
        "by_source": by_source,
    }


def render_markdown(summary: dict, input_path: Path) -> str:
    lines = [
        "# Proxy Source Quality",
        "",
        f"- Input: `{input_path}`",
        f"- Total checked: {summary.get('total', 0)}",
        f"- Success: {summary.get('success', 0)}",
        f"- Clean: {summary.get('clean', 0)}",
        f"- Sources: {summary.get('source_count', 0)}",
        f"- Cooldown recommended: {len(summary.get('cooldown_sources') or {})}",
        "",
        "| Source | Total | Success | Clean | Clean % | Unique clean exits | Cooldown | Top errors / dirty reasons |",
        "|---|---:|---:|---:|---:|---:|---|---|",
    ]

    sources = summary.get("by_source", {})
    ranked = sorted(
        sources.items(),
        key=lambda item: (item[1].get("clean", 0), item[1].get("success", 0), -item[1].get("total", 0), item[0]),
        reverse=True,
    )
    for source, item in ranked:
        reasons = []
        for key, value in list((item.get("dirty_reasons") or {}).items())[:3]:
            reasons.append(f"{key}:{value}")
        for key, value in list((item.get("errors") or {}).items())[:2]:
            reasons.append(f"{key}:{value}")
        reason_text = "; ".join(reasons)
        lines.append(
            f"| `{source}` | {item.get('total', 0)} | {item.get('success', 0)} | {item.get('clean', 0)} | "
            f"{item.get('clean_rate_pct', 0)} | {item.get('unique_clean_exit_ips', 0)} | "
            f"{item.get('cooldown_reason') or ''} | {reason_text} |"
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT)
    parser.add_argument("--md-out", type=Path, default=DEFAULT_MD_OUT)
    parser.add_argument("--cooldown-min-total", type=int, default=DEFAULT_COOLDOWN_MIN_TOTAL)
    parser.add_argument("--cooldown-max-clean-rate", type=float, default=DEFAULT_COOLDOWN_MAX_CLEAN_RATE)
    parser.add_argument("--cooldown-max-success-rate", type=float, default=DEFAULT_COOLDOWN_MAX_SUCCESS_RATE)
    args = parser.parse_args()

    data = read_json(args.input)
    if not isinstance(data, list):
        raise SystemExit(f"input must be a JSON list: {args.input}")

    summary = summarize_source_quality(
        data,
        cooldown_min_total=args.cooldown_min_total,
        cooldown_max_clean_rate=args.cooldown_max_clean_rate,
        cooldown_max_success_rate=args.cooldown_max_success_rate,
    )
    write_json(args.json_out, summary)
    args.md_out.parent.mkdir(parents=True, exist_ok=True)
    args.md_out.write_text(render_markdown(summary, args.input), encoding="utf-8")
    print(json.dumps({"input": str(args.input), "total": summary["total"], "clean": summary["clean"], "sources": summary["source_count"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
