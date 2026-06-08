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
DEFAULT_SELECTION_SUMMARY = IP_RUNTIME_DIR / "research/proxy_candidate_selection.latest.json"
DEFAULT_COOLDOWN_MIN_TOTAL = int(os.environ.get("IP_PROXY_SOURCE_COOLDOWN_MIN_TOTAL", "20"))
DEFAULT_COOLDOWN_MAX_CLEAN_RATE = float(os.environ.get("IP_PROXY_SOURCE_COOLDOWN_MAX_CLEAN_RATE", "1.0"))
DEFAULT_COOLDOWN_MAX_SUCCESS_RATE = float(os.environ.get("IP_PROXY_SOURCE_COOLDOWN_MAX_SUCCESS_RATE", "25.0"))


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_json_if_exists(path: Path) -> object:
    if not path.exists():
        return {}
    return read_json(path)


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


def refresh_summary_indexes(summary: dict) -> None:
    by_source = summary.get("by_source") if isinstance(summary.get("by_source"), dict) else {}
    ranked = sorted(
        by_source.items(),
        key=lambda item: (item[1].get("clean", 0), item[1].get("success", 0), -item[1].get("total", 0), item[0]),
        reverse=True,
    )
    cooldown_sources = {
        source: {
            "reason": item.get("cooldown_reason"),
            "total": item.get("total"),
            "success_rate_pct": item.get("success_rate_pct"),
            "clean_rate_pct": item.get("clean_rate_pct"),
            "carried_forward": bool(item.get("carried_forward")),
            "last_observed_ts": item.get("last_observed_ts"),
        }
        for source, item in sorted(by_source.items())
        if isinstance(item, dict) and item.get("cooldown_recommended")
    }
    summary["source_count"] = len(by_source)
    summary["top_sources_by_clean"] = [source for source, _ in ranked[:8]]
    summary["cooldown_sources"] = cooldown_sources


def merge_previous_cooldown_sources(summary: dict, previous: object) -> dict:
    if not isinstance(previous, dict):
        return summary
    previous_by_source = previous.get("by_source")
    if not isinstance(previous_by_source, dict):
        return summary

    by_source = summary.setdefault("by_source", {})
    if not isinstance(by_source, dict):
        by_source = {}
        summary["by_source"] = by_source

    carried: dict[str, dict] = {}
    current_sources = set(by_source)
    for source, item in sorted(previous_by_source.items()):
        source = str(source)
        if source in current_sources or not isinstance(item, dict):
            continue
        if not item.get("cooldown_recommended"):
            continue
        copied = dict(item)
        copied["carried_forward"] = True
        copied["not_checked_in_current_run"] = True
        copied["last_observed_ts"] = previous.get("ts")
        by_source[source] = copied
        carried[source] = {
            "reason": copied.get("cooldown_reason"),
            "total": copied.get("total"),
            "success_rate_pct": copied.get("success_rate_pct"),
            "clean_rate_pct": copied.get("clean_rate_pct"),
            "last_observed_ts": copied.get("last_observed_ts"),
        }

    summary["carried_forward_cooldown_sources"] = carried
    summary["carried_forward_cooldown_source_count"] = len(carried)
    refresh_summary_indexes(summary)
    return summary


def merge_selection_cooldown_sources(summary: dict, selection: object) -> dict:
    if not isinstance(selection, dict):
        return summary
    selection_cooldown = selection.get("cooldown_sources")
    if not isinstance(selection_cooldown, dict):
        return summary

    by_source = summary.setdefault("by_source", {})
    if not isinstance(by_source, dict):
        by_source = {}
        summary["by_source"] = by_source

    recovered: dict[str, dict] = {}
    current_sources = set(by_source)
    for source, item in sorted(selection_cooldown.items()):
        source = str(source)
        if source in current_sources or not isinstance(item, dict):
            continue
        reason = str(item.get("reason") or "selection_cooldown").strip()
        total = int(item.get("total") or item.get("candidates") or 0)
        success = int(item.get("success") or 0)
        clean = int(item.get("clean") or 0)
        success_rate = pct(success, total)
        clean_rate = pct(clean, total)
        by_source[source] = {
            "total": total,
            "success": success,
            "clean": clean,
            "success_rate_pct": success_rate,
            "clean_rate_pct": clean_rate,
            "unique_exit_ips": 0,
            "unique_clean_exit_ips": 0,
            "by_kind": {},
            "clean_by_kind": {},
            "dirty_reasons": {},
            "errors": {},
            "cooldown_recommended": True,
            "cooldown_reason": reason,
            "carried_forward": True,
            "recovered_from_selection": True,
            "not_checked_in_current_run": True,
            "selection_candidates": item.get("candidates"),
            "selection_selected": item.get("selected"),
        }
        recovered[source] = {
            "reason": reason,
            "total": total,
            "success_rate_pct": success_rate,
            "clean_rate_pct": clean_rate,
            "selection_candidates": item.get("candidates"),
            "selection_selected": item.get("selected"),
        }

    summary["recovered_selection_cooldown_sources"] = recovered
    summary["recovered_selection_cooldown_source_count"] = len(recovered)
    refresh_summary_indexes(summary)
    return summary


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
        f"- Carried-forward cooldown sources: {summary.get('carried_forward_cooldown_source_count', 0)}",
        f"- Recovered selection cooldown sources: {summary.get('recovered_selection_cooldown_source_count', 0)}",
        "",
        "| Source | Total | Success | Clean | Clean % | Unique clean exits | Cooldown | Carried | Top errors / dirty reasons |",
        "|---|---:|---:|---:|---:|---:|---|---|---|",
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
            f"{item.get('cooldown_reason') or ''} | {'yes' if item.get('carried_forward') else ''} | {reason_text} |"
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
    parser.add_argument("--previous-source-quality", type=Path, default=DEFAULT_JSON_OUT)
    parser.add_argument("--no-merge-previous-source-quality", action="store_true")
    parser.add_argument("--selection-summary", type=Path, default=DEFAULT_SELECTION_SUMMARY)
    parser.add_argument("--no-merge-selection-summary", action="store_true")
    args = parser.parse_args()

    previous = {} if args.no_merge_previous_source_quality else read_json_if_exists(args.previous_source_quality)
    selection = {} if args.no_merge_selection_summary else read_json_if_exists(args.selection_summary)
    data = read_json(args.input)
    if not isinstance(data, list):
        raise SystemExit(f"input must be a JSON list: {args.input}")

    summary = summarize_source_quality(
        data,
        cooldown_min_total=args.cooldown_min_total,
        cooldown_max_clean_rate=args.cooldown_max_clean_rate,
        cooldown_max_success_rate=args.cooldown_max_success_rate,
    )
    if previous:
        summary = merge_previous_cooldown_sources(summary, previous)
    if selection:
        summary = merge_selection_cooldown_sources(summary, selection)
    write_json(args.json_out, summary)
    args.md_out.parent.mkdir(parents=True, exist_ok=True)
    args.md_out.write_text(render_markdown(summary, args.input), encoding="utf-8")
    print(
        json.dumps(
            {
                "input": str(args.input),
                "total": summary["total"],
                "clean": summary["clean"],
                "sources": summary["source_count"],
                "carried_forward_cooldown_source_count": summary.get("carried_forward_cooldown_source_count", 0),
                "recovered_selection_cooldown_source_count": summary.get("recovered_selection_cooldown_source_count", 0),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
