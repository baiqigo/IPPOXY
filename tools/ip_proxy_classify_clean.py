#!/usr/bin/env python3
"""Classify IPPOXY candidates into strict and relaxed Resin pool buckets."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
CHECK_JSON = IP_RUNTIME_DIR / "research/proxy_candidate_check.latest.json"
RESIN_DIR = IP_RUNTIME_DIR / "resin"
RISKY_DIRTY_FLAGS = {"is_datacenter", "is_proxy", "is_vpn"}
HARD_DIRTY_FLAGS = {"is_tor", "is_abuser", "is_bogon"}
RUNTIME_CANDIDATE_KINDS = {
    "turn",
    "http",
    "https",
    "socks4",
    "socks5",
    "vless",
    "vmess",
    "trojan",
    "ss",
}


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def dirty_flags(item: dict) -> set[str]:
    values = item.get("dirty") or []
    if not isinstance(values, list):
        return set()
    return {str(value).strip() for value in values if str(value).strip()}


def registration_tier(item: dict) -> str:
    if not item.get("success"):
        return "dirty"
    dirty = dirty_flags(item)
    if not dirty:
        return "clean"
    if dirty & HARD_DIRTY_FLAGS:
        return "dirty"
    country = (item.get("country") or "").upper()
    if country == "CN":
        return "dirty"
    if dirty <= RISKY_DIRTY_FLAGS:
        return "risky"
    # L3: alive + non-CN + non-hard-dirty but has other dirty flags
    return "dirty_alive_noncn"


def bucket(item: dict) -> str:
    company_type = (item.get("company_type") or "").lower()
    asn_type = (item.get("asn_type") or "").lower()
    if company_type == "isp" and asn_type == "isp":
        return "residential"
    if "hosting" in {company_type, asn_type}:
        return "risk_review"
    return "static"


def write_json(path: Path, data: object) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def turn_candidate_count(rows: list[dict], tiers: set[str] | None = None) -> int:
    total = 0
    for item in rows:
        if item.get("kind") != "turn":
            continue
        if not item.get("raw") or not item.get("exit_ip"):
            continue
        if tiers is not None and str(item.get("registration_tier") or "").lower() not in tiers:
            continue
        total += 1
    return total


def runtime_candidate_count(rows: list[dict], tiers: set[str] | None = None) -> int:
    total = 0
    for item in rows:
        if item.get("kind") not in RUNTIME_CANDIDATE_KINDS:
            continue
        if not item.get("raw") or not item.get("exit_ip"):
            continue
        if tiers is not None and str(item.get("registration_tier") or "").lower() not in tiers:
            continue
        total += 1
    return total


def latest_update_guard(
    *,
    clean: list[dict],
    relaxed: list[dict],
    candidate_rows: list[dict],
    min_clean_turn: int,
    min_relaxed_turn: int,
    min_all_turn: int,
    force: bool,
) -> dict:
    counts = {
        "clean_turn": turn_candidate_count(clean, {"clean"}),
        "relaxed_turn": turn_candidate_count(relaxed, {"clean", "risky"}),
        "all_turn": turn_candidate_count(candidate_rows),
        "clean_runtime": runtime_candidate_count(clean, {"clean"}),
        "relaxed_runtime": runtime_candidate_count(relaxed, {"clean", "risky"}),
        "all_runtime": runtime_candidate_count(candidate_rows),
    }
    thresholds = {
        "min_clean_turn": max(0, int(min_clean_turn)),
        "min_relaxed_turn": max(0, int(min_relaxed_turn)),
        "min_all_turn": max(0, int(min_all_turn)),
    }
    failures = []
    for count_key, threshold_key in (
        ("clean_runtime", "min_clean_turn"),
        ("relaxed_runtime", "min_relaxed_turn"),
        ("all_runtime", "min_all_turn"),
    ):
        if counts[count_key] < thresholds[threshold_key]:
            failures.append(
                {
                    "reason": "latest_quality_gate_failed",
                    "count_key": count_key,
                    "actual": counts[count_key],
                    "threshold_key": threshold_key,
                    "expected": thresholds[threshold_key],
                }
            )
    return {
        "allowed": bool(force or not failures),
        "forced": bool(force),
        "counts": counts,
        "thresholds": thresholds,
        "failures": failures,
    }


def display_date(run_id: str) -> str:
    date = run_id[:8] if len(run_id) >= 8 and run_id[:8].isdigit() else time.strftime("%Y%m%d")
    return f"{date[:4]}-{date[4:6]}-{date[6:8]}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=CHECK_JSON)
    parser.add_argument("--run-id", default="")
    parser.add_argument(
        "--force-latest",
        action="store_true",
        default=env_bool("IP_PROXY_CLASSIFY_FORCE_LATEST", False),
        help="update .latest outputs even when the latest quality gate would block them",
    )
    parser.add_argument(
        "--min-latest-clean-turn",
        type=int,
        default=int(os.environ.get("IP_PROXY_CLASSIFY_MIN_LATEST_CLEAN_TURN", "1")),
        help="minimum clean TURN rows required before .latest classification files are replaced",
    )
    parser.add_argument(
        "--min-latest-relaxed-turn",
        type=int,
        default=int(os.environ.get("IP_PROXY_CLASSIFY_MIN_LATEST_RELAXED_TURN", "1")),
        help="minimum clean+risky TURN rows required before .latest classification files are replaced",
    )
    parser.add_argument(
        "--min-latest-all-turn",
        type=int,
        default=int(os.environ.get("IP_PROXY_CLASSIFY_MIN_LATEST_ALL_TURN", "1")),
        help="minimum checked TURN rows required before .latest classification files are replaced",
    )
    args = parser.parse_args()
    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")

    data = json.loads(args.input.read_text(encoding="utf-8-sig"))
    candidate_rows = [dict(item) for item in data if isinstance(item, dict)]
    for item in candidate_rows:
        item["registration_tier"] = registration_tier(item)
        item["pool_bucket"] = bucket(item)
        item["registration_eligible"] = item["registration_tier"] in {"clean", "risky", "dirty_alive_noncn"}

    clean = [item for item in candidate_rows if item["registration_tier"] == "clean"]
    relaxed = [item for item in candidate_rows if item["registration_tier"] in {"clean", "risky"}]
    dirty = [item for item in candidate_rows if item["registration_tier"] == "dirty"]
    l3_raw = [item for item in candidate_rows if item["registration_tier"] == "dirty_alive_noncn"]
    for items in (clean, relaxed, dirty, l3_raw):
        items.sort(key=lambda item: (item["registration_tier"], bucket(item), item.get("kind") or "", item.get("responseTime") or 999999))

    counts = Counter(item["pool_bucket"] for item in clean)
    relaxed_counts = Counter(item["registration_tier"] for item in relaxed)
    kind_counts = Counter((item["pool_bucket"], item.get("kind")) for item in clean)
    relaxed_kind_counts = Counter((item["registration_tier"], item.get("kind")) for item in relaxed)
    type_counts = Counter((item.get("company_type"), item.get("asn_type")) for item in clean)
    dirty_reason_counts = Counter(flag for item in candidate_rows for flag in dirty_flags(item))
    latest_guard = latest_update_guard(
        clean=clean,
        relaxed=relaxed,
        candidate_rows=candidate_rows,
        min_clean_turn=args.min_latest_clean_turn,
        min_relaxed_turn=args.min_latest_relaxed_turn,
        min_all_turn=args.min_latest_all_turn,
        force=args.force_latest,
    )
    update_latest = bool(latest_guard["allowed"])

    RESIN_DIR.mkdir(parents=True, exist_ok=True)
    write_json(RESIN_DIR / f"clean_candidates_classified_{run_id}.json", clean)
    write_json(RESIN_DIR / f"relaxed_candidates_classified_{run_id}.json", relaxed)
    write_json(RESIN_DIR / f"dirty_candidates_classified_{run_id}.json", dirty)
    write_json(RESIN_DIR / f"l3_raw_candidates_classified_{run_id}.json", l3_raw)
    write_json(RESIN_DIR / f"all_candidates_classified_{run_id}.json", candidate_rows)
    if update_latest:
        write_json(RESIN_DIR / "clean_candidates_classified.latest.json", clean)
        write_json(RESIN_DIR / "relaxed_candidates_classified.latest.json", relaxed)
        write_json(RESIN_DIR / "dirty_candidates_classified.latest.json", dirty)
        write_json(RESIN_DIR / "l3_raw_candidates_classified.latest.json", l3_raw)
        write_json(RESIN_DIR / "all_candidates_classified.latest.json", candidate_rows)

    for name in ["residential", "static", "risk_review"]:
        bucket_rows = [item["raw"] for item in clean if item["pool_bucket"] == name]
        text = ("\n".join(bucket_rows) + "\n") if bucket_rows else ""
        atomic_write_text(RESIN_DIR / f"{name}_clean_candidates_{run_id}.txt", text)
        if update_latest:
            atomic_write_text(RESIN_DIR / f"{name}_clean_candidates.latest.txt", text)
    for name in ["clean", "risky"]:
        tier_rows = [item["raw"] for item in relaxed if item["registration_tier"] == name]
        text = ("\n".join(tier_rows) + "\n") if tier_rows else ""
        atomic_write_text(RESIN_DIR / f"{name}_relaxed_candidates_{run_id}.txt", text)
        if update_latest:
            atomic_write_text(RESIN_DIR / f"{name}_relaxed_candidates.latest.txt", text)
    # L3 raw tier output
    l3_rows = [item["raw"] for item in l3_raw]
    l3_text = ("\n".join(l3_rows) + "\n") if l3_rows else ""
    atomic_write_text(RESIN_DIR / f"l3_raw_candidates_{run_id}.txt", l3_text)
    if update_latest:
        atomic_write_text(RESIN_DIR / "l3_raw_candidates.latest.txt", l3_text)

    lines = [
        f"# Candidate Classification {display_date(run_id)}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Checked candidates: {len(candidate_rows)}",
        f"- Clean candidates: {len(clean)}",
        f"- Relaxed candidates: {len(relaxed)}",
        f"- Risky candidates: {relaxed_counts['risky']}",
        f"- Dirty candidates: {len(dirty)}",
        f"- L3 raw candidates: {len(l3_raw)}",
        f"- Residential priority: {counts['residential']}",
        f"- Static/education/business: {counts['static']}",
        f"- Risk review: {counts['risk_review']}",
        "",
        "## Strict Clean By Protocol",
        "",
        "| Bucket | TURN | SSTP | SOCKS5 | Total |",
        "|---|---:|---:|---:|---:|",
    ]
    for name in ["residential", "static", "risk_review"]:
        turn = kind_counts[(name, "turn")]
        sstp = kind_counts[(name, "sstp")]
        socks5 = kind_counts[(name, "socks5")]
        lines.append(f"| {name} | {turn} | {sstp} | {socks5} | {turn + sstp + socks5} |")

    lines += [
        "",
        "## Relaxed By Protocol",
        "",
        "| Tier | TURN | SSTP | SOCKS5 | Total |",
        "|---|---:|---:|---:|---:|",
    ]
    for name in ["clean", "risky"]:
        turn = relaxed_kind_counts[(name, "turn")]
        sstp = relaxed_kind_counts[(name, "sstp")]
        socks5 = relaxed_kind_counts[(name, "socks5")]
        lines.append(f"| {name} | {turn} | {sstp} | {socks5} | {turn + sstp + socks5} |")

    lines += [
        "",
        "## Dirty Reason Counts",
        "",
        "| Reason | Count |",
        "|---|---:|",
    ]
    for reason, count in sorted(dirty_reason_counts.items(), key=lambda row: (-row[1], row[0])):
        lines.append(f"| `{reason}` | {count} |")

    lines += [
        "",
        "## Type Counts",
        "",
        "| company/asn type | Count |",
        "|---|---:|",
    ]
    for (company_type, asn_type), count in sorted(type_counts.items(), key=lambda row: (-row[1], str(row[0]))):
        lines.append(f"| `{company_type or ''}/{asn_type or ''}` | {count} |")

    lines += [
        "",
        "## Residential Priority",
        "",
        "| Kind | Candidate | Exit IP | Country | Company | RT ms |",
        "|---|---|---|---|---|---:|",
    ]
    for item in [i for i in clean if i["pool_bucket"] == "residential"]:
        lines.append(
            f"| {item.get('kind')} | `{item.get('raw')}` | `{item.get('exit_ip') or ''}` | "
            f"{item.get('country') or ''} | {item.get('company') or ''} | {item.get('responseTime') or ''} |"
        )

    lines += [
        "",
        "## Static / Education / Business",
        "",
        "| Kind | Candidate | Exit IP | Country | Type | Company | RT ms |",
        "|---|---|---|---|---|---|---:|",
    ]
    for item in [i for i in clean if i["pool_bucket"] == "static"]:
        lines.append(
            f"| {item.get('kind')} | `{item.get('raw')}` | `{item.get('exit_ip') or ''}` | "
            f"{item.get('country') or ''} | {item.get('company_type')}/{item.get('asn_type')} | "
            f"{item.get('company') or ''} | {item.get('responseTime') or ''} |"
        )

    lines += [
        "",
        "## Risk Review",
        "",
        "| Kind | Candidate | Exit IP | Country | Type | Company | RT ms |",
        "|---|---|---|---|---|---|---:|",
    ]
    for item in [i for i in clean if i["pool_bucket"] == "risk_review"]:
        lines.append(
            f"| {item.get('kind')} | `{item.get('raw')}` | `{item.get('exit_ip') or ''}` | "
            f"{item.get('country') or ''} | {item.get('company_type')}/{item.get('asn_type')} | "
            f"{item.get('company') or ''} | {item.get('responseTime') or ''} |"
        )

    lines += [
        "",
        "## Risky Relaxed Candidates",
        "",
        "| Kind | Candidate | Exit IP | Country | Dirty | Type | Company | RT ms |",
        "|---|---|---|---|---|---|---|---:|",
    ]
    for item in [i for i in relaxed if i["registration_tier"] == "risky"]:
        lines.append(
            f"| {item.get('kind')} | `{item.get('raw')}` | `{item.get('exit_ip') or ''}` | "
            f"{item.get('country') or ''} | `{','.join(sorted(dirty_flags(item)))}` | "
            f"{item.get('company_type')}/{item.get('asn_type')} | {item.get('company') or ''} | "
            f"{item.get('responseTime') or ''} |"
        )

    md = "\n".join(lines) + "\n"
    atomic_write_text(RESIN_DIR / f"clean_candidate_classification_{run_id}.md", md)
    if update_latest:
        atomic_write_text(RESIN_DIR / "clean_candidate_classification.latest.md", md)
    guard_report = {
        "run_id": run_id,
        "latest_updated": update_latest,
        "latest_guard": latest_guard,
    }
    write_json(RESIN_DIR / f"candidate_classification_guard_{run_id}.json", guard_report)
    write_json(RESIN_DIR / "candidate_classification_guard.latest.json", guard_report)
    print(
        json.dumps(
            {
                "run_id": run_id,
                "checked": len(candidate_rows),
                "clean": len(clean),
                "relaxed": len(relaxed),
                "risky": relaxed_counts["risky"],
                "dirty": len(dirty),
                "l3_raw": len(l3_raw),
                "pool_buckets": dict(counts),
                "latest_updated": update_latest,
                "latest_guard": latest_guard,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
