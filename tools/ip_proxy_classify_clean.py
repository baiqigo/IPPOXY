#!/usr/bin/env python3
"""Classify clean IPPOXY candidates into Resin pool buckets."""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK_JSON = ROOT / "docs/ip-proxy/research/runtime/proxy_candidate_check.latest.json"
RESIN_DIR = ROOT / "docs/ip-proxy/resin"


def bucket(item: dict) -> str:
    company_type = (item.get("company_type") or "").lower()
    asn_type = (item.get("asn_type") or "").lower()
    if company_type == "isp" and asn_type == "isp":
        return "residential"
    if "hosting" in {company_type, asn_type}:
        return "risk_review"
    return "static"


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=CHECK_JSON)
    parser.add_argument("--run-id", default="")
    args = parser.parse_args()
    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")

    data = json.loads(args.input.read_text(encoding="utf-8"))
    clean = [item for item in data if item.get("clean")]
    clean.sort(key=lambda item: (bucket(item), item.get("kind") or "", item.get("responseTime") or 999999))

    for item in clean:
        item["pool_bucket"] = bucket(item)

    counts = Counter(item["pool_bucket"] for item in clean)
    kind_counts = Counter((item["pool_bucket"], item.get("kind")) for item in clean)
    type_counts = Counter((item.get("company_type"), item.get("asn_type")) for item in clean)

    RESIN_DIR.mkdir(parents=True, exist_ok=True)
    write_json(RESIN_DIR / f"clean_candidates_classified_{run_id}.json", clean)
    write_json(RESIN_DIR / "clean_candidates_classified.latest.json", clean)

    for name in ["residential", "static", "risk_review"]:
        rows = [item["raw"] for item in clean if item["pool_bucket"] == name]
        text = ("\n".join(rows) + "\n") if rows else ""
        (RESIN_DIR / f"{name}_clean_candidates_{run_id}.txt").write_text(
            text,
            encoding="utf-8",
        )
        (RESIN_DIR / f"{name}_clean_candidates.latest.txt").write_text(
            ("\n".join(rows) + "\n") if rows else "",
            encoding="utf-8",
        )

    lines = [
        "# Clean Candidate Classification 2026-06-08",
        "",
        f"- Run ID: `{run_id}`",
        f"- Clean candidates: {len(clean)}",
        f"- Residential priority: {counts['residential']}",
        f"- Static/education/business: {counts['static']}",
        f"- Risk review: {counts['risk_review']}",
        "",
        "## By Protocol",
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

    md = "\n".join(lines) + "\n"
    (RESIN_DIR / f"clean_candidate_classification_{run_id}.md").write_text(md, encoding="utf-8")
    (RESIN_DIR / "clean_candidate_classification.latest.md").write_text(md, encoding="utf-8")
    print(json.dumps({"run_id": run_id, "clean": len(clean), **counts}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
