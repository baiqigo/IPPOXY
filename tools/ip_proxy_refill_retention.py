#!/usr/bin/env python3
"""Prune per-run IP proxy refill artifacts while preserving latest aliases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ARTIFACT_PATTERNS: dict[str, list[str]] = {
    ".runtime/ip-proxy/research": [
        "layer0_http_socks_pool_*.json",
        "layer0_subscription_stage0_raw_*.json",
        "layer0_intake_manifest_*.json",
        "free_proxy_list_dynamic_sources_*.json",
        "free_proxy_list_subscription_sources_*.json",
        "subscription_stage0_raw_*.json",
        "subscription_stage0_summary_*.json",
        "proxy_candidate_check_*.json",
        "proxy_candidate_pool_*.json",
        "proxy_candidate_selection_*.json",
        "proxy_candidate_sandbox_live_*.json",
        "proxy_candidate_sandbox_promoted_*.json",
        "proxy_candidate_thin_live_*.json",
        "proxy_candidate_google_live_*.json",
        "proxy_source_quality_*.json",
        "proxy_source_quality_*.md",
    ],
    ".runtime/ip-proxy/resin": [
        "all_candidates_classified_*.json",
        "candidate_classification_guard_*.json",
        "clean_candidate_classification_*.md",
        "clean_candidates_classified_*.json",
        "clean_relaxed_candidates_*.txt",
        "dirty_candidates_classified_*.json",
        "l3_raw_candidates_*.txt",
        "l3_raw_candidates_classified_*.json",
        "relaxed_candidates_classified_*.json",
        "residential_clean_candidates_*.txt",
        "risk_review_clean_candidates_*.txt",
        "risky_relaxed_candidates_*.txt",
        "static_clean_candidates_*.txt",
        "turn_clean_candidates_*.txt",
    ],
}


def is_latest_alias(path: Path) -> bool:
    return ".latest." in path.name or path.name.endswith(".latest.json")


def prune_refill_artifacts(root: Path, keep_runs: int) -> dict:
    if keep_runs <= 0:
        return {
            "status": "refill_artifact_prune",
            "keep_runs": keep_runs,
            "deleted": 0,
            "deleted_bytes": 0,
            "disabled": True,
        }

    deleted: list[dict] = []
    for relative_root, patterns in ARTIFACT_PATTERNS.items():
        artifact_root = root / relative_root
        if not artifact_root.exists():
            continue
        for pattern in patterns:
            files = [path for path in artifact_root.glob(pattern) if path.is_file() and not is_latest_alias(path)]
            files.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
            for path in files[keep_runs:]:
                try:
                    size = path.stat().st_size
                    path.unlink()
                except OSError:
                    continue
                deleted.append({"path": str(path), "bytes": size})

    return {
        "status": "refill_artifact_prune",
        "keep_runs": keep_runs,
        "deleted": len(deleted),
        "deleted_bytes": sum(item["bytes"] for item in deleted),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--keep-runs", type=int, default=4)
    args = parser.parse_args()

    print(json.dumps(prune_refill_artifacts(args.root, args.keep_runs), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
