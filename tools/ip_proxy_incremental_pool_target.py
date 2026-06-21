#!/usr/bin/env python3
"""Compute the next runtime pool limit for incremental sandbox-live growth."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_rows(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = []
        for key in ("candidates", "results", "rows", "items"):
            value = data.get(key)
            if isinstance(value, list):
                rows = value
                break
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def row_exit(row: dict) -> str:
    return str(row.get("exit_ip") or row.get("trace_ip") or "").strip()


def is_sandbox_live(row: dict) -> bool:
    if bool(row.get("sandbox_live")) and row.get("success"):
        return True
    checked_from = str(row.get("checked_from") or row.get("live_checked_from") or "").lower()
    if checked_from in {"sandbox", "daytona", "daytona_sandbox"} and row.get("success"):
        return bool(row.get("trace_ip") or row.get("exit_ip"))
    live_check = row.get("live_check")
    if isinstance(live_check, dict):
        source = str(live_check.get("checked_from") or live_check.get("environment") or "").lower()
        ok = bool(live_check.get("success") or live_check.get("ok") or live_check.get("live"))
        if source in {"sandbox", "daytona", "daytona_sandbox"} and ok:
            return bool(live_check.get("trace_ip") or live_check.get("exit_ip") or row.get("exit_ip"))
    return False


def baseline_state(rows: list[dict]) -> tuple[int, set[str]]:
    seen_raw: set[str] = set()
    exits: set[str] = set()
    count = 0
    for row in rows:
        raw = str(row.get("turn") or row.get("raw") or "").strip()
        exit_ip = row_exit(row)
        if not raw or not exit_ip or raw in seen_raw or exit_ip in exits:
            continue
        seen_raw.add(raw)
        exits.add(exit_ip)
        count += 1
    return count, exits


def compute_incremental_target(
    *,
    target: int,
    baseline_rows: list[dict],
    sandbox_live_rows: list[dict],
) -> dict:
    baseline_count, baseline_exits = baseline_state(baseline_rows)
    live_exits = {
        row_exit(row)
        for row in sandbox_live_rows
        if is_sandbox_live(row) and row_exit(row)
    }
    new_live_exits = live_exits - baseline_exits
    effective_limit = min(max(0, target), baseline_count + len(new_live_exits))
    min_new_candidates = max(0, effective_limit - baseline_count)
    return {
        "status": "incremental_pool_target",
        "target": target,
        "effective_limit": effective_limit,
        "baseline_count": baseline_count,
        "sandbox_live_rows": len(sandbox_live_rows),
        "sandbox_live_exits": len(live_exits),
        "new_live_exits": len(new_live_exits),
        "min_new_candidates": min_new_candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=int, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--sandbox-live", type=Path, required=True)
    args = parser.parse_args()

    result = compute_incremental_target(
        target=args.target,
        baseline_rows=read_rows(args.baseline),
        sandbox_live_rows=read_rows(args.sandbox_live),
    )
    result["baseline"] = str(args.baseline)
    result["sandbox_live_input"] = str(args.sandbox_live)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
