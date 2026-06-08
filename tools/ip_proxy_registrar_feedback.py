#!/usr/bin/env python3
"""Convert registrar flow statistics into IP pool refresh feedback."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
DEFAULT_EVENTS = ROOT / "captures/outlook_flow_events.jsonl"
DEFAULT_OUT = ROOT / "captures/ip_registrar_feedback_latest.json"
RETRYABLE_IP_REASONS = {
    "entry_failed",
    "rate_or_abnormal_after_profile",
}


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def build_feedback(events: list[dict], min_failures: int, quarantine_reasons: set[str]) -> dict:
    attempts = [item for item in events if item.get("event") == "registration_attempt_result"]
    by_exit_ip: dict[str, Counter] = defaultdict(Counter)
    by_identity: dict[str, Counter] = defaultdict(Counter)
    unknown_exit_by_identity: dict[str, Counter] = defaultdict(Counter)
    precheck_errors = Counter()

    for item in attempts:
        reason = item.get("failure_reason") or ("success" if item.get("success") else "unknown")
        identity = item.get("proxy_identity") or "unknown"
        exit_probe = item.get("exit_probe") if isinstance(item.get("exit_probe"), dict) else {}
        exit_ip = str(exit_probe.get("ip") or "").strip() or "unknown"
        by_exit_ip[exit_ip][reason] += 1
        by_identity[identity][reason] += 1
        if exit_ip == "unknown":
            unknown_exit_by_identity[identity][reason] += 1
            if exit_probe.get("enabled"):
                precheck_errors[str(exit_probe.get("error") or "unknown_precheck_error")] += 1

    bad_exit_ips = []
    exit_details = {}
    for exit_ip, counts in sorted(by_exit_ip.items()):
        if exit_ip == "unknown":
            continue
        retryable_failures = sum(counts.get(reason, 0) for reason in quarantine_reasons)
        successes = counts.get("success", 0)
        if retryable_failures >= min_failures and successes == 0:
            bad_exit_ips.append(exit_ip)
            exit_details[exit_ip] = {
                "counts": dict(counts),
                "retryable_failures": retryable_failures,
                "successes": successes,
                "reason": "retryable_registrar_failures_without_success",
            }

    unknown_retryable_details = {}
    for identity, counts in sorted(unknown_exit_by_identity.items()):
        retryable_failures = sum(counts.get(reason, 0) for reason in quarantine_reasons)
        if retryable_failures:
            unknown_retryable_details[identity] = {
                "counts": dict(counts),
                "retryable_failures": retryable_failures,
                "reason": "retryable_failures_without_exit_ip_evidence",
            }

    return {
        "ts": int(time.time()),
        "attempts": len(attempts),
        "min_failures": min_failures,
        "quarantine_reasons": sorted(quarantine_reasons),
        "bad_exit_ips": bad_exit_ips,
        "bad_exit_details": exit_details,
        "unknown_exit_retryable_attempts": sum(
            item["retryable_failures"] for item in unknown_retryable_details.values()
        ),
        "unknown_exit_retryable_details": unknown_retryable_details,
        "precheck_errors": dict(precheck_errors),
        "by_exit_ip": {key: dict(value) for key, value in sorted(by_exit_ip.items())},
        "by_identity": {key: dict(value) for key, value in sorted(by_identity.items())},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--min-failures", type=int, default=int(os.environ.get("IP_PROXY_REGISTRAR_MIN_FAILURES", "2")))
    parser.add_argument(
        "--reason",
        action="append",
        dest="reasons",
        default=[],
        help="Failure reason that can contribute to bad-exit feedback. Defaults to IP/entry retryable reasons.",
    )
    args = parser.parse_args()

    reasons = set(args.reasons) if args.reasons else set(RETRYABLE_IP_REASONS)
    result = build_feedback(load_jsonl(args.events), max(1, args.min_failures), reasons)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
