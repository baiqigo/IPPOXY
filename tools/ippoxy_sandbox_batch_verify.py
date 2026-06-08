#!/usr/bin/env python3
"""One-shot sandbox verification runner for IPPOXY Outlook registration."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT_FILES = {
    "logged_email": ROOT / "Results/logged_email.txt",
    "oauth_pending": ROOT / "Results/oauth_pending.txt",
    "outlook_token": ROOT / "Results/outlook_token.txt",
    "unlogged_email": ROOT / "Results/unlogged_email.txt",
}


def line_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def result_counts() -> dict:
    return {name: line_count(path) for name, path in RESULT_FILES.items()}


def run(cmd: list[str], *, env: dict | None = None, log_path: Path | None = None, check: bool = False) -> dict:
    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = proc.stdout or ""
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(output, encoding="utf-8", errors="replace")
    result = {
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_s": round(time.time() - started, 2),
        "log_path": str(log_path) if log_path else "",
        "ok": proc.returncode == 0,
    }
    if check and proc.returncode != 0:
        raise RuntimeError(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def load_json(path: Path) -> object:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"error": f"json_decode_failed: {exc}", "path": str(path)}


def tail_result_detail(log_path: Path) -> dict:
    if not log_path.exists():
        return {}
    details = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("[ResultDetail] - "):
            continue
        try:
            details.append(json.loads(line.split(" - ", 1)[1]))
        except Exception as exc:
            details.append({"error": repr(exc), "line": line[:500]})
    return details[-1] if details else {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tasks", type=int, default=int(os.environ.get("OUTLOOK_BATCH_VERIFY_TASKS", "3")))
    parser.add_argument("--concurrent", type=int, default=int(os.environ.get("OUTLOOK_BATCH_VERIFY_CONCURRENT", "1")))
    parser.add_argument("--ip-failure-retries", type=int, default=int(os.environ.get("OUTLOOK_IP_FAILURE_RETRIES", "1")))
    parser.add_argument("--run-id", default=time.strftime("%Y%m%d_%H%M%S", time.gmtime()))
    parser.add_argument("--build", action="store_true", help="Run docker compose build outlook-register before the batch.")
    parser.add_argument("--dry-run", action="store_true", help="Only print planned commands and write no report.")
    parser.add_argument("--skip-release-check", action="store_true")
    args = parser.parse_args()

    captures = ROOT / "captures"
    report_path = captures / f"outlook_batch_verify_{args.run_id}.json"
    log_path = captures / f"outlook_batch_verify_{args.run_id}.log"
    env = os.environ.copy()
    env.update(
        {
            "OUTLOOK_MAX_TASKS": str(args.tasks),
            "OUTLOOK_CONCURRENT_FLOWS": str(args.concurrent),
            "OUTLOOK_IP_FAILURE_RETRIES": str(args.ip_failure_retries),
            "OUTLOOK_PROXY_PRECHECK": env.get("OUTLOOK_PROXY_PRECHECK", "1"),
        }
    )

    commands = []
    if not args.skip_release_check:
        commands.append([sys.executable, "tools/ippoxy_release_check.py"])
    if args.build:
        commands.append(["docker", "compose", "build", "outlook-register"])
    batch_cmd = ["docker", "compose", "run", "--rm", "outlook-register"]
    commands.append(batch_cmd)
    commands.append([sys.executable, "tools/ip_proxy_registrar_feedback.py"])
    commands.append([sys.executable, "tools/ip_proxy_pool_refresh.py", "--dry-run"])

    if args.dry_run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "report_path": str(report_path),
                    "log_path": str(log_path),
                    "env": {k: env[k] for k in sorted(env) if k.startswith("OUTLOOK_")},
                    "commands": commands,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    before = result_counts()
    steps = []
    for cmd in commands:
        step_log = log_path if cmd == batch_cmd else captures / f"outlook_batch_verify_{args.run_id}_{Path(cmd[0]).name}.log"
        steps.append(run(cmd, env=env, log_path=step_log, check=cmd != batch_cmd))

    after = result_counts()
    report = {
        "ok": True,
        "run_id": args.run_id,
        "tasks": args.tasks,
        "concurrent": args.concurrent,
        "ip_failure_retries": args.ip_failure_retries,
        "counts_before": before,
        "counts_after": after,
        "count_delta": {key: after.get(key, 0) - before.get(key, 0) for key in sorted(set(before) | set(after))},
        "steps": steps,
        "result_detail": tail_result_detail(log_path),
        "flow_stats": load_json(captures / "outlook_flow_stats_latest.json"),
        "registrar_feedback": load_json(captures / "ip_registrar_feedback_latest.json"),
        "pool_refresh": load_json(captures / "ip_pool_refresh_latest.json"),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    return 0 if all(step.get("ok") for step in steps[:-3]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
