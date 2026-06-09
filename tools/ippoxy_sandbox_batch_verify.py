#!/usr/bin/env python3
"""One-shot sandbox verification runner for IPPOXY Outlook registration."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mailhub_client import get_outlook_stats
RESULT_FILES = {
    "logged_email": ROOT / "Results/logged_email.txt",
    "oauth_pending": ROOT / "Results/oauth_pending.txt",
    "outlook_token": ROOT / "Results/outlook_token.txt",
    "unlogged_email": ROOT / "Results/unlogged_email.txt",
}
IP_RUNTIME = ROOT / ".runtime/ip-proxy"
DEFAULT_OUTLOOK_PROXY = "http://IPPOXY_RES.outlook-register:daytona@127.0.0.1:2260"
PROXY_PLATFORM_PREFIXES = {
    "res": "IPPOXY_RES",
    "static": "IPPOXY_STATIC",
    "all": "IPPOXY_ALL",
}
SOURCE_QUALITY_JSON = IP_RUNTIME / "research/proxy_source_quality_latest.json"
SOURCE_QUALITY_MD = IP_RUNTIME / "research/proxy_source_quality_latest.md"
PROXY_CANDIDATE_CHECK = IP_RUNTIME / "research/proxy_candidate_check.latest.json"
IP_FAILURE_REASONS = {"entry_failed", "proxy_precheck_bad_exit", "rate_or_abnormal_after_profile"}
PROGRAM_FAILURE_REASONS = {
    "flow_exception",
    "register_exception",
    "token_auth_failed",
    "mailhub_import_failed",
    "oauth_pending_not_ready",
}
MAILHUB_ENV_KEYS = (
    "MAIL_HUB_URL",
    "MAIL_HUB_API_SECRET",
    "MAILPILOT_TOKEN",
    "MAILPILOT_API_KEY",
    "MAILPILOT_API_SECRET",
)
MAILHUB_STAT_KEYS = (
    "total",
    "available",
    "assigned",
    "validToken",
    "invalidToken",
    "pendingOAuth",
    "noToken",
)


def load_env_defaults(path: Path = ROOT / ".env") -> dict:
    if not path.exists():
        return {"path": str(path), "loaded": False}
    loaded = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in MAILHUB_ENV_KEYS or os.environ.get(key):
            continue
        value = value.strip().strip('"').strip("'")
        os.environ[key] = value
        loaded.append(key)
    return {"path": str(path), "loaded": bool(loaded), "keys": loaded}


def default_proxy_for_platform(platform: str) -> str:
    prefix = PROXY_PLATFORM_PREFIXES[platform]
    return f"http://{prefix}.outlook-register:daytona@127.0.0.1:2260"


def pool_mode_for_platform(platform: str) -> str:
    return "relaxed" if platform == "all" else "strict"


def summarize_mailhub_stats(result: object) -> dict:
    if not isinstance(result, dict):
        return {}
    data = result.get("data")
    if not isinstance(data, dict):
        return {}
    return {key: data.get(key) for key in MAILHUB_STAT_KEYS if key in data}


def public_mailhub_result(result: object) -> dict:
    if not isinstance(result, dict):
        return {"ok": False, "error": "invalid_result"}
    output = {
        "enabled": result.get("enabled"),
        "ok": result.get("ok"),
        "status": result.get("status"),
        "counts": summarize_mailhub_stats(result),
    }
    if result.get("error"):
        output["error"] = str(result.get("error"))[:300]
    return output


def mailhub_stats_delta(before: dict, after: dict) -> dict:
    delta = {}
    for key in sorted(set(before) | set(after)):
        try:
            delta[key] = int(after.get(key) or 0) - int(before.get(key) or 0)
        except (TypeError, ValueError):
            delta[key] = None
    return delta


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


def file_artifact(path: Path) -> dict:
    return {
        "path": str(path),
        "exists": path.exists(),
        "size": path.stat().st_size if path.exists() else 0,
    }


def compact_source_quality(data: object) -> dict:
    if not isinstance(data, dict):
        return {}
    by_source = data.get("by_source") if isinstance(data.get("by_source"), dict) else {}
    cooldown_sources = data.get("cooldown_sources") if isinstance(data.get("cooldown_sources"), dict) else {}
    top_names = data.get("top_sources_by_clean") if isinstance(data.get("top_sources_by_clean"), list) else []
    top_details = []
    for source in top_names[:5]:
        item = by_source.get(str(source), {})
        if not isinstance(item, dict):
            item = {}
        top_details.append(
            {
                "source": str(source),
                "total": item.get("total", 0),
                "success": item.get("success", 0),
                "clean": item.get("clean", 0),
                "success_rate_pct": item.get("success_rate_pct", 0),
                "clean_rate_pct": item.get("clean_rate_pct", 0),
                "cooldown_recommended": bool(item.get("cooldown_recommended")),
                "cooldown_reason": item.get("cooldown_reason", ""),
            }
        )
    return {
        "total": data.get("total", 0),
        "success": data.get("success", 0),
        "clean": data.get("clean", 0),
        "source_count": data.get("source_count", len(by_source)),
        "by_kind": data.get("by_kind", {}),
        "top_sources_by_clean": top_names[:8],
        "top_source_details": top_details,
        "cooldown_source_count": len(cooldown_sources),
        "cooldown_sources": cooldown_sources,
        "cooldown_policy": data.get("cooldown_policy", {}),
    }


def _as_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _failure_reasons(result_detail: object, flow_stats: object) -> dict[str, int]:
    for source in (result_detail, flow_stats):
        if not isinstance(source, dict):
            continue
        reasons = source.get("failure_reasons")
        if isinstance(reasons, dict):
            parsed = {str(key): _as_int(value) for key, value in reasons.items() if _as_int(value) > 0}
            if parsed:
                return parsed
    return {}


def batch_diagnosis(
    result_detail: object,
    flow_stats: object,
    count_delta: dict,
    mailhub_delta: dict | None = None,
) -> dict:
    reasons = _failure_reasons(result_detail, flow_stats)
    challenge_reasons = {key: value for key, value in reasons.items() if key.startswith("challenge_failed_")}
    ip_reasons = {key: value for key, value in reasons.items() if key in IP_FAILURE_REASONS}
    program_reasons = {key: value for key, value in reasons.items() if key in PROGRAM_FAILURE_REASONS}
    other_reasons = {
        key: value
        for key, value in reasons.items()
        if key not in ip_reasons and key not in program_reasons and key not in challenge_reasons
    }
    lane_counts = {
        "ip_entry": sum(ip_reasons.values()),
        "challenge": sum(challenge_reasons.values()),
        "program": sum(program_reasons.values()),
        "other": sum(other_reasons.values()),
    }
    dominant_lane = "none"
    if any(lane_counts.values()):
        dominant_lane = max(lane_counts, key=lambda key: (lane_counts[key], key))
        if lane_counts[dominant_lane] <= 0:
            dominant_lane = "none"

    token_delta = _as_int(count_delta.get("outlook_token")) if isinstance(count_delta, dict) else 0
    logged_delta = _as_int(count_delta.get("logged_email")) if isinstance(count_delta, dict) else 0
    mailhub_total_delta = _as_int(mailhub_delta.get("total")) if isinstance(mailhub_delta, dict) else 0
    status = "success_progress" if token_delta > 0 or mailhub_total_delta > 0 else "no_token_progress"
    if program_reasons:
        status = "program_failure_present"
    elif dominant_lane == "ip_entry":
        status = "ip_entry_blocked"
    elif dominant_lane == "challenge":
        status = "challenge_blocked"
    elif dominant_lane == "other" and other_reasons:
        status = "unclassified_failure_present"

    return {
        "status": status,
        "dominant_lane": dominant_lane,
        "lane_counts": lane_counts,
        "ip_reasons": ip_reasons,
        "challenge_reasons": challenge_reasons,
        "program_reasons": program_reasons,
        "other_reasons": other_reasons,
        "token_delta": token_delta,
        "logged_email_delta": logged_delta,
        "mailhub_total_delta": mailhub_total_delta,
        "needs_program_fix": bool(program_reasons),
        "needs_ip_refresh": bool(ip_reasons) and lane_counts["ip_entry"] >= lane_counts["challenge"],
        "needs_challenge_evidence_or_manual_fallback": bool(challenge_reasons),
        "fresh_token_or_mailhub_progress": token_delta > 0 or mailhub_total_delta > 0,
    }


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
    parser.add_argument(
        "--runner",
        choices=["native", "docker"],
        default=os.environ.get("OUTLOOK_BATCH_VERIFY_RUNNER", "native"),
        help="Run the registration batch directly with Python or via docker compose.",
    )
    parser.add_argument("--build", action="store_true", help="Run docker compose build outlook-register before a docker batch.")
    parser.add_argument(
        "--proxy-platform",
        choices=sorted(PROXY_PLATFORM_PREFIXES),
        default=os.environ.get("OUTLOOK_PROXY_PLATFORM", "res"),
        help="Default Resin platform when OUTLOOK_PROXY is not set. Use all for relaxed pool tests.",
    )
    parser.add_argument(
        "--force-proxy-platform",
        action="store_true",
        default=os.environ.get("OUTLOOK_FORCE_PROXY_PLATFORM", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="Use --proxy-platform even when OUTLOOK_PROXY is already set in the environment.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only print planned commands and write a dry-run report.")
    parser.add_argument("--skip-release-check", action="store_true")
    args = parser.parse_args()

    captures = ROOT / "captures"
    report_path = captures / f"outlook_batch_verify_{args.run_id}.json"
    log_path = captures / f"outlook_batch_verify_{args.run_id}.log"
    flow_stats_dir = captures / f"outlook_flow_{args.run_id}"
    flow_events_path = flow_stats_dir / "outlook_flow_events.jsonl"
    registrar_feedback_path = captures / f"ip_registrar_feedback_{args.run_id}.json"
    registrar_feedback_latest_path = captures / "ip_registrar_feedback_latest.json"
    pool_refresh_latest_path = captures / "ip_pool_refresh_latest.json"
    env = os.environ.copy()
    inherited_outlook_proxy = env.get("OUTLOOK_PROXY")
    selected_outlook_proxy = default_proxy_for_platform(args.proxy_platform) if args.force_proxy_platform else env.get("OUTLOOK_PROXY", default_proxy_for_platform(args.proxy_platform))
    env.update(
        {
            "OUTLOOK_MAX_TASKS": str(args.tasks),
            "OUTLOOK_CONCURRENT_FLOWS": str(args.concurrent),
            "OUTLOOK_IP_FAILURE_RETRIES": str(args.ip_failure_retries),
            "OUTLOOK_PROXY_PRECHECK": env.get("OUTLOOK_PROXY_PRECHECK", "1"),
            "OUTLOOK_PROXY": selected_outlook_proxy,
            "OUTLOOK_PROXY_PLATFORM": args.proxy_platform,
            "OUTLOOK_PROXY_STICKY_MODE": env.get("OUTLOOK_PROXY_STICKY_MODE", "flow"),
            "OUTLOOK_FLOW_STATS_DIR": env.get("OUTLOOK_FLOW_STATS_DIR", str(flow_stats_dir)),
        }
    )

    commands = []
    if not args.skip_release_check:
        release_cmd = [sys.executable, "tools/ippoxy_release_check.py"]
        if args.runner == "native":
            release_cmd.append("--skip-docker")
        commands.append(release_cmd)
    if args.runner == "native":
        commands.append([sys.executable, "tools/ippoxy_native_env_check.py"])
    build_skipped = False
    if args.build and args.runner == "docker":
        commands.append(["docker", "compose", "build", "outlook-register"])
    elif args.build:
        build_skipped = True
    if args.runner == "docker":
        batch_cmd = ["docker", "compose", "run", "--rm", "outlook-register"]
    else:
        batch_cmd = [sys.executable, "main.py"]
        if shutil.which("xvfb-run") and os.environ.get("OUTLOOK_HEADLESS", "").strip().lower() not in ("1", "true", "yes"):
            batch_cmd = ["xvfb-run", "-a", *batch_cmd]
    commands.append(batch_cmd)
    feedback_cmd = [
        sys.executable,
        "tools/ip_proxy_registrar_feedback.py",
        "--events",
        str(flow_events_path),
        "--out",
        str(registrar_feedback_path),
    ]
    pool_refresh_cmd = [
        sys.executable,
        "tools/ip_proxy_pool_refresh.py",
        "--dry-run",
        "--pool-mode",
        pool_mode_for_platform(args.proxy_platform),
        "--registrar-feedback",
        str(registrar_feedback_path),
    ]
    commands.append(feedback_cmd)
    commands.append(pool_refresh_cmd)

    if args.dry_run:
        report = {
            "dry_run": True,
            "runner": args.runner,
            "build_skipped": build_skipped,
            "proxy_platform": args.proxy_platform,
            "force_proxy_platform": args.force_proxy_platform,
            "inherited_outlook_proxy_set": bool(inherited_outlook_proxy),
            "pool_mode": pool_mode_for_platform(args.proxy_platform),
            "report_path": str(report_path),
            "log_path": str(log_path),
            "env": {k: env[k] for k in sorted(env) if k.startswith("OUTLOOK_")},
            "commands": commands,
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                report,
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    mailhub_env = load_env_defaults()
    before = result_counts()
    mailhub_before_result = get_outlook_stats()
    mailhub_before = summarize_mailhub_stats(mailhub_before_result)
    steps = []
    for cmd in commands:
        step_log = log_path if cmd == batch_cmd else captures / f"outlook_batch_verify_{args.run_id}_{Path(cmd[0]).name}.log"
        steps.append(run(cmd, env=env, log_path=step_log, check=cmd != batch_cmd))
    registrar_feedback = load_json(registrar_feedback_path)
    pool_refresh = load_json(pool_refresh_latest_path)
    if registrar_feedback_path.exists():
        registrar_feedback_latest_path.write_text(
            json.dumps(registrar_feedback, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )

    after = result_counts()
    mailhub_after_result = get_outlook_stats()
    mailhub_after = summarize_mailhub_stats(mailhub_after_result)
    mailhub_delta = mailhub_stats_delta(mailhub_before, mailhub_after)
    source_quality = load_json(SOURCE_QUALITY_JSON)
    flow_stats_path = Path(env["OUTLOOK_FLOW_STATS_DIR"]) / "outlook_flow_stats_latest.json"
    flow_stats = load_json(flow_stats_path)
    count_delta = {key: after.get(key, 0) - before.get(key, 0) for key in sorted(set(before) | set(after))}
    result_detail = tail_result_detail(log_path)
    report = {
        "ok": True,
        "run_id": args.run_id,
        "runner": args.runner,
        "build_skipped": build_skipped,
        "proxy_platform": args.proxy_platform,
        "pool_mode": pool_mode_for_platform(args.proxy_platform),
        "tasks": args.tasks,
        "concurrent": args.concurrent,
        "ip_failure_retries": args.ip_failure_retries,
        "counts_before": before,
        "counts_after": after,
        "count_delta": count_delta,
        "mailhub_env": mailhub_env,
        "mailhub_stats_before": public_mailhub_result(mailhub_before_result),
        "mailhub_stats_after": public_mailhub_result(mailhub_after_result),
        "mailhub_stats_delta": mailhub_delta,
        "steps": steps,
        "result_detail": result_detail,
        "flow_stats": flow_stats,
        "registrar_feedback": registrar_feedback,
        "pool_refresh": pool_refresh,
        "source_quality": source_quality,
        "source_quality_summary": compact_source_quality(source_quality),
        "batch_diagnosis": batch_diagnosis(result_detail, flow_stats, count_delta, mailhub_delta),
        "artifacts": {
            "flow_stats": file_artifact(flow_stats_path),
            "flow_events": file_artifact(flow_events_path),
            "registrar_feedback": file_artifact(registrar_feedback_path),
            "registrar_feedback_latest": file_artifact(registrar_feedback_latest_path),
            "pool_refresh": file_artifact(pool_refresh_latest_path),
            "source_quality_json": file_artifact(SOURCE_QUALITY_JSON),
            "source_quality_markdown": file_artifact(SOURCE_QUALITY_MD),
            "proxy_candidate_check": file_artifact(PROXY_CANDIDATE_CHECK),
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    return 0 if all(step.get("ok") for step in steps[:-3]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
