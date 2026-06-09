#!/usr/bin/env python3
"""Apply an IP proxy pool refresh with runtime verification and rollback."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
CAPTURES = ROOT / "captures"
REPORT = CAPTURES / "ip_refresh_apply_verify_latest.json"
RUNTIME_FILES = [
    RUNTIME / "turn_xray_pool_20260608.json",
    RUNTIME / "conf/xray_turn_pool_25.generated.json",
    RUNTIME / "resin/turn_xray_pool_25.local.txt",
    RUNTIME / "resin/turn_xray_pool.local.txt",
    RUNTIME / "resin/turn_vless_pool_25.txt",
]


def file_artifact(path: Path) -> dict:
    return {
        "path": str(path),
        "exists": path.exists(),
        "size": path.stat().st_size if path.exists() else 0,
    }


def run(cmd: list[str], *, check: bool = False) -> dict:
    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    item = {
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_s": round(time.time() - started, 2),
        "ok": proc.returncode == 0,
        "output_tail": (proc.stdout or "")[-4000:],
    }
    if check and proc.returncode != 0:
        raise RuntimeError(json.dumps(item, ensure_ascii=False, indent=2))
    return item


def skipped_step(name: str, reason: str) -> dict:
    return {"cmd": [], "name": name, "status": "skipped", "reason": reason, "ok": True}


def resolve_runtime_binary(env_name: str, default_name: str) -> dict:
    configured = os.environ.get(env_name, "").strip()
    candidate = configured or default_name
    path = shutil.which(candidate) or (candidate if Path(candidate).exists() else "")
    return {
        "env": env_name,
        "configured": configured,
        "candidate": candidate,
        "path": path,
        "exists": bool(path),
    }


def native_runtime_preflight() -> dict:
    binaries = {
        "xray": resolve_runtime_binary("XRAY_BIN", "xray"),
        "resin": resolve_runtime_binary("RESIN_BIN", "resin"),
    }
    missing = [item["env"] for item in binaries.values() if not item["exists"]]
    return {
        "cmd": [],
        "name": "native_runtime_preflight",
        "status": "ok" if not missing else "missing_binaries",
        "ok": not missing,
        "binaries": binaries,
        "missing_binaries": missing,
    }


def load_json(path: Path) -> object:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return {"error": f"json_decode_failed: {exc}", "path": str(path)}


def summarize_batch_report(path: Path) -> dict:
    if not path.exists():
        return {"path": str(path), "loaded": False, "reason": "missing_report"}
    data = load_json(path)
    if not isinstance(data, dict) or data.get("error"):
        return {"path": str(path), "loaded": False, "reason": "invalid_report"}
    diagnosis = data.get("batch_diagnosis") if isinstance(data.get("batch_diagnosis"), dict) else {}
    return {
        "path": str(path),
        "loaded": True,
        "ok": data.get("ok"),
        "run_id": data.get("run_id"),
        "count_delta": data.get("count_delta", {}),
        "mailhub_stats_delta": data.get("mailhub_stats_delta", {}),
        "batch_diagnosis": {
            "status": diagnosis.get("status"),
            "dominant_lane": diagnosis.get("dominant_lane"),
            "fresh_token_or_mailhub_progress": diagnosis.get("fresh_token_or_mailhub_progress"),
            "needs_ip_refresh": diagnosis.get("needs_ip_refresh"),
            "needs_challenge_evidence_or_manual_fallback": diagnosis.get("needs_challenge_evidence_or_manual_fallback"),
            "needs_program_fix": diagnosis.get("needs_program_fix"),
        },
    }


def runtime_up_command(runner: str, *, resin_force_replace: bool = False) -> list[str]:
    if runner == "native":
        cmd = [sys.executable, "tools/ip_proxy_runtime_up_native.py"]
        if resin_force_replace:
            cmd.append("--resin-force-replace")
        return cmd
    if runner == "docker":
        return ["bash", "tools/ip_proxy_runtime_up.sh"]
    return []


def backup_runtime_files(backup_dir: Path, files: list[Path] | None = None) -> dict:
    files = files or RUNTIME_FILES
    copied = []
    missing = []
    backup_dir.mkdir(parents=True, exist_ok=True)
    for path in files:
        rel = path.relative_to(RUNTIME)
        target = backup_dir / rel
        if path.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            copied.append(str(rel).replace("\\", "/"))
        else:
            missing.append(str(rel).replace("\\", "/"))
    return {"backup_dir": str(backup_dir), "copied": copied, "missing": missing}


def restore_runtime_files(backup_dir: Path, files: list[Path] | None = None) -> dict:
    files = files or RUNTIME_FILES
    restored = []
    skipped = []
    for path in files:
        rel = path.relative_to(RUNTIME)
        source = backup_dir / rel
        if source.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, path)
            restored.append(str(rel).replace("\\", "/"))
        else:
            skipped.append(str(rel).replace("\\", "/"))
    return {"backup_dir": str(backup_dir), "restored": restored, "skipped": skipped}


def write_report(report: dict, path: Path = REPORT) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely refresh the IPPOXY runtime pool and verify/rollback.")
    parser.add_argument("--apply", action="store_true", help="Actually write runtime files and restart Xray/Resin.")
    parser.add_argument("--skip-verify", action="store_true", help="Skip runtime verification after apply.")
    parser.add_argument("--no-rollback", action="store_true", help="Do not restore the previous runtime files on failure.")
    parser.add_argument(
        "--runtime-runner",
        choices=["native", "docker", "skip"],
        default=os.environ.get("IP_PROXY_RUNTIME_RUNNER", "native"),
        help="Runtime restart method after apply. native avoids Docker; skip only writes refreshed files.",
    )
    parser.add_argument("--run-batch", action="store_true", help="After a successful apply, run Outlook batch verification.")
    parser.add_argument("--batch-tasks", type=int, default=int(os.environ.get("OUTLOOK_BATCH_VERIFY_TASKS", "3")))
    parser.add_argument("--batch-concurrent", type=int, default=int(os.environ.get("OUTLOOK_BATCH_VERIFY_CONCURRENT", "1")))
    parser.add_argument("--batch-ip-failure-retries", type=int, default=int(os.environ.get("OUTLOOK_IP_FAILURE_RETRIES", "1")))
    parser.add_argument(
        "--batch-runner",
        choices=["native", "docker"],
        default=os.environ.get("OUTLOOK_BATCH_VERIFY_RUNNER", "native"),
        help="Runner forwarded to ippoxy_sandbox_batch_verify.py.",
    )
    parser.add_argument("--batch-run-id", default="")
    parser.add_argument("--batch-build", action="store_true", help="Build outlook-register before the post-refresh batch.")
    parser.add_argument("--batch-skip-release-check", action="store_true")
    parser.add_argument(
        "--batch-proxy-platform",
        choices=["res", "static", "all"],
        default=os.environ.get("OUTLOOK_BATCH_VERIFY_PROXY_PLATFORM", "res"),
        help="Proxy platform forwarded to ippoxy_sandbox_batch_verify.py.",
    )
    parser.add_argument(
        "--batch-force-proxy-platform",
        action="store_true",
        default=os.environ.get("OUTLOOK_BATCH_VERIFY_FORCE_PROXY_PLATFORM", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="Force the batch verifier to use --batch-proxy-platform even if OUTLOOK_PROXY is inherited.",
    )
    parser.add_argument("--pool-refresh-arg", action="append", default=[], help="Extra arg forwarded to ip_proxy_pool_refresh.py.")
    parser.add_argument(
        "--resin-force-replace",
        action="store_true",
        default=os.environ.get("RESIN_FORCE_REPLACE", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="When using native runtime, configure Resin in repair mode after refresh.",
    )
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()

    batch_run_id = args.batch_run_id or f"refresh_batch_{time.strftime('%Y%m%d_%H%M%S', time.gmtime())}"
    batch_report_path = CAPTURES / f"outlook_batch_verify_{batch_run_id}.json"
    batch_cmd = [
        sys.executable,
        "tools/ippoxy_sandbox_batch_verify.py",
        "--tasks",
        str(args.batch_tasks),
        "--concurrent",
        str(args.batch_concurrent),
        "--ip-failure-retries",
        str(args.batch_ip_failure_retries),
        "--runner",
        args.batch_runner,
        "--proxy-platform",
        args.batch_proxy_platform,
        "--run-id",
        batch_run_id,
    ]
    if args.batch_force_proxy_platform:
        batch_cmd.append("--force-proxy-platform")
    if args.batch_build:
        batch_cmd.append("--build")
    if args.batch_skip_release_check:
        batch_cmd.append("--skip-release-check")
    runtime_cmd = runtime_up_command(args.runtime_runner, resin_force_replace=args.resin_force_replace)

    backup_dir = RUNTIME / "backups" / time.strftime("refresh_%Y%m%d_%H%M%S", time.gmtime())
    report = {
        "ts": int(time.time()),
        "apply": bool(args.apply),
        "runtime_runner": args.runtime_runner,
        "resin_force_replace": bool(args.resin_force_replace),
        "runtime_cmd": runtime_cmd,
        "run_batch": bool(args.run_batch),
        "root": str(ROOT),
        "runtime": str(RUNTIME),
        "backup_dir": str(backup_dir),
        "post_refresh_batch": {
            "planned": bool(args.run_batch),
            "cmd": batch_cmd,
            "report_path": str(batch_report_path),
        },
        "runtime_files_before": [file_artifact(path) for path in RUNTIME_FILES],
        "steps": [],
    }

    if not args.apply:
        cmd = [sys.executable, "tools/ip_proxy_pool_refresh.py", "--dry-run", *args.pool_refresh_arg]
        report["steps"].append(run(cmd))
        report["runtime_files_after"] = [file_artifact(path) for path in RUNTIME_FILES]
        report["status"] = "dry_run"
        report["post_refresh_batch"]["planned"] = False
        report["post_refresh_batch"]["reason"] = "dry_run_no_runtime_switch"
        write_report(report, args.report)
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return 0 if report["steps"][-1]["ok"] else 1

    if args.runtime_runner == "native":
        preflight = native_runtime_preflight()
        report["steps"].append(preflight)
        if not preflight["ok"]:
            report["status"] = "native_runtime_preflight_failed"
            report["runtime_files_after"] = [file_artifact(path) for path in RUNTIME_FILES]
            write_report(report, args.report)
            print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
            return 2

    report["backup"] = backup_runtime_files(backup_dir)
    try:
        report["steps"].append(run([sys.executable, "tools/ip_proxy_pool_refresh.py", *args.pool_refresh_arg], check=True))
        if args.runtime_runner == "skip":
            report["steps"].append(skipped_step("runtime_up", "runtime_runner_skip"))
        else:
            report["steps"].append(run(runtime_cmd, check=True))
        if args.runtime_runner == "skip":
            report["steps"].append(skipped_step("runtime_verify", "runtime_runner_skip"))
        elif not args.skip_verify:
            report["steps"].append(run([sys.executable, "tools/ip_proxy_runtime_verify.py"], check=True))
        else:
            report["steps"].append(skipped_step("runtime_verify", "skip_verify"))
        if args.run_batch:
            report["steps"].append(run(batch_cmd, check=False))
            report["post_refresh_batch"]["summary"] = summarize_batch_report(batch_report_path)
        report["status"] = "ok" if args.runtime_runner != "skip" else "files_refreshed_runtime_skipped"
        exit_code = 0
        if args.run_batch and not report["steps"][-1]["ok"]:
            report["status"] = "batch_failed"
            exit_code = 1
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = str(exc)[:4000]
        exit_code = 1
        if not args.no_rollback:
            report["rollback"] = restore_runtime_files(backup_dir)
            if args.runtime_runner == "skip":
                report["steps"].append(skipped_step("runtime_up_rollback", "runtime_runner_skip"))
            else:
                report["steps"].append(run(runtime_cmd))
            if args.runtime_runner == "skip":
                report["steps"].append(skipped_step("runtime_verify_rollback", "runtime_runner_skip"))
            elif not args.skip_verify:
                report["steps"].append(run([sys.executable, "tools/ip_proxy_runtime_verify.py"]))
            else:
                report["steps"].append(skipped_step("runtime_verify_rollback", "skip_verify"))

    report["runtime_files_after"] = [file_artifact(path) for path in RUNTIME_FILES]
    write_report(report, args.report)
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
