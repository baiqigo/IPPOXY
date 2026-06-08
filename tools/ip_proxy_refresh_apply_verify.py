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
    parser.add_argument("--pool-refresh-arg", action="append", default=[], help="Extra arg forwarded to ip_proxy_pool_refresh.py.")
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()

    backup_dir = RUNTIME / "backups" / time.strftime("refresh_%Y%m%d_%H%M%S", time.gmtime())
    report = {
        "ts": int(time.time()),
        "apply": bool(args.apply),
        "root": str(ROOT),
        "runtime": str(RUNTIME),
        "backup_dir": str(backup_dir),
        "runtime_files_before": [file_artifact(path) for path in RUNTIME_FILES],
        "steps": [],
    }

    if not args.apply:
        cmd = [sys.executable, "tools/ip_proxy_pool_refresh.py", "--dry-run", *args.pool_refresh_arg]
        report["steps"].append(run(cmd))
        report["runtime_files_after"] = [file_artifact(path) for path in RUNTIME_FILES]
        report["status"] = "dry_run"
        write_report(report, args.report)
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return 0 if report["steps"][-1]["ok"] else 1

    report["backup"] = backup_runtime_files(backup_dir)
    try:
        report["steps"].append(run([sys.executable, "tools/ip_proxy_pool_refresh.py", *args.pool_refresh_arg], check=True))
        report["steps"].append(run(["bash", "tools/ip_proxy_runtime_up.sh"], check=True))
        if not args.skip_verify:
            report["steps"].append(run([sys.executable, "tools/ip_proxy_runtime_verify.py"], check=True))
        report["status"] = "ok"
        exit_code = 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = str(exc)[:4000]
        exit_code = 1
        if not args.no_rollback:
            report["rollback"] = restore_runtime_files(backup_dir)
            report["steps"].append(run(["bash", "tools/ip_proxy_runtime_up.sh"]))
            if not args.skip_verify:
                report["steps"].append(run([sys.executable, "tools/ip_proxy_runtime_verify.py"]))

    report["runtime_files_after"] = [file_artifact(path) for path in RUNTIME_FILES]
    write_report(report, args.report)
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
