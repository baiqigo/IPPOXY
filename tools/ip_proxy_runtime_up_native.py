#!/usr/bin/env python3
"""Start the IPPOXY Xray/Resin runtime without Docker."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
LOG_DIR = RUNTIME / "logs"
CONF_DIR = RUNTIME / "conf"
XRAY_CONF = Path(os.environ.get("IP_PROXY_XRAY_CONF", CONF_DIR / "xray_turn_pool_25.generated.json"))
XRAY_PID = Path(os.environ.get("IP_PROXY_XRAY_PID", RUNTIME / "xray-turn-pool-25.pid"))
RESIN_PID = Path(os.environ.get("IP_PROXY_RESIN_PID", RUNTIME / "resin.pid"))
RESIN_ROOT = ROOT / ".runtime/resin"
REPORT = ROOT / "captures/ip_runtime_up_native_latest.json"


def resolve_binary(env_name: str, default_name: str) -> dict:
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


def run(cmd: list[str], *, timeout: int = 30) -> dict:
    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "duration_s": round(time.time() - started, 2),
        "ok": proc.returncode == 0,
        "output_tail": (proc.stdout or "")[-3000:],
    }


def planned_step(cmd: list[str], reason: str) -> dict:
    return {"cmd": cmd, "status": "planned", "ok": True, "reason": reason}


def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def process_cmd(pid: int) -> str:
    if os.name == "nt":
        return ""
    try:
        proc = subprocess.run(["ps", "-p", str(pid), "-o", "args="], text=True, capture_output=True)
        return proc.stdout.strip()
    except Exception:
        return ""


def stop_pid_file(path: Path, labels: tuple[str, ...], *, dry_run: bool) -> dict:
    if not path.exists():
        return {"pid_file": str(path), "status": "missing"}
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    try:
        pid = int(raw)
    except ValueError:
        return {"pid_file": str(path), "status": "invalid_pid", "raw": raw}
    if not pid_exists(pid):
        if not dry_run:
            path.unlink(missing_ok=True)
        return {"pid_file": str(path), "status": "stale", "pid": pid}
    cmd = process_cmd(pid)
    if cmd and not any(label.lower() in cmd.lower() for label in labels):
        return {"pid_file": str(path), "status": "refused_foreign_process", "ok": False, "pid": pid, "cmd": cmd[:500]}
    if dry_run:
        return {"pid_file": str(path), "status": "would_stop", "ok": True, "pid": pid, "cmd": cmd[:500]}
    os.kill(pid, signal.SIGTERM)
    for _ in range(20):
        if not pid_exists(pid):
            break
        time.sleep(0.25)
    if pid_exists(pid):
        os.kill(pid, signal.SIGKILL)
    path.unlink(missing_ok=True)
    return {"pid_file": str(path), "status": "stopped", "ok": True, "pid": pid, "cmd": cmd[:500]}


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def wait_port(port: int, *, expect_open: bool, timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if port_open(port) is expect_open:
            return True
        time.sleep(0.25)
    return port_open(port) is expect_open


def wait_resin_health(timeout_s: float = 30.0) -> dict:
    deadline = time.time() + timeout_s
    last_error = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:2260/healthz", timeout=2) as resp:
                body = resp.read()
                return {"ok": True, "status": resp.status, "bytes": len(body)}
        except Exception as exc:
            last_error = str(exc)
            time.sleep(0.5)
    return {"ok": False, "error": last_error}


def start_process(cmd: list[str], env: dict, pid_file: Path, log_file: Path, *, dry_run: bool) -> dict:
    item = {"cmd": cmd, "pid_file": str(pid_file), "log_file": str(log_file), "dry_run": dry_run}
    if dry_run:
        item["status"] = "planned"
        return item
    log_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    stream = log_file.open("ab")
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
    stream.close()
    time.sleep(0.5)
    if proc.poll() is not None:
        log_tail = ""
        if log_file.exists():
            log_tail = log_file.read_text(encoding="utf-8", errors="replace")[-3000:]
        pid_file.unlink(missing_ok=True)
        item.update(
            {
                "status": "exited_early",
                "ok": False,
                "returncode": proc.returncode,
                "output_tail": log_tail,
            }
        )
        return item
    pid_file.write_text(str(proc.pid) + "\n", encoding="utf-8")
    item["status"] = "started"
    item["ok"] = True
    item["pid"] = proc.pid
    return item


def prepare_dirs() -> None:
    for path in (
        LOG_DIR,
        CONF_DIR,
        RESIN_ROOT / "cache",
        RESIN_ROOT / "state",
        RESIN_ROOT / "log",
        ROOT / "captures",
    ):
        path.mkdir(parents=True, exist_ok=True)
    if not XRAY_CONF.exists():
        fallback = ROOT / "docs/ip-proxy/resin/xray_turn_pool_25.generated.json"
        if fallback.exists():
            shutil.copy2(fallback, XRAY_CONF)


def write_report(report: dict, path: Path = REPORT) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Start IPPOXY Xray/Resin runtime without Docker.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-xray", action="store_true")
    parser.add_argument("--skip-resin", action="store_true")
    parser.add_argument("--skip-resin-configure", action="store_true")
    parser.add_argument(
        "--resin-force-replace",
        action="store_true",
        default=os.environ.get("RESIN_FORCE_REPLACE", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="Configure Resin in repair mode: do not preserve incremental alive nodes and shorten platform sticky TTLs.",
    )
    parser.add_argument("--no-stop", action="store_true", help="Do not stop existing PID-file processes before start.")
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()

    resin_configure_cmd = [sys.executable, "tools/ip_proxy_resin_configure.py"]
    if args.resin_force_replace:
        resin_configure_cmd.append("--force-replace")
    xray_bin = resolve_binary("XRAY_BIN", "xray")
    resin_bin = resolve_binary("RESIN_BIN", "resin")
    report = {
        "ts": int(time.time()),
        "root": str(ROOT),
        "runtime": str(RUNTIME),
        "dry_run": bool(args.dry_run),
        "resin_force_replace": bool(args.resin_force_replace),
        "binaries": {"xray": xray_bin, "resin": resin_bin},
        "commands": {
            "xray_test": [xray_bin["path"] or xray_bin["candidate"], "run", "-test", "-config", str(XRAY_CONF)],
            "xray_start": [xray_bin["path"] or xray_bin["candidate"], "run", "-config", str(XRAY_CONF)],
            "resin_start": [resin_bin["path"] or resin_bin["candidate"]],
            "resin_configure": resin_configure_cmd,
        },
        "steps": [],
    }
    prepare_dirs()

    missing = []
    if not args.skip_xray and not xray_bin["exists"]:
        missing.append("XRAY_BIN")
    if not args.skip_resin and not resin_bin["exists"]:
        missing.append("RESIN_BIN")
    report["missing_binaries"] = missing
    if missing and not args.dry_run:
        report["status"] = "missing_binaries"
        write_report(report, args.report)
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return 2

    if not args.skip_xray and args.dry_run:
        report["steps"].append(planned_step(report["commands"]["xray_test"], "dry_run"))
    if not args.skip_xray and xray_bin["exists"] and not args.dry_run:
        report["steps"].append(run([xray_bin["path"], "run", "-test", "-config", str(XRAY_CONF)], timeout=60))
        if not report["steps"][-1]["ok"]:
            report["status"] = "xray_config_invalid"
            write_report(report, args.report)
            print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
            return 1

    if not args.no_stop:
        if not args.skip_xray:
            report["steps"].append(stop_pid_file(XRAY_PID, ("xray", "ippoxy"), dry_run=args.dry_run))
        if not args.skip_resin:
            report["steps"].append(stop_pid_file(RESIN_PID, ("resin", "ippoxy"), dry_run=args.dry_run))
        refused = [step for step in report["steps"] if step.get("status") == "refused_foreign_process"]
        if refused:
            report["status"] = "refused_foreign_process"
            write_report(report, args.report)
            print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
            return 1

    env = os.environ.copy()
    if not args.skip_xray:
        report["steps"].append(
            start_process(
                [xray_bin["path"] or xray_bin["candidate"], "run", "-config", str(XRAY_CONF)],
                env,
                XRAY_PID,
                LOG_DIR / "xray-turn-pool-native.log",
                dry_run=args.dry_run,
            )
        )
    if not args.skip_resin:
        resin_env = env.copy()
        resin_env.update(
            {
                "RESIN_AUTH_VERSION": resin_env.get("RESIN_AUTH_VERSION", "V1"),
                "RESIN_ADMIN_TOKEN": resin_env.get("RESIN_ADMIN_TOKEN", "daytona-admin"),
                "RESIN_PROXY_TOKEN": resin_env.get("RESIN_PROXY_TOKEN", "daytona"),
                "RESIN_LISTEN_ADDRESS": resin_env.get("RESIN_LISTEN_ADDRESS", "127.0.0.1"),
                "RESIN_PORT": resin_env.get("RESIN_PORT", "2260"),
                "RESIN_CACHE_DIR": resin_env.get("RESIN_CACHE_DIR", str(RESIN_ROOT / "cache")),
                "RESIN_STATE_DIR": resin_env.get("RESIN_STATE_DIR", str(RESIN_ROOT / "state")),
                "RESIN_LOG_DIR": resin_env.get("RESIN_LOG_DIR", str(RESIN_ROOT / "log")),
            }
        )
        report["resin_env"] = {
            key: resin_env[key]
            for key in (
                "RESIN_AUTH_VERSION",
                "RESIN_LISTEN_ADDRESS",
                "RESIN_PORT",
                "RESIN_CACHE_DIR",
                "RESIN_STATE_DIR",
                "RESIN_LOG_DIR",
            )
        }
        report["steps"].append(
            start_process(
                [resin_bin["path"] or resin_bin["candidate"]],
                resin_env,
                RESIN_PID,
                LOG_DIR / "resin-native.log",
                dry_run=args.dry_run,
            )
        )

    if args.dry_run:
        if not args.skip_resin and not args.skip_resin_configure:
            report["steps"].append(planned_step(report["commands"]["resin_configure"], "dry_run"))
        report["status"] = "dry_run"
        write_report(report, args.report)
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return 0

    checks = {}
    if not args.skip_xray:
        checks["xray_19080_open"] = wait_port(19080, expect_open=True, timeout_s=15)
        checks["xray_19104_open"] = wait_port(19104, expect_open=True, timeout_s=15)
    if not args.skip_resin:
        checks["resin_health"] = wait_resin_health(timeout_s=45)
        if checks["resin_health"].get("ok") and not args.skip_resin_configure:
            report["steps"].append(run(resin_configure_cmd, timeout=90))
    report["checks"] = checks
    ok = all(value is True for key, value in checks.items() if key.startswith("xray_"))
    resin_health = checks.get("resin_health")
    if isinstance(resin_health, dict):
        ok = ok and bool(resin_health.get("ok"))
    ok = ok and all(step.get("ok", True) for step in report["steps"])
    report["status"] = "ok" if ok else "verify_failed"
    write_report(report, args.report)
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
