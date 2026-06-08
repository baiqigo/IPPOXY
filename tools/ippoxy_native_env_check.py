#!/usr/bin/env python3
"""Check native no-Docker prerequisites for IPPOXY."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
import time
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
REPORT = ROOT / "captures/ippoxy_native_env_check_latest.json"
REQUIRED_MODULES = ("requests", "faker", "patchright")
OPTIONAL_MODULES = ("playwright",)


def load_config() -> dict:
    path = ROOT / "config.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        return {"_error": repr(exc)}


def module_status(name: str) -> dict:
    spec = importlib.util.find_spec(name)
    return {"name": name, "installed": spec is not None}


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


def path_status(path_value: str) -> dict:
    path = Path(path_value) if path_value else Path()
    return {"path": path_value, "configured": bool(path_value), "exists": bool(path_value and path.exists())}


def browser_status(config: dict) -> dict:
    choose_browser = str(config.get("choose_browser", "patchright")).strip() or "patchright"
    env_path = os.environ.get("OUTLOOK_BROWSER_PATH", "").strip()
    config_path = ""
    if choose_browser == "patchright":
        config_path = str((config.get("patchright") or {}).get("browser_path") or "").strip()
    elif choose_browser == "playwright":
        config_path = str((config.get("playwright") or {}).get("browser_path") or "").strip()
    effective = env_path or config_path
    candidates = [effective] if effective else []
    if os.name == "posix":
        candidates.extend(["/usr/bin/chromium", "/usr/bin/google-chrome", "/usr/bin/chromium-browser"])
    resolved = ""
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            resolved = candidate
            break
    return {
        "choose_browser": choose_browser,
        "env_path": env_path,
        "config_path": config_path,
        "effective_path": effective,
        "resolved_path": resolved,
        "exists": bool(resolved),
    }


def build_report(args: argparse.Namespace) -> dict:
    config = load_config()
    required_modules = [module_status(name) for name in REQUIRED_MODULES]
    optional_modules = [module_status(name) for name in OPTIONAL_MODULES]
    runtime_binaries = {
        "xray": resolve_binary("XRAY_BIN", "xray"),
        "resin": resolve_binary("RESIN_BIN", "resin"),
    }
    browser = browser_status(config)
    missing_modules = [item["name"] for item in required_modules if not item["installed"]]
    missing_runtime = [item["env"] for item in runtime_binaries.values() if not item["exists"]]
    missing_browser = not browser["exists"]
    failures = []
    if config.get("_error"):
        failures.append("config_json")
    if missing_modules:
        failures.append("python_modules")
    if missing_browser:
        failures.append("browser")
    if args.require_runtime and missing_runtime:
        failures.append("runtime_binaries")
    return {
        "ts": int(time.time()),
        "root": str(ROOT),
        "python": sys.executable,
        "platform": sys.platform,
        "require_runtime": bool(args.require_runtime),
        "config_error": config.get("_error", ""),
        "choose_browser": browser["choose_browser"],
        "required_modules": required_modules,
        "optional_modules": optional_modules,
        "browser": browser,
        "runtime_binaries": runtime_binaries,
        "missing_modules": missing_modules,
        "missing_runtime_binaries": missing_runtime,
        "failures": failures,
        "ok": not failures,
        "next_steps": {
            "install_python_deps": "python -m pip install -r requirements.txt",
            "set_browser": "Set OUTLOOK_BROWSER_PATH or config.json patchright.browser_path to an existing Chromium/Chrome binary.",
            "set_runtime": "Install xray/resin or set XRAY_BIN and RESIN_BIN before --runtime-runner native --apply.",
        },
    }


def write_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check native IPPOXY prerequisites without Docker.")
    parser.add_argument("--require-runtime", action="store_true", help="Fail if xray/resin binaries are missing.")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--json", action="store_true", help="Print full JSON only.")
    args = parser.parse_args()

    report = build_report(args)
    write_report(report, args.report)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    else:
        print(
            json.dumps(
                {
                    "ok": report["ok"],
                    "failures": report["failures"],
                    "missing_modules": report["missing_modules"],
                    "browser": report["browser"],
                    "missing_runtime_binaries": report["missing_runtime_binaries"],
                    "report": str(args.report),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
