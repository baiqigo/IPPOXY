#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", "/home/daytona/IPPOXY"))
MAPPING = ROOT / "docs/ip-proxy/research/runtime/turn_xray_pool_20260608.json"


def curl(args: list[str], timeout: int = 25) -> str:
    proc = subprocess.run(["curl", "-fsS", "--max-time", str(timeout), *args], text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"curl failed: {proc.returncode}")
    return proc.stdout.strip()


def main() -> None:
    rows = json.loads(MAPPING.read_text(encoding="utf-8"))
    port_results = []
    for row in rows:
        port = int(row["local_port"])
        expected = str(row["exit_ip"])
        try:
            got = curl(["-x", f"socks5h://127.0.0.1:{port}", "https://api.ipify.org"])
            ok = got == expected
        except Exception as exc:
            got = str(exc)
            ok = False
        port_results.append({"port": port, "expected": expected, "got": got, "ok": ok})

    resin_tests = []
    for identity in ("IPPOXY_RES.test1", "IPPOXY_STATIC.test1", "IPPOXY_ALL.test1"):
        try:
            got = curl(["--proxy", "socks5h://127.0.0.1:2260", "-U", f"{identity}:daytona", "https://api.ipify.org"], timeout=35)
            ok = bool(got)
        except Exception as exc:
            got = str(exc)
            ok = False
        resin_tests.append({"identity": identity, "got": got, "ok": ok})

    health = {}
    admin_token = os.environ.get("RESIN_ADMIN_TOKEN", "daytona-admin")
    for path in ("/healthz", "/api/v1/nodes?limit=200", "/api/v1/platforms?limit=200"):
        try:
            headers = {"Authorization": f"Bearer {admin_token}"} if path.startswith("/api/") else {}
            req = urllib.request.Request(f"http://127.0.0.1:2260{path}", headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                health[path] = {"status": resp.status, "bytes": len(resp.read())}
        except Exception as exc:
            health[path] = {"error": str(exc)}

    result = {
        "ts": int(time.time()),
        "ports_ok": sum(1 for item in port_results if item["ok"]),
        "ports_total": len(port_results),
        "resin_ok": sum(1 for item in resin_tests if item["ok"]),
        "resin_total": len(resin_tests),
        "port_results": port_results,
        "resin_tests": resin_tests,
        "health": health,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["ports_ok"] < 1 or result["resin_ok"] < 1:
        sys.exit(1)


if __name__ == "__main__":
    main()
