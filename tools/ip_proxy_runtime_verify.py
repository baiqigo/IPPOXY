#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", "/home/daytona/IPPOXY"))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
MAPPING = Path(
    os.environ.get(
        "IP_PROXY_MAPPING_FILE",
        RUNTIME / "turn_xray_pool_20260608.json",
    )
)
if not MAPPING.exists():
    MAPPING = ROOT / "docs/ip-proxy/research/runtime/turn_xray_pool_20260608.json"
REGISTRAR_FEEDBACK = Path(os.environ.get("OUTLOOK_REGISTRAR_FEEDBACK_FILE", ROOT / "captures/ip_registrar_feedback_latest.json"))
IPIFY_URL = os.environ.get("IP_PROXY_VERIFY_IP_URL", "https://api.ipify.org")
TARGET_URL = os.environ.get(
    "IP_PROXY_VERIFY_TARGET_URL",
    os.environ.get("IP_PROXY_VERIFY_SIGNUP_URL", IPIFY_URL),
)


def curl(args: list[str], timeout: int = 25) -> str:
    proc = subprocess.run(["curl", "-fsS", "--max-time", str(timeout), *args], text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"curl failed: {proc.returncode}")
    return proc.stdout.strip()


def looks_like_ip(value: object) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def registrar_bad_exit_ips(path: Path) -> set[str]:
    data = read_json(path, {})
    if not isinstance(data, dict):
        return set()
    out: set[str] = set()
    for field in ("bad_exit_ips", "avoid_exit_ips"):
        values = data.get(field, [])
        if isinstance(values, list):
            out.update(str(item).strip() for item in values if str(item).strip())
    return out


def check_port(row: dict, timeout: int, ip_url: str) -> dict:
    port = int(row["local_port"])
    expected = str(row["exit_ip"])
    try:
        got = curl(["-x", f"socks5h://127.0.0.1:{port}", ip_url], timeout=timeout)
        ok = got == expected
    except Exception as exc:
        got = str(exc)
        ok = False
    return {"port": port, "expected": expected, "got": got, "ok": ok, "pool_class": row.get("pool_class"), "tag": row.get("tag")}


def check_resin_identity(
    identity: str,
    timeout: int,
    target_timeout: int,
    bad_exit_ips: set[str],
    ip_url: str,
    target_url: str,
) -> dict:
    try:
        socks_got = curl(["--proxy", "socks5h://127.0.0.1:2260", "-U", f"{identity}:daytona", ip_url], timeout=timeout)
        http_got = curl(["--proxy", f"http://{identity}:daytona@127.0.0.1:2260", ip_url], timeout=timeout)
        target_status = curl(
            [
                "--proxy",
                f"http://{identity}:daytona@127.0.0.1:2260",
                "-A",
                "Mozilla/5.0",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                target_url,
            ],
            timeout=target_timeout,
        )
        ok = bool(socks_got) and socks_got == http_got
        target_ok = target_status in {"200", "204", "301", "302", "303"}
        got: object = {"socks5h": socks_got, "http": http_got, "target_status": target_status, "signup_status": target_status}
        exit_ip = socks_got if looks_like_ip(socks_got) else ""
    except Exception as exc:
        got = str(exc)
        ok = False
        target_status = ""
        target_ok = False
        exit_ip = ""
    return {
        "identity": identity,
        "exit_ip": exit_ip,
        "got": got,
        "ok": ok,
        "target_status": target_status,
        "target_ok": target_ok,
        "signup_status": target_status,
        "signup_ok": target_ok,
        "bad_exit": bool(exit_ip and exit_ip in bad_exit_ips),
    }


def make_identities(platform: str, count: int, run_id: str) -> list[str]:
    return [f"{platform}.verify-{run_id}-{index:02d}" for index in range(max(0, count))]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=int(os.environ.get("IP_PROXY_VERIFY_WORKERS", "12")))
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("IP_PROXY_VERIFY_TIMEOUT", "25")))
    parser.add_argument("--target-timeout", type=int, default=int(os.environ.get("IP_PROXY_VERIFY_TARGET_TIMEOUT", os.environ.get("IP_PROXY_VERIFY_SIGNUP_TIMEOUT", "35"))))
    parser.add_argument("--signup-timeout", type=int, default=None, help="Backward-compatible alias for --target-timeout.")
    parser.add_argument("--res-identities", type=int, default=int(os.environ.get("IP_PROXY_VERIFY_RES_IDENTITIES", "24")))
    parser.add_argument("--static-identities", type=int, default=int(os.environ.get("IP_PROXY_VERIFY_STATIC_IDENTITIES", "8")))
    parser.add_argument("--all-identities", type=int, default=int(os.environ.get("IP_PROXY_VERIFY_ALL_IDENTITIES", "8")))
    parser.add_argument("--min-unique-res-exits", type=int, default=int(os.environ.get("IP_PROXY_MIN_UNIQUE_RES_EXITS", "12")))
    parser.add_argument("--ip-url", default=IPIFY_URL, help="Neutral endpoint returning the observed exit IP.")
    parser.add_argument("--target-url", default=TARGET_URL, help="Neutral target endpoint used for routed HTTP status checks.")
    parser.add_argument("--run-id", default=time.strftime("%Y%m%d%H%M%S", time.gmtime()))
    args = parser.parse_args()
    target_timeout = args.signup_timeout if args.signup_timeout is not None else args.target_timeout

    rows = json.loads(MAPPING.read_text(encoding="utf-8"))
    bad_exit_ips = registrar_bad_exit_ips(REGISTRAR_FEEDBACK)
    port_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [executor.submit(check_port, row, args.timeout, args.ip_url) for row in rows]
        for future in concurrent.futures.as_completed(futures):
            port_results.append(future.result())
    port_results.sort(key=lambda item: item.get("port", 0))

    identities = [
        *make_identities("IPPOXY_RES", args.res_identities, args.run_id),
        *make_identities("IPPOXY_STATIC", args.static_identities, args.run_id),
        *make_identities("IPPOXY_ALL", args.all_identities, args.run_id),
    ]
    resin_tests = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [
            executor.submit(check_resin_identity, identity, args.timeout, target_timeout, bad_exit_ips, args.ip_url, args.target_url)
            for identity in identities
        ]
        for future in concurrent.futures.as_completed(futures):
            resin_tests.append(future.result())
    resin_tests.sort(key=lambda item: item.get("identity", ""))

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
        "mapping_file": str(MAPPING),
        "registrar_feedback": str(REGISTRAR_FEEDBACK),
        "verify_ip_url": args.ip_url,
        "verify_target_url": args.target_url,
        "registrar_bad_exit_ips": sorted(bad_exit_ips),
        "ports_ok": sum(1 for item in port_results if item["ok"]),
        "ports_total": len(port_results),
        "resin_ok": sum(1 for item in resin_tests if item["ok"]),
        "resin_total": len(resin_tests),
        "resin_target_ok": sum(1 for item in resin_tests if item.get("target_ok")),
        "resin_signup_ok": sum(1 for item in resin_tests if item.get("signup_ok")),
        "resin_bad_exit_hits": sum(1 for item in resin_tests if item.get("bad_exit")),
        "unique_res_exit_ips": sorted({item["exit_ip"] for item in resin_tests if item.get("identity", "").startswith("IPPOXY_RES.") and item.get("exit_ip")}),
        "unique_static_exit_ips": sorted({item["exit_ip"] for item in resin_tests if item.get("identity", "").startswith("IPPOXY_STATIC.") and item.get("exit_ip")}),
        "unique_all_exit_ips": sorted({item["exit_ip"] for item in resin_tests if item.get("identity", "").startswith("IPPOXY_ALL.") and item.get("exit_ip")}),
        "port_results": port_results,
        "resin_tests": resin_tests,
        "health": health,
    }
    result["unique_res_exit_count"] = len(result["unique_res_exit_ips"])
    result["unique_static_exit_count"] = len(result["unique_static_exit_ips"])
    result["unique_all_exit_count"] = len(result["unique_all_exit_ips"])
    captures = ROOT / "captures"
    captures.mkdir(parents=True, exist_ok=True)
    (captures / "ip_runtime_verify_latest.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    min_ports_ok = int(os.environ.get("IP_PROXY_MIN_PORTS_OK", "23"))
    min_resin_ok = int(os.environ.get("IP_PROXY_MIN_RESIN_OK", str(len(identities))))
    if (
        result["ports_ok"] < min_ports_ok
        or result["resin_ok"] < min_resin_ok
        or result["resin_bad_exit_hits"] > 0
        or result["unique_res_exit_count"] < args.min_unique_res_exits
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
