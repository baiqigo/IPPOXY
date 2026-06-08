#!/usr/bin/env python3
"""Harvest and check IPPOXY proxy candidates.

This script only checks explicitly collected candidates through the public
cmliussss checker. It does not scan the public internet.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import csv
import io
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RUNTIME_DIR = IP_RUNTIME_DIR / "research"
RESIN_DIR = IP_RUNTIME_DIR / "resin"
DEFAULT_SOURCE_QUALITY = RUNTIME_DIR / "proxy_source_quality_latest.json"
SOURCES = {
    "cmliussss_vpngate": "https://sub.cmliussss.net/vpngate",
    "delta_vpn_gate": "https://raw.githubusercontent.com/Delta-Kronecker/Vpn-Gate/refs/heads/main/sstp_hosts.txt",
    "vpngate_official_api": "https://www.vpngate.net/api/iphone/",
    "f0rc3run_sstp": "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/sstp-configs/sstp_with_country.txt",
    "toicf_turn_results": "https://raw.githubusercontent.com/ToiCF/CF-Workers-TURN/main/turn_results.txt",
    "cmliu_socks5api": "https://raw.githubusercontent.com/cmliu/Socks2Vlesssub/main/socks5api.txt",
    "cmliu_worker_socks5": "https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/socks5Data",
    "proxifly_socks5": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "proxyscrape_socks5": "https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=socks5&format=txt&timeout=10000&country=all",
    "speedx_socks5": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
}
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json,text/plain,*/*",
    "Referer": "https://check.socks5.cmliussss.net/",
}


def fetch_text(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def safe_fetch_text(source: str, timeout: int = 30) -> str:
    try:
        return fetch_text(SOURCES[source], timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(json.dumps({"source": source, "error": repr(exc)}, ensure_ascii=False))
        return ""


def maybe_decode_base64(text: str) -> list[str]:
    blobs = [text]
    compact = "".join(text.split())
    if compact and re.fullmatch(r"[A-Za-z0-9+/=]+", compact[:2000]):
        try:
            padding = "=" * (-len(compact) % 4)
            blobs.append(base64.b64decode(compact + padding).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return blobs


def add_candidate(candidates: list[dict], kind: str, raw: str, source: str) -> None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return
    candidates.append({"kind": kind, "raw": raw, "source": source})


def add_socks5_line(candidates: list[dict], raw: str, source: str) -> bool:
    raw = raw.strip().strip("|")
    if not raw or raw.startswith("#"):
        return False
    m = re.search(r"socks5://[^\s\r\n|]+", raw)
    if m:
        add_candidate(candidates, "socks5", m.group(0), source)
        return True
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})\b", raw)
    if m:
        add_candidate(candidates, "socks5", "socks5://" + m.group(1), source)
        return True
    return False


def normalize_opengw_host(host: str) -> str:
    host = host.strip()
    if not host:
        return ""
    if host.endswith(".opengw.net"):
        return host
    if re.match(r"^(public-vpn-|vpn)[A-Za-z0-9-]+$", host):
        return host + ".opengw.net"
    return host


def load_vpngate_official(candidates: list[dict]) -> None:
    text = safe_fetch_text("vpngate_official_api")
    lines = [line for line in text.splitlines() if line and not line.startswith("*") and not line.startswith("#")]
    if not lines:
        return
    header_line = next((line for line in text.splitlines() if line.startswith("#HostName,")), "")
    if not header_line:
        return
    header = header_line.lstrip("#").split(",")
    reader = csv.DictReader(io.StringIO("\n".join(lines)), fieldnames=header)
    for row in reader:
        host = normalize_opengw_host(row.get("HostName") or "")
        if host and ("opengw.net" in host or host.startswith("public-vpn-")):
            add_candidate(candidates, "sstp", f"sstp://vpn:vpn@{host}:443", "vpngate_official_api")


def load_f0rc3run_sstp(candidates: list[dict]) -> None:
    text = safe_fetch_text("f0rc3run_sstp")
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "|" in s:
            s = s.split("|", 1)[1].strip()
        if "opengw.net" in s:
            if not s.startswith("sstp://"):
                s = "sstp://vpn:vpn@" + s
            add_candidate(candidates, "sstp", s, "f0rc3run_sstp")


def load_toicf_turn(candidates: list[dict]) -> None:
    text = safe_fetch_text("toicf_turn_results")
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        hostport = parts[0]
        transport = parts[1].upper()
        if transport == "UDP":
            continue
        if not re.match(r"^[A-Za-z0-9.-]+:\d{2,5}$", hostport):
            continue
        cred = re.search(r"CRED\(([^:()\s]+):([^()\s]+)\)", s)
        if cred:
            raw = f"turn://{cred.group(1)}:{cred.group(2)}@{hostport}"
        else:
            raw = f"turn://{hostport}"
        add_candidate(candidates, "turn", raw, "toicf_turn_results")


def load_socks_sources(candidates: list[dict], max_per_source: int) -> None:
    for source in [
        "cmliu_socks5api",
        "cmliu_worker_socks5",
        "proxifly_socks5",
        "proxyscrape_socks5",
        "speedx_socks5",
    ]:
        text = safe_fetch_text(source)
        added = 0
        for line in text.splitlines():
            if add_socks5_line(candidates, line, source):
                added += 1
                if added >= max_per_source:
                    break


def load_candidates() -> list[dict]:
    candidates: list[dict] = []

    cmliussss = safe_fetch_text("cmliussss_vpngate")
    for blob in maybe_decode_base64(cmliussss):
        for m in re.finditer(r"sstp://[^\s\r\n]+", blob):
            add_candidate(candidates, "sstp", m.group(0), "cmliussss_vpngate")
        for line in blob.splitlines():
            s = line.strip()
            if s and (s.endswith(".opengw.net") or "opengw.net:" in s):
                if not s.startswith("sstp://"):
                    s = "sstp://vpn:vpn@" + s
                add_candidate(candidates, "sstp", s, "cmliussss_vpngate")

    delta = safe_fetch_text("delta_vpn_gate")
    for line in delta.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "opengw.net" in s or re.match(r"^[A-Za-z0-9.-]+:\d+$", s):
            if not s.startswith("sstp://"):
                s = "sstp://vpn:vpn@" + s
            add_candidate(candidates, "sstp", s, "delta_vpn_gate")

    load_vpngate_official(candidates)
    load_f0rc3run_sstp(candidates)
    load_toicf_turn(candidates)

    for path in [
        ROOT / "docs/ip-proxy/research/cmliussss_sstp_turn_plan_20260606.md",
        ROOT / "docs/ip-proxy/research/runtime/turn_check_20260606_223018.md",
    ]:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"turn://[^\s`|]+", text):
            add_candidate(candidates, "turn", m.group(0).rstrip(".,)"), path.name)

    load_socks_sources(candidates, load_candidates.max_socks_per_source)

    dedup: list[dict] = []
    seen: set[str] = set()
    for item in candidates:
        if item["raw"] in seen:
            continue
        seen.add(item["raw"])
        item["port"] = extract_port(item["raw"])
        dedup.append(item)
    return dedup


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def safe_float(value: object) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def load_source_quality(path: Path) -> dict[str, dict]:
    data = read_json(path, {})
    if not isinstance(data, dict):
        return {}
    by_source = data.get("by_source")
    if not isinstance(by_source, dict):
        return {}
    return {str(source): item for source, item in by_source.items() if isinstance(item, dict)}


def run_date(run_id: str) -> str:
    return run_id[:8] if len(run_id) >= 8 and run_id[:8].isdigit() else time.strftime("%Y%m%d")


def display_date(run_id: str) -> str:
    date = run_date(run_id)
    return f"{date[:4]}-{date[4:6]}-{date[6:8]}"


def extract_port(raw: str) -> int | None:
    m = re.search(r":(\d+)(?:[/?#]|$)", raw)
    return int(m.group(1)) if m else None


def kind_priority(item: dict) -> int:
    kind = item.get("kind")
    if kind == "turn":
        return 0
    if kind == "sstp" and item.get("port") == 443:
        return 1
    if kind == "sstp":
        return 2
    return 3


def candidate_sort_key(item: dict, source_quality: dict[str, dict] | None = None) -> tuple:
    quality = (source_quality or {}).get(str(item.get("source") or "unknown"), {})
    return (
        kind_priority(item),
        -safe_int(quality.get("clean")),
        -safe_float(quality.get("clean_rate_pct")),
        -safe_int(quality.get("success")),
        -safe_float(quality.get("success_rate_pct")),
        item.get("raw") or "",
    )


def prioritize_candidates(candidates: list[dict], source_quality: dict[str, dict] | None = None) -> list[dict]:
    return sorted(candidates, key=lambda item: candidate_sort_key(item, source_quality))


def check_candidate(item: dict, timeout: int) -> dict:
    proxy = item["raw"]
    url = "https://check.socks5.cmliussss.net/check?proxy=" + urllib.parse.quote(proxy, safe="")
    req = urllib.request.Request(url, headers=HEADERS)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {
            **item,
            "checked": True,
            "success": False,
            "clean": False,
            "dirty": [],
            "error": repr(exc),
            "elapsed_ms": round((time.time() - t0) * 1000),
        }

    exit_info = data.get("exit") or {}
    dirty = [
        key
        for key in ["is_datacenter", "is_proxy", "is_vpn", "is_tor", "is_abuser", "is_bogon"]
        if exit_info.get(key)
    ]
    success = bool(data.get("success"))
    return {
        **item,
        "checked": True,
        "success": success,
        "clean": success and not dirty,
        "dirty": dirty,
        "responseTime": data.get("responseTime"),
        "exit_ip": exit_info.get("ip"),
        "country": (exit_info.get("location") or {}).get("country_code"),
        "city": (exit_info.get("location") or {}).get("city"),
        "company_type": (exit_info.get("company") or {}).get("type"),
        "asn_type": (exit_info.get("asn") or {}).get("type"),
        "company": (exit_info.get("company") or {}).get("name"),
        "error": data.get("error") or data.get("message"),
        "raw_result": data,
        "elapsed_ms": round((time.time() - t0) * 1000),
    }


def write_outputs(candidates: list[dict], results: list[dict], run_id: str) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    RESIN_DIR.mkdir(parents=True, exist_ok=True)
    date_id = run_date(run_id)

    write_json(RUNTIME_DIR / f"proxy_candidate_pool_{run_id}.json", candidates)
    write_json(RUNTIME_DIR / "proxy_candidate_pool.latest.json", candidates)
    write_json(RUNTIME_DIR / f"proxy_candidate_check_{run_id}.json", results)
    write_json(RUNTIME_DIR / "proxy_candidate_check.latest.json", results)

    clean = [r for r in results if r.get("clean")]
    turn = sorted(
        [r for r in clean if r["kind"] == "turn"],
        key=lambda r: r.get("responseTime") or 999999,
    )
    sstp = sorted(
        [r for r in clean if r["kind"] == "sstp"],
        key=lambda r: (0 if r.get("port") == 443 else 1, r.get("responseTime") or 999999),
    )
    (RESIN_DIR / f"turn_clean_candidates_{date_id}.txt").write_text(
        "\n".join(r["raw"] for r in turn) + "\n",
        encoding="utf-8",
    )
    (RESIN_DIR / "turn_clean_candidates.latest.txt").write_text(
        "\n".join(r["raw"] for r in turn) + "\n",
        encoding="utf-8",
    )
    socks5 = sorted(
        [r for r in clean if r["kind"] == "socks5"],
        key=lambda r: r.get("responseTime") or 999999,
    )
    (RESIN_DIR / f"sstp_clean_candidates_{date_id}.txt").write_text(
        "\n".join(r["raw"] for r in sstp) + "\n",
        encoding="utf-8",
    )
    (RESIN_DIR / "sstp_clean_candidates.latest.txt").write_text(
        "\n".join(r["raw"] for r in sstp) + "\n",
        encoding="utf-8",
    )
    (RESIN_DIR / f"socks5_clean_candidates_{date_id}.txt").write_text(
        ("\n".join(r["raw"] for r in socks5) + "\n") if socks5 else "",
        encoding="utf-8",
    )
    (RESIN_DIR / "socks5_clean_candidates.latest.txt").write_text(
        ("\n".join(r["raw"] for r in socks5) + "\n") if socks5 else "",
        encoding="utf-8",
    )

    summary: dict[str, dict[str, int]] = {}
    for r in results:
        row = summary.setdefault(r["kind"], {"total": 0, "success": 0, "clean": 0})
        row["total"] += 1
        row["success"] += int(bool(r.get("success")))
        row["clean"] += int(bool(r.get("clean")))

    lines = [
        f"# Proxy Candidate Check {display_date(run_id)}",
        "",
        f"Run ID: `{run_id}`",
        "",
        f"Total checked: {len(results)}",
        "",
        "| Kind | Total | Success | Clean |",
        "|---|---:|---:|---:|",
    ]
    for kind, row in sorted(summary.items()):
        lines.append(f"| {kind} | {row['total']} | {row['success']} | {row['clean']} |")
    lines += ["", f"Clean candidates: {len(clean)}", ""]
    md = "\n".join(lines) + "\n"
    (RUNTIME_DIR / f"proxy_candidate_check_{run_id}.md").write_text(md, encoding="utf-8")
    (RUNTIME_DIR / "proxy_candidate_check.latest.md").write_text(md, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=18)
    parser.add_argument("--harvest-only", action="store_true")
    parser.add_argument("--max-socks-per-source", type=int, default=200)
    parser.add_argument("--max-check", type=int, default=0, help="limit checked candidates after sorting; 0 means all")
    parser.add_argument("--run-id", default="", help="stable run id for timestamped outputs")
    parser.add_argument("--source-quality", type=Path, default=DEFAULT_SOURCE_QUALITY)
    args = parser.parse_args()
    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")

    load_candidates.max_socks_per_source = args.max_socks_per_source
    candidates = load_candidates()
    source_quality = load_source_quality(args.source_quality)
    candidates = prioritize_candidates(candidates, source_quality)
    if args.harvest_only:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        write_json(RUNTIME_DIR / f"proxy_candidate_pool_{run_id}.json", candidates)
        write_json(RUNTIME_DIR / "proxy_candidate_pool.latest.json", candidates)
        summary: dict[str, int] = {}
        for item in candidates:
            summary[item["kind"]] = summary.get(item["kind"], 0) + 1
        print(json.dumps({"run_id": run_id, "candidates": len(candidates), "by_kind": summary}, ensure_ascii=False))
        return 0
    if args.max_check > 0:
        candidates = candidates[: args.max_check]
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_candidate, item, args.timeout) for item in candidates]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    write_outputs(candidates, results, run_id)
    clean = sum(1 for r in results if r.get("clean"))
    print(json.dumps({"run_id": run_id, "candidates": len(candidates), "checked": len(results), "clean": clean}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
