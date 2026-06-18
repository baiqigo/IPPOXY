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
import subprocess
from collections import Counter
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

# Global fetch proxy: set via --fetch-proxy CLI arg or IP_PROXY_FETCH_PROXY env.
# When set, all HTTP fetches route through this proxy (e.g. socks5h://127.0.0.1:19081).
FETCH_PROXY: str | None = os.environ.get("IP_PROXY_FETCH_PROXY") or None


def fetch_text(url: str, timeout: int = 30) -> str:
    if FETCH_PROXY:
        return _fetch_curl(url, timeout)
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def _fetch_curl(url: str, timeout: int = 30) -> str:
    """Fetch URL via curl subprocess with SOCKS5/HTTP proxy support."""
    cmd = [
        "curl", "-sS", "--max-time", str(timeout),
        "-x", FETCH_PROXY,
        "-H", "User-Agent: Mozilla/5.0",
        "-H", "Accept: application/json,text/plain,*/*",
        "-H", "Referer: https://check.socks5.cmliussss.net/",
        url,
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
    if result.returncode != 0:
        raise OSError(f"curl failed (rc={result.returncode}): {result.stderr.decode('utf-8', errors='ignore').strip()}")
    return result.stdout.decode("utf-8", errors="ignore")


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

    load_dynamic_sources(candidates)

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


def normalize_candidate_rows(candidates: list[dict]) -> list[dict]:
    dedup: list[dict] = []
    seen: set[str] = set()
    for item in candidates:
        raw = str(item.get("raw") or "").strip()
        kind = str(item.get("kind") or "").strip()
        if not raw or not kind or raw in seen:
            continue
        seen.add(raw)
        row = dict(item)
        row["kind"] = kind
        row["raw"] = raw
        row["source"] = str(row.get("source") or row.get("source_id") or "unknown")
        row["port"] = row.get("port") or extract_port(raw)
        dedup.append(row)
    return dedup


def load_extra_candidate_pools(paths: list[Path]) -> list[dict]:
    candidates: list[dict] = []
    for path in paths:
        data = read_json(path, [])
        if not isinstance(data, list):
            continue
        for item in data:
            if isinstance(item, dict):
                candidates.append(dict(item))
    return normalize_candidate_rows(candidates)


def load_dynamic_sources(candidates: list[dict]) -> None:
    """Load supplementary sources from dynamic_sources.json (written by ip_grok_source_discovery.py)."""
    dynamic_path = RUNTIME_DIR / "dynamic_sources.json"
    if not dynamic_path.exists():
        return
    try:
        data = json.loads(dynamic_path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return
    sources = data.get("sources") or []
    if not sources:
        return
    static_urls = set(SOURCES.values())
    for entry in sources:
        url = entry.get("url", "")
        if not url or url in static_urls or not entry.get("fetchable"):
            continue
        expected_kind = entry.get("expected_kind", "unknown")
        source_name = f"grok_dynamic_{entry.get('source_type', 'unknown')}"
        try:
            text = fetch_text(url, timeout=20)
        except (OSError, TimeoutError) as exc:
            print(json.dumps({"source": source_name, "url": url, "error": repr(exc)}, ensure_ascii=False))
            continue
        if expected_kind == "sstp":
            for blob in maybe_decode_base64(text):
                for m in re.finditer(r"sstp://[^\s\r\n]+", blob):
                    add_candidate(candidates, "sstp", m.group(0), source_name)
                for line in blob.splitlines():
                    s = line.strip()
                    if s and ("opengw.net" in s or re.match(r"^[A-Za-z0-9.-]+:\d+$", s)):
                        if not s.startswith("sstp://"):
                            s = "sstp://vpn:vpn@" + s
                        add_candidate(candidates, "sstp", s, source_name)
        elif expected_kind == "turn":
            for line in text.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9.-]+:\d+)", s)
                if m:
                    cred = re.search(r"CRED\(([^:()\s]+):([^()\s]+)\)", s)
                    raw = f"turn://{cred.group(1)}:{cred.group(2)}@{m.group(1)}" if cred else f"turn://{m.group(1)}"
                    add_candidate(candidates, "turn", raw, source_name)
        elif expected_kind == "socks5":
            for line in text.splitlines():
                add_socks5_line(candidates, line, source_name)
        elif expected_kind == "subscription":
            for blob in maybe_decode_base64(text):
                for proto in ["vmess", "vless", "trojan", "ss"]:
                    for m in re.finditer(rf"{proto}://[^\s\r\n]+", blob):
                        add_candidate(candidates, proto, m.group(0), source_name)
        else:
            # Unknown kind: try generic socks5/turn/sstp extraction
            for line in text.splitlines():
                add_socks5_line(candidates, line, source_name)
            for m in re.finditer(r"turn://[^\s\r\n]+", text):
                add_candidate(candidates, "turn", m.group(0), source_name)
            for m in re.finditer(r"sstp://[^\s\r\n]+", text):
                add_candidate(candidates, "sstp", m.group(0), source_name)


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


def candidate_source(item: dict) -> str:
    return str(item.get("source") or "unknown")


def candidate_kind(item: dict) -> str:
    return str(item.get("kind") or "unknown")


def is_cooldown_source(item: dict, source_quality: dict[str, dict] | None = None) -> bool:
    quality = (source_quality or {}).get(candidate_source(item), {})
    return bool(quality.get("cooldown_recommended"))


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
    quality = (source_quality or {}).get(candidate_source(item), {})
    return (
        kind_priority(item),
        1 if quality.get("cooldown_recommended") else 0,
        -safe_int(quality.get("clean")),
        -safe_float(quality.get("clean_rate_pct")),
        -safe_int(quality.get("success")),
        -safe_float(quality.get("success_rate_pct")),
        item.get("raw") or "",
    )


def prioritize_candidates(candidates: list[dict], source_quality: dict[str, dict] | None = None) -> list[dict]:
    return sorted(candidates, key=lambda item: candidate_sort_key(item, source_quality))


def ordered_candidate_kinds(candidates: list[dict]) -> list[str]:
    kinds = {candidate_kind(item) for item in candidates}
    return sorted(kinds, key=lambda kind: kind_priority({"kind": kind}))


def round_robin_pick(
    candidates: list[dict],
    *,
    selected: list[dict],
    selected_ids: set[int],
    per_source: dict[str, int],
    per_kind: dict[str, int],
    limit: int,
    max_per_source: int = 0,
    max_per_kind: int = 0,
) -> None:
    if len(selected) >= limit:
        return

    buckets: dict[str, list[dict]] = {}
    cursors: dict[str, int] = {}
    for item in candidates:
        buckets.setdefault(candidate_kind(item), []).append(item)
    for kind in buckets:
        cursors[kind] = 0

    kinds = ordered_candidate_kinds(candidates)
    while len(selected) < limit:
        progressed = False
        for kind in kinds:
            bucket = buckets.get(kind) or []
            cursor = cursors.get(kind, 0)
            while cursor < len(bucket):
                item = bucket[cursor]
                cursor += 1
                if id(item) in selected_ids:
                    continue
                source = candidate_source(item)
                if max_per_source > 0 and per_source.get(source, 0) >= max_per_source:
                    continue
                if max_per_kind > 0 and per_kind.get(kind, 0) >= max_per_kind:
                    continue
                selected.append(item)
                selected_ids.add(id(item))
                per_source[source] = per_source.get(source, 0) + 1
                per_kind[kind] = per_kind.get(kind, 0) + 1
                progressed = True
                break
            cursors[kind] = cursor
            if len(selected) >= limit:
                return
        if not progressed:
            return


def select_check_candidates(
    candidates: list[dict],
    max_check: int,
    max_per_source: int = 0,
    source_quality: dict[str, dict] | None = None,
    include_cooldown_sources: bool = False,
    max_per_kind: int = 0,
    relax_source_cap: bool = False,
    only_kinds: set[str] | None = None,
) -> list[dict]:
    active = [
        item
        for item in candidates
        if include_cooldown_sources or not is_cooldown_source(item, source_quality)
    ]
    if only_kinds:
        active = [item for item in active if candidate_kind(item) in only_kinds]
    limit = len(active) if max_check <= 0 else min(max_check, len(active))
    if limit <= 0:
        return []

    selected: list[dict] = []
    selected_ids: set[int] = set()
    per_source: dict[str, int] = {}
    per_kind: dict[str, int] = {}

    auto_kind_cap = 0
    if max_check > 0 and max_per_kind <= 0:
        kind_count = max(1, len(ordered_candidate_kinds(active)))
        auto_kind_cap = max(1, (limit + kind_count - 1) // kind_count)

    round_robin_pick(
        active,
        selected=selected,
        selected_ids=selected_ids,
        per_source=per_source,
        per_kind=per_kind,
        limit=limit,
        max_per_source=max_per_source,
        max_per_kind=max_per_kind or auto_kind_cap,
    )
    round_robin_pick(
        active,
        selected=selected,
        selected_ids=selected_ids,
        per_source=per_source,
        per_kind=per_kind,
        limit=limit,
        max_per_source=0 if relax_source_cap else max_per_source,
        max_per_kind=max_per_kind,
    )
    return selected


def count_by(items: list[dict], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(item.get(field) or "unknown") for item in items).items()))


def selection_summary(
    candidates: list[dict],
    selected: list[dict],
    *,
    source_quality: dict[str, dict] | None = None,
    include_cooldown_sources: bool = False,
    max_check: int = 0,
    max_per_source: int = 0,
    max_per_kind: int = 0,
    relax_source_cap: bool = False,
    only_kinds: set[str] | None = None,
) -> dict:
    selected_ids = {id(item) for item in selected}
    cooldown_candidates = [item for item in candidates if is_cooldown_source(item, source_quality)]
    cooldown_sources: dict[str, dict] = {}
    for source, quality in sorted((source_quality or {}).items()):
        if not quality.get("cooldown_recommended"):
            continue
        source_candidates = [item for item in candidates if candidate_source(item) == source]
        if not source_candidates:
            continue
        cooldown_sources[source] = {
            "reason": quality.get("cooldown_reason"),
            "candidates": len(source_candidates),
            "selected": sum(1 for item in source_candidates if id(item) in selected_ids),
            "clean": safe_int(quality.get("clean")),
            "success": safe_int(quality.get("success")),
            "total": safe_int(quality.get("total")),
        }
    return {
        "candidates": len(candidates),
        "selected": len(selected),
        "max_check": max_check,
        "max_check_per_source": max_per_source,
        "max_check_per_kind": max_per_kind,
        "relax_source_cap": relax_source_cap,
        "only_kinds": sorted(only_kinds or []),
        "include_cooldown_sources": include_cooldown_sources,
        "skipped_cooldown_candidates": 0
        if include_cooldown_sources
        else sum(1 for item in cooldown_candidates if id(item) not in selected_ids),
        "by_kind": count_by(candidates, "kind"),
        "selected_by_kind": count_by(selected, "kind"),
        "by_source": count_by(candidates, "source"),
        "selected_by_source": count_by(selected, "source"),
        "cooldown_sources": cooldown_sources,
    }


def write_selection_summary(
    candidates: list[dict],
    selected: list[dict],
    run_id: str,
    *,
    source_quality: dict[str, dict] | None = None,
    include_cooldown_sources: bool = False,
    max_check: int = 0,
    max_per_source: int = 0,
    max_per_kind: int = 0,
    relax_source_cap: bool = False,
    only_kinds: set[str] | None = None,
) -> dict:
    summary = selection_summary(
        candidates,
        selected,
        source_quality=source_quality,
        include_cooldown_sources=include_cooldown_sources,
        max_check=max_check,
        max_per_source=max_per_source,
        max_per_kind=max_per_kind,
        relax_source_cap=relax_source_cap,
        only_kinds=only_kinds,
    )
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    write_json(RUNTIME_DIR / f"proxy_candidate_selection_{run_id}.json", summary)
    write_json(RUNTIME_DIR / "proxy_candidate_selection.latest.json", summary)
    return summary


def check_candidate(item: dict, timeout: int) -> dict:
    proxy = item["raw"]
    url = "https://check.socks5.cmliussss.net/check?proxy=" + urllib.parse.quote(proxy, safe="")
    t0 = time.time()
    try:
        body = fetch_text(url, timeout=timeout)
        data = json.loads(body)
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
    parser.add_argument("--max-check-per-source", type=int, default=int(os.environ.get("IP_PROXY_MAX_CHECK_PER_SOURCE", "0")))
    parser.add_argument(
        "--max-check-per-kind",
        type=int,
        default=int(os.environ.get("IP_PROXY_MAX_CHECK_PER_KIND", "0")),
        help="cap checked candidates per kind; 0 auto-balances when --max-check is set",
    )
    parser.add_argument(
        "--include-cooldown-sources",
        action="store_true",
        help="also check sources previously marked cooldown_recommended by source quality",
    )
    parser.add_argument(
        "--relax-source-cap",
        action="store_true",
        help="allow the second fill pass to exceed --max-check-per-source when non-cooldown supply is sparse",
    )
    parser.add_argument(
        "--only-kind",
        action="append",
        choices=["turn", "sstp", "socks4", "socks5", "http", "https"],
        default=[],
        help="limit checked candidates to the given kind; repeat to allow multiple kinds",
    )
    parser.add_argument("--run-id", default="", help="stable run id for timestamped outputs")
    parser.add_argument("--source-quality", type=Path, default=DEFAULT_SOURCE_QUALITY)
    parser.add_argument(
        "--extra-candidate-pool",
        type=Path,
        action="append",
        default=[],
        help="additional JSON candidate pool, such as layer0_http_socks_pool_<run_id>.json",
    )
    parser.add_argument(
        "--skip-default-sources",
        action="store_true",
        help="only use --extra-candidate-pool inputs; useful for local/offline intake tests",
    )
    parser.add_argument(
        "--fetch-proxy",
        default="",
        help="proxy for all HTTP fetches (e.g. socks5h://127.0.0.1:19081); "
             "also set via IP_PROXY_FETCH_PROXY env",
    )
    args = parser.parse_args()
    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    global FETCH_PROXY
    if args.fetch_proxy:
        FETCH_PROXY = args.fetch_proxy
    elif not FETCH_PROXY:
        FETCH_PROXY = None

    load_candidates.max_socks_per_source = args.max_socks_per_source
    only_kinds = set(args.only_kind or [])
    candidates = [] if args.skip_default_sources else load_candidates()
    if args.extra_candidate_pool:
        candidates.extend(load_extra_candidate_pools(args.extra_candidate_pool))
        candidates = normalize_candidate_rows(candidates)
    if FETCH_PROXY:
        print(json.dumps({"fetch_proxy": FETCH_PROXY[:12] + "...", "note": "all fetches routed through proxy"}, ensure_ascii=False))
    source_quality = load_source_quality(args.source_quality)
    candidates = prioritize_candidates(candidates, source_quality)
    if args.harvest_only:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        write_json(RUNTIME_DIR / f"proxy_candidate_pool_{run_id}.json", candidates)
        write_json(RUNTIME_DIR / "proxy_candidate_pool.latest.json", candidates)
        summary = write_selection_summary(
            candidates,
            [],
            run_id,
            source_quality=source_quality,
            include_cooldown_sources=args.include_cooldown_sources,
            max_check=args.max_check,
            max_per_source=args.max_check_per_source,
            max_per_kind=args.max_check_per_kind,
            relax_source_cap=args.relax_source_cap,
            only_kinds=only_kinds,
        )
        print(
            json.dumps(
                {
                    "run_id": run_id,
                    "candidates": len(candidates),
                    "by_kind": summary["by_kind"],
                    "cooldown_sources": len(summary["cooldown_sources"]),
                    "skipped_cooldown_candidates": summary["skipped_cooldown_candidates"],
                },
                ensure_ascii=False,
            )
        )
        return 0
    pool_candidates = candidates
    candidates = select_check_candidates(
        pool_candidates,
        args.max_check,
        args.max_check_per_source,
        source_quality,
        args.include_cooldown_sources,
        args.max_check_per_kind,
        args.relax_source_cap,
        only_kinds,
    )
    selection = write_selection_summary(
        pool_candidates,
        candidates,
        run_id,
        source_quality=source_quality,
        include_cooldown_sources=args.include_cooldown_sources,
        max_check=args.max_check,
        max_per_source=args.max_check_per_source,
        max_per_kind=args.max_check_per_kind,
        relax_source_cap=args.relax_source_cap,
        only_kinds=only_kinds,
    )
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_candidate, item, args.timeout) for item in candidates]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    write_outputs(candidates, results, run_id)
    clean = sum(1 for r in results if r.get("clean"))
    print(
        json.dumps(
            {
                "run_id": run_id,
                "candidates": len(pool_candidates),
                "selected": len(candidates),
                "checked": len(results),
                "clean": clean,
                "selected_by_kind": selection["selected_by_kind"],
                "skipped_cooldown_candidates": selection["skipped_cooldown_candidates"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
