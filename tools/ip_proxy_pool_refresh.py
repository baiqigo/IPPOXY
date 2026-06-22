#!/usr/bin/env python3
"""Refresh the sandbox runtime Xray/Resin pool from IP candidate files."""

from __future__ import annotations

import argparse
import collections
import copy
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.parse
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RESIN_DIR = ROOT / "docs/ip-proxy/resin"
DOC_RUNTIME_DIR = ROOT / "docs/ip-proxy/research/runtime"
RUNTIME_RESIN_DIR = RUNTIME / "resin"

DEFAULT_STRICT_INPUT = RUNTIME_RESIN_DIR / "clean_candidates_classified.latest.json"
DEFAULT_RELAXED_INPUT = RUNTIME_RESIN_DIR / "relaxed_candidates_classified.latest.json"
DEFAULT_RAW_INPUT = RUNTIME / "research/proxy_candidate_google_live.latest.json"
DEFAULT_INPUT = DEFAULT_STRICT_INPUT
DEFAULT_BASELINE = DOC_RUNTIME_DIR / "turn_xray_pool_20260608.json"
DEFAULT_VERIFY = ROOT / "captures/ip_runtime_verify_latest.json"
DEFAULT_REGISTRAR_FEEDBACK = ROOT / "captures/ip_registrar_feedback_latest.json"
DEFAULT_SOURCE_QUALITY = RUNTIME / "research/proxy_source_quality_latest.json"
DEFAULT_WORKER_HOST = os.environ.get("IP_PROXY_TURN_WORKER_HOST", "ip-proxy-turn-poc.yanielachilles90-mhnxbt5n94.workers.dev")
DEFAULT_UUID = "2523c510-9ff0-415b-9582-93949bfae7e3"
DEFAULT_MAX_FALLBACK_CANDIDATE_AGE_HOURS = float(os.environ.get("IP_PROXY_MAX_FALLBACK_CANDIDATE_AGE_HOURS", "48"))
ALLOWED_POOL_MODES = {"strict", "relaxed", "raw"}
RUNTIME_CANDIDATE_KINDS = {
    "turn",
    "http",
    "https",
    "socks4",
    "socks5",
    "vless",
    "vmess",
    "trojan",
    "ss",
}
RISKY_DIRTY_FLAGS = {"is_datacenter", "is_proxy", "is_vpn"}
HARD_DIRTY_FLAGS = {"is_tor", "is_abuser", "is_bogon"}
DEFAULT_MAX_RISKY_CANDIDATES = int(os.environ.get("IP_PROXY_MAX_RISKY_CANDIDATES", "10"))
DEFAULT_MAX_RISKY_RATIO = float(os.environ.get("IP_PROXY_MAX_RISKY_RATIO", "0.40") or "0")
DEFAULT_MIN_STRICT_CLEAN_SELECTED = int(os.environ.get("IP_PROXY_MIN_STRICT_CLEAN_SELECTED", "12"))
DEFAULT_MIN_COUNTRIES = int(os.environ.get("IP_PROXY_MIN_COUNTRIES", "8"))
DEFAULT_MAX_COUNTRY_RATIO = float(os.environ.get("IP_PROXY_MAX_COUNTRY_RATIO", "0.40") or "0")
DEFAULT_MAX_COMPANY_RATIO = float(os.environ.get("IP_PROXY_MAX_COMPANY_RATIO", "0.24") or "0")
DEFAULT_MAX_ASN_RATIO = float(os.environ.get("IP_PROXY_MAX_ASN_RATIO", "0.24") or "0")
DEFAULT_ACTIVE_POOL_SIZE = int(os.environ.get("IP_PROXY_DEFAULT_POOL_SIZE", "500"))
RELAXED_QUANTITY_DEFAULTS = {
    "limit": (DEFAULT_ACTIVE_POOL_SIZE, "--limit", "IP_PROXY_POOL_SIZE"),
    "min_clean": (1, "--min-clean", "IP_PROXY_MIN_CLEAN"),
    "min_new_candidates": (55, "--min-new-candidates", "IP_PROXY_MIN_NEW_CANDIDATES"),
    "max_risky_candidates": (-1, "--max-risky-candidates", "IP_PROXY_MAX_RISKY_CANDIDATES"),
    "max_risky_ratio": (0.0, "--max-risky-ratio", "IP_PROXY_MAX_RISKY_RATIO"),
    "min_strict_clean_selected": (0, "--min-strict-clean-selected", "IP_PROXY_MIN_STRICT_CLEAN_SELECTED"),
    "min_countries": (0, "--min-countries", "IP_PROXY_MIN_COUNTRIES"),
    "max_country_ratio": (0.0, "--max-country-ratio", "IP_PROXY_MAX_COUNTRY_RATIO"),
    "max_company_ratio": (0.0, "--max-company-ratio", "IP_PROXY_MAX_COMPANY_RATIO"),
    "max_asn_ratio": (0.0, "--max-asn-ratio", "IP_PROXY_MAX_ASN_RATIO"),
}
RAW_QUANTITY_DEFAULTS = {
    "limit": (DEFAULT_ACTIVE_POOL_SIZE, "--limit", "IP_PROXY_POOL_SIZE"),
    "min_clean": (1, "--min-clean", "IP_PROXY_MIN_CLEAN"),
    "min_new_candidates": (55, "--min-new-candidates", "IP_PROXY_MIN_NEW_CANDIDATES"),
    "max_risky_candidates": (-1, "--max-risky-candidates", "IP_PROXY_MAX_RISKY_CANDIDATES"),
    "max_risky_ratio": (0.0, "--max-risky-ratio", "IP_PROXY_MAX_RISKY_RATIO"),
    "min_strict_clean_selected": (0, "--min-strict-clean-selected", "IP_PROXY_MIN_STRICT_CLEAN_SELECTED"),
    "min_countries": (0, "--min-countries", "IP_PROXY_MIN_COUNTRIES"),
    "max_country_ratio": (0.0, "--max-country-ratio", "IP_PROXY_MAX_COUNTRY_RATIO"),
    "max_company_ratio": (0.0, "--max-company-ratio", "IP_PROXY_MAX_COMPANY_RATIO"),
    "max_asn_ratio": (0.0, "--max-asn-ratio", "IP_PROXY_MAX_ASN_RATIO"),
}


def slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value or "unknown"


def classify(item: dict) -> str:
    company_type = (item.get("company_type") or "").lower()
    asn_type = (item.get("asn_type") or "").lower()
    if company_type == "isp" and asn_type == "isp":
        return "res"
    if "isp" in {company_type, asn_type}:
        return "isp"
    return "static"


def pool_priority(item: dict) -> int:
    tier = str(item.get("registration_tier") or "").lower()
    company_type = (item.get("company_type") or "").lower()
    asn_type = (item.get("asn_type") or "").lower()
    type_text = f"{company_type} {asn_type}"
    if tier == "risky":
        return 4
    if company_type == "isp" and asn_type == "isp":
        return 0
    if "isp" in {company_type, asn_type}:
        return 1
    if any(word in type_text for word in ["hosting", "datacenter", "data center", "cdn", "cloud"]):
        return 3
    return 2


def make_tag(item: dict) -> str:
    tier = str(item.get("registration_tier") or "").lower()
    if bool(item.get("raw_pool")) or tier == "dirty_alive_noncn":
        bucket = "raw"
    else:
        bucket = "relaxed" if tier == "risky" or bool(item.get("relaxed_pool")) else classify(item)
    country = slug(item.get("country") or "xx")
    company = slug(item.get("company") or item.get("exit_ip") or "node")
    city = slug(item.get("city") or "")
    host = slug((item.get("exit_ip") or item.get("raw") or "node").replace(".", "-"))
    middle = "-".join(part for part in [country, company[:28], city[:18], host] if part)
    return f"ippoxy-{bucket}-{middle}"


def vless_url(uuid: str, worker_host: str, turn_url: str) -> str:
    path = f"/{turn_url}?ed=2560"
    query = {
        "type": "ws",
        "encryption": "none",
        "host": worker_host,
        "path": path,
        "security": "tls",
        "sni": worker_host,
        "packetEncoding": "xudp",
    }
    return f"vless://{uuid}@{worker_host}:443/?" + urllib.parse.urlencode(query, safe="/:")


def parse_proxy_url(raw: str, kind: str) -> dict:
    value = str(raw or "").strip()
    if "://" not in value:
        value = f"{kind}://{value}"
    parsed = urllib.parse.urlparse(value)
    host = parsed.hostname
    port = parsed.port
    if not host or not port:
        raise ValueError(f"invalid proxy URL: {raw!r}")
    server: dict[str, object] = {"address": host, "port": int(port)}
    if parsed.username is not None:
        user = urllib.parse.unquote(parsed.username)
        password = urllib.parse.unquote(parsed.password or "")
        server["users"] = [{"user": user, "pass": password}]
    return server


def outbound_for_row(row: dict, uuid: str, worker_host: str, outbound_tag: str) -> dict:
    kind = str(row.get("kind") or "turn").lower()
    raw = str(row.get("raw") or row.get("turn") or "")
    if kind == "turn":
        turn_path = f"/{raw}?ed=2560"
        return {
            "tag": outbound_tag,
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": worker_host,
                        "port": 443,
                        "users": [{"id": uuid, "encryption": "none"}],
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {"serverName": worker_host},
                "wsSettings": {"path": turn_path, "headers": {"Host": worker_host}},
            },
        }
    if kind in {"http", "https"}:
        return {
            "tag": outbound_tag,
            "protocol": "http",
            "settings": {"servers": [parse_proxy_url(raw, kind)]},
        }
    if kind in {"socks4", "socks5"}:
        return {
            "tag": outbound_tag,
            "protocol": "socks",
            "settings": {"servers": [parse_proxy_url(raw, kind)]},
        }
    if kind in {"vless", "vmess", "trojan", "ss"}:
        from ip_proxy_stage0_healthcheck import PARSERS

        parser = PARSERS.get(kind)
        parsed = parser(raw) if parser else None
        if parsed and parsed.get("outbound"):
            outbound = copy.deepcopy(parsed["outbound"])
            outbound["tag"] = outbound_tag
            return outbound
    raise ValueError(f"unsupported runtime proxy kind: {kind!r}")


def xray_config(rows: list[dict], uuid: str, worker_host: str) -> dict:
    inbounds = []
    outbounds = []
    rules = []
    for row in rows:
        port = int(row["local_port"])
        inbound_tag = f"in-{port}"
        outbound_tag = f"out-{port}"
        inbounds.append(
            {
                "tag": inbound_tag,
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            }
        )
        outbounds.append(outbound_for_row(row, uuid, worker_host, outbound_tag))
        rules.append({"type": "field", "inboundTag": [inbound_tag], "outboundTag": outbound_tag})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


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


def split_csv_values(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip().upper() for part in value.split(",") if part.strip()}


def cli_flag_present(flag: str, argv: list[str] | None = None) -> bool:
    argv = sys.argv[1:] if argv is None else argv
    return any(part == flag or part.startswith(f"{flag}=") for part in argv)


def apply_pool_mode_defaults(args: argparse.Namespace) -> None:
    defaults = {
        "relaxed": RELAXED_QUANTITY_DEFAULTS,
        "raw": RAW_QUANTITY_DEFAULTS,
    }.get(args.pool_mode)
    if defaults is None:
        return
    for attr, (value, flag, env_name) in defaults.items():
        if cli_flag_present(flag) or env_name in os.environ:
            continue
        if attr == "min_new_candidates":
            value = min(safe_int(value), safe_int(args.limit))
        setattr(args, attr, value)


def file_sha(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bytes_sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def dirty_flags(item: dict) -> set[str]:
    values = item.get("dirty") or []
    if not isinstance(values, list):
        return set()
    return {str(value).strip() for value in values if str(value).strip()}


def normalized_group_value(value: object, fallback: str = "unknown") -> str:
    text = str(value or "").strip()
    return text or fallback


def country_key(item: dict) -> str:
    return normalized_group_value(item.get("country"), "XX").upper()


def company_key(item: dict) -> str:
    return normalized_group_value(item.get("company"), "unknown").lower()


def raw_result_asn(item: dict) -> object:
    raw_result = item.get("raw_result")
    if not isinstance(raw_result, dict):
        return None
    exit_data = raw_result.get("exit")
    if not isinstance(exit_data, dict):
        return None
    asn = exit_data.get("asn")
    if isinstance(asn, dict):
        return asn.get("asn")
    return asn


def asn_key(item: dict) -> str:
    return normalized_group_value(
        item.get("asn")
        or item.get("asn_number")
        or raw_result_asn(item)
        or item.get("exit_ip"),
        "unknown",
    )


def candidate_tier(item: dict) -> str:
    if not item.get("success"):
        return "dirty"
    tier = str(item.get("registration_tier") or "").strip().lower()
    if tier in {"dirty"}:
        return tier
    dirty = dirty_flags(item)
    if dirty & HARD_DIRTY_FLAGS:
        return "dirty"
    country = (item.get("country") or "").upper()
    if country == "CN":
        return "dirty"
    if dirty:
        return "risky" if dirty <= RISKY_DIRTY_FLAGS else "dirty_alive_noncn"
    if tier in {"clean", "risky", "dirty_alive_noncn"}:
        return tier
    if item.get("clean") and item.get("success"):
        return "clean"
    return "clean"


def pool_mode_tiers(pool_mode: str) -> set[str]:
    if pool_mode == "strict":
        return {"clean"}
    if pool_mode == "relaxed":
        return {"clean", "risky"}
    if pool_mode == "raw":
        return {"clean", "risky", "dirty_alive_noncn"}
    raise ValueError(f"invalid pool_mode={pool_mode!r}")


def turn_candidates(path: Path, pool_mode: str = "strict") -> list[dict]:
    if pool_mode not in ALLOWED_POOL_MODES:
        raise ValueError(f"invalid pool_mode={pool_mode!r}")
    data = read_json(path, [])
    if not isinstance(data, list):
        return []
    out = []
    allowed_tiers = pool_mode_tiers(pool_mode)
    for item in data:
        if not isinstance(item, dict):
            continue
        if item.get("kind") not in RUNTIME_CANDIDATE_KINDS or not item.get("success"):
            continue
        if not item.get("raw") or not item.get("exit_ip"):
            continue
        tier = candidate_tier(item)
        if tier not in allowed_tiers:
            continue
        row = dict(item)
        row["registration_tier"] = tier
        row["registration_eligible"] = True
        row["relaxed_pool"] = pool_mode == "relaxed"
        row["raw_pool"] = pool_mode == "raw"
        out.append(row)
    out.sort(key=lambda item: (pool_priority(item), item.get("responseTime") or 999999, item.get("raw") or ""))
    return out


def filter_candidates(
    candidates: list[dict],
    *,
    exclude_countries: set[str] | None = None,
    max_response_time: float = 0.0,
) -> tuple[list[dict], dict]:
    exclude_countries = exclude_countries or set()
    out: list[dict] = []
    excluded_country = 0
    excluded_response_time = 0
    for item in candidates:
        country = str(item.get("country") or "").upper()
        if exclude_countries and country in exclude_countries:
            excluded_country += 1
            continue
        response_time = safe_float(item.get("responseTime"))
        if max_response_time > 0 and response_time > max_response_time:
            excluded_response_time += 1
            continue
        out.append(item)
    return out, {
        "before_filter": len(candidates),
        "after_filter": len(out),
        "excluded_country": excluded_country,
        "excluded_response_time": excluded_response_time,
        "exclude_countries": sorted(exclude_countries),
        "max_response_time": max_response_time,
    }


def is_sandbox_live_candidate(item: dict) -> bool:
    if bool(item.get("sandbox_live")) and item.get("success"):
        return True
    checked_from = str(item.get("checked_from") or item.get("live_checked_from") or "").lower()
    if checked_from in {"sandbox", "daytona", "daytona_sandbox"} and item.get("success"):
        return bool(item.get("trace_ip") or item.get("exit_ip"))
    live_check = item.get("live_check")
    if isinstance(live_check, dict):
        source = str(live_check.get("checked_from") or live_check.get("environment") or "").lower()
        ok = bool(live_check.get("success") or live_check.get("ok") or live_check.get("live"))
        if source in {"sandbox", "daytona", "daytona_sandbox"} and ok:
            return bool(live_check.get("trace_ip") or live_check.get("exit_ip") or item.get("exit_ip"))
    return False


def filter_sandbox_live_candidates(candidates: list[dict], require_sandbox_live: bool) -> tuple[list[dict], dict]:
    if not require_sandbox_live:
        return candidates, {
            "require_sandbox_live": False,
            "before_filter": len(candidates),
            "after_filter": len(candidates),
            "excluded_not_sandbox_live": 0,
        }
    out = [item for item in candidates if is_sandbox_live_candidate(item)]
    return out, {
        "require_sandbox_live": True,
        "before_filter": len(candidates),
        "after_filter": len(out),
        "excluded_not_sandbox_live": len(candidates) - len(out),
    }


def clean_turn_candidates(path: Path) -> list[dict]:
    return turn_candidates(path, "strict")


def default_input_for_pool_mode(pool_mode: str) -> Path:
    if pool_mode == "raw":
        return DEFAULT_RAW_INPUT
    return DEFAULT_RELAXED_INPUT if pool_mode == "relaxed" else DEFAULT_STRICT_INPUT


def candidate_file_prefix_for_pool_mode(pool_mode: str) -> str:
    if pool_mode == "raw":
        return "all"
    return "relaxed" if pool_mode == "relaxed" else "clean"


def file_age_hours(path: Path, now: float | None = None) -> float | None:
    if not path.exists():
        return None
    now = time.time() if now is None else now
    return round(max(0.0, now - path.stat().st_mtime) / 3600.0, 2)


def candidate_file_audit(
    path: Path,
    candidates: list[dict],
    *,
    role: str,
    min_clean: int,
    max_age_hours: float,
    allow_stale: bool,
    filter_meta: dict | None = None,
    now: float | None = None,
) -> dict:
    age_hours = file_age_hours(path, now)
    enough_clean = len(candidates) >= min_clean
    fresh_enough = (
        allow_stale
        or max_age_hours <= 0
        or age_hours is None
        or age_hours <= max_age_hours
    )
    reason = ""
    if not enough_clean:
        reason = "not_enough_clean_candidates"
    elif not fresh_enough:
        reason = "stale_candidate_file"
    return {
        "path": str(path),
        "role": role,
        "candidate_count": len(candidates),
        "clean_turn_candidates": sum(1 for item in candidates if candidate_tier(item) == "clean"),
        "risky_turn_candidates": sum(1 for item in candidates if candidate_tier(item) == "risky"),
        "min_clean": min_clean,
        "age_hours": age_hours,
        "max_age_hours": max_age_hours,
        "allow_stale": allow_stale,
        "filters": filter_meta or {},
        "accepted": bool(enough_clean and fresh_enough),
        "reason": reason,
    }


def load_source_quality(path: Path) -> tuple[dict[str, dict], dict]:
    data = read_json(path, {})
    if not isinstance(data, dict):
        return {}, {"path": str(path), "loaded": False, "reason": "invalid_json_shape"}
    by_source = data.get("by_source")
    if not isinstance(by_source, dict):
        return {}, {"path": str(path), "loaded": False, "reason": "missing_by_source"}
    quality = {str(source): item for source, item in by_source.items() if isinstance(item, dict)}
    return quality, {"path": str(path), "loaded": bool(quality), "source_count": len(quality)}


def source_quality_sort_key(item: dict, source_quality: dict[str, dict] | None) -> tuple:
    quality = (source_quality or {}).get(str(item.get("source") or "unknown"), {})
    return (
        pool_priority(item),
        -safe_int(quality.get("clean")),
        -safe_float(quality.get("clean_rate_pct")),
        -safe_int(quality.get("success")),
        -safe_float(quality.get("success_rate_pct")),
        item.get("responseTime") or 999999,
        item.get("raw") or "",
    )


def prioritize_candidates(candidates: list[dict], source_quality: dict[str, dict] | None) -> list[dict]:
    if not source_quality:
        return diversify_candidates(candidates)
    return diversify_candidates(sorted(candidates, key=lambda item: source_quality_sort_key(item, source_quality)))


def diversify_candidates(candidates: list[dict]) -> list[dict]:
    """Spread otherwise similar candidates across country/company/ASN groups."""
    remaining = list(enumerate(candidates))
    out: list[dict] = []
    country_counts: collections.Counter[str] = collections.Counter()
    company_counts: collections.Counter[str] = collections.Counter()
    asn_counts: collections.Counter[str] = collections.Counter()
    while remaining:
        best_index, (original_index, item) = min(
            enumerate(remaining),
            key=lambda row: (
                pool_priority(row[1][1]),
                country_counts[country_key(row[1][1])],
                asn_counts[asn_key(row[1][1])],
                company_counts[company_key(row[1][1])],
                row[1][0],
                safe_float(row[1][1].get("responseTime")) or 999999,
                row[1][1].get("raw") or "",
            ),
        )
        remaining.pop(best_index)
        out.append(item)
        country_counts[country_key(item)] += 1
        company_counts[company_key(item)] += 1
        asn_counts[asn_key(item)] += 1
    return out


def counter_dict(counter: collections.Counter[str]) -> dict[str, int]:
    return {key: count for key, count in sorted(counter.items(), key=lambda row: (-row[1], row[0]))}


def top_counter_item(counter: collections.Counter[str], total: int) -> dict:
    if not counter or total <= 0:
        return {"value": "", "count": 0, "ratio": 0.0}
    value, count = sorted(counter.items(), key=lambda row: (-row[1], row[0]))[0]
    return {"value": value, "count": count, "ratio": round(count / total, 4)}


def selection_quality_report(rows: list[dict]) -> dict:
    total = len(rows)
    tier_counts = collections.Counter(str(row.get("registration_tier") or "unknown") for row in rows)
    country_counts = collections.Counter(country_key(row) for row in rows)
    company_counts = collections.Counter(company_key(row) for row in rows)
    asn_counts = collections.Counter(asn_key(row) for row in rows)
    risky = tier_counts.get("risky", 0)
    clean = tier_counts.get("clean", 0)
    return {
        "total": total,
        "clean_selected": clean,
        "risky_selected": risky,
        "risky_ratio": round(risky / total, 4) if total else 0.0,
        "tier_counts": counter_dict(tier_counts),
        "unique_country_count": len(country_counts),
        "unique_company_count": len(company_counts),
        "unique_asn_count": len(asn_counts),
        "country_counts": counter_dict(country_counts),
        "company_counts": counter_dict(company_counts),
        "asn_counts": counter_dict(asn_counts),
        "top_country": top_counter_item(country_counts, total),
        "top_company": top_counter_item(company_counts, total),
        "top_asn": top_counter_item(asn_counts, total),
    }


def selection_quality_gate_config(args: argparse.Namespace) -> dict:
    return {
        "max_risky_candidates": args.max_risky_candidates,
        "max_risky_ratio": args.max_risky_ratio,
        "min_strict_clean_selected": args.min_strict_clean_selected,
        "min_countries": args.min_countries,
        "max_country_ratio": args.max_country_ratio,
        "max_company_ratio": args.max_company_ratio,
        "max_asn_ratio": args.max_asn_ratio,
        "allow_selection_quality_failures": args.allow_selection_quality_failures,
    }


def selection_quality_violations(quality: dict, gate: dict) -> list[dict]:
    violations: list[dict] = []
    risky_selected = safe_int(quality.get("risky_selected"))
    max_risky_candidates = safe_int(gate.get("max_risky_candidates"))
    if max_risky_candidates >= 0 and risky_selected > max_risky_candidates:
        violations.append(
            {
                "field": "risky_selected",
                "actual": risky_selected,
                "limit": max_risky_candidates,
                "reason": "too_many_risky_candidates",
            }
        )
    max_risky_ratio = safe_float(gate.get("max_risky_ratio"))
    if max_risky_ratio > 0 and safe_float(quality.get("risky_ratio")) > max_risky_ratio:
        violations.append(
            {
                "field": "risky_ratio",
                "actual": quality.get("risky_ratio"),
                "limit": max_risky_ratio,
                "reason": "risky_ratio_too_high",
            }
        )
    min_strict_clean_selected = safe_int(gate.get("min_strict_clean_selected"))
    if min_strict_clean_selected > 0 and safe_int(quality.get("clean_selected")) < min_strict_clean_selected:
        violations.append(
            {
                "field": "clean_selected",
                "actual": quality.get("clean_selected"),
                "limit": min_strict_clean_selected,
                "reason": "not_enough_strict_clean_selected",
            }
        )
    min_countries = safe_int(gate.get("min_countries"))
    if min_countries > 0 and safe_int(quality.get("unique_country_count")) < min_countries:
        violations.append(
            {
                "field": "unique_country_count",
                "actual": quality.get("unique_country_count"),
                "limit": min_countries,
                "reason": "not_enough_country_diversity",
            }
        )
    for field, gate_field, reason in (
        ("top_country", "max_country_ratio", "country_concentration_too_high"),
        ("top_company", "max_company_ratio", "company_concentration_too_high"),
        ("top_asn", "max_asn_ratio", "asn_concentration_too_high"),
    ):
        limit = safe_float(gate.get(gate_field))
        top = quality.get(field) if isinstance(quality.get(field), dict) else {}
        actual = safe_float(top.get("ratio"))
        if limit > 0 and actual > limit:
            violations.append(
                {
                    "field": f"{field}.ratio",
                    "actual": actual,
                    "limit": limit,
                    "value": top.get("value"),
                    "count": top.get("count"),
                    "reason": reason,
                }
            )
    return violations


def resolve_candidate_input(
    path: Path,
    min_clean: int,
    source_quality: dict[str, dict] | None = None,
    max_age_hours: float = DEFAULT_MAX_FALLBACK_CANDIDATE_AGE_HOURS,
    allow_stale: bool = False,
    pool_mode: str = "strict",
    exclude_countries: set[str] | None = None,
    max_response_time: float = 0.0,
) -> tuple[Path, list[dict], str | None, list[dict]]:
    audit: list[dict] = []
    raw_candidates = turn_candidates(path, pool_mode)
    candidates, filter_meta = filter_candidates(
        raw_candidates,
        exclude_countries=exclude_countries,
        max_response_time=max_response_time,
    )
    candidates = prioritize_candidates(candidates, source_quality)
    requested_audit = candidate_file_audit(
        path,
        candidates,
        role="requested_input",
        min_clean=min_clean,
        max_age_hours=max_age_hours,
        allow_stale=allow_stale,
        filter_meta=filter_meta,
    )
    audit.append(requested_audit)
    if requested_audit["accepted"]:
        return path, candidates, None, audit

    fallback_files = sorted(
        [
            *RUNTIME_RESIN_DIR.glob(f"{candidate_file_prefix_for_pool_mode(pool_mode)}_candidates_classified*.json"),
            *RESIN_DIR.glob(f"{candidate_file_prefix_for_pool_mode(pool_mode)}_candidates_classified*.json"),
        ],
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    # Limit fallback search to most recent files; accumulated empty cron
    # outputs can create thousands of files that bloat the audit list and
    # trigger ARG_MAX when the JSON is passed on the command line.
    _MAX_FALLBACK_FILES = int(os.environ.get("IP_PROXY_MAX_FALLBACK_FILES", "30"))
    fallback_files = fallback_files[:_MAX_FALLBACK_FILES]
    for fallback in fallback_files:
        if fallback == path:
            continue
        # Skip files that are clearly empty (3 bytes = "[]\n") to avoid
        # unnecessary parsing and audit entries.
        if fallback.stat().st_size <= 5:
            continue
        fallback_raw_candidates = turn_candidates(fallback, pool_mode)
        fallback_candidates, fallback_filter_meta = filter_candidates(
            fallback_raw_candidates,
            exclude_countries=exclude_countries,
            max_response_time=max_response_time,
        )
        fallback_candidates = prioritize_candidates(fallback_candidates, source_quality)
        item_audit = candidate_file_audit(
            fallback,
            fallback_candidates,
            role="fallback",
            min_clean=min_clean,
            max_age_hours=max_age_hours,
            allow_stale=allow_stale,
            filter_meta=fallback_filter_meta,
        )
        audit.append(item_audit)
        if item_audit["accepted"]:
            if requested_audit["reason"] == "stale_candidate_file":
                reason = f"{path} had {len(candidates)} clean TURN candidates but was stale ({requested_audit['age_hours']}h)"
            else:
                reason = f"{path} only had {len(candidates)} clean TURN candidates"
            return fallback, fallback_candidates, reason, audit
    return path, [] if requested_audit["reason"] == "stale_candidate_file" else candidates, requested_audit["reason"] or None, audit


def failed_exit_ips(verify_path: Path) -> set[str]:
    return {
        exit_ip
        for exit_ip, detail in failed_exit_details(verify_path).items()
        if exit_ip and not detail.get("sentinel")
    }


def failed_exit_details(verify_path: Path) -> dict[str, dict]:
    data = read_json(verify_path, {})
    if not isinstance(data, dict):
        return {}
    failed: dict[str, dict] = {}

    def add(exit_ip: object, reason: str, source: str, **extra: object) -> None:
        value = str(exit_ip or "").strip()
        if not value:
            return
        item = failed.setdefault(value, {"exit_ip": value, "reasons": {}, "sources": set()})
        item["reasons"][reason] = int(item["reasons"].get(reason, 0)) + 1
        item["sources"].add(source)
        for key, val in extra.items():
            if val not in (None, "", [], {}):
                item[key] = val

    for item in data.get("port_results", []):
        if isinstance(item, dict) and not item.get("ok") and item.get("expected"):
            add(
                item.get("expected"),
                "port_result_failed",
                "port_results",
                port=item.get("port"),
                got=str(item.get("got") or "")[:300],
            )

    resin_tests = [item for item in data.get("resin_tests", []) if isinstance(item, dict)]
    exit_counter: collections.Counter[str] = collections.Counter()
    for item in resin_tests:
        exit_ip = str(item.get("exit_ip") or "").strip()
        identity = str(item.get("identity") or "")
        if exit_ip:
            exit_counter[exit_ip] += 1
        if exit_ip and item.get("bad_exit"):
            add(exit_ip, "resin_bad_exit_hit", "resin_tests", identity=identity)
        target_failed = item.get("target_ok") is False or ("target_ok" not in item and item.get("signup_ok") is False)
        if exit_ip and item.get("ok") and target_failed:
            add(
                exit_ip,
                "resin_target_failed",
                "resin_tests",
                identity=identity,
                target_status=item.get("target_status") or item.get("signup_status"),
            )

    unique_res_count = safe_int(data.get("unique_res_exit_count"))
    resin_total = safe_int(data.get("resin_total"))
    resin_ok = safe_int(data.get("resin_ok"))
    min_unique_res = safe_int(data.get("min_unique_res_exits") or os.environ.get("IP_PROXY_MIN_UNIQUE_RES_EXITS", "12"))
    if resin_ok > 0 and unique_res_count > 0 and unique_res_count < min_unique_res:
        for exit_ip, count in exit_counter.items():
            add(
                exit_ip,
                "resin_low_diversity",
                "resin_tests",
                resin_identity_hits=count,
                unique_res_exit_count=unique_res_count,
                min_unique_res_exits=min_unique_res,
            )
    if resin_total > 0 and resin_ok == 0:
        failed["__runtime_resin_unusable__"] = {
            "exit_ip": "",
            "reasons": {"resin_all_identities_failed": resin_total},
            "sources": {"resin_tests"},
            "sentinel": True,
        }

    for item in failed.values():
        sources = item.get("sources")
        if isinstance(sources, set):
            item["sources"] = sorted(sources)
    return failed


def registrar_failed_exit_ips(feedback_path: Path) -> set[str]:
    data = read_json(feedback_path, {})
    if not isinstance(data, dict):
        return set()
    failed: set[str] = set()
    for field in ("bad_exit_ips", "avoid_exit_ips"):
        values = data.get(field, [])
        if not isinstance(values, list):
            continue
        failed.update(str(item).strip() for item in values if str(item).strip())
    return failed


def normalize_row(item: dict, port: int, worker_host: str, uuid: str, source: str) -> dict:
    raw = item.get("turn") or item.get("raw")
    kind = str(item.get("kind") or "turn").lower()
    row = dict(item)
    row["raw"] = raw
    if kind == "turn":
        row["turn"] = raw
    elif "turn" in row:
        row.pop("turn", None)
    row["local_port"] = port
    row["kind"] = kind
    row["success"] = True
    row["source"] = source
    row["selection_source"] = source
    row["upstream_source"] = item.get("source")
    tier = candidate_tier(row)
    row["registration_tier"] = tier
    row["clean"] = tier == "clean"
    row["registration_eligible"] = row["registration_tier"] in {"clean", "risky", "dirty_alive_noncn"}
    row["relaxed_pool"] = row.get("registration_tier") == "risky" or bool(item.get("relaxed_pool"))
    row["raw_pool"] = bool(item.get("raw_pool"))
    row["pool_class"] = classify(row)
    row["pool_priority"] = pool_priority(row)
    row["tag"] = row.get("tag") or make_tag(row)
    if kind == "turn":
        row["worker_path"] = f"/{raw}?ed=2560"
        row["vless"] = vless_url(uuid, worker_host, raw)
    return row


def select_rows(
    baseline: list[dict],
    candidates: list[dict],
    bad_exit_ips: set[str],
    limit: int,
    worker_host: str,
    uuid: str,
    min_new_candidates: int = 0,
    preserve_baseline_count: int = 0,
    retain_failed_baseline: bool = True,
) -> tuple[list[dict], dict]:
    by_exit: dict[str, dict] = {}
    by_raw: set[str] = set()
    by_port: set[int] = set()
    selected: list[dict] = []

    def next_available_port() -> int:
        port = 19080
        while port in by_port:
            port += 1
        return port

    def add(item: dict, source: str, allow_bad: bool = False, port: int | None = None) -> bool:
        raw = item.get("turn") or item.get("raw")
        exit_ip = item.get("exit_ip")
        if not raw or not exit_ip or raw in by_raw or exit_ip in by_exit:
            return False
        if not allow_bad and str(exit_ip) in bad_exit_ips:
            return False
        if len(selected) >= limit:
            return False
        if port is not None and port in by_port:
            return False
        local_port = int(port) if port is not None else next_available_port()
        selected.append(normalize_row(item, local_port, worker_host, uuid, source))
        by_raw.add(str(raw))
        by_port.add(local_port)
        by_exit[str(exit_ip)] = item
        return True

    min_new_candidates = max(0, min(int(min_new_candidates or 0), limit))
    preserve_baseline_count = max(0, min(int(preserve_baseline_count or 0), max(0, limit - min_new_candidates)))
    baseline_good = [item for item in baseline if str(item.get("exit_ip")) not in bad_exit_ips]
    baseline_priority = [item for item in baseline_good if pool_priority(item) <= 1]
    baseline_fallback = [item for item in baseline_good if pool_priority(item) > 1]
    baseline_by_port = sorted(
        baseline_good,
        key=lambda item: (safe_int(item.get("local_port")) or 999999, item.get("raw") or item.get("turn") or ""),
    )

    retained_protected_baseline = 0
    if preserve_baseline_count:
        for item in baseline_by_port:
            port = safe_int(item.get("local_port")) or 19080 + len(selected)
            if add(item, "baseline_protected", port=port):
                retained_protected_baseline += 1
            if retained_protected_baseline >= preserve_baseline_count:
                break

    retained_stable_baseline = 0
    if preserve_baseline_count:
        for item in baseline_by_port:
            port = safe_int(item.get("local_port")) or 19080 + len(selected)
            if add(item, "baseline_stable", port=port):
                retained_stable_baseline += 1
            if len(selected) >= limit:
                break

    for item in baseline_priority:
        if len(selected) >= max(0, limit - min_new_candidates):
            break
        add(item, "baseline")

    added_from_candidates = 0
    for item in candidates:
        if add(item, "clean_latest"):
            added_from_candidates += 1
        if len(selected) >= limit:
            break

    retained_reserved_baseline = 0
    if len(selected) < limit:
        for item in baseline_priority:
            if add(item, "baseline_reserved"):
                retained_reserved_baseline += 1
            if len(selected) >= limit:
                break

    retained_low_priority_baseline = 0
    if len(selected) < limit:
        for item in baseline_fallback:
            if add(item, "baseline_low_priority"):
                retained_low_priority_baseline += 1
            if len(selected) >= limit:
                break

    if retain_failed_baseline and len(selected) < limit:
        for item in baseline:
            add(item, "baseline_retain_failed", allow_bad=True)
            if len(selected) >= limit:
                break

    retained_bad_exit_ips = sorted(
        {
            str(row.get("exit_ip"))
            for row in selected
            if row.get("source") == "baseline_retain_failed" and str(row.get("exit_ip")) in bad_exit_ips
        }
    )
    retained_bad_exit_details = {
        exit_ip: {
            "source": "baseline_retain_failed",
            "reason": "not_enough_replacement_candidates",
        }
        for exit_ip in retained_bad_exit_ips
    }

    selected.sort(key=lambda row: int(row.get("local_port") or 0))
    return selected, {
        "bad_exit_ips": sorted(bad_exit_ips),
        "added_from_candidates": added_from_candidates,
        "retained_protected_baseline": retained_protected_baseline,
        "retained_stable_baseline": retained_stable_baseline,
        "retained_priority_baseline": sum(1 for row in selected if row.get("source") == "baseline"),
        "retained_reserved_baseline": retained_reserved_baseline,
        "retained_low_priority_baseline": retained_low_priority_baseline,
        "retained_bad_exit_ips": retained_bad_exit_ips,
        "retained_bad_exit_details": retained_bad_exit_details,
        "dropped_failed_baseline": not retain_failed_baseline,
        "selected": len(selected),
        "limit": limit,
    }


def write_runtime(rows: list[dict], worker_host: str, uuid: str, write_docs: bool, dry_run: bool) -> dict:
    runtime_conf = RUNTIME / "conf"
    runtime_resin = RUNTIME / "resin"
    if not dry_run:
        runtime_conf.mkdir(parents=True, exist_ok=True)
        runtime_resin.mkdir(parents=True, exist_ok=True)
        RUNTIME.mkdir(parents=True, exist_ok=True)

    files = {
        "mapping": RUNTIME / "turn_xray_pool_20260608.json",
        "xray": runtime_conf / "xray_turn_pool_25.generated.json",
        "subscription": runtime_resin / "turn_xray_pool_25.local.txt",
        "subscription_alias": runtime_resin / "turn_xray_pool.local.txt",
        "vless": runtime_resin / "turn_vless_pool_25.txt",
    }
    before = {name: file_sha(path) for name, path in files.items()}

    local_lines = [f"socks5://127.0.0.1:{row['local_port']}#{row['tag']}" for row in rows]
    vless_lines = [f"{row['vless']}#{row['tag']}" for row in rows if row.get("vless")]
    payloads = {
        "mapping": json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
        "xray": json.dumps(xray_config(rows, uuid, worker_host), ensure_ascii=False, indent=2) + "\n",
        "subscription": "\n".join(local_lines) + "\n",
        "subscription_alias": "\n".join(local_lines) + "\n",
        "vless": "\n".join(vless_lines) + "\n",
    }
    if not dry_run:
        for name, text in payloads.items():
            atomic_write_text(files[name], text)

    if write_docs:
        if dry_run:
            raise SystemExit("--dry-run cannot be combined with --write-docs")
        shutil.copy2(files["mapping"], DOC_RUNTIME_DIR / "turn_xray_pool_20260608.json")
        shutil.copy2(files["xray"], RESIN_DIR / "xray_turn_pool_25.generated.json")
        shutil.copy2(files["subscription"], RESIN_DIR / "turn_xray_pool_25.local.txt")
        shutil.copy2(files["subscription_alias"], RESIN_DIR / "turn_xray_pool.local.txt")
        shutil.copy2(files["vless"], RESIN_DIR / "turn_vless_pool_25.txt")

    if dry_run:
        after = {name: bytes_sha(payloads[name].encode("utf-8")) for name in files}
    else:
        after = {name: file_sha(path) for name, path in files.items()}
    changed = [name for name in files if before[name] != after[name]]
    return {"files": {name: str(path) for name, path in files.items()}, "changed_files": changed, "dry_run": dry_run}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=None)
    parser.add_argument("--baseline", type=Path, default=RUNTIME / "turn_xray_pool_20260608.json")
    parser.add_argument(
        "--ignore-baseline",
        action="store_true",
        default=os.environ.get("IP_PROXY_IGNORE_BASELINE", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="build the runtime only from the current candidate input; used by rolling live pools",
    )
    parser.add_argument("--verify", type=Path, default=DEFAULT_VERIFY)
    parser.add_argument("--registrar-feedback", type=Path, default=DEFAULT_REGISTRAR_FEEDBACK)
    parser.add_argument("--source-quality", type=Path, default=DEFAULT_SOURCE_QUALITY)
    parser.add_argument("--worker-host", default=DEFAULT_WORKER_HOST)
    parser.add_argument("--uuid", default=DEFAULT_UUID)
    parser.add_argument(
        "--limit",
        type=int,
        default=int(os.environ.get("IP_PROXY_POOL_SIZE", os.environ.get("IP_PROXY_DEFAULT_POOL_SIZE", "25"))),
    )
    parser.add_argument("--min-clean", type=int, default=int(os.environ.get("IP_PROXY_MIN_CLEAN", "12")))
    parser.add_argument("--min-new-candidates", type=int, default=int(os.environ.get("IP_PROXY_MIN_NEW_CANDIDATES", "8")))
    parser.add_argument(
        "--exclude-country",
        default=os.environ.get("IP_PROXY_EXCLUDE_COUNTRY", ""),
        help="comma-separated country codes to exclude from candidate selection, for example CN,RU",
    )
    parser.add_argument(
        "--max-response-time",
        type=float,
        default=float(os.environ.get("IP_PROXY_MAX_RESPONSE_TIME", "0") or "0"),
        help="drop candidates slower than this checker responseTime in ms; 0 disables the filter",
    )
    parser.add_argument(
        "--pool-mode",
        choices=sorted(ALLOWED_POOL_MODES),
        default=os.environ.get("IP_PROXY_POOL_MODE", "strict"),
        help="strict uses clean TURN candidates only; relaxed also admits risky non-hard-dirty TURN candidates for testing.",
    )
    parser.add_argument(
        "--max-risky-candidates",
        type=int,
        default=DEFAULT_MAX_RISKY_CANDIDATES,
        help="maximum risky candidates allowed in the selected pool; -1 disables this gate",
    )
    parser.add_argument(
        "--max-risky-ratio",
        type=float,
        default=DEFAULT_MAX_RISKY_RATIO,
        help="maximum risky/total ratio allowed in the selected pool; 0 disables this gate",
    )
    parser.add_argument(
        "--min-strict-clean-selected",
        type=int,
        default=DEFAULT_MIN_STRICT_CLEAN_SELECTED,
        help="minimum strict-clean rows required in the selected pool; 0 disables this gate",
    )
    parser.add_argument(
        "--min-countries",
        type=int,
        default=DEFAULT_MIN_COUNTRIES,
        help="minimum number of countries required in the selected pool; 0 disables this gate",
    )
    parser.add_argument(
        "--max-country-ratio",
        type=float,
        default=DEFAULT_MAX_COUNTRY_RATIO,
        help="maximum share of the selected pool allowed for one country; 0 disables this gate",
    )
    parser.add_argument(
        "--max-company-ratio",
        type=float,
        default=DEFAULT_MAX_COMPANY_RATIO,
        help="maximum share of the selected pool allowed for one company; 0 disables this gate",
    )
    parser.add_argument(
        "--max-asn-ratio",
        type=float,
        default=DEFAULT_MAX_ASN_RATIO,
        help="maximum share of the selected pool allowed for one ASN; 0 disables this gate",
    )
    parser.add_argument(
        "--max-fallback-candidate-age-hours",
        type=float,
        default=DEFAULT_MAX_FALLBACK_CANDIDATE_AGE_HOURS,
        help="maximum age for requested/fallback clean candidate files; 0 disables the age check",
    )
    parser.add_argument(
        "--allow-stale-fallback-candidates",
        action="store_true",
        default=os.environ.get("IP_PROXY_ALLOW_STALE_FALLBACK_CANDIDATES", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="allow stale clean candidate files to be used when replacing the runtime pool",
    )
    parser.add_argument("--write-docs", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="compute the refresh result without modifying runtime files")
    parser.add_argument(
        "--require-sandbox-live-candidates",
        action="store_true",
        default=os.environ.get("IP_PROXY_REQUIRE_SANDBOX_LIVE_CANDIDATES", "").strip().lower() in ("1", "true", "yes", "on"),
        help="only promote candidates with sandbox-side live proof into runtime",
    )
    parser.add_argument(
        "--allow-external-checker-candidates",
        action="store_true",
        default=os.environ.get("IP_PROXY_ALLOW_EXTERNAL_CHECKER_CANDIDATES", "").strip().lower() in ("1", "true", "yes", "on"),
        help="allow non-dry-run raw apply from external-checker-only candidates; unsafe unless explicitly acknowledged",
    )
    parser.add_argument(
        "--allow-retain-bad-exits",
        action="store_true",
        default=os.environ.get("IP_PROXY_ALLOW_RETAIN_BAD_EXITS", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="allow runtime apply even if the selected pool still contains known bad exits",
    )
    parser.add_argument(
        "--drop-failed-baseline",
        action="store_true",
        default=os.environ.get("IP_PROXY_DROP_FAILED_BASELINE", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="do not retain known bad baseline exits just to fill --limit; allows shrinking the runtime pool",
    )
    parser.add_argument(
        "--allow-selection-quality-failures",
        action="store_true",
        default=os.environ.get("IP_PROXY_ALLOW_SELECTION_QUALITY_FAILURES", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="allow runtime apply even if the selected pool violates risky/diversity gates",
    )
    args = parser.parse_args()
    apply_pool_mode_defaults(args)
    if (
        args.pool_mode == "raw"
        and not args.dry_run
        and not args.allow_external_checker_candidates
        and "IP_PROXY_REQUIRE_SANDBOX_LIVE_CANDIDATES" not in os.environ
    ):
        args.require_sandbox_live_candidates = True
    if args.input is None:
        args.input = default_input_for_pool_mode(args.pool_mode)

    baseline_path = args.baseline if args.baseline.exists() else DEFAULT_BASELINE
    baseline = [] if args.ignore_baseline else read_json(baseline_path, [])
    if not isinstance(baseline, list):
        raise SystemExit(f"invalid baseline mapping: {baseline_path}")
    source_quality, source_quality_meta = load_source_quality(args.source_quality)
    input_path, candidates, fallback_reason, candidate_input_audit = resolve_candidate_input(
        args.input,
        args.min_clean,
        source_quality,
        args.max_fallback_candidate_age_hours,
        args.allow_stale_fallback_candidates,
        args.pool_mode,
        split_csv_values(args.exclude_country),
        args.max_response_time,
    )
    candidates, sandbox_live_filter = filter_sandbox_live_candidates(candidates, args.require_sandbox_live_candidates)
    if len(candidates) < args.min_clean:
        print(
            json.dumps(
                {
                    "status": "skipped",
                    "reason": "not_enough_clean_candidates",
                    "input": str(args.input),
                    "clean": len(candidates),
                    "min_clean": args.min_clean,
                    "fallback_reason": fallback_reason,
                    "candidate_input_audit": candidate_input_audit,
                    "sandbox_live_filter": sandbox_live_filter,
                    "pool_mode": args.pool_mode,
                    "exclude_country": args.exclude_country,
                    "max_response_time": args.max_response_time,
                    "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
                    "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
                },
                ensure_ascii=False,
            )
        )
        return 0 if args.dry_run else 2

    verify_failed_details = failed_exit_details(args.verify)
    verify_failed = {
        exit_ip
        for exit_ip, detail in verify_failed_details.items()
        if exit_ip and not detail.get("sentinel")
    }
    registrar_failed = registrar_failed_exit_ips(args.registrar_feedback)
    rows, meta = select_rows(
        baseline,
        candidates,
        verify_failed | registrar_failed,
        args.limit,
        args.worker_host,
        args.uuid,
        args.min_new_candidates,
        max(0, args.limit - args.min_new_candidates) if args.pool_mode in {"relaxed", "raw"} else 0,
        not args.drop_failed_baseline,
    )
    if len(rows) < args.limit and not args.drop_failed_baseline:
        raise SystemExit(f"only selected {len(rows)} rows, need {args.limit}")
    if len(rows) <= 0:
        raise SystemExit("selected 0 rows; refusing to write an empty runtime")
    selection_quality = selection_quality_report(rows)
    selection_quality_gate = selection_quality_gate_config(args)
    selection_quality_failures = selection_quality_violations(selection_quality, selection_quality_gate)
    if selection_quality_failures and not args.allow_selection_quality_failures:
        result = {
            "status": "blocked",
            "reason": "selection_quality_gate_failed",
            "changed": False,
            "baseline": str(baseline_path),
            "input": str(input_path),
            "requested_input": str(args.input),
            "verify": str(args.verify),
            "registrar_feedback": str(args.registrar_feedback),
            "source_quality": source_quality_meta,
            "candidate_input_audit": candidate_input_audit,
            "sandbox_live_filter": sandbox_live_filter,
            "pool_mode": args.pool_mode,
            "exclude_country": args.exclude_country,
            "max_response_time": args.max_response_time,
            "verify_bad_exit_ips": sorted(verify_failed),
            "verify_bad_exit_details": verify_failed_details,
            "registrar_bad_exit_ips": sorted(registrar_failed),
            "fallback_reason": fallback_reason,
            "min_new_candidates": args.min_new_candidates,
            "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
            "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
            "selection_quality": selection_quality,
            "selection_quality_gate": selection_quality_gate,
            "selection_quality_failures": selection_quality_failures,
            "dry_run": args.dry_run,
            **meta,
        }
        (ROOT / "captures").mkdir(parents=True, exist_ok=True)
        (ROOT / "captures/ip_pool_refresh_latest.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0 if args.dry_run else 2
    if meta.get("retained_bad_exit_ips") and not args.dry_run and not args.allow_retain_bad_exits:
        result = {
            "status": "blocked",
            "reason": "retained_bad_exits_requires_more_clean_candidates",
            "changed": False,
            "baseline": str(baseline_path),
            "input": str(input_path),
            "requested_input": str(args.input),
            "verify": str(args.verify),
            "registrar_feedback": str(args.registrar_feedback),
            "source_quality": source_quality_meta,
            "candidate_input_audit": candidate_input_audit,
            "sandbox_live_filter": sandbox_live_filter,
            "pool_mode": args.pool_mode,
            "exclude_country": args.exclude_country,
            "max_response_time": args.max_response_time,
            "verify_bad_exit_ips": sorted(verify_failed),
            "verify_bad_exit_details": verify_failed_details,
            "registrar_bad_exit_ips": sorted(registrar_failed),
            "fallback_reason": fallback_reason,
            "min_new_candidates": args.min_new_candidates,
            "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
            "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
            "selection_quality": selection_quality,
            "selection_quality_gate": selection_quality_gate,
            "selection_quality_failures": selection_quality_failures,
            "dry_run": args.dry_run,
            **meta,
        }
        (ROOT / "captures").mkdir(parents=True, exist_ok=True)
        (ROOT / "captures/ip_pool_refresh_latest.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(result, ensure_ascii=False))
        return 2
    written = write_runtime(rows, args.worker_host, args.uuid, args.write_docs, args.dry_run)
    result = {
        "status": "ok",
        "changed": bool(written["changed_files"]),
        "baseline": str(baseline_path),
        "input": str(input_path),
        "requested_input": str(args.input),
        "verify": str(args.verify),
        "registrar_feedback": str(args.registrar_feedback),
        "source_quality": source_quality_meta,
        "candidate_input_audit": candidate_input_audit,
        "sandbox_live_filter": sandbox_live_filter,
        "pool_mode": args.pool_mode,
        "exclude_country": args.exclude_country,
        "max_response_time": args.max_response_time,
        "ignore_baseline": args.ignore_baseline,
        "risky_selected": sum(1 for row in rows if row.get("registration_tier") == "risky"),
        "clean_selected": sum(1 for row in rows if row.get("registration_tier") == "clean"),
        "verify_bad_exit_ips": sorted(verify_failed),
        "verify_bad_exit_details": verify_failed_details,
        "registrar_bad_exit_ips": sorted(registrar_failed),
        "fallback_reason": fallback_reason,
        "min_new_candidates": args.min_new_candidates,
        "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
        "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
        "selection_quality": selection_quality,
        "selection_quality_gate": selection_quality_gate,
        "selection_quality_failures": selection_quality_failures,
        **meta,
        **written,
    }
    (ROOT / "captures").mkdir(parents=True, exist_ok=True)
    (ROOT / "captures/ip_pool_refresh_latest.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
