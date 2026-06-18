#!/usr/bin/env python3
"""Export fixed URL subscription endpoint payloads for IPPOXY."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.parse
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import ip_proxy_pool_refresh as pool


DEFAULT_OUTPUT_DIR = pool.RUNTIME / "subscriptions"
DEFAULT_PUBLIC_DIR = pool.RUNTIME / "subscriptions_public"
DEFAULT_BASE_URL = os.environ.get("IP_PROXY_SUBSCRIPTION_BASE_URL", "https://ipcfg.baiqigo.dpdns.org")
DEFAULT_ALIAS_SALT = os.environ.get("IP_PROXY_SUBSCRIPTION_ALIAS_SALT", "ippoxy-subscription-alias-v1")
DEFAULT_ALIAS_HOST_SEED = os.environ.get(
    "IP_PROXY_SUBSCRIPTION_ALIAS_HOST_SEED",
    "ip-proxy-turn-poc.khowk1isgv.workers.dev",
)
DEFAULT_LIMIT = int(os.environ.get("IP_PROXY_SUBSCRIPTION_LIMIT", os.environ.get("IP_PROXY_POOL_SIZE", "100")))
DEFAULT_EXCLUDE_COUNTRIES = os.environ.get("IP_PROXY_SUBSCRIPTION_EXCLUDE_COUNTRIES", "CN")
DEFAULT_MAX_RESPONSE_MS = int(os.environ.get("IP_PROXY_SUBSCRIPTION_MAX_RESPONSE_MS", "3000"))

COUNTRY_ZH = {
    "AU": "澳大利亚",
    "BD": "孟加拉",
    "BR": "巴西",
    "CA": "加拿大",
    "CN": "中国",
    "DE": "德国",
    "ES": "西班牙",
    "FR": "法国",
    "GB": "英国",
    "HK": "香港",
    "ID": "印尼",
    "IN": "印度",
    "IT": "意大利",
    "JP": "日本",
    "KR": "韩国",
    "MY": "马来西亚",
    "NL": "荷兰",
    "PK": "巴基斯坦",
    "PT": "葡萄牙",
    "RU": "俄罗斯",
    "SG": "新加坡",
    "TH": "泰国",
    "TW": "台湾",
    "US": "美国",
    "VN": "越南",
}

ENDPOINT_PATHS = {
    "flclash": "flclash",
    "flclash_residential": "flclash-residential",
    "flclash_static": "flclash-static",
    "vless": "vless",
    "vless_all": "vless-all",
    "vless_b64": "vless-b64",
    "residential": "residential",
    "residential_b64": "residential-b64",
    "static": "static",
    "static_b64": "static-b64",
    "resin": "resin",
    "resin_residential": "resin-residential",
    "resin_static": "resin-static",
    "xray": "xray",
    "xray_residential": "xray-residential",
    "xray_static": "xray-static",
    "meta": "meta",
    "urls": "urls",
}

CONTENT_TYPES = {
    "flclash": "text/yaml; charset=utf-8",
    "flclash_residential": "text/yaml; charset=utf-8",
    "flclash_static": "text/yaml; charset=utf-8",
    "vless": "text/plain; charset=utf-8",
    "vless_all": "text/plain; charset=utf-8",
    "vless_b64": "text/plain; charset=utf-8",
    "residential": "text/plain; charset=utf-8",
    "residential_b64": "text/plain; charset=utf-8",
    "static": "text/plain; charset=utf-8",
    "static_b64": "text/plain; charset=utf-8",
    "resin": "text/plain; charset=utf-8",
    "resin_residential": "text/plain; charset=utf-8",
    "resin_static": "text/plain; charset=utf-8",
    "xray": "application/json; charset=utf-8",
    "xray_residential": "application/json; charset=utf-8",
    "xray_static": "application/json; charset=utf-8",
    "meta": "application/json; charset=utf-8",
    "urls": "text/plain; charset=utf-8",
}

ALIAS_PREFIXES = {
    "flclash": "assets/profile",
    "flclash_residential": "assets/profile",
    "flclash_static": "assets/profile",
    "vless": "cdn-cfg",
    "vless_all": "cdn-cfg",
    "vless_b64": "cdn-cfg",
    "residential": "update",
    "residential_b64": "update",
    "static": "cache/pkg",
    "static_b64": "cache/pkg",
    "resin": "assets/local",
    "resin_residential": "assets/local",
    "resin_static": "assets/local",
    "xray": "assets/runtime",
    "xray_residential": "assets/runtime",
    "xray_static": "assets/runtime",
    "meta": "health",
    "urls": "assets/list",
}

PUBLIC_ENDPOINTS = {
    "flclash",
    "flclash_residential",
    "flclash_static",
    "vless",
    "vless_all",
    "vless_b64",
    "residential",
    "residential_b64",
    "static",
    "static_b64",
    "resin",
    "resin_residential",
    "resin_static",
    "xray",
    "xray_residential",
    "xray_static",
    "urls",
}


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def yaml_scalar(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def slug_part(value: object, default: str = "unknown", max_len: int = 24) -> str:
    text = str(value or "").strip()
    if not text:
        text = default
    text = text.replace("&", " and ")
    text = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")
    text = text or default
    return text[:max_len].strip("-") or default


def display_class(row: dict) -> str:
    if str(row.get("pool_class") or "").lower() == "res":
        return "RES"
    company_type = str(row.get("company_type") or "").lower()
    asn_type = str(row.get("asn_type") or "").lower()
    if "isp" in {company_type, asn_type} or int(row.get("pool_priority", 99) or 99) == 1:
        return "ISP"
    return "STATIC"


def display_class_zh(row: dict) -> str:
    klass = display_class(row)
    if klass == "RES":
        return "住宅"
    if klass == "ISP":
        return "ISP"
    return "静态"


def country_zh(value: object) -> str:
    code = str(value or "XX").strip().upper()
    return COUNTRY_ZH.get(code, code or "未知")


def node_label(row: dict) -> str:
    location = country_zh(row.get("country"))
    klass = display_class_zh(row)
    exit_ip = str(row.get("exit_ip") or "").strip()
    if exit_ip:
        return f"{location}{klass} {exit_ip}"
    latency = pool.safe_int(row.get("responseTime") or row.get("latency_ms"))
    suffix = f" {latency}ms" if latency > 0 else ""
    return f"{location}{klass}{suffix}"


def annotate_rows(rows: list[dict]) -> list[dict]:
    annotated: list[dict] = []
    seen: dict[str, int] = {}
    for row in rows:
        item = dict(row)
        item["display_class"] = display_class(item)
        base = node_label(item)
        count = seen.get(base, 0) + 1
        seen[base] = count
        item["tag"] = base if count == 1 else f"{base}-{count:02d}"
        annotated.append(item)
    return annotated


def unique_names(rows: list[dict]) -> list[str]:
    seen: dict[str, int] = {}
    names: list[str] = []
    for row in rows:
        base = str(row.get("tag") or row.get("exit_ip") or row.get("raw") or "IPPOXY-NODE")
        count = seen.get(base, 0) + 1
        seen[base] = count
        names.append(base if count == 1 else f"{base}-{count:02d}")
    return names


def url_fragment(name: str) -> str:
    return urllib.parse.quote(name, safe="")


def parse_country_set(value: str) -> set[str]:
    return {part.strip().upper() for part in re.split(r"[,;\s]+", value or "") if part.strip()}


def filter_rows_for_subscription(rows: list[dict], args: argparse.Namespace) -> tuple[list[dict], dict]:
    exclude_countries = parse_country_set(args.exclude_countries)
    max_response_ms = int(args.max_response_ms or 0)
    kept: list[dict] = []
    dropped: list[dict] = []
    reason_counts: Counter[str] = Counter()
    for row in rows:
        reason = None
        country = str(row.get("country") or "").strip().upper()
        response_ms = pool.safe_int(row.get("responseTime") or row.get("latency_ms"))
        if country and country in exclude_countries:
            reason = "excluded_country"
        elif max_response_ms > 0 and response_ms > max_response_ms:
            reason = "response_ms_over_limit"
        if reason:
            reason_counts[reason] += 1
            dropped.append(
                {
                    "name": row.get("tag"),
                    "exit_ip": row.get("exit_ip"),
                    "country": country,
                    "display_class": row.get("display_class"),
                    "response_ms": response_ms,
                    "reason": reason,
                }
            )
            continue
        kept.append(row)
    return kept, {
        "enabled": bool(exclude_countries or max_response_ms > 0),
        "before": len(rows),
        "after": len(kept),
        "dropped": len(dropped),
        "exclude_countries": sorted(exclude_countries),
        "max_response_ms": max_response_ms,
        "drop_reasons": dict(sorted(reason_counts.items())),
        "dropped_examples": dropped[:12],
    }


def endpoint_urls(base_url: str) -> dict[str, str]:
    base = base_url.rstrip("/")
    return {key: f"{base}/{path}" for key, path in ENDPOINT_PATHS.items()}


def alias_path(endpoint: str, args: argparse.Namespace) -> str:
    seed = f"{args.alias_salt}:{args.uuid}:{args.alias_host_seed}:{endpoint}"
    token = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:18]
    prefix = ALIAS_PREFIXES.get(endpoint, "assets/profile").strip("/")
    return f"/{prefix}/{token}"


def alias_urls(base_url: str, args: argparse.Namespace) -> dict[str, str]:
    if args.no_aliases:
        return {}
    base = base_url.rstrip("/")
    return {endpoint: f"{base}{alias_path(endpoint, args)}" for endpoint in ENDPOINT_PATHS}


def vless_export_rows(rows: list[dict]) -> list[dict]:
    return [row for row in rows if row.get("kind") == "turn" and row.get("vless")]


def render_clash(rows: list[dict], worker_host: str, uuid: str) -> str:
    rows = vless_export_rows(rows)
    names = unique_names(rows)
    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "",
        "proxies:",
    ]
    if not rows:
        lines.append("  []")
    for row, name in zip(rows, names, strict=True):
        path = row.get("worker_path") or f"/{row['turn']}?ed=2560"
        lines.extend(
            [
                f"  - name: {yaml_scalar(name)}",
                "    type: vless",
                f"    server: {yaml_scalar(worker_host)}",
                "    port: 443",
                f"    uuid: {yaml_scalar(uuid)}",
                "    udp: true",
                "    tls: true",
                f"    servername: {yaml_scalar(worker_host)}",
                "    network: ws",
                "    encryption: none",
                "    flow: \"\"",
                "    client-fingerprint: chrome",
                "    packet-encoding: xudp",
                "    ws-opts:",
                f"      path: {yaml_scalar(path)}",
                "      headers:",
                f"        Host: {yaml_scalar(worker_host)}",
            ]
        )

    lines.extend(
        [
            "",
            "proxy-groups:",
            "  - name: PROXY",
            "    type: select",
            "    proxies:",
        ]
    )
    if rows:
        lines.append("      - AUTO")
        lines.extend(f"      - {yaml_scalar(name)}" for name in names)
    lines.append("      - DIRECT")
    if rows:
        lines.extend(
            [
                "  - name: AUTO",
                "    type: url-test",
                "    url: https://www.gstatic.com/generate_204",
                "    interval: 300",
                "    tolerance: 80",
                "    proxies:",
            ]
        )
        lines.extend(f"      - {yaml_scalar(name)}" for name in names)
    lines.extend(["", "rules:", "  - MATCH,PROXY", ""])
    return "\n".join(lines)


def render_vless(rows: list[dict]) -> str:
    rows = vless_export_rows(rows)
    return "\n".join(f"{row['vless']}#{url_fragment(name)}" for row, name in zip(rows, unique_names(rows), strict=True)) + "\n"


def render_resin(rows: list[dict]) -> str:
    return "\n".join(
        f"socks5://127.0.0.1:{row['local_port']}#{url_fragment(name)}"
        for row, name in zip(rows, unique_names(rows), strict=True)
    ) + "\n"


def b64_text(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii") + "\n"


def render_headers(
    aliases: dict[str, str],
    include_direct: bool = True,
    content_type_overrides: dict[str, str] | None = None,
) -> str:
    lines: list[str] = []
    content_type_overrides = content_type_overrides or {}
    if include_direct:
        for endpoint, path in ENDPOINT_PATHS.items():
            lines.extend(
                [
                    f"/{path}",
                    f"  Content-Type: {content_type_overrides.get(endpoint, CONTENT_TYPES[endpoint])}",
                    "  Cache-Control: no-store",
                    "  X-Robots-Tag: noindex",
                ]
            )
    for endpoint, url in aliases.items():
        alias_url_path = "/" + url.split("/", 3)[3]
        lines.extend(
            [
                alias_url_path,
                f"  Content-Type: {content_type_overrides.get(endpoint, CONTENT_TYPES[endpoint])}",
                "  Cache-Control: no-store",
                "  X-Robots-Tag: noindex",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def render_urls(
    urls: dict[str, str],
    aliases: dict[str, str],
    *,
    include_debug: bool = True,
    include_meta: bool = True,
) -> str:
    recommended = aliases or urls
    labels = [
        ("FlClash all", "flclash"),
        ("FlClash residential", "flclash_residential"),
        ("FlClash static/ISP", "flclash_static"),
        ("v2rayN plain VLESS all", "vless_all"),
        ("v2rayN base64 VLESS all", "vless_b64"),
        ("v2rayN residential", "residential"),
        ("v2rayN static/ISP", "static"),
        ("Resin local SOCKS all", "resin"),
        ("Resin residential", "resin_residential"),
        ("Resin static/ISP", "resin_static"),
        ("Local Xray config all", "xray"),
        ("Metadata", "meta"),
    ]
    if not include_meta:
        labels = [item for item in labels if item[1] != "meta"]
    lines = ["Recommended import URLs:"]
    lines.extend(f"{label}: {recommended[key]}" for label, key in labels if key in recommended)
    if include_debug:
        lines.extend(["", "Direct debug URLs:"])
        lines.extend(f"{label}: {urls[key]}" for label, key in labels if key in urls)
    lines.append("")
    return "\n".join(lines)


def load_selected_rows(args: argparse.Namespace) -> tuple[list[dict], dict]:
    baseline_path = args.baseline if args.baseline.exists() else pool.DEFAULT_BASELINE
    baseline = pool.read_json(baseline_path, [])
    if not isinstance(baseline, list):
        raise SystemExit(f"invalid baseline mapping: {baseline_path}")

    source_quality, source_quality_meta = pool.load_source_quality(args.source_quality)
    input_path, candidates, fallback_reason, candidate_input_audit = pool.resolve_candidate_input(
        args.input,
        args.min_clean,
        source_quality,
        args.max_fallback_candidate_age_hours,
        args.allow_stale_fallback_candidates,
        args.pool_mode,
    )
    if len(candidates) < args.min_clean:
        raise SystemExit(
            json.dumps(
                {
                    "status": "skipped",
                    "reason": "not_enough_clean_candidates",
                    "input": str(input_path),
                    "clean": len(candidates),
                    "min_clean": args.min_clean,
                    "fallback_reason": fallback_reason,
                    "candidate_input_audit": candidate_input_audit,
                    "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
                    "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
                },
                ensure_ascii=False,
            )
        )

    verify_failed = pool.failed_exit_ips(args.verify)
    registrar_failed = pool.registrar_failed_exit_ips(args.registrar_feedback)
    bad_exit_ips = verify_failed | registrar_failed
    rows, selection_meta = pool.select_rows(
        baseline,
        candidates,
        bad_exit_ips,
        args.limit,
        args.worker_host,
        args.uuid,
    )
    retained_bad = set(selection_meta.get("retained_bad_exit_ips") or [])
    if retained_bad and not args.allow_retain_bad_exits:
        if args.strict_limit:
            raise SystemExit(
                json.dumps(
                    {
                        "status": "blocked",
                        "reason": "retained_bad_exits_requires_more_clean_candidates",
                        "retained_bad_exit_ips": sorted(retained_bad),
                    },
                    ensure_ascii=False,
                )
            )
        rows = [row for row in rows if str(row.get("exit_ip")) not in retained_bad]
        selection_meta["dropped_bad_exit_ips"] = sorted(retained_bad)
        selection_meta["retained_bad_exit_ips"] = []
        selection_meta["retained_bad_exit_details"] = {}
        selection_meta["selected"] = len(rows)

    required = args.limit if args.strict_limit else min(args.min_clean, args.limit)
    if len(rows) < required:
        raise SystemExit(f"only selected {len(rows)} rows, need {required}")

    rows = annotate_rows(rows)
    rows, subscription_filter = filter_rows_for_subscription(rows, args)
    if len(rows) < required:
        raise SystemExit(f"only selected {len(rows)} rows after subscription filters, need {required}")
    meta = {
        "baseline": str(baseline_path),
        "input": str(input_path),
        "requested_input": str(args.input),
        "verify": str(args.verify),
        "registrar_feedback": str(args.registrar_feedback),
        "source_quality": source_quality_meta,
        "verify_bad_exit_ips": sorted(verify_failed),
        "registrar_bad_exit_ips": sorted(registrar_failed),
        "fallback_reason": fallback_reason,
        "candidate_input_audit": candidate_input_audit,
        "pool_mode": args.pool_mode,
        "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
        "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
        "requested_limit": args.limit,
        "strict_limit": args.strict_limit,
        "subscription_filter": subscription_filter,
        **selection_meta,
    }
    return rows, meta


def row_group(rows: list[dict], group: str) -> list[dict]:
    if group == "residential":
        return [row for row in rows if str(row.get("pool_class") or "").lower() == "res"]
    if group == "static":
        return [row for row in rows if str(row.get("pool_class") or "").lower() != "res"]
    return rows


def node_meta(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        out.append(
            {
                "name": row.get("tag"),
                "exit_ip": row.get("exit_ip"),
                "country": row.get("country"),
                "city": row.get("city"),
                "company": row.get("company"),
                "company_type": row.get("company_type"),
                "asn_type": row.get("asn_type"),
                "pool_class": row.get("pool_class"),
                "display_class": row.get("display_class"),
                "response_ms": row.get("responseTime"),
                "source": row.get("selection_source"),
            }
        )
    return out


def build_meta(
    rows: list[dict],
    groups: dict[str, list[dict]],
    selection_meta: dict,
    urls: dict[str, str],
    aliases: dict[str, str],
    output_dir: Path,
    args: argparse.Namespace,
) -> dict:
    countries = Counter(str(row.get("country") or "unknown") for row in rows)
    pool_classes = Counter(str(row.get("pool_class") or "unknown") for row in rows)
    display_classes = Counter(str(row.get("display_class") or "unknown") for row in rows)
    priorities = Counter(str(row.get("pool_priority", "unknown")) for row in rows)
    country_class = Counter(
        f"{row.get('country') or 'unknown'}:{row.get('display_class') or 'unknown'}" for row in rows
    )
    output_counts = {
        "all": len(groups["all"]),
        "residential": len(groups["residential"]),
        "static": len(groups["static"]),
    }
    return {
        "status": "ok",
        "generated_at": int(time.time()),
        "base_url": args.base_url.rstrip("/"),
        "endpoints": urls,
        "alias_endpoints": aliases,
        "recommended_endpoints": aliases or urls,
        "output_dir": str(output_dir),
        "node_count": len(rows),
        "unique_exit_ips": len({str(row.get("exit_ip")) for row in rows if row.get("exit_ip")}),
        "requested_limit": args.limit,
        "worker_host": args.worker_host,
        "alias_mode": "static_path_aliases" if aliases else "disabled",
        "alias_note": "Aliases disguise public import paths only; use a private alias salt or Worker access checks for real access control.",
        "resin_requires_local_xray": True,
        "resin_note": "Use the /xray endpoint, or its alias, to run local Xray SOCKS ports before importing /resin into local Resin.",
        "counts": {
            "by_country": dict(sorted(countries.items())),
            "by_pool_class": dict(sorted(pool_classes.items())),
            "by_display_class": dict(sorted(display_classes.items())),
            "by_pool_priority": dict(sorted(priorities.items())),
            "by_country_display_class": dict(sorted(country_class.items())),
        },
        "output_counts": output_counts,
        "nodes": node_meta(rows),
        "selection": selection_meta,
        "files": {endpoint: str(output_dir / path) for endpoint, path in ENDPOINT_PATHS.items()},
    }


def build_payloads(
    rows: list[dict],
    groups: dict[str, list[dict]],
    meta: dict,
    urls: dict[str, str],
    aliases: dict[str, str],
    args: argparse.Namespace,
) -> dict[str, str]:
    del rows, urls, aliases
    all_vless = render_vless(groups["all"])
    residential_vless = render_vless(groups["residential"])
    static_vless = render_vless(groups["static"])
    return {
        "flclash": render_clash(groups["all"], args.worker_host, args.uuid),
        "flclash_residential": render_clash(groups["residential"], args.worker_host, args.uuid),
        "flclash_static": render_clash(groups["static"], args.worker_host, args.uuid),
        "vless": all_vless,
        "vless_all": all_vless,
        "vless_b64": b64_text(all_vless),
        "residential": residential_vless,
        "residential_b64": b64_text(residential_vless),
        "static": static_vless,
        "static_b64": b64_text(static_vless),
        "resin": render_resin(groups["all"]),
        "resin_residential": render_resin(groups["residential"]),
        "resin_static": render_resin(groups["static"]),
        "xray": json.dumps(pool.xray_config(groups["all"], args.uuid, args.worker_host), ensure_ascii=False, indent=2) + "\n",
        "xray_residential": json.dumps(
            pool.xray_config(groups["residential"], args.uuid, args.worker_host),
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        "xray_static": json.dumps(
            pool.xray_config(groups["static"], args.uuid, args.worker_host),
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        "meta": json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        "urls": render_urls(meta["endpoints"], meta["alias_endpoints"]),
    }


def clear_runtime_public_dir(public_dir: Path) -> None:
    if not public_dir.exists():
        return
    try:
        public_dir.resolve().relative_to(pool.RUNTIME.resolve())
    except ValueError:
        return
    for child in public_dir.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def write_public_alias_dir(
    public_dir: Path,
    aliases: dict[str, str],
    payloads: dict[str, str],
) -> dict:
    clear_runtime_public_dir(public_dir)
    public_payloads = dict(payloads)
    public_payloads["urls"] = payloads["flclash"]
    public_content_types = {"urls": CONTENT_TYPES["flclash"]}
    public_aliases = {endpoint: url for endpoint, url in aliases.items() if endpoint in PUBLIC_ENDPOINTS}
    for endpoint, url in public_aliases.items():
        alias_url_path = "/" + url.split("/", 3)[3]
        atomic_write_text(public_dir / alias_url_path.lstrip("/"), public_payloads[endpoint])
    atomic_write_text(
        public_dir / "_headers",
        render_headers(public_aliases, include_direct=False, content_type_overrides=public_content_types),
    )
    atomic_write_text(public_dir / "404.html", "not found\n")
    return {
        "path": str(public_dir),
        "mode": "alias_only",
        "alias_file_count": len(public_aliases),
        "published_endpoints": sorted(public_aliases),
        "direct_debug_files_included": False,
    }


def write_outputs(rows: list[dict], selection_meta: dict, args: argparse.Namespace) -> dict:
    output_dir = args.output_dir
    urls = endpoint_urls(args.base_url)
    aliases = alias_urls(args.base_url, args)
    groups = {
        "all": row_group(rows, "all"),
        "residential": row_group(rows, "residential"),
        "static": row_group(rows, "static"),
    }
    meta = build_meta(rows, groups, selection_meta, urls, aliases, output_dir, args)
    payloads = build_payloads(rows, groups, meta, urls, aliases, args)
    payloads["_headers"] = render_headers(aliases, include_direct=True)

    for endpoint, path_name in ENDPOINT_PATHS.items():
        atomic_write_text(output_dir / path_name, payloads[endpoint])
    for endpoint, url in aliases.items():
        alias_url_path = "/" + url.split("/", 3)[3]
        atomic_write_text(output_dir / alias_url_path.lstrip("/"), payloads[endpoint])
    atomic_write_text(output_dir / "_headers", payloads["_headers"])
    atomic_write_text(output_dir / "alias-map.json", json.dumps(aliases, ensure_ascii=False, indent=2) + "\n")
    if not args.skip_public_dir:
        meta["public_dir"] = write_public_alias_dir(args.public_dir, aliases, payloads)
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description="Export fixed URL subscription endpoint payloads for IPPOXY.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--public-dir", type=Path, default=DEFAULT_PUBLIC_DIR)
    parser.add_argument("--skip-public-dir", action="store_true")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--input", type=Path, default=None)
    parser.add_argument("--baseline", type=Path, default=pool.RUNTIME / "turn_xray_pool_20260608.json")
    parser.add_argument("--verify", type=Path, default=pool.DEFAULT_VERIFY)
    parser.add_argument("--registrar-feedback", type=Path, default=pool.DEFAULT_REGISTRAR_FEEDBACK)
    parser.add_argument("--source-quality", type=Path, default=pool.DEFAULT_SOURCE_QUALITY)
    parser.add_argument("--worker-host", default=pool.DEFAULT_WORKER_HOST)
    parser.add_argument("--uuid", default=pool.DEFAULT_UUID)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--min-clean", type=int, default=int(os.environ.get("IP_PROXY_MIN_CLEAN", "12")))
    parser.add_argument(
        "--pool-mode",
        choices=sorted(pool.ALLOWED_POOL_MODES),
        default=os.environ.get("IP_PROXY_POOL_MODE", "strict"),
        help="strict exports clean TURN candidates; relaxed also admits risky non-hard-dirty TURN candidates.",
    )
    parser.add_argument(
        "--max-fallback-candidate-age-hours",
        type=float,
        default=pool.DEFAULT_MAX_FALLBACK_CANDIDATE_AGE_HOURS,
        help="maximum age for requested/fallback clean candidate files; 0 disables the age check",
    )
    parser.add_argument(
        "--allow-stale-fallback-candidates",
        action="store_true",
        default=os.environ.get("IP_PROXY_ALLOW_STALE_FALLBACK_CANDIDATES", "0").strip().lower()
        in ("1", "true", "yes", "on"),
        help="allow stale clean candidate files to be used when exporting subscription payloads",
    )
    parser.add_argument("--strict-limit", action="store_true", help="fail if fewer than --limit clean rows are selected")
    parser.add_argument("--alias-salt", default=DEFAULT_ALIAS_SALT)
    parser.add_argument("--alias-host-seed", default=DEFAULT_ALIAS_HOST_SEED)
    parser.add_argument("--no-aliases", action="store_true")
    parser.add_argument(
        "--exclude-countries",
        default=DEFAULT_EXCLUDE_COUNTRIES,
        help="comma/space separated country codes excluded from client subscriptions; default excludes CN",
    )
    parser.add_argument(
        "--max-response-ms",
        type=int,
        default=DEFAULT_MAX_RESPONSE_MS,
        help="drop nodes whose candidate-check responseTime is above this value; 0 disables",
    )
    parser.add_argument(
        "--allow-retain-bad-exits",
        action="store_true",
        default=os.environ.get("IP_PROXY_ALLOW_RETAIN_BAD_EXITS", "0").strip().lower() in ("1", "true", "yes", "on"),
    )
    args = parser.parse_args()
    if args.input is None:
        args.input = pool.default_input_for_pool_mode(args.pool_mode)

    rows, selection_meta = load_selected_rows(args)
    meta = write_outputs(rows, selection_meta, args)
    print(
        json.dumps(
            {
                "status": "ok",
                "node_count": meta["node_count"],
                "unique_exit_ips": meta["unique_exit_ips"],
                "requested_limit": meta["requested_limit"],
                "output_counts": meta["output_counts"],
                "endpoints": meta["endpoints"],
                "alias_endpoints": meta["alias_endpoints"],
                "output_dir": meta["output_dir"],
                "public_dir": meta.get("public_dir"),
                "resin_requires_local_xray": meta["resin_requires_local_xray"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
