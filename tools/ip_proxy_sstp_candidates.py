#!/usr/bin/env python3
"""Build a bounded SSTP/OpenGW candidate manifest.

This tool is source intake only. It does not start SSTP, modify routes, write
runtime files, or touch Resin/Xray.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
DEFAULT_OUTPUT_DIR = IP_RUNTIME_DIR / "research"

DEFAULT_SOURCES = [
    {
        "name": "cmliussss_vpngate",
        "url": "https://sub.cmliussss.net/vpngate",
        "type": "generic",
    },
    {
        "name": "delta_vpn_gate",
        "url": "https://raw.githubusercontent.com/Delta-Kronecker/Vpn-Gate/refs/heads/main/sstp_hosts.txt",
        "type": "generic",
    },
    {
        "name": "f0rc3run_sstp",
        "url": "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/sstp-configs/sstp_with_country.txt",
        "type": "generic",
    },
    {
        "name": "vpngate_official_api",
        "url": "https://www.vpngate.net/api/iphone/",
        "type": "vpngate_official",
    },
]

SSTP_URL_RE = re.compile(r"sstp://[^\s`\"'<>|]+", re.IGNORECASE)
HOST_PORT_RE = re.compile(r"\b([A-Za-z0-9.-]+(?:\.opengw\.net)?)(?::(\d{2,5}))?\b")
OPEN_GW_HOST_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)*opengw\.net$", re.IGNORECASE)
OPEN_GW_SHORT_RE = re.compile(r"^(?:public-vpn-[A-Za-z0-9-]+|vpn[A-Za-z0-9-]+)$", re.IGNORECASE)
PORT_PRIORITY = {443: 0, 992: 1, 1310: 2, 1194: 3}


def fetch_text(url: str, timeout: int) -> str:
    if url.startswith("file://"):
        parsed = urllib.parse.urlparse(url)
        path = urllib.request.url2pathname(parsed.path)
        if len(path) >= 3 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def normalize_host(host: str) -> str:
    value = str(host or "").strip().strip(".,;)]}")
    if not value:
        return ""
    lower = value.lower()
    if OPEN_GW_HOST_RE.match(lower):
        return lower
    if OPEN_GW_SHORT_RE.match(lower):
        return f"{lower}.opengw.net"
    return ""


def safe_port(value: object, default: int = 443) -> int | None:
    try:
        port = int(value or default)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def candidate_from_parts(
    *,
    host: str,
    port: int | None,
    source: str,
    username: str = "vpn",
    password: str = "vpn",
) -> dict | None:
    normalized_host = normalize_host(host)
    normalized_port = safe_port(port, 443)
    if not normalized_host or not normalized_port:
        return None
    user = urllib.parse.quote(username or "vpn", safe="")
    passwd = urllib.parse.quote(password or "vpn", safe="")
    raw = f"sstp://{user}:{passwd}@{normalized_host}:{normalized_port}"
    return {
        "kind": "sstp",
        "raw": raw,
        "host": normalized_host,
        "port": normalized_port,
        "username": username or "vpn",
        "source": source,
        "dedup_key": f"{normalized_host}|{normalized_port}|{username or 'vpn'}|{password or 'vpn'}",
    }


def candidate_from_sstp_url(raw: str, source: str) -> dict | None:
    text = str(raw or "").strip().strip(".,;)]}")
    parsed = urllib.parse.urlparse(text)
    if parsed.scheme.lower() != "sstp" or not parsed.hostname:
        return None
    port = safe_port(parsed.port, 443)
    username = urllib.parse.unquote(parsed.username or "vpn")
    password = urllib.parse.unquote(parsed.password or "vpn")
    return candidate_from_parts(
        host=parsed.hostname,
        port=port,
        source=source,
        username=username,
        password=password,
    )


def parse_generic_text(text: str, source: str) -> list[dict]:
    candidates: list[dict] = []
    for match in SSTP_URL_RE.finditer(text):
        item = candidate_from_sstp_url(match.group(0), source)
        if item:
            candidates.append(item)

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("*"):
            continue
        for token in re.split(r"[\s|,]+", stripped):
            token = token.strip()
            if not token or token.lower().startswith("sstp://"):
                continue
            match = HOST_PORT_RE.fullmatch(token)
            if not match:
                continue
            item = candidate_from_parts(
                host=match.group(1),
                port=safe_port(match.group(2), 443),
                source=source,
            )
            if item:
                candidates.append(item)
    return candidates


def parse_vpngate_official(text: str, source: str) -> list[dict]:
    header_line = next((line for line in text.splitlines() if line.startswith("#HostName,")), "")
    if not header_line:
        return []
    header = header_line.lstrip("#").split(",")
    rows = [
        line
        for line in text.splitlines()
        if line and not line.startswith("#") and not line.startswith("*")
    ]
    candidates: list[dict] = []
    reader = csv.DictReader(io.StringIO("\n".join(rows)), fieldnames=header)
    for row in reader:
        host = row.get("HostName") or ""
        item = candidate_from_parts(host=host, port=443, source=source)
        if item:
            item["country"] = row.get("CountryShort") or row.get("CountryLong") or ""
            candidates.append(item)
    return candidates


def parse_source_text(text: str, source: str, source_type: str) -> list[dict]:
    if source_type == "vpngate_official":
        return parse_vpngate_official(text, source)
    return parse_generic_text(text, source)


def priority_key(item: dict) -> tuple:
    port = int(item.get("port") or 0)
    return (PORT_PRIORITY.get(port, 50), str(item.get("host") or ""), port, str(item.get("raw") or ""))


def dedupe_candidates(candidates: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for item in sorted(candidates, key=priority_key):
        key = str(item.get("dedup_key") or item.get("raw") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        row = dict(item)
        row.pop("dedup_key", None)
        out.append(row)
    return out


def build_manifest(
    *,
    run_id: str,
    source_specs: list[dict],
    timeout: int,
    limit: int,
) -> dict:
    all_candidates: list[dict] = []
    source_rows: list[dict] = []
    errors: list[dict] = []

    for spec in source_specs:
        name = str(spec.get("name") or "unknown")
        url = str(spec.get("url") or "")
        source_type = str(spec.get("type") or "generic")
        trace = {
            "source": name,
            "url": url,
            "type": source_type,
            "status": "ok",
            "raw_count": 0,
            "unique_count": 0,
        }
        try:
            text = fetch_text(url, timeout)
            candidates = parse_source_text(text, name, source_type)
        except Exception as exc:  # noqa: BLE001 - this is evidence capture for source intake.
            trace["status"] = "error"
            trace["error"] = repr(exc)
            candidates = []
            errors.append({"source": name, "url": url, "error": repr(exc)})
        trace["raw_count"] = len(candidates)
        trace["unique_count"] = len(dedupe_candidates(candidates))
        source_rows.append(trace)
        all_candidates.extend(candidates)

    deduped = dedupe_candidates(all_candidates)
    available_before_limit = len(deduped)
    if limit > 0:
        deduped = deduped[:limit]

    by_port = Counter(str(item.get("port") or "unknown") for item in deduped)
    return {
        "run_id": run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_count": len(source_specs),
        "sources": source_rows,
        "errors": errors,
        "available_before_limit": available_before_limit,
        "total": len(deduped),
        "by_port": dict(sorted(by_port.items())),
        "candidates": deduped,
    }


def parse_source_arg(value: str) -> dict:
    if "=" in value:
        name, url = value.split("=", 1)
        return {"name": name.strip() or "cli_source", "url": url.strip(), "type": "generic"}
    return {"name": "cli_source", "url": value.strip(), "type": "generic"}


def write_manifest(manifest: dict, output_dir: Path, *, dry_run: bool) -> None:
    if dry_run:
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = str(manifest["run_id"])
    text = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    (output_dir / f"sstp_candidates_{run_id}.json").write_text(text, encoding="utf-8")
    (output_dir / "sstp_candidates.latest.json").write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build SSTP/OpenGW candidate manifest.")
    parser.add_argument("--run-id", default=time.strftime("sstp_%Y%m%d_%H%M%S"))
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout", type=int, default=25)
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument("--dry-run", action="store_true", help="print manifest without writing artifacts")
    parser.add_argument("--no-default-sources", action="store_true")
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="extra source as name=url or url; parsed as generic SSTP/OpenGW text",
    )
    args = parser.parse_args()

    sources: list[dict] = []
    if not args.no_default_sources:
        sources.extend(DEFAULT_SOURCES)
    sources.extend(parse_source_arg(value) for value in args.source)

    manifest = build_manifest(
        run_id=args.run_id,
        source_specs=sources,
        timeout=args.timeout,
        limit=args.limit,
    )
    write_manifest(manifest, args.output_dir, dry_run=args.dry_run)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
