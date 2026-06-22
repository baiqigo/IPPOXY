#!/usr/bin/env python3
"""Import local gfpcom/free-proxy-list source URLs into IPPOXY runtime inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urlparse


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
DEFAULT_SOURCE_DIR = ROOT / "layer0_sources/free-proxy-list/sources"
DEFAULT_SOURCE_BASE_URL = "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/sources"
DEFAULT_REGISTRY = ROOT / "tools/layer0_sources.json"
DEFAULT_OUTPUT_DIR = IP_RUNTIME_DIR / "research"
HEADERS = {
    "User-Agent": "IPPOXY-free-proxy-list-import/1.0",
    "Accept": "text/plain,*/*",
}
TEMPLATE_PLACEHOLDER_RE = re.compile(r"\{[^}]+\}")

DIRECT_SOURCE_FILES = {
    "http.txt": ("http", "ip_port"),
    "https.txt": ("https", "ip_port"),
    "socks4.txt": ("socks4", "ip_port"),
    "socks5.txt": ("socks5", "ip_port"),
}
SUBSCRIPTION_SOURCE_FILES = {
    "ss.txt",
    "ssr.txt",
    "trojan.txt",
    "vless.txt",
    "vmess.txt",
}


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def source_urls(registry_path: Path) -> set[str]:
    data = read_json(registry_path, {})
    if not isinstance(data, dict):
        return set()
    urls: set[str] = set()
    for rows in data.values():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "").strip()
            if url:
                urls.add(url)
            for extra_url in row.get("urls") or []:
                value = str(extra_url).strip()
                if value:
                    urls.add(value)
    return urls


def sha10(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:10]


def clean_name(value: str, fallback: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_").lower()
    return value[:80] or fallback


def parse_source_line(line: str) -> tuple[str, str, str]:
    value = line.strip()
    if not value or value.startswith("#"):
        return "", "", ""
    parts = [part.strip() for part in value.split(",")]
    return parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else ""


def is_fetchable_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def has_template_placeholder(url: str) -> bool:
    return bool(TEMPLATE_PLACEHOLDER_RE.search(url))


def entry_name(prefix: str, url: str) -> str:
    parsed = urlparse(url)
    tail = parsed.path.rsplit("/", 1)[-1] or parsed.netloc
    return clean_name(f"gfp_{prefix}_{tail}_{sha10(url)}", f"gfp_{prefix}_{sha10(url)}")


def fetch_source_text(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(1_000_000)
    return raw.decode("utf-8", errors="ignore")


def load_source_file(
    path: Path,
    *,
    source_base_url: str = "",
    fetch_timeout: int = 15,
    fetch_text_func=fetch_source_text,
) -> list[tuple[str, str, str]]:
    if path.exists():
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
    elif source_base_url:
        base = source_base_url.rstrip("/")
        url = f"{base}/{path.name}"
        try:
            text = fetch_text_func(url, fetch_timeout)
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeError):
            return []
    else:
        return []
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        url, transformer, parser = parse_source_line(line)
        if url and is_fetchable_url(url) and not has_template_placeholder(url):
            rows.append((url, transformer, parser))
    return rows


def build_direct_sources(
    *,
    source_dir: Path,
    skip_urls: set[str],
    include_existing: bool,
    source_base_url: str = "",
    fetch_timeout: int = 15,
    fetch_text_func=fetch_source_text,
) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for filename, (kind, parser_type) in DIRECT_SOURCE_FILES.items():
        for url, _transformer, parser_hint in load_source_file(
            source_dir / filename,
            source_base_url=source_base_url,
            fetch_timeout=fetch_timeout,
            fetch_text_func=fetch_text_func,
        ):
            if url in seen or (not include_existing and url in skip_urls):
                continue
            seen.add(url)
            source_type = f"gfp_{kind}"
            source_format = parser_type
            if parser_hint.lower() == "spaceurl":
                source_format = "regex_ip_port"
            rows.append(
                {
                    "name": entry_name(kind, url),
                    "url": url,
                    "source_type": source_type,
                    "expected_kind": kind,
                    "fetchable": True,
                    "source_format": source_format,
                    "origin": "gfpcom/free-proxy-list",
                }
            )
    return rows


def build_subscription_sources(
    *,
    source_dir: Path,
    skip_urls: set[str],
    include_existing: bool,
    source_base_url: str = "",
    fetch_timeout: int = 15,
    fetch_text_func=fetch_source_text,
) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for filename in sorted(SUBSCRIPTION_SOURCE_FILES):
        protocol = filename.rsplit(".", 1)[0]
        for url, _transformer, _parser_hint in load_source_file(
            source_dir / filename,
            source_base_url=source_base_url,
            fetch_timeout=fetch_timeout,
            fetch_text_func=fetch_text_func,
        ):
            if url in seen or (not include_existing and url in skip_urls):
                continue
            seen.add(url)
            rows.append(
                {
                    "name": entry_name(protocol, url),
                    "project": "gfpcom/free-proxy-list",
                    "url": url,
                    "protocol_hint": protocol,
                }
            )
    return rows


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import gfpcom/free-proxy-list sources into IPPOXY runtime inputs.")
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR)
    parser.add_argument(
        "--source-base-url",
        default=DEFAULT_SOURCE_BASE_URL,
        help="fallback raw URL base used when --source-dir files are missing; empty disables network fallback",
    )
    parser.add_argument("--fetch-timeout", type=int, default=15)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--include-existing", action="store_true", help="do not skip URLs already in layer0_sources.json")
    args = parser.parse_args()

    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    skip = source_urls(args.registry)
    direct_sources = build_direct_sources(
        source_dir=args.source_dir,
        skip_urls=skip,
        include_existing=args.include_existing,
        source_base_url=args.source_base_url,
        fetch_timeout=args.fetch_timeout,
    )
    subscription_sources = build_subscription_sources(
        source_dir=args.source_dir,
        skip_urls=skip,
        include_existing=args.include_existing,
        source_base_url=args.source_base_url,
        fetch_timeout=args.fetch_timeout,
    )

    direct_path = args.output_dir / f"free_proxy_list_dynamic_sources_{run_id}.json"
    subscription_path = args.output_dir / f"free_proxy_list_subscription_sources_{run_id}.json"
    direct_latest = args.output_dir / "free_proxy_list_dynamic_sources.latest.json"
    subscription_latest = args.output_dir / "free_proxy_list_subscription_sources.latest.json"
    dynamic_payload = {
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": "gfpcom/free-proxy-list",
        "sources": direct_sources,
    }
    write_json(direct_path, dynamic_payload)
    write_json(direct_latest, dynamic_payload)
    write_json(subscription_path, subscription_sources)
    write_json(subscription_latest, subscription_sources)

    print(
        json.dumps(
            {
                "run_id": run_id,
                "direct_sources": len(direct_sources),
                "subscription_sources": len(subscription_sources),
                "direct_path": str(direct_path),
                "subscription_path": str(subscription_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
