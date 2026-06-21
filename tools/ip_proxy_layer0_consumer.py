#!/usr/bin/env python3
"""Layer 0 consumer: fetch upstream raw files and parse into unified candidate format.

This is the bridge between external proxy-aggregation projects and our classify pipeline.
It does NOT modify upstream projects; it only curls their output files and normalizes
the format to {kind, raw, source} dicts compatible with ip_proxy_candidate_harvest.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RUNTIME_DIR = IP_RUNTIME_DIR / "research"
RESIN_DIR = IP_RUNTIME_DIR / "resin"

SHARE_URL_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hy2://", "hysteria2://")
IP_PORT_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}$")
FETCH_PROXY: str | None = os.environ.get("IP_PROXY_FETCH_PROXY") or None
DEFAULT_SOURCES_CONFIG = ROOT / "tools" / "layer0_sources.json"


def fetch_text(url: str, timeout: int = 30, max_bytes: int | None = None) -> str:
    """Fetch text content from URL, with optional proxy support."""
    if url.startswith("file://"):
        # Windows-compatible local file reading
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        # On Windows, file:///C:/... -> /C:/... -> C:/...
        if len(path) >= 3 and path[0] == '/' and path[2] == ':':
            path = path[1:]
        if max_bytes and max_bytes > 0:
            return Path(path).read_bytes()[:max_bytes].decode("utf-8", errors="ignore")
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    if FETCH_PROXY:
        return _fetch_curl(url, timeout, max_bytes=max_bytes)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if max_bytes and max_bytes > 0:
            return resp.read(max_bytes).decode("utf-8", errors="ignore")
        return resp.read().decode("utf-8", errors="ignore")


def _fetch_curl(url: str, timeout: int = 30, max_bytes: int | None = None) -> str:
    import subprocess
    cmd = ["curl", "-sS", "--max-time", str(timeout), "-x", FETCH_PROXY, url]
    if max_bytes and max_bytes > 0:
        cmd[1:1] = ["--range", f"0-{max_bytes - 1}"]
    result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
    if result.returncode != 0:
        raise OSError(f"curl failed (rc={result.returncode})")
    return result.stdout.decode("utf-8", errors="ignore")


def parse_line(line: str, *, source: str, kind: str | None = None) -> dict | None:
    """Parse a single line from an upstream raw file into {kind, raw, source}.

    Args:
        line: raw text line from upstream output
        source: source name for tracing
        kind: forced kind for ip_port sources (e.g. "http", "socks5"); None for auto-detect

    Returns:
        dict with kind/raw/source, or None if line should be skipped.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Share URL format: protocol://...
    lower = line.lower()
    for prefix in SHARE_URL_PREFIXES:
        if lower.startswith(prefix):
            detected_kind = line.split("://")[0].lower()
            # Normalize hysteria2 -> hy2
            if detected_kind == "hysteria2":
                detected_kind = "hy2"
            return {"kind": detected_kind, "raw": line, "source": source}

    # Full URL format: http://ip:port or socks5://ip:port. Prefer the line's
    # explicit protocol over the source default because dynamic sources can be
    # mixed or imperfectly classified.
    if "://" in line:
        detected_kind = line.split("://", 1)[0].lower()
        if detected_kind in {"http", "https", "socks4", "socks5"}:
            return {"kind": detected_kind, "raw": line, "source": source}
        if kind:
            return {"kind": kind, "raw": line, "source": source}

    # ip:port format
    if IP_PORT_RE.match(line) and kind:
        return {"kind": kind, "raw": f"{kind}://{line}", "source": source}

    return None


def decode_base64_content(text: str) -> str:
    """Attempt base64 decode of text content."""
    compact = "".join(text.split())
    if not compact or not re.fullmatch(r"[A-Za-z0-9+/=]+", compact[:2000]):
        return text
    try:
        padding = "=" * (-len(compact) % 4)
        return base64.b64decode(compact + padding).decode("utf-8", errors="ignore")
    except Exception:
        return text


def fetch_and_parse_source(
    source_name: str,
    url: str,
    source_type: str,
    kind: str | None = None,
    timeout: int = 30,
) -> list[dict]:
    """Fetch one upstream source and parse all lines into candidate dicts.

    Args:
        source_name: identifier for this source
        url: URL to fetch (http/https or file://)
        source_type: "ip_port", "share_url", or "base64_subscription"
        kind: forced kind for ip_port sources
        timeout: fetch timeout in seconds

    Returns:
        list of {kind, raw, source} dicts
    """
    try:
        raw_text = fetch_text(url, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError, http.client.IncompleteRead) as exc:
        print(json.dumps({"source": source_name, "url": url, "error": repr(exc)}, ensure_ascii=False))
        return []

    # For base64 subscriptions, decode first
    if source_type == "base64_subscription":
        decoded = decode_base64_content(raw_text)
        if decoded != raw_text:
            raw_text = decoded

    results = []
    for line in raw_text.splitlines():
        parsed = parse_line(line, source=source_name, kind=kind)
        if parsed is not None:
            results.append(parsed)

    return results


def load_sources_config(config_path: Path | None = None) -> dict:
    """Load source configuration from JSON file."""
    path = config_path or DEFAULT_SOURCES_CONFIG
    if not path.exists():
        return {"http_sources": [], "socks_sources": [], "subscription_sources": [], "api_sources": []}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data


def consume_all_sources(config_path: Path | None = None, timeout: int = 30) -> tuple[list[dict], list[dict]]:
    """Fetch and parse all configured sources.

    Returns:
        (http_socks_candidates, subscription_candidates)
        - http_socks_candidates: items with kind in {http, https, socks4, socks5} for cmliussss check
        - subscription_candidates: items with kind in {vless, vmess, trojan, ss, ssr, hy2} for Xray check
    """
    config = load_sources_config(config_path)
    http_socks = []
    subscriptions = []
    HTTP_KINDS = {"http", "https", "socks4", "socks5"}

    for group_key, default_kind in [("http_sources", "http"), ("socks_sources", "socks5"), ("api_sources", "http")]:
        for entry in config.get(group_key, []):
            name = entry.get("name", "unknown")
            url = entry.get("url", "")
            entry_kind = entry.get("kind", default_kind)
            source_type = entry.get("type", "ip_port")
            if not url:
                continue
            items = fetch_and_parse_source(name, url, source_type, kind=entry_kind, timeout=timeout)
            for item in items:
                if item["kind"] in HTTP_KINDS:
                    http_socks.append(item)
                else:
                    subscriptions.append(item)

    for entry in config.get("subscription_sources", []):
        name = entry.get("name", "unknown")
        url = entry.get("url", "")
        source_type = entry.get("type", "share_url")
        if not url:
            continue
        items = fetch_and_parse_source(name, url, source_type, kind=None, timeout=timeout)
        subscriptions.extend(items)

    return http_socks, subscriptions


def write_outputs(
    http_socks: list[dict],
    subscriptions: list[dict],
    run_id: str,
    output_dir: Path | None = None,
    update_latest: bool = True,
) -> dict:
    """Write parsed candidates to runtime JSON files.

    Outputs:
        - {output_dir}/layer0_http_socks_pool_{run_id}.json
        - {output_dir}/layer0_subscription_stage0_raw_{run_id}.json
        - .latest variants if update_latest=True
    """
    out_dir = output_dir or RUNTIME_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    def _write(path: Path, data: object) -> None:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    http_path = out_dir / f"layer0_http_socks_pool_{run_id}.json"
    sub_path = out_dir / f"layer0_subscription_stage0_raw_{run_id}.json"

    _write(http_path, http_socks)
    _write(sub_path, subscriptions)

    if update_latest:
        _write(out_dir / "layer0_http_socks_pool.latest.json", http_socks)
        _write(out_dir / "layer0_subscription_stage0_raw.latest.json", subscriptions)

    return {
        "run_id": run_id,
        "http_socks": len(http_socks),
        "subscriptions": len(subscriptions),
        "total": len(http_socks) + len(subscriptions),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Layer 0 consumer: fetch and parse upstream proxy sources")
    parser.add_argument("--run-id", default="", help="stable run id for timestamped outputs")
    parser.add_argument("--config", type=Path, default=None, help="path to layer0_sources.json")
    parser.add_argument("--output-dir", type=Path, default=None, help="override output directory")
    parser.add_argument("--timeout", type=int, default=30, help="fetch timeout per source")
    parser.add_argument("--no-latest", action="store_true", help="skip updating .latest files")
    args = parser.parse_args()

    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    http_socks, subscriptions = consume_all_sources(args.config, args.timeout)
    meta = write_outputs(http_socks, subscriptions, run_id, args.output_dir, not args.no_latest)
    print(json.dumps(meta, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
