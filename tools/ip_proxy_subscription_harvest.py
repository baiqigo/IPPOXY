#!/usr/bin/env python3
"""Harvest Stage 0 public subscription nodes for IPPOXY.

This is a source-ingestion layer only. It fetches explicit public
subscription outputs from known aggregator projects, parses common share URLs
and Clash YAML nodes, deduplicates them, and writes Stage 0 artifacts. It does
not check node health, overwrite existing candidate pool files, or apply the
runtime.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RUNTIME_DIR = IP_RUNTIME_DIR / "research"
DEFAULT_LIMIT = int(os.environ.get("IP_PROXY_STAGE0_SUBSCRIPTION_LIMIT", "500"))
DEFAULT_MAX_BYTES = int(os.environ.get("IP_PROXY_STAGE0_SOURCE_MAX_BYTES", str(4 * 1024 * 1024)))

SUPPORTED_PROTOCOLS = {"ss", "ssr", "vmess", "vless", "trojan", "hysteria2", "hy2"}
PROTO_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])((?:ssr|ss|vmess|vless|trojan|hysteria2|hy2)://[^\s`\"'<>|]+)"
)

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/plain,application/yaml,application/json,*/*",
}

DEFAULT_SOURCES = [
    {
        "name": "v2go_all",
        "project": "Danialsamadi/v2go",
        "url": "https://raw.githubusercontent.com/Danialsamadi/v2go/main/AllConfigsSub.txt",
    },
    {
        "name": "barryfar_all",
        "project": "barry-far/V2ray-Config",
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    },
    {
        "name": "barryfar_all_base64",
        "project": "barry-far/V2ray-Config",
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_base64_Sub.txt",
    },
    {
        "name": "v2rayaggregator_sub_merge",
        "project": "mahdibland/V2RayAggregator",
        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    },
    {
        "name": "v2rayaggregator_sub_merge_base64",
        "project": "mahdibland/V2RayAggregator",
        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    },
    {
        "name": "nomorewalls_list",
        "project": "peasoft/NoMoreWalls",
        "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    },
    {
        "name": "nomorewalls_clash",
        "project": "peasoft/NoMoreWalls",
        "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
    },
    {
        "name": "ermaozi_v2ray",
        "project": "ermaozi01/free_clash_vpn",
        "url": "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/v2ray.txt",
    },
    {
        "name": "ermaozi_clash",
        "project": "ermaozi01/free_clash_vpn",
        "url": "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/clash.yml",
    },
    {
        "name": "airport_free_v2ray",
        "project": "xiaoji235/airport-free",
        "url": "https://raw.githubusercontent.com/xiaoji235/airport-free/main/v2ray.txt",
    },
]


def sha12(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json_or_text_sources(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8-sig", errors="ignore")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        data = data.get("sources") or data.get("items") or data.get("urls") or []
    if isinstance(data, list):
        out = []
        for index, item in enumerate(data, start=1):
            if isinstance(item, str):
                out.append({"name": f"source_file_{index}", "url": item.strip()})
            elif isinstance(item, dict) and item.get("url"):
                out.append(
                    {
                        "name": str(item.get("name") or f"source_file_{index}"),
                        "project": str(item.get("project") or ""),
                        "url": str(item.get("url")),
                    }
                )
        return [item for item in out if item.get("url")]

    out = []
    for index, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if "=" in value and not value.startswith("http"):
            name, url = value.split("=", 1)
            out.append({"name": name.strip(), "url": url.strip()})
        else:
            out.append({"name": f"source_file_{index}", "url": value})
    return [item for item in out if item.get("url")]


def cli_source(value: str, index: int) -> dict:
    if "=" in value and not value.startswith("http"):
        name, url = value.split("=", 1)
        return {"name": name.strip(), "url": url.strip()}
    return {"name": f"cli_source_{index}", "url": value.strip()}


def fetch_text(url: str, *, timeout: int, max_bytes: int) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", errors="ignore")


def b64_decode_text(value: str) -> str | None:
    compact = "".join(value.split())
    if len(compact) < 16:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/_=-]+", compact):
        return None
    padding = "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder((compact + padding).encode("ascii"))
        except Exception:
            continue
        text = raw.decode("utf-8", errors="ignore")
        stripped = text.lstrip()
        if "://" in text or "\n" in text or stripped.startswith(("{", "[")):
            return text
    return None


def subscription_blobs(text: str) -> list[tuple[str, str]]:
    blobs: list[tuple[str, str]] = [("plain", text)]
    seen = {text}
    queue = [("base64", text)]
    for line_index, line in enumerate(text.splitlines(), start=1):
        decoded = b64_decode_text(line.strip())
        if decoded and decoded not in seen:
            seen.add(decoded)
            blobs.append((f"line{line_index}:base64", decoded))
            if len(blobs) < 8:
                queue.append((f"line{line_index}:base64", decoded))
    while queue:
        label, current = queue.pop(0)
        decoded = b64_decode_text(current)
        if not decoded or decoded in seen:
            continue
        seen.add(decoded)
        blobs.append((label, decoded))
        if len(blobs) < 4:
            queue.append((label + ":base64", decoded))
    return blobs


def strip_url_tail(raw: str) -> str:
    return raw.rstrip(".,;)]}\r\n")


def extract_share_urls(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in PROTO_RE.finditer(text):
        raw = strip_url_tail(match.group(1))
        if raw and raw not in seen:
            seen.add(raw)
            out.append(raw)
    return out


def normalize_protocol(value: str) -> str:
    proto = value.lower().strip()
    return "hysteria2" if proto == "hy2" else proto


def parse_port(value: object) -> int | None:
    try:
        port = int(str(value).strip().strip('"\''))
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def b64_decode_json(value: str) -> dict | None:
    decoded = b64_decode_text(value)
    if not decoded:
        return None
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def decoded_ss_payload(raw: str) -> str:
    payload = raw.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0]
    if "@" in payload:
        return urllib.parse.unquote(payload)
    decoded = b64_decode_text(payload)
    return decoded or urllib.parse.unquote(payload)


def parse_ss(raw: str) -> tuple[str, int | None, str]:
    payload = decoded_ss_payload(raw)
    if "@" not in payload:
        return "", None, ""
    credential, hostport = payload.rsplit("@", 1)
    host = hostport.rsplit(":", 1)[0].strip("[]")
    port = parse_port(hostport.rsplit(":", 1)[1] if ":" in hostport else "")
    return host, port, credential


def parse_ssr(raw: str) -> tuple[str, int | None, str]:
    payload = raw.split("://", 1)[1].split("#", 1)[0]
    decoded = b64_decode_text(payload) or urllib.parse.unquote(payload)
    parts = decoded.split("/?", 1)[0].split(":")
    if len(parts) < 6:
        return "", None, ""
    host = parts[0].strip("[]")
    port = parse_port(parts[1])
    credential = parts[5]
    return host, port, credential


def parse_standard_url(raw: str) -> tuple[str, int | None, str]:
    parsed = urllib.parse.urlsplit(raw)
    host = parsed.hostname or ""
    port = parsed.port
    credential = urllib.parse.unquote(parsed.username or "")
    if parsed.password:
        credential += ":" + urllib.parse.unquote(parsed.password)
    return host, port, credential


def parse_vmess(raw: str) -> tuple[str, int | None, str]:
    payload = raw.split("://", 1)[1].split("#", 1)[0]
    data = b64_decode_json(payload)
    if not data:
        return "", None, ""
    host = str(data.get("add") or data.get("server") or "").strip()
    port = parse_port(data.get("port"))
    credential = str(data.get("id") or data.get("uuid") or "")
    return host, port, credential


def candidate_from_share_url(raw: str, source: dict, blob_format: str) -> dict | None:
    protocol = normalize_protocol(raw.split("://", 1)[0])
    if protocol not in {normalize_protocol(p) for p in SUPPORTED_PROTOCOLS}:
        return None
    try:
        if protocol == "vmess":
            host, port, credential = parse_vmess(raw)
        elif protocol == "ss":
            host, port, credential = parse_ss(raw)
        elif protocol == "ssr":
            host, port, credential = parse_ssr(raw)
        else:
            host, port, credential = parse_standard_url(raw)
    except (ValueError, TypeError):
        return None
    if not host or not port:
        return None
    credential_hash = sha12(credential) if credential else ""
    dedup_key = f"{protocol}|{host.lower()}|{port}|{credential_hash}"
    return {
        "kind": protocol,
        "protocol": protocol,
        "raw": raw,
        "host": host,
        "port": port,
        "credential_sha256_12": credential_hash,
        "source": source["name"],
        "source_project": source.get("project") or "",
        "source_url": source["url"],
        "format": "share_url" if blob_format == "plain" else f"share_url:{blob_format}",
        "dedup_key": dedup_key,
    }


def clean_scalar(value: str) -> str:
    value = value.strip().strip(",")
    if not value:
        return ""
    if value[0:1] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    if " #" in value:
        value = value.split(" #", 1)[0].strip()
    return value


def split_inline_items(body: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    quote = ""
    escape = False
    for char in body:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            current.append(char)
            escape = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char == ",":
            out.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        out.append("".join(current).strip())
    return out


def parse_inline_mapping(text: str) -> dict:
    body = text.strip()
    if body.startswith("{") and body.endswith("}"):
        body = body[1:-1]
    result: dict[str, str] = {}
    for item in split_inline_items(body):
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        result[clean_scalar(key)] = clean_scalar(value)
    return result


def parse_key_value_line(text: str) -> tuple[str, str] | None:
    if ":" not in text:
        return None
    key, value = text.split(":", 1)
    key = clean_scalar(key)
    if not key:
        return None
    return key, clean_scalar(value)


def parse_clash_yaml_nodes(text: str) -> list[dict]:
    nodes: list[dict] = []
    in_proxies = False
    current: dict[str, str] | None = None

    def flush() -> None:
        nonlocal current
        if current:
            nodes.append(current)
        current = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not in_proxies:
            if stripped == "proxies:":
                in_proxies = True
            continue
        if not line.startswith((" ", "-")) and stripped.endswith(":") and stripped != "proxies:":
            flush()
            break
        if stripped.startswith("- "):
            flush()
            rest = stripped[2:].strip()
            if rest.startswith("{"):
                current = parse_inline_mapping(rest)
            else:
                current = {}
                pair = parse_key_value_line(rest)
                if pair:
                    current[pair[0]] = pair[1]
            continue
        if current is not None:
            pair = parse_key_value_line(stripped)
            if pair:
                current[pair[0]] = pair[1]
    flush()
    return nodes


def candidate_from_clash_node(node: dict, source: dict) -> dict | None:
    protocol = normalize_protocol(str(node.get("type") or node.get("protocol") or ""))
    if protocol not in {normalize_protocol(p) for p in SUPPORTED_PROTOCOLS}:
        return None
    host = str(node.get("server") or node.get("host") or "").strip()
    port = parse_port(node.get("port"))
    if not host or not port:
        return None
    credential = str(
        node.get("uuid")
        or node.get("id")
        or node.get("password")
        or node.get("passwd")
        or node.get("username")
        or ""
    )
    credential_hash = sha12(credential) if credential else ""
    raw = json.dumps(node, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "kind": protocol,
        "protocol": protocol,
        "raw": raw,
        "host": host,
        "port": port,
        "credential_sha256_12": credential_hash,
        "source": source["name"],
        "source_project": source.get("project") or "",
        "source_url": source["url"],
        "format": "clash_yaml",
        "dedup_key": f"{protocol}|{host.lower()}|{port}|{credential_hash}",
    }


def parse_subscription_text(text: str, source: dict) -> tuple[list[dict], dict]:
    candidates: list[dict] = []
    blob_stats = []
    for blob_format, blob in subscription_blobs(text):
        share_urls = extract_share_urls(blob)
        added = 0
        for raw in share_urls:
            item = candidate_from_share_url(raw, source, blob_format)
            if item:
                candidates.append(item)
                added += 1
        clash_nodes = parse_clash_yaml_nodes(blob)
        clash_added = 0
        for node in clash_nodes:
            item = candidate_from_clash_node(node, source)
            if item:
                candidates.append(item)
                clash_added += 1
        blob_stats.append(
            {
                "format": blob_format,
                "share_urls": len(share_urls),
                "share_candidates": added,
                "clash_nodes": len(clash_nodes),
                "clash_candidates": clash_added,
            }
        )
    return candidates, {"blobs": blob_stats}


def dedupe_candidates(candidates: Iterable[dict]) -> tuple[list[dict], dict]:
    out: list[dict] = []
    seen: set[str] = set()
    duplicate_count = 0
    for item in candidates:
        key = str(item.get("dedup_key") or sha12(str(item.get("raw") or "")))
        if key in seen:
            duplicate_count += 1
            continue
        seen.add(key)
        out.append(item)
    return out, {"duplicates": duplicate_count, "unique": len(out)}


def select_stage0_candidates(candidates: list[dict], limit: int) -> list[dict]:
    if limit <= 0 or len(candidates) <= limit:
        return candidates
    buckets: dict[str, list[dict]] = {}
    for item in candidates:
        buckets.setdefault(str(item.get("source") or "unknown"), []).append(item)
    source_names = sorted(buckets)
    cursors = {name: 0 for name in source_names}
    selected: list[dict] = []
    while len(selected) < limit:
        progressed = False
        for source_name in source_names:
            cursor = cursors[source_name]
            bucket = buckets[source_name]
            if cursor >= len(bucket):
                continue
            selected.append(bucket[cursor])
            cursors[source_name] = cursor + 1
            progressed = True
            if len(selected) >= limit:
                break
        if not progressed:
            break
    return selected


def count_by(items: list[dict], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(item.get(field) or "unknown") for item in items).items()))


def load_sources(args: argparse.Namespace) -> list[dict]:
    sources: list[dict] = []
    if not args.no_default_sources:
        sources.extend(DEFAULT_SOURCES)
    for path in args.source_file or []:
        sources.extend(read_json_or_text_sources(path))
    for index, value in enumerate(args.source_url or [], start=1):
        sources.append(cli_source(value, index))

    out: list[dict] = []
    seen_urls: set[str] = set()
    for index, source in enumerate(sources, start=1):
        url = str(source.get("url") or "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        out.append(
            {
                "name": str(source.get("name") or f"source_{index}"),
                "project": str(source.get("project") or ""),
                "url": url,
            }
        )
    return out


def run_harvest(args: argparse.Namespace) -> tuple[list[dict], dict]:
    sources = load_sources(args)
    all_candidates: list[dict] = []

    def process_source(source: dict) -> tuple[list[dict], dict]:
        started = time.time()
        try:
            text = fetch_text(source["url"], timeout=args.timeout, max_bytes=args.max_bytes)
            candidates, parse_meta = parse_subscription_text(text, source)
            return candidates, (
                {
                    "name": source["name"],
                    "project": source.get("project") or "",
                    "url": source["url"],
                    "ok": True,
                    "bytes": len(text.encode("utf-8", errors="ignore")),
                    "candidates": len(candidates),
                    "elapsed_ms": round((time.time() - started) * 1000),
                    "parse": parse_meta,
                }
            )
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeError) as exc:
            return [], (
                {
                    "name": source["name"],
                    "project": source.get("project") or "",
                    "url": source["url"],
                    "ok": False,
                    "error": repr(exc),
                    "elapsed_ms": round((time.time() - started) * 1000),
                }
            )

    workers = max(1, int(getattr(args, "workers", 1) or 1))
    if workers == 1 or len(sources) <= 1:
        processed = [process_source(source) for source in sources]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            processed = list(executor.map(process_source, sources))

    source_reports: list[dict] = []
    for candidates, source_report in processed:
        all_candidates.extend(candidates)
        source_reports.append(source_report)
    unique, dedupe = dedupe_candidates(all_candidates)
    selected = select_stage0_candidates(unique, max(0, args.limit))
    summary = {
        "run_id": args.run_id,
        "source_count": len(sources),
        "sources_ok": sum(1 for item in source_reports if item.get("ok")),
        "sources_failed": sum(1 for item in source_reports if not item.get("ok")),
        "raw_candidates": len(all_candidates),
        "unique_candidates": len(unique),
        "selected": len(selected),
        "limit": args.limit,
        "dedupe": dedupe,
        "by_protocol": count_by(selected, "protocol"),
        "by_source": count_by(selected, "source"),
        "by_format": count_by(selected, "format"),
        "source_reports": source_reports,
        "runtime_effect": "none",
    }
    return selected, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Harvest Stage 0 public subscription candidates.")
    parser.add_argument("--run-id", default=time.strftime("%Y%m%d_%H%M%S"))
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--output-dir", type=Path, default=RUNTIME_DIR)
    parser.add_argument("--source-file", type=Path, action="append", default=[])
    parser.add_argument("--source-url", action="append", default=[], help="URL or name=URL; may be repeated.")
    parser.add_argument("--no-default-sources", action="store_true")
    parser.add_argument(
        "--no-latest",
        action="store_true",
        help="write run-specific artifacts only; do not update subscription_stage0_* latest files",
    )
    args = parser.parse_args()

    candidates, summary = run_harvest(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = args.output_dir / f"subscription_stage0_raw_{args.run_id}.json"
    summary_path = args.output_dir / f"subscription_stage0_summary_{args.run_id}.json"
    write_json(raw_path, candidates)
    write_json(summary_path, summary)
    if not args.no_latest:
        write_json(args.output_dir / "subscription_stage0_raw.latest.json", candidates)
        write_json(args.output_dir / "subscription_stage0_summary.latest.json", summary)
    print(
        json.dumps(
            {
                "run_id": args.run_id,
                "sources_ok": summary["sources_ok"],
                "sources_failed": summary["sources_failed"],
                "raw_candidates": summary["raw_candidates"],
                "unique_candidates": summary["unique_candidates"],
                "selected": summary["selected"],
                "by_protocol": summary["by_protocol"],
                "runtime_effect": "none",
                "raw_path": str(raw_path),
                "summary_path": str(summary_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
