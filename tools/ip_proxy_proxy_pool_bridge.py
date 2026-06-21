#!/usr/bin/env python3
"""Bridge jhao104/proxy_pool fetchers into IPPOXY Layer0 artifacts.

The source project stays under third_party/proxy_pool. This script imports its
own fetcher classes, runs them on demand, and normalizes yielded host:port rows
into IPPOXY's existing Layer0 candidate JSON shape.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib
import importlib.util
import inspect
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RESEARCH_DIR = IP_RUNTIME_DIR / "research"
DEFAULT_PROXY_POOL_REPO = ROOT / "third_party" / "proxy_pool"
DEFAULT_PROXY_POOL_URL = "https://github.com/jhao104/proxy_pool.git"
IP_PORT_RE = re.compile(r"(?:(http|https|socks4|socks5)://)?(?<!\d)((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)", re.I)
HTTP_SOCKS_KINDS = {"http", "https", "socks4", "socks5"}


@dataclass(frozen=True)
class FetcherSpec:
    name: str
    module: str
    cls: type
    url: str


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def ensure_proxy_pool_repo(repo: Path, *, clone_url: str, clone_if_missing: bool, update: bool) -> None:
    if not repo.exists():
        if not clone_if_missing:
            raise FileNotFoundError(f"proxy_pool repo missing: {repo}")
        repo.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", clone_url, str(repo)], check=True)
    if update:
        subprocess.run(["git", "-C", str(repo), "pull", "--ff-only"], check=True)


def _drop_proxy_pool_modules() -> None:
    prefixes = ("fetcher", "handler", "util", "setting")
    for name in list(sys.modules):
        if name in prefixes or any(name.startswith(prefix + ".") for prefix in prefixes):
            sys.modules.pop(name, None)


def _import_module_from_file(module_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot import {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_fetcher_excludes(repo: Path) -> set[str]:
    added_path = False
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))
        added_path = True
    try:
        try:
            setting = importlib.import_module("setting")
        except Exception:
            return set()
        raw = getattr(setting, "PROXY_FETCHER_EXCLUDE", []) or []
        return {str(item) for item in raw}
    finally:
        if added_path:
            try:
                sys.path.remove(str(repo))
            except ValueError:
                pass


def discover_fetchers(repo: Path, *, include_disabled: bool = False) -> tuple[list[FetcherSpec], list[dict]]:
    sources_dir = repo / "fetcher" / "sources"
    if not sources_dir.exists():
        raise FileNotFoundError(f"proxy_pool fetcher sources missing: {sources_dir}")

    _drop_proxy_pool_modules()
    sys.path.insert(0, str(repo))
    errors: list[dict] = []
    specs: list[FetcherSpec] = []
    excludes = load_fetcher_excludes(repo)
    try:
        base_module = importlib.import_module("fetcher.baseFetcher")
        base_cls = getattr(base_module, "BaseFetcher")
        for path in sorted(sources_dir.glob("*.py")):
            if path.name == "__init__.py":
                continue
            module_name = f"ippoxy_proxy_pool_{path.stem}_{abs(hash(str(path))) & 0xffffffff:x}"
            try:
                module = _import_module_from_file(path, module_name)
            except Exception as exc:
                errors.append({"module": path.name, "error": repr(exc)})
                continue
            for _name, cls in inspect.getmembers(module, inspect.isclass):
                if cls is base_cls or not issubclass(cls, base_cls):
                    continue
                fetcher_name = str(getattr(cls, "name", "") or cls.__name__)
                if not include_disabled and not bool(getattr(cls, "enabled", True)):
                    continue
                if fetcher_name in excludes or cls.__name__ in excludes:
                    continue
                specs.append(
                    FetcherSpec(
                        name=fetcher_name,
                        module=path.name,
                        cls=cls,
                        url=str(getattr(cls, "url", "") or ""),
                    )
                )
        return specs, errors
    finally:
        try:
            sys.path.remove(str(repo))
        except ValueError:
            pass


def valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def valid_port(port: str) -> bool:
    try:
        value = int(port)
    except (TypeError, ValueError):
        return False
    return 1 <= value <= 65535


def normalize_kind(value: object, default_kind: str) -> str:
    kind = str(value or "").lower()
    if kind in HTTP_SOCKS_KINDS:
        return kind
    return default_kind if default_kind in HTTP_SOCKS_KINDS else "http"


def normalize_proxy_rows(rows: list[object], *, source: str, source_url: str, run_id: str, default_kind: str) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for raw_row in rows:
        text = str(raw_row or "").strip()
        if not text:
            continue
        match = IP_PORT_RE.search(text)
        if not match:
            continue
        proto, ip, port = match.groups()
        if not valid_ip(ip) or not valid_port(port):
            continue
        kind = normalize_kind(proto, default_kind)
        raw = f"{kind}://{ip}:{int(port)}"
        if raw in seen:
            continue
        seen.add(raw)
        out.append(
            {
                "kind": kind,
                "raw": raw,
                "source": source,
                "source_id": source,
                "source_type": "proxy_pool_fetcher",
                "trace": {
                    "run_id": run_id,
                    "source_id": source,
                    "source_type": "proxy_pool_fetcher",
                    "source_format": "jhao104_proxy_pool",
                    "lane": "http_socks",
                    "url": source_url,
                },
            }
        )
    return out


def run_fetcher(spec: FetcherSpec, *, run_id: str, default_kind: str, max_per_source: int) -> tuple[list[dict], dict]:
    trace = {
        "source_id": spec.name,
        "module": spec.module,
        "url": spec.url,
        "status": "ok",
        "raw_count": 0,
    }
    try:
        fetcher = spec.cls()
        raw_rows: list[object] = []
        for item in fetcher.fetch():
            raw_rows.append(item)
            if max_per_source and len(raw_rows) >= max_per_source:
                break
        rows = normalize_proxy_rows(raw_rows, source=spec.name, source_url=spec.url, run_id=run_id, default_kind=default_kind)
        trace["raw_count"] = len(rows)
        trace["yielded_count"] = len(raw_rows)
        return rows, trace
    except Exception as exc:
        trace.update({"status": "error", "error": repr(exc)})
        return [], trace


def dedupe_rows(rows: list[dict], *, limit: int = 0) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        raw = str(row.get("raw") or "")
        if not raw or raw in seen:
            continue
        seen.add(raw)
        out.append(row)
        if limit and len(out) >= limit:
            break
    return out


def run_bridge(
    *,
    repo: Path,
    output_dir: Path,
    run_id: str,
    dry_run: bool,
    default_kind: str = "http",
    workers: int = 6,
    max_per_source: int = 500,
    limit: int = 0,
    include_sources: set[str] | None = None,
    exclude_sources: set[str] | None = None,
    include_disabled: bool = False,
) -> dict:
    specs, import_errors = discover_fetchers(repo, include_disabled=include_disabled)
    include = include_sources or set()
    exclude = exclude_sources or set()
    if include:
        specs = [spec for spec in specs if spec.name in include or spec.module in include]
    if exclude:
        specs = [spec for spec in specs if spec.name not in exclude and spec.module not in exclude]

    output_dir.mkdir(parents=True, exist_ok=True)
    worker_count = max(1, int(workers or 1))
    processed: list[tuple[int, list[dict], dict]] = []

    def process(index_spec: tuple[int, FetcherSpec]) -> tuple[int, list[dict], dict]:
        index, spec = index_spec
        rows, trace = run_fetcher(spec, run_id=run_id, default_kind=default_kind, max_per_source=max_per_source)
        return index, rows, trace

    indexed = list(enumerate(specs))
    if worker_count == 1 or len(indexed) <= 1:
        processed = [process(item) for item in indexed]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(process, item) for item in indexed]
            for future in concurrent.futures.as_completed(futures):
                processed.append(future.result())

    rows: list[dict] = []
    traces: list[dict] = []
    for _index, source_rows, trace in sorted(processed, key=lambda item: item[0]):
        rows.extend(source_rows)
        traces.append(trace)
    rows = dedupe_rows(rows, limit=limit)

    raw_path = output_dir / f"layer0_http_socks_pool_proxy_pool_{run_id}.json"
    manifest_path = output_dir / f"proxy_pool_bridge_manifest_{run_id}.json"
    manifest = {
        "schema": "ippoxy_proxy_pool_bridge.v1",
        "run_id": run_id,
        "dry_run": bool(dry_run),
        "proxy_pool_repo": str(repo),
        "raw_path": str(raw_path),
        "raw_count": len(rows),
        "fetchers_total": len(specs),
        "fetchers_ok": sum(1 for item in traces if item.get("status") == "ok"),
        "fetchers_error": sum(1 for item in traces if item.get("status") != "ok"),
        "import_errors": import_errors,
        "sources": traces,
    }
    write_json(raw_path, rows)
    write_json(manifest_path, manifest)
    if not dry_run:
        write_json(output_dir / "layer0_http_socks_pool_proxy_pool.latest.json", rows)
        write_json(output_dir / "proxy_pool_bridge_manifest.latest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run jhao104/proxy_pool fetchers and emit IPPOXY Layer0 candidates.")
    parser.add_argument("--proxy-pool-repo", type=Path, default=DEFAULT_PROXY_POOL_REPO)
    parser.add_argument("--clone-url", default=DEFAULT_PROXY_POOL_URL)
    parser.add_argument("--clone-if-missing", action="store_true")
    parser.add_argument("--update", action="store_true", help="git pull --ff-only before running fetchers")
    parser.add_argument("--output-dir", type=Path, default=RESEARCH_DIR)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--default-kind", choices=sorted(HTTP_SOCKS_KINDS), default="http")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--max-per-source", type=int, default=500)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--include-source", action="append", default=[])
    parser.add_argument("--exclude-source", action="append", default=[])
    parser.add_argument("--include-disabled", action="store_true")
    args = parser.parse_args()

    ensure_proxy_pool_repo(
        args.proxy_pool_repo,
        clone_url=args.clone_url,
        clone_if_missing=args.clone_if_missing,
        update=args.update,
    )
    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    manifest = run_bridge(
        repo=args.proxy_pool_repo,
        output_dir=args.output_dir,
        run_id=run_id,
        dry_run=args.dry_run,
        default_kind=args.default_kind,
        workers=args.workers,
        max_per_source=args.max_per_source,
        limit=args.limit,
        include_sources=set(args.include_source or []),
        exclude_sources=set(args.exclude_source or []),
        include_disabled=args.include_disabled,
    )
    print(json.dumps(manifest, ensure_ascii=False))
    return 0 if manifest.get("raw_count", 0) else 2


if __name__ == "__main__":
    raise SystemExit(main())
