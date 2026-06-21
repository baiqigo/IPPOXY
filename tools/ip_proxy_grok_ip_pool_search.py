#!/usr/bin/env python3
"""Run Grok search as IPPOXY Layer0 source discovery.

This wraps the workspace grok_crawl_research search helper instead of copying
it. Unlike the ai-reg batch-search workflow, IP source discovery dedupes by full
URL because many useful sources live under the same root domain.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Callable

from ip_grok_source_discovery import classify_urls


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = ROOT.parent
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RESEARCH_DIR = IP_RUNTIME_DIR / "research"
DEFAULT_QUERY_FILE = ROOT / "tools" / "ip_proxy_grok_ip_pool_queries.txt"
DEFAULT_GROK_CRAWL_SCRIPT = WORKSPACE_ROOT / "tools" / "grok_crawl_research.py"
DEFAULT_BASE_URL = os.environ.get("GROK_BASE_URL", "https://newapi.baiqi.xyz/v1")
DEFAULT_MODEL_SEQUENCE = ["grok-4.20-fast", "grok-4.20-multi-agent-low", "grok-4.20-multi-agent-medium"]
SearchFunc = Callable[[str, str, int], list[str]]


def normalize_api_key(api_key: str) -> str:
    value = str(api_key or "").strip()
    if re.match(r"^[A-Za-z]{2}sk-", value):
        return value[2:]
    return value


def read_queries(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    queries: list[str] = []
    seen: set[str] = set()
    for line in lines:
        query = line.strip()
        if not query or query.startswith("#") or query in seen:
            continue
        seen.add(query)
        queries.append(query)
    return queries


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_grok_crawl_module(script_path: Path):
    if not script_path.exists():
        raise FileNotFoundError(f"grok_crawl_research.py not found: {script_path}")
    sys.path.insert(0, str(script_path.parent))
    try:
        spec = importlib.util.spec_from_file_location("ippoxy_grok_crawl_research", script_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot import {script_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules["ippoxy_grok_crawl_research"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        try:
            sys.path.remove(str(script_path.parent))
        except ValueError:
            pass


def make_grok_search_func(*, script_path: Path, base_url: str, api_key: str, max_urls: int, timeout: int) -> SearchFunc:
    module = load_grok_crawl_module(script_path)

    def search(query: str, model: str, query_timeout: int) -> list[str]:
        namespace = argparse.Namespace(
            query=query,
            profile="",
            profile_file="",
            exclude_domain=[],
            search_model=model,
            base_url=base_url,
            api_key=api_key,
            timeout=query_timeout or timeout,
            max_urls=max_urls,
            raw_file="",
            allow_private_urls=False,
        )
        _raw, urls = module.search_with_grok(namespace)
        return [str(url) for url in urls if str(url).strip()]

    return search


def run_search(
    *,
    queries: list[str],
    model_sequence: list[str],
    search_func: SearchFunc,
    timeout: int,
    target_urls: int,
    concurrency: int = 1,
) -> dict:
    def run_one(index_query: tuple[int, str]) -> dict:
        index, query = index_query
        status = "empty"
        error = ""
        model_used = ""
        raw_urls: list[str] = []
        attempts: list[dict] = []
        for model in model_sequence:
            model_used = model
            try:
                raw_urls = search_func(query, model, timeout)
            except (Exception, SystemExit) as exc:
                status = "error"
                error = repr(exc)
                attempts.append({"model": model, "status": "error", "raw_urls": 0, "error": error})
                continue
            if raw_urls:
                status = "ok"
                attempts.append({"model": model, "status": "ok", "raw_urls": len(raw_urls), "error": ""})
                break
            attempts.append({"model": model, "status": "empty", "raw_urls": 0, "error": ""})
        return {
            "run": index,
            "query": query,
            "model": model_used,
            "status": status,
            "raw_urls": len(raw_urls),
            "error": error,
            "attempts": attempts,
            "_urls": raw_urls,
        }

    query_items = [(index, query) for index, query in enumerate(queries, 1)]
    workers = max(1, int(concurrency or 1))
    if workers == 1 or len(query_items) <= 1:
        run_results = {index: run_one((index, query)) for index, query in query_items}
    else:
        run_results: dict[int, dict] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(run_one, item): item[0] for item in query_items}
            for future in concurrent.futures.as_completed(futures):
                run_results[futures[future]] = future.result()

    selected: list[dict] = []
    seen_urls: set[str] = set()
    runs: list[dict] = []
    for index, query in query_items:
        result = run_results[index]
        raw_urls = [str(url) for url in result.pop("_urls", [])]
        before = len(selected)
        for url in raw_urls:
            url = url.strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            selected.append({"url": url, "query_index": index, "query": query, "model": result.get("model", "")})
            if target_urls and len(selected) >= target_urls:
                break
        result["added"] = len(selected) - before
        runs.append(result)
        if target_urls and len(selected) >= target_urls:
            break
    urls = [item["url"] for item in selected]
    dynamic_sources = classify_urls(urls)
    return {
        "schema": "ippoxy_grok_ip_pool_search.v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "dedupe": "full_url",
        "target_urls": target_urls,
        "concurrency": workers,
        "url_count": len(selected),
        "urls": selected,
        "dynamic_sources": dynamic_sources,
        "runs": runs,
    }


def write_outputs(*, result: dict, output_dir: Path, run_id: str, dry_run: bool, dynamic_sources_path: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / f"grok_ip_pool_search_{run_id}.json"
    dynamic_payload = {
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": "ip_proxy_grok_ip_pool_search",
        "sources": result.get("dynamic_sources", []),
    }
    write_json(result_path, result)
    if not dry_run:
        write_json(dynamic_sources_path, dynamic_payload)
        write_json(output_dir / "grok_ip_pool_search.latest.json", result)
    return {
        "result_path": str(result_path),
        "dynamic_sources_path": str(dynamic_sources_path) if not dry_run else "",
        "url_count": result.get("url_count", 0),
        "dynamic_sources": len(result.get("dynamic_sources", [])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Use Grok search to refresh IPPOXY dynamic Layer0 source URLs.")
    parser.add_argument("--query-file", type=Path, default=DEFAULT_QUERY_FILE)
    parser.add_argument("--grok-crawl-script", type=Path, default=DEFAULT_GROK_CRAWL_SCRIPT)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--api-key", default=os.environ.get("GROK_API_KEY") or os.environ.get("BAIQI_API_KEY") or "")
    parser.add_argument("--model", action="append", default=[], help="model fallback order; can repeat")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-urls", type=int, default=40)
    parser.add_argument("--target-urls", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--output-dir", type=Path, default=RESEARCH_DIR)
    parser.add_argument("--dynamic-sources-path", type=Path, default=RESEARCH_DIR / "dynamic_sources.json")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("missing --api-key or GROK_API_KEY/BAIQI_API_KEY")
    queries = read_queries(args.query_file)
    if not queries:
        raise SystemExit(f"no queries in {args.query_file}")
    models = args.model or DEFAULT_MODEL_SEQUENCE
    search_func = make_grok_search_func(
        script_path=args.grok_crawl_script,
        base_url=args.base_url,
        api_key=normalize_api_key(args.api_key),
        max_urls=args.max_urls,
        timeout=args.timeout,
    )
    result = run_search(
        queries=queries,
        model_sequence=models,
        search_func=search_func,
        timeout=args.timeout,
        target_urls=args.target_urls,
        concurrency=args.concurrency,
    )
    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    summary = write_outputs(
        result=result,
        output_dir=args.output_dir,
        run_id=run_id,
        dry_run=args.dry_run,
        dynamic_sources_path=args.dynamic_sources_path,
    )
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if summary["url_count"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
