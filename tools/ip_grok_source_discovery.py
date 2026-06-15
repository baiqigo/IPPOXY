#!/usr/bin/env python3
"""Use Grok search to discover explicit IPPOXY candidate sources.

This is source discovery, not internet-wide scanning. It asks Grok for public
subscription/list/repository URLs and writes the result for manual or scripted
triage before those URLs are added to the candidate harvester.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RUNTIME_DIR = IP_RUNTIME_DIR / "research"
RESEARCH_DIR = ROOT / "docs/ip-proxy/research"
DYNAMIC_SOURCES_PATH = RUNTIME_DIR / "dynamic_sources.json"

DEFAULT_BASE_URL = "https://newapi.baiqi.xyz/v1"
DEFAULT_MODEL = "grok-4.20-multi-agent-high"

FETCH_PROXY: str | None = os.environ.get("IP_PROXY_FETCH_PROXY") or None


PROMPT = """你是 IPPOXY 的公开资料检索助手。当前目标是寻找可周期性拉取的公开 URL、官方 API、GitHub raw 文件、订阅页面和工具仓库，用于维护授权环境里的网络出口候选目录。

背景：
- 运行环境是 setbox/Daytona Linux sandbox。
- Resin 负责代理池、健康检查、坏节点剔除、粘性租约、轮换。
- 现有来源包括：
  1. https://sub.cmliussss.net/vpngate
  2. https://www.vpngate.net/api/iphone/
  3. https://raw.githubusercontent.com/Delta-Kronecker/Vpn-Gate/refs/heads/main/sstp_hosts.txt
  4. 用户已有 TURN 链式候选，格式 turn://host:port 或 turn://user:pass@host:port
  5. https://check.socks5.cmliussss.net/ 用于检测候选，不是来源池。

请联网搜索新的“明确可抓取公开来源”，重点方向：
1. VPNGate/OpenGW/SSTP 的公开订阅、raw 列表、GitHub 自动采集仓库。
2. cmliussss / edgetunnel / CF-Workers-TURN / CF-Workers-CheckSocks5 生态里可能暴露 TURN/SSTP/SOCKS5 候选的页面或仓库。
3. 免费 SOCKS5/HTTP 订阅或 raw 列表，必须是明确 URL，且适合导入 Resin 前再检测分类。
4. 自动维护相关工具或仓库：能周期拉取公开列表、验证可用性、输出 SOCKS5/HTTP/VLESS/SSTP/TURN 列表。
5. 如果有“链式TURN代理”“turn://”“OpenGW SSTP”“sstp://vpn:vpn@”相关公开列表，请优先列出。

硬性要求：
- 不要建议 FOFA/Shodan/Censys 或任何全网探测；本阶段只接受公开列表、订阅、GitHub raw、官方 API、教程中明确给出的候选源。
- 每条必须给 URL。
- 每条标注：source_type（sstp_subscription / official_api / github_raw / turn_list / socks_subscription / tool_only / tutorial_only）、是否可直接抓取、预计候选量、是否可能住宅/ISP、风险。
- 标出和现有来源重复的项，不要当新来源。
- 最后给出“建议马上接入 harvester 的前 10 个公开 URL”。
- 输出 Markdown。
"""


def parse_sse_or_json(body: str) -> str:
    chunks: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            continue
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            continue
        delta = ((obj.get("choices") or [{}])[0].get("delta") or {}).get("content")
        if delta:
            chunks.append(delta)
    if chunks:
        return "".join(chunks)

    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return body
    choice = (obj.get("choices") or [{}])[0]
    return ((choice.get("message") or {}).get("content") or "").strip()


def extract_urls(markdown: str) -> list[str]:
    urls = re.findall(r"https?://[^\s)>\]\"']+", markdown)
    clean: list[str] = []
    seen: set[str] = set()
    for url in urls:
        url = url.rstrip(".,;，。；")
        if url not in seen:
            seen.add(url)
            clean.append(url)
    return clean


def call_grok(base_url: str, api_key: str, model: str, timeout: int) -> tuple[str, str]:
    """Call Grok API. Routes through FETCH_PROXY if set."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": PROMPT}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "web_search",
                    "description": "Search the web",
                    "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
                },
            }
        ],
    }
    api_url = base_url.rstrip("/") + "/chat/completions"
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if FETCH_PROXY:
        cmd = [
            "curl", "-sS", "--max-time", str(timeout),
            "-x", FETCH_PROXY,
            "-H", f"Authorization: Bearer {api_key}",
            "-H", "Content-Type: application/json",
            "-H", "Accept: application/json,text/event-stream,*/*",
            "-H", "User-Agent: Mozilla/5.0",
            "-d", "@-",
            api_url,
        ]
        result = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout + 30)
        if result.returncode != 0:
            raise OSError(f"curl grok API failed (rc={result.returncode}): {result.stderr.decode(errors='ignore').strip()}")
        body = result.stdout.decode("utf-8", errors="ignore")
    else:
        req = urllib.request.Request(
            api_url,
            data=data,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json,text/event-stream,*/*",
                "User-Agent": "Mozilla/5.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
    return body, parse_sse_or_json(body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-key", default=os.environ.get("GROK_API_KEY") or os.environ.get("BAIQI_API_KEY"))
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--fetch-proxy", default="", help="proxy for API calls; also via IP_PROXY_FETCH_PROXY env")
    args = parser.parse_args()

    if not args.api_key:
        raise SystemExit("missing --api-key or GROK_API_KEY/BAIQI_API_KEY")

    global FETCH_PROXY
    if args.fetch_proxy:
        FETCH_PROXY = args.fetch_proxy

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    RESEARCH_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")

    try:
        raw, markdown = call_grok(args.base_url, args.api_key, args.model, args.timeout)
    except urllib.error.URLError as exc:
        raise SystemExit(f"grok request failed: {exc!r}") from exc

    urls = extract_urls(markdown)
    dynamic_sources = classify_urls(urls)

    raw_path = RUNTIME_DIR / f"grok_ip_source_discovery_{stamp}.raw.txt"
    json_path = RUNTIME_DIR / f"grok_ip_source_discovery_{stamp}.json"
    md_path = RESEARCH_DIR / f"grok_ip_source_discovery_{time.strftime('%Y%m%d')}.md"
    raw_path.write_text(raw, encoding="utf-8")
    json_path.write_text(
        json.dumps({"model": args.model, "urls": urls, "dynamic_sources": dynamic_sources, "markdown": markdown}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    DYNAMIC_SOURCES_PATH.write_text(
        json.dumps({"updated": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": args.model, "sources": dynamic_sources}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path.write_text(
        f"# Grok IP Source Discovery {time.strftime('%Y-%m-%d')}\n\n"
        f"- Model: `{args.model}`\n"
        f"- Raw: `{raw_path.name}`\n"
        f"- Parsed JSON: `{json_path.name}`\n"
        f"- Dynamic sources: `{DYNAMIC_SOURCES_PATH.name}` ({len(dynamic_sources)} entries)\n"
        f"- Extracted URLs: {len(urls)}\n\n"
        "## Result\n\n"
        + markdown.strip()
        + "\n\n## Extracted URLs\n\n"
        + "\n".join(f"- {url}" for url in urls)
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"urls": len(urls), "dynamic_sources": len(dynamic_sources), "markdown": str(md_path), "json": str(json_path), "dynamic_json": str(DYNAMIC_SOURCES_PATH)}, ensure_ascii=False))
    return 0


_STATIC_SOURCE_URLS: set[str] = {
    "https://sub.cmliussss.net/vpngate",
    "https://www.vpngate.net/api/iphone/",
    "https://raw.githubusercontent.com/Delta-Kronecker/Vpn-Gate/refs/heads/main/sstp_hosts.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/sstp-configs/sstp_with_country.txt",
    "https://raw.githubusercontent.com/ToiCF/CF-Workers-TURN/main/turn_results.txt",
    "https://raw.githubusercontent.com/cmliu/Socks2Vlesssub/main/socks5api.txt",
    "https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/socks5Data",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=socks5&format=txt&timeout=10000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
}


def classify_urls(urls: list[str]) -> list[dict]:
    """Classify discovered URLs by source_type heuristics."""
    sources: list[dict] = []
    for url in urls:
        if url in _STATIC_SOURCE_URLS:
            continue
        url_lower = url.lower()
        if "vpngate" in url_lower or "opengw" in url_lower or "sstp" in url_lower:
            source_type = "sstp_subscription"
        elif "turn" in url_lower and "cf-workers" in url_lower:
            source_type = "turn_list"
        elif "socks5" in url_lower or "socks" in url_lower or "proxy-list" in url_lower or "proxyscrape" in url_lower or "proxifly" in url_lower:
            source_type = "socks_subscription"
        elif "raw.githubusercontent.com" in url_lower:
            source_type = "github_raw"
        elif "api." in url_lower and ("vpngate" in url_lower or "proxy" in url_lower):
            source_type = "official_api"
        elif "github.com" in url_lower and "raw" not in url_lower:
            source_type = "github_repo"
        else:
            source_type = "other"
        if source_type in ("sstp_subscription", "official_api"):
            expected_kind = "sstp"
        elif source_type == "turn_list":
            expected_kind = "turn"
        elif source_type == "socks_subscription":
            expected_kind = "socks5"
        elif source_type == "github_raw":
            if any(kw in url_lower for kw in ("v2ray", "vless", "vmess", "clash", "trojan", "sub", "free")):
                expected_kind = "subscription"
            else:
                expected_kind = "unknown"
        else:
            expected_kind = "unknown"
        sources.append({
            "url": url,
            "source_type": source_type,
            "expected_kind": expected_kind,
            "fetchable": source_type in ("sstp_subscription", "official_api", "github_raw", "socks_subscription", "turn_list"),
        })
    return sources


if __name__ == "__main__":
    raise SystemExit(main())
