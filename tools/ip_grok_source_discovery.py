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
  - https://sub.cmliussss.net/vpngate
  - https://www.vpngate.net/api/iphone/
  - https://raw.githubusercontent.com/Delta-Kronecker/Vpn-Gate/refs/heads/main/sstp_hosts.txt
  - TURN 链式候选，格式 turn://host:port 或 turn://user:pass@host:port
  - https://raw.githubusercontent.com/ToiCF/CF-Workers-TURN/main/turn_results.txt
  - https://raw.githubusercontent.com/cmliu/Socks2Vlesssub/main/socks5api.txt
  - https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt
  - https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=socks5&format=txt
  - https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt
  - https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt
  - https://check.socks5.cmliussss.net/ 检测用，不是来源池

请联网搜索新的"明确可抓取公开来源"，重点方向：
- VPNGate/OpenGW/SSTP 的公开订阅、raw 列表、GitHub 自动采集仓库
- cmliussss / edgetunnel / CF-Workers-TURN 生态里暴露 TURN/SSTP/SOCKS5 候选的页面或仓库
- 免费 SOCKS5/HTTP 订阅或 raw 列表（明确 URL，适合自动拉取）
- V2Ray/VMess/VLESS/Trojan/Clash 订阅聚合站（如 v2rayfree, freefq, airport-free 等 GitHub raw 文件）
- 非GitHub来源：Pastebin、rentry.co、justpaste.it、Telegraph、Telegram频道镜像、博客文章中明确给出的订阅URL
- 自动维护相关工具或仓库：能周期拉取公开列表、验证可用性、输出候选列表
- "链式TURN代理""turn://""OpenGW SSTP""sstp://vpn:vpn@"相关公开列表优先

硬性要求：
- 不要建议 FOFA/Shodan/Censys 或任何全网探测；本阶段只接受公开列表、订阅、GitHub raw、官方 API、教程中明确给出的候选源。
- 每条必须给 URL。
- 每条标注：source_type、是否可直接抓取、预计候选量、是否可能住宅/ISP、风险。
- 标出和现有来源重复的项，不要当新来源。
- 最后给出"建议马上接入 harvester 的前 10 个公开 URL"。
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
        # Strip Grok markdown artifacts: trailing **, *, quotes
        url = url.rstrip("*\"'")
        url = re.sub(r'\*+$', '', url)
        if url not in seen:
            seen.add(url)
            clean.append(url)
    return clean


def call_grok(base_url: str, api_key: str, model: str, timeout: int) -> tuple[str, str]:
    """Call Grok API. Routes through FETCH_PROXY if set."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": PROMPT}],
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


# Common raw file paths to try when expanding a github_repo URL into fetchable raw URLs
_GITHUB_REPO_EXPANSION_PATHS = [
    "sub.txt",
    "v2ray.txt",
    "clash.yaml",
    "proxy-list.txt",
    "socks5.txt",
    "socks5Data",
    "turn_results.txt",
    "sstp_hosts.txt",
    "result.txt",
]

_GITHUB_REPO_EXPANSION_BRANCHES = ["main"]


def _expand_github_repo(url: str) -> list[dict]:
    """Expand a github_repo URL into candidate raw.githubusercontent.com URLs."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/?$", url.rstrip("/"))
    if not m:
        return []
    owner, repo = m.group(1), m.group(2)
    sources: list[dict] = []
    seen_urls: set[str] = set()
    for branch in _GITHUB_REPO_EXPANSION_BRANCHES:
        for path in _GITHUB_REPO_EXPANSION_PATHS:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/refs/heads/{branch}/{path}"
            if raw_url not in seen_urls:
                seen_urls.add(raw_url)
                # Determine expected_kind based on path keywords
                path_lower = path.lower()
                if "sstp" in path_lower:
                    expected_kind = "sstp"
                    source_type = "github_raw"
                elif "turn" in path_lower:
                    expected_kind = "turn"
                    source_type = "github_raw"
                elif "socks5" in path_lower or "socks" in path_lower or "proxy-list" in path_lower:
                    expected_kind = "socks5"
                    source_type = "github_raw"
                elif any(kw in path_lower for kw in ("v2ray", "vless", "vmess", "clash", "sub", "trojan")):
                    expected_kind = "subscription"
                    source_type = "github_raw"
                else:
                    expected_kind = "unknown"
                    source_type = "github_raw"
                sources.append({
                    "url": raw_url,
                    "source_type": source_type,
                    "expected_kind": expected_kind,
                    "fetchable": True,
                    "expanded_from": url,
                })
    return sources


def classify_urls(urls: list[str]) -> list[dict]:
    """Classify discovered URLs by source_type heuristics.

    Improvements over original:
    - Strips Grok markdown artifacts (**, quotes) from URLs
    - Expands github_repo URLs into candidate raw.githubusercontent.com URLs
    - Marks gist raw URLs as fetchable
    - Classifies raw.cmliussss.com as fetchable
    - Adds subscription as a fetchable source_type
    """
    sources: list[dict] = []
    seen_urls: set[str] = set()
    for url in urls:
        # Clean markdown artifacts
        url = url.rstrip("*\"'")
        url = re.sub(r'\*+$', '', url)
        if url in seen_urls or url in _STATIC_SOURCE_URLS:
            continue
        seen_urls.add(url)

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
        elif "gist.githubusercontent.com" in url_lower:
            source_type = "gist_raw"
        elif "github.com" in url_lower and "raw" not in url_lower:
            source_type = "github_repo"
        else:
            source_type = "other"
        if source_type == "gist_raw":
            # gist raw files are directly fetchable, guess kind from URL keywords
            if any(kw in url_lower for kw in ("socks5", "socks", "proxy")):
                expected_kind = "socks5"
            elif any(kw in url_lower for kw in ("v2ray", "vless", "vmess", "clash", "sub")):
                expected_kind = "subscription"
            else:
                expected_kind = "unknown"
            sources.append({
                "url": url,
                "source_type": source_type,
                "expected_kind": expected_kind,
                "fetchable": True,
            })
            continue
        elif source_type in ("sstp_subscription", "official_api"):
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
        fetchable = source_type in (
            "sstp_subscription", "official_api", "github_raw",
            "socks_subscription", "turn_list", "gist_raw",
        )
        # Special: raw.cmliussss.com is fetchable
        if "raw.cmliussss.com" in url_lower:
            source_type = "github_raw"
            fetchable = True
            expected_kind = "subscription"
        if source_type == "github_repo":
            # Expand repo into candidate raw URLs instead of marking not fetchable
            expanded = _expand_github_repo(url)
            if expanded:
                sources.extend(expanded)
                continue
            # If expansion fails (unlikely URL pattern), keep as not fetchable
            fetchable = False
        sources.append({
            "url": url,
            "source_type": source_type,
            "expected_kind": expected_kind,
            "fetchable": fetchable,
        })
    return sources


if __name__ == "__main__":
    raise SystemExit(main())
