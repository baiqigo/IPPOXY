#!/usr/bin/env python3
"""Check proxy candidates from the current sandbox and emit live proof rows."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RESEARCH_DIR = RUNTIME / "research"
RESIN_DIR = RUNTIME / "resin"
DEFAULT_INPUT = RESIN_DIR / "all_candidates_classified.latest.json"
DEFAULT_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
SUPPORTED_DIRECT_PROXY_KINDS = {"http", "https", "socks4", "socks5"}


Runner = Callable[..., subprocess.CompletedProcess]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_candidate_rows(path: Path) -> list[dict]:
    data = read_json(path, [])
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = []
        for key in ("candidates", "results", "rows", "items"):
            value = data.get(key)
            if isinstance(value, list):
                rows = value
                break
    else:
        rows = []
    return [dict(item) for item in rows if isinstance(item, dict)]


def normalize_proxy_url(raw: str, kind: str) -> urllib.parse.ParseResult | None:
    value = str(raw or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = f"{kind}://{value}"
    parsed = urllib.parse.urlparse(value)
    if not parsed.hostname or not parsed.port:
        return None
    return parsed


def proxy_authority(parsed: urllib.parse.ParseResult) -> str:
    auth = ""
    if parsed.username is not None:
        auth = urllib.parse.unquote(parsed.username)
        if parsed.password is not None:
            auth += ":" + urllib.parse.unquote(parsed.password)
        auth += "@"
    return f"{auth}{parsed.hostname}:{parsed.port}"


def build_curl_command(raw: str, kind: str, trace_url: str, timeout: int) -> list[str]:
    kind = str(kind or "").lower()
    if kind not in SUPPORTED_DIRECT_PROXY_KINDS:
        raise ValueError(f"unsupported_kind:{kind or 'unknown'}")
    parsed = normalize_proxy_url(raw, kind)
    if parsed is None:
        raise ValueError("invalid_proxy_url")

    cmd = [
        "curl",
        "-sS",
        "--max-time",
        str(timeout),
        "-H",
        "User-Agent: IPPOXY-sandbox-live-check/1.0",
    ]
    if kind in {"http", "https"}:
        scheme = "https" if kind == "https" else "http"
        cmd.extend(["-x", f"{scheme}://{proxy_authority(parsed)}"])
    elif kind == "socks4":
        cmd.extend(["--socks4a", proxy_authority(parsed)])
    elif kind == "socks5":
        cmd.extend(["--socks5-hostname", proxy_authority(parsed)])
    cmd.append(trace_url)
    return cmd


def parse_cloudflare_trace(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return {
        "trace_ip": parsed.get("ip", ""),
        "trace_loc": parsed.get("loc", ""),
        "trace_colo": parsed.get("colo", ""),
        "trace_http": parsed.get("http", ""),
        "trace_tls": parsed.get("tls", ""),
        "trace_raw": parsed,
    }


def failure_row(item: dict, *, checked_at: str, reason: str, elapsed_ms: int = 0, error: str = "") -> dict:
    row = dict(item)
    row.update(
        {
            "success": False,
            "sandbox_live": False,
            "checked_from": "sandbox",
            "checked_at": checked_at,
            "failure_reason": reason,
            "sandbox_response_ms": elapsed_ms,
            "live_check": {
                "success": False,
                "checked_from": "sandbox",
                "checked_at": checked_at,
                "failure_reason": reason,
            },
        }
    )
    if error:
        row["error"] = error[:500]
    return row


def success_row(item: dict, *, checked_at: str, elapsed_ms: int, trace: dict[str, str]) -> dict:
    trace_ip = str(trace.get("trace_ip") or "")
    row = dict(item)
    original_success = row.get("success")
    if original_success is not None:
        row["upstream_success"] = bool(original_success)
    row.update(
        {
            "success": True,
            "sandbox_live": True,
            "checked_from": "sandbox",
            "checked_at": checked_at,
            "failure_reason": "",
            "trace_ip": trace_ip,
            "trace_loc": trace.get("trace_loc", ""),
            "trace_colo": trace.get("trace_colo", ""),
            "sandbox_response_ms": elapsed_ms,
            "exit_ip": trace_ip,
            "live_check": {
                "success": True,
                "checked_from": "sandbox",
                "checked_at": checked_at,
                "trace_ip": trace_ip,
                "trace_loc": trace.get("trace_loc", ""),
                "trace_colo": trace.get("trace_colo", ""),
            },
        }
    )
    if trace.get("trace_loc") and not row.get("country"):
        row["country"] = trace["trace_loc"]
    if not row.get("registration_tier"):
        row["registration_tier"] = "dirty_alive_noncn"
    if "dirty" not in row:
        row["dirty"] = ["sandbox_live_unclassified"]
    if not row.get("responseTime"):
        row["responseTime"] = elapsed_ms
    return row


def check_candidate(
    item: dict,
    *,
    timeout: int,
    trace_url: str = DEFAULT_TRACE_URL,
    runner: Runner = subprocess.run,
    checked_at: str | None = None,
) -> dict:
    checked_at = checked_at or utc_now()
    kind = str(item.get("kind") or "").lower()
    raw = str(item.get("raw") or "").strip()
    started = time.monotonic()
    try:
        cmd = build_curl_command(raw, kind, trace_url, timeout)
    except ValueError as exc:
        return failure_row(item, checked_at=checked_at, reason=str(exc))

    try:
        proc = runner(
            cmd,
            capture_output=True,
            timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return failure_row(item, checked_at=checked_at, reason="timeout", elapsed_ms=elapsed_ms)
    except OSError as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return failure_row(item, checked_at=checked_at, reason="curl_exec_failed", elapsed_ms=elapsed_ms, error=repr(exc))

    elapsed_ms = round((time.monotonic() - started) * 1000)
    stdout = proc.stdout.decode("utf-8", errors="ignore") if isinstance(proc.stdout, bytes) else str(proc.stdout or "")
    stderr = proc.stderr.decode("utf-8", errors="ignore") if isinstance(proc.stderr, bytes) else str(proc.stderr or "")
    if proc.returncode != 0:
        return failure_row(
            item,
            checked_at=checked_at,
            reason="curl_failed",
            elapsed_ms=elapsed_ms,
            error=stderr.strip(),
        )

    trace = parse_cloudflare_trace(stdout)
    if not trace.get("trace_ip"):
        return failure_row(
            item,
            checked_at=checked_at,
            reason="trace_parse_failed",
            elapsed_ms=elapsed_ms,
            error=stdout[:500],
        )
    return success_row(item, checked_at=checked_at, elapsed_ms=elapsed_ms, trace=trace)


def filter_candidate_kinds(rows: list[dict], only_kinds: set[str]) -> list[dict]:
    if not only_kinds:
        return rows
    return [row for row in rows if str(row.get("kind") or "").lower() in only_kinds]


def run_checks(
    rows: list[dict],
    *,
    timeout: int,
    workers: int,
    trace_url: str,
) -> list[dict]:
    if workers <= 1 or len(rows) <= 1:
        return [check_candidate(row, timeout=timeout, trace_url=trace_url) for row in rows]
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(rows))) as executor:
        futures = [executor.submit(check_candidate, row, timeout=timeout, trace_url=trace_url) for row in rows]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results


def summary(rows: list[dict]) -> dict:
    by_kind: dict[str, dict[str, int]] = {}
    for row in rows:
        kind = str(row.get("kind") or "unknown")
        slot = by_kind.setdefault(kind, {"checked": 0, "live": 0, "failed": 0})
        slot["checked"] += 1
        if row.get("sandbox_live"):
            slot["live"] += 1
        else:
            slot["failed"] += 1
    return {
        "checked": len(rows),
        "live": sum(1 for row in rows if row.get("sandbox_live")),
        "failed": sum(1 for row in rows if not row.get("sandbox_live")),
        "by_kind": by_kind,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sandbox-side live check for direct HTTP/SOCKS proxy candidates.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("IP_PROXY_SANDBOX_LIVE_TIMEOUT", "10")))
    parser.add_argument("--workers", type=int, default=int(os.environ.get("IP_PROXY_SANDBOX_LIVE_WORKERS", "8")))
    parser.add_argument("--trace-url", default=DEFAULT_TRACE_URL)
    parser.add_argument("--max-check", type=int, default=0, help="limit candidates after filtering; 0 means all")
    parser.add_argument(
        "--only-kind",
        action="append",
        choices=sorted(SUPPORTED_DIRECT_PROXY_KINDS),
        default=[],
        help="limit checks to one direct proxy kind; repeat to allow multiple kinds",
    )
    parser.add_argument("--no-latest", action="store_true", help="do not update proxy_candidate_sandbox_live.latest.json")
    args = parser.parse_args()

    run_id = args.run_id or time.strftime("%Y%m%d_%H%M%S")
    output = args.output or (RESEARCH_DIR / f"proxy_candidate_sandbox_live_{run_id}.json")
    rows = filter_candidate_kinds(load_candidate_rows(args.input), set(args.only_kind or []))
    if args.max_check and args.max_check > 0:
        rows = rows[: args.max_check]
    results = run_checks(rows, timeout=args.timeout, workers=max(1, args.workers), trace_url=args.trace_url)
    write_json(output, results)
    latest = None
    if not args.no_latest:
        latest = RESEARCH_DIR / "proxy_candidate_sandbox_live.latest.json"
        write_json(latest, results)
    result_summary = {
        "run_id": run_id,
        "input": str(args.input),
        "output": str(output),
        "latest": str(latest) if latest else "",
        **summary(results),
    }
    print(json.dumps(result_summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
