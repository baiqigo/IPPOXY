#!/usr/bin/env python3
"""Filter proxy_pool candidates and export a mihomo provider for Vertex."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RESEARCH_DIR = RUNTIME / "research"
MIHOMO_DIR = RUNTIME / "mihomo"
DEFAULT_INPUT = RESEARCH_DIR / "layer0_http_socks_pool_proxy_pool.latest.json"
DEFAULT_OUTPUT = MIHOMO_DIR / "vertex-auto.yaml"
DEFAULT_REPORT = MIHOMO_DIR / "vertex-auto-report.json"
DEFAULT_IPPOXY_LATEST = RESEARCH_DIR / "proxy_candidate_google_live.latest.json"
DEFAULT_TEST_URLS = (
    "https://www.gstatic.com/generate_204",
)
EXPORTABLE_KINDS = {"http", "https", "socks5"}
CHECKABLE_KINDS = {"http", "https", "socks4", "socks5"}
HTTP_OK_RE = re.compile(r"^2\d\d$|^3\d\d$")


Runner = Callable[..., subprocess.CompletedProcess]


class ProxyCheckError(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


@dataclass(frozen=True)
class ProxyRef:
    kind: str
    raw: str
    host: str
    port: int
    username: str
    password: str
    source: str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def atomic_write_json(path: Path, data: object) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def load_rows(path: Path) -> list[dict]:
    data = read_json(path, [])
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = []
        for key in ("rows", "candidates", "items", "results"):
            value = data.get(key)
            if isinstance(value, list):
                rows = value
                break
    else:
        rows = []
    return [dict(row) for row in rows if isinstance(row, dict)]


def parse_proxy(row: dict, default_kind: str = "http") -> ProxyRef | None:
    raw = str(row.get("raw") or "").strip()
    kind = str(row.get("kind") or default_kind or "http").lower()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"{kind}://{raw}"
    parsed = urllib.parse.urlparse(raw)
    try:
        port = parsed.port
    except ValueError:
        return None
    if not parsed.hostname or not port:
        return None
    kind = parsed.scheme.lower() or kind
    if kind not in CHECKABLE_KINDS:
        return None
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    return ProxyRef(
        kind=kind,
        raw=raw,
        host=parsed.hostname,
        port=int(port),
        username=username,
        password=password,
        source=str(row.get("source") or row.get("source_id") or "unknown"),
    )


def proxy_authority(proxy: ProxyRef) -> str:
    auth = ""
    if proxy.username:
        auth = urllib.parse.quote(proxy.username, safe="")
        if proxy.password:
            auth += ":" + urllib.parse.quote(proxy.password, safe="")
        auth += "@"
    return f"{auth}{proxy.host}:{proxy.port}"


def build_curl_command(proxy: ProxyRef, url: str, timeout: int) -> list[str]:
    cmd = [
        "curl",
        "-sS",
        "-o",
        os.devnull,
        "-w",
        "%{http_code}",
        "--max-time",
        str(timeout),
        "-H",
        "User-Agent: IPPOXY-vertex-mihomo-filter/1.0",
    ]
    authority = proxy_authority(proxy)
    if proxy.kind in {"http", "https"}:
        cmd.extend(["-x", f"{proxy.kind}://{authority}"])
    elif proxy.kind == "socks4":
        cmd.extend(["--socks4a", authority])
    elif proxy.kind == "socks5":
        cmd.extend(["--socks5-hostname", authority])
    else:
        raise ValueError(f"unsupported_kind:{proxy.kind}")
    cmd.append(url)
    return cmd


def target_from_url(url: str) -> tuple[str, int, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProxyCheckError("unsupported_test_url", url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.hostname, parsed.port or 443, path


def recv_until(sock: socket.socket | ssl.SSLSocket, marker: bytes, *, max_bytes: int = 65536) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_bytes:
            raise ProxyCheckError("response_too_large")
    return bytes(data)


def connect_tcp(host: str, port: int, timeout: int) -> socket.socket:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    except TimeoutError as exc:
        raise ProxyCheckError("timeout", repr(exc)) from exc
    except OSError as exc:
        raise ProxyCheckError("connect_failed", repr(exc)) from exc


def basic_auth_header(proxy: ProxyRef) -> str:
    if not proxy.username:
        return ""
    raw = f"{proxy.username}:{proxy.password}".encode("utf-8")
    return "Proxy-Authorization: Basic " + base64.b64encode(raw).decode("ascii") + "\r\n"


def http_connect_tunnel(proxy: ProxyRef, target_host: str, target_port: int, timeout: int) -> socket.socket | ssl.SSLSocket:
    sock: socket.socket | ssl.SSLSocket = connect_tcp(proxy.host, proxy.port, timeout)
    if proxy.kind == "https":
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=proxy.host)
            sock.settimeout(timeout)
        except OSError as exc:
            try:
                sock.close()
            finally:
                raise ProxyCheckError("proxy_tls_failed", repr(exc)) from exc

    request = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        "User-Agent: IPPOXY-vertex-mihomo-filter/1.0\r\n"
        f"{basic_auth_header(proxy)}"
        "Proxy-Connection: Keep-Alive\r\n"
        "\r\n"
    ).encode("ascii", errors="ignore")
    try:
        sock.sendall(request)
        header = recv_until(sock, b"\r\n\r\n", max_bytes=16384)
    except TimeoutError as exc:
        sock.close()
        raise ProxyCheckError("timeout", repr(exc)) from exc
    except OSError as exc:
        sock.close()
        raise ProxyCheckError("proxy_connect_failed", repr(exc)) from exc

    first = header.splitlines()[0].decode("iso-8859-1", errors="ignore") if header else ""
    parts = first.split()
    status = parts[1] if len(parts) >= 2 else ""
    if status != "200":
        sock.close()
        raise ProxyCheckError("proxy_connect_status", first[:160])
    return sock


def socks5_read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProxyCheckError("socks5_closed")
        data.extend(chunk)
    return bytes(data)


def socks5_tunnel(proxy: ProxyRef, target_host: str, target_port: int, timeout: int) -> socket.socket:
    sock = connect_tcp(proxy.host, proxy.port, timeout)
    try:
        methods = b"\x00\x02" if proxy.username else b"\x00"
        sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
        version, method = socks5_read_exact(sock, 2)
        if version != 5:
            raise ProxyCheckError("socks5_bad_version")
        if method == 2:
            user = proxy.username.encode("utf-8")
            password = proxy.password.encode("utf-8")
            if len(user) > 255 or len(password) > 255:
                raise ProxyCheckError("socks5_auth_too_long")
            sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
            auth_version, auth_status = socks5_read_exact(sock, 2)
            if auth_version != 1 or auth_status != 0:
                raise ProxyCheckError("socks5_auth_failed")
        elif method != 0:
            raise ProxyCheckError("socks5_no_method")

        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise ProxyCheckError("target_host_too_long")
        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", target_port)
        sock.sendall(request)
        head = socks5_read_exact(sock, 4)
        if head[0] != 5:
            raise ProxyCheckError("socks5_bad_connect_version")
        if head[1] != 0:
            raise ProxyCheckError("socks5_connect_failed", f"rep={head[1]}")
        atyp = head[3]
        if atyp == 1:
            socks5_read_exact(sock, 4)
        elif atyp == 3:
            length = socks5_read_exact(sock, 1)[0]
            socks5_read_exact(sock, length)
        elif atyp == 4:
            socks5_read_exact(sock, 16)
        else:
            raise ProxyCheckError("socks5_bad_atyp")
        socks5_read_exact(sock, 2)
        return sock
    except (OSError, TimeoutError) as exc:
        sock.close()
        raise ProxyCheckError("socks5_failed", repr(exc)) from exc
    except ProxyCheckError:
        sock.close()
        raise


def socks4_tunnel(proxy: ProxyRef, target_host: str, target_port: int, timeout: int) -> socket.socket:
    sock = connect_tcp(proxy.host, proxy.port, timeout)
    try:
        user_id = proxy.username.encode("utf-8", errors="ignore")
        host = target_host.encode("idna")
        request = struct.pack(">BBH", 4, 1, target_port) + b"\x00\x00\x00\x01" + user_id + b"\x00" + host + b"\x00"
        sock.sendall(request)
        response = socks5_read_exact(sock, 8)
        if len(response) != 8 or response[1] != 90:
            code = response[1] if len(response) >= 2 else ""
            raise ProxyCheckError("socks4_failed", f"code={code}")
        return sock
    except TimeoutError as exc:
        sock.close()
        raise ProxyCheckError("timeout", repr(exc)) from exc
    except ProxyCheckError:
        sock.close()
        raise
    except OSError as exc:
        sock.close()
        raise ProxyCheckError("socks4_connect_failed", repr(exc)) from exc


def open_tunnel(proxy: ProxyRef, target_host: str, target_port: int, timeout: int) -> socket.socket | ssl.SSLSocket:
    if proxy.kind in {"http", "https"}:
        return http_connect_tunnel(proxy, target_host, target_port, timeout)
    if proxy.kind == "socks4":
        return socks4_tunnel(proxy, target_host, target_port, timeout)
    if proxy.kind == "socks5":
        return socks5_tunnel(proxy, target_host, target_port, timeout)
    raise ProxyCheckError("unsupported_kind", proxy.kind)


def native_https_status(proxy: ProxyRef, url: str, timeout: int) -> str:
    target_host, target_port, path = target_from_url(url)
    tunnel = open_tunnel(proxy, target_host, target_port, timeout)
    try:
        tls = ssl.create_default_context().wrap_socket(tunnel, server_hostname=target_host)
        tls.settimeout(timeout)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            "User-Agent: IPPOXY-vertex-mihomo-filter/1.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii", errors="ignore")
        tls.sendall(request)
        response = recv_until(tls, b"\r\n", max_bytes=4096)
        first = response.splitlines()[0].decode("iso-8859-1", errors="ignore") if response else ""
        parts = first.split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise ProxyCheckError("bad_http_response", first[:160])
        return parts[1]
    except TimeoutError as exc:
        raise ProxyCheckError("timeout", repr(exc)) from exc
    except ssl.SSLError as exc:
        raise ProxyCheckError("target_tls_failed", repr(exc)) from exc
    except OSError as exc:
        raise ProxyCheckError("target_request_failed", repr(exc)) from exc
    finally:
        try:
            tunnel.close()
        except OSError:
            pass


def curl_status(proxy: ProxyRef, url: str, timeout: int, runner: Runner) -> tuple[str, str, str]:
    proc = runner(build_curl_command(proxy, url, timeout), capture_output=True, timeout=timeout + 3)
    stdout = proc.stdout.decode("utf-8", errors="ignore") if isinstance(proc.stdout, bytes) else str(proc.stdout or "")
    stderr = proc.stderr.decode("utf-8", errors="ignore") if isinstance(proc.stderr, bytes) else str(proc.stderr or "")
    status = stdout.strip()[-3:]
    if proc.returncode != 0:
        return status, "curl_failed", stderr.strip()[:300]
    return status, "", ""


def check_proxy(
    row: dict,
    *,
    test_urls: list[str],
    timeout: int,
    engine: str = "native",
    runner: Runner | None = None,
    checked_at: str | None = None,
) -> dict:
    checked_at = checked_at or utc_now()
    proxy = parse_proxy(row)
    if proxy is None:
        item = dict(row)
        item.update({"success": False, "failure_reason": "invalid_proxy", "checked_at": checked_at})
        return item

    item = dict(row)
    item.update(
        {
            "kind": proxy.kind,
            "raw": proxy.raw,
            "host": proxy.host,
            "port": proxy.port,
            "source": proxy.source,
            "checked_at": checked_at,
            "success": False,
            "engine": engine,
            "tests": [],
        }
    )
    started_all = time.monotonic()
    for url in test_urls:
        started = time.monotonic()
        try:
            if runner is not None or engine == "curl":
                status, reason, error = curl_status(proxy, url, timeout, runner or subprocess.run)
            else:
                status = native_https_status(proxy, url, timeout)
                reason, error = "", ""
        except subprocess.TimeoutExpired:
            elapsed_ms = round((time.monotonic() - started) * 1000)
            item["tests"].append({"url": url, "success": False, "status": "", "elapsed_ms": elapsed_ms, "error": "timeout"})
            item["failure_reason"] = "timeout"
            return item
        except ProxyCheckError as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000)
            item["tests"].append(
                {"url": url, "success": False, "status": "", "elapsed_ms": elapsed_ms, "error": exc.detail[:300]}
            )
            item["failure_reason"] = exc.reason
            return item
        except OSError as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000)
            item["tests"].append(
                {"url": url, "success": False, "status": "", "elapsed_ms": elapsed_ms, "error": repr(exc)[:300]}
            )
            item["failure_reason"] = "curl_exec_failed"
            return item

        elapsed_ms = round((time.monotonic() - started) * 1000)
        ok = bool(HTTP_OK_RE.match(status))
        item["tests"].append(
            {
                "url": url,
                "success": ok,
                "status": status,
                "elapsed_ms": elapsed_ms,
                "error": "" if ok else error,
            }
        )
        if not ok:
            item["failure_reason"] = reason or "http_status"
            return item

    item["success"] = True
    item["failure_reason"] = ""
    item["response_ms"] = round((time.monotonic() - started_all) * 1000)
    return item


def dedupe_rows(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        proxy = parse_proxy(row)
        if proxy is None:
            continue
        if proxy.kind not in CHECKABLE_KINDS:
            continue
        key = f"{proxy.kind}://{proxy.host}:{proxy.port}:{proxy.username}"
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def interleave_rows_by_source(rows: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    order: list[str] = []
    for row in rows:
        source = str(row.get("source") or row.get("source_id") or "unknown")
        if source not in groups:
            groups[source] = []
            order.append(source)
        groups[source].append(row)

    out: list[dict] = []
    index = 0
    while True:
        added = False
        for source in order:
            group = groups[source]
            if index < len(group):
                out.append(group[index])
                added = True
        if not added:
            return out
        index += 1


def select_rows(rows: list[dict], limit: int) -> list[dict]:
    rows = dedupe_rows(rows)
    if limit > 0:
        rows = interleave_rows_by_source(rows)[:limit]
    return rows


def yaml_scalar(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def node_name(row: dict, index: int) -> str:
    source = re.sub(r"[^A-Za-z0-9]+", "-", str(row.get("source") or "src")).strip("-")[:18] or "src"
    kind = str(row.get("kind") or "proxy")
    host = str(row.get("host") or "").replace(".", "-")
    port = str(row.get("port") or "")
    return f"vertex-{source}-{kind}-{host}-{port}-{index:03d}"


def render_mihomo_provider(live_rows: list[dict]) -> str:
    lines = ["proxies:"]
    if not live_rows:
        lines.append("  []")
        return "\n".join(lines) + "\n"

    for index, row in enumerate(live_rows, 1):
        kind = str(row.get("kind") or "").lower()
        if kind not in EXPORTABLE_KINDS:
            continue
        proxy_type = "http" if kind in {"http", "https"} else "socks5"
        lines.extend(
            [
                f"  - name: {yaml_scalar(node_name(row, index))}",
                f"    type: {proxy_type}",
                f"    server: {yaml_scalar(row.get('host'))}",
                f"    port: {int(row.get('port'))}",
            ]
        )
        if kind == "https":
            lines.append("    tls: true")
        if proxy_type == "socks5":
            lines.append("    udp: true")
        if row.get("username"):
            lines.append(f"    username: {yaml_scalar(row.get('username'))}")
        if row.get("password"):
            lines.append(f"    password: {yaml_scalar(row.get('password'))}")
    return "\n".join(lines) + "\n"


def exportable_live_rows(results: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for row in results:
        if row.get("success") is True and str(row.get("kind") or "").lower() in EXPORTABLE_KINDS:
            proxy = parse_proxy(row)
            if proxy is None:
                continue
            item = dict(row)
            item.update(
                {
                    "kind": proxy.kind,
                    "raw": proxy.raw,
                    "host": proxy.host,
                    "port": proxy.port,
                    "username": proxy.username,
                    "password": proxy.password,
                    "source": proxy.source,
                }
            )
            rows.append(item)
    rows.sort(key=lambda item: (int(item.get("response_ms") or 999999), str(item.get("raw") or "")))
    return rows


def ipproxy_live_rows(results: list[dict]) -> list[dict]:
    rows: list[dict] = []
    seen_raw: set[str] = set()
    seen_exit: set[str] = set()
    for row in results:
        if row.get("success") is not True:
            continue
        proxy = parse_proxy(row)
        if proxy is None:
            continue
        raw = proxy.raw
        # Fast Google probing does not reveal the final egress IP. For direct public
        # proxies, the proxy host is the best cheap identity until registrar feedback
        # observes a real exit probe.
        exit_ip = proxy.host
        if raw in seen_raw or exit_ip in seen_exit:
            continue
        seen_raw.add(raw)
        seen_exit.add(exit_ip)
        item = dict(row)
        item.update(
            {
                "kind": proxy.kind,
                "raw": raw,
                "host": proxy.host,
                "port": proxy.port,
                "username": proxy.username,
                "password": proxy.password,
                "source": proxy.source,
                "success": True,
                "sandbox_live": True,
                "checked_from": "native_google_generate_204",
                "exit_ip": exit_ip,
                "exit_ip_source": "proxy_host_fast_probe",
                "registration_tier": "dirty_alive_noncn",
                "raw_pool": True,
                "responseTime": item.get("response_ms"),
                "dirty": ["google_live_unclassified"],
            }
        )
        rows.append(item)
    rows.sort(key=lambda item: (int(item.get("response_ms") or 999999), str(item.get("raw") or "")))
    return rows


def run_filter(
    *,
    input_path: Path,
    output_path: Path,
    report_path: Path,
    latest_path: Path | None,
    ipproxy_output_path: Path | None,
    ipproxy_latest_path: Path | None,
    test_urls: list[str],
    workers: int,
    limit: int,
    timeout: int,
    min_live: int,
    engine: str = "native",
    runner: Runner | None = None,
    allow_empty_output: bool = False,
) -> dict:
    rows = select_rows(load_rows(input_path), limit)
    checked_at = utc_now()
    worker_count = max(1, int(workers or 1))
    results: list[dict] = []

    def work(row: dict) -> dict:
        return check_proxy(row, test_urls=test_urls, timeout=timeout, engine=engine, runner=runner, checked_at=checked_at)

    if worker_count == 1 or len(rows) <= 1:
        results = [work(row) for row in rows]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(work, row) for row in rows]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

    live_rows = exportable_live_rows(results)
    ipproxy_rows = ipproxy_live_rows(results)
    provider_text = render_mihomo_provider(live_rows)
    enough_live = len(live_rows) >= min_live
    output_updated = False
    output_preserved = False
    if enough_live or allow_empty_output or not output_path.exists():
        atomic_write_text(output_path, provider_text)
        output_updated = True
    else:
        output_preserved = True
    updated_latest = False
    if latest_path is not None and enough_live:
        atomic_write_text(latest_path, provider_text)
        updated_latest = True

    ipproxy_latest_updated = False
    if ipproxy_output_path is not None:
        atomic_write_json(ipproxy_output_path, ipproxy_rows)
    if ipproxy_latest_path is not None and len(ipproxy_rows) >= min_live:
        atomic_write_json(ipproxy_latest_path, ipproxy_rows)
        ipproxy_latest_updated = True

    success_count = sum(1 for row in results if row.get("success") is True)

    report = {
        "schema": "ippoxy_mihomo_provider_filter.v1",
        "checked_at": checked_at,
        "input_path": str(input_path),
        "output_path": str(output_path),
        "output_updated": output_updated,
        "output_preserved": output_preserved,
        "allow_empty_output": allow_empty_output,
        "latest_path": str(latest_path) if latest_path else "",
        "latest_updated": updated_latest,
        "ipproxy_output_path": str(ipproxy_output_path) if ipproxy_output_path else "",
        "ipproxy_latest_path": str(ipproxy_latest_path) if ipproxy_latest_path else "",
        "ipproxy_latest_updated": ipproxy_latest_updated,
        "test_urls": test_urls,
        "workers": worker_count,
        "engine": engine,
        "timeout": timeout,
        "min_live": min_live,
        "candidates": len(rows),
        "success": success_count,
        "live": len(live_rows),
        "ipproxy_live": len(ipproxy_rows),
        "failed": len(results) - success_count,
        "by_failure_reason": {},
        "live_rows": live_rows,
        "ipproxy_rows": ipproxy_rows,
        "failed_examples": [row for row in results if row.get("success") is not True][:20],
    }
    counts: dict[str, int] = {}
    for row in results:
        if row.get("success") is True:
            continue
        reason = str(row.get("failure_reason") or "unknown")
        counts[reason] = counts.get(reason, 0) + 1
    report["by_failure_reason"] = dict(sorted(counts.items()))
    atomic_write_json(report_path, report)
    return report


def cleanup_files(directory: Path, patterns: list[str], *, keep: int, max_total_mb: int) -> list[str]:
    if not directory.exists():
        return []
    files: list[Path] = []
    for pattern in patterns:
        files.extend(path for path in directory.glob(pattern) if path.is_file())
    unique = sorted(set(files), key=lambda path: path.stat().st_mtime, reverse=True)
    to_delete: list[Path] = []
    if keep >= 0:
        to_delete.extend(unique[keep:])
    if max_total_mb > 0:
        max_bytes = max_total_mb * 1024 * 1024
        total = 0
        for path in unique:
            if path in to_delete:
                continue
            total += path.stat().st_size
            if total > max_bytes:
                to_delete.append(path)
    deleted: list[str] = []
    for path in sorted(set(to_delete)):
        try:
            path.unlink()
            deleted.append(str(path))
        except OSError:
            pass
    return deleted


def reload_mihomo_provider(api_base: str, provider_name: str, timeout: int) -> dict:
    api_base = api_base.rstrip("/")
    provider = urllib.parse.quote(provider_name, safe="")
    url = f"{api_base}/providers/proxies/{provider}"
    request = urllib.request.Request(url, method="PUT")
    try:
        with urllib.request.urlopen(request, timeout=max(1, timeout)) as response:
            body = response.read(2000).decode("utf-8", errors="replace").strip()
            return {
                "ok": 200 <= int(response.status) < 300,
                "status": int(response.status),
                "url": url,
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(2000).decode("utf-8", errors="replace").strip()
        return {"ok": False, "status": int(exc.code), "url": url, "body": body}
    except OSError as exc:
        return {"ok": False, "status": 0, "url": url, "error": repr(exc)}


def maybe_run_bridge(args: argparse.Namespace) -> tuple[Path, Path | None]:
    if not args.run_bridge:
        return args.input, None
    sys.path.insert(0, str(ROOT / "tools"))
    from ip_proxy_proxy_pool_bridge import DEFAULT_PROXY_POOL_REPO, DEFAULT_PROXY_POOL_URL, ensure_proxy_pool_repo, run_bridge

    run_id = args.run_id or time.strftime("vertex_mihomo_%Y%m%d_%H%M%S")
    repo = args.proxy_pool_repo or DEFAULT_PROXY_POOL_REPO
    ensure_proxy_pool_repo(repo, clone_url=DEFAULT_PROXY_POOL_URL, clone_if_missing=args.clone_if_missing, update=args.bridge_update)
    manifest = run_bridge(
        repo=repo,
        output_dir=args.bridge_output_dir,
        run_id=run_id,
        dry_run=not args.bridge_update_latest,
        workers=args.bridge_workers,
        max_per_source=args.bridge_max_per_source,
        limit=args.bridge_limit,
        include_sources=set(args.include_source or []),
        exclude_sources=set(args.exclude_source or []),
    )
    return Path(str(manifest["raw_path"])), Path(str(manifest["raw_path"]))


def maybe_run_layer0(args: argparse.Namespace, run_id: str) -> tuple[Path, Path | None]:
    if not args.run_layer0:
        return args.input, None
    sys.path.insert(0, str(ROOT / "tools"))
    from ip_proxy_layer0_intake import DEFAULT_SOURCES_CONFIG, run_intake

    manifest = run_intake(
        source_registry=args.layer0_config or DEFAULT_SOURCES_CONFIG,
        output_dir=args.layer0_output_dir,
        run_id=run_id,
        dry_run=not args.layer0_update_latest,
        timeout=args.layer0_timeout,
        workers=args.layer0_workers,
        dynamic_sources=args.layer0_dynamic_sources,
        include_dynamic_sources=not args.layer0_no_dynamic_sources,
        only_dynamic_sources=args.layer0_only_dynamic_sources,
    )
    raw_path = Path(str(manifest["lanes"]["http_socks"]["raw_path"]))
    return raw_path, raw_path


def run_once(args: argparse.Namespace) -> tuple[dict, Path | None]:
    run_id = args.run_id or time.strftime("vertex_mihomo_%Y%m%d_%H%M%S")
    input_path, layer0_raw_path = maybe_run_layer0(args, run_id)
    bridge_raw_path = None
    if not args.run_layer0:
        input_path, bridge_raw_path = maybe_run_bridge(args)
    test_urls = args.test_url or list(DEFAULT_TEST_URLS)
    latest_path = None if args.no_latest else args.latest
    ipproxy_output = None if args.no_ipproxy_output else (
        args.ipproxy_output or (RESEARCH_DIR / f"proxy_candidate_google_live_{run_id}.json")
    )
    ipproxy_latest = None if args.no_ipproxy_latest else args.ipproxy_latest
    report = run_filter(
        input_path=input_path,
        output_path=args.output,
        report_path=args.report,
        latest_path=latest_path,
        ipproxy_output_path=ipproxy_output,
        ipproxy_latest_path=ipproxy_latest,
        test_urls=test_urls,
        workers=args.workers,
        limit=args.limit,
        timeout=args.timeout,
        min_live=args.min_live,
        engine=args.engine,
        allow_empty_output=args.allow_empty_output,
    )
    if args.mihomo_api and args.mihomo_provider_name and report.get("output_updated"):
        report["mihomo_reload"] = reload_mihomo_provider(
            args.mihomo_api,
            args.mihomo_provider_name,
            args.mihomo_reload_timeout,
        )
        atomic_write_json(args.report, report)
    raw_path = layer0_raw_path or bridge_raw_path
    if raw_path and not args.keep_raw_artifact:
        try:
            raw_path.unlink()
            report["deleted_raw_candidates"] = str(raw_path)
        except OSError:
            report["deleted_raw_candidates"] = ""
    deleted = cleanup_files(
        args.bridge_output_dir,
        [
            "layer0_http_socks_pool_proxy_pool_*.json",
            "layer0_http_socks_pool_*.json",
            "layer0_intake_manifest_*.json",
            "proxy_pool_bridge_manifest_*.json",
            "proxy_candidate_google_live_*.json",
        ],
        keep=args.keep_runs,
        max_total_mb=args.max_research_mb,
    )
    if deleted:
        report["retention_deleted"] = deleted[:20]
        atomic_write_json(args.report, report)
    return report, raw_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Filter proxy_pool candidates into a mihomo provider for Vertex.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--latest", type=Path, default=MIHOMO_DIR / "vertex-auto.latest.yaml")
    parser.add_argument("--no-latest", action="store_true")
    parser.add_argument("--ipproxy-output", type=Path, default=None)
    parser.add_argument("--ipproxy-latest", type=Path, default=DEFAULT_IPPOXY_LATEST)
    parser.add_argument("--no-ipproxy-output", action="store_true")
    parser.add_argument("--no-ipproxy-latest", action="store_true")
    parser.add_argument("--test-url", action="append", default=[])
    parser.add_argument("--workers", type=int, default=512)
    parser.add_argument("--limit", type=int, default=200000)
    parser.add_argument("--timeout", type=int, default=4)
    parser.add_argument("--min-live", type=int, default=1)
    parser.add_argument("--engine", choices=["native", "curl"], default="native")
    parser.add_argument(
        "--allow-empty-output",
        action="store_true",
        help="write an empty provider when live < --min-live; by default an existing provider is preserved",
    )
    parser.add_argument("--run-id", default="")
    parser.add_argument("--loop", action="store_true", help="Run forever; use with an external supervisor or explicit approval.")
    parser.add_argument("--interval", type=int, default=300)

    parser.add_argument("--run-bridge", action="store_true", help="Run proxy_pool bridge before filtering.")
    parser.add_argument("--proxy-pool-repo", type=Path, default=None)
    parser.add_argument("--clone-if-missing", action="store_true")
    parser.add_argument("--bridge-update", action="store_true", help="git pull proxy_pool before bridge.")
    parser.add_argument("--bridge-update-latest", action="store_true", help="Let bridge update its latest artifact.")
    parser.add_argument("--bridge-output-dir", type=Path, default=RESEARCH_DIR)
    parser.add_argument("--bridge-workers", type=int, default=6)
    parser.add_argument("--bridge-max-per-source", type=int, default=20000)
    parser.add_argument("--bridge-limit", type=int, default=200000)
    parser.add_argument("--include-source", action="append", default=[])
    parser.add_argument("--exclude-source", action="append", default=[])
    parser.add_argument("--run-layer0", action="store_true", help="Run IPPOXY layer0_sources.json URL intake before filtering.")
    parser.add_argument("--layer0-config", type=Path, default=None)
    parser.add_argument("--layer0-output-dir", type=Path, default=RESEARCH_DIR)
    parser.add_argument("--layer0-update-latest", action="store_true", help="Let Layer0 intake update latest artifacts.")
    parser.add_argument("--layer0-timeout", type=int, default=8)
    parser.add_argument("--layer0-workers", type=int, default=64)
    parser.add_argument("--layer0-dynamic-sources", type=Path, default=None)
    parser.add_argument("--layer0-no-dynamic-sources", action="store_true")
    parser.add_argument("--layer0-only-dynamic-sources", action="store_true")
    parser.add_argument("--keep-raw-artifact", action="store_true")
    parser.add_argument("--keep-runs", type=int, default=3)
    parser.add_argument("--max-research-mb", type=int, default=512)
    parser.add_argument("--mihomo-api", default="", help="Optional mihomo external-controller URL for provider reload.")
    parser.add_argument("--mihomo-provider-name", default="", help="Reload this mihomo provider after output is updated.")
    parser.add_argument("--mihomo-reload-timeout", type=int, default=10)
    args = parser.parse_args()

    last_report: dict | None = None
    while True:
        report, _raw_path = run_once(args)
        last_report = report
        print(
            json.dumps(
                {
                    k: report.get(k)
                    for k in (
                        "candidates",
                        "live",
                        "ipproxy_live",
                        "failed",
                        "output_updated",
                        "output_preserved",
                        "latest_updated",
                        "ipproxy_latest_updated",
                        "output_path",
                        "ipproxy_output_path",
                        "deleted_raw_candidates",
                        "mihomo_reload",
                    )
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        if not args.loop:
            break
        time.sleep(max(1, int(args.interval)))
    if not last_report:
        return 2
    if int(last_report["live"]) >= int(args.min_live):
        return 0
    if last_report.get("output_preserved"):
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
