#!/usr/bin/env python3
"""Tests for proxy_pool -> mihomo provider filtering."""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_parse_proxy_supports_auth_and_scheme():
    from ip_proxy_mihomo_provider_filter import parse_proxy

    proxy = parse_proxy({"raw": "socks5://user:pass@203.0.113.10:1080", "source": "fixture"})

    assert proxy is not None
    assert proxy.kind == "socks5"
    assert proxy.host == "203.0.113.10"
    assert proxy.port == 1080
    assert proxy.username == "user"
    assert proxy.password == "pass"


def test_check_proxy_requires_all_test_urls_to_pass():
    from ip_proxy_mihomo_provider_filter import check_proxy

    calls = []

    def fake_runner(cmd, capture_output, timeout):
        calls.append(cmd[-1])
        status = b"204" if len(calls) == 1 else b"503"
        return subprocess.CompletedProcess(cmd, 0, stdout=status, stderr=b"")

    row = check_proxy(
        {"kind": "http", "raw": "http://203.0.113.20:8080", "source": "fixture"},
        test_urls=["https://www.gstatic.com/generate_204", "https://www.google.com/generate_204"],
        timeout=5,
        runner=fake_runner,
        checked_at="2026-06-22T00:00:00Z",
    )

    assert row["success"] is False
    assert row["failure_reason"] == "http_status"
    assert [test["status"] for test in row["tests"]] == ["204", "503"]


def test_render_mihomo_provider_exports_only_safe_kinds():
    from ip_proxy_mihomo_provider_filter import render_mihomo_provider

    text = render_mihomo_provider(
        [
            {"kind": "http", "host": "203.0.113.10", "port": 8080, "source": "a"},
            {"kind": "https", "host": "203.0.113.11", "port": 8443, "source": "b"},
            {"kind": "socks5", "host": "203.0.113.12", "port": 1080, "source": "c"},
            {"kind": "socks4", "host": "203.0.113.13", "port": 1081, "source": "d"},
        ]
    )

    assert 'server: "203.0.113.10"' in text
    assert 'server: "203.0.113.11"' in text
    assert "tls: true" in text
    assert 'server: "203.0.113.12"' in text
    assert "udp: true" in text
    assert "203.0.113.13" not in text


def test_run_filter_keeps_old_latest_when_live_below_min(tmp_path):
    from ip_proxy_mihomo_provider_filter import run_filter

    input_path = tmp_path / "candidates.json"
    output_path = tmp_path / "out.yaml"
    report_path = tmp_path / "report.json"
    latest_path = tmp_path / "latest.yaml"
    output_path.write_text("proxies:\n  - name: old-output\n", encoding="utf-8")
    latest_path.write_text("proxies:\n  - name: old\n", encoding="utf-8")
    input_path.write_text(
        json.dumps([{"kind": "http", "raw": "http://203.0.113.20:8080", "source": "fixture"}]),
        encoding="utf-8",
    )

    def fake_runner(cmd, capture_output, timeout):
        return subprocess.CompletedProcess(cmd, 7, stdout=b"", stderr=b"connect failed")

    report = run_filter(
        input_path=input_path,
        output_path=output_path,
        report_path=report_path,
        latest_path=latest_path,
        ipproxy_output_path=None,
        ipproxy_latest_path=None,
        test_urls=["https://www.gstatic.com/generate_204"],
        workers=1,
        limit=10,
        timeout=5,
        min_live=1,
        runner=fake_runner,
    )

    assert report["live"] == 0
    assert report["output_updated"] is False
    assert report["output_preserved"] is True
    assert report["latest_updated"] is False
    assert output_path.read_text(encoding="utf-8") == "proxies:\n  - name: old-output\n"
    assert latest_path.read_text(encoding="utf-8") == "proxies:\n  - name: old\n"


def test_run_filter_can_write_empty_output_when_explicitly_allowed(tmp_path):
    from ip_proxy_mihomo_provider_filter import run_filter

    input_path = tmp_path / "candidates.json"
    output_path = tmp_path / "out.yaml"
    report_path = tmp_path / "report.json"
    input_path.write_text(
        json.dumps([{"kind": "http", "raw": "http://203.0.113.20:8080", "source": "fixture"}]),
        encoding="utf-8",
    )
    output_path.write_text("proxies:\n  - name: old-output\n", encoding="utf-8")

    def fake_runner(cmd, capture_output, timeout):
        return subprocess.CompletedProcess(cmd, 7, stdout=b"", stderr=b"connect failed")

    report = run_filter(
        input_path=input_path,
        output_path=output_path,
        report_path=report_path,
        latest_path=None,
        ipproxy_output_path=None,
        ipproxy_latest_path=None,
        test_urls=["https://www.gstatic.com/generate_204"],
        workers=1,
        limit=10,
        timeout=5,
        min_live=1,
        runner=fake_runner,
        allow_empty_output=True,
    )

    assert report["live"] == 0
    assert report["output_updated"] is True
    assert report["output_preserved"] is False
    assert output_path.read_text(encoding="utf-8") == "proxies:\n  []\n"


def test_run_filter_writes_latest_when_live_passes(tmp_path):
    from ip_proxy_mihomo_provider_filter import run_filter

    input_path = tmp_path / "candidates.json"
    output_path = tmp_path / "out.yaml"
    report_path = tmp_path / "report.json"
    latest_path = tmp_path / "latest.yaml"
    ipproxy_output_path = tmp_path / "ipproxy.json"
    ipproxy_latest_path = tmp_path / "ipproxy.latest.json"
    input_path.write_text(
        json.dumps([{"kind": "http", "raw": "http://203.0.113.20:8080", "source": "fixture"}]),
        encoding="utf-8",
    )

    def fake_runner(cmd, capture_output, timeout):
        return subprocess.CompletedProcess(cmd, 0, stdout=b"204", stderr=b"")

    report = run_filter(
        input_path=input_path,
        output_path=output_path,
        report_path=report_path,
        latest_path=latest_path,
        ipproxy_output_path=ipproxy_output_path,
        ipproxy_latest_path=ipproxy_latest_path,
        test_urls=["https://www.gstatic.com/generate_204"],
        workers=1,
        limit=10,
        timeout=5,
        min_live=1,
        runner=fake_runner,
    )

    assert report["live"] == 1
    assert report["latest_updated"] is True
    assert latest_path.read_text(encoding="utf-8") == output_path.read_text(encoding="utf-8")
    assert 'type: http' in latest_path.read_text(encoding="utf-8")
    ipproxy_rows = json.loads(ipproxy_output_path.read_text(encoding="utf-8"))
    assert ipproxy_rows[0]["raw"] == "http://203.0.113.20:8080"
    assert ipproxy_rows[0]["exit_ip"] == "203.0.113.20"
    assert ipproxy_rows[0]["registration_tier"] == "dirty_alive_noncn"
    assert ipproxy_rows[0]["raw_pool"] is True
    assert json.loads(ipproxy_latest_path.read_text(encoding="utf-8")) == ipproxy_rows


def test_socks4_tunnel_uses_socks4a_hostname_handshake(monkeypatch):
    import ip_proxy_mihomo_provider_filter as provider_filter

    class FakeSocket:
        def __init__(self):
            self.sent = b""
            self.closed = False

        def sendall(self, data):
            self.sent += data

        def recv(self, size):
            return b"\x00\x5a\x00\x00\x00\x00\x00\x00"[:size]

        def close(self):
            self.closed = True

    fake_socket = FakeSocket()
    monkeypatch.setattr(provider_filter, "connect_tcp", lambda host, port, timeout: fake_socket)
    proxy = provider_filter.parse_proxy({"raw": "socks4://user@203.0.113.30:1080", "source": "fixture"})

    tunnel = provider_filter.socks4_tunnel(proxy, "www.gstatic.com", 443, 4)

    assert tunnel is fake_socket
    assert fake_socket.sent.startswith(b"\x04\x01\x01\xbb\x00\x00\x00\x01user\x00")
    assert fake_socket.sent.endswith(b"www.gstatic.com\x00")
    assert fake_socket.closed is False


def test_ipproxy_live_rows_dedupes_for_runtime_refresh():
    from ip_proxy_mihomo_provider_filter import ipproxy_live_rows

    rows = ipproxy_live_rows(
        [
            {
                "kind": "http",
                "raw": "http://203.0.113.20:8080",
                "source": "fixture",
                "success": True,
                "response_ms": 20,
            },
            {
                "kind": "http",
                "raw": "http://203.0.113.20:8080",
                "source": "fixture",
                "success": True,
                "response_ms": 30,
            },
            {
                "kind": "socks4",
                "raw": "socks4://203.0.113.21:1080",
                "source": "fixture",
                "success": True,
                "response_ms": 10,
            },
        ]
    )

    assert [row["raw"] for row in rows] == ["socks4://203.0.113.21:1080", "http://203.0.113.20:8080"]
    assert all(row["sandbox_live"] is True for row in rows)
    assert {row["exit_ip_source"] for row in rows} == {"proxy_host_fast_probe"}


def test_select_rows_keeps_socks4_for_ipproxy_runtime_refresh():
    from ip_proxy_mihomo_provider_filter import select_rows

    rows = select_rows(
        [
            {"kind": "socks4", "raw": "socks4://203.0.113.21:1080", "source": "fixture"},
            {"kind": "http", "raw": "http://203.0.113.20:8080", "source": "fixture"},
        ],
        limit=10,
    )

    assert [row["kind"] for row in rows] == ["socks4", "http"]


def test_select_rows_interleaves_sources_before_limit():
    from ip_proxy_mihomo_provider_filter import select_rows

    rows = select_rows(
        [
            {"kind": "http", "raw": "http://203.0.113.10:8080", "source": "source-a"},
            {"kind": "http", "raw": "http://203.0.113.11:8080", "source": "source-a"},
            {"kind": "http", "raw": "http://203.0.113.12:8080", "source": "source-a"},
            {"kind": "http", "raw": "http://203.0.113.20:8080", "source": "source-b"},
            {"kind": "http", "raw": "http://203.0.113.21:8080", "source": "source-b"},
        ],
        limit=3,
    )

    assert [row["source"] for row in rows] == ["source-a", "source-b", "source-a"]


def test_cleanup_files_keeps_newest_and_deletes_old_runs(tmp_path):
    from ip_proxy_mihomo_provider_filter import cleanup_files

    paths = []
    for index in range(5):
        path = tmp_path / f"layer0_http_socks_pool_proxy_pool_run{index}.json"
        path.write_text("x" * 10, encoding="utf-8")
        paths.append(path)

    deleted = cleanup_files(tmp_path, ["layer0_http_socks_pool_proxy_pool_*.json"], keep=2, max_total_mb=0)

    assert len(deleted) == 3
    assert sum(1 for path in paths if path.exists()) == 2


def test_run_once_can_intake_layer0_sources_and_emit_ipproxy_rows(tmp_path, monkeypatch):
    import ip_proxy_mihomo_provider_filter as provider_filter

    source_file = tmp_path / "http.txt"
    source_file.write_text("203.0.113.50:8080\n203.0.113.51:8081\n", encoding="utf-8")
    registry = tmp_path / "layer0_sources.json"
    registry.write_text(
        json.dumps(
            {
                "http_sources": [
                    {
                        "name": "fixture_layer0_http",
                        "url": source_file.as_uri(),
                        "kind": "http",
                        "type": "ip_port",
                    }
                ],
                "socks_sources": [],
                "subscription_sources": [],
                "api_sources": [],
            }
        ),
        encoding="utf-8",
    )

    def fake_check_proxy(row, *, test_urls, timeout, engine, runner, checked_at):
        parsed = provider_filter.parse_proxy(row)
        assert parsed is not None
        return {
            **row,
            "kind": parsed.kind,
            "raw": parsed.raw,
            "host": parsed.host,
            "port": parsed.port,
            "source": parsed.source,
            "success": True,
            "response_ms": 10,
            "tests": [{"url": test_urls[0], "status": "204"}],
            "checked_at": checked_at,
        }

    monkeypatch.setattr(provider_filter, "check_proxy", fake_check_proxy)

    output_dir = tmp_path / "out"
    args = Namespace(
        input=tmp_path / "unused.json",
        output=output_dir / "vertex-auto.yaml",
        report=output_dir / "vertex-auto-report.json",
        latest=output_dir / "vertex-auto.latest.yaml",
        no_latest=False,
        ipproxy_output=output_dir / "proxy_candidate_google_live.json",
        ipproxy_latest=output_dir / "proxy_candidate_google_live.latest.json",
        no_ipproxy_output=False,
        no_ipproxy_latest=False,
        test_url=["https://www.gstatic.com/generate_204"],
        workers=1,
        limit=100,
        timeout=4,
        min_live=1,
        engine="native",
        allow_empty_output=False,
        run_id="layer0-unit",
        run_bridge=False,
        proxy_pool_repo=None,
        clone_if_missing=False,
        bridge_update=False,
        bridge_update_latest=False,
        bridge_output_dir=output_dir,
        bridge_workers=1,
        bridge_max_per_source=100,
        bridge_limit=100,
        include_source=[],
        exclude_source=[],
        run_layer0=True,
        layer0_config=registry,
        layer0_output_dir=output_dir,
        layer0_update_latest=False,
        layer0_timeout=1,
        layer0_workers=1,
        layer0_dynamic_sources=None,
        layer0_no_dynamic_sources=True,
        layer0_only_dynamic_sources=False,
        keep_raw_artifact=True,
        keep_runs=100,
        max_research_mb=0,
        mihomo_api="",
        mihomo_provider_name="",
        mihomo_reload_timeout=10,
    )

    report, raw_path = provider_filter.run_once(args)

    raw_rows = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    ipproxy_rows = json.loads(args.ipproxy_output.read_text(encoding="utf-8"))
    manifest = json.loads((output_dir / "layer0_intake_manifest_layer0-unit.json").read_text(encoding="utf-8"))

    assert report["live"] == 2
    assert report["ipproxy_live"] == 2
    assert [row["source"] for row in raw_rows] == ["fixture_layer0_http", "fixture_layer0_http"]
    assert [row["raw"] for row in ipproxy_rows] == ["http://203.0.113.50:8080", "http://203.0.113.51:8081"]
    assert all(row["raw_pool"] is True for row in ipproxy_rows)
    assert manifest["lanes"]["http_socks"]["raw_count"] == 2


def test_run_once_reloads_mihomo_provider_after_output_update(tmp_path, monkeypatch):
    import ip_proxy_mihomo_provider_filter as provider_filter

    input_path = tmp_path / "candidates.json"
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    input_path.write_text(
        json.dumps([{"kind": "http", "raw": "http://203.0.113.20:8080", "source": "fixture"}]),
        encoding="utf-8",
    )

    def fake_check_proxy(row, *, test_urls, timeout, engine, runner, checked_at):
        parsed = provider_filter.parse_proxy(row)
        return {
            **row,
            "kind": parsed.kind,
            "raw": parsed.raw,
            "host": parsed.host,
            "port": parsed.port,
            "source": parsed.source,
            "success": True,
            "response_ms": 10,
            "tests": [{"url": test_urls[0], "status": "204"}],
            "checked_at": checked_at,
        }

    reload_calls = []

    def fake_reload(api_base, provider_name, timeout):
        reload_calls.append((api_base, provider_name, timeout))
        return {"ok": True, "status": 204, "url": f"{api_base}/providers/proxies/{provider_name}", "body": ""}

    monkeypatch.setattr(provider_filter, "check_proxy", fake_check_proxy)
    monkeypatch.setattr(provider_filter, "reload_mihomo_provider", fake_reload)

    args = Namespace(
        input=input_path,
        output=output_dir / "vertex-auto.yaml",
        report=output_dir / "vertex-auto-report.json",
        latest=output_dir / "vertex-auto.latest.yaml",
        no_latest=False,
        ipproxy_output=output_dir / "proxy_candidate_google_live.json",
        ipproxy_latest=output_dir / "proxy_candidate_google_live.latest.json",
        no_ipproxy_output=False,
        no_ipproxy_latest=False,
        test_url=["https://www.gstatic.com/generate_204"],
        workers=1,
        limit=100,
        timeout=4,
        min_live=1,
        engine="native",
        allow_empty_output=False,
        run_id="reload-unit",
        run_bridge=False,
        proxy_pool_repo=None,
        clone_if_missing=False,
        bridge_update=False,
        bridge_update_latest=False,
        bridge_output_dir=output_dir,
        bridge_workers=1,
        bridge_max_per_source=100,
        bridge_limit=100,
        include_source=[],
        exclude_source=[],
        run_layer0=False,
        layer0_config=None,
        layer0_output_dir=output_dir,
        layer0_update_latest=False,
        layer0_timeout=1,
        layer0_workers=1,
        layer0_dynamic_sources=None,
        layer0_no_dynamic_sources=True,
        layer0_only_dynamic_sources=False,
        keep_raw_artifact=True,
        keep_runs=100,
        max_research_mb=0,
        mihomo_api="http://127.0.0.1:9090",
        mihomo_provider_name="IPPOXY-LIVE",
        mihomo_reload_timeout=3,
    )

    report, _raw_path = provider_filter.run_once(args)
    persisted_report = json.loads(args.report.read_text(encoding="utf-8"))

    assert report["mihomo_reload"]["ok"] is True
    assert persisted_report["mihomo_reload"]["status"] == 204
    assert reload_calls == [("http://127.0.0.1:9090", "IPPOXY-LIVE", 3)]
