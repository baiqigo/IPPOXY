#!/usr/bin/env python3
"""Behavior tests for SSTP/OpenGW short preflight."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


class FakeSocket:
    def __init__(self, *, cipher=None, version=None):
        self.closed = False
        self._cipher = cipher
        self._version = version

    def close(self):
        self.closed = True

    def cipher(self):
        return self._cipher

    def version(self):
        return self._version


def test_preflight_reports_tls_ok():
    from ip_proxy_sstp_preflight import preflight_candidate

    raw_sock = FakeSocket()
    tls_sock = FakeSocket(cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), version="TLSv1.3")

    row = preflight_candidate(
        "sstp://vpn:vpn@public-vpn-109.opengw.net:443",
        timeout=1,
        dialer=lambda address, timeout: raw_sock,
        tls_wrapper=lambda sock, host: tls_sock,
    )

    assert row["candidate"] == "sstp://vpn:***@public-vpn-109.opengw.net:443"
    assert row["tcp_ok"] is True
    assert row["tls_ok"] is True
    assert row["status"] == "tls_ok"
    assert row["tls_version"] == "TLSv1.3"
    assert row["tls_cipher"] == "TLS_AES_256_GCM_SHA384"
    assert raw_sock.closed is True
    assert tls_sock.closed is True


def test_preflight_reports_tcp_error():
    from ip_proxy_sstp_preflight import preflight_candidate

    def fail_tcp(address, timeout):
        raise TimeoutError("dial timeout")

    row = preflight_candidate(
        "sstp://vpn:vpn@public-vpn-109.opengw.net:443",
        timeout=1,
        dialer=fail_tcp,
    )

    assert row["tcp_ok"] is False
    assert row["tls_ok"] is False
    assert row["status"] == "tcp_error"
    assert row["error_stage"] == "tcp"
    assert "TimeoutError" in row["error"]


def test_preflight_reports_tls_error_and_loads_manifest(tmp_path):
    from ip_proxy_sstp_preflight import load_candidates, preflight_candidate

    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"candidates": [{"raw": "sstp://vpn:vpn@public-vpn-109.opengw.net:443"}]}),
        encoding="utf-8",
    )
    assert load_candidates(manifest) == ["sstp://vpn:vpn@public-vpn-109.opengw.net:443"]

    raw_sock = FakeSocket()

    def fail_tls(sock, host):
        raise ConnectionResetError("reset by peer")

    row = preflight_candidate(
        "sstp://vpn:vpn@public-vpn-109.opengw.net:443",
        timeout=1,
        dialer=lambda address, timeout: raw_sock,
        tls_wrapper=fail_tls,
    )

    assert row["tcp_ok"] is True
    assert row["tls_ok"] is False
    assert row["status"] == "tls_error"
    assert row["error_stage"] == "tls"
    assert "ConnectionResetError" in row["error"]
    assert raw_sock.closed is True


def test_preflight_cli_outputs_report_without_network(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"candidates": []}), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "tools/ip_proxy_sstp_preflight.py",
            "--candidate",
            "sstp://vpn:vpn@127.0.0.1:1",
            "--limit",
            "1",
            "--timeout",
            "0.1",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        timeout=20,
    )

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["total"] == 1
    assert payload["results"][0]["candidate"] == "sstp://vpn:***@127.0.0.1:1"
