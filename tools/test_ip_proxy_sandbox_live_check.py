#!/usr/bin/env python3
"""Behavior tests for sandbox-side IPPOXY live checks."""

from __future__ import annotations

import subprocess


def test_parse_cloudflare_trace_extracts_live_proof_fields():
    from ip_proxy_sandbox_live_check import parse_cloudflare_trace

    trace = parse_cloudflare_trace(
        "\n".join(
            [
                "fl=123f1",
                "ip=198.51.100.44",
                "colo=LAX",
                "loc=US",
                "http=http/2",
                "tls=TLSv1.3",
            ]
        )
    )

    assert trace["trace_ip"] == "198.51.100.44"
    assert trace["trace_loc"] == "US"
    assert trace["trace_colo"] == "LAX"
    assert trace["trace_http"] == "http/2"
    assert trace["trace_tls"] == "TLSv1.3"


def test_build_curl_command_uses_proxy_flags_for_direct_kinds():
    from ip_proxy_sandbox_live_check import build_curl_command

    http = build_curl_command("http://user:pass@203.0.113.10:8080", "http", "https://trace.test", 7)
    socks4 = build_curl_command("203.0.113.11:1080", "socks4", "https://trace.test", 7)
    socks5 = build_curl_command("socks5://203.0.113.12:1081", "socks5", "https://trace.test", 7)

    assert "-x" in http
    assert "http://user:pass@203.0.113.10:8080" in http
    assert "--socks4a" in socks4
    assert "203.0.113.11:1080" in socks4
    assert "--socks5-hostname" in socks5
    assert "203.0.113.12:1081" in socks5


def test_check_candidate_success_row_is_accepted_by_pool_refresh_gate():
    from ip_proxy_pool_refresh import is_sandbox_live_candidate
    from ip_proxy_sandbox_live_check import check_candidate

    def fake_runner(cmd, capture_output, timeout):
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=b"ip=198.51.100.50\nloc=US\ncolo=SJC\n",
            stderr=b"",
        )

    row = check_candidate(
        {
            "kind": "socks5",
            "raw": "socks5://203.0.113.50:1080",
            "source": "fixture",
            "registration_tier": "dirty_alive_noncn",
            "dirty": ["is_proxy"],
        },
        timeout=5,
        runner=fake_runner,
        checked_at="2026-06-19T00:00:00Z",
    )

    assert row["success"] is True
    assert row["sandbox_live"] is True
    assert row["checked_from"] == "sandbox"
    assert row["trace_ip"] == "198.51.100.50"
    assert row["exit_ip"] == "198.51.100.50"
    assert row["failure_reason"] == ""
    assert is_sandbox_live_candidate(row) is True


def test_check_candidate_records_curl_failure_without_live_proof():
    from ip_proxy_sandbox_live_check import check_candidate

    def fake_runner(cmd, capture_output, timeout):
        return subprocess.CompletedProcess(cmd, 7, stdout=b"", stderr=b"connect timeout")

    row = check_candidate(
        {"kind": "http", "raw": "http://203.0.113.10:8080", "source": "fixture"},
        timeout=5,
        runner=fake_runner,
        checked_at="2026-06-19T00:00:00Z",
    )

    assert row["success"] is False
    assert row["sandbox_live"] is False
    assert row["checked_from"] == "sandbox"
    assert row["failure_reason"] == "curl_failed"
    assert "connect timeout" in row["error"]


def test_check_candidate_rejects_unsupported_kind_cleanly():
    from ip_proxy_sandbox_live_check import check_candidate

    row = check_candidate(
        {"kind": "turn", "raw": "turn://turn.example.test:3478", "source": "fixture"},
        timeout=5,
        checked_at="2026-06-19T00:00:00Z",
    )

    assert row["success"] is False
    assert row["sandbox_live"] is False
    assert row["failure_reason"] == "unsupported_kind:turn"
