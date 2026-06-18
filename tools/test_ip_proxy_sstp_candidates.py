#!/usr/bin/env python3
"""Behavior tests for bounded SSTP/OpenGW candidate manifests."""

from __future__ import annotations

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_sstp_manifest_normalizes_and_dedupes_sources(tmp_path):
    from ip_proxy_sstp_candidates import build_manifest

    cmliussss = tmp_path / "cmliussss.txt"
    cmliussss.write_text(
        "sstp://vpn:vpn@public-vpn-210.opengw.net:443#JP\n"
        "public-vpn-210.opengw.net:443\n"
        "public-vpn-111\n",
        encoding="utf-8",
    )
    f0 = tmp_path / "f0.txt"
    f0.write_text(
        "Japan | laud.opengw.net:443\n"
        "Hong Kong | vpn445018862.opengw.net:1310\n",
        encoding="utf-8",
    )
    official = tmp_path / "official.csv"
    official.write_text(
        "*vpn_servers\n"
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort\n"
        "public-vpn-184,219.100.37.162,1,2,3,Japan,JP\n",
        encoding="utf-8",
    )

    manifest = build_manifest(
        run_id="sstp-test",
        source_specs=[
            {"name": "cmliussss", "url": cmliussss.as_uri(), "type": "generic"},
            {"name": "f0", "url": f0.as_uri(), "type": "generic"},
            {"name": "official", "url": official.as_uri(), "type": "vpngate_official"},
        ],
        timeout=1,
        limit=0,
    )

    assert manifest["run_id"] == "sstp-test"
    assert manifest["total"] == 5
    assert manifest["by_port"] == {"443": 4, "1310": 1}

    rows = manifest["candidates"]
    assert rows[0]["raw"] == "sstp://vpn:vpn@laud.opengw.net:443"
    assert {row["raw"] for row in rows} == {
        "sstp://vpn:vpn@public-vpn-210.opengw.net:443",
        "sstp://vpn:vpn@public-vpn-111.opengw.net:443",
        "sstp://vpn:vpn@laud.opengw.net:443",
        "sstp://vpn:vpn@vpn445018862.opengw.net:1310",
        "sstp://vpn:vpn@public-vpn-184.opengw.net:443",
    }
    assert {row["source"] for row in rows if row["host"] == "public-vpn-210.opengw.net"} == {"cmliussss"}


def test_sstp_manifest_applies_limit_after_priority_sort(tmp_path):
    from ip_proxy_sstp_candidates import build_manifest

    source = tmp_path / "sstp.txt"
    source.write_text(
        "vpn445018862.opengw.net:1310\n"
        "public-vpn-210.opengw.net:443\n"
        "public-vpn-999.opengw.net:992\n",
        encoding="utf-8",
    )

    manifest = build_manifest(
        run_id="limit-test",
        source_specs=[{"name": "source", "url": source.as_uri(), "type": "generic"}],
        timeout=1,
        limit=2,
    )

    assert [row["port"] for row in manifest["candidates"]] == [443, 992]
    assert manifest["total"] == 2
    assert manifest["available_before_limit"] == 3


def test_sstp_cli_harvest_only_writes_run_artifact_without_latest(tmp_path):
    import subprocess

    source = tmp_path / "sstp.txt"
    source.write_text("public-vpn-210.opengw.net:443\n", encoding="utf-8")
    output_dir = tmp_path / "out"

    proc = subprocess.run(
        [
            sys.executable,
            "tools/ip_proxy_sstp_candidates.py",
            "--run-id",
            "cli-test",
            "--no-default-sources",
            "--source",
            f"fixture={source.as_uri()}",
            "--output-dir",
            str(output_dir),
            "--dry-run",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        timeout=20,
    )

    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["total"] == 1
    assert not (output_dir / "sstp_candidates_cli-test.json").exists()
    assert not (output_dir / "sstp_candidates.latest.json").exists()
