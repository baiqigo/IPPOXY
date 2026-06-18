#!/usr/bin/env python3
"""Behavior tests for the bounded SSTP converter probe wrapper."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_converter_plan_masks_password_and_uses_isolated_container(tmp_path):
    from ip_proxy_sstp_converter_probe import build_probe_plan, parse_sstp_candidate

    candidate = parse_sstp_candidate("sstp://user:secret@public-vpn-210.opengw.net:443")
    plan = build_probe_plan(
        candidate=candidate,
        run_id="unit",
        local_port=19280,
        duration_seconds=45,
        artifact_dir=tmp_path / "artifacts",
    )

    assert plan["candidate"]["raw_masked"] == "sstp://user:***@public-vpn-210.opengw.net:443"
    assert plan["candidate"]["password_redacted"] is True
    assert plan["ports"] == {"host": "127.0.0.1:19280", "container": "0.0.0.0:1080"}
    assert "--device" in plan["docker_command_display"]
    assert "/dev/ppp" in plan["docker_command_display"]
    assert "NET_ADMIN" in plan["docker_command_display"]
    assert "secret" not in json.dumps(plan)
    assert plan["impact"] == [
        "pulls/runs a temporary Debian container",
        "uses /dev/ppp and NET_ADMIN inside the container",
        "binds only 127.0.0.1:19280 on the host",
        "does not rewrite host Xray/Resin runtime files",
    ]


def test_converter_artifact_writer_outputs_entrypoint_and_masked_plan(tmp_path):
    from ip_proxy_sstp_converter_probe import build_probe_plan, parse_sstp_candidate, write_probe_artifacts

    candidate = parse_sstp_candidate("sstp://vpn:vpn@public-vpn-210.opengw.net:443")
    plan = build_probe_plan(
        candidate=candidate,
        run_id="write-test",
        local_port=19281,
        duration_seconds=30,
        artifact_dir=tmp_path / "probe",
    )
    written = write_probe_artifacts(plan, tmp_path / "probe")

    assert Path(written["entrypoint"]).read_text(encoding="utf-8").startswith("#!/usr/bin/env bash")
    assert "SSTP_PASSWORD" in Path(written["entrypoint"]).read_text(encoding="utf-8")
    plan_text = Path(written["plan"]).read_text(encoding="utf-8")
    assert "sstp://vpn:***@public-vpn-210.opengw.net:443" in plan_text
    assert "SSTP_PASSWORD=<redacted>" in Path(written["launch_example"]).read_text(encoding="utf-8")


def test_converter_cli_refuses_run_without_explicit_ack(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            "tools/ip_proxy_sstp_converter_probe.py",
            "--candidate",
            "sstp://vpn:vpn@public-vpn-210.opengw.net:443",
            "--local-port",
            "19282",
            "--artifact-dir",
            str(tmp_path / "probe"),
            "--run",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        timeout=20,
    )

    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["status"] == "refused"
    assert payload["reason"] == "run_requires_explicit_ack"
    assert "vpn" not in payload["docker_command_display"].replace("public-vpn", "")
