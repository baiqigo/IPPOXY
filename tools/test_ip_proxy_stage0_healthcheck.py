#!/usr/bin/env python3
"""Behavior tests for subscription Stage0 candidate selection."""

from __future__ import annotations


def test_stage0_candidate_sampling_spreads_across_sources_and_kinds():
    from ip_proxy_stage0_healthcheck import select_candidates_for_check

    rows = (
        [{"kind": "vless", "raw": f"vless://id@a{idx}.example:443", "source": "vless_a"} for idx in range(100)]
        + [{"kind": "trojan", "raw": f"trojan://pw@b{idx}.example:443", "source": "trojan_b"} for idx in range(100)]
        + [{"kind": "ss", "raw": f"ss://method:pw@c{idx}.example:8388", "source": "ss_c"} for idx in range(100)]
    )

    selected = select_candidates_for_check(rows, 6, "stage0-run")

    assert len(selected) == 6
    assert {row["source"] for row in selected} == {"vless_a", "trojan_b", "ss_c"}
    assert {row["kind"] for row in selected} == {"vless", "trojan", "ss"}
    assert selected != rows[:6]
