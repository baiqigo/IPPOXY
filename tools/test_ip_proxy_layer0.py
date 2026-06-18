#!/usr/bin/env python3
"""Tests for Layer 0 integration: classify L3 tier + consumer parsing."""

import json
import pytest
from pathlib import Path
import sys

# Add tools dir to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))


import os

_LAYER0_DIR = Path(__file__).resolve().parents[1] / "layer0_sources"


# --- L3 classify tests ---

def _make_item(**overrides):
    """Build a candidate item with sensible defaults."""
    base = {
        "kind": "vless",
        "raw": "vless://test@1.2.3.4:443?type=ws",
        "source": "test",
        "checked": True,
        "success": True,
        "clean": True,
        "dirty": [],
        "responseTime": 200,
        "exit_ip": "1.2.3.4",
        "country": "US",
        "city": "LA",
        "company_type": "isp",
        "asn_type": "isp",
        "company": "TestISP",
    }
    base.update(overrides)
    return base


class TestClassifyL3Tier:
    """Verify registration_tier produces dirty_alive_noncn for L3 candidates."""

    def test_clean_node_stays_clean(self):
        from ip_proxy_classify_clean import registration_tier
        item = _make_item(dirty=[])
        assert registration_tier(item) == "clean"

    def test_dead_node_is_dirty(self):
        from ip_proxy_classify_clean import registration_tier
        item = _make_item(success=False)
        assert registration_tier(item) == "dirty"

    def test_hard_dirty_is_dirty(self):
        from ip_proxy_classify_clean import registration_tier
        for flag in ["is_tor", "is_abuser", "is_bogon"]:
            item = _make_item(dirty=[flag])
            assert registration_tier(item) == "dirty", f"{flag} should be dirty, not L3"

    def test_cn_ip_is_dirty(self):
        from ip_proxy_classify_clean import registration_tier
        item = _make_item(dirty=["is_datacenter"], country="CN")
        assert registration_tier(item) == "dirty", "CN IP should always be dirty"

    def test_soft_dirty_non_cn_is_risky(self):
        from ip_proxy_classify_clean import registration_tier
        for flag in ["is_datacenter", "is_proxy", "is_vpn"]:
            item = _make_item(dirty=[flag], country="US")
            assert registration_tier(item) == "risky", f"{flag} alone should be risky"

    def test_mixed_soft_dirty_non_cn_is_risky(self):
        from ip_proxy_classify_clean import registration_tier
        item = _make_item(dirty=["is_datacenter", "is_vpn"], country="DE")
        assert registration_tier(item) == "risky", "soft dirty combo should be risky"

    def test_unknown_dirty_non_cn_is_L3(self):
        from ip_proxy_classify_clean import registration_tier
        # is_datacenter + some unknown dirty flag -> not purely soft dirty -> L3
        item = _make_item(dirty=["is_datacenter", "is_suspicious"], country="JP")
        tier = registration_tier(item)
        assert tier == "dirty_alive_noncn", f"unknown dirty + non-CN should be L3, got {tier}"

    def test_soft_dirty_cn_is_dirty_not_L3(self):
        from ip_proxy_classify_clean import registration_tier
        item = _make_item(dirty=["is_datacenter"], country="CN")
        assert registration_tier(item) == "dirty", "CN even with soft dirty should be dirty"

    def test_alive_non_cn_no_dirty_is_clean(self):
        from ip_proxy_classify_clean import registration_tier
        item = _make_item(dirty=[], country="FR")
        assert registration_tier(item) == "clean"


# --- Consumer parse tests ---

class TestConsumerParse:
    """Verify layer0 consumer correctly parses upstream raw files."""

    def test_ip_port_line_parses_as_http(self):
        from ip_proxy_layer0_consumer import parse_line
        result = parse_line("147.161.246.38:10920", source="databay_http", kind="http")
        assert result == {"kind": "http", "raw": "http://147.161.246.38:10920", "source": "databay_http"}

    def test_ip_port_line_parses_as_socks5(self):
        from ip_proxy_layer0_consumer import parse_line
        result = parse_line("77.110.126.90:1080", source="databay_socks5", kind="socks5")
        assert result == {"kind": "socks5", "raw": "socks5://77.110.126.90:1080", "source": "databay_socks5"}

    def test_share_url_vless(self):
        from ip_proxy_layer0_consumer import parse_line
        url = "vless://uuid@host:443?type=ws&security=tls&sni=example.com"
        result = parse_line(url, source="gfpcom_vless", kind=None)
        assert result == {"kind": "vless", "raw": url, "source": "gfpcom_vless"}

    def test_share_url_vmess(self):
        from ip_proxy_layer0_consumer import parse_line
        url = "vmess://base64json=="
        result = parse_line(url, source="gfpcom_vmess", kind=None)
        assert result == {"kind": "vmess", "raw": url, "source": "gfpcom_vmess"}

    def test_share_url_trojan(self):
        from ip_proxy_layer0_consumer import parse_line
        url = "trojan://pass@host:443?security=tls"
        result = parse_line(url, source="gfpcom_trojan", kind=None)
        assert result == {"kind": "trojan", "raw": url, "source": "gfpcom_trojan"}

    def test_share_url_ss(self):
        from ip_proxy_layer0_consumer import parse_line
        url = "ss://base64@host:443"
        result = parse_line(url, source="gfpcom_ss", kind=None)
        assert result == {"kind": "ss", "raw": url, "source": "gfpcom_ss"}

    def test_empty_line_skipped(self):
        from ip_proxy_layer0_consumer import parse_line
        assert parse_line("", source="test", kind="http") is None

    def test_comment_line_skipped(self):
        from ip_proxy_layer0_consumer import parse_line
        assert parse_line("# this is a comment", source="test", kind="http") is None

    def test_http_url_format(self):
        from ip_proxy_layer0_consumer import parse_line
        result = parse_line("http://147.161.246.38:10920", source="gfpcom_http", kind="http")
        assert result == {"kind": "http", "raw": "http://147.161.246.38:10920", "source": "gfpcom_http"}

    def test_socks5_url_format(self):
        from ip_proxy_layer0_consumer import parse_line
        result = parse_line("socks5://77.110.126.90:1080", source="gfpcom_socks5", kind="socks5")
        assert result == {"kind": "socks5", "raw": "socks5://77.110.126.90:1080", "source": "gfpcom_socks5"}

    def test_base64_subscription_decoded(self):
        from ip_proxy_layer0_consumer import parse_line
        import base64
        inner = "vless://uuid@host:443?type=ws\ntrojan://pass@host:443\n"
        encoded = base64.b64encode(inner.encode()).decode()
        # base64 lines should be decoded by the consumer, not by parse_line
        # this is tested at a higher level in test_fetch_and_parse_source

    def test_fetch_and_parse_source_local_file(self, tmp_path):
        from ip_proxy_layer0_consumer import fetch_and_parse_source
        # Write a temp file simulating gfpcom vless output
        content = "vless://uuid1@host1:443?type=ws\nvless://uuid2@host2:443?type=ws\n# comment\n\n"
        f = tmp_path / "vless.txt"
        f.write_text(content, encoding="utf-8")
        results = fetch_and_parse_source(
            source_name="test_vless",
            url=f.as_uri(),
            source_type="share_url",
            kind=None,
        )
        assert len(results) == 2
        assert results[0]["kind"] == "vless"
        assert results[0]["source"] == "test_vless"
        assert results[1]["kind"] == "vless"

    def test_fetch_and_parse_source_ip_port_file(self, tmp_path):
        from ip_proxy_layer0_consumer import fetch_and_parse_source
        content = "147.161.246.38:10920\n27.147.221.23:4545\n# skip\n\n"
        f = tmp_path / "http.txt"
        f.write_text(content, encoding="utf-8")
        results = fetch_and_parse_source(
            source_name="databay_http",
            url=f.as_uri(),
            source_type="ip_port",
            kind="http",
        )
        assert len(results) == 2
        assert results[0] == {"kind": "http", "raw": "http://147.161.246.38:10920", "source": "databay_http"}
        assert results[1] == {"kind": "http", "raw": "http://27.147.221.23:4545", "source": "databay_http"}

    def test_fetch_and_parse_source_base64_sub(self, tmp_path):
        from ip_proxy_layer0_consumer import fetch_and_parse_source
        import base64
        inner = "vless://uuid1@host1:443?type=ws\nss://cfg@host2:443\n"
        encoded = base64.b64encode(inner.encode()).decode()
        f = tmp_path / "sub.txt"
        f.write_text(encoded, encoding="utf-8")
        results = fetch_and_parse_source(
            source_name="pawdroid_sub",
            url=f.as_uri(),
            source_type="base64_subscription",
            kind=None,
        )
        assert len(results) == 2
        assert results[0]["kind"] == "vless"
        assert results[1]["kind"] == "ss"


# --- End-to-end classify tests ---

class TestClassifyEndToEnd:
    """Verify classify produces L1/L2/L3 from mixed candidates."""

    def test_classify_separates_L1_L2_L3(self, tmp_path):
        from ip_proxy_classify_clean import main as classify_main
        # Build a mixed candidate list
        candidates = [
            _make_item(raw="clean-1", exit_ip="1.1.1.1", country="US", dirty=[]),  # L1 clean
            _make_item(raw="risky-1", exit_ip="2.2.2.2", country="DE", dirty=["is_datacenter"]),  # L2 risky
            _make_item(raw="L3-1", exit_ip="3.3.3.3", country="JP", dirty=["is_datacenter", "is_suspicious"]),  # L3
            _make_item(raw="dead-1", exit_ip="4.4.4.4", success=False),  # dirty
            _make_item(raw="cn-1", exit_ip="5.5.5.5", country="CN", dirty=["is_datacenter"]),  # dirty
            _make_item(raw="tor-1", exit_ip="6.6.6.6", country="US", dirty=["is_tor"]),  # dirty
        ]
        input_json = tmp_path / "candidates.json"
        input_json.write_text(json.dumps(candidates, ensure_ascii=False), encoding="utf-8")
        import os
        os.environ["IP_PROXY_RUNTIME_DIR"] = str(tmp_path / "runtime")
        (tmp_path / "runtime" / "resin").mkdir(parents=True, exist_ok=True)
        import ip_proxy_classify_clean as classify_mod
        classify_mod.IP_RUNTIME_DIR = tmp_path / "runtime"
        classify_mod.CHECK_JSON = input_json
        classify_mod.RESIN_DIR = tmp_path / "runtime" / "resin"
        # Run classify
        classify_main.__wrapped__ = classify_main  # no argparse in test
        # We'll call the core logic directly to avoid argparse
        from ip_proxy_classify_clean import registration_tier, bucket
        tiers = [registration_tier(c) for c in candidates]
        assert tiers == ["clean", "risky", "dirty_alive_noncn", "dirty", "dirty", "dirty"]


# --- Integration tests with local project data ---

@pytest.mark.skipif(not _LAYER0_DIR.exists(), reason="layer0_sources directory not present")
class TestLocalProjectIntegration:
    """Verify consumer correctly parses actual files from cloned projects."""

    def test_databay_http_file(self):
        from ip_proxy_layer0_consumer import fetch_and_parse_source
        fpath = _LAYER0_DIR / "databay-free-proxy-list" / "http.txt"
        if not fpath.exists():
            pytest.skip("databay http.txt not found")
        results = fetch_and_parse_source("databay_http", fpath.as_uri(), "ip_port", kind="http")
        assert len(results) > 100, f"Expected many HTTP proxies, got {len(results)}"
        for item in results:
            assert item["kind"] == "http"
            assert item["raw"].startswith("http://")
            assert item["source"] == "databay_http"

    def test_databay_socks5_file(self):
        from ip_proxy_layer0_consumer import fetch_and_parse_source
        fpath = _LAYER0_DIR / "databay-free-proxy-list" / "socks5.txt"
        if not fpath.exists():
            pytest.skip("databay socks5.txt not found")
        results = fetch_and_parse_source("databay_socks5", fpath.as_uri(), "ip_port", kind="socks5")
        assert len(results) > 100, f"Expected many SOCKS5 proxies, got {len(results)}"
        for item in results:
            assert item["kind"] == "socks5"
            assert item["raw"].startswith("socks5://")

    def test_v2rayroot_vless_file(self):
        from ip_proxy_layer0_consumer import fetch_and_parse_source
        fpath = _LAYER0_DIR / "V2RayConfig" / "Config" / "vless.txt"
        if not fpath.exists():
            pytest.skip("V2RayConfig vless.txt not found")
        results = fetch_and_parse_source("v2rayroot_vless", fpath.as_uri(), "share_url", kind=None)
        assert len(results) > 50, f"Expected many VLESS nodes, got {len(results)}"
        for item in results:
            assert item["kind"] == "vless"
            assert item["raw"].startswith("vless://")

    def test_v2rayroot_trojan_file(self):
        from ip_proxy_layer0_consumer import fetch_and_parse_source
        fpath = _LAYER0_DIR / "V2RayConfig" / "Config" / "trojan.txt"
        if not fpath.exists():
            pytest.skip("V2RayConfig trojan.txt not found")
        results = fetch_and_parse_source("v2rayroot_trojan", fpath.as_uri(), "share_url", kind=None)
        assert len(results) > 10, f"Expected trojan nodes, got {len(results)}"
        for item in results:
            assert item["kind"] == "trojan"

    def test_v2rayroot_ss_file(self):
        from ip_proxy_layer0_consumer import fetch_and_parse_source
        fpath = _LAYER0_DIR / "V2RayConfig" / "Config" / "shadowsocks.txt"
        if not fpath.exists():
            pytest.skip("V2RayConfig shadowsocks.txt not found")
        results = fetch_and_parse_source("v2rayroot_ss", fpath.as_uri(), "share_url", kind=None)
        assert len(results) > 50, f"Expected many SS nodes, got {len(results)}"
        for item in results:
            assert item["kind"] == "ss"

    def test_consumer_all_local_sources(self):
        """Verify consuming all local files produces meaningful totals."""
        from ip_proxy_layer0_consumer import consume_all_sources, write_outputs
        import tempfile
        # Build a custom config pointing to local files
        config = {
            "http_sources": [
                {"name": "databay_http", "url": (_LAYER0_DIR / "databay-free-proxy-list" / "http.txt").as_uri(), "kind": "http", "type": "ip_port"},
            ],
            "socks_sources": [
                {"name": "databay_socks5", "url": (_LAYER0_DIR / "databay-free-proxy-list" / "socks5.txt").as_uri(), "kind": "socks5", "type": "ip_port"},
            ],
            "subscription_sources": [
                {"name": "v2rayroot_vless", "url": (_LAYER0_DIR / "V2RayConfig" / "Config" / "vless.txt").as_uri(), "type": "share_url"},
                {"name": "v2rayroot_ss", "url": (_LAYER0_DIR / "V2RayConfig" / "Config" / "shadowsocks.txt").as_uri(), "type": "share_url"},
            ],
            "api_sources": [],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump(config, tf)
            config_path = Path(tf.name)
        try:
            http_socks, subscriptions = consume_all_sources(config_path)
            total = len(http_socks) + len(subscriptions)
            assert total > 500, f"Expected 500+ total candidates from local files, got {total}"
            assert len(http_socks) > 100, f"Expected 100+ HTTP/SOCKS from databay, got {len(http_socks)}"
            assert len(subscriptions) > 100, f"Expected 100+ subscriptions from V2RayConfig, got {len(subscriptions)}"
        finally:
            config_path.unlink(missing_ok=True)
