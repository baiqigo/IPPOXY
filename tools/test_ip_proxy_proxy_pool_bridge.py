#!/usr/bin/env python3
"""Tests for bridging jhao104/proxy_pool fetchers into IPPOXY Layer0."""

from __future__ import annotations

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))


def write_fake_proxy_pool(root: Path) -> None:
    (root / "fetcher" / "sources").mkdir(parents=True)
    (root / "handler").mkdir()
    (root / "util").mkdir()
    (root / "fetcher" / "__init__.py").write_text("", encoding="utf-8")
    (root / "fetcher" / "sources" / "__init__.py").write_text("", encoding="utf-8")
    (root / "handler" / "__init__.py").write_text("", encoding="utf-8")
    (root / "util" / "__init__.py").write_text("", encoding="utf-8")
    (root / "setting.py").write_text("PROXY_FETCHER_EXCLUDE = ['excluded']\n", encoding="utf-8")
    (root / "fetcher" / "baseFetcher.py").write_text(
        """
class BaseFetcher(object):
    name = ""
    url = ""
    enabled = True
    def fetch(self):
        raise NotImplementedError
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (root / "fetcher" / "sources" / "fixture.py").write_text(
        """
from fetcher.baseFetcher import BaseFetcher

class FixtureFetcher(BaseFetcher):
    name = "fixture"
    url = "https://example.test/free"
    def fetch(self):
        yield "203.0.113.10:8080"
        yield "http://203.0.113.11:8081"
        yield "999.0.0.1:8080"
        yield "203.0.113.10:8080"

class ExcludedFetcher(BaseFetcher):
    name = "excluded"
    url = "https://example.test/excluded"
    def fetch(self):
        yield "198.51.100.1:8080"

class DisabledFetcher(BaseFetcher):
    name = "disabled"
    enabled = False
    def fetch(self):
        yield "198.51.100.2:8080"
""".strip()
        + "\n",
        encoding="utf-8",
    )


def test_proxy_pool_bridge_imports_project_fetchers_and_writes_layer0(tmp_path):
    from ip_proxy_proxy_pool_bridge import run_bridge

    repo = tmp_path / "proxy_pool"
    write_fake_proxy_pool(repo)

    manifest = run_bridge(
        repo=repo,
        output_dir=tmp_path / "out",
        run_id="fixture",
        dry_run=True,
        workers=1,
    )

    assert manifest["schema"] == "ippoxy_proxy_pool_bridge.v1"
    assert manifest["raw_count"] == 2
    assert manifest["fetchers_total"] == 1
    rows = json.loads(Path(manifest["raw_path"]).read_text(encoding="utf-8"))
    assert [row["raw"] for row in rows] == ["http://203.0.113.10:8080", "http://203.0.113.11:8081"]
    assert all(row["source_type"] == "proxy_pool_fetcher" for row in rows)
    assert rows[0]["trace"]["source_format"] == "jhao104_proxy_pool"
    assert not (tmp_path / "out" / "layer0_http_socks_pool_proxy_pool.latest.json").exists()


def test_proxy_pool_bridge_can_update_latest_when_not_dry_run(tmp_path):
    from ip_proxy_proxy_pool_bridge import run_bridge

    repo = tmp_path / "proxy_pool"
    write_fake_proxy_pool(repo)
    out = tmp_path / "out"

    manifest = run_bridge(
        repo=repo,
        output_dir=out,
        run_id="latest",
        dry_run=False,
        workers=1,
        include_sources={"fixture"},
    )

    assert manifest["raw_count"] == 2
    latest_rows = json.loads((out / "layer0_http_socks_pool_proxy_pool.latest.json").read_text(encoding="utf-8"))
    latest_manifest = json.loads((out / "proxy_pool_bridge_manifest.latest.json").read_text(encoding="utf-8"))
    assert len(latest_rows) == 2
    assert latest_manifest["run_id"] == "latest"
