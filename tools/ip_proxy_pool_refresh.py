#!/usr/bin/env python3
"""Refresh the sandbox runtime Xray/Resin pool from latest clean IP candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import urllib.parse
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RESIN_DIR = ROOT / "docs/ip-proxy/resin"
DOC_RUNTIME_DIR = ROOT / "docs/ip-proxy/research/runtime"

DEFAULT_INPUT = RESIN_DIR / "clean_candidates_classified.latest.json"
DEFAULT_BASELINE = DOC_RUNTIME_DIR / "turn_xray_pool_20260608.json"
DEFAULT_VERIFY = ROOT / "captures/ip_runtime_verify_latest.json"
DEFAULT_WORKER_HOST = "ip-proxy-turn-poc.khowk1isgv.workers.dev"
DEFAULT_UUID = "2523c510-9ff0-415b-9582-93949bfae7e3"


def slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value or "unknown"


def classify(item: dict) -> str:
    company_type = (item.get("company_type") or "").lower()
    asn_type = (item.get("asn_type") or "").lower()
    if company_type == "isp" and asn_type == "isp":
        return "res"
    return "static"


def make_tag(item: dict) -> str:
    bucket = classify(item)
    country = slug(item.get("country") or "xx")
    company = slug(item.get("company") or item.get("exit_ip") or "node")
    city = slug(item.get("city") or "")
    host = slug((item.get("exit_ip") or item.get("raw") or "node").replace(".", "-"))
    middle = "-".join(part for part in [country, company[:28], city[:18], host] if part)
    return f"ippoxy-{bucket}-{middle}"


def vless_url(uuid: str, worker_host: str, turn_url: str) -> str:
    path = f"/{turn_url}?ed=2560"
    query = {
        "type": "ws",
        "encryption": "none",
        "host": worker_host,
        "path": path,
        "security": "tls",
        "sni": worker_host,
        "packetEncoding": "xudp",
    }
    return f"vless://{uuid}@{worker_host}:443/?" + urllib.parse.urlencode(query, safe="/:")


def xray_config(rows: list[dict], uuid: str, worker_host: str) -> dict:
    inbounds = []
    outbounds = []
    rules = []
    for row in rows:
        port = int(row["local_port"])
        inbound_tag = f"in-{port}"
        outbound_tag = f"out-{port}"
        turn_path = f"/{row['turn']}?ed=2560"
        inbounds.append(
            {
                "tag": inbound_tag,
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            }
        )
        outbounds.append(
            {
                "tag": outbound_tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": worker_host,
                            "port": 443,
                            "users": [{"id": uuid, "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {"serverName": worker_host},
                    "wsSettings": {"path": turn_path, "headers": {"Host": worker_host}},
                },
            }
        )
        rules.append({"type": "field", "inboundTag": [inbound_tag], "outboundTag": outbound_tag})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def file_sha(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_turn_candidates(path: Path) -> list[dict]:
    data = read_json(path, [])
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if item.get("kind") != "turn" or not item.get("clean") or not item.get("success"):
            continue
        if not item.get("raw") or not item.get("exit_ip"):
            continue
        out.append(dict(item))
    out.sort(key=lambda item: (item.get("responseTime") or 999999, item.get("raw") or ""))
    return out


def resolve_candidate_input(path: Path, min_clean: int) -> tuple[Path, list[dict], str | None]:
    candidates = clean_turn_candidates(path)
    if len(candidates) >= min_clean:
        return path, candidates, None

    fallback_files = sorted(
        RESIN_DIR.glob("clean_candidates_classified*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for fallback in fallback_files:
        if fallback == path:
            continue
        fallback_candidates = clean_turn_candidates(fallback)
        if len(fallback_candidates) >= min_clean:
            return fallback, fallback_candidates, f"{path} only had {len(candidates)} clean TURN candidates"
    return path, candidates, None


def failed_exit_ips(verify_path: Path) -> set[str]:
    data = read_json(verify_path, {})
    if not isinstance(data, dict):
        return set()
    failed = set()
    for item in data.get("port_results", []):
        if isinstance(item, dict) and not item.get("ok") and item.get("expected"):
            failed.add(str(item["expected"]))
    return failed


def normalize_row(item: dict, port: int, worker_host: str, uuid: str, source: str) -> dict:
    raw = item.get("turn") or item.get("raw")
    row = dict(item)
    row["raw"] = raw
    row["turn"] = raw
    row["local_port"] = port
    row["kind"] = "turn"
    row["clean"] = True
    row["success"] = True
    row["source"] = source
    row["pool_class"] = classify(row)
    row["tag"] = row.get("tag") or make_tag(row)
    row["worker_path"] = f"/{raw}?ed=2560"
    row["vless"] = vless_url(uuid, worker_host, raw)
    return row


def select_rows(
    baseline: list[dict],
    candidates: list[dict],
    bad_exit_ips: set[str],
    limit: int,
    worker_host: str,
    uuid: str,
) -> tuple[list[dict], dict]:
    by_exit: dict[str, dict] = {}
    by_raw: set[str] = set()
    selected: list[dict] = []

    def add(item: dict, source: str) -> bool:
        raw = item.get("turn") or item.get("raw")
        exit_ip = item.get("exit_ip")
        if not raw or not exit_ip or raw in by_raw or exit_ip in by_exit:
            return False
        if len(selected) >= limit:
            return False
        selected.append(normalize_row(item, 19080 + len(selected), worker_host, uuid, source))
        by_raw.add(str(raw))
        by_exit[str(exit_ip)] = item
        return True

    for item in baseline:
        if str(item.get("exit_ip")) not in bad_exit_ips:
            add(item, "baseline")

    added_from_candidates = 0
    for item in candidates:
        if add(item, "clean_latest"):
            added_from_candidates += 1
        if len(selected) >= limit:
            break

    if len(selected) < limit:
        for item in baseline:
            add(item, "baseline_retain_failed")
            if len(selected) >= limit:
                break

    return selected, {
        "bad_exit_ips": sorted(bad_exit_ips),
        "added_from_candidates": added_from_candidates,
        "selected": len(selected),
        "limit": limit,
    }


def write_runtime(rows: list[dict], worker_host: str, uuid: str, write_docs: bool) -> dict:
    runtime_conf = RUNTIME / "conf"
    runtime_resin = RUNTIME / "resin"
    runtime_conf.mkdir(parents=True, exist_ok=True)
    runtime_resin.mkdir(parents=True, exist_ok=True)
    RUNTIME.mkdir(parents=True, exist_ok=True)

    files = {
        "mapping": RUNTIME / "turn_xray_pool_20260608.json",
        "xray": runtime_conf / "xray_turn_pool_25.generated.json",
        "subscription": runtime_resin / "turn_xray_pool_25.local.txt",
        "subscription_alias": runtime_resin / "turn_xray_pool.local.txt",
        "vless": runtime_resin / "turn_vless_pool_25.txt",
    }
    before = {name: file_sha(path) for name, path in files.items()}

    local_lines = [f"socks5://127.0.0.1:{row['local_port']}#{row['tag']}" for row in rows]
    vless_lines = [f"{row['vless']}#{row['tag']}" for row in rows]
    files["mapping"].write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    files["xray"].write_text(
        json.dumps(xray_config(rows, uuid, worker_host), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    files["subscription"].write_text("\n".join(local_lines) + "\n", encoding="utf-8")
    files["subscription_alias"].write_text("\n".join(local_lines) + "\n", encoding="utf-8")
    files["vless"].write_text("\n".join(vless_lines) + "\n", encoding="utf-8")

    if write_docs:
        shutil.copy2(files["mapping"], DOC_RUNTIME_DIR / "turn_xray_pool_20260608.json")
        shutil.copy2(files["xray"], RESIN_DIR / "xray_turn_pool_25.generated.json")
        shutil.copy2(files["subscription"], RESIN_DIR / "turn_xray_pool_25.local.txt")
        shutil.copy2(files["subscription_alias"], RESIN_DIR / "turn_xray_pool.local.txt")
        shutil.copy2(files["vless"], RESIN_DIR / "turn_vless_pool_25.txt")

    after = {name: file_sha(path) for name, path in files.items()}
    changed = [name for name in files if before[name] != after[name]]
    return {"files": {name: str(path) for name, path in files.items()}, "changed_files": changed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--baseline", type=Path, default=RUNTIME / "turn_xray_pool_20260608.json")
    parser.add_argument("--verify", type=Path, default=DEFAULT_VERIFY)
    parser.add_argument("--worker-host", default=DEFAULT_WORKER_HOST)
    parser.add_argument("--uuid", default=DEFAULT_UUID)
    parser.add_argument("--limit", type=int, default=int(os.environ.get("IP_PROXY_POOL_SIZE", "25")))
    parser.add_argument("--min-clean", type=int, default=int(os.environ.get("IP_PROXY_MIN_CLEAN", "12")))
    parser.add_argument("--write-docs", action="store_true")
    args = parser.parse_args()

    baseline_path = args.baseline if args.baseline.exists() else DEFAULT_BASELINE
    baseline = read_json(baseline_path, [])
    if not isinstance(baseline, list):
        raise SystemExit(f"invalid baseline mapping: {baseline_path}")
    input_path, candidates, fallback_reason = resolve_candidate_input(args.input, args.min_clean)
    if len(candidates) < args.min_clean:
        print(
            json.dumps(
                {
                    "status": "skipped",
                    "reason": "not_enough_clean_candidates",
                    "input": str(args.input),
                    "clean": len(candidates),
                    "min_clean": args.min_clean,
                },
                ensure_ascii=False,
            )
        )
        return 0

    rows, meta = select_rows(
        baseline,
        candidates,
        failed_exit_ips(args.verify),
        args.limit,
        args.worker_host,
        args.uuid,
    )
    if len(rows) < args.limit:
        raise SystemExit(f"only selected {len(rows)} rows, need {args.limit}")
    written = write_runtime(rows, args.worker_host, args.uuid, args.write_docs)
    result = {
        "status": "ok",
        "changed": bool(written["changed_files"]),
        "baseline": str(baseline_path),
        "input": str(input_path),
        "requested_input": str(args.input),
        "fallback_reason": fallback_reason,
        **meta,
        **written,
    }
    (ROOT / "captures").mkdir(parents=True, exist_ok=True)
    (ROOT / "captures/ip_pool_refresh_latest.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
