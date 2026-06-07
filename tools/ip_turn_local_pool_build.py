#!/usr/bin/env python3
"""Build local TURN/Xray pool artifacts for IPPOXY.

The input is the clean TURN checker output created by
tools/ip_proxy_candidate_harvest.py. This script does not start any proxy
process; it only creates reproducible mapping files for the sandbox runtime.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK_JSON = ROOT / "docs/ip-proxy/research/runtime/proxy_candidate_check_20260608.json"
RESIN_DIR = ROOT / "docs/ip-proxy/resin"
RUNTIME_DIR = ROOT / "docs/ip-proxy/research/runtime"

DEFAULT_WORKER_HOST = "ip-proxy-turn-poc.khowk1isgv.workers.dev"
DEFAULT_UUID = "2523c510-9ff0-415b-9582-93949bfae7e3"
DEFAULT_APPEND_PORT = 19092

EXISTING_POC = [
    {
        "raw": "turn://104.184.105.172:3478",
        "local_port": 19080,
        "tag": "ippoxy-res-us-att-lubbock",
        "exit_ip": "104.184.105.172",
        "country": "US",
        "city": "Lubbock",
        "company_type": "isp",
        "asn_type": "isp",
        "company": "AT&T Enterprises, LLC",
        "responseTime": 272,
    },
    {
        "raw": "turn://24.130.161.222:3478",
        "local_port": 19081,
        "tag": "ippoxy-res-us-comcast-lafayette",
        "exit_ip": "24.130.161.222",
        "country": "US",
        "company_type": "isp",
        "asn_type": "isp",
        "company": "Comcast Cable Communications Holdings, Inc",
        "responseTime": 613,
    },
    {
        "raw": "turn://195.80.16.8:3478",
        "local_port": 19082,
        "tag": "ippoxy-static-gb-bnw-london",
        "exit_ip": "195.80.16.8",
        "country": "GB",
        "company_type": "business",
        "asn_type": "isp",
        "company": "BNW TECHNOLOGY LTD",
        "responseTime": 1019,
    },
    {
        "raw": "turn://77.200.201.104:3478",
        "local_port": 19083,
        "tag": "ippoxy-res-fr-sfr-rhone",
        "exit_ip": "77.200.201.104",
        "country": "FR",
        "company_type": "isp",
        "asn_type": "isp",
        "company": "Dynamic pools",
        "responseTime": 1125,
    },
    {
        "raw": "turn://46.26.142.252:3478",
        "local_port": 19084,
        "tag": "ippoxy-res-es-vodafone-sabadell",
        "exit_ip": "46.26.142.252",
        "country": "ES",
        "company_type": "isp",
        "asn_type": "isp",
        "company": "VODAFONE ESPANA, S.A.U",
        "responseTime": 1170,
    },
    {
        "raw": "turn://188.111.122.196:3478",
        "local_port": 19085,
        "tag": "ippoxy-res-de-vodafone-heilbronn",
        "exit_ip": "188.111.122.196",
        "country": "DE",
        "company_type": "isp",
        "asn_type": "isp",
        "company": "Vodafone GmbH",
        "responseTime": 1240,
    },
    {
        "raw": "turn://212.201.138.103:3478",
        "local_port": 19086,
        "tag": "ippoxy-static-de-bielefeld-dfn",
        "exit_ip": "212.201.138.103",
        "country": "DE",
        "company_type": "education",
        "asn_type": "isp",
        "company": "Hochschule Bielefeld",
        "responseTime": 1284,
    },
    {
        "raw": "turn://77.20.212.9:3478",
        "local_port": 19087,
        "tag": "ippoxy-res-de-vodafone-hamburg",
        "exit_ip": "77.20.212.9",
        "country": "DE",
        "company_type": "isp",
        "asn_type": "isp",
        "company": "Vodafone Kabel Deutschland GmbH",
        "responseTime": 1257,
    },
    {
        "raw": "turn://145.100.106.100:3478",
        "local_port": 19088,
        "tag": "ippoxy-static-nl-surf-amsterdam",
        "exit_ip": "145.100.106.100",
        "country": "NL",
        "company_type": "education",
        "asn_type": "isp",
        "company": "Universiteit van Amsterdam",
        "responseTime": 1555,
    },
    {
        "raw": "turn://212.66.105.99:3478",
        "local_port": 19089,
        "tag": "ippoxy-res-it-panservice-rome",
        "exit_ip": "212.66.105.99",
        "country": "IT",
        "company_type": "isp",
        "asn_type": "isp",
        "company": "Panservice",
        "responseTime": 1386,
    },
    {
        "raw": "turn://133.28.25.48:3478",
        "local_port": 19090,
        "tag": "ippoxy-static-jp-kanazawa",
        "exit_ip": "133.28.25.48",
        "country": "JP",
        "company_type": "education",
        "asn_type": "education",
        "company": "Kanazawa University",
        "responseTime": 1569,
    },
    {
        "raw": "turn://test:test123@81.93.119.16:3478",
        "local_port": 19091,
        "tag": "ippoxy-static-de-prosieben",
        "exit_ip": "81.93.119.1",
        "country": "DE",
        "company_type": "business",
        "asn_type": "business",
        "company": "ProSiebenSat.1 Tech Solutions GmbH",
        "responseTime": 1161,
    },
]


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
    raw = item["raw"]
    bucket = classify(item)
    country = slug(item.get("country") or "xx")
    company = slug(item.get("company") or item.get("exit_ip") or "node")
    city = slug(item.get("city") or "")
    host = slug((item.get("exit_ip") or raw).replace(".", "-"))
    middle = "-".join(part for part in [country, company[:28], city[:18], host] if part)
    return f"ippoxy-{bucket}-{middle}"


def load_clean_turns(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    clean = [item for item in data if item.get("kind") == "turn" and item.get("clean")]
    clean.sort(key=lambda item: item.get("responseTime") or 999999)
    return clean


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
        port = row["local_port"]
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


def write_outputs(rows: list[dict], uuid: str, worker_host: str) -> None:
    RESIN_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

    local_lines = [f"socks5://127.0.0.1:{row['local_port']}#{row['tag']}" for row in rows]
    delta_lines = [
        f"socks5://127.0.0.1:{row['local_port']}#{row['tag']}"
        for row in rows
        if row["local_port"] >= 19092
    ]
    vless_lines = [f"{row['vless']}#{row['tag']}" for row in rows]

    total = len(rows)
    delta = sum(1 for row in rows if row["local_port"] >= 19092)
    (RESIN_DIR / f"turn_xray_pool_{total}.local.txt").write_text("\n".join(local_lines) + "\n", encoding="utf-8")
    (RESIN_DIR / f"turn_xray_pool_delta_{delta}.local.txt").write_text(
        "\n".join(delta_lines) + "\n", encoding="utf-8"
    )
    (RESIN_DIR / f"turn_vless_pool_{total}.txt").write_text("\n".join(vless_lines) + "\n", encoding="utf-8")
    (RUNTIME_DIR / "turn_xray_pool_20260608.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (RESIN_DIR / f"xray_turn_pool_{total}.generated.json").write_text(
        json.dumps(xray_config(rows, uuid, worker_host), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    lines = [
        "# TURN Local Port Expansion 2026-06-08",
        "",
        f"- Worker host: `{worker_host}`",
        f"- UUID: `{uuid}`",
        f"- Local TURN ports mapped: {total}",
        "- Source: 12 existing POC ports plus current clean TURN candidates not already local.",
        f"- Existing POC ports preserved: 12 (`19080-19091`)",
        f"- New ports to add: {delta} (`19092-{19091 + delta}`)",
        "",
        "## Port Map",
        "",
        "| Port | Tag | TURN | Exit IP | Country | Type | RT ms |",
        "|---:|---|---|---|---|---|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['local_port']} | `{row['tag']}` | `{row['turn']}` | "
            f"`{row.get('exit_ip') or ''}` | {row.get('country') or ''} | "
            f"{row.get('company_type') or ''}/{row.get('asn_type') or ''} | "
            f"{row.get('responseTime') or ''} |"
        )
    lines.extend(
        [
            "",
            "## Outputs",
            "",
            f"- `docs/ip-proxy/resin/turn_xray_pool_{total}.local.txt`: Resin local subscription for all mapped TURN ports.",
            f"- `docs/ip-proxy/resin/turn_xray_pool_delta_{delta}.local.txt`: only the ports not yet present in the 12-port POC.",
            f"- `docs/ip-proxy/resin/turn_vless_pool_{total}.txt`: VLESS share links carrying TURN paths.",
            f"- `docs/ip-proxy/resin/xray_turn_pool_{total}.generated.json`: generated Xray client config draft.",
            "- `docs/ip-proxy/research/runtime/turn_xray_pool_20260608.json`: structured mapping data.",
            "",
            "## Next Runtime Step",
            "",
            "Start or containerize the generated Xray client in the sandbox only after confirming the long-running process details. Verification target: each `127.0.0.1:<port>` returns the matching `Exit IP` through `curl -x socks5h://127.0.0.1:<port> https://api.ipify.org`.",
            "",
        ]
    )
    (RESIN_DIR / "turn_local_port_expansion_20260608.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=CHECK_JSON)
    parser.add_argument("--worker-host", default=DEFAULT_WORKER_HOST)
    parser.add_argument("--uuid", default=DEFAULT_UUID)
    parser.add_argument("--append-port", type=int, default=DEFAULT_APPEND_PORT)
    args = parser.parse_args()

    turns = load_clean_turns(args.input)
    rows = []
    seen_raw = set()
    for item in EXISTING_POC:
        row = dict(item)
        row["turn"] = item["raw"]
        row["source"] = "existing_poc"
        row["kind"] = "turn"
        row["clean"] = True
        row["success"] = True
        row["pool_class"] = classify(item)
        row["worker_path"] = f"/{item['raw']}?ed=2560"
        row["vless"] = vless_url(args.uuid, args.worker_host, item["raw"])
        rows.append(row)
        seen_raw.add(item["raw"])
    next_port = args.append_port
    for item in turns:
        if item["raw"] in seen_raw:
            continue
        row = dict(item)
        row["turn"] = item["raw"]
        row["local_port"] = next_port
        row["tag"] = make_tag(item)
        row["pool_class"] = classify(item)
        row["worker_path"] = f"/{item['raw']}?ed=2560"
        row["vless"] = vless_url(args.uuid, args.worker_host, item["raw"])
        rows.append(row)
        seen_raw.add(item["raw"])
        next_port += 1
    write_outputs(rows, args.uuid, args.worker_host)
    delta = sum(1 for row in rows if row["local_port"] >= args.append_port)
    print(
        json.dumps(
            {"turn": len(rows), "existing": len(EXISTING_POC), "delta": delta, "ports": [rows[0]["local_port"], rows[-1]["local_port"]]},
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
