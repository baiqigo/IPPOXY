#!/usr/bin/env python3
"""Refresh the sandbox runtime Xray/Resin pool from latest clean IP candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import time
import urllib.parse
from pathlib import Path


ROOT = Path(os.environ.get("IPPOXY_ROOT", Path(__file__).resolve().parents[1]))
RUNTIME = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
RESIN_DIR = ROOT / "docs/ip-proxy/resin"
DOC_RUNTIME_DIR = ROOT / "docs/ip-proxy/research/runtime"
RUNTIME_RESIN_DIR = RUNTIME / "resin"

DEFAULT_INPUT = RUNTIME_RESIN_DIR / "clean_candidates_classified.latest.json"
DEFAULT_BASELINE = DOC_RUNTIME_DIR / "turn_xray_pool_20260608.json"
DEFAULT_VERIFY = ROOT / "captures/ip_runtime_verify_latest.json"
DEFAULT_REGISTRAR_FEEDBACK = ROOT / "captures/ip_registrar_feedback_latest.json"
DEFAULT_SOURCE_QUALITY = RUNTIME / "research/proxy_source_quality_latest.json"
DEFAULT_WORKER_HOST = os.environ.get("IP_PROXY_TURN_WORKER_HOST", "cdn.baiqi.xyz")
DEFAULT_UUID = "2523c510-9ff0-415b-9582-93949bfae7e3"
DEFAULT_MAX_FALLBACK_CANDIDATE_AGE_HOURS = float(os.environ.get("IP_PROXY_MAX_FALLBACK_CANDIDATE_AGE_HOURS", "48"))


def slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value or "unknown"


def classify(item: dict) -> str:
    company_type = (item.get("company_type") or "").lower()
    asn_type = (item.get("asn_type") or "").lower()
    if company_type == "isp" and asn_type == "isp":
        return "res"
    if "isp" in {company_type, asn_type}:
        return "isp"
    return "static"


def pool_priority(item: dict) -> int:
    company_type = (item.get("company_type") or "").lower()
    asn_type = (item.get("asn_type") or "").lower()
    type_text = f"{company_type} {asn_type}"
    if company_type == "isp" and asn_type == "isp":
        return 0
    if "isp" in {company_type, asn_type}:
        return 1
    if any(word in type_text for word in ["hosting", "datacenter", "data center", "cdn", "cloud"]):
        return 3
    return 2


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
    return json.loads(path.read_text(encoding="utf-8-sig"))


def safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def safe_float(value: object) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def file_sha(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bytes_sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


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


def file_age_hours(path: Path, now: float | None = None) -> float | None:
    if not path.exists():
        return None
    now = time.time() if now is None else now
    return round(max(0.0, now - path.stat().st_mtime) / 3600.0, 2)


def candidate_file_audit(
    path: Path,
    candidates: list[dict],
    *,
    role: str,
    min_clean: int,
    max_age_hours: float,
    allow_stale: bool,
    now: float | None = None,
) -> dict:
    age_hours = file_age_hours(path, now)
    enough_clean = len(candidates) >= min_clean
    fresh_enough = (
        allow_stale
        or max_age_hours <= 0
        or age_hours is None
        or age_hours <= max_age_hours
    )
    reason = ""
    if not enough_clean:
        reason = "not_enough_clean_candidates"
    elif not fresh_enough:
        reason = "stale_candidate_file"
    return {
        "path": str(path),
        "role": role,
        "clean_turn_candidates": len(candidates),
        "min_clean": min_clean,
        "age_hours": age_hours,
        "max_age_hours": max_age_hours,
        "allow_stale": allow_stale,
        "accepted": bool(enough_clean and fresh_enough),
        "reason": reason,
    }


def load_source_quality(path: Path) -> tuple[dict[str, dict], dict]:
    data = read_json(path, {})
    if not isinstance(data, dict):
        return {}, {"path": str(path), "loaded": False, "reason": "invalid_json_shape"}
    by_source = data.get("by_source")
    if not isinstance(by_source, dict):
        return {}, {"path": str(path), "loaded": False, "reason": "missing_by_source"}
    quality = {str(source): item for source, item in by_source.items() if isinstance(item, dict)}
    return quality, {"path": str(path), "loaded": bool(quality), "source_count": len(quality)}


def source_quality_sort_key(item: dict, source_quality: dict[str, dict] | None) -> tuple:
    quality = (source_quality or {}).get(str(item.get("source") or "unknown"), {})
    return (
        pool_priority(item),
        -safe_int(quality.get("clean")),
        -safe_float(quality.get("clean_rate_pct")),
        -safe_int(quality.get("success")),
        -safe_float(quality.get("success_rate_pct")),
        item.get("responseTime") or 999999,
        item.get("raw") or "",
    )


def prioritize_candidates(candidates: list[dict], source_quality: dict[str, dict] | None) -> list[dict]:
    if not source_quality:
        return candidates
    return sorted(candidates, key=lambda item: source_quality_sort_key(item, source_quality))


def resolve_candidate_input(
    path: Path,
    min_clean: int,
    source_quality: dict[str, dict] | None = None,
    max_age_hours: float = DEFAULT_MAX_FALLBACK_CANDIDATE_AGE_HOURS,
    allow_stale: bool = False,
) -> tuple[Path, list[dict], str | None, list[dict]]:
    audit: list[dict] = []
    candidates = prioritize_candidates(clean_turn_candidates(path), source_quality)
    requested_audit = candidate_file_audit(
        path,
        candidates,
        role="requested_input",
        min_clean=min_clean,
        max_age_hours=max_age_hours,
        allow_stale=allow_stale,
    )
    audit.append(requested_audit)
    if requested_audit["accepted"]:
        return path, candidates, None, audit

    fallback_files = sorted(
        [*RUNTIME_RESIN_DIR.glob("clean_candidates_classified*.json"), *RESIN_DIR.glob("clean_candidates_classified*.json")],
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for fallback in fallback_files:
        if fallback == path:
            continue
        fallback_candidates = prioritize_candidates(clean_turn_candidates(fallback), source_quality)
        item_audit = candidate_file_audit(
            fallback,
            fallback_candidates,
            role="fallback",
            min_clean=min_clean,
            max_age_hours=max_age_hours,
            allow_stale=allow_stale,
        )
        audit.append(item_audit)
        if item_audit["accepted"]:
            if requested_audit["reason"] == "stale_candidate_file":
                reason = f"{path} had {len(candidates)} clean TURN candidates but was stale ({requested_audit['age_hours']}h)"
            else:
                reason = f"{path} only had {len(candidates)} clean TURN candidates"
            return fallback, fallback_candidates, reason, audit
    return path, [] if requested_audit["reason"] == "stale_candidate_file" else candidates, requested_audit["reason"] or None, audit


def failed_exit_ips(verify_path: Path) -> set[str]:
    data = read_json(verify_path, {})
    if not isinstance(data, dict):
        return set()
    failed = set()
    for item in data.get("port_results", []):
        if isinstance(item, dict) and not item.get("ok") and item.get("expected"):
            failed.add(str(item["expected"]))
    return failed


def registrar_failed_exit_ips(feedback_path: Path) -> set[str]:
    data = read_json(feedback_path, {})
    if not isinstance(data, dict):
        return set()
    failed: set[str] = set()
    for field in ("bad_exit_ips", "avoid_exit_ips"):
        values = data.get(field, [])
        if not isinstance(values, list):
            continue
        failed.update(str(item).strip() for item in values if str(item).strip())
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
    row["selection_source"] = source
    row["upstream_source"] = item.get("source")
    row["pool_class"] = classify(row)
    row["pool_priority"] = pool_priority(row)
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
    min_new_candidates: int = 0,
) -> tuple[list[dict], dict]:
    by_exit: dict[str, dict] = {}
    by_raw: set[str] = set()
    selected: list[dict] = []

    def add(item: dict, source: str, allow_bad: bool = False) -> bool:
        raw = item.get("turn") or item.get("raw")
        exit_ip = item.get("exit_ip")
        if not raw or not exit_ip or raw in by_raw or exit_ip in by_exit:
            return False
        if not allow_bad and str(exit_ip) in bad_exit_ips:
            return False
        if len(selected) >= limit:
            return False
        selected.append(normalize_row(item, 19080 + len(selected), worker_host, uuid, source))
        by_raw.add(str(raw))
        by_exit[str(exit_ip)] = item
        return True

    min_new_candidates = max(0, min(int(min_new_candidates or 0), limit))
    baseline_good = [item for item in baseline if str(item.get("exit_ip")) not in bad_exit_ips]
    baseline_priority = [item for item in baseline_good if pool_priority(item) <= 1]
    baseline_fallback = [item for item in baseline_good if pool_priority(item) > 1]

    for item in baseline_priority:
        if len(selected) >= max(0, limit - min_new_candidates):
            break
        add(item, "baseline")

    added_from_candidates = 0
    for item in candidates:
        if add(item, "clean_latest"):
            added_from_candidates += 1
        if len(selected) >= limit:
            break

    retained_reserved_baseline = 0
    if len(selected) < limit:
        for item in baseline_priority:
            if add(item, "baseline_reserved"):
                retained_reserved_baseline += 1
            if len(selected) >= limit:
                break

    retained_low_priority_baseline = 0
    if len(selected) < limit:
        for item in baseline_fallback:
            if add(item, "baseline_low_priority"):
                retained_low_priority_baseline += 1
            if len(selected) >= limit:
                break

    if len(selected) < limit:
        for item in baseline:
            add(item, "baseline_retain_failed", allow_bad=True)
            if len(selected) >= limit:
                break

    retained_bad_exit_ips = sorted(
        {
            str(row.get("exit_ip"))
            for row in selected
            if row.get("source") == "baseline_retain_failed" and str(row.get("exit_ip")) in bad_exit_ips
        }
    )
    retained_bad_exit_details = {
        exit_ip: {
            "source": "baseline_retain_failed",
            "reason": "not_enough_replacement_candidates",
        }
        for exit_ip in retained_bad_exit_ips
    }

    return selected, {
        "bad_exit_ips": sorted(bad_exit_ips),
        "added_from_candidates": added_from_candidates,
        "retained_priority_baseline": sum(1 for row in selected if row.get("source") == "baseline"),
        "retained_reserved_baseline": retained_reserved_baseline,
        "retained_low_priority_baseline": retained_low_priority_baseline,
        "retained_bad_exit_ips": retained_bad_exit_ips,
        "retained_bad_exit_details": retained_bad_exit_details,
        "selected": len(selected),
        "limit": limit,
    }


def write_runtime(rows: list[dict], worker_host: str, uuid: str, write_docs: bool, dry_run: bool) -> dict:
    runtime_conf = RUNTIME / "conf"
    runtime_resin = RUNTIME / "resin"
    if not dry_run:
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
    payloads = {
        "mapping": json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
        "xray": json.dumps(xray_config(rows, uuid, worker_host), ensure_ascii=False, indent=2) + "\n",
        "subscription": "\n".join(local_lines) + "\n",
        "subscription_alias": "\n".join(local_lines) + "\n",
        "vless": "\n".join(vless_lines) + "\n",
    }
    if not dry_run:
        for name, text in payloads.items():
            atomic_write_text(files[name], text)

    if write_docs:
        if dry_run:
            raise SystemExit("--dry-run cannot be combined with --write-docs")
        shutil.copy2(files["mapping"], DOC_RUNTIME_DIR / "turn_xray_pool_20260608.json")
        shutil.copy2(files["xray"], RESIN_DIR / "xray_turn_pool_25.generated.json")
        shutil.copy2(files["subscription"], RESIN_DIR / "turn_xray_pool_25.local.txt")
        shutil.copy2(files["subscription_alias"], RESIN_DIR / "turn_xray_pool.local.txt")
        shutil.copy2(files["vless"], RESIN_DIR / "turn_vless_pool_25.txt")

    if dry_run:
        after = {name: bytes_sha(payloads[name].encode("utf-8")) for name in files}
    else:
        after = {name: file_sha(path) for name, path in files.items()}
    changed = [name for name in files if before[name] != after[name]]
    return {"files": {name: str(path) for name, path in files.items()}, "changed_files": changed, "dry_run": dry_run}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--baseline", type=Path, default=RUNTIME / "turn_xray_pool_20260608.json")
    parser.add_argument("--verify", type=Path, default=DEFAULT_VERIFY)
    parser.add_argument("--registrar-feedback", type=Path, default=DEFAULT_REGISTRAR_FEEDBACK)
    parser.add_argument("--source-quality", type=Path, default=DEFAULT_SOURCE_QUALITY)
    parser.add_argument("--worker-host", default=DEFAULT_WORKER_HOST)
    parser.add_argument("--uuid", default=DEFAULT_UUID)
    parser.add_argument("--limit", type=int, default=int(os.environ.get("IP_PROXY_POOL_SIZE", "25")))
    parser.add_argument("--min-clean", type=int, default=int(os.environ.get("IP_PROXY_MIN_CLEAN", "12")))
    parser.add_argument("--min-new-candidates", type=int, default=int(os.environ.get("IP_PROXY_MIN_NEW_CANDIDATES", "8")))
    parser.add_argument(
        "--max-fallback-candidate-age-hours",
        type=float,
        default=DEFAULT_MAX_FALLBACK_CANDIDATE_AGE_HOURS,
        help="maximum age for requested/fallback clean candidate files; 0 disables the age check",
    )
    parser.add_argument(
        "--allow-stale-fallback-candidates",
        action="store_true",
        default=os.environ.get("IP_PROXY_ALLOW_STALE_FALLBACK_CANDIDATES", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="allow stale clean candidate files to be used when replacing the runtime pool",
    )
    parser.add_argument("--write-docs", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="compute the refresh result without modifying runtime files")
    parser.add_argument(
        "--allow-retain-bad-exits",
        action="store_true",
        default=os.environ.get("IP_PROXY_ALLOW_RETAIN_BAD_EXITS", "0").strip().lower() in ("1", "true", "yes", "on"),
        help="allow runtime apply even if the selected pool still contains known bad exits",
    )
    args = parser.parse_args()

    baseline_path = args.baseline if args.baseline.exists() else DEFAULT_BASELINE
    baseline = read_json(baseline_path, [])
    if not isinstance(baseline, list):
        raise SystemExit(f"invalid baseline mapping: {baseline_path}")
    source_quality, source_quality_meta = load_source_quality(args.source_quality)
    input_path, candidates, fallback_reason, candidate_input_audit = resolve_candidate_input(
        args.input,
        args.min_clean,
        source_quality,
        args.max_fallback_candidate_age_hours,
        args.allow_stale_fallback_candidates,
    )
    if len(candidates) < args.min_clean:
        print(
            json.dumps(
                {
                    "status": "skipped",
                    "reason": "not_enough_clean_candidates",
                    "input": str(args.input),
                    "clean": len(candidates),
                    "min_clean": args.min_clean,
                    "fallback_reason": fallback_reason,
                    "candidate_input_audit": candidate_input_audit,
                    "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
                    "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
                },
                ensure_ascii=False,
            )
        )
        return 0 if args.dry_run else 2

    verify_failed = failed_exit_ips(args.verify)
    registrar_failed = registrar_failed_exit_ips(args.registrar_feedback)
    rows, meta = select_rows(
        baseline,
        candidates,
        verify_failed | registrar_failed,
        args.limit,
        args.worker_host,
        args.uuid,
        args.min_new_candidates,
    )
    if len(rows) < args.limit:
        raise SystemExit(f"only selected {len(rows)} rows, need {args.limit}")
    if meta.get("retained_bad_exit_ips") and not args.dry_run and not args.allow_retain_bad_exits:
        result = {
            "status": "blocked",
            "reason": "retained_bad_exits_requires_more_clean_candidates",
            "changed": False,
            "baseline": str(baseline_path),
            "input": str(input_path),
            "requested_input": str(args.input),
            "verify": str(args.verify),
            "registrar_feedback": str(args.registrar_feedback),
            "source_quality": source_quality_meta,
            "candidate_input_audit": candidate_input_audit,
            "verify_bad_exit_ips": sorted(verify_failed),
            "registrar_bad_exit_ips": sorted(registrar_failed),
            "fallback_reason": fallback_reason,
            "min_new_candidates": args.min_new_candidates,
            "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
            "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
            "dry_run": args.dry_run,
            **meta,
        }
        (ROOT / "captures").mkdir(parents=True, exist_ok=True)
        (ROOT / "captures/ip_pool_refresh_latest.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(result, ensure_ascii=False))
        return 2
    written = write_runtime(rows, args.worker_host, args.uuid, args.write_docs, args.dry_run)
    result = {
        "status": "ok",
        "changed": bool(written["changed_files"]),
        "baseline": str(baseline_path),
        "input": str(input_path),
        "requested_input": str(args.input),
        "verify": str(args.verify),
        "registrar_feedback": str(args.registrar_feedback),
        "source_quality": source_quality_meta,
        "candidate_input_audit": candidate_input_audit,
        "verify_bad_exit_ips": sorted(verify_failed),
        "registrar_bad_exit_ips": sorted(registrar_failed),
        "fallback_reason": fallback_reason,
        "min_new_candidates": args.min_new_candidates,
        "max_fallback_candidate_age_hours": args.max_fallback_candidate_age_hours,
        "allow_stale_fallback_candidates": args.allow_stale_fallback_candidates,
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
