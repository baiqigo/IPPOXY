import hashlib
import json
import os
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import requests


_WRITE_LOCK = threading.Lock()


def _captures_dir():
    path = Path(os.environ.get("OUTLOOK_FLOW_STATS_DIR", Path(__file__).resolve().parent / "captures"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _events_path():
    return Path(os.environ.get("OUTLOOK_FLOW_EVENTS_FILE", _captures_dir() / "outlook_flow_events.jsonl"))


def _summary_path():
    return Path(os.environ.get("OUTLOOK_FLOW_SUMMARY_FILE", _captures_dir() / "outlook_flow_stats_latest.json"))


def _hash_email(email):
    value = (email or "").strip().lower()
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _redact_proxy_url(proxy_url):
    if not proxy_url:
        return ""
    try:
        parsed = urlparse(proxy_url)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        if parsed.username or parsed.password:
            username = parsed.username or ""
            auth = username if not parsed.password else f"{username}:***"
            netloc = f"{auth}@{netloc}"
        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    except Exception:
        return "<redacted-proxy>"


def proxy_identity(proxy_url):
    if not proxy_url:
        return ""
    try:
        return urlparse(proxy_url).username or ""
    except Exception:
        return ""


def proxy_platform(identity):
    if not identity:
        return ""
    return identity.split(".", 1)[0]


def proxy_probe_enabled():
    raw = os.environ.get("OUTLOOK_PROXY_PRECHECK", "0").strip().lower()
    return raw in ("1", "true", "yes", "on")


def probe_exit_ip(proxy_url):
    if not proxy_probe_enabled():
        return {"enabled": False, "ok": False}
    if not proxy_url:
        return {"enabled": True, "ok": False, "error": "no_proxy_url"}

    url = os.environ.get("OUTLOOK_PROXY_PRECHECK_URL", "https://api.ipify.org").strip()
    timeout = float(os.environ.get("OUTLOOK_PROXY_PRECHECK_TIMEOUT", "12"))
    started = time.time()
    try:
        response = requests.get(
            url,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=timeout,
        )
        response.raise_for_status()
        body = response.text.strip()
        ip = ""
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                ip = str(parsed.get("ip") or parsed.get("origin") or "").strip()
        except Exception:
            ip = body[:128]
        return {
            "enabled": True,
            "ok": True,
            "url": url,
            "ip": ip,
            "status": response.status_code,
            "latency_ms": int((time.time() - started) * 1000),
        }
    except Exception as exc:
        return {
            "enabled": True,
            "ok": False,
            "url": url,
            "error": repr(exc),
            "latency_ms": int((time.time() - started) * 1000),
        }


def attempt_id(attempt_index):
    return f"{int(time.time() * 1000)}-{threading.get_ident() % 100000}-{attempt_index}"


def build_attempt_event(
    *,
    event,
    attempt_id_value,
    attempt_index,
    total_attempts,
    full_email,
    proxy_url,
    exit_probe,
    success,
    failure,
    result_stage,
):
    identity = proxy_identity(proxy_url)
    return {
        "ts": int(time.time()),
        "event": event,
        "attempt_id": attempt_id_value,
        "attempt_index": attempt_index,
        "total_attempts": total_attempts,
        "email_hash": _hash_email(full_email),
        "email_suffix": "@" + full_email.rsplit("@", 1)[-1] if "@" in full_email else "",
        "proxy_identity": identity,
        "proxy_platform": proxy_platform(identity),
        "proxy_url": _redact_proxy_url(proxy_url),
        "exit_probe": exit_probe or {"enabled": False, "ok": False},
        "success": bool(success),
        "result_stage": result_stage,
        "failure_reason": (failure or {}).get("reason", ""),
        "failure_details": (failure or {}).get("details", {}),
    }


def append_event(event):
    events_path = _events_path()
    summary_path = _summary_path()
    with _WRITE_LOCK:
        events_path.parent.mkdir(parents=True, exist_ok=True)
        with events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        summary = summarize_events(events_path)
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def _load_events(path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def summarize_events(path=None, since_ts=None):
    rows = _load_events(Path(path) if path else _events_path())
    if since_ts is not None:
        rows = [row for row in rows if int(row.get("ts") or 0) >= int(since_ts)]
    attempts = [row for row in rows if row.get("event") == "registration_attempt_result"]
    flows = [row for row in rows if row.get("event") == "flow_result"]

    by_identity = defaultdict(Counter)
    by_exit_ip = defaultdict(Counter)
    by_reason = Counter()
    for row in attempts:
        reason = row.get("failure_reason") or ("success" if row.get("success") else "unknown")
        identity = row.get("proxy_identity") or "unknown"
        exit_ip = ((row.get("exit_probe") or {}).get("ip")) or "unknown"
        by_identity[identity][reason] += 1
        by_exit_ip[exit_ip][reason] += 1
        by_reason[reason] += 1

    return {
        "ts": int(time.time()),
        "events": len(rows),
        "registration_attempts": len(attempts),
        "flows": len(flows),
        "success_attempts": sum(1 for row in attempts if row.get("success")),
        "failure_reasons": dict(by_reason),
        "by_identity": {key: dict(value) for key, value in sorted(by_identity.items())},
        "by_exit_ip": {key: dict(value) for key, value in sorted(by_exit_ip.items())},
    }


def compact_summary(summary, top=8):
    def top_counts(mapping):
        ranked = sorted(
            mapping.items(),
            key=lambda item: sum(item[1].values()) if isinstance(item[1], dict) else 0,
            reverse=True,
        )
        return {key: value for key, value in ranked[:top]}

    return {
        "registration_attempts": summary.get("registration_attempts", 0),
        "flows": summary.get("flows", 0),
        "success_attempts": summary.get("success_attempts", 0),
        "failure_reasons": summary.get("failure_reasons", {}),
        "top_identity_failures": top_counts(summary.get("by_identity", {})),
        "top_exit_ip_failures": top_counts(summary.get("by_exit_ip", {})),
    }


if __name__ == "__main__":
    print(json.dumps(summarize_events(), ensure_ascii=False, indent=2, default=str))
