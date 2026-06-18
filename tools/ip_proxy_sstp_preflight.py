#!/usr/bin/env python3
"""Short TCP/TLS preflight for SSTP/OpenGW candidates.

This tool does not start SSTP, Docker, PPP, or proxy processes. It only checks
whether a candidate that looks reachable on TCP can complete a TLS handshake
from the current runtime environment.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import time
from collections import Counter
from pathlib import Path
from typing import Callable

from ip_proxy_sstp_converter_probe import mask_candidate, parse_sstp_candidate, safe_name


Dialer = Callable[[tuple[str, int], float], object]
TlsWrapper = Callable[[object, str], object]


def load_candidates(path: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("candidates") or []
    else:
        rows = []

    out: list[str] = []
    for row in rows:
        if isinstance(row, str):
            out.append(row)
        elif isinstance(row, dict) and row.get("raw"):
            out.append(str(row["raw"]))
    return out


def default_tls_wrapper(sock: object, host: str) -> object:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=host)


def _close_quietly(obj: object | None) -> None:
    if obj is None:
        return
    close = getattr(obj, "close", None)
    if callable(close):
        close()


def preflight_candidate(
    raw: str,
    *,
    timeout: float,
    dialer: Dialer = socket.create_connection,
    tls_wrapper: TlsWrapper = default_tls_wrapper,
) -> dict:
    candidate = parse_sstp_candidate(raw)
    row = {
        "candidate": mask_candidate(candidate),
        "host": candidate["host"],
        "port": candidate["port"],
        "tcp_ok": False,
        "tls_ok": False,
        "status": "unknown",
        "error_stage": "",
        "error": "",
    }
    sock: object | None = None
    tls_sock: object | None = None
    try:
        sock = dialer((candidate["host"], int(candidate["port"])), timeout)
        row["tcp_ok"] = True
    except Exception as exc:  # noqa: BLE001 - diagnostic tool should serialize errors
        row.update({"status": "tcp_error", "error_stage": "tcp", "error": f"{type(exc).__name__}: {exc}"})
        return row

    try:
        tls_sock = tls_wrapper(sock, candidate["host"])
        row["tls_ok"] = True
        row["status"] = "tls_ok"
        cipher = getattr(tls_sock, "cipher", lambda: None)()
        version = getattr(tls_sock, "version", lambda: None)()
        if cipher:
            row["tls_cipher"] = cipher[0] if isinstance(cipher, tuple) else str(cipher)
        if version:
            row["tls_version"] = str(version)
        return row
    except Exception as exc:  # noqa: BLE001 - diagnostic tool should serialize errors
        row.update({"status": "tls_error", "error_stage": "tls", "error": f"{type(exc).__name__}: {exc}"})
        return row
    finally:
        _close_quietly(tls_sock)
        if tls_sock is not sock:
            _close_quietly(sock)


def build_report(*, run_id: str, raw_candidates: list[str], timeout: float, limit: int) -> dict:
    selected = raw_candidates[:limit] if limit > 0 else raw_candidates
    rows = [preflight_candidate(raw, timeout=timeout) for raw in selected]
    counts = Counter(str(row.get("status") or "unknown") for row in rows)
    return {
        "run_id": run_id,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(rows),
        "counts": dict(sorted(counts.items())),
        "results": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run short TCP/TLS preflight for SSTP candidates.")
    parser.add_argument("--candidate", action="append", default=[], help="sstp:// candidate; can be repeated")
    parser.add_argument("--input", type=Path, help="candidate manifest JSON with a candidates array")
    parser.add_argument("--run-id", default=time.strftime("sstp_preflight_%Y%m%d_%H%M%S"))
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    raw_candidates: list[str] = []
    if args.input:
        raw_candidates.extend(load_candidates(args.input))
    raw_candidates.extend(args.candidate)
    if not raw_candidates:
        raise SystemExit("at least one --candidate or --input is required")

    report = build_report(
        run_id=safe_name(args.run_id),
        raw_candidates=raw_candidates,
        timeout=args.timeout,
        limit=args.limit,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
