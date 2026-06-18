#!/usr/bin/env python3
"""Prepare a bounded SSTP/OpenGW-to-SOCKS converter proof.

Default behavior is safe: print or write a masked launch plan only. The tool
refuses to run Docker unless both --allow-run and --acknowledge-long-running
are present.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IP_RUNTIME_DIR = Path(os.environ.get("IP_PROXY_RUNTIME_DIR", ROOT / ".runtime/ip-proxy"))
DEFAULT_ARTIFACT_BASE = IP_RUNTIME_DIR / "sstp_probe"


def parse_sstp_candidate(raw: str) -> dict:
    parsed = urllib.parse.urlparse(str(raw or "").strip())
    if parsed.scheme.lower() != "sstp" or not parsed.hostname:
        raise ValueError("candidate must be an sstp:// URL with a host")
    port = int(parsed.port or 443)
    if port <= 0 or port > 65535:
        raise ValueError("candidate port must be 1-65535")
    username = urllib.parse.unquote(parsed.username or "vpn")
    password = urllib.parse.unquote(parsed.password or "vpn")
    host = parsed.hostname.lower()
    return {
        "raw": f"sstp://{urllib.parse.quote(username, safe='')}:{urllib.parse.quote(password, safe='')}@{host}:{port}",
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "server": f"{host}:{port}",
    }


def mask_candidate(candidate: dict) -> str:
    user = urllib.parse.quote(str(candidate.get("username") or "vpn"), safe="")
    host = str(candidate["host"])
    port = int(candidate["port"])
    return f"sstp://{user}:***@{host}:{port}"


def safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-") or "sstp"


def build_probe_plan(
    *,
    candidate: dict,
    run_id: str,
    local_port: int,
    duration_seconds: int,
    artifact_dir: Path,
) -> dict:
    if local_port <= 0 or local_port > 65535:
        raise ValueError("local_port must be 1-65535")
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")

    container_name = f"ippoxy-sstp-probe-{safe_name(run_id)}"
    artifact_path = str(artifact_dir)
    docker_parts = [
        "docker run --rm",
        f"--name {container_name}",
        "--device /dev/ppp",
        "--cap-add NET_ADMIN",
        "--cap-add NET_RAW",
        f"-p 127.0.0.1:{local_port}:1080",
        f"-e SSTP_SERVER={candidate['server']}",
        "-e SSTP_USER=<redacted>",
        "-e SSTP_PASSWORD=<redacted>",
        f"-e PROBE_DURATION_SECONDS={duration_seconds}",
        f"-v {artifact_path}:/work",
        "debian:trixie-slim",
        "/work/entrypoint.sh",
    ]
    return {
        "run_id": run_id,
        "candidate": {
            "raw_masked": mask_candidate(candidate),
            "host": candidate["host"],
            "port": candidate["port"],
            "username_redacted": True,
            "password_redacted": True,
        },
        "container_name": container_name,
        "image": "debian:trixie-slim",
        "artifact_dir": artifact_path,
        "entrypoint": str(artifact_dir / "entrypoint.sh"),
        "ports": {"host": f"127.0.0.1:{local_port}", "container": "0.0.0.0:1080"},
        "duration_seconds": duration_seconds,
        "docker_command_display": " ".join(docker_parts),
        "logs": [
            f"docker logs {container_name}",
            str(artifact_dir / "trace.txt"),
            str(artifact_dir / "probe.log"),
        ],
        "impact": [
            "pulls/runs a temporary Debian container",
            "uses /dev/ppp and NET_ADMIN inside the container",
            f"binds only 127.0.0.1:{local_port} on the host",
            "does not rewrite host Xray/Resin runtime files",
        ],
        "stop_method": f"docker rm -f {container_name}",
        "verification": f"curl --socks5-hostname 127.0.0.1:{local_port} https://www.cloudflare.com/cdn-cgi/trace",
    }


def entrypoint_script() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[sstp-probe] %s\\n' "$*" | tee -a /work/probe.log
}

cleanup() {
  pkill sstpc >/dev/null 2>&1 || true
  pkill microsocks >/dev/null 2>&1 || true
}
trap cleanup EXIT

: "${SSTP_SERVER:?SSTP_SERVER is required}"
: "${SSTP_USER:?SSTP_USER is required}"
: "${SSTP_PASSWORD:?SSTP_PASSWORD is required}"
: "${PROBE_DURATION_SECONDS:=60}"

export DEBIAN_FRONTEND=noninteractive
log "installing packages"
apt-get update >>/work/probe.log 2>&1
apt-get install -y --no-install-recommends \\
  ca-certificates curl iproute2 microsocks ppp procps sstp-client \\
  >>/work/probe.log 2>&1

log "starting sstpc"
SSTP_IPPARAM="ippoxy-${SSTP_SERVER//[^a-zA-Z0-9]/-}"
sstpc --log-stderr --log-level 4 --cert-warn --tls-ext --save-server-route --ipparam "$SSTP_IPPARAM" \\
  --user "$SSTP_USER" \\
  --password "$SSTP_PASSWORD" \\
  "$SSTP_SERVER" \\
  noauth defaultroute usepeerdns \\
  require-mschap-v2 require-mppe refuse-eap refuse-pap refuse-chap refuse-mschap \\
  nobsdcomp nodeflate \\
  >>/work/probe.log 2>&1 &

for _ in $(seq 1 35); do
  if ip link show ppp0 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

ip addr show ppp0 >>/work/probe.log 2>&1 || {
  log "ppp0 did not appear"
  exit 20
}

log "starting microsocks"
microsocks -i 0.0.0.0 -p 1080 >>/work/probe.log 2>&1 &
sleep 2

log "running trace through local socks"
curl -fsS --max-time 30 --socks5-hostname 127.0.0.1:1080 \\
  https://www.cloudflare.com/cdn-cgi/trace \\
  | tee /work/trace.txt

log "holding probe for ${PROBE_DURATION_SECONDS}s"
sleep "$PROBE_DURATION_SECONDS"
log "probe complete"
"""


def launch_example(plan: dict) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail

# This is a masked example. Prefer running:
#   python tools/ip_proxy_sstp_converter_probe.py --candidate <sstp-url> --local-port <port> --run --allow-run --acknowledge-long-running

{plan["docker_command_display"]}
"""


def write_probe_artifacts(plan: dict, artifact_dir: Path) -> dict:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    entrypoint = artifact_dir / "entrypoint.sh"
    launch = artifact_dir / "launch.example.sh"
    plan_path = artifact_dir / "plan.json"
    entrypoint.write_text(entrypoint_script(), encoding="utf-8")
    entrypoint.chmod(0o755)
    launch.write_text(launch_example(plan), encoding="utf-8")
    launch.chmod(0o755)
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "entrypoint": str(entrypoint),
        "launch_example": str(launch),
        "plan": str(plan_path),
    }


def actual_docker_command(plan: dict, candidate: dict) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        str(plan["container_name"]),
        "--device",
        "/dev/ppp",
        "--cap-add",
        "NET_ADMIN",
        "--cap-add",
        "NET_RAW",
        "-p",
        f"{plan['ports']['host']}:1080",
        "-e",
        f"SSTP_SERVER={candidate['server']}",
        "-e",
        f"SSTP_USER={candidate['username']}",
        "-e",
        f"SSTP_PASSWORD={candidate['password']}",
        "-e",
        f"PROBE_DURATION_SECONDS={plan['duration_seconds']}",
        "-v",
        f"{plan['artifact_dir']}:/work",
        str(plan["image"]),
        "/work/entrypoint.sh",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare or run a bounded SSTP converter probe.")
    parser.add_argument("--candidate", required=True, help="sstp:// URL to test")
    parser.add_argument("--run-id", default=time.strftime("sstp_probe_%Y%m%d_%H%M%S"))
    parser.add_argument("--local-port", type=int, required=True)
    parser.add_argument("--duration-seconds", type=int, default=60)
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--write-artifacts", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--allow-run", action="store_true")
    parser.add_argument("--acknowledge-long-running", action="store_true")
    args = parser.parse_args()

    candidate = parse_sstp_candidate(args.candidate)
    artifact_dir = args.artifact_dir or (DEFAULT_ARTIFACT_BASE / safe_name(args.run_id))
    plan = build_probe_plan(
        candidate=candidate,
        run_id=args.run_id,
        local_port=args.local_port,
        duration_seconds=args.duration_seconds,
        artifact_dir=artifact_dir,
    )

    if args.run and not (args.allow_run and args.acknowledge_long_running):
        print(
            json.dumps(
                {
                    "status": "refused",
                    "reason": "run_requires_explicit_ack",
                    **plan,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2

    if args.write_artifacts or args.run:
        plan["artifacts"] = write_probe_artifacts(plan, artifact_dir)

    if not args.run:
        print(json.dumps({"status": "planned", **plan}, ensure_ascii=False, indent=2))
        return 0

    command = actual_docker_command(plan, candidate)
    result = subprocess.run(command, text=True)
    print(json.dumps({"status": "completed", "returncode": result.returncode, **plan}, ensure_ascii=False, indent=2))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
