#!/usr/bin/env python3
"""Pre-push sanity checks for the IPPOXY registrar/IP patch set."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "main.py",
    "outlook_flow_stats.py",
    "challenge_providers/router.py",
    "challenge_providers/stubs.py",
    "tools/ip_proxy_registrar_feedback.py",
    "tools/ippoxy_sandbox_batch_verify.py",
    "tools/ip_proxy_pool_refresh.py",
    "tools/ip_proxy_refill_once.sh",
    "docker-compose.yml",
]


def run(cmd: list[str], *, optional: bool = False) -> dict:
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    item = {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "optional": optional,
        "ok": proc.returncode == 0 or optional,
    }
    if proc.returncode != 0 and not optional:
        raise RuntimeError(json.dumps(item, ensure_ascii=False, indent=2))
    return item


def check_required_files() -> dict:
    missing = [name for name in REQUIRED_FILES if not (ROOT / name).exists()]
    if missing:
        raise RuntimeError(f"missing required files: {missing}")
    return {"ok": True, "required_files": REQUIRED_FILES}


def check_imports() -> dict:
    sys.path.insert(0, str(ROOT))
    modules = [
        "main",
        "outlook_flow_stats",
        "tools.ip_proxy_registrar_feedback",
        "tools.ippoxy_sandbox_batch_verify",
        "tools.ip_proxy_pool_refresh",
        "challenge_providers.router",
    ]
    imported = []
    for module in modules:
        importlib.import_module(module)
        imported.append(module)
    return {"ok": True, "imported": imported}


def check_router_without_optional_providers() -> dict:
    src = ROOT / "challenge_providers"
    tmp_parent = Path(tempfile.mkdtemp(prefix="ippoxy_router_minimal_"))
    tmp_pkg = tmp_parent / "challenge_providers"
    tmp_pkg.mkdir(parents=True)
    for name in ["__init__.py", "base.py", "classifier.py", "microsoft_press.py", "router.py", "stubs.py"]:
        shutil.copy2(src / name, tmp_pkg / name)

    script = (
        "import sys;"
        f"sys.path.insert(0, {str(tmp_parent)!r});"
        "from challenge_providers.router import ChallengeRouter;"
        "r=ChallengeRouter();"
        "assert r.providers['cdp_browser'].name == 'cdp_browser';"
        "assert r.providers['altcha_pow'].name == 'altcha_pow';"
        "assert r.providers['self_hosted_solver'].name == 'self_hosted_solver';"
        "print('ok')"
    )
    return run([sys.executable, "-c", script])


def check_fake_flow_summary() -> dict:
    script = r"""
import io
import json
import os
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

root = Path(tempfile.mkdtemp(prefix="ippoxy_flow_stats_"))
os.environ["OUTLOOK_IP_FAILURE_RETRIES"] = "0"
os.environ["OUTLOOK_IP_RETRY_DELAY_MIN_S"] = "0"
os.environ["OUTLOOK_IP_RETRY_DELAY_MAX_S"] = "0"
os.environ["OUTLOOK_TASK_SUBMIT_DELAY_MIN_S"] = "0"
os.environ["OUTLOOK_TASK_SUBMIT_DELAY_MAX_S"] = "0"
os.environ["OUTLOOK_PROXY_PRECHECK"] = "0"
os.environ["OUTLOOK_FLOW_STATS_DIR"] = str(root)

import main

class FakeController:
    email_suffix = "@hotmail.com"
    enable_oauth2 = False
    oauth2_client_id = "client"
    def __init__(self):
        self.calls = 0
        self.failure = {"reason": "", "details": {}}
    def begin_flow_proxy_identity(self):
        pass
    def reset_flow_failure(self):
        self.failure = {"reason": "", "details": {}}
    def get_thread_page(self):
        return object()
    def thread_proxy_url(self):
        return "http://IPPOXY_RES.release-check:daytona@127.0.0.1:2260"
    def outlook_register(self, page, email, password):
        self.calls += 1
        self.failure = {"reason": "entry_failed", "details": {"stage": "entry"}}
        return False
    def get_flow_failure(self):
        return self.failure
    def clean_up(self, page=None, type="all_browser"):
        pass

buf = io.StringIO()
with redirect_stdout(buf):
    main.run_concurrent_flows(FakeController(), concurrent_flows=1, max_tasks=1)
line = [line for line in buf.getvalue().splitlines() if line.startswith("[ResultDetail] - ")][-1]
summary = json.loads(line.split(" - ", 1)[1])
assert summary["failure_reasons"]["entry_failed"] == 1, summary
print("ok")
"""
    return run([sys.executable, "-c", script])


def check_flow_throttle_zero_delay() -> dict:
    script = r"""
import io
import json
import os
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

root = Path(tempfile.mkdtemp(prefix="ippoxy_flow_throttle_"))
os.environ["OUTLOOK_IP_FAILURE_RETRIES"] = "1"
os.environ["OUTLOOK_IP_RETRY_DELAY_MIN_S"] = "0"
os.environ["OUTLOOK_IP_RETRY_DELAY_MAX_S"] = "0"
os.environ["OUTLOOK_TASK_SUBMIT_DELAY_MIN_S"] = "0"
os.environ["OUTLOOK_TASK_SUBMIT_DELAY_MAX_S"] = "0"
os.environ["OUTLOOK_PROXY_PRECHECK"] = "0"
os.environ["OUTLOOK_FLOW_STATS_DIR"] = str(root)

import main

class FakeController:
    email_suffix = "@hotmail.com"
    enable_oauth2 = False
    oauth2_client_id = "client"
    def __init__(self):
        self.failure = {"reason": "", "details": {}}
    def begin_flow_proxy_identity(self):
        pass
    def reset_flow_failure(self):
        self.failure = {"reason": "", "details": {}}
    def get_thread_page(self):
        return object()
    def thread_proxy_url(self):
        return "http://IPPOXY_RES.throttle-check:daytona@127.0.0.1:2260"
    def outlook_register(self, page, email, password):
        self.failure = {"reason": "entry_failed", "details": {"stage": "entry"}}
        return False
    def get_flow_failure(self):
        return self.failure
    def clean_up(self, page=None, type="all_browser"):
        pass

buf = io.StringIO()
with redirect_stdout(buf):
    main.run_concurrent_flows(FakeController(), concurrent_flows=1, max_tasks=2)
line = [line for line in buf.getvalue().splitlines() if line.startswith("[ResultDetail] - ")][-1]
summary = json.loads(line.split(" - ", 1)[1])
assert summary["registration_attempts"] == 4, summary
assert summary["failure_reasons"]["entry_failed"] == 4, summary
print("ok")
"""
    return run([sys.executable, "-c", script])


def check_bad_exit_precheck_skip() -> dict:
    script = r"""
import io
import json
import os
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

root = Path(tempfile.mkdtemp(prefix="ippoxy_bad_exit_skip_"))
captures = root / "captures"
captures.mkdir(parents=True)
(captures / "ip_registrar_feedback_latest.json").write_text(
    json.dumps({"bad_exit_ips": ["10.0.0.9"]}),
    encoding="utf-8",
)
os.environ["IPPOXY_ROOT"] = str(root)
os.environ["OUTLOOK_IP_FAILURE_RETRIES"] = "0"
os.environ["OUTLOOK_IP_RETRY_DELAY_MIN_S"] = "0"
os.environ["OUTLOOK_IP_RETRY_DELAY_MAX_S"] = "0"
os.environ["OUTLOOK_TASK_SUBMIT_DELAY_MIN_S"] = "0"
os.environ["OUTLOOK_TASK_SUBMIT_DELAY_MAX_S"] = "0"
os.environ["OUTLOOK_PROXY_PRECHECK_SKIP_BAD"] = "1"
os.environ["OUTLOOK_PROXY_PRECHECK"] = "0"
os.environ["OUTLOOK_FLOW_STATS_DIR"] = str(captures)

import main

main.probe_exit_ip = lambda proxy_url: {"enabled": True, "ok": True, "ip": "10.0.0.9"}

class FakeController:
    email_suffix = "@hotmail.com"
    enable_oauth2 = False
    oauth2_client_id = "client"
    def __init__(self):
        self.register_called = 0
        self.failure = {"reason": "", "details": {}}
    def begin_flow_proxy_identity(self):
        pass
    def reset_flow_failure(self):
        self.failure = {"reason": "", "details": {}}
    def set_flow_failure(self, reason, details=None):
        self.failure = {"reason": reason, "details": details or {}}
    def get_thread_page(self):
        raise AssertionError("browser should not start for known bad exit")
    def thread_proxy_url(self):
        return "http://IPPOXY_RES.bad-exit-check:daytona@127.0.0.1:2260"
    def outlook_register(self, page, email, password):
        self.register_called += 1
        return True
    def get_flow_failure(self):
        return self.failure
    def clean_up(self, page=None, type="all_browser"):
        pass

controller = FakeController()
buf = io.StringIO()
with redirect_stdout(buf):
    result = main.process_single_flow(controller)
assert result is False
assert controller.register_called == 0
events = [
    json.loads(line)
    for line in (captures / "outlook_flow_events.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
attempts = [item for item in events if item["event"] == "registration_attempt_result"]
assert attempts[0]["failure_reason"] == "proxy_precheck_bad_exit", attempts
assert attempts[0]["result_stage"] == "proxy_precheck_skip", attempts
print("ok")
"""
    return run([sys.executable, "-c", script])


def check_registrar_feedback_diagnostics() -> dict:
    script = r"""
from tools.ip_proxy_registrar_feedback import build_feedback

events = [
    {
        "event": "registration_attempt_result",
        "failure_reason": "entry_failed",
        "success": False,
        "proxy_identity": "IPPOXY_RES.known",
        "exit_probe": {"enabled": True, "ok": True, "ip": "10.0.0.1"},
    },
    {
        "event": "registration_attempt_result",
        "failure_reason": "rate_or_abnormal_after_profile",
        "success": False,
        "proxy_identity": "IPPOXY_RES.known",
        "exit_probe": {"enabled": True, "ok": True, "ip": "10.0.0.1"},
    },
    {
        "event": "registration_attempt_result",
        "failure_reason": "entry_failed",
        "success": False,
        "proxy_identity": "IPPOXY_RES.noexit",
        "exit_probe": {"enabled": True, "ok": False, "error": "all_precheck_urls_failed"},
    },
    {
        "event": "registration_attempt_result",
        "failure_reason": "challenge_failed_microsoft_press",
        "success": False,
        "proxy_identity": "IPPOXY_RES.challenge",
        "exit_probe": {"enabled": True, "ok": True, "ip": "10.0.0.2"},
    },
]
feedback = build_feedback(events, 2, {"entry_failed", "rate_or_abnormal_after_profile"})
assert feedback["bad_exit_ips"] == ["10.0.0.1"], feedback
assert feedback["unknown_exit_retryable_attempts"] == 1, feedback
assert feedback["unknown_exit_retryable_details"]["IPPOXY_RES.noexit"]["retryable_failures"] == 1, feedback
assert feedback["precheck_errors"]["all_precheck_urls_failed"] == 1, feedback
assert "10.0.0.2" not in feedback["bad_exit_ips"], feedback
print("ok")
"""
    return run([sys.executable, "-c", script])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-docker", action="store_true")
    args = parser.parse_args()

    checks = {
        "required_files": check_required_files(),
        "py_compile": run(
            [
                sys.executable,
                "-m",
                "py_compile",
                "main.py",
                "outlook_flow_stats.py",
                "challenge_providers/router.py",
                "challenge_providers/stubs.py",
                "tools/ip_proxy_registrar_feedback.py",
                "tools/ippoxy_sandbox_batch_verify.py",
                "tools/ip_proxy_pool_refresh.py",
            ]
        ),
        "imports": check_imports(),
        "router_without_optional_providers": check_router_without_optional_providers(),
        "fake_flow_summary": check_fake_flow_summary(),
        "flow_throttle_zero_delay": check_flow_throttle_zero_delay(),
        "bad_exit_precheck_skip": check_bad_exit_precheck_skip(),
        "registrar_feedback_diagnostics": check_registrar_feedback_diagnostics(),
    }
    if args.skip_docker or shutil.which("docker") is None:
        checks["docker_compose_config"] = {"ok": True, "skipped": True}
    else:
        checks["docker_compose_config"] = run(["docker", "compose", "config", "--quiet"])

    print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
