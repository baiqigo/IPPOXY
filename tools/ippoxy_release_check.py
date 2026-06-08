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
    "tools/ip_proxy_source_quality_report.py",
    "tools/ip_proxy_candidate_harvest.py",
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
        "tools.ip_proxy_source_quality_report",
        "tools.ip_proxy_candidate_harvest",
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


def check_pool_refresh_retained_bad_guard() -> dict:
    script = r"""
from tools.ip_proxy_pool_refresh import select_rows

baseline = [
    {"raw": "turn://bad", "turn": "turn://bad", "exit_ip": "10.0.0.1", "kind": "turn", "clean": True, "success": True},
    {"raw": "turn://good", "turn": "turn://good", "exit_ip": "10.0.0.2", "kind": "turn", "clean": True, "success": True},
]
candidates = []
rows, meta = select_rows(
    baseline,
    candidates,
    {"10.0.0.1"},
    2,
    "example.invalid",
    "2523c510-9ff0-415b-9582-93949bfae7e3",
)
assert len(rows) == 2, rows
assert meta["retained_bad_exit_ips"] == ["10.0.0.1"], meta
assert rows[-1]["source"] == "baseline_retain_failed", rows
print("ok")
"""
    return run([sys.executable, "-c", script])


def check_source_quality_summary() -> dict:
    script = r"""
from tools.ip_proxy_source_quality_report import summarize_source_quality

rows = [
    {"source": "source_a", "kind": "turn", "success": True, "clean": True, "exit_ip": "10.0.0.1"},
    {"source": "source_a", "kind": "turn", "success": True, "clean": False, "exit_ip": "10.0.0.2", "dirty": ["is_proxy"]},
    {"source": "source_b", "kind": "socks5", "success": False, "clean": False, "error": "timeout"},
    {"source": "source_b", "kind": "turn", "success": False, "clean": False, "error": "timeout"},
    {"source": "source_b", "kind": "turn", "success": False, "clean": False, "error": "timeout"},
]
summary = summarize_source_quality(rows, cooldown_min_total=2, cooldown_max_clean_rate=1.0, cooldown_max_success_rate=25.0)
assert summary["total"] == 5, summary
assert summary["clean"] == 1, summary
assert summary["by_source"]["source_a"]["total"] == 2, summary
assert summary["by_source"]["source_a"]["clean"] == 1, summary
assert summary["by_source"]["source_a"]["dirty_reasons"]["is_proxy"] == 1, summary
assert summary["by_source"]["source_b"]["errors"]["timeout"] == 3, summary
assert summary["by_source"]["source_b"]["cooldown_recommended"] is True, summary
assert summary["cooldown_sources"]["source_b"]["reason"] == "no_clean_candidates", summary
assert summary["top_sources_by_clean"][0] == "source_a", summary
print("ok")
"""
    return run([sys.executable, "-c", script])


def check_batch_verifier_source_quality_report() -> dict:
    script = r"""
from tools.ippoxy_sandbox_batch_verify import compact_source_quality

report = {
    "total": 5,
    "success": 2,
    "clean": 1,
    "source_count": 2,
    "by_kind": {"turn": 4, "socks5": 1},
    "top_sources_by_clean": ["source_a", "source_b"],
    "cooldown_policy": {"min_total": 2},
    "cooldown_sources": {
        "source_b": {
            "reason": "no_clean_candidates",
            "total": 3,
            "success_rate_pct": 0.0,
            "clean_rate_pct": 0.0,
        }
    },
    "by_source": {
        "source_a": {
            "total": 2,
            "success": 2,
            "clean": 1,
            "success_rate_pct": 100.0,
            "clean_rate_pct": 50.0,
        },
        "source_b": {
            "total": 3,
            "success": 0,
            "clean": 0,
            "success_rate_pct": 0.0,
            "clean_rate_pct": 0.0,
            "cooldown_recommended": True,
            "cooldown_reason": "no_clean_candidates",
        },
    },
}
summary = compact_source_quality(report)
assert summary["total"] == 5, summary
assert summary["source_count"] == 2, summary
assert summary["by_kind"]["turn"] == 4, summary
assert summary["top_sources_by_clean"] == ["source_a", "source_b"], summary
assert summary["top_source_details"][1]["source"] == "source_b", summary
assert summary["top_source_details"][1]["cooldown_recommended"] is True, summary
assert summary["cooldown_source_count"] == 1, summary
assert summary["cooldown_sources"]["source_b"]["reason"] == "no_clean_candidates", summary
assert compact_source_quality([]) == {}, summary
print("ok")
"""
    return run([sys.executable, "-c", script])


def check_source_quality_pool_priority() -> dict:
    script = r"""
from tools.ip_proxy_pool_refresh import normalize_row, prioritize_candidates

candidates = [
    {"source": "weak_source", "kind": "turn", "success": True, "clean": True, "exit_ip": "10.0.0.1", "raw": "turn://weak", "responseTime": 1, "company_type": "ISP", "asn_type": "ISP"},
    {"source": "strong_source", "kind": "turn", "success": True, "clean": True, "exit_ip": "10.0.0.2", "raw": "turn://strong", "responseTime": 999, "company_type": "ISP", "asn_type": "ISP"},
    {"source": "hosting_source", "kind": "turn", "success": True, "clean": True, "exit_ip": "10.0.0.3", "raw": "turn://hosting", "responseTime": 0, "company_type": "hosting", "asn_type": "hosting"},
]
source_quality = {
    "weak_source": {"total": 200, "success": 20, "clean": 1, "success_rate_pct": 10.0, "clean_rate_pct": 0.5},
    "strong_source": {"total": 200, "success": 180, "clean": 100, "success_rate_pct": 90.0, "clean_rate_pct": 50.0},
    "hosting_source": {"total": 200, "success": 200, "clean": 200, "success_rate_pct": 100.0, "clean_rate_pct": 100.0},
}
prioritized = prioritize_candidates(candidates, source_quality)
assert prioritized[0]["source"] == "strong_source", prioritized
assert prioritized[-1]["source"] == "hosting_source", prioritized
assert prioritize_candidates(candidates, {})[0]["source"] == "weak_source", candidates
malformed = {"weak_source": {"clean": "not-a-number"}, "strong_source": {"clean": "2"}}
assert prioritize_candidates(candidates, malformed)[0]["source"] == "strong_source", candidates
row = normalize_row(candidates[0], 19080, "example.invalid", "2523c510-9ff0-415b-9582-93949bfae7e3", "clean_latest")
assert row["source"] == "clean_latest", row
assert row["selection_source"] == "clean_latest", row
assert row["upstream_source"] == "weak_source", row
assert row["pool_priority"] == 0, row
print("ok")
"""
    return run([sys.executable, "-c", script])


def check_pool_refresh_replaces_low_priority_baseline() -> dict:
    script = r"""
from tools.ip_proxy_pool_refresh import select_rows

baseline = [
    {"raw": "turn://base-res", "turn": "turn://base-res", "exit_ip": "10.0.0.1", "kind": "turn", "clean": True, "success": True, "company_type": "ISP", "asn_type": "ISP"},
    {"raw": "turn://base-hosting", "turn": "turn://base-hosting", "exit_ip": "10.0.0.2", "kind": "turn", "clean": True, "success": True, "company_type": "hosting", "asn_type": "hosting"},
]
candidates = [
    {"raw": "turn://new-res", "turn": "turn://new-res", "exit_ip": "10.0.0.3", "kind": "turn", "clean": True, "success": True, "company_type": "ISP", "asn_type": "ISP"},
]
rows, meta = select_rows(
    baseline,
    candidates,
    set(),
    2,
    "example.invalid",
    "2523c510-9ff0-415b-9582-93949bfae7e3",
)
assert [row["raw"] for row in rows] == ["turn://base-res", "turn://new-res"], rows
assert meta["added_from_candidates"] == 1, meta
assert meta["retained_priority_baseline"] == 1, meta
assert meta["retained_low_priority_baseline"] == 0, meta
assert rows[1]["source"] == "clean_latest", rows
print("ok")
"""
    return run([sys.executable, "-c", script])


def check_candidate_harvest_source_priority() -> dict:
    script = r"""
from tools.ip_proxy_candidate_harvest import prioritize_candidates, select_check_candidates

candidates = [
    {"source": "weak_turn", "kind": "turn", "raw": "turn://aaa"},
    {"source": "strong_turn", "kind": "turn", "raw": "turn://zzz"},
    {"source": "cooldown_turn", "kind": "turn", "raw": "turn://cool"},
    {"source": "strong_socks", "kind": "socks5", "raw": "socks5://127.0.0.1:1080"},
]
source_quality = {
    "weak_turn": {"clean": 1, "clean_rate_pct": 1.0, "success": 2, "success_rate_pct": 2.0},
    "strong_turn": {"clean": 100, "clean_rate_pct": 50.0, "success": 150, "success_rate_pct": 75.0},
    "cooldown_turn": {"clean": 1000, "clean_rate_pct": 90.0, "success": 1000, "success_rate_pct": 99.0, "cooldown_recommended": True},
    "strong_socks": {"clean": 999, "clean_rate_pct": 99.0, "success": 999, "success_rate_pct": 99.0},
}
prioritized = prioritize_candidates(candidates, source_quality)
assert [item["source"] for item in prioritized] == ["strong_turn", "weak_turn", "cooldown_turn", "strong_socks"], prioritized
assert [item["source"] for item in prioritize_candidates(candidates, {})] == ["weak_turn", "cooldown_turn", "strong_turn", "strong_socks"], candidates

many = [
    {"source": "source_a", "kind": "turn", "raw": f"turn://a{i}"}
    for i in range(4)
] + [
    {"source": "source_b", "kind": "turn", "raw": "turn://b0"},
]
selected = select_check_candidates(many, max_check=3, max_per_source=2)
assert [item["raw"] for item in selected] == ["turn://a0", "turn://a1", "turn://b0"], selected
filled = select_check_candidates(many[:2], max_check=3, max_per_source=1)
assert [item["raw"] for item in filled] == ["turn://a0", "turn://a1"], filled
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
                "tools/ip_proxy_source_quality_report.py",
                "tools/ip_proxy_candidate_harvest.py",
            ]
        ),
        "imports": check_imports(),
        "router_without_optional_providers": check_router_without_optional_providers(),
        "fake_flow_summary": check_fake_flow_summary(),
        "flow_throttle_zero_delay": check_flow_throttle_zero_delay(),
        "bad_exit_precheck_skip": check_bad_exit_precheck_skip(),
        "registrar_feedback_diagnostics": check_registrar_feedback_diagnostics(),
        "pool_refresh_retained_bad_guard": check_pool_refresh_retained_bad_guard(),
        "source_quality_summary": check_source_quality_summary(),
        "batch_verifier_source_quality_report": check_batch_verifier_source_quality_report(),
        "source_quality_pool_priority": check_source_quality_pool_priority(),
        "pool_refresh_replaces_low_priority_baseline": check_pool_refresh_replaces_low_priority_baseline(),
        "candidate_harvest_source_priority": check_candidate_harvest_source_priority(),
    }
    if args.skip_docker or shutil.which("docker") is None:
        checks["docker_compose_config"] = {"ok": True, "skipped": True}
    else:
        checks["docker_compose_config"] = run(["docker", "compose", "config", "--quiet"])

    print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
