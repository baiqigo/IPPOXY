import json
import os
import time
from pathlib import Path

from .base import ChallengeResult
from .classifier import classify_challenge
from .microsoft_press import MicrosoftPressProvider
from .stubs import HumanQueueProvider, PaidCaptchaProvider, SkippedProvider, VisualAgentProvider

try:
    from .altcha_pow import AltchaPowProvider
except ImportError:
    AltchaPowProvider = None

try:
    from .cdp_browser import CdpBrowserProvider
except ImportError:
    CdpBrowserProvider = None

try:
    from .self_hosted_solver import SelfHostedSolverProvider
except ImportError:
    SelfHostedSolverProvider = None


class ChallengeRouter:
    def __init__(self, config=None):
        config = config or {}
        self.enabled = bool(config.get("enabled", True))
        self.order = config.get("order") or [
            "microsoft_press",
            "cdp_browser",
            "visual_agent",
            "altcha_pow",
            "self_hosted_solver",
            "human_queue",
            "paid_captcha",
        ]
        self.self_hosted_endpoint = config.get("self_hosted_endpoint", "")
        self.human_timeout_seconds = int(config.get("human_timeout_seconds", 0) or 0)
        self.providers = {
            "microsoft_press": MicrosoftPressProvider(),
            "cdp_browser": (
                CdpBrowserProvider()
                if CdpBrowserProvider
                else SkippedProvider("cdp_browser", "cdp_browser provider module is not installed")
            ),
            "visual_agent": VisualAgentProvider(),
            "altcha_pow": (
                AltchaPowProvider()
                if AltchaPowProvider
                else SkippedProvider("altcha_pow", "altcha_pow provider module is not installed")
            ),
            "self_hosted_solver": (
                SelfHostedSolverProvider(self.self_hosted_endpoint)
                if SelfHostedSolverProvider
                else SkippedProvider("self_hosted_solver", "self_hosted_solver provider module is not installed")
            ),
            "human_queue": HumanQueueProvider(self.human_timeout_seconds),
            "paid_captcha": PaidCaptchaProvider(),
        }

    @classmethod
    def from_config(cls, config=None):
        return cls(config or {})

    def _save_router_evidence(self, controller, evidence, result=None):
        try:
            ts = int(time.time())
            base = Path(controller.captures_dir) / f"{ts}_challenge_router"
            payload = {
                "timestamp": ts,
                "evidence": evidence,
                "result": result.__dict__ if result else None,
            }
            with open(base.with_suffix(".json"), "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"[ChallengeRouter] - saved router evidence: {base}.json", flush=True)
        except Exception as e:
            print(f"[ChallengeRouter] - failed to save router evidence: {e}", flush=True)

    def solve(self, page, controller) -> bool:
        if not self.enabled:
            print("[ChallengeRouter] - disabled; using legacy Microsoft press handler", flush=True)
            provider = self.providers["microsoft_press"]
            result = provider.solve(page, controller, {"type": "microsoft_press"})
            return result.cleared

        evidence = classify_challenge(page)
        challenge_type = evidence.get("type", "unknown")
        print(
            f"[ChallengeRouter] - type={challenge_type} signals={evidence.get('signals')}",
            flush=True,
        )
        self._save_router_evidence(controller, evidence)

        last_result = ChallengeResult(
            status="failed",
            provider="none",
            challenge_type=challenge_type,
            reason="no provider attempted",
            evidence=evidence,
        )

        for provider_name in self.order:
            provider = self.providers.get(provider_name)
            if not provider:
                print(f"[ChallengeRouter] - unknown provider skipped: {provider_name}", flush=True)
                continue
            if not provider.can_handle(challenge_type, evidence):
                print(
                    f"[ChallengeRouter] - provider skipped: {provider.name} for {challenge_type}",
                    flush=True,
                )
                continue

            print(f"[ChallengeRouter] - provider selected: {provider.name}", flush=True)
            result = provider.solve(page, controller, evidence)
            last_result = result
            if not result.cleared and hasattr(controller, "set_flow_failure"):
                controller.set_flow_failure(
                    f"challenge_failed_{result.provider}",
                    {
                        "stage": "challenge",
                        "challenge_type": result.challenge_type,
                        "provider": result.provider,
                        "reason": result.reason,
                    },
                    overwrite=True,
                )
            self._save_router_evidence(controller, evidence, result)
            print(
                f"[ChallengeRouter] - provider={result.provider} "
                f"status={result.status} reason={result.reason}",
                flush=True,
            )
            if result.cleared:
                return True

        controller.capture_debug_state(page, f"router_failed_{challenge_type}_{last_result.provider}")
        return False
