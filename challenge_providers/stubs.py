import os
import time
from .base import ChallengeProvider, ChallengeResult


class HumanQueueProvider(ChallengeProvider):
    name = "human_queue"

    def __init__(self, timeout_seconds=0):
        self.timeout_seconds = int(timeout_seconds or 0)

    def can_handle(self, challenge_type, evidence):
        return self.timeout_seconds > 0

    def solve(self, page, controller, evidence=None):
        controller.capture_debug_state(page, "router_human_queue_required")
        if not self.timeout_seconds:
            return ChallengeResult(
                status="skipped",
                provider=self.name,
                challenge_type=(evidence or {}).get("type", "unknown"),
                reason="human queue is not configured",
                evidence=evidence or {},
            )

        print(
            f"[ChallengeRouter] - waiting {self.timeout_seconds}s for manual challenge handling",
            flush=True,
        )
        deadline = time.time() + self.timeout_seconds
        while time.time() < deadline:
            if page.locator('iframe[title="验证质询"]').count() == 0:
                return ChallengeResult(
                    status="cleared",
                    provider=self.name,
                    challenge_type=(evidence or {}).get("type", "unknown"),
                    reason="challenge frame disappeared during manual wait",
                    evidence=evidence or {},
                )
            page.wait_for_timeout(2000)

        return ChallengeResult(
            status="failed",
            provider=self.name,
            challenge_type=(evidence or {}).get("type", "unknown"),
            reason="manual wait timed out",
            evidence=evidence or {},
        )


class VisualAgentProvider(ChallengeProvider):
    name = "visual_agent"

    def can_handle(self, challenge_type, evidence):
        return bool(os.environ.get("CHALLENGE_VISUAL_AGENT")) and challenge_type in {
            "hcaptcha",
            "recaptcha",
        }

    def solve(self, page, controller, evidence=None):
        controller.capture_debug_state(page, "router_visual_agent_not_implemented")
        return ChallengeResult(
            status="skipped",
            provider=self.name,
            challenge_type=(evidence or {}).get("type", "unknown"),
            reason="visual agent provider is a scaffold only",
            evidence=evidence or {},
        )


class PaidCaptchaProvider(ChallengeProvider):
    name = "paid_captcha"

    def can_handle(self, challenge_type, evidence):
        return bool(os.environ.get("CHALLENGE_PAID_CAPTCHA"))

    def solve(self, page, controller, evidence=None):
        controller.capture_debug_state(page, "router_paid_captcha_not_configured")
        return ChallengeResult(
            status="skipped",
            provider=self.name,
            challenge_type=(evidence or {}).get("type", "unknown"),
            reason="paid captcha provider is not configured in this registrar",
            evidence=evidence or {},
        )


class SkippedProvider(ChallengeProvider):
    def __init__(self, name, reason):
        self.name = name
        self.reason = reason

    def can_handle(self, challenge_type, evidence):
        return False

    def solve(self, page, controller, evidence=None):
        return ChallengeResult(
            status="skipped",
            provider=self.name,
            challenge_type=(evidence or {}).get("type", "unknown"),
            reason=self.reason,
            evidence=evidence or {},
        )
