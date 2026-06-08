import random
import re

from .base import ChallengeProvider, ChallengeResult


class MicrosoftPressProvider(ChallengeProvider):
    name = "microsoft_press"

    def can_handle(self, challenge_type, evidence):
        return challenge_type == "microsoft_press"

    def _challenge_gone(self, page, challenge_frame):
        try:
            if page.get_by_text("一些异常活动").count() > 0:
                return False
        except Exception:
            pass
        try:
            title = page.title()
            if "不是机器人" in title or "robot" in title.lower():
                return False
        except Exception:
            pass
        try:
            if page.locator('iframe[title="验证质询"]').count() > 0:
                return False
        except Exception:
            pass
        try:
            frame_urls = [frame.url for frame in page.frames]
            if any("hsprotect.net" in url or "fpt.live.com" in url for url in frame_urls):
                return False
        except Exception:
            pass
        try:
            if challenge_frame.locator(".draw").count() > 0:
                return False
        except Exception:
            pass
        return True

    def _locator_count(self, locator):
        try:
            return locator.count()
        except Exception:
            return 0

    def _first_available_locator(self, locators):
        for label, locator in locators:
            count = self._locator_count(locator)
            print(f"[ChallengeRouter] - {label} count={count}", flush=True)
            if count > 0:
                return label, locator, count
        return "", None, 0

    def _hold_button_locators(self, challenge_frame):
        hold_words = re.compile(r"(按住|再次按下|长按|hold|press)", re.I)
        return [
            ("press_again_aria", challenge_frame.locator('[aria-label="再次按下"]')),
            ("hold_aria", challenge_frame.locator('[aria-label="按住"]')),
            ("hold_text_exact", challenge_frame.get_by_text("按住", exact=True)),
            ("press_again_text_exact", challenge_frame.get_by_text("再次按下", exact=True)),
            ("hold_role_button", challenge_frame.get_by_role("button", name=hold_words)),
            ("hold_text_regex", challenge_frame.get_by_text(hold_words)),
        ]

    def _rate_limited(self, page):
        try:
            return (
                page.get_by_text("一些异常活动").count() > 0
                or page.get_by_text("此站点正在维护，暂时无法使用，请稍后重试。").count() > 0
            )
        except Exception:
            return False

    def _wait_after_press(self, page, controller, challenge_frame, attempt, suffix):
        try:
            challenge_frame.locator(".draw").wait_for(state="detached", timeout=15000)
        except Exception as e:
            print(f"[ChallengeRouter] - .draw did not detach after {suffix}: {e}", flush=True)

        try:
            page.locator('[role="status"][aria-label="正在加载..."]').wait_for(timeout=5000)
            page.wait_for_timeout(8000)
        except Exception:
            page.wait_for_timeout(1800)

        if self._rate_limited(page):
            controller.capture_debug_state(page, f"router_{self.name}_{suffix}_rate_limited")
            return "rate_limited"

        if self._challenge_gone(page, challenge_frame):
            return "cleared"

        try:
            challenge_frame.get_by_text("请再试一次").wait_for(timeout=3500)
        except Exception:
            pass

        controller.capture_debug_state(page, f"router_{self.name}_attempt_{attempt + 1}_{suffix}_still_visible")
        return "retry"

    def solve(self, page, controller, evidence=None):
        challenge_type = (evidence or {}).get("type", "microsoft_press")
        try:
            challenge_frame, frame_meta = controller._find_challenge_frame(page)
        except Exception as e:
            controller.capture_debug_state(page, "router_microsoft_frame_not_found")
            return ChallengeResult(
                status="failed",
                provider=self.name,
                challenge_type=challenge_type,
                reason=f"challenge frame not found: {e}",
                evidence=evidence or {},
            )

        for attempt in range(0, controller.max_captcha_retries + 1):
            page.wait_for_timeout(200)
            print(
                f"[ChallengeRouter] - {self.name} attempt "
                f"{attempt + 1}/{controller.max_captcha_retries + 1}",
                flush=True,
            )

            loc = challenge_frame.locator('[aria-label="可访问性挑战"]')
            accessibility_count = self._locator_count(loc)
            print(f"[ChallengeRouter] - accessibility count={accessibility_count}", flush=True)

            hold_label, hold_locator, hold_count = self._first_available_locator(
                self._hold_button_locators(challenge_frame)
            )

            if accessibility_count > 0 or hold_count > 0:
                if accessibility_count > 0:
                    controller._click_locator_or_box(page, loc, "accessibility_challenge", frame_meta)
                    page.wait_for_timeout(random.randint(400, 900))
                    hold_label, hold_locator, hold_count = self._first_available_locator(
                        self._hold_button_locators(challenge_frame)
                    )
                if hold_count > 0:
                    print(f"[ChallengeRouter] - holding button via {hold_label}", flush=True)
                    controller._hold_locator_or_box(page, hold_locator, "press_again", frame_meta)
                else:
                    print("[ChallengeRouter] - no hold locator after accessibility; visual long-press", flush=True)
                    controller._visual_challenge_press(page, frame_meta, "press_again")
            else:
                print("[ChallengeRouter] - no DOM buttons found; visual long-press on hold button", flush=True)
                controller._visual_challenge_press(page, frame_meta, "press_again")

            wait_result = self._wait_after_press(page, controller, challenge_frame, attempt, "mouse")
            if wait_result == "cleared":
                return ChallengeResult(
                    status="cleared",
                    provider=self.name,
                    challenge_type=challenge_type,
                    reason="challenge cleared after mouse press",
                    evidence=evidence or {},
                )
            if wait_result == "rate_limited":
                return ChallengeResult(
                    status="failed",
                    provider=self.name,
                    challenge_type=challenge_type,
                    reason="rate limited or abnormal activity after mouse press",
                    evidence=evidence or {},
                )

            if accessibility_count == 0 and hold_count == 0:
                print("[ChallengeRouter] - mouse press did not clear; trying keyboard hold fallback", flush=True)
                controller._keyboard_challenge_press(page, frame_meta)
                wait_result = self._wait_after_press(page, controller, challenge_frame, attempt, "keyboard")
                if wait_result == "cleared":
                    return ChallengeResult(
                        status="cleared",
                        provider=self.name,
                        challenge_type=challenge_type,
                        reason="challenge cleared after keyboard fallback",
                        evidence=evidence or {},
                    )
                if wait_result == "rate_limited":
                    return ChallengeResult(
                        status="failed",
                        provider=self.name,
                        challenge_type=challenge_type,
                        reason="rate limited or abnormal activity after keyboard fallback",
                        evidence=evidence or {},
                    )

        controller.capture_debug_state(page, f"router_{self.name}_attempts_exhausted")
        return ChallengeResult(
            status="failed",
            provider=self.name,
            challenge_type=challenge_type,
            reason="attempts exhausted",
            evidence=evidence or {},
        )
