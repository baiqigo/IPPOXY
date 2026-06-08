import os
import random
import threading
from urllib.parse import urlparse, urlunparse, unquote
from patchright.sync_api import sync_playwright
from .base_controller import BaseBrowserController
from challenge_providers import ChallengeRouter


class PatchrightController(BaseBrowserController):
    def _iframe_meta_for_frame(self, page, target_frame):
        for idx, iframe in enumerate(page.query_selector_all("iframe")):
            try:
                frame = iframe.content_frame()
            except Exception:
                frame = None
            if frame != target_frame:
                continue
            try:
                meta = iframe.evaluate(
                    """e => ({
                        id: e.id,
                        name: e.getAttribute('name'),
                        title: e.getAttribute('title'),
                        src: e.getAttribute('src'),
                        style: e.getAttribute('style'),
                        box: (() => {
                            const r = e.getBoundingClientRect();
                            return {x: r.x, y: r.y, width: r.width, height: r.height};
                        })()
                    })"""
                )
            except Exception as e:
                meta = {"error": repr(e)}
            meta["source"] = "page.frames_matched_iframe"
            meta["index"] = idx
            return meta
        return {}

    def _find_challenge_frame(self, page):
        page.wait_for_selector(
            'iframe[title="验证质询"], iframe#enforcementFrame, iframe[src*="hsprotect.net"]',
            timeout=12000,
        )
        candidates = []
        for idx, frame in enumerate(page.frames):
            score = 0
            meta = {"source": "page.frames", "index": idx, "name": frame.name, "url": frame.url}
            matched_meta = self._iframe_meta_for_frame(page, frame)
            if matched_meta:
                meta.update(matched_meta)
                meta["url"] = frame.url
            try:
                if frame.locator('[aria-label="可访问性挑战"]').count() > 0:
                    score += 10
                if frame.locator('[aria-label="再次按下"]').count() > 0:
                    score += 10
                if frame.get_by_text("按住", exact=True).count() > 0:
                    score += 10
                if "hsprotect.net" in (frame.url or ""):
                    score += 4
                if frame.locator("button, [role=button], [aria-label]").count() > 0:
                    score += 2
            except Exception:
                pass
            if score:
                candidates.append((score, idx, frame, meta))

        iframe_handles = page.query_selector_all("iframe")
        for idx, iframe in enumerate(iframe_handles):
            try:
                meta = iframe.evaluate(
                    """e => ({
                        id: e.id,
                        name: e.getAttribute('name'),
                        title: e.getAttribute('title'),
                        src: e.getAttribute('src'),
                        style: e.getAttribute('style'),
                        box: (() => {
                            const r = e.getBoundingClientRect();
                            return {x: r.x, y: r.y, width: r.width, height: r.height};
                        })()
                    })"""
                )
            except Exception as e:
                meta = {"error": repr(e)}
            frame = iframe.content_frame()
            if not frame:
                continue
            score = 0
            meta["source"] = "top_iframe_element"
            title = meta.get("title") or ""
            src = meta.get("src") or ""
            if "验证" in title or "challenge" in title.lower():
                score += 5
            if "hsprotect.net" in src:
                score += 4
            try:
                if frame.locator('[aria-label="可访问性挑战"]').count() > 0:
                    score += 10
                if frame.locator('[aria-label="再次按下"]').count() > 0:
                    score += 10
                if frame.get_by_text("按住", exact=True).count() > 0:
                    score += 10
                if frame.locator("button, [role=button], [aria-label]").count() > 0:
                    score += 2
            except Exception:
                pass
            candidates.append((score, idx, frame, meta))
        candidates.sort(key=lambda x: (x[0], bool((x[3] or {}).get("box"))), reverse=True)
        if not candidates or candidates[0][0] <= 0:
            raise RuntimeError(f"challenge frame not found; iframe_count={len(iframe_handles)}")
        score, idx, frame, meta = candidates[0]
        print(f"[Captcha] - using iframe index={idx} score={score} meta={meta}", flush=True)
        return frame, meta

    def _challenge_hold_ms(self):
        low = int(os.environ.get("OUTLOOK_PRESS_HOLD_MIN_MS", "11000"))
        high = int(os.environ.get("OUTLOOK_PRESS_HOLD_MAX_MS", "15000"))
        if high < low:
            high = low
        return random.randint(low, high)

    def _press_point(self, page, x, y, label, hold_ms=None, micro_jitter=False):
        page.mouse.move(x + random.randint(-3, 3), y + random.randint(-3, 3), steps=random.randint(8, 15))
        page.wait_for_timeout(random.randint(120, 350))
        page.mouse.down()
        if hold_ms is None:
            hold_ms = random.randint(650, 1400)
        if micro_jitter and hold_ms > 1200:
            elapsed = 0
            while elapsed < hold_ms:
                step_ms = min(random.randint(700, 1300), hold_ms - elapsed)
                page.wait_for_timeout(step_ms)
                elapsed += step_ms
                if elapsed < hold_ms:
                    page.mouse.move(
                        x + random.uniform(-1.5, 1.5),
                        y + random.uniform(-1.2, 1.2),
                        steps=random.randint(2, 4),
                    )
        else:
            page.wait_for_timeout(hold_ms)
        page.mouse.up()
        print(f"[Captcha] - pressed {label} at x={x:.1f}, y={y:.1f}, hold_ms={hold_ms}", flush=True)

    def _visual_challenge_press(self, page, frame_meta, label):
        box = (frame_meta or {}).get("box") or {}
        x0 = float(box.get("x", 0))
        y0 = float(box.get("y", 0))
        width = float(box.get("width", 360))
        height = float(box.get("height", 90))
        y = y0 + min(max(height * 0.60, 48), height - 12)
        if label == "accessibility_challenge":
            x = x0 + min(max(width * 0.18, 45), width - 20)
            hold_ms = random.randint(900, 1600)
        else:
            x = x0 + min(max(width * 0.56, 155), width - 30)
            hold_ms = self._challenge_hold_ms()
        self._press_point(page, x, y, f"visual_{label}", hold_ms=hold_ms, micro_jitter=False)

    def _hold_locator_or_box(self, page, locator, label, frame_meta=None, hold_ms=None):
        if hold_ms is None:
            hold_ms = self._challenge_hold_ms()
        try:
            box = locator.first.bounding_box(timeout=5000)
            print(f"[Captcha] - {label} hold box={box}", flush=True)
            if box:
                x = box["x"] + box["width"] / 2 + random.uniform(-4, 4)
                y = box["y"] + box["height"] / 2 + random.uniform(-3, 3)
                self._press_point(page, x, y, f"hold_{label}", hold_ms=hold_ms, micro_jitter=False)
                return True
        except Exception as e:
            print(f"[Captcha] - hold box failed for {label}: {e}", flush=True)
        self._visual_challenge_press(page, frame_meta, label)
        return True

    def _keyboard_challenge_press(self, page, frame_meta, hold_ms=None):
        box = (frame_meta or {}).get("box") or {}
        x0 = float(box.get("x", 0))
        y0 = float(box.get("y", 0))
        width = float(box.get("width", 360))
        height = float(box.get("height", 90))
        x = x0 + min(max(width * 0.50, 120), width - 30)
        y = y0 + min(max(height * 0.55, 44), height - 12)
        if hold_ms is None:
            hold_ms = random.randint(10500, 12500)
        try:
            page.mouse.click(x, y)
            page.wait_for_timeout(random.randint(250, 600))
        except Exception as e:
            print(f"[Captcha] - keyboard focus click failed: {e}", flush=True)
        try:
            page.keyboard.down("Enter")
            page.wait_for_timeout(hold_ms)
            page.keyboard.up("Enter")
            print(f"[Captcha] - held Enter on challenge, hold_ms={hold_ms}", flush=True)
            return True
        except Exception as e:
            print(f"[Captcha] - keyboard challenge press failed: {e}", flush=True)
            try:
                page.keyboard.press("Enter")
                page.wait_for_timeout(hold_ms)
                page.keyboard.press("Enter")
                print(f"[Captcha] - pressed Enter pair on challenge, wait_ms={hold_ms}", flush=True)
                return True
            except Exception as e2:
                print(f"[Captcha] - Enter pair fallback failed: {e2}", flush=True)
                return False

    def _click_locator_or_box(self, page, locator, label, frame_meta=None):
        try:
            locator.first.click(timeout=8000)
            print(f"[Captcha] - clicked {label} by locator", flush=True)
            return True
        except Exception as e:
            print(f"[Captcha] - locator click failed for {label}: {e}", flush=True)
        try:
            box = locator.first.bounding_box(timeout=3000)
            print(f"[Captcha] - {label} fallback box={box}", flush=True)
            x = box['x'] + box['width'] / 2 + random.randint(-8, 8)
            y = box['y'] + box['height'] / 2 + random.randint(-8, 8)
            self._press_point(page, x, y, f"box_{label}")
            return True
        except Exception as e:
            print(f"[Captcha] - box fallback failed for {label}: {e}", flush=True)
        self._visual_challenge_press(page, frame_meta, label)
        return True

    def _browser_path(self):
        env_path = os.environ.get("OUTLOOK_BROWSER_PATH", "").strip()
        if env_path:
            return env_path
        config_path = (getattr(self, "patchright_browser_path", "") or "").strip()
        if config_path:
            return config_path
        linux_system_chromium = "/usr/bin/chromium"
        if os.name == "posix" and os.path.exists(linux_system_chromium):
            return linux_system_chromium
        return ""

    def launch_browser(self):
        try:
            p = sync_playwright().start() 

            proxy_settings = self.browser_proxy_settings()

            profile_dir = os.path.abspath(os.path.join(
                os.path.dirname(__file__),
                '..',
                '.profiles',
                f'patchright_{threading.get_ident()}',
            ))
            os.makedirs(profile_dir, exist_ok=True)
            launch_kwargs = {}
            browser_path = self._browser_path()
            if browser_path:
                launch_kwargs["executable_path"] = browser_path
            headless = os.environ.get("OUTLOOK_HEADLESS", "").strip().lower() in ("1", "true", "yes")

            b = p.chromium.launch_persistent_context(
                user_data_dir=profile_dir,
                headless=headless,
                args=[
                    '--lang=zh-CN',
                    '--accept-lang=zh-CN,zh',
                    '--force-local-ntp=zh-CN',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--disable-popup-blocking',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-features=WebRtcHideLocalIpsWithMdns',
                    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
                ],
                locale='zh-CN',
                timezone_id='America/New_York',
                viewport={"width": 1365, "height": 768},
                screen={"width": 1365, "height": 768},
                proxy=proxy_settings,
                **launch_kwargs,
            )

            return p, b

        except Exception as e:
            print(f"启动浏览器失败: {e}")
            return False, False
        
    def handle_captcha(self, page):
        router = ChallengeRouter.from_config(self.challenge_router_config)
        return router.solve(page, self)

    def get_thread_page(self):
        context = self.get_thread_browser()
        if context.pages:
            return context.pages[0]
        return context.new_page()

    def clean_up(self, page=None, type="all_browser"):
        if type == "done_browser" and page:
            context = page.context
            try:
                context.close()
            except Exception:
                pass
            try:
                self.thread_local.playwright.stop()
            except Exception:
                pass
            for attr in ("browser", "playwright", "proxy_identity"):
                try:
                    delattr(self.thread_local, attr)
                except Exception:
                    pass

        elif type == "all_browser":
            for p, b in self.active_resources:
                try:
                    b.close()
                except Exception: pass
                try:
                    p.stop()
                except Exception: pass

    
