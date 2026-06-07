import os
import random
import threading
from urllib.parse import urlparse, urlunparse, unquote
from patchright.sync_api import sync_playwright
from .base_controller import BaseBrowserController
from challenge_providers import ChallengeRouter


class PatchrightController(BaseBrowserController):
    def _find_challenge_frame(self, page):
        page.wait_for_selector('iframe[title="验证质询"]', timeout=12000)
        candidates = []
        for idx, frame in enumerate(page.frames):
            score = 0
            meta = {"source": "page.frames", "index": idx, "name": frame.name, "url": frame.url}
            try:
                if frame.locator('[aria-label="可访问性挑战"]').count() > 0:
                    score += 10
                if frame.locator('[aria-label="再次按下"]').count() > 0:
                    score += 10
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
            if "验证" in title or "challenge" in title.lower():
                score += 5
            try:
                if frame.locator('[aria-label="可访问性挑战"]').count() > 0:
                    score += 10
                if frame.locator('[aria-label="再次按下"]').count() > 0:
                    score += 10
                if frame.locator("button, [role=button], [aria-label]").count() > 0:
                    score += 2
            except Exception:
                pass
            candidates.append((score, idx, frame, meta))
        candidates.sort(key=lambda x: x[0], reverse=True)
        if not candidates or candidates[0][0] <= 0:
            raise RuntimeError(f"challenge frame not found; iframe_count={len(iframe_handles)}")
        score, idx, frame, meta = candidates[0]
        print(f"[Captcha] - using iframe index={idx} score={score} meta={meta}", flush=True)
        return frame, meta

    def _press_point(self, page, x, y, label, hold_ms=None):
        page.mouse.move(x + random.randint(-3, 3), y + random.randint(-3, 3), steps=random.randint(8, 15))
        page.wait_for_timeout(random.randint(120, 350))
        page.mouse.down()
        if hold_ms is None:
            hold_ms = random.randint(650, 1400)
        page.wait_for_timeout(hold_ms)
        page.mouse.up()
        print(f"[Captcha] - pressed {label} at x={x:.1f}, y={y:.1f}, hold_ms={hold_ms}", flush=True)

    def _visual_challenge_press(self, page, frame_meta, label):
        box = (frame_meta or {}).get("box") or {}
        x0 = float(box.get("x", 0))
        y0 = float(box.get("y", 0))
        width = float(box.get("width", 360))
        height = float(box.get("height", 90))
        y = y0 + min(max(height * 0.58, 48), height - 12)
        if label == "accessibility_challenge":
            x = x0 + min(max(width * 0.18, 45), width - 20)
        else:
            x = x0 + min(max(width * 0.57, 160), width - 30)
        hold_ms = random.randint(4200, 6200) if label == "press_again" else random.randint(900, 1600)
        self._press_point(page, x, y, f"visual_{label}", hold_ms=hold_ms)

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

            proxy_settings = None
            if self.proxy:
                parsed = urlparse(self.proxy)
                if parsed.username or parsed.password:
                    host = parsed.hostname or ''
                    if parsed.port:
                        host = f"{host}:{parsed.port}"
                    proxy_settings = {
                        "server": urlunparse((parsed.scheme, host, '', '', '', '')),
                        "username": unquote(parsed.username or ''),
                        "password": unquote(parsed.password or ''),
                        "bypass": "localhost",
                    }
                else:
                    proxy_settings = {
                        "server": self.proxy,
                        "bypass": "localhost",
                    }

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
            context.close()

        elif type == "all_browser":
            for p, b in self.active_resources:
                try:
                    b.close()
                except Exception: pass
                try:
                    p.stop()
                except Exception: pass

    
