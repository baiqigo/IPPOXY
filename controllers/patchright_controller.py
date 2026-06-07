import os
import random
import threading
from urllib.parse import urlparse, urlunparse, unquote
from patchright.sync_api import sync_playwright
from .base_controller import BaseBrowserController


class PatchrightController(BaseBrowserController):
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

            b = p.chromium.launch_persistent_context(
                user_data_dir=profile_dir,
                headless=False,
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

        frame1 = page.frame_locator('iframe[title="验证质询"]')
        frame2 = frame1.frame_locator('iframe[style*="display: block"]')


        for _ in range(0, self.max_captcha_retries + 1):

            page.wait_for_timeout(200)
            loc = frame2.locator('[aria-label="可访问性挑战"]')
            box = loc.bounding_box()
            x = box['x'] + box['width'] / 2 + random.randint(-10, 10)
            y = box['y'] + box['height'] / 2 + random.randint(-10, 10)
            page.mouse.click(x, y)

            loc2 = frame2.locator('[aria-label="再次按下"]')
            box2 = loc2.bounding_box()
            x = box2['x'] + box2['width'] / 2 + random.randint(-20, 20)
            y = box2['y'] + box2['height'] / 2 + random.randint(-13, 13)
            page.mouse.click(x, y)

            try:

                page.locator('.draw').wait_for(state="detached")
                try:

                    # 简单的认为加载8秒后成功，暂不考虑请求.
                    page.locator('[role="status"][aria-label="正在加载..."]').wait_for(timeout=5000)
                    page.wait_for_timeout(8000)
                    if page.get_by_text('一些异常活动').count() or page.get_by_text('此站点正在维护，暂时无法使用，请稍后重试。').count() > 0:
                        print("[Error: Rate limit] - 正常通过验证码，但当前IP注册频率过快。")
                        return False
                    elif frame2.locator('[aria-label="可访问性挑战"]').count() > 0:
                        continue
                    break

                except:

                    if page.get_by_text('取消').count() > 0:
                        break
                    frame1.get_by_text("请再试一次").wait_for(timeout=15000)
                    continue

            except:
                if page.get_by_text('取消').count() > 0:
                     break
                return False
        else: 
            return False

        return True

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

    
