import os
import time
import json
import random
import threading
from pathlib import Path
from faker import Faker
from abc import ABC, abstractmethod
from urllib.parse import urlparse, urlunparse, unquote

class BaseBrowserController(ABC):
    """
    所有浏览器通用的接口和共享逻辑
    """

    def __init__(self):
        with open('config.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.wait_time = data['bot_protection_wait'] * 1000
        self.max_captcha_retries = data['max_captcha_retries']
        env_oauth = os.environ.get("OUTLOOK_ENABLE_OAUTH2", "").strip().lower()
        oauth2_config = data.get("oauth2", {})
        self.enable_oauth2 = oauth2_config.get('enable_oauth2', False) or env_oauth in ("1", "true", "yes")
        self.oauth2_client_id = os.environ.get("OUTLOOK_OAUTH_CLIENT_ID", "").strip() or str(oauth2_config.get("client_id", "")).strip()
        self.oauth2_redirect_url = os.environ.get("OUTLOOK_OAUTH_REDIRECT_URL", "").strip() or str(oauth2_config.get("redirect_url", "")).strip()
        if self.enable_oauth2 and (not self.oauth2_client_id or not self.oauth2_redirect_url):
            raise ValueError(
                "OAuth2 token mode requires OUTLOOK_OAUTH_CLIENT_ID and "
                "OUTLOOK_OAUTH_REDIRECT_URL, or config.json oauth2.client_id/oauth2.redirect_url."
            )
        env_proxy = os.environ.get("OUTLOOK_PROXY", "").strip()
        self.proxy = env_proxy or data['proxy']
        self.proxy_source = "OUTLOOK_PROXY" if env_proxy else "config.json"
        print(f"[Proxy] source={self.proxy_source} value={self.proxy}", flush=True)
        self.email_suffix = data['email_suffix']
        self.patchright_browser_path = data.get("patchright", {}).get("browser_path", "")
        self.challenge_router_config = data.get("challenge_router", {})

        self.thread_local = threading.local()
        self.cleanup_lock = threading.Lock()
        self.active_resources = []  # 记录资源以便关闭

        self.results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Results')
        os.makedirs(self.results_dir, exist_ok=True)
        self.captures_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'captures')
        os.makedirs(self.captures_dir, exist_ok=True)

    def browser_proxy_settings(self):
        if not self.proxy:
            return None

        parsed = urlparse(self.proxy)
        scheme = "socks5" if parsed.scheme == "socks5h" else parsed.scheme
        if parsed.username or parsed.password:
            host = parsed.hostname or ''
            if parsed.port:
                host = f"{host}:{parsed.port}"
            return {
                "server": urlunparse((scheme, host, '', '', '', '')),
                "username": unquote(parsed.username or ''),
                "password": unquote(parsed.password or ''),
                "bypass": "localhost",
            }

        if parsed.scheme == "socks5h":
            return {
                "server": urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)),
                "bypass": "localhost",
            }
        return {
            "server": self.proxy,
            "bypass": "localhost",
        }

    @abstractmethod
    def launch_browser(self):
        """
        获取浏览器实例,返回playwright_instance, browser_instance
        """
        pass

    @abstractmethod
    def handle_captcha(self, page):
        """
        验证码处理流程
        """
        pass

    @abstractmethod 
    def clean_up(self, page=None, type = "all_browser"):
        """
        清理自己创建的内容
        一个是单进程结束后关闭进程，另一个是程序结束后清除所有内容
        """
        pass

    @abstractmethod
    def get_thread_page(self):
        """
        返回页面
        """


    def get_thread_browser(self):
        """
        通用逻辑:获取不同进程的浏览器
        """

        if not hasattr(self.thread_local,"browser"):

            p, b  = self.launch_browser()
            if not p:
                return False

            self.thread_local.playwright = p
            self.thread_local.browser = b

            with self.cleanup_lock:
                self.active_resources.append((p, b))

        return self.thread_local.browser

    def capture_debug_state(self, page, label):
        """
        Save a small forensic snapshot for anti-bot/challenge failures.
        """
        if not page:
            return

        ts = int(time.time())
        safe_label = ''.join(ch if ch.isalnum() or ch in ('-', '_') else '_' for ch in label)[:80]
        base = Path(self.captures_dir) / f"{ts}_{safe_label}"
        data = {
            "label": label,
            "timestamp": ts,
            "url": "",
            "title": "",
            "frames": [],
            "iframe_elements": [],
            "iframe_button_snapshots": [],
            "visible_buttons": [],
            "visible_inputs": [],
            "texts": {},
            "locators": {},
        }

        try:
            data["url"] = page.url
        except Exception as e:
            data["url_error"] = repr(e)
        try:
            data["title"] = page.title()
        except Exception as e:
            data["title_error"] = repr(e)

        try:
            page.screenshot(path=str(base.with_suffix(".png")), full_page=True, timeout=8000)
        except Exception as e:
            data["screenshot_error"] = repr(e)

        try:
            for frame in page.frames:
                data["frames"].append({
                    "name": frame.name,
                    "url": frame.url,
                })
        except Exception as e:
            data["frames_error"] = repr(e)

        try:
            iframe_handles = page.query_selector_all("iframe")
            for idx, iframe in enumerate(iframe_handles[:20]):
                meta = iframe.evaluate(
                    """e => ({
                        index: 0,
                        id: e.id,
                        name: e.getAttribute('name'),
                        title: e.getAttribute('title'),
                        src: e.getAttribute('src'),
                        style: e.getAttribute('style'),
                        aria: e.getAttribute('aria-label'),
                        box: (() => {
                            const r = e.getBoundingClientRect();
                            return {x: r.x, y: r.y, width: r.width, height: r.height};
                        })()
                    })"""
                )
                meta["index"] = idx
                data["iframe_elements"].append(meta)
                frame = iframe.content_frame()
                if frame:
                    try:
                        buttons = frame.locator("button, [role=button], [aria-label]").evaluate_all(
                            """els => els.slice(0, 80).map(e => ({
                                tag: e.tagName,
                                text: (e.innerText || e.textContent || '').slice(0, 120),
                                aria: e.getAttribute('aria-label'),
                                role: e.getAttribute('role'),
                                id: e.id,
                                cls: e.className,
                                visible: !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length)
                            }))"""
                        )
                    except Exception as e:
                        buttons = {"error": repr(e)}
                    data["iframe_button_snapshots"].append({
                        "index": idx,
                        "frame_url": frame.url,
                        "buttons": buttons,
                    })
        except Exception as e:
            data["iframe_elements_error"] = repr(e)

        try:
            data["visible_buttons"] = page.locator(
                "button, [role=button], [aria-label]"
            ).evaluate_all(
                """els => els.slice(0, 80).map(e => ({
                    tag: e.tagName,
                    text: (e.innerText || e.textContent || '').slice(0, 120),
                    aria: e.getAttribute('aria-label'),
                    role: e.getAttribute('role'),
                    id: e.id,
                    cls: e.className,
                    visible: !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length)
                }))"""
            )
        except Exception as e:
            data["visible_buttons_error"] = repr(e)

        try:
            data["visible_inputs"] = page.locator(
                "input, select, textarea"
            ).evaluate_all(
                """els => els.slice(0, 80).map(e => ({
                    tag: e.tagName,
                    name: e.getAttribute('name'),
                    type: e.getAttribute('type'),
                    aria: e.getAttribute('aria-label'),
                    placeholder: e.getAttribute('placeholder'),
                    value_len: (e.value || '').length,
                    visible: !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length)
                }))"""
            )
        except Exception as e:
            data["visible_inputs_error"] = repr(e)

        for text in ("一些异常活动", "此站点正在维护", "请再试一次", "取消", "正在加载"):
            try:
                data["texts"][text] = page.get_by_text(text).count()
            except Exception as e:
                data["texts"][text] = repr(e)

        locator_checks = {
            "enforcementFrame": "iframe#enforcementFrame",
            "challenge_title_frame": 'iframe[title="验证质询"]',
            "visible_style_frame": 'iframe[style*="display: block"]',
            "draw": ".draw",
            "loading_status": '[role="status"][aria-label="正在加载..."]',
            "accessibility_challenge": '[aria-label="可访问性挑战"]',
            "press_again": '[aria-label="再次按下"]',
            "primary_button": '[data-testid="primaryButton"]',
        }
        for name, selector in locator_checks.items():
            try:
                loc = page.locator(selector)
                item = {"count": loc.count()}
                if item["count"]:
                    try:
                        item["first_box"] = loc.first.bounding_box(timeout=2000)
                    except Exception as e:
                        item["first_box_error"] = repr(e)
                data["locators"][name] = item
            except Exception as e:
                data["locators"][name] = {"error": repr(e)}

        try:
            with open(base.with_suffix(".json"), "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"[Debug] - saved challenge state: {base}.json")
        except Exception as e:
            print(f"[Debug] - failed to save challenge state: {e}")

    def outlook_register(self, page, email, password):
        """
        通用逻辑:注册邮箱
        """

        fake = Faker()

        lastname = fake.last_name()
        firstname = fake.first_name()
        year = str(random.randint(1960, 2005))
        month = str(random.randint(1, 12))
        day = str(random.randint(1, 28))

        try:
            page.goto("https://outlook.live.com/mail/0/?prompt=create_account", timeout=20000, wait_until="domcontentloaded")
            page.get_by_text('同意并继续').wait_for(timeout=30000)
            start_time = time.time()
            page.wait_for_timeout(0.1 * self.wait_time)
            page.get_by_text('同意并继续').click(timeout=30000)
        except:
            self.capture_debug_state(page, "entry_failed")
            print("[Error: IP] - IP质量不佳，无法进入注册界面。")
            return False

        try:
            if self.email_suffix == "@hotmail.com":
                page.get_by_text("@outlook.com").click(timeout=10000)
                page.locator(f'[role="option"]:text-is("@hotmail.com")').click()

            page.locator('[aria-label="新建电子邮件"]').type(email, delay=0.006 * self.wait_time, timeout=10000)
            page.locator('[data-testid="primaryButton"]').click(timeout=5000)
            page.wait_for_timeout(0.02 * self.wait_time)
            page.locator('[type="password"]').type(password, delay=0.004 * self.wait_time, timeout=10000)
            page.wait_for_timeout(0.02 * self.wait_time)
            page.locator('[data-testid="primaryButton"]').click(timeout=5000)

            page.wait_for_timeout(0.03 * self.wait_time)
            page.locator('[name="BirthYear"]').fill(year, timeout=10000)

            try:
                page.wait_for_timeout(0.02 * self.wait_time)
                page.locator('[name="BirthMonth"]').select_option(value=month, timeout=1000)
                page.wait_for_timeout(0.05 * self.wait_time)
                page.locator('[name="BirthDay"]').select_option(value=day)
            except:
                page.locator('[name="BirthMonth"]').click()
                page.wait_for_timeout(0.02 * self.wait_time)
                page.locator(f'[role="option"]:text-is("{month}月")').click()
                page.wait_for_timeout(0.04 * self.wait_time)
                page.locator('[name="BirthDay"]').click()
                page.wait_for_timeout(0.03 * self.wait_time)
                page.locator(f'[role="option"]:text-is("{day}日")').click()
                page.locator('[data-testid="primaryButton"]').click(timeout=5000)

            page.locator('#lastNameInput').type(lastname, delay=0.002 * self.wait_time, timeout=10000)
            page.wait_for_timeout(0.02 * self.wait_time)
            page.locator('#firstNameInput').fill(firstname, timeout=10000)

            if time.time() - start_time < self.wait_time / 1000:
                page.wait_for_timeout(self.wait_time - (time.time() - start_time) * 1000)

            page.locator('[data-testid="primaryButton"]').click(timeout=5000)
            page.locator('span > [href="https://go.microsoft.com/fwlink/?LinkID=521839"]').wait_for(state='detached', timeout=22000)
            page.wait_for_timeout(400)

            if page.get_by_text('一些异常活动').count() or page.get_by_text('此站点正在维护，暂时无法使用，请稍后重试。').count() > 0:
                self.capture_debug_state(page, "rate_or_abnormal_after_profile")
                print("[Error: IP or browser] - 当前IP注册频率过快。检查IP与是否为指纹浏览器并关闭了无头模式。")
                return False

            if page.locator('iframe#enforcementFrame').count() > 0:
                self.capture_debug_state(page, "funcaptcha_type_detected")
                print("[Error: FunCaptcha] - 验证码类型错误，非按压验证码。")
                return False

            captcha_result = self.handle_captcha(page)
            if not captcha_result:
                self.capture_debug_state(page, "captcha_result_false")
                raise TimeoutError

        except Exception:
            self.capture_debug_state(page, "register_exception")
            print("[Error: IP] - 加载超时或因触发机器人检测导致按压次数达到最大仍未通过。")
            return False

        if not self.enable_oauth2:
            filename = os.path.join(self.results_dir, 'unlogged_email.txt')
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(f"{email}{self.email_suffix}: {password}\n")
            print(f'[Success: Email Registration] - {email}{self.email_suffix}: {password}')
            return True

        mailbox_ready = False
        try:
            page.locator('[aria-label="新邮件"]').wait_for(timeout=32000)
            mailbox_ready = True
            print(f'[MailboxReady] - {email}{self.email_suffix} mailbox UI initialized.', flush=True)
        except Exception as e:
            self.capture_debug_state(page, "mailbox_init_timeout")
            print(f'[Warn: MailboxInit] - 邮箱界面未在等待时间内初始化，等待 MSA 登录侧账号可用。 error={e}', flush=True)

        try:
            from get_token import wait_msa_login_ready
            account_ready, account_status = wait_msa_login_ready(page, email)
        except Exception as e:
            account_ready = False
            account_status = {"ok": False, "reason": repr(e)}
            print(f"[AccountReady] - probe failed: {account_status}", flush=True)

        if not account_ready:
            pending_file = os.path.join(self.results_dir, 'oauth_pending.txt')
            with open(pending_file, 'a', encoding='utf-8') as f:
                f.write(
                    f"{email}{self.email_suffix}---{password}---"
                    f"mailbox_ready={mailbox_ready}---account_status={json.dumps(account_status, ensure_ascii=False)}\n"
                )
            print(
                f"[Pending: Email Registration] - {email}{self.email_suffix} "
                f"mailbox_ready={mailbox_ready} account_status={account_status}",
                flush=True,
            )
            return False

        filename = os.path.join(self.results_dir, 'logged_email.txt')
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"{email}{self.email_suffix}: {password}\n")
        print(
            f'[Success: Email Registration] - {email}{self.email_suffix}: {password} '
            f'mailbox_ready={mailbox_ready} account_status={account_status}',
            flush=True,
        )
        return True
