import json
import base64
import string
import hashlib
import secrets
import requests
from datetime import datetime
from urllib.request import getproxies
from urllib.parse import quote, parse_qs, urlparse, urljoin
import os
import time
import re
import html
from pathlib import Path
from html.parser import HTMLParser

def get_proxy():
    proxies = getproxies()
    http_proxy = proxies.get('http') or proxies.get('https')
    if http_proxy:
        return {"http": http_proxy, "https": http_proxy}
    return {"http": None, "https": None}


def get_oauth_proxy(data=None, proxy_url=None):
    proxy = (proxy_url or "").strip() or os.environ.get("OUTLOOK_PROXY", "").strip()
    if not proxy and data:
        proxy = str(data.get("proxy", "")).strip()
    if proxy.startswith("http://") or proxy.startswith("https://"):
        return {"http": proxy, "https": proxy}
    if proxy.startswith("socks"):
        print(f"[OAuth2:Protocol] - SOCKS proxy unsupported by requests without extra deps: {proxy}", flush=True)
    return get_proxy()


def _summarize_credential_data(data):
    if not isinstance(data, dict):
        return {"body_type": type(data).__name__}
    credentials = data.get("Credentials") if isinstance(data.get("Credentials"), dict) else {}
    proofs = credentials.get("OtcLoginEligibleProofs")
    summary = {
        "if_exists": data.get("IfExistsResult"),
        "has_password": credentials.get("HasPassword"),
        "has_phone": credentials.get("HasPhone"),
        "has_remote_ngc": credentials.get("HasRemoteNGC"),
        "pref_credential": credentials.get("PrefCredential"),
        "full_password_reset": data.get("FullPasswordResetExperience"),
    }
    if isinstance(proofs, list):
        summary["otc_proof_count"] = len(proofs)
        summary["otc_proof_types"] = [proof.get("type") for proof in proofs[:5] if isinstance(proof, dict)]
    if "raw" in data:
        summary["raw_len"] = len(str(data.get("raw") or ""))
    return summary


def _summarize_credential_status(status):
    if not isinstance(status, dict):
        return {"status_type": type(status).__name__}
    keep = {
        key: status.get(key)
        for key in ("ok", "ready", "status", "if_exists", "has_password", "reason", "has_code")
        if key in status
    }
    if "body" in status:
        keep["body_summary"] = _summarize_credential_data(status.get("body"))
    elif "body_summary" in status:
        keep["body_summary"] = status.get("body_summary")
    if "url" in status:
        parsed = urlparse(str(status.get("url") or ""))
        keep["url"] = f"{parsed.netloc}{parsed.path}"
    return keep


def _is_security_recovery_url(url):
    parsed = urlparse(str(url or ""))
    return parsed.netloc.lower() == "account.live.com" and parsed.path.lower().startswith("/recover")


def generate_code_verifier(length=128):
    alphabet = string.ascii_letters + string.digits + '-._~'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_code_challenge(code_verifier):
    sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode().rstrip('=')


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "form":
            self._current = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").lower(),
                "inputs": {},
            }
            self.forms.append(self._current)
        elif self._current is not None and tag.lower() in ("input", "button"):
            name = attrs.get("name")
            if name:
                self._current["inputs"][name] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._current = None

def _click_if_visible(locator, timeout=3000):
    try:
        if locator.count() > 0:
            locator.first.click(timeout=timeout)
            return True
    except Exception:
        pass
    return False


def _capture_oauth_state(page, label):
    captures_dir = Path(__file__).resolve().parent / "captures"
    captures_dir.mkdir(exist_ok=True)
    ts = int(time.time())
    safe_label = ''.join(ch if ch.isalnum() or ch in ('-', '_') else '_' for ch in label)[:80]
    base = captures_dir / f"oauth_{ts}_{safe_label}"
    data = {"label": label, "timestamp": ts}

    try:
        data["url"] = page.url
    except Exception as e:
        data["url_error"] = repr(e)
    try:
        data["title"] = page.title()
    except Exception as e:
        data["title_error"] = repr(e)
    try:
        data["frames"] = [{"name": frame.name, "url": frame.url} for frame in page.frames]
    except Exception as e:
        data["frames_error"] = repr(e)
    try:
        data["inputs"] = page.locator("input, textarea, select").evaluate_all(
            """els => els.slice(0, 60).map(el => ({
                tag: el.tagName,
                type: el.getAttribute('type'),
                name: el.getAttribute('name'),
                id: el.getAttribute('id'),
                aria: el.getAttribute('aria-label'),
                placeholder: el.getAttribute('placeholder'),
                value_len: (el.value || '').length,
                visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            }))"""
        )
    except Exception as e:
        data["inputs_error"] = repr(e)
    try:
        data["buttons"] = page.locator("button, input[type=submit], [role=button]").evaluate_all(
            """els => els.slice(0, 80).map(el => ({
                tag: el.tagName,
                type: el.getAttribute('type'),
                name: el.getAttribute('name'),
                id: el.getAttribute('id'),
                aria: el.getAttribute('aria-label'),
                text: (el.innerText || el.value || el.textContent || '').slice(0, 120),
                visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            }))"""
        )
    except Exception as e:
        data["buttons_error"] = repr(e)
    try:
        data["texts"] = {
            text: page.get_by_text(text).count()
            for text in (
                "登录到您的帐户",
                "输入密码",
                "保持登录状态",
                "接受",
                "同意",
                "Approve",
                "Accept",
                "Stay signed in",
                "Sign in",
                "Next",
            )
        }
    except Exception as e:
        data["texts_error"] = repr(e)
    try:
        page.screenshot(path=str(base.with_suffix(".png")), full_page=True, timeout=8000)
    except Exception as e:
        data["screenshot_error"] = repr(e)
    try:
        with open(base.with_suffix(".json"), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[OAuth2] - saved state {base}.json", flush=True)
    except Exception as e:
        print(f"[OAuth2] - save state failed: {e}", flush=True)


def _url_has_auth_code(url):
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return bool(params.get("code"))
    except Exception:
        return False


def _url_has_auth_error(url):
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return bool(params.get("error"))
    except Exception:
        return False


def _extract_auth_error(url):
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {
            "error": (params.get("error") or [""])[0],
            "error_description": (params.get("error_description") or [""])[0],
        }
    except Exception as e:
        return {"error": "parse_failed", "error_description": repr(e)}


def _extract_auth_code(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query)["code"][0]


def _is_redirect_navigation(url, redirect_url):
    if not url or not redirect_url:
        return False
    if url.startswith(redirect_url):
        return True
    try:
        current = urlparse(url)
        expected = urlparse(redirect_url)
        return current.scheme == expected.scheme and current.netloc == expected.netloc and current.path == expected.path
    except Exception:
        return False


def _submit_microsoft_form(page):
    submitted = False
    for selector in ['#idSIButton9', 'input[type="submit"]', 'button[type="submit"]']:
        try:
            locator = page.locator(selector)
            if locator.count() > 0:
                locator.first.click(timeout=3000)
                submitted = True
                break
        except Exception:
            pass
    for selector in ['#idSIButton9', 'input[type="submit"]', 'button[type="submit"]']:
        try:
            locator = page.locator(selector)
            if locator.count() > 0:
                locator.first.evaluate("el => el.click()")
                submitted = True
                break
        except Exception:
            pass
    try:
        page.keyboard.press("Enter")
        submitted = True
    except Exception:
        pass
    return submitted


def _set_input_value_native(page, selector, value):
    try:
        return page.evaluate(
            """({selector, value}) => {
                const el = document.querySelector(selector);
                if (!el) return {ok: false, reason: 'missing'};
                el.focus();
                const proto = el instanceof HTMLTextAreaElement
                    ? HTMLTextAreaElement.prototype
                    : HTMLInputElement.prototype;
                const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
                if (descriptor && descriptor.set) descriptor.set.call(el, value);
                else el.value = value;
                el.dispatchEvent(new InputEvent('input', {
                    bubbles: true,
                    inputType: 'insertText',
                    data: value
                }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                el.dispatchEvent(new KeyboardEvent('keydown', {
                    bubbles: true,
                    key: 'Enter',
                    code: 'Enter',
                    keyCode: 13,
                    which: 13
                }));
                el.dispatchEvent(new KeyboardEvent('keyup', {
                    bubbles: true,
                    key: 'Enter',
                    code: 'Enter',
                    keyCode: 13,
                    which: 13
                }));
                return {ok: true, value_len: (el.value || '').length};
            }""",
            {"selector": selector, "value": value},
        )
    except Exception as e:
        return {"ok": False, "error": repr(e)}


def _submit_visible_button_by_text(page, labels):
    try:
        return page.evaluate(
            """labels => {
                const wanted = new Set(labels.map(x => String(x).trim().toLowerCase()));
                const els = Array.from(document.querySelectorAll('button, input[type=submit], [role=button]'));
                const isVisible = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
                const candidates = els.filter(isVisible);
                const target = candidates.find(el => {
                    const text = (el.innerText || el.value || el.textContent || '').trim().toLowerCase();
                    return wanted.has(text);
                }) || candidates.find(el => {
                    const type = (el.getAttribute('type') || '').toLowerCase();
                    return type === 'submit';
                });
                if (!target) return {ok: false, reason: 'missing'};
                target.focus();
                target.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
                target.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
                target.click();
                const form = target.form || target.closest('form');
                if (form && form.requestSubmit) {
                    try { form.requestSubmit(target); } catch (_) { form.requestSubmit(); }
                }
                return {
                    ok: true,
                    tag: target.tagName,
                    id: target.id,
                    text: (target.innerText || target.value || target.textContent || '').trim()
                };
            }""",
            labels,
        )
    except Exception as e:
        return {"ok": False, "error": repr(e)}


def _submit_live_login_step(page, email=None, password=None):
    login_result = {"ok": False, "reason": "not_attempted"}
    password_result = {"ok": False, "reason": "not_attempted"}
    try:
        if email and page.locator("#usernameEntry, input[name='loginfmt'], #i0116, input[type='email']").count() > 0:
            login_result = _set_input_value_native(page, "#usernameEntry, input[name='loginfmt'], #i0116, input[type='email']", email)
    except Exception as e:
        login_result = {"ok": False, "error": repr(e)}
    try:
        if password and page.locator("#passwordEntry, input[name='passwd'], #i0118, input[type='password']").count() > 0:
            password_result = _set_input_value_native(page, "#passwordEntry, input[name='passwd'], #i0118, input[type='password']", password)
    except Exception as e:
        password_result = {"ok": False, "error": repr(e)}
    button_result = _submit_visible_button_by_text(
        page,
        ["下一步", "登录", "是", "接受", "同意", "Next", "Sign in", "Yes", "Accept", "Approve"],
    )
    try:
        page.keyboard.press("Enter")
    except Exception:
        pass
    return {"login": login_result, "password": password_result, "button": button_result}


def _click_microsoft_next(page):
    selectors = [
        '#idSIButton9',
        '#idSubmit_ProofUp_Redirect',
        'input[type="submit"]',
        'button[type="submit"]',
    ]
    for selector in selectors:
        if _click_if_visible(page.locator(selector), timeout=2500):
            return True
    labels = [
        "下一步",
        "登录",
        "是",
        "接受",
        "同意",
        "Next",
        "Sign in",
        "Yes",
        "Accept",
        "Approve",
    ]
    for label in labels:
        if _click_if_visible(page.get_by_text(label, exact=True), timeout=2000):
            return True
    return _submit_microsoft_form(page)


def _set_microsoft_login_values(page, email=None, password=None):
    try:
        return page.evaluate(
            """({email, password}) => {
                const setValue = (el, value) => {
                    if (!el || value === null || value === undefined) return false;
                    el.focus();
                    el.value = value;
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                    return true;
                };
                const login = document.querySelector('input[name="loginfmt"], #i0116, input[type="email"]');
                const pass = document.querySelector('input[name="passwd"], #i0118, input[type="password"]');
                const loginSet = setValue(login, email);
                const passSet = setValue(pass, password);
                const btn = document.querySelector('#idSIButton9, input[type="submit"], button[type="submit"]');
                if (btn) {
                    btn.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                    btn.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                    btn.click();
                }
                const form = (btn && btn.form) || document.querySelector('form');
                if (form && form.requestSubmit) form.requestSubmit();
                else if (form) form.submit();
                return { loginSet, passSet, button: !!btn, form: !!form };
            }""",
            {"email": email, "password": password},
        )
    except Exception as e:
        return {"error": repr(e)}


def _fill_first_visible(page, selectors, value, timeout=3000):
    for selector in selectors:
        try:
            locator = page.locator(selector)
            if locator.count() > 0:
                locator.first.fill(value, timeout=timeout)
                return selector
        except Exception:
            pass
    return ""


def _log_oauth_controls(page):
    try:
        controls = page.locator("input, button").evaluate_all(
            """els => els.slice(0, 20).map(el => ({
                tag: el.tagName,
                type: el.getAttribute('type'),
                name: el.getAttribute('name'),
                id: el.getAttribute('id'),
                aria: el.getAttribute('aria-label'),
                text: el.tagName === 'BUTTON' ? (el.innerText || '').slice(0, 80) : '<redacted>'
            }))"""
        )
        print(f"[OAuth2] - visible controls snapshot: {controls}", flush=True)
    except Exception as e:
        print(f"[OAuth2] - controls snapshot failed: {e}", flush=True)


def handle_oauth2_form(page, email, password=None):
    filled_login = False
    filled_password = False
    consent_clicked = False

    for _ in range(40):
        try:
            if not filled_login:
                login_selector = _fill_first_visible(
                    page,
                    ['[name="loginfmt"]', '#i0116', 'input[type="email"]'],
                    email,
                    timeout=3000,
                )
                if login_selector:
                    print(f"[OAuth2] - filled login via {login_selector}", flush=True)
                    js_result = _set_microsoft_login_values(page, email=email)
                    print(f"[OAuth2] - js submit after login {js_result}", flush=True)
                    live_result = _submit_live_login_step(page, email=email)
                    print(f"[OAuth2] - live submit after login {live_result}", flush=True)
                    _submit_microsoft_form(page)
                    filled_login = True
                    page.wait_for_timeout(1500)

            if password and not filled_password:
                password_selector = _fill_first_visible(
                    page,
                    ['[name="passwd"]', '#i0118', 'input[type="password"]'],
                    password,
                    timeout=3000,
                )
                if password_selector:
                    print(f"[OAuth2] - filled password via {password_selector}", flush=True)
                    js_result = _set_microsoft_login_values(page, email=email, password=password)
                    print(f"[OAuth2] - js submit after password {js_result}", flush=True)
                    live_result = _submit_live_login_step(page, email=email, password=password)
                    print(f"[OAuth2] - live submit after password {live_result}", flush=True)
                    _submit_microsoft_form(page)
                    filled_password = True
                    page.wait_for_timeout(2000)

            if _click_if_visible(page.locator('[data-testid="appConsentPrimaryButton"]'), timeout=2000):
                consent_clicked = True

            _click_microsoft_next(page)

            if consent_clicked:
                return
        except Exception:
            pass
        page.wait_for_timeout(500)


def get_access_token(page, email, password=None, max_retries=3, proxy_url=None):
    method = os.environ.get("OUTLOOK_OAUTH_METHOD", "protocol").strip().lower()
    browser_fallback = os.environ.get("OUTLOOK_OAUTH_BROWSER_FALLBACK", "").strip().lower() in ("1", "true", "yes")
    last_result = (False, False, False)
    if method in ("protocol", "protocol_then_browser"):
        for attempt in range(max_retries):
            result = _try_get_access_token_protocol(page, email, password=password, attempt=attempt + 1, proxy_url=proxy_url)
            last_result = result
            if result[0] is not False:
                return result
        if method == "protocol" and not browser_fallback:
            print("[OAuth2:Protocol] - failed and browser fallback disabled", flush=True)
            return last_result

    for attempt in range(max_retries):
        result = _try_get_access_token(page, email, password=password, attempt=attempt + 1, proxy_url=proxy_url)
        last_result = result
        if result[0] is not False:
            return result
    return last_result

def _safe_page_state(page):
    try:
        url = page.url
    except Exception:
        url = "<url unavailable>"
    try:
        title = page.title()
    except Exception:
        title = "<title unavailable>"
    return url, title


def _load_oauth_settings(email, proxy_url=None):
    with open('config.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    env_scopes = os.environ.get("OUTLOOK_OAUTH_SCOPES", "").strip()
    SCOPES = env_scopes.split() if env_scopes else data['oauth2']['Scopes']
    client_id = os.environ.get("OUTLOOK_OAUTH_CLIENT_ID", "").strip() or data['oauth2']['client_id'].strip()
    redirect_url = os.environ.get("OUTLOOK_OAUTH_REDIRECT_URL", "").strip() or data['oauth2']['redirect_url'].strip()
    tenant = os.environ.get("OUTLOOK_OAUTH_TENANT", "").strip() or str(data['oauth2'].get('tenant', 'consumers')).strip() or "consumers"
    prompt = os.environ.get("OUTLOOK_OAUTH_PROMPT", "consent").strip()
    domain_hint = os.environ.get("OUTLOOK_OAUTH_DOMAIN_HINT", "").strip()
    _email_suffix = data['email_suffix']
    email_full = email if "@" in email else f"{email}{_email_suffix}"
    if not client_id or not redirect_url:
        print(
            "[Error: OAuth2] - missing client_id/redirect_url. "
            "Set config.json oauth2.client_id/oauth2.redirect_url or "
            "OUTLOOK_OAUTH_CLIENT_ID/OUTLOOK_OAUTH_REDIRECT_URL.",
            flush=True,
        )
        return None
    
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    params = {
        'client_id': client_id,
        'response_type': 'code',
        'redirect_uri': redirect_url,
        'scope': ' '.join(SCOPES),
        'response_mode': 'query',
        'login_hint': email_full,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    if prompt:
        params['prompt'] = prompt
    if domain_hint:
        params['domain_hint'] = domain_hint

    authorize_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{'&'.join(f'{k}={quote(v)}' for k, v in params.items())}"
    return {
        "data": data,
        "scopes": SCOPES,
        "client_id": client_id,
        "redirect_url": redirect_url,
        "tenant": tenant,
        "code_verifier": code_verifier,
        "authorize_url": authorize_url,
        "email_full": email_full,
        "proxy_url": proxy_url,
    }


def _exchange_auth_code(settings, auth_code):
    response = requests.post(
        f"https://login.microsoftonline.com/{settings['tenant']}/oauth2/v2.0/token",
        data={
            'client_id': settings["client_id"],
            'code': auth_code,
            'redirect_uri': settings["redirect_url"],
            'grant_type': 'authorization_code',
            'code_verifier': settings["code_verifier"],
            'scope': ' '.join(settings["scopes"])
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        proxies=get_oauth_proxy(settings.get("data"), settings.get("proxy_url")),
        timeout=30,
    )

    try:
        tokens = response.json()
    except Exception:
        print(
            f"[Error: OAuth2] - token response is not json "
            f"status={response.status_code} body={response.text[:300]}",
            flush=True,
        )
        return False, False, False
    if 'refresh_token' in tokens:
        return (
            tokens['refresh_token'],
            tokens.get('access_token', ''),
            datetime.now().timestamp() + tokens.get('expires_in', 3600)
        )
    print(
        f"[Error: OAuth2] - token response missing refresh_token "
        f"status={response.status_code} body={str(tokens)[:300]}",
        flush=True,
    )
    return False, False, False


def _session_from_page_context(page):
    session = requests.Session()
    if page is None:
        session.headers.update({
            "User-Agent": os.environ.get(
                "OUTLOOK_OAUTH_USER_AGENT",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        print("[OAuth2:Protocol] - no browser page; using protocol-only session", flush=True)
        return session
    try:
        user_agent = page.evaluate("() => navigator.userAgent")
    except Exception:
        user_agent = ""
    session.headers.update({
        "User-Agent": user_agent or "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    cookies = []
    try:
        cookies = page.context.cookies()
    except Exception as e:
        print(f"[OAuth2:Protocol] - export cookies failed: {e}", flush=True)
    for cookie in cookies:
        domain = cookie.get("domain") or ""
        if not any(part in domain for part in ("live.com", "microsoft.com", "microsoftonline.com", "outlook.com")):
            continue
        session.cookies.set(
            cookie.get("name", ""),
            cookie.get("value", ""),
            domain=domain,
            path=cookie.get("path") or "/",
            secure=bool(cookie.get("secure")),
        )
    print(f"[OAuth2:Protocol] - imported Microsoft cookies={len(session.cookies)}", flush=True)
    return session


def _parse_forms(html):
    parser = _FormParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass
    return parser.forms


def _extract_js_string(text, key):
    match = re.search(r'"' + re.escape(key) + r'"\s*:\s*"((?:\\.|[^"\\])*)"', text or "")
    if not match:
        return ""
    try:
        return json.loads(f'"{match.group(1)}"')
    except Exception:
        return ""


def _submit_msa_config_login(session, response, email, password):
    if not password:
        return None, "missing_password"

    url_post = _extract_js_string(response.text, "urlPost") or _extract_js_string(response.text, "urlPostMsa")
    url_get_credential = _extract_js_string(response.text, "urlGetCredentialType")
    ft_tag = html.unescape(_extract_js_string(response.text, "sFTTag"))
    ppft_match = re.search(r'name="PPFT"[^>]*value="([^"]+)"', ft_tag)
    if not url_post or not ppft_match:
        return None, "no_msa_config"

    ppft = ppft_match.group(1)
    uaid = _extract_js_string(response.text, "sUnauthSessionID")
    hpgid = _extract_js_string(response.text, "hpgid")
    if url_get_credential:
        credential_payload = {
            "username": email,
            "uaid": uaid,
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": False,
            "forceotclogin": False,
            "otclogindisallowed": False,
            "isExternalFederationDisallowed": False,
            "isRemoteConnectSupported": False,
            "federationFlags": 3,
            "isSignup": False,
            "flowToken": ppft,
        }
        try:
            credential_response = session.post(
                url_get_credential,
                json=credential_payload,
                headers={
                    "Referer": response.url,
                    "Origin": "https://login.live.com",
                    "hpgid": str(hpgid or ""),
                    "hpgact": "0",
                },
                allow_redirects=False,
                timeout=30,
            )
            try:
                credential_data = credential_response.json()
            except Exception:
                credential_data = {}
            print(
                f"[OAuth2:Protocol] - GetCredentialType status={credential_response.status_code} "
                f"summary={_summarize_credential_data(credential_data)}",
                flush=True,
            )
            credentials = credential_data.get("Credentials") if isinstance(credential_data, dict) else {}
            if isinstance(credential_data, dict) and credential_data.get("IfExistsResult") == 1:
                print("[OAuth2:Protocol] - account not visible to MSA login yet", flush=True)
                return None, "account_not_visible"
            if isinstance(credentials, dict) and credentials.get("HasPassword") == 0:
                print("[OAuth2:Protocol] - MSA account has no password credential", flush=True)
                return None, "account_without_password"
        except Exception as e:
            print(f"[OAuth2:Protocol] - GetCredentialType failed: {e}", flush=True)

    data = {
        "login": email,
        "loginfmt": email,
        "passwd": password,
        "PPFT": ppft,
        "PPSX": "Passpor",
        "NewUser": "1",
        "LoginOptions": "3",
        "type": "11",
        "i13": "0",
        "ps": "2",
        "flowToken": ppft,
        "fspost": "0",
        "CookieDisclosure": "0",
        "IsFidoSupported": "0",
        "isSignupPost": "0",
        "isRecoveryAttemptPost": "0",
        "i19": "3772",
    }
    print(
        f"[OAuth2:Protocol] - submitting MSA config login url={urlparse(url_post).netloc}{urlparse(url_post).path} "
        f"ppft_len={len(ppft)}",
        flush=True,
    )
    login_response = session.post(
        url_post,
        data=data,
        headers={"Referer": response.url, "Origin": "https://login.live.com"},
        allow_redirects=False,
        timeout=30,
    )
    print(
        f"[OAuth2:Protocol] - MSA config login status={login_response.status_code} "
        f"url={urlparse(login_response.url).netloc}{urlparse(login_response.url).path} "
        f"location={login_response.headers.get('Location', '')[:160]}",
        flush=True,
    )
    return login_response, "posted_msa_config"


def _fetch_msa_credential_status(page, email):
    settings = _load_oauth_settings(email)
    if not settings:
        return {"ok": False, "reason": "missing_oauth_settings"}

    session = _session_from_page_context(page)
    proxies = get_oauth_proxy(settings.get("data"))
    session.proxies.update({k: v for k, v in (proxies or {}).items() if v})
    try:
        response = session.get(settings["authorize_url"], allow_redirects=False, proxies=proxies, timeout=30)
        if response.status_code in (301, 302, 303, 307, 308):
            response = session.get(urljoin(response.url, response.headers.get("Location", "")), allow_redirects=False, timeout=30)

        url_get_credential = _extract_js_string(response.text, "urlGetCredentialType")
        ft_tag = html.unescape(_extract_js_string(response.text, "sFTTag"))
        ppft_match = re.search(r'name="PPFT"[^>]*value="([^"]+)"', ft_tag)
        if not url_get_credential or not ppft_match:
            return {
                "ok": False,
                "reason": "missing_get_credential_config",
                "status": response.status_code,
                "url": response.url,
                "has_code": _is_redirect_navigation(response.url, settings["redirect_url"]) and _url_has_auth_code(response.url),
            }

        ppft = ppft_match.group(1)
        credential_response = session.post(
            url_get_credential,
            json={
                "username": settings["email_full"],
                "uaid": _extract_js_string(response.text, "sUnauthSessionID"),
                "isOtherIdpSupported": True,
                "checkPhones": False,
                "isRemoteNGCSupported": True,
                "isCookieBannerShown": False,
                "isFidoSupported": False,
                "forceotclogin": False,
                "otclogindisallowed": False,
                "isExternalFederationDisallowed": False,
                "isRemoteConnectSupported": False,
                "federationFlags": 3,
                "isSignup": False,
                "flowToken": ppft,
            },
            headers={
                "Referer": response.url,
                "Origin": "https://login.live.com",
                "hpgid": str(_extract_js_string(response.text, "hpgid") or ""),
                "hpgact": "0",
            },
            allow_redirects=False,
            timeout=30,
        )
        try:
            data = credential_response.json()
        except Exception:
            data = {"raw": credential_response.text[:300]}
        credentials = data.get("Credentials") if isinstance(data, dict) else {}
        ready = bool(isinstance(credentials, dict) and credentials.get("HasPassword") == 1)
        if not ready and isinstance(data, dict):
            ready = data.get("IfExistsResult") == 0
        return {
            "ok": True,
            "ready": ready,
            "status": credential_response.status_code,
            "if_exists": data.get("IfExistsResult") if isinstance(data, dict) else None,
            "has_password": credentials.get("HasPassword") if isinstance(credentials, dict) else None,
            "body_summary": _summarize_credential_data(data),
        }
    except Exception as e:
        return {"ok": False, "reason": repr(e)}


def wait_msa_login_ready(page, email, max_wait_seconds=None, interval_seconds=None):
    if max_wait_seconds is None:
        max_wait_seconds = int(os.environ.get("OUTLOOK_ACCOUNT_READY_WAIT_SECONDS", "240"))
    if interval_seconds is None:
        interval_seconds = int(os.environ.get("OUTLOOK_ACCOUNT_READY_POLL_SECONDS", "12"))
    deadline = time.time() + max_wait_seconds
    attempt = 0
    last_status = {}

    while True:
        attempt += 1
        last_status = _fetch_msa_credential_status(page, email)
        print(f"[AccountReady] - attempt={attempt} status={_summarize_credential_status(last_status)}", flush=True)
        if last_status.get("ready"):
            return True, last_status
        if time.time() >= deadline:
            return False, last_status
        time.sleep(max(1, interval_seconds))


def _submit_protocol_form(session, response, email, password):
    forms = _parse_forms(response.text)
    if not forms:
        return _submit_msa_config_login(session, response, email, password)

    def form_score(item):
        inputs = item.get("inputs") or {}
        keys = {key.lower() for key in inputs}
        score = 0
        if {"loginfmt", "login", "username", "email"} & keys:
            score += 3
        if {"passwd", "password"} & keys:
            score += 3
        if {"otc", "code", "proofconfirmation"} & keys:
            score += 1
        if item.get("action"):
            score += 1
        return score

    form = max(forms, key=form_score)
    data = dict(form.get("inputs") or {})
    keys = set(data)
    lowered = {k.lower(): k for k in keys}

    login_key = lowered.get("loginfmt") or lowered.get("login") or lowered.get("username") or lowered.get("email")
    password_key = lowered.get("passwd") or lowered.get("password")
    if login_key:
        data[login_key] = email
    if password_key and password:
        data[password_key] = password

    action = form.get("action") or response.url
    url = urljoin(response.url, action)
    if _is_security_recovery_url(url):
        print("[OAuth2:Protocol] - security recovery form detected; stopping protocol login", flush=True)
        return None, "security_recovery_required"
    method = (form.get("method") or "get").lower()
    headers = {"Referer": response.url, "Origin": f"{urlparse(response.url).scheme}://{urlparse(response.url).netloc}"}
    print(
        f"[OAuth2:Protocol] - submitting form method={method} url={urlparse(url).netloc}{urlparse(url).path} "
        f"login_field={bool(login_key)} password_field={bool(password_key)} keys={len(data)}",
        flush=True,
    )
    if method == "post":
        return session.post(url, data=data, headers=headers, allow_redirects=False, timeout=30), "posted_form"
    return session.get(url, params=data, headers=headers, allow_redirects=False, timeout=30), "submitted_form"


def _try_get_access_token_protocol(page, email, password=None, attempt=1, proxy_url=None):
    settings = _load_oauth_settings(email, proxy_url=proxy_url)
    if not settings:
        return False, False, False

    session = _session_from_page_context(page)
    proxies = get_oauth_proxy(settings.get("data"), settings.get("proxy_url"))
    session.proxies.update({k: v for k, v in (proxies or {}).items() if v})
    url = settings["authorize_url"]
    pending_response = None
    print(f"[OAuth2:Protocol] - authorize attempt {attempt} tenant={settings['tenant']}", flush=True)

    try:
        for step in range(12):
            if pending_response is None:
                response = session.get(url, allow_redirects=False, proxies=proxies, timeout=30)
            else:
                response = pending_response
                pending_response = None
            print(
                f"[OAuth2:Protocol] - step={step} status={response.status_code} "
                f"url={urlparse(response.url).netloc}{urlparse(response.url).path}",
                flush=True,
            )

            if _is_redirect_navigation(response.url, settings["redirect_url"]) and _url_has_auth_code(response.url):
                return _exchange_auth_code(settings, _extract_auth_code(response.url))
            if _is_redirect_navigation(response.url, settings["redirect_url"]) and _url_has_auth_error(response.url):
                print(f"[OAuth2:Protocol] - redirect auth error {_extract_auth_error(response.url)}", flush=True)
                return False, False, False
            if _is_security_recovery_url(response.url):
                print("[OAuth2:Protocol] - security recovery required; stopping protocol login", flush=True)
                return False, "security_recovery_required", False

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                next_url = urljoin(response.url, location)
                if _is_redirect_navigation(next_url, settings["redirect_url"]) and _url_has_auth_code(next_url):
                    print("[OAuth2:Protocol] - captured code from redirect", flush=True)
                    return _exchange_auth_code(settings, _extract_auth_code(next_url))
                if _is_redirect_navigation(next_url, settings["redirect_url"]) and _url_has_auth_error(next_url):
                    print(f"[OAuth2:Protocol] - redirect auth error {_extract_auth_error(next_url)}", flush=True)
                    return False, False, False
                url = next_url
                continue

            if response.status_code >= 400:
                print(f"[OAuth2:Protocol] - stopping on http {response.status_code}", flush=True)
                break

            submitted, reason = _submit_protocol_form(session, response, settings["email_full"], password)
            if submitted is None:
                print(f"[OAuth2:Protocol] - no protocol form progress reason={reason}", flush=True)
                if reason == "security_recovery_required":
                    return False, reason, False
                break
            response = submitted
            if _is_redirect_navigation(response.url, settings["redirect_url"]) and _url_has_auth_code(response.url):
                return _exchange_auth_code(settings, _extract_auth_code(response.url))
            if _is_redirect_navigation(response.url, settings["redirect_url"]) and _url_has_auth_error(response.url):
                print(f"[OAuth2:Protocol] - form auth error {_extract_auth_error(response.url)}", flush=True)
                return False, False, False
            if _is_security_recovery_url(response.url):
                print("[OAuth2:Protocol] - security recovery required after form submit; stopping protocol login", flush=True)
                return False, "security_recovery_required", False
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                url = urljoin(response.url, location)
                if _is_redirect_navigation(url, settings["redirect_url"]) and _url_has_auth_code(url):
                    print("[OAuth2:Protocol] - captured code from form redirect", flush=True)
                    return _exchange_auth_code(settings, _extract_auth_code(url))
                if _is_redirect_navigation(url, settings["redirect_url"]) and _url_has_auth_error(url):
                    print(f"[OAuth2:Protocol] - form auth error {_extract_auth_error(url)}", flush=True)
                    return False, False, False
                if _is_security_recovery_url(url):
                    print("[OAuth2:Protocol] - security recovery redirect required; stopping protocol login", flush=True)
                    return False, "security_recovery_required", False
                continue
            url = response.url
            pending_response = response
    except Exception as e:
        print(f"[OAuth2:Protocol] - failed: {e}", flush=True)

    return False, False, False


def _try_get_access_token(page, email, password=None, attempt=1, proxy_url=None):
    settings = _load_oauth_settings(email, proxy_url=proxy_url)
    if not settings:
        return False, False, False
    SCOPES = settings["scopes"]
    client_id = settings["client_id"]
    redirect_url = settings["redirect_url"]
    tenant = settings["tenant"]
    code_verifier = settings["code_verifier"]
    authorize_url = settings["authorize_url"]
    email_full = settings["email_full"]
    print(f"[OAuth2] - authorize attempt {attempt} tenant={tenant}", flush=True)

    captured_url = None

    def on_request(request):
        nonlocal captured_url
        if _is_redirect_navigation(request.url, redirect_url) and _url_has_auth_code(request.url):
            captured_url = request.url
            print("[OAuth2] - captured code from request", flush=True)

    def on_frame_navigated(frame):
        nonlocal captured_url
        try:
            url = frame.url
        except Exception:
            return
        if _is_redirect_navigation(url, redirect_url) and _url_has_auth_code(url):
            captured_url = url
            print("[OAuth2] - captured code from frame navigation", flush=True)

    page.on("request", on_request)
    page.on("framenavigated", on_frame_navigated)

    try:
        try:
            page.wait_for_timeout(250)
            page.goto(authorize_url, timeout=30000, wait_until="domcontentloaded")
        except Exception as e:
            print(f"[Error: OAuth2] - authorize navigation failed: {e}", flush=True)
            return False, False, False

        handle_oauth2_form(page, email_full, password=password)
        _log_oauth_controls(page)

        max_refreshes = 1
        refresh_count = 0
        refresh_interval = 200 

        for i in range(400):
            page.wait_for_timeout(100)
            if _is_redirect_navigation(page.url, redirect_url) and _url_has_auth_code(page.url):
                captured_url = page.url
                print("[OAuth2] - captured code from current page url", flush=True)
                break
            if captured_url:
                break

            if i > 0 and i % refresh_interval == 0:
                if refresh_count >= max_refreshes:
                    url, title = _safe_page_state(page)
                    _capture_oauth_state(page, f"code_not_captured_refresh_limit_attempt_{attempt}")
                    print(f"[Error: OAuth2] - code not captured before refresh limit url={url} title={title}", flush=True)
                    return False, False, False
                refresh_count += 1
                try:
                    page.reload(timeout=10000)
                except:
                    pass
        else:
            url, title = _safe_page_state(page)
            _capture_oauth_state(page, f"authorization_code_not_captured_attempt_{attempt}")
            print(f"[Error: OAuth2] - authorization code not captured url={url} title={title}", flush=True)
            return False, False, False

    finally:
        page.remove_listener("request", on_request)
        page.remove_listener("framenavigated", on_frame_navigated)

    if not captured_url or 'code=' not in captured_url:
        url, title = _safe_page_state(page)
        _capture_oauth_state(page, f"missing_captured_code_attempt_{attempt}")
        print(f"[Error: OAuth2] - missing captured code url={url} title={title}", flush=True)
        return False, False, False

    auth_code = _extract_auth_code(captured_url)

    try:
        return _exchange_auth_code(settings, auth_code)
    except Exception as e:
        print(f"[Error: OAuth2] - token exchange failed: {e}", flush=True)
        return False, False, False

    return False, False, False
