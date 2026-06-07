import json
import base64
import string
import hashlib
import secrets
import requests
from datetime import datetime
from urllib.request import getproxies
from urllib.parse import quote, parse_qs
import os

def get_proxy():
    proxies = getproxies()
    http_proxy = proxies.get('http') or proxies.get('https')
    if http_proxy:
        return {"http": http_proxy, "https": http_proxy}
    return {"http": None, "https": None}

def generate_code_verifier(length=128):
    alphabet = string.ascii_letters + string.digits + '-._~'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_code_challenge(code_verifier):
    sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode().rstrip('=')

def _click_if_visible(locator, timeout=3000):
    try:
        if locator.count() > 0:
            locator.first.click(timeout=timeout)
            return True
    except Exception:
        pass
    return False


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
                text: (el.innerText || el.value || '').slice(0, 80)
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
                    _click_if_visible(page.locator('#idSIButton9, input[type="submit"], button[type="submit"]'), timeout=3000)
                    filled_login = True
                    page.wait_for_timeout(700)

            if password and not filled_password:
                password_selector = _fill_first_visible(
                    page,
                    ['[name="passwd"]', '#i0118', 'input[type="password"]'],
                    password,
                    timeout=3000,
                )
                if password_selector:
                    print(f"[OAuth2] - filled password via {password_selector}", flush=True)
                    _click_if_visible(page.locator('#idSIButton9, input[type="submit"], button[type="submit"]'), timeout=5000)
                    filled_password = True
                    page.wait_for_timeout(1000)

            if _click_if_visible(page.locator('[data-testid="appConsentPrimaryButton"]'), timeout=2000):
                consent_clicked = True

            _click_if_visible(page.locator('#idSIButton9, input[type="submit"], button[type="submit"]'), timeout=1000)

            if consent_clicked:
                return
        except Exception:
            pass
        page.wait_for_timeout(500)


def get_access_token(page, email, password=None, max_retries=3):
    for attempt in range(max_retries):
        result = _try_get_access_token(page, email, password=password, attempt=attempt + 1)
        if result[0] is not False:
            return result
    return False, False, False

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


def _try_get_access_token(page, email, password=None, attempt=1):
    with open('config.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    env_scopes = os.environ.get("OUTLOOK_OAUTH_SCOPES", "").strip()
    SCOPES = env_scopes.split() if env_scopes else data['oauth2']['Scopes']
    client_id = os.environ.get("OUTLOOK_OAUTH_CLIENT_ID", "").strip() or data['oauth2']['client_id'].strip()
    redirect_url = os.environ.get("OUTLOOK_OAUTH_REDIRECT_URL", "").strip() or data['oauth2']['redirect_url'].strip()
    _email_suffix = data['email_suffix']
    if not client_id or not redirect_url:
        print(
            "[Error: OAuth2] - missing client_id/redirect_url. "
            "Set config.json oauth2.client_id/oauth2.redirect_url or "
            "OUTLOOK_OAUTH_CLIENT_ID/OUTLOOK_OAUTH_REDIRECT_URL.",
            flush=True,
        )
        return False, False, False
    
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    params = {
        'client_id': client_id,
        'response_type': 'code',
        'redirect_uri': redirect_url,
        'scope': ' '.join(SCOPES),
        'response_mode': 'query',
        'prompt': 'select_account',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    authorize_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{'&'.join(f'{k}={quote(v)}' for k, v in params.items())}"
    print(f"[OAuth2] - authorize attempt {attempt}", flush=True)

    captured_url = None

    def on_request(request):
        nonlocal captured_url
        if redirect_url in request.url and 'code=' in request.url:
            captured_url = request.url

    page.on("request", on_request)

    try:
        try:
            page.wait_for_timeout(250)
            page.goto(authorize_url, timeout=30000, wait_until="domcontentloaded")
        except Exception as e:
            print(f"[Error: OAuth2] - authorize navigation failed: {e}", flush=True)
            return False, False, False

        handle_oauth2_form(page, f"{email}{_email_suffix}", password=password)
        _log_oauth_controls(page)

        max_refreshes = 1
        refresh_count = 0
        refresh_interval = 200 

        for i in range(400):
            page.wait_for_timeout(100)
            if captured_url:
                break

            if i > 0 and i % refresh_interval == 0:
                if refresh_count >= max_refreshes:
                    url, title = _safe_page_state(page)
                    print(f"[Error: OAuth2] - code not captured before refresh limit url={url} title={title}", flush=True)
                    return False, False, False
                refresh_count += 1
                try:
                    page.reload(timeout=10000)
                except:
                    pass
        else:
            url, title = _safe_page_state(page)
            print(f"[Error: OAuth2] - authorization code not captured url={url} title={title}", flush=True)
            return False, False, False

    finally:
        page.remove_listener("request", on_request)

    if not captured_url or 'code=' not in captured_url:
        url, title = _safe_page_state(page)
        print(f"[Error: OAuth2] - missing captured code url={url} title={title}", flush=True)
        return False, False, False

    auth_code = parse_qs(captured_url.split('?')[1])['code'][0]

    try:
        response = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            data={
                'client_id': client_id,
                'code': auth_code,
                'redirect_uri': redirect_url,
                'grant_type': 'authorization_code',
                'code_verifier': code_verifier,
                'scope': ' '.join(SCOPES)
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            proxies=get_proxy(),
            timeout=30,
        )

        tokens = response.json()
        if 'refresh_token' in tokens:
            return (
                tokens['refresh_token'],
                tokens.get('access_token', ''),
                datetime.now().timestamp() + tokens['expires_in']
            )
        print(
            f"[Error: OAuth2] - token response missing refresh_token "
            f"status={response.status_code} body={str(tokens)[:300]}",
            flush=True,
        )
    except Exception as e:
        print(f"[Error: OAuth2] - token exchange failed: {e}", flush=True)
        return False, False, False

    return False, False, False
