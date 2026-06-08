import json
import os
from urllib.parse import quote, urlencode
from urllib import request
from urllib.error import HTTPError, URLError
from socket import timeout as SocketTimeout


def format_outlook_import_line(email, password, client_id, refresh_token):
    return f"{email}----{password}----{client_id}----{refresh_token}"


def get_mailhub_bearer_token():
    for name in (
        "MAIL_HUB_API_SECRET",
        "MAILPILOT_TOKEN",
        "MAILPILOT_API_KEY",
        "MAILPILOT_API_SECRET",
    ):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def get_mailhub_base_url():
    configured = os.environ.get("MAIL_HUB_URL", "").strip().rstrip("/")
    if configured:
        return configured
    if get_mailhub_bearer_token():
        return "http://127.0.0.1:3100"
    return ""


def _parse_json_body(body):
    if not body:
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"raw": body[:500]}


def mailhub_request(method, path, payload=None, params=None, timeout=20):
    base_url = get_mailhub_base_url()
    if not base_url:
        return {"enabled": False}

    normalized_path = "/" + path.lstrip("/")
    url = f"{base_url}{normalized_path}"
    if params:
        url = f"{url}?{urlencode(params)}"

    headers = {}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")

    api_secret = get_mailhub_bearer_token()
    if api_secret:
        headers["Authorization"] = f"Bearer {api_secret}"

    req = request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            response_body = resp.read().decode("utf-8", errors="replace")
            return {
                "enabled": True,
                "ok": 200 <= resp.status < 300,
                "status": resp.status,
                "data": _parse_json_body(response_body),
            }
    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        return {
            "enabled": True,
            "ok": False,
            "status": e.code,
            "error": error_body[:1000],
            "data": _parse_json_body(error_body),
        }
    except URLError as e:
        return {"enabled": True, "ok": False, "error": str(e.reason)}
    except (TimeoutError, SocketTimeout) as e:
        return {"enabled": True, "ok": False, "error": str(e)}


def import_outlook_account(email, password, client_id, refresh_token):
    account_type = os.environ.get("MAIL_HUB_OUTLOOK_TYPE", "long").strip() or "long"
    group = os.environ.get("MAIL_HUB_OUTLOOK_GROUP", "IPPOXY").strip() or "IPPOXY"

    payload = {
        "accounts": format_outlook_import_line(email, password, client_id, refresh_token),
        "type": account_type,
        "group": group,
    }
    return mailhub_request("POST", "/api/outlook/import", payload=payload, timeout=20)


def get_outlook_stats():
    return mailhub_request("GET", "/api/outlook/stats", timeout=10)


def acquire_outlook_inbox(service="ippoxy-smoke", username="", duration=None, need_polling=None):
    payload = {
        "provider": "outlook",
        "for": service or "ippoxy-smoke",
    }
    if username:
        payload["username"] = username
    if duration is not None:
        payload["duration"] = duration
    if need_polling is not None:
        payload["needPolling"] = bool(need_polling)
    return mailhub_request("POST", "/api/inbox", payload=payload, timeout=20)


def list_inbox_messages(inbox_id, provider="outlook"):
    return mailhub_request(
        "GET",
        f"/api/inbox/{quote(str(inbox_id), safe='')}/messages",
        params={"provider": provider},
        timeout=20,
    )


def get_inbox_code(inbox_id, provider="outlook", wait=False, code_type="numeric", timeout=None, keyword=""):
    params = {
        "provider": provider,
        "wait": "true" if wait else "false",
        "type": code_type,
    }
    if timeout is not None:
        params["timeout"] = int(timeout)
    if keyword:
        params["keyword"] = keyword
    return mailhub_request(
        "GET",
        f"/api/inbox/{quote(str(inbox_id), safe='')}/code",
        params=params,
        timeout=max(20, int(timeout or 0) + 5),
    )


def report_inbox(inbox_id, success, provider="outlook", meta=None):
    payload = {
        "provider": provider,
        "success": bool(success),
        "meta": meta or {},
    }
    result = mailhub_request(
        "POST",
        f"/api/inbox/{quote(str(inbox_id), safe='')}/report",
        payload=payload,
        timeout=10,
    )
    if result.get("status") in (404, 405):
        legacy_payload = {
            "provider": provider,
            "email": str(inbox_id),
            "success": bool(success),
            "meta": meta or {},
        }
        return mailhub_request("POST", "/api/inbox/report", payload=legacy_payload, timeout=10)
    return result


def release_inbox(inbox_id, provider="outlook"):
    result = mailhub_request(
        "DELETE",
        f"/api/inbox/{quote(str(inbox_id), safe='')}",
        params={"provider": provider},
        timeout=10,
    )
    if result.get("status") in (404, 405):
        return mailhub_request(
            "DELETE",
            "/api/inbox",
            payload={"provider": provider, "emails": [str(inbox_id)]},
            timeout=10,
        )
    return result
