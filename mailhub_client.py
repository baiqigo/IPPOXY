import json
import os
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


def import_outlook_account(email, password, client_id, refresh_token):
    base_url = os.environ.get("MAIL_HUB_URL", "").strip().rstrip("/")
    if not base_url:
        return {"enabled": False}

    api_secret = get_mailhub_bearer_token()
    account_type = os.environ.get("MAIL_HUB_OUTLOOK_TYPE", "long").strip() or "long"
    group = os.environ.get("MAIL_HUB_OUTLOOK_GROUP", "IPPOXY").strip() or "IPPOXY"

    payload = {
        "accounts": format_outlook_import_line(email, password, client_id, refresh_token),
        "type": account_type,
        "group": group,
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_secret:
        headers["Authorization"] = f"Bearer {api_secret}"

    req = request.Request(
        f"{base_url}/api/outlook/import",
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {"enabled": True, "ok": 200 <= resp.status < 300, "status": resp.status, "data": data}
    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        return {"enabled": True, "ok": False, "status": e.code, "error": error_body}
    except URLError as e:
        return {"enabled": True, "ok": False, "error": str(e.reason)}
    except (TimeoutError, SocketTimeout) as e:
        return {"enabled": True, "ok": False, "error": str(e)}
