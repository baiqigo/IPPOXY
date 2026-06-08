import argparse
import json
import os
from pathlib import Path

import requests

from mailhub_client import import_outlook_account


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "Results"


def _parse_token_line(line):
    parts = line.rstrip("\n").split("---")
    if len(parts) < 4:
        return None
    email, password, refresh_token = parts[0].strip(), parts[1].strip(), parts[2].strip()
    if not email or not password or not refresh_token:
        return None
    return {
        "email": email,
        "password": password,
        "refresh_token": refresh_token,
    }


def load_token_accounts(path):
    if not path.exists():
        return []
    accounts_by_email = {}
    order = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        item = _parse_token_line(line)
        if not item:
            continue
        key = item["email"].lower()
        if key not in accounts_by_email:
            order.append(key)
        accounts_by_email[key] = item
    return [accounts_by_email[key] for key in order]


def mask_email(email):
    if "@" not in email:
        return "<invalid-email>"
    prefix, domain = email.split("@", 1)
    return f"{prefix[:3]}***@{domain}"


def _oauth_settings(config):
    oauth2 = config.get("oauth2", {})
    scopes = os.environ.get("OUTLOOK_OAUTH_SCOPES", "").strip().split()
    if not scopes:
        scopes = list(oauth2.get("Scopes") or [])
    tenant = os.environ.get("OUTLOOK_OAUTH_TENANT", "").strip() or str(oauth2.get("tenant", "consumers")).strip() or "consumers"
    token_url = (
        os.environ.get("OUTLOOK_OAUTH_TOKEN_URL", "").strip()
        or f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    )
    return {
        "config": config,
        "scopes": scopes,
        "tenant": tenant,
        "token_url": token_url,
    }


def validate_refresh_token(refresh_token, client_id, settings, timeout=20):
    if not refresh_token:
        return {"ok": False, "reason": "missing_refresh_token"}
    payload = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if settings.get("scopes"):
        payload["scope"] = " ".join(settings["scopes"])
    try:
        from get_token import get_oauth_proxy

        response = requests.post(
            settings["token_url"],
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            proxies=get_oauth_proxy(settings.get("config")),
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return {"ok": False, "reason": "request_failed", "error": str(exc)[:240]}

    try:
        data = response.json()
    except ValueError:
        data = {"raw_len": len(response.text or "")}

    if not (200 <= response.status_code < 300):
        return {
            "ok": False,
            "status": response.status_code,
            "reason": data.get("error") if isinstance(data, dict) else "token_http_error",
            "error_description": str(data.get("error_description", ""))[:240] if isinstance(data, dict) else "",
        }

    access_token = data.get("access_token") if isinstance(data, dict) else ""
    return {
        "ok": bool(access_token),
        "status": response.status_code,
        "token_type": data.get("token_type") if isinstance(data, dict) else "",
        "expires_in": data.get("expires_in") if isinstance(data, dict) else None,
        "access_token_len": len(access_token or ""),
        "reason": "" if access_token else "missing_access_token",
    }


def write_json_report(path, data):
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=str(RESULTS / "outlook_token.txt"))
    parser.add_argument("--email", default="")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--validate-refresh", action="store_true", help="Refresh each token before importing it.")
    parser.add_argument("--validation-report", default="", help="Write a redacted refresh-token validation report.")
    parser.add_argument("--validation-timeout", type=int, default=20)
    parser.add_argument("--verify-pool", action="store_true", help="After imports, run a MailHub Outlook pool smoke.")
    parser.add_argument("--smoke-service", default="ippoxy-backfill-smoke")
    parser.add_argument("--smoke-report", default="", help="Write the redacted pool smoke report to this path.")
    parser.add_argument("--expect-min-available", type=int, default=-1)
    args = parser.parse_args()

    with open(ROOT / "config.json", "r", encoding="utf-8") as f:
        config = json.load(f)
    client_id = os.environ.get("OUTLOOK_OAUTH_CLIENT_ID", "").strip() or config["oauth2"]["client_id"].strip()
    oauth_settings = _oauth_settings(config)

    accounts = load_token_accounts(Path(args.path))
    if args.email:
        wanted = args.email.strip().lower()
        accounts = [item for item in accounts if item["email"].lower() == wanted]
    accounts = accounts[: args.limit]

    print(
        f"[MailHubBackfill] - candidates={len(accounts)} dry_run={args.dry_run} "
        f"validate_refresh={args.validate_refresh}",
        flush=True,
    )
    success = 0
    validation_report = []
    for item in accounts:
        refresh_valid = True
        validation = {"ok": True, "skipped": True}
        if args.validate_refresh:
            validation = validate_refresh_token(
                item["refresh_token"],
                client_id,
                oauth_settings,
                timeout=args.validation_timeout,
            )
            refresh_valid = bool(validation.get("ok"))
            public_validation = {
                key: validation.get(key)
                for key in ("ok", "status", "token_type", "expires_in", "access_token_len", "reason", "error_description", "error")
                if key in validation
            }
            print(
                f"[MailHubBackfill] - validate email={mask_email(item['email'])} "
                f"ok={public_validation.get('ok')} result={public_validation}",
                flush=True,
            )
            validation_report.append({"email": mask_email(item["email"]), **public_validation})
        if not refresh_valid:
            print(f"[MailHubBackfill] - skip invalid refresh email={mask_email(item['email'])}", flush=True)
            continue

        if args.dry_run:
            result = {"enabled": True, "ok": True, "dry_run": True}
        else:
            result = import_outlook_account(
                item["email"],
                item["password"],
                client_id,
                item["refresh_token"],
            )
        public_result = dict(result)
        data = public_result.get("data")
        if isinstance(data, dict):
            public_result["data"] = {
                key: data.get(key)
                for key in ("imported", "duplicated", "skipped", "total", "success")
                if key in data
            }
        print(
            f"[MailHubBackfill] - email={mask_email(item['email'])} "
            f"ok={public_result.get('ok')} result={public_result}",
            flush=True,
        )
        if result.get("ok") or not result.get("enabled"):
            success += 1
    write_json_report(args.validation_report, {"items": validation_report, "count": len(validation_report)})
    print(f"[MailHubBackfill] - success={success}/{len(accounts)}", flush=True)
    if args.verify_pool and not args.dry_run:
        from mailhub_outlook_smoke import run_smoke, write_report

        summary, smoke_code = run_smoke(
            service=args.smoke_service,
            expect_min_available=args.expect_min_available,
        )
        write_report(args.smoke_report, summary)
        print(
            "[MailHubBackfill] - verify_pool "
            f"ok={summary.get('ok')} messages_count={summary.get('messages_count')} "
            f"stats_before={summary.get('stats_before_counts')} stats_after={summary.get('stats_after_counts')}",
            flush=True,
        )
        if smoke_code != 0:
            return smoke_code
    return 0 if success == len(accounts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
