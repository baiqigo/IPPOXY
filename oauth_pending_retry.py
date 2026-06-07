import argparse
import json
import os
import time
from pathlib import Path

from get_token import get_access_token, wait_msa_login_ready
from mailhub_client import import_outlook_account


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "Results"


def _parse_pending_line(line):
    parts = line.rstrip("\n").split("---")
    if len(parts) < 2:
        return None
    return {"email": parts[0].strip(), "password": parts[1].strip(), "source": "oauth_pending"}


def _parse_logged_line(line):
    if ": " not in line:
        return None
    email, password = line.rstrip("\n").split(": ", 1)
    return {"email": email.strip(), "password": password.strip(), "source": "logged_email"}


def load_candidates(include_logged=False):
    seen = set()
    candidates = []
    files = [(RESULTS / "oauth_pending.txt", _parse_pending_line)]
    if include_logged:
        files.append((RESULTS / "logged_email.txt", _parse_logged_line))

    for path, parser in files:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            item = parser(line)
            if not item or not item["email"] or not item["password"]:
                continue
            key = item["email"].lower()
            if key in seen:
                continue
            seen.add(key)
            candidates.append(item)
    return candidates


def load_imported_emails():
    path = RESULTS / "oauth_imported.txt"
    if not path.exists():
        return set()
    imported = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        email = line.split("---", 1)[0].strip().lower()
        if email:
            imported.add(email)
    return imported


def append_line(path, line):
    path.parent.mkdir(exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")


def retry_one(item, wait_seconds, poll_seconds):
    email = item["email"]
    password = item["password"]
    ready, status = wait_msa_login_ready(
        None,
        email,
        max_wait_seconds=wait_seconds,
        interval_seconds=poll_seconds,
    )
    if not ready:
        return {"email": email, "ok": False, "stage": "account_ready", "status": status}

    refresh_token, access_token, expire_at = get_access_token(None, email, password=password, max_retries=1)
    if not refresh_token:
        return {"email": email, "ok": False, "stage": "oauth_token", "status": status}

    with open(ROOT / "config.json", "r", encoding="utf-8") as f:
        config = json.load(f)
    client_id = os.environ.get("OUTLOOK_OAUTH_CLIENT_ID", "").strip() or config["oauth2"]["client_id"].strip()

    append_line(
        RESULTS / "outlook_token.txt",
        f"{email}---{password}---{refresh_token}---{access_token}---{expire_at}",
    )
    mailhub_result = import_outlook_account(email, password, client_id, refresh_token)
    if mailhub_result.get("enabled") and not mailhub_result.get("ok"):
        return {
            "email": email,
            "ok": False,
            "stage": "mailhub_import",
            "mailhub": mailhub_result,
        }
    append_line(RESULTS / "oauth_imported.txt", f"{email}---{int(time.time())}---source={item['source']}")
    return {"email": email, "ok": True, "stage": "done", "mailhub": mailhub_result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-logged", action="store_true")
    parser.add_argument("--email", default="", help="Retry only one full email address.")
    parser.add_argument("--skip-imported", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--wait-seconds", type=int, default=int(os.environ.get("OUTLOOK_PENDING_READY_WAIT_SECONDS", "30")))
    parser.add_argument("--poll-seconds", type=int, default=int(os.environ.get("OUTLOOK_PENDING_READY_POLL_SECONDS", "10")))
    args = parser.parse_args()

    candidates = load_candidates(include_logged=args.include_logged)
    if args.email:
        wanted = args.email.strip().lower()
        candidates = [item for item in candidates if item["email"].lower() == wanted]
    if args.skip_imported:
        imported = load_imported_emails()
        candidates = [item for item in candidates if item["email"].lower() not in imported]
    candidates = candidates[: args.limit]
    print(
        f"[PendingRetry] - candidates={len(candidates)} include_logged={args.include_logged} "
        f"email_filter={args.email or '<none>'} skip_imported={args.skip_imported}",
        flush=True,
    )
    success = 0
    for item in candidates:
        result = retry_one(item, args.wait_seconds, args.poll_seconds)
        print(f"[PendingRetry] - result={result}", flush=True)
        if result.get("ok"):
            success += 1
    print(f"[PendingRetry] - success={success}/{len(candidates)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
